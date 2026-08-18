// cgdnsload finds where a resolver stops answering everything, and what gives
// way first.
//
// A resolver that is merely "fast enough" at the load you have today tells you
// nothing about the load you are planning for. What matters is the shape of the
// curve as it approaches capacity: latency usually degrades gracefully while
// loss does not, and UDP loss is silent — the query simply never comes back,
// which looks like a network fault rather than a saturated daemon. Finding that
// point deliberately, on a machine nobody depends on, is much cheaper than
// finding it during a peak.
//
// It ramps through offered rates, holds each one long enough to be meaningful,
// and reports what was actually achieved rather than what was asked for. The
// difference between the two is the answer.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type stage struct {
	offered  int
	sent     int64
	answered int64
	timeouts int64
	errors   int64
	rcodes   map[int]int64
	latency  []time.Duration
	elapsed  time.Duration
}

func main() {
	var (
		target      = flag.String("target", "127.0.0.1:5353", "resolver under test")
		namesPath   = flag.String("names", "", "domain list, one per line or CSV; generated names are used when empty")
		nameCount   = flag.Int("unique", 10000, "how many distinct names to draw from")
		rates       = flag.String("rates", "500,1000,2000,4000,8000,16000,32000", "offered rates to step through, queries per second")
		hold        = flag.Duration("hold", 20*time.Second, "how long to hold each rate")
		settle      = flag.Duration("settle", 3*time.Second, "pause between stages so queues drain")
		timeout     = flag.Duration("timeout", 2*time.Second, "per-query timeout")
		workers     = flag.Int("workers", 256, "concurrent senders")
		zipf        = flag.Float64("zipf", 1.1, "skew of the name distribution; 0 draws uniformly")
		lossCeiling = flag.Float64("stop-at-loss", 5.0, "stop ramping once loss exceeds this percentage")
	)
	flag.Parse()

	names, err := loadNames(*namesPath, *nameCount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cgdnsload: %v\n", err)
		os.Exit(2)
	}

	var offered []int
	for _, f := range strings.Split(*rates, ",") {
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(f), "%d", &n); err == nil && n >= 0 {
			offered = append(offered, n)
		}
	}
	if len(offered) == 0 {
		fmt.Fprintln(os.Stderr, "cgdnsload: no valid rates")
		os.Exit(2)
	}

	fmt.Printf("target %s, %d distinct names, zipf %.2f, %s per stage\n\n",
		*target, len(names), *zipf, *hold)
	fmt.Printf("%8s %10s %10s %8s %9s %9s %9s %9s\n",
		"offered", "achieved", "answered", "loss%", "p50", "p95", "p99", "max")

	for _, rate := range offered {
		st := run(*target, names, rate, *hold, *timeout, *workers, *zipf)
		report(st)
		if st.lossPct() > *lossCeiling {
			fmt.Printf("\nloss passed %.1f%% at %d qps offered; stopping the ramp\n", *lossCeiling, rate)
			break
		}
		time.Sleep(*settle)
	}
}

func (s *stage) lossPct() float64 {
	if s.sent == 0 {
		return 0
	}
	lost := s.sent - s.answered
	return float64(lost) * 100 / float64(s.sent)
}

// run offers one rate for the hold time.
//
// Senders are paced from a shared ticker rather than sleeping individually, so
// the offered rate is what was asked for even when the resolver slows down —
// a generator that waits for each reply before sending the next measures its
// own patience, not the server's capacity.
func run(target string, names []string, rate int, hold, timeout time.Duration, workers int, skew float64) *stage {
	st := &stage{offered: rate, rcodes: map[int]int64{}}
	var (
		mu   sync.Mutex
		lats []time.Duration
	)

	pick := picker(len(names), skew)
	work := make(chan string, rate)

	ctx, cancel := context.WithTimeout(context.Background(), hold)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &dns.Client{Timeout: timeout}
			local := make([]time.Duration, 0, 1024)
			for name := range work {
				m := new(dns.Msg)
				m.SetQuestion(name, dns.TypeA)
				m.RecursionDesired = true

				start := time.Now()
				resp, _, err := c.Exchange(m, target)
				took := time.Since(start)

				atomic.AddInt64(&st.sent, 1)
				switch {
				case err != nil && strings.Contains(err.Error(), "timeout"):
					atomic.AddInt64(&st.timeouts, 1)
				case err != nil:
					atomic.AddInt64(&st.errors, 1)
				default:
					atomic.AddInt64(&st.answered, 1)
					local = append(local, took)
					mu.Lock()
					st.rcodes[resp.Rcode]++
					mu.Unlock()
				}
			}
			mu.Lock()
			lats = append(lats, local...)
			mu.Unlock()
		}()
	}

	begin := time.Now()
	go func() {
		defer close(work)
		// Rate 0 means send as fast as the workers will take it, which is how
		// the actual ceiling gets found. Paced mode cannot: a ticker asked for
		// an interval of a few microseconds does not keep it, so above a few
		// tens of thousands per second the generator becomes the bottleneck and
		// the measurement quietly turns into a measurement of itself.
		if rate <= 0 {
			for {
				select {
				case <-ctx.Done():
					return
				case work <- names[pick()]:
				}
			}
		}
		interval := time.Duration(float64(time.Second) / float64(rate))
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				select {
				case work <- names[pick()]:
				default:
					// The queue is full: the resolver is not keeping up and the
					// generator must not block, or it would quietly reduce the
					// offered rate and hide the very thing being measured.
					atomic.AddInt64(&st.sent, 1)
					atomic.AddInt64(&st.errors, 1)
				}
			}
		}
	}()

	wg.Wait()
	st.elapsed = time.Since(begin)
	st.latency = lats
	return st
}

// picker draws names with a realistic skew. Real traffic is dominated by a
// small set of popular names, and drawing uniformly from a large list would
// give a cache hit rate near zero — measuring a cold resolver rather than a
// working one.
func picker(n int, skew float64) func() int {
	if skew <= 0 {
		var mu sync.Mutex
		r := rand.New(rand.NewSource(1))
		return func() int {
			mu.Lock()
			defer mu.Unlock()
			return r.Intn(n)
		}
	}
	var mu sync.Mutex
	z := rand.NewZipf(rand.New(rand.NewSource(1)), 1+skew, 1, uint64(n-1))
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return int(z.Uint64())
	}
}

func report(s *stage) {
	sort.Slice(s.latency, func(i, j int) bool { return s.latency[i] < s.latency[j] })
	achieved := float64(s.sent) / s.elapsed.Seconds()
	label := fmt.Sprintf("%d", s.offered)
	if s.offered == 0 {
		label = "max"
	}
	fmt.Printf("%8s %10.0f %10d %7.2f%% %9s %9s %9s %9s\n",
		label, achieved, s.answered, s.lossPct(),
		pct(s.latency, 50), pct(s.latency, 95), pct(s.latency, 99), pct(s.latency, 100))

	var parts []string
	for code, n := range s.rcodes {
		if code != dns.RcodeSuccess {
			parts = append(parts, fmt.Sprintf("%s=%d", dns.RcodeToString[code], n))
		}
	}
	if s.timeouts > 0 {
		parts = append(parts, fmt.Sprintf("timeouts=%d", s.timeouts))
	}
	if s.errors > 0 {
		parts = append(parts, fmt.Sprintf("errors=%d", s.errors))
	}
	if len(parts) > 0 {
		sort.Strings(parts)
		fmt.Printf("%8s %s\n", "", strings.Join(parts, " "))
	}
}

func pct(sorted []time.Duration, p int) string {
	if len(sorted) == 0 {
		return "-"
	}
	idx := int(math.Ceil(float64(p)/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx].Round(100 * time.Microsecond).String()
}

func loadNames(path string, count int) ([]string, error) {
	if path == "" {
		out := make([]string, 0, count)
		for i := 0; i < count; i++ {
			out = append(out, fmt.Sprintf("n%d.load.test.", i))
		}
		return out, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() && len(out) < count {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		name := line
		if strings.Contains(line, ",") {
			rec, err := csv.NewReader(strings.NewReader(line)).Read()
			if err != nil || len(rec) < 3 {
				continue
			}
			name = strings.TrimSpace(rec[2])
		}
		if !strings.Contains(name, ".") {
			continue
		}
		out = append(out, dns.Fqdn(name))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no names found in %s", path)
	}
	return out, sc.Err()
}
