// cgdnsdiff compares what two resolvers answer for the same names.
//
// It exists because this resolver's worst failures have all been silent: an
// answer that looks well-formed, arrives quickly, and is wrong. Unit tests pass
// through them because the fixtures are the ones we thought to write. Real
// names hit CNAME chains that cross zone cuts, half-signed zones, authoritative
// servers that answer one family and not the other — and a divergence from a
// known-good resolver surfaces all of it in minutes, without a subscriber
// having to be the detector.
//
// The comparison is deliberately narrow: response code and the AD bit. Address
// records legitimately differ between two resolvers (CDNs, geo steering), so
// comparing them would drown the signal. Losing AD, or returning SERVFAIL where
// the reference says NOERROR, cannot be legitimate.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type verdict int

const (
	agree verdict = iota
	rcodeDiffers
	adLost
	adGained
	bothFailed
)

type result struct {
	name    string
	qtype   uint16
	v       verdict
	aRcode  int
	bRcode  int
	aAD     bool
	bAD     bool
	aErr    string
	bErr    string
	aTiming time.Duration
}

func main() {
	var (
		subject   = flag.String("subject", "", "resolver under test, host:port")
		reference = flag.String("reference", "9.9.9.9:53", "known-good resolver to compare against")
		listPath  = flag.String("list", "", "domain list: one name per line, or a CSV with a domain column")
		column    = flag.Int("column", 3, "1-indexed domain column when the list is CSV")
		count     = flag.Int("n", 2000, "how many names to sample")
		stride    = flag.Int("stride", 0, "sample every Nth name rather than the first n (0 picks a stride that spans the list)")
		workers   = flag.Int("workers", 24, "concurrent queries")
		timeout   = flag.Duration("timeout", 6*time.Second, "per-query timeout")
		qtypeName = flag.String("type", "A", "query type")
		maxFail   = flag.Float64("max-divergence", 1.0, "exit non-zero above this percentage of diverging names")
		verbose   = flag.Bool("v", false, "list every divergence rather than the first 40")
	)
	flag.Parse()

	if *subject == "" || *listPath == "" {
		fmt.Fprintln(os.Stderr, "cgdnsdiff: -subject and -list are required")
		os.Exit(2)
	}
	qtype, ok := dns.StringToType[strings.ToUpper(*qtypeName)]
	if !ok {
		fmt.Fprintf(os.Stderr, "cgdnsdiff: unknown query type %q\n", *qtypeName)
		os.Exit(2)
	}

	names, err := loadNames(*listPath, *column, *count, *stride)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cgdnsdiff: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("comparing %d names, %s vs %s, type %s\n\n",
		len(names), *subject, *reference, strings.ToUpper(*qtypeName))

	results := run(names, qtype, *subject, *reference, *workers, *timeout)
	report(results, *verbose)

	diverged := 0
	for _, r := range results {
		if r.v != agree && r.v != bothFailed {
			diverged++
		}
	}
	comparable := 0
	for _, r := range results {
		if r.v != bothFailed {
			comparable++
		}
	}
	if comparable == 0 {
		fmt.Println("\nno comparable answers — check reachability")
		os.Exit(1)
	}
	pct := float64(diverged) / float64(comparable) * 100
	fmt.Printf("\ndivergence: %.2f%% of %d comparable (threshold %.2f%%)\n", pct, comparable, *maxFail)
	if pct > *maxFail {
		os.Exit(1)
	}
}

// loadNames reads the domain list, taking a stride through it so the sample
// spans the whole popularity range. The tail of a ranked list is where the
// broken zones live, and those are the interesting ones.
func loadNames(path string, column, count, stride int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var all []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		name := line
		if strings.Contains(line, ",") {
			rec, err := csv.NewReader(strings.NewReader(line)).Read()
			if err != nil || len(rec) < column {
				continue
			}
			name = strings.TrimSpace(rec[column-1])
		}
		if first {
			first = false
			// A CSV header names the column rather than a domain.
			if !strings.Contains(name, ".") {
				continue
			}
		}
		if name == "" || !strings.Contains(name, ".") {
			continue
		}
		all = append(all, name)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("no names found in %s", path)
	}

	if stride <= 0 {
		stride = len(all) / count
	}
	if stride < 1 {
		stride = 1
	}
	var out []string
	for i := 0; i < len(all) && len(out) < count; i += stride {
		out = append(out, all[i])
	}
	return out, nil
}

func run(names []string, qtype uint16, subject, reference string, workers int, timeout time.Duration) []result {
	in := make(chan string)
	out := make(chan result, len(names))

	var done atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &dns.Client{Timeout: timeout}
			for name := range in {
				out <- compare(c, name, qtype, subject, reference, timeout)
				if n := done.Add(1); n%250 == 0 {
					fmt.Fprintf(os.Stderr, "  %d/%d\n", n, len(names))
				}
			}
		}()
	}
	go func() {
		for _, n := range names {
			in <- n
		}
		close(in)
	}()
	wg.Wait()
	close(out)

	var results []result
	for r := range out {
		results = append(results, r)
	}
	return results
}

func compare(c *dns.Client, name string, qtype uint16, subject, reference string, timeout time.Duration) result {
	r := result{name: name, qtype: qtype}

	start := time.Now()
	aResp, aErr := ask(c, name, qtype, subject, timeout)
	r.aTiming = time.Since(start)
	bResp, bErr := ask(c, name, qtype, reference, timeout)

	if aErr != nil {
		r.aErr = aErr.Error()
	}
	if bErr != nil {
		r.bErr = bErr.Error()
	}

	// A reference that could not answer proves nothing about the subject.
	if aErr != nil || bErr != nil {
		r.v = bothFailed
		return r
	}

	r.aRcode, r.bRcode = aResp.Rcode, bResp.Rcode
	r.aAD, r.bAD = aResp.AuthenticatedData, bResp.AuthenticatedData

	switch {
	case r.aRcode != r.bRcode:
		r.v = rcodeDiffers
	case r.bAD && !r.aAD:
		r.v = adLost
	case r.aAD && !r.bAD:
		r.v = adGained
	default:
		r.v = agree
	}
	return r
}

// ask retries once: a single lost UDP packet is not a divergence, and treating
// it as one would bury the real findings in noise.
func ask(c *dns.Client, name string, qtype uint16, server string, timeout time.Duration) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(1232, true)
	m.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), timeout*2)
	defer cancel()

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		resp, _, err := c.ExchangeContext(ctx, m, server)
		if err == nil {
			if resp.Truncated {
				tc := &dns.Client{Net: "tcp", Timeout: timeout}
				if tr, _, terr := tc.ExchangeContext(ctx, m, server); terr == nil {
					return tr, nil
				}
			}
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func report(results []result, verbose bool) {
	counts := map[verdict]int{}
	for _, r := range results {
		counts[r.v]++
	}

	fmt.Printf("%-18s %d\n", "agree", counts[agree])
	fmt.Printf("%-18s %d\n", "rcode differs", counts[rcodeDiffers])
	fmt.Printf("%-18s %d   <- subject failed to validate what the reference did\n", "AD lost", counts[adLost])
	fmt.Printf("%-18s %d\n", "AD gained", counts[adGained])
	fmt.Printf("%-18s %d   (not comparable)\n", "no answer", counts[bothFailed])

	var diffs []result
	for _, r := range results {
		if r.v != agree && r.v != bothFailed {
			diffs = append(diffs, r)
		}
	}
	if len(diffs) == 0 {
		return
	}
	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].v != diffs[j].v {
			return diffs[i].v < diffs[j].v
		}
		return diffs[i].name < diffs[j].name
	})

	limit := 40
	if verbose || len(diffs) < limit {
		limit = len(diffs)
	}
	fmt.Printf("\ndivergences (%d shown of %d):\n", limit, len(diffs))
	for _, d := range diffs[:limit] {
		fmt.Printf("  %-42s subject=%-9s ad=%-5t   reference=%-9s ad=%-5t\n",
			d.name, dns.RcodeToString[d.aRcode], d.aAD, dns.RcodeToString[d.bRcode], d.bAD)
	}

	// SERVFAIL where the reference succeeded is the shape every DNSSEC bug in
	// this resolver has taken, so it is called out rather than left in the list.
	servfail := 0
	for _, d := range diffs {
		if d.aRcode == dns.RcodeServerFailure && d.bRcode == dns.RcodeSuccess {
			servfail++
		}
	}
	if servfail > 0 {
		fmt.Printf("\n%d names SERVFAIL on the subject but resolve on the reference — investigate these first\n", servfail)
	}
}
