// cgdns-probe checks a resolver from outside itself.
//
// It exists because this resolver has twice reported itself healthy through a
// total failure. A node's own metrics describe what it believes; they cannot
// describe what a subscriber actually receives, and the gap between those two
// is where every serious incident here has lived. So this runs somewhere else,
// speaks to the anycast address the way a subscriber does, and judges only the
// answer that comes back.
//
// Three checks, because there are three ways to be broken and they need telling
// apart:
//
//   - a signed name must return NOERROR with AD. Losing AD means validation
//     silently stopped, which no availability check would notice.
//   - a deliberately broken name must return SERVFAIL. Answering it means
//     validation is off, or worse, accepting forged data.
//   - an ordinary name must resolve, which is the plain availability question.
//
// A resolver failing the first two while passing the third looks perfectly
// healthy on a dashboard and is not serving DNSSEC at all.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type outcome int

const (
	pass outcome = iota
	fail
	unreachable
)

type check struct {
	name   string
	qname  string
	expect func(*dns.Msg) (bool, string)
}

type target struct {
	label     string
	addr      string
	transport string
	tlsName   string
}

type result struct {
	target  target
	check   check
	out     outcome
	detail  string
	elapsed time.Duration
}

func checks() []check {
	return []check{
		{
			name:  "validates",
			qname: "internetsociety.org.",
			expect: func(m *dns.Msg) (bool, string) {
				if m.Rcode != dns.RcodeSuccess {
					return false, "rcode " + dns.RcodeToString[m.Rcode]
				}
				if !m.AuthenticatedData {
					return false, "AD not set: the resolver is no longer validating"
				}
				return true, ""
			},
		},
		{
			name:  "rejects_bogus",
			qname: "dnssec-failed.org.",
			expect: func(m *dns.Msg) (bool, string) {
				if m.Rcode != dns.RcodeServerFailure {
					return false, "answered " + dns.RcodeToString[m.Rcode] +
						" for a deliberately broken zone: validation is not rejecting"
				}
				return true, ""
			},
		},
		{
			name:  "resolves",
			qname: "example.com.",
			expect: func(m *dns.Msg) (bool, string) {
				if m.Rcode != dns.RcodeSuccess {
					return false, "rcode " + dns.RcodeToString[m.Rcode]
				}
				if len(m.Answer) == 0 {
					return false, "no answer records"
				}
				return true, ""
			},
		},
	}
}

func main() {
	var (
		targetSpec = flag.String("targets", "", "comma-separated label=addr[:port][@transport][#tlsname], e.g. ns1=160.30.37.252@udp,ns1-dot=160.30.37.252:853@dot#dns1.example")
		listen     = flag.String("listen", "", "expose Prometheus metrics here and probe continuously; empty runs once and exits")
		interval   = flag.Duration("interval", 30*time.Second, "how often to probe when serving metrics")
		timeout    = flag.Duration("timeout", 5*time.Second, "per-query timeout")
		verbose    = flag.Bool("v", false, "print every result, not just failures")
	)
	flag.Parse()

	targets, err := parseTargets(*targetSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cgdns-probe: %v\n", err)
		os.Exit(2)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "cgdns-probe: -targets is required")
		os.Exit(2)
	}

	if *listen == "" {
		results := runAll(targets, *timeout)
		report(results, *verbose)
		for _, r := range results {
			if r.out != pass {
				os.Exit(1)
			}
		}
		return
	}

	state := &state{}
	go func() {
		for {
			state.set(runAll(targets, *timeout))
			time.Sleep(*interval)
		}
	}()

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(state.render()))
	})
	log.Printf("cgdns-probe serving metrics on %s, probing %d targets every %s", *listen, len(targets), *interval)
	srv := &http.Server{Addr: *listen, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// parseTargets reads label=addr[@transport][#tlsname] entries.
func parseTargets(spec string) ([]target, error) {
	var out []target
	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		label, rest, ok := strings.Cut(raw, "=")
		if !ok {
			return nil, fmt.Errorf("target %q is missing a label", raw)
		}
		t := target{label: label, transport: "udp"}
		if before, name, found := strings.Cut(rest, "#"); found {
			rest, t.tlsName = before, name
		}
		if before, tr, found := strings.Cut(rest, "@"); found {
			rest, t.transport = before, tr
		}
		switch t.transport {
		case "udp", "tcp", "dot":
		default:
			return nil, fmt.Errorf("target %q: unsupported transport %q", label, t.transport)
		}
		// net.SplitHostPort is the only reliable way to tell "has a port" from
		// "is a bare IPv6 literal", and JoinHostPort brackets v6 for us.
		if _, _, err := net.SplitHostPort(rest); err != nil {
			port := "53"
			if t.transport == "dot" {
				port = "853"
			}
			rest = net.JoinHostPort(strings.Trim(rest, "[]"), port)
		}
		t.addr = rest
		out = append(out, t)
	}
	return out, nil
}

func runAll(targets []target, timeout time.Duration) []result {
	var (
		mu      sync.Mutex
		results []result
		wg      sync.WaitGroup
	)
	for _, t := range targets {
		for _, c := range checks() {
			wg.Add(1)
			go func(t target, c check) {
				defer wg.Done()
				r := probe(t, c, timeout)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}(t, c)
		}
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		if results[i].target.label != results[j].target.label {
			return results[i].target.label < results[j].target.label
		}
		return results[i].check.name < results[j].check.name
	})
	return results
}

func probe(t target, c check, timeout time.Duration) result {
	m := new(dns.Msg)
	m.SetQuestion(c.qname, dns.TypeA)
	m.SetEdns0(1232, true)
	m.RecursionDesired = true

	client := &dns.Client{Timeout: timeout}
	switch t.transport {
	case "tcp":
		client.Net = "tcp"
	case "dot":
		client.Net = "tcp-tls"
		client.TLSConfig = &tls.Config{ServerName: t.tlsName, MinVersion: tls.VersionTLS12}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*2)
	defer cancel()

	start := time.Now()
	resp, _, err := client.ExchangeContext(ctx, m, t.addr)
	elapsed := time.Since(start)
	if err != nil {
		return result{target: t, check: c, out: unreachable, detail: err.Error(), elapsed: elapsed}
	}
	ok, why := c.expect(resp)
	if !ok {
		return result{target: t, check: c, out: fail, detail: why, elapsed: elapsed}
	}
	return result{target: t, check: c, out: pass, elapsed: elapsed}
}

func report(results []result, verbose bool) {
	for _, r := range results {
		switch r.out {
		case pass:
			if verbose {
				fmt.Printf("ok      %-14s %-14s %s\n", r.target.label, r.check.name, r.elapsed.Round(time.Millisecond))
			}
		case fail:
			fmt.Printf("FAIL    %-14s %-14s %s\n", r.target.label, r.check.name, r.detail)
		case unreachable:
			fmt.Printf("UNREACH %-14s %-14s %s\n", r.target.label, r.check.name, r.detail)
		}
	}
}

type state struct {
	mu      sync.RWMutex
	results []result
	stamp   time.Time
}

func (s *state) set(r []result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results, s.stamp = r, time.Now()
}

func (s *state) render() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var b strings.Builder
	b.WriteString("# HELP cgdns_probe_success Whether the check passed, judged from outside the resolver.\n")
	b.WriteString("# TYPE cgdns_probe_success gauge\n")
	for _, r := range s.results {
		v := 0
		if r.out == pass {
			v = 1
		}
		fmt.Fprintf(&b, "cgdns_probe_success{target=%q,transport=%q,check=%q} %d\n",
			r.target.label, r.target.transport, r.check.name, v)
	}
	b.WriteString("# HELP cgdns_probe_reachable Whether the resolver answered at all.\n")
	b.WriteString("# TYPE cgdns_probe_reachable gauge\n")
	for _, r := range s.results {
		v := 1
		if r.out == unreachable {
			v = 0
		}
		fmt.Fprintf(&b, "cgdns_probe_reachable{target=%q,transport=%q,check=%q} %d\n",
			r.target.label, r.target.transport, r.check.name, v)
	}
	b.WriteString("# HELP cgdns_probe_duration_seconds How long the query took.\n")
	b.WriteString("# TYPE cgdns_probe_duration_seconds gauge\n")
	for _, r := range s.results {
		fmt.Fprintf(&b, "cgdns_probe_duration_seconds{target=%q,transport=%q,check=%q} %f\n",
			r.target.label, r.target.transport, r.check.name, r.elapsed.Seconds())
	}
	b.WriteString("# HELP cgdns_probe_last_run_timestamp When the probe last completed.\n")
	b.WriteString("# TYPE cgdns_probe_last_run_timestamp gauge\n")
	fmt.Fprintf(&b, "cgdns_probe_last_run_timestamp %d\n", s.stamp.Unix())
	return b.String()
}
