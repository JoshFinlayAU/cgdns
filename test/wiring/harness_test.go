//go:build integration

// Package wiring tests that what the config enables is actually connected.
//
// Every unit test in this repo can pass while a feature does nothing at all:
// prefetch once refreshed entries by reading the very entry it meant to renew,
// and denial validation was dead code for a week. Both were wiring failures —
// the algorithms were correct and well covered, and nothing joined them to the
// serving path.
//
// So these tests do not call the packages. They start the real binary with a
// real config, drive real queries at it, and assert the observable effect that
// exists only if the feature is connected.
package wiring

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeUpstream is an authoritative server the daemon forwards to. It answers
// anything under its zone, and can be told to stop answering so serve-stale has
// something to serve through.
type fakeUpstream struct {
	addr    string
	ttl     atomic.Uint32
	failing atomic.Bool
	queries atomic.Int64
	srv     *dns.Server
}

func startUpstream(t *testing.T) *fakeUpstream {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding the fake upstream: %v", err)
	}
	u := &fakeUpstream{addr: pc.LocalAddr().String()}
	u.ttl.Store(2)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		u.queries.Add(1)
		if u.failing.Load() {
			return // silence, which is what an unreachable authoritative looks like
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		switch {
		case strings.HasPrefix(q.Name, "absent."):
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{&dns.SOA{
				Hdr:    dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
				Ns:     "ns.test.", Mbox: "hostmaster.test.",
				Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: 60,
			}}
		case q.Qtype == dns.TypeA:
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: u.ttl.Load()},
				A:   net.ParseIP("192.0.2.10"),
			}}
		}
		_ = w.WriteMsg(m)
	})

	u.srv = &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = u.srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = u.srv.Shutdown() })
	return u
}

// daemon is a running cgdns.
type daemon struct {
	dnsAddr     string
	metricsAddr string
	cmd         *exec.Cmd
	log         *strings.Builder
	mu          sync.Mutex
}

var buildOnce struct {
	sync.Once
	path string
	err  error
}

// binary builds cgdns once for the whole package.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "cgdns-wiring-*")
		if err != nil {
			buildOnce.err = err
			return
		}
		out := filepath.Join(dir, "cgdns")
		cmd := exec.Command("go", "build", "-o", out, "../../cmd/cgdns")
		if raw, err := cmd.CombinedOutput(); err != nil {
			buildOnce.err = fmt.Errorf("building cgdns: %v\n%s", err, raw)
			return
		}
		buildOnce.path = out
	})
	if buildOnce.err != nil {
		t.Fatal(buildOnce.err)
	}
	return buildOnce.path
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// start writes a config with extra spliced in and runs the daemon.
func start(t *testing.T, upstream string, extra string) *daemon {
	t.Helper()

	// Anything under a cache_extra: key belongs inside the cache block, since
	// prefetch and serve-stale are cache settings; the rest is top level.
	var cacheExtra, topExtra string
	if rest, ok := strings.CutPrefix(strings.TrimLeft(extra, "\n"), "cache_extra:\n"); ok {
		cacheExtra = rest
	} else {
		topExtra = extra
	}

	dir := t.TempDir()
	dnsPort := freePort(t)
	metricsPort := freePort(t)

	cfg := fmt.Sprintf(`
node:
  id: wiring
  state_dir: %s
listen:
  udp: ["127.0.0.1:%d"]
  tcp: ["127.0.0.1:%d"]
  allow_query: ["127.0.0.0/8"]
resolver:
  mode: forward
  upstreams: ["%s"]
  client_budget: 5s
  query_timeout: 2s
  udp_buffer_size: 1232
  use_ipv4: true
  use_ipv6: false
  dnssec: false
  aggressive_nsec: false
cache:
  max_entries: 10000
  shards: 8
  min_ttl: 1s
  max_ttl: 1h
  max_negative_ttl: 1m
  infra:
    max_entries: 1000
    shards: 4
    initial_rtt: 20ms
    max_backoff: 1s
%s
control:
  store_file: %s/control.json
management:
  enabled: false
health:
  enabled: false
metrics:
  listen: "127.0.0.1:%d"
  allow_from: ["127.0.0.0/8"]
log:
  level: info
  format: text
%s
`, dir, dnsPort, dnsPort, upstream, cacheExtra, dir, metricsPort, topExtra)

	path := filepath.Join(dir, "cgdns.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("config:\n%s", cfg)
		}
	})

	d := &daemon{
		dnsAddr:     fmt.Sprintf("127.0.0.1:%d", dnsPort),
		metricsAddr: fmt.Sprintf("127.0.0.1:%d", metricsPort),
		log:         &strings.Builder{},
	}
	d.cmd = exec.Command(binary(t), "-config", path)
	d.cmd.Stdout = d.log
	d.cmd.Stderr = d.log
	if err := d.cmd.Start(); err != nil {
		t.Fatalf("starting cgdns: %v", err)
	}
	t.Cleanup(func() {
		_ = d.cmd.Process.Kill()
		_, _ = d.cmd.Process.Wait()
		if t.Failed() {
			t.Logf("daemon log:\n%s", d.log.String())
		}
	})

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := d.query("ready.test.", dns.TypeA); err == nil {
			return d
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("cgdns did not become ready:\n%s", d.log.String())
	return nil
}

// flood sends a query without waiting long for a reply. A rate limiter's whole
// job is to not answer, so waiting out a full timeout on every dropped query
// turns a short test into a very long one.
func (d *daemon) flood(name string, qtype uint16) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 150 * time.Millisecond}
	_, _, _ = c.Exchange(m, d.dnsAddr)
}

func (d *daemon) query(name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 3 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, _, err := c.ExchangeContext(ctx, m, d.dnsAddr)
	return resp, err
}

// metric reads one Prometheus sample by name prefix, returning 0 when absent.
func (d *daemon) metric(t *testing.T, name string) float64 {
	t.Helper()
	c := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := c.Dial("tcp", d.metricsAddr)
	if err != nil {
		t.Fatalf("dialling metrics: %v", err)
	}
	_, _ = conn.Write([]byte("GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n"))
	buf := make([]byte, 1<<20)
	n, _ := conn.Read(buf)
	_ = conn.Close()

	for _, line := range strings.Split(string(buf[:n]), "\n") {
		if !strings.HasPrefix(line, name) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var v float64
		if _, err := fmt.Sscanf(fields[len(fields)-1], "%g", &v); err == nil {
			return v
		}
	}
	return 0
}
