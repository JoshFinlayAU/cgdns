package resolver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// fakeUpstream is a real DNS server on loopback, so the forwarder is exercised
// over an actual socket rather than through a mocked exchange. Wire behaviour
// (EDNS0, truncation, IDs) is exactly what we most need to get right.
type fakeUpstream struct {
	addr    netip.AddrPort
	queries atomic.Int64
}

func newFakeUpstream(t *testing.T, h func(w dns.ResponseWriter, r *dns.Msg)) *fakeUpstream {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for fake upstream: %v", err)
	}
	up := &fakeUpstream{}
	ap, err := netip.ParseAddrPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("parsing fake upstream address: %v", err)
	}
	up.addr = ap

	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			up.queries.Add(1)
			h(w, r)
		}),
		NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = srv.ActivateAndServe() }()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("fake upstream did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	return up
}

// deadAddr returns a loopback address with nothing listening. On Linux a UDP
// send there draws an immediate ICMP port-unreachable, so failover is tested
// without waiting out a timeout.
func deadAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a dead address: %v", err)
	}
	ap, err := netip.ParseAddrPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("parsing dead address: %v", err)
	}
	_ = pc.Close()
	return ap
}

func testCache(t *testing.T) *cache.Cache {
	t.Helper()
	c, err := cache.New(cache.Options{
		MaxEntries:     1024,
		Shards:         16,
		MinTTL:         time.Second,
		MaxTTL:         time.Hour,
		MaxNegativeTTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("building cache: %v", err)
	}
	return c
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTestForwarder(t *testing.T, c *cache.Cache, upstreams ...netip.AddrPort) *Forwarder {
	t.Helper()
	f, err := NewForwarder(ForwardOptions{
		Upstreams:    upstreams,
		Cache:        c,
		QueryTimeout: 2 * time.Second,
		UDPSize:      1232,
		Log:          quietLogger(),
	})
	if err != nil {
		t.Fatalf("building forwarder: %v", err)
	}
	return f
}

func query(name string, qtype uint16) *transport.Request {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	return &transport.Request{
		Msg:             m,
		Client:          netip.MustParseAddrPort("192.0.2.10:34567"),
		Local:           netip.MustParseAddr("127.0.0.1"),
		Proto:           transport.ProtoUDP,
		Received:        time.Now(),
		MaxResponseSize: 1232,
	}
}

// answerWith replies with a single A record.
func answerWith(ip string, ttl uint32) func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.ParseIP(ip),
		})
		_ = w.WriteMsg(m)
	}
}

func TestServeDNS_ForwardsAndAnswers(t *testing.T) {
	up := newFakeUpstream(t, answerWith("192.0.2.55", 300))
	f := newTestForwarder(t, testCache(t), up.addr)

	req := query("example.com.", dns.TypeA)
	resp := f.ServeDNS(context.Background(), req)

	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is %T, want *dns.A", resp.Answer[0])
	}
	if a.A.String() != "192.0.2.55" {
		t.Errorf("answer = %s, want 192.0.2.55", a.A)
	}
	if resp.Id != req.Msg.Id {
		t.Errorf("response ID = %d, want the query's %d", resp.Id, req.Msg.Id)
	}
	if !resp.RecursionAvailable {
		t.Error("RA should be set on a recursive resolver's response")
	}
}

// The second identical query must be served from cache, not re-forwarded.
func TestServeDNS_SecondQueryHitsCache(t *testing.T) {
	up := newFakeUpstream(t, answerWith("192.0.2.55", 300))
	f := newTestForwarder(t, testCache(t), up.addr)

	for i := 0; i < 3; i++ {
		resp := f.ServeDNS(context.Background(), query("example.com.", dns.TypeA))
		if resp == nil || len(resp.Answer) != 1 {
			t.Fatalf("query %d: expected an answer, got %v", i, resp)
		}
	}

	if got := up.queries.Load(); got != 1 {
		t.Errorf("upstream saw %d queries, want 1 — the rest should have been cache hits", got)
	}
	if hits := f.opts.Metrics.CacheHits.Load(); hits != 2 {
		t.Errorf("CacheHits = %d, want 2", hits)
	}
}

// Forward mode does not validate DNSSEC, so it must never claim it did — even
// when the upstream sets AD on the response it hands us.
func TestServeDNS_StripsAuthenticatedData(t *testing.T) {
	up := newFakeUpstream(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.AuthenticatedData = true // upstream claims it validated
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.55"),
		})
		_ = w.WriteMsg(m)
	})
	f := newTestForwarder(t, testCache(t), up.addr)

	// Both the forwarded path and the subsequent cached path must strip it.
	for i, label := range []string{"forwarded", "cached"} {
		resp := f.ServeDNS(context.Background(), query("example.com.", dns.TypeA))
		if resp == nil {
			t.Fatalf("%s: expected a response", label)
		}
		if resp.AuthenticatedData {
			t.Errorf("%s (query %d): AD must not be set — this path does not validate", label, i)
		}
	}
}

func TestServeDNS_CachesNXDOMAIN(t *testing.T) {
	up := newFakeUpstream(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		m.Ns = append(m.Ns, &dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  1,
			Minttl:  120, // RFC 2308: negative TTL is min(MINIMUM, SOA TTL)
			Refresh: 7200, Retry: 3600, Expire: 1209600,
		})
		_ = w.WriteMsg(m)
	})
	f := newTestForwarder(t, testCache(t), up.addr)

	for i := 0; i < 2; i++ {
		resp := f.ServeDNS(context.Background(), query("nope.example.com.", dns.TypeA))
		if resp == nil {
			t.Fatal("expected a response")
		}
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("query %d: rcode = %s, want NXDOMAIN", i, dns.RcodeToString[resp.Rcode])
		}
	}
	if got := up.queries.Load(); got != 1 {
		t.Errorf("upstream saw %d queries, want 1 — the denial should have been cached", got)
	}

	// The cached denial must carry the SOA so the client knows how long the
	// denial is good for (RFC 2308 §3).
	resp := f.ServeDNS(context.Background(), query("nope.example.com.", dns.TypeA))
	if len(resp.Ns) != 1 {
		t.Errorf("cached NXDOMAIN should return the SOA in the authority section, got %d records", len(resp.Ns))
	}
}

// SERVFAIL describes the state of a server, not of the namespace. Caching it
// would turn a transient upstream blip into a sustained subscriber outage.
func TestServeDNS_DoesNotCacheServfail(t *testing.T) {
	up := newFakeUpstream(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})
	f := newTestForwarder(t, testCache(t), up.addr)

	for i := 0; i < 3; i++ {
		f.ServeDNS(context.Background(), query("broken.example.com.", dns.TypeA))
	}
	if got := up.queries.Load(); got != 3 {
		t.Errorf("upstream saw %d queries, want 3 — SERVFAIL must not be cached", got)
	}
}

func TestServeDNS_RefusesMetaAndNonINET(t *testing.T) {
	tests := []struct {
		name   string
		qtype  uint16
		qclass uint16
	}{
		{"AXFR", dns.TypeAXFR, dns.ClassINET},
		{"IXFR", dns.TypeIXFR, dns.ClassINET},
		{"CHAOS class", dns.TypeTXT, dns.ClassCHAOS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			up := newFakeUpstream(t, answerWith("192.0.2.55", 300))
			f := newTestForwarder(t, testCache(t), up.addr)

			req := query("example.com.", tt.qtype)
			req.Msg.Question[0].Qclass = tt.qclass

			resp := f.ServeDNS(context.Background(), req)
			if resp == nil {
				t.Fatal("expected a response")
			}
			if resp.Rcode != dns.RcodeRefused {
				t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
			}
			if got := up.queries.Load(); got != 0 {
				t.Errorf("upstream saw %d queries, want 0 — this must be refused locally", got)
			}
		})
	}
}

func TestServeDNS_FailsOverToHealthyUpstream(t *testing.T) {
	dead := deadAddr(t)
	up := newFakeUpstream(t, answerWith("192.0.2.55", 300))

	// Dead one first, so failover is actually exercised.
	f := newTestForwarder(t, testCache(t), dead, up.addr)

	resp := f.ServeDNS(context.Background(), query("example.com.", dns.TypeA))
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR after failover", dns.RcodeToString[resp.Rcode])
	}
	if got := up.queries.Load(); got != 1 {
		t.Errorf("healthy upstream saw %d queries, want 1", got)
	}
	if fails := f.opts.Metrics.UpstreamFail.Load(); fails == 0 {
		t.Error("expected the dead upstream to be counted as a failure")
	}
}

// When nothing answers, the client must get SERVFAIL carrying an RFC 8914
// Extended DNS Error so the failure is diagnosable rather than opaque.
func TestServeDNS_AllUpstreamsDeadReturnsServfailWithEDE(t *testing.T) {
	f := newTestForwarder(t, testCache(t), deadAddr(t), deadAddr(t))

	resp := f.ServeDNS(context.Background(), query("example.com.", dns.TypeA))
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	if resp.AuthenticatedData {
		t.Error("AD must never be set on a failure response")
	}

	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("expected an OPT record carrying the extended error")
	}
	var foundEDE bool
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok {
			foundEDE = true
			if ede.InfoCode != dns.ExtendedErrorCodeNetworkError {
				t.Errorf("EDE code = %d, want NetworkError (%d)", ede.InfoCode, dns.ExtendedErrorCodeNetworkError)
			}
		}
	}
	if !foundEDE {
		t.Error("SERVFAIL should carry an RFC 8914 Extended DNS Error")
	}
}

func TestServeDNS_CachedResponseCountsTTLDown(t *testing.T) {
	up := newFakeUpstream(t, answerWith("192.0.2.55", 10))
	f := newTestForwarder(t, testCache(t), up.addr)

	first := f.ServeDNS(context.Background(), query("example.com.", dns.TypeA))
	if first == nil || len(first.Answer) == 0 {
		t.Fatal("expected an answer")
	}
	firstTTL := first.Answer[0].Header().Ttl

	time.Sleep(1100 * time.Millisecond)

	second := f.ServeDNS(context.Background(), query("example.com.", dns.TypeA))
	if second == nil || len(second.Answer) == 0 {
		t.Fatal("expected a cached answer")
	}
	secondTTL := second.Answer[0].Header().Ttl

	if secondTTL >= firstTTL {
		t.Errorf("cached TTL did not decrease: first = %d, second = %d", firstTTL, secondTTL)
	}
}

// The forwarder must not cache records that do not answer the question asked;
// accepting whatever an upstream volunteers is how cache poisoning works.
func TestServeDNS_DoesNotCacheOutOfBailiwickAnswers(t *testing.T) {
	up := newFakeUpstream(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		// The legitimate answer...
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.55"),
		})
		// ...smuggled alongside an unrelated one.
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "victim.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("198.51.100.99"),
		})
		_ = w.WriteMsg(m)
	})

	c := testCache(t)
	f := newTestForwarder(t, c, up.addr)
	f.ServeDNS(context.Background(), query("example.com.", dns.TypeA))

	if _, ok := c.Get(cache.NewKey("victim.example.net.", dns.TypeA, dns.ClassINET)); ok {
		t.Error("an unrelated record from the answer section must not be cached")
	}
	entry, ok := c.Get(cache.NewKey("example.com.", dns.TypeA, dns.ClassINET))
	if !ok {
		t.Fatal("the legitimate answer should have been cached")
	}
	for _, rr := range entry.RRs {
		if !strings.EqualFold(rr.Header().Name, "example.com.") {
			t.Errorf("cached an out-of-bailiwick record: %s", rr.Header().Name)
		}
	}
}

func TestNewForwarder_RejectsBadOptions(t *testing.T) {
	c := testCache(t)
	tests := []struct {
		name string
		opts ForwardOptions
	}{
		{"no upstreams", ForwardOptions{Cache: c}},
		{"no cache", ForwardOptions{Upstreams: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewForwarder(tt.opts); err == nil {
				t.Error("expected NewForwarder to reject these options")
			}
		})
	}
}

func TestNegativeTTL(t *testing.T) {
	tests := []struct {
		name    string
		soaTTL  uint32
		minTTL  uint32
		wantSec time.Duration
	}{
		{"minimum is smaller", 3600, 120, 120 * time.Second},
		{"soa ttl is smaller", 60, 3600, 60 * time.Second},
		{"equal", 300, 300, 300 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := new(dns.Msg)
			m.Ns = []dns.RR{&dns.SOA{
				Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: tt.soaTTL},
				Minttl: tt.minTTL,
			}}
			_, got := negativeTTL(m)
			if got != tt.wantSec {
				t.Errorf("negativeTTL = %s, want %s", got, tt.wantSec)
			}
		})
	}

	t.Run("no soa yields no negative caching", func(t *testing.T) {
		t.Parallel()
		if _, got := negativeTTL(new(dns.Msg)); got != 0 {
			t.Errorf("negativeTTL = %s, want 0", got)
		}
	})
}
