package servestale

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// clock lets a test walk past an expiry without sleeping.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func testCache(t *testing.T, clk *clock, maxStale time.Duration) *cache.Cache {
	t.Helper()
	c, err := cache.New(cache.Options{
		MaxEntries: 1024, Shards: 4,
		MinTTL: time.Second, MaxTTL: time.Hour, MaxNegativeTTL: time.Hour,
		MaxStale: maxStale,
		Now:      clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type stub struct {
	resp func(*transport.Request) *dns.Msg
}

func (s stub) ServeDNS(_ context.Context, req *transport.Request) *dns.Msg { return s.resp(req) }

func request(name string, qtype uint16) *transport.Request {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return &transport.Request{
		Msg:    m,
		Client: netip.MustParseAddrPort("203.0.113.9:5300"),
		Proto:  transport.ProtoUDP,
	}
}

func aRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func servfail(req *transport.Request) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req.Msg, dns.RcodeServerFailure)
	return m
}

// The case this exists for: the authoritative has gone away, and the choice is
// between old data and nothing at all.
func TestServesStaleWhenResolutionFails(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	key := cache.NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, true)

	h := New(Options{Next: stub{resp: servfail}, Cache: c, AnswerTTL: 30 * time.Second, Log: quietLogger()})

	// While it is live, the resolver's own failure stands: nothing is stale yet.
	if resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA)); resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("with a live entry, got rcode %d, want SERVFAIL from the resolver", resp.Rcode)
	}

	clk.add(2 * time.Minute) // past the 60s TTL, inside the 1h stale window

	resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA))
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("got rcode %d, want NOERROR from stale data", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "192.0.2.1" {
		t.Fatalf("got %v, want the stale 192.0.2.1", resp.Answer[0])
	}
	if ttl := resp.Answer[0].Header().Ttl; ttl != 30 {
		t.Fatalf("stale answer TTL is %d, want the configured 30", ttl)
	}
}

// A zero TTL would tell every client never to cache the answer, sending all of
// them straight back to a resolver that is already failing.
func TestStaleAnswerNeverHasAZeroTTL(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	c.PutRRset(cache.NewKey("example.com.", dns.TypeA, dns.ClassINET),
		[]dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, false)
	clk.add(2 * time.Minute)

	h := New(Options{Next: stub{resp: servfail}, Cache: c, AnswerTTL: time.Millisecond, Log: quietLogger()})
	resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA))
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers", len(resp.Answer))
	}
	if ttl := resp.Answer[0].Header().Ttl; ttl < 1 {
		t.Fatalf("stale answer TTL is %d, which tells clients not to cache it at all", ttl)
	}
}

// The signatures are as old as the data, so claiming the chain validated is a
// claim we cannot stand behind.
func TestStaleAnswerNeverSetsAD(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	c.PutRRset(cache.NewKey("example.com.", dns.TypeA, dns.ClassINET),
		[]dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, true) // stored as authenticated
	clk.add(2 * time.Minute)

	h := New(Options{Next: stub{resp: servfail}, Cache: c, Log: quietLogger()})
	resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA))
	if resp.AuthenticatedData {
		t.Fatal("a stale answer set AD, claiming a validation it cannot stand behind")
	}
}

// A client has to be able to tell a stale answer from a fresh one.
func TestStaleAnswerCarriesEDE(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	c.PutRRset(cache.NewKey("example.com.", dns.TypeA, dns.ClassINET),
		[]dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, false)
	clk.add(2 * time.Minute)

	h := New(Options{Next: stub{resp: servfail}, Cache: c, Log: quietLogger()})
	resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA))

	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("stale answer carries no EDNS0 record, so it cannot carry an EDE")
	}
	found := false
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok && ede.InfoCode == dns.ExtendedErrorCodeStaleAnswer {
			found = true
		}
	}
	if !found {
		t.Fatal("stale answer does not carry EDE 3 (Stale Answer)")
	}
}

// NXDOMAIN and NODATA are answers: the authoritative was reached and said no.
// Overriding them would resurrect names their owner deliberately removed.
func TestDoesNotOverrideARealDenial(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	c.PutRRset(cache.NewKey("example.com.", dns.TypeA, dns.ClassINET),
		[]dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, false)
	clk.add(2 * time.Minute)

	for _, tc := range []struct {
		name  string
		rcode int
	}{
		{"nxdomain", dns.RcodeNameError},
		{"nodata", dns.RcodeSuccess},
		{"refused", dns.RcodeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := New(Options{Cache: c, Log: quietLogger(), Next: stub{resp: func(req *transport.Request) *dns.Msg {
				m := new(dns.Msg)
				m.SetRcode(req.Msg, tc.rcode)
				return m
			}}})
			resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA))
			if len(resp.Answer) != 0 {
				t.Fatalf("a %s was replaced with stale data", tc.name)
			}
			if resp.Rcode != tc.rcode {
				t.Fatalf("rcode changed from %d to %d", tc.rcode, resp.Rcode)
			}
		})
	}
}

// A successful answer must pass through untouched, or serve-stale would be
// competing with a working authoritative.
func TestPassesSuccessThrough(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	c.PutRRset(cache.NewKey("example.com.", dns.TypeA, dns.ClassINET),
		[]dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, false)
	clk.add(2 * time.Minute)

	h := New(Options{Cache: c, Log: quietLogger(), Next: stub{resp: func(req *transport.Request) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req.Msg)
		m.Answer = []dns.RR{aRR(t, "example.com. 300 IN A 198.51.100.7")}
		return m
	}}})

	resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA))
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "198.51.100.7" {
		t.Fatalf("got %v, want the fresh answer", resp.Answer[0])
	}
	if resp.Answer[0].Header().Ttl != 300 {
		t.Fatal("a fresh answer was re-stamped with the stale TTL")
	}
}

// Past the window the data is simply gone, and SERVFAIL is the honest answer.
func TestStopsServingPastTheStaleWindow(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, 10*time.Minute)
	c.PutRRset(cache.NewKey("example.com.", dns.TypeA, dns.ClassINET),
		[]dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, false)

	h := New(Options{Next: stub{resp: servfail}, Cache: c, Log: quietLogger()})

	clk.add(5 * time.Minute)
	if resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA)); resp.Rcode != dns.RcodeSuccess {
		t.Fatal("inside the window, stale should have been served")
	}

	clk.add(30 * time.Minute)
	if resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA)); resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("past the window, got rcode %d, want SERVFAIL", resp.Rcode)
	}
}

// With serve-stale off the cache must behave exactly as before, dropping
// entries at expiry rather than hoarding them.
func TestDisabledKeepsNothingStale(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, 0)
	key := cache.NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, false)

	clk.add(2 * time.Minute)
	if _, ok := c.Get(key); ok {
		t.Fatal("expired entry was served")
	}
	if _, ok := c.GetStale(key); ok {
		t.Fatal("GetStale returned an entry with serve-stale disabled")
	}
	if c.Len() != 0 {
		t.Fatalf("cache holds %d entries after expiry with serve-stale off", c.Len())
	}

	h := New(Options{Next: stub{resp: servfail}, Cache: c, Log: quietLogger()})
	if resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA)); resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("got rcode %d, want SERVFAIL", resp.Rcode)
	}
}

// A live entry is never treated as stale: the normal path owns it.
func TestGetStaleIgnoresLiveEntries(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	key := cache.NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, false)

	if _, ok := c.GetStale(key); ok {
		t.Fatal("GetStale returned a live entry")
	}
}

// Serving stale must not distort the cache hit ratio, which is a signal about
// client traffic rather than about upstream failures.
func TestStaleLookupsDoNotCountAsHits(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	key := cache.NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, false)
	clk.add(2 * time.Minute)

	before := c.Stats()
	for range 5 {
		if _, ok := c.GetStale(key); !ok {
			t.Fatal("stale entry vanished")
		}
	}
	after := c.Stats()
	if after.Hits != before.Hits {
		t.Fatalf("stale lookups added %d hits", after.Hits-before.Hits)
	}
}

func TestServesStaleNegativeEntries(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	key := cache.NewKey("gone.example.com.", dns.TypeA, dns.ClassINET)
	soa := aRR(t, "example.com. 60 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 60")
	c.PutNegative(key, dns.RcodeNameError, []dns.RR{soa}, time.Minute, false)
	clk.add(2 * time.Minute)

	h := New(Options{Next: stub{resp: servfail}, Cache: c, Log: quietLogger()})
	resp := h.ServeDNS(context.Background(), request("gone.example.com", dns.TypeA))
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("got rcode %d, want NXDOMAIN from the stale negative entry", resp.Rcode)
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("stale denial carries %d authority records, want the SOA", len(resp.Ns))
	}
}

func TestMetrics(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	c.PutRRset(cache.NewKey("example.com.", dns.TypeA, dns.ClassINET),
		[]dns.RR{aRR(t, "example.com. 60 IN A 192.0.2.1")}, false)
	clk.add(2 * time.Minute)

	m := &Metrics{}
	h := New(Options{Next: stub{resp: servfail}, Cache: c, Log: quietLogger(), Metrics: m})

	h.ServeDNS(context.Background(), request("example.com", dns.TypeA))
	h.ServeDNS(context.Background(), request("nothing-cached.example.com", dns.TypeA))

	if got := m.Served.Load(); got != 1 {
		t.Fatalf("served=%d, want 1", got)
	}
	if got := m.Eligible.Load(); got != 2 {
		t.Fatalf("eligible=%d, want 2", got)
	}
	if got := m.Unavailable.Load(); got != 1 {
		t.Fatalf("unavailable=%d, want 1", got)
	}
}

// A dropped query must stay dropped rather than becoming a stale answer that
// nothing asked for.
func TestNilResponseWithNothingStale(t *testing.T) {
	clk := &clock{t: time.Now()}
	c := testCache(t, clk, time.Hour)
	h := New(Options{Cache: c, Log: quietLogger(), Next: stub{resp: func(*transport.Request) *dns.Msg { return nil }}})

	if resp := h.ServeDNS(context.Background(), request("example.com", dns.TypeA)); resp != nil {
		t.Fatal("a dropped query produced a response")
	}
}
