package ratelimit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/netacl"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testLimiter(t *testing.T, opts Options) *Limiter {
	t.Helper()
	l, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func key(prefix string, class Class, name string) Key {
	return Key{Prefix: netip.MustParsePrefix(prefix), Class: class, Name: name}
}

func TestLimiter_AllowsUpToTheRateThenLimits(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 5, Window: time.Second, SlipRatio: 0})

	k := key("203.0.113.0/24", ClassDenial, "victim.com.")

	allowed := 0
	for range 20 {
		if l.Allow(k, base) == ActionAllow {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("allowed %d in a burst, want 5 (rate 5/s, window 1s)", allowed)
	}
}

// A rate of zero means unlimited, which is how an operator keeps limiting for
// denials while leaving answers alone.
func TestLimiter_ZeroRateIsUnlimited(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 1, ResponsesPerSecond: 0, Window: time.Second})

	for i := range 1000 {
		if got := l.Allow(key("203.0.113.0/24", ClassAnswer, "example.com."), base); got != ActionAllow {
			t.Fatalf("answer %d was %s, want allow", i, got)
		}
	}
}

func TestLimiter_CreditRefills(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 10, Window: time.Second})
	k := key("203.0.113.0/24", ClassDenial, "victim.com.")

	for range 10 {
		l.Allow(k, base)
	}
	if got := l.Allow(k, base); got == ActionAllow {
		t.Fatal("bucket should be empty")
	}

	// Half a second buys five more.
	later := base.Add(500 * time.Millisecond)
	allowed := 0
	for range 10 {
		if l.Allow(k, later) == ActionAllow {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("allowed %d after 500ms at 10/s, want 5", allowed)
	}
}

// A client that has been around and quiet may bank up to the window, but no
// further: being idle for an hour must not buy an hour's worth of burst.
func TestLimiter_WindowCapsBanking(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 10, Window: 2 * time.Second})
	k := key("203.0.113.0/24", ClassDenial, "victim.com.")

	l.Allow(k, base) // establishes the bucket

	allowed := 0
	for range 100 {
		if l.Allow(k, base.Add(time.Hour)) == ActionAllow {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("allowed %d after an idle hour, want 20 (10/s x 2s window)", allowed)
	}
}

// A source nobody has seen before has earned nothing, so it starts with one
// second of allowance rather than a full window. Starting it full would hand
// every fresh prefix a free burst, and an attacker spoofing across a range
// would never reuse a bucket.
func TestLimiter_NewBucketGetsOneSecondNotAWholeWindow(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 10, Window: 60 * time.Second, SlipRatio: 0})

	allowed := 0
	for range 500 {
		if l.Allow(key("203.0.113.0/24", ClassDenial, "victim.com."), base) == ActionAllow {
			allowed++
		}
	}
	if allowed != 10 {
		t.Fatalf("a first-contact source got %d responses, want 10 (one second at 10/s, not the 600 a full window would give)", allowed)
	}
}

func TestLimiter_SlipRatio(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 1, Window: time.Second, SlipRatio: 2})
	k := key("203.0.113.0/24", ClassDenial, "victim.com.")

	l.Allow(k, base) // consumes the single credit

	var drops, slips int
	for range 10 {
		switch l.Allow(k, base) {
		case ActionDrop:
			drops++
		case ActionSlip:
			slips++
		}
	}
	if slips != 5 || drops != 5 {
		t.Fatalf("slips=%d drops=%d, want 5 and 5 at a slip ratio of 2", slips, drops)
	}
}

func TestLimiter_SlipRatioZeroAlwaysDrops(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 1, Window: time.Second, SlipRatio: 0})
	k := key("203.0.113.0/24", ClassDenial, "victim.com.")
	l.Allow(k, base)

	for range 10 {
		if got := l.Allow(k, base); got != ActionDrop {
			t.Fatalf("got %s, want drop", got)
		}
	}
}

// Different clients, classes and names must not share a bucket, or one busy
// client would limit everyone else.
func TestLimiter_BucketsAreIndependent(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 1, ResponsesPerSecond: 1, Window: time.Second})

	for _, k := range []Key{
		key("203.0.113.0/24", ClassDenial, "victim.com."),
		key("198.51.100.0/24", ClassDenial, "victim.com."),
		key("203.0.113.0/24", ClassDenial, "other.com."),
		key("203.0.113.0/24", ClassAnswer, "victim.com."),
	} {
		if got := l.Allow(k, base); got != ActionAllow {
			t.Fatalf("%v: got %s, want allow", k, got)
		}
	}
}

func TestLimiter_Mask(t *testing.T) {
	l := testLimiter(t, Options{IPv4PrefixLen: 24, IPv6PrefixLen: 56})
	for in, want := range map[string]string{
		"203.0.113.45":        "203.0.113.0/24",
		"203.0.113.200":       "203.0.113.0/24",
		"2001:db8:1:2:3::4":   "2001:db8:1::/56",
		"2001:db8:1:99:3::4":  "2001:db8:1::/56",
		"2001:db8:1:100:3::4": "2001:db8:1:100::/56",
		"::ffff:203.0.113.45": "203.0.113.0/24",
	} {
		got := l.Mask(netip.MustParseAddr(in))
		if got != netip.MustParsePrefix(want) {
			t.Fatalf("Mask(%s) = %s, want %s", in, got, want)
		}
	}
}

// The table must not become the attack. An attacker spoofing across a huge
// range should be bounded by MaxBuckets, not by memory.
func TestLimiter_BoundsBucketCount(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 1, Window: time.Second, MaxBuckets: 256, Shards: 4})

	for i := range 20000 {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		l.Allow(Key{Prefix: l.Mask(addr), Class: ClassDenial, Name: "victim.com."}, base)
	}

	if n := l.Len(); n > 256 {
		t.Fatalf("held %d buckets, want at most 256", n)
	}
	// A full table must still limit; refusing to create buckets would let an
	// attacker switch limiting off by filling it.
	k := key("203.0.113.0/24", ClassDenial, "victim.com.")
	l.Allow(k, base)
	if got := l.Allow(k, base); got == ActionAllow {
		t.Fatal("a full table stopped limiting")
	}
}

func TestLimiter_SweepDropsIdleBuckets(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 1, Window: time.Second})

	for i := range 100 {
		addr := netip.AddrFrom4([4]byte{203, 0, byte(i), 1})
		l.Allow(Key{Prefix: l.Mask(addr), Class: ClassDenial, Name: "victim.com."}, base)
	}
	if l.Len() != 100 {
		t.Fatalf("held %d buckets, want 100", l.Len())
	}

	if removed := l.Sweep(base.Add(time.Second)); removed != 0 {
		t.Fatalf("swept %d buckets that were not idle", removed)
	}
	if removed := l.Sweep(base.Add(time.Hour)); removed != 100 {
		t.Fatalf("swept %d idle buckets, want 100", removed)
	}
	if l.Len() != 0 {
		t.Fatalf("%d buckets survived the sweep", l.Len())
	}
}

func TestNew_RejectsNegativeRates(t *testing.T) {
	if _, err := New(Options{DenialsPerSecond: -1}); err == nil {
		t.Fatal("expected an error")
	}
}

// --- handler ---

type stubHandler struct {
	resp func(req *transport.Request) *dns.Msg
}

func (s stubHandler) ServeDNS(_ context.Context, req *transport.Request) *dns.Msg {
	return s.resp(req)
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func nxdomainFrom(zone string, req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)
	soa, err := dns.NewRR(zone + " 300 IN SOA ns.example. hostmaster.example. 1 2 3 4 300")
	if err != nil {
		panic(err)
	}
	m.Ns = []dns.RR{soa}
	return m
}

func request(client, name string, qtype uint16, proto transport.Proto) *transport.Request {
	return &transport.Request{
		Msg:    query(name, qtype),
		Client: netip.MustParseAddrPort(client),
		Proto:  proto,
	}
}

func testHandler(t *testing.T, l *Limiter, next transport.Handler, exempt *netacl.ACL) *Handler {
	t.Helper()
	return NewHandler(HandlerOptions{Limiter: l, Next: next, Exempt: exempt, Log: quietLogger()})
}

// The attack this package exists to stop: every query carries a fresh QNAME, so
// grouping by QNAME would give each one its own bucket and limit nothing.
func TestHandler_RandomSubdomainFloodCollapsesIntoOneBucket(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 10, Window: time.Second, SlipRatio: 0, Now: func() time.Time { return base }})
	next := stubHandler{resp: func(req *transport.Request) *dns.Msg {
		return nxdomainFrom("victim.com.", req.Msg)
	}}
	h := NewHandler(HandlerOptions{Limiter: l, Next: next, Log: quietLogger(), Now: func() time.Time { return base }})

	answered := 0
	for i := range 500 {
		req := request("203.0.113.9:5300", fmt.Sprintf("r%d.victim.com", i), dns.TypeA, transport.ProtoUDP)
		if h.ServeDNS(context.Background(), req) != nil {
			answered++
		}
	}
	if answered != 10 {
		t.Fatalf("answered %d of 500 flood queries, want 10 (the denial rate); the flood is not collapsing into one bucket", answered)
	}
	if n := l.Len(); n != 1 {
		t.Fatalf("the flood created %d buckets, want 1", n)
	}
}

// Without an SOA the grouping must still hold, or an authoritative that omits
// one would hand an attacker a way around the limit.
func TestHandler_FloodWithoutSOAStillCollapses(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 10, Window: time.Second})
	next := stubHandler{resp: func(req *transport.Request) *dns.Msg {
		m := new(dns.Msg)
		m.SetRcode(req.Msg, dns.RcodeNameError)
		return m
	}}
	h := NewHandler(HandlerOptions{Limiter: l, Next: next, Log: quietLogger(), Now: func() time.Time { return base }})

	for i := range 200 {
		req := request("203.0.113.9:5300", fmt.Sprintf("r%d.victim.com", i), dns.TypeA, transport.ProtoUDP)
		h.ServeDNS(context.Background(), req)
	}
	if n := l.Len(); n != 1 {
		t.Fatalf("created %d buckets without an SOA, want 1", n)
	}
}

// A flood must not take out ordinary resolution for the same client.
func TestHandler_FloodDoesNotStarveRealAnswers(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 5, ResponsesPerSecond: 100, Window: time.Second})
	next := stubHandler{resp: func(req *transport.Request) *dns.Msg {
		q := req.Msg.Question[0]
		if q.Name == "good.example.com." {
			m := new(dns.Msg)
			m.SetReply(req.Msg)
			rr, _ := dns.NewRR("good.example.com. 300 IN A 192.0.2.1")
			m.Answer = []dns.RR{rr}
			return m
		}
		return nxdomainFrom("victim.com.", req.Msg)
	}}
	h := NewHandler(HandlerOptions{Limiter: l, Next: next, Log: quietLogger(), Now: func() time.Time { return base }})

	for i := range 200 {
		h.ServeDNS(context.Background(), request("203.0.113.9:5300", fmt.Sprintf("r%d.victim.com", i), dns.TypeA, transport.ProtoUDP))
	}

	answered := 0
	for range 50 {
		if h.ServeDNS(context.Background(), request("203.0.113.9:5300", "good.example.com", dns.TypeA, transport.ProtoUDP)) != nil {
			answered++
		}
	}
	if answered != 50 {
		t.Fatalf("a denial flood starved %d of 50 real answers", 50-answered)
	}
}

// TCP, DoT and DoH complete a handshake, so there is nothing to spoof and
// nothing to reflect. Limiting them would only punish provably real clients.
func TestHandler_OnlyLimitsUDP(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 1, Window: time.Second})
	next := stubHandler{resp: func(req *transport.Request) *dns.Msg {
		return nxdomainFrom("victim.com.", req.Msg)
	}}
	h := NewHandler(HandlerOptions{Limiter: l, Next: next, Log: quietLogger(), Now: func() time.Time { return base }})

	for _, proto := range []transport.Proto{transport.ProtoTCP, transport.ProtoDoT, transport.ProtoDoH} {
		for i := range 100 {
			req := request("203.0.113.9:5300", fmt.Sprintf("r%d.victim.com", i), dns.TypeA, proto)
			if h.ServeDNS(context.Background(), req) == nil {
				t.Fatalf("%s response %d was dropped", proto, i)
			}
		}
	}
}

func TestHandler_SlipSendsTruncated(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 1, Window: time.Second, SlipRatio: 1})
	next := stubHandler{resp: func(req *transport.Request) *dns.Msg {
		return nxdomainFrom("victim.com.", req.Msg)
	}}
	h := NewHandler(HandlerOptions{Limiter: l, Next: next, Log: quietLogger(), Now: func() time.Time { return base }})

	h.ServeDNS(context.Background(), request("203.0.113.9:5300", "a.victim.com", dns.TypeA, transport.ProtoUDP))

	resp := h.ServeDNS(context.Background(), request("203.0.113.9:5300", "b.victim.com", dns.TypeA, transport.ProtoUDP))
	if resp == nil {
		t.Fatal("a slip should send a response, not drop")
	}
	if !resp.Truncated {
		t.Fatal("the slipped response is not truncated, so the client will not retry over TCP")
	}
	if len(resp.Answer) != 0 || len(resp.Ns) != 0 || len(resp.Extra) != 0 {
		t.Fatal("the slipped response carries records, which is exactly the amplification it exists to avoid")
	}
	if len(resp.Question) != 1 || resp.Question[0].Name != "b.victim.com." {
		t.Fatalf("the slipped response does not echo the question: %+v", resp.Question)
	}
}

func TestHandler_ExemptClientsAreNeverLimited(t *testing.T) {
	base := time.Now()
	l := testLimiter(t, Options{DenialsPerSecond: 1, Window: time.Second})
	next := stubHandler{resp: func(req *transport.Request) *dns.Msg {
		return nxdomainFrom("victim.com.", req.Msg)
	}}
	exempt := netacl.New([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, false)
	h := NewHandler(HandlerOptions{Limiter: l, Next: next, Exempt: exempt, Log: quietLogger(), Now: func() time.Time { return base }})

	for i := range 100 {
		req := request("203.0.113.9:5300", fmt.Sprintf("r%d.victim.com", i), dns.TypeA, transport.ProtoUDP)
		if h.ServeDNS(context.Background(), req) == nil {
			t.Fatalf("exempt client was limited at query %d", i)
		}
	}

	// A client outside the exemption is still limited.
	limited := false
	for i := range 100 {
		req := request("198.51.100.9:5300", fmt.Sprintf("r%d.victim.com", i), dns.TypeA, transport.ProtoUDP)
		if h.ServeDNS(context.Background(), req) == nil {
			limited = true
		}
	}
	if !limited {
		t.Fatal("a non-exempt client was never limited")
	}
}

// A dropped query must produce no response at all, rather than an empty one:
// the point is that a spoofed victim receives nothing.
func TestHandler_PassesThroughANilResponse(t *testing.T) {
	l := testLimiter(t, Options{DenialsPerSecond: 1, Window: time.Second})
	next := stubHandler{resp: func(*transport.Request) *dns.Msg { return nil }}
	h := testHandler(t, l, next, nil)

	if resp := h.ServeDNS(context.Background(), request("203.0.113.9:5300", "a.example.com", dns.TypeA, transport.ProtoUDP)); resp != nil {
		t.Fatal("a nil response from the resolver must stay nil")
	}
}

func TestDenialZone(t *testing.T) {
	for _, tc := range []struct{ name, qname, soa, want string }{
		{"soa wins", "random.victim.com.", "victim.com.", "victim.com."},
		{"deep name, shallow zone", "a.b.c.victim.com.", "victim.com.", "victim.com."},
		{"no soa strips one label", "random.victim.com.", "", "victim.com."},
		{"no soa, apex", "victim.com.", "", "com."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &transport.Request{Msg: query(tc.qname, dns.TypeA)}
			resp := new(dns.Msg)
			resp.SetRcode(req.Msg, dns.RcodeNameError)
			if tc.soa != "" {
				rr, err := dns.NewRR(tc.soa + " 300 IN SOA ns.x. hm.x. 1 2 3 4 300")
				if err != nil {
					t.Fatal(err)
				}
				resp.Ns = []dns.RR{rr}
			}
			if got := denialZone(req, resp); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCutLabel(t *testing.T) {
	for _, tc := range []struct {
		in, label, rest string
		found           bool
	}{
		{"a.b.c.", "a", "b.c.", true},
		{"victim.com.", "victim", "com.", true},
		{"com.", "com", ".", true},
		{".", "", ".", false},
		{"", "", ".", false},
	} {
		label, rest, found := cutLabel(tc.in)
		if label != tc.label || rest != tc.rest || found != tc.found {
			t.Fatalf("cutLabel(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, label, rest, found, tc.label, tc.rest, tc.found)
		}
	}
}

func BenchmarkLimiter_Allow(b *testing.B) {
	now := time.Now()
	l, err := New(Options{DenialsPerSecond: 1000000, Window: time.Second})
	if err != nil {
		b.Fatal(err)
	}
	k := key("203.0.113.0/24", ClassDenial, "victim.com.")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		l.Allow(k, now)
	}
}
