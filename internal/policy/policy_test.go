package policy

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/subscriber"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// resolvedHandler stands in for the resolver and records whether it was
// reached, which is how the tests tell "allowed through" from "blocked".
type resolvedHandler struct{ called bool }

func (h *resolvedHandler) ServeDNS(ctx context.Context, req *transport.Request) *dns.Msg {
	h.called = true
	m := new(dns.Msg)
	m.SetReply(req.Msg)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: req.Msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   netipTo4(netip.MustParseAddr("203.0.113.10")),
	})
	return m
}

func netipTo4(a netip.Addr) []byte { return a.AsSlice() }

func request(t *testing.T, client, qname string, qtype uint16) *transport.Request {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	return &transport.Request{
		Msg:             m,
		Client:          netip.MustParseAddrPort(client),
		Local:           netip.MustParseAddr("127.0.0.1"),
		Proto:           transport.ProtoUDP,
		Received:        time.Now(),
		MaxResponseSize: 1232,
	}
}

func TestSet_MatchSpecificity(t *testing.T) {
	s := NewSet()
	s.AddWildcard("example.com.", Rule{Action: ActionNXDOMAIN, Feed: "broad"})
	s.AddExact("safe.example.com.", Rule{Action: ActionPassthru, Feed: "narrow"})
	s.AddWildcard("deep.example.com.", Rule{Action: ActionNODATA, Feed: "deeper"})

	tests := []struct {
		name   string
		qname  string
		want   Action
		wantOK bool
	}{
		{"wildcard covers a subdomain", "bad.example.com.", ActionNXDOMAIN, true},
		{"exact beats the wildcard", "safe.example.com.", ActionPassthru, true},
		{"deeper wildcard wins", "x.deep.example.com.", ActionNODATA, true},
		{"wildcard does not cover the parent itself", "example.com.", ActionNone, false},
		{"unrelated name", "example.net.", ActionNone, false},
		{"case insensitive", "BAD.EXAMPLE.COM.", ActionNXDOMAIN, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, ok := s.Match(tt.qname)
			if ok != tt.wantOK {
				t.Fatalf("matched = %v, want %v", ok, tt.wantOK)
			}
			if ok && r.Action != tt.want {
				t.Errorf("action = %s, want %s", r.Action, tt.want)
			}
		})
	}
}

func TestParseRPZ(t *testing.T) {
	zone := `
$TTL 60
rpz.athena.test.                 SOA ns.athena.test. hostmaster.athena.test. 1 3600 900 604800 60
rpz.athena.test.                 NS  ns.athena.test.
malware.example.com.rpz.athena.test.      CNAME .
*.badnet.example.rpz.athena.test.         CNAME .
nodata.example.com.rpz.athena.test.       CNAME *.
allowed.example.com.rpz.athena.test.      CNAME rpz-passthru.
silent.example.com.rpz.athena.test.       CNAME rpz-drop.
garden.example.com.rpz.athena.test.       A 192.0.2.100
rewrite.example.com.rpz.athena.test.      CNAME safe.athena.test.
`
	set, err := ParseRPZ(strings.NewReader(zone), "rpz.athena.test.", "athena-curated")
	if err != nil {
		t.Fatalf("ParseRPZ: %v", err)
	}

	tests := []struct {
		qname  string
		want   Action
		wantOK bool
	}{
		{"malware.example.com.", ActionNXDOMAIN, true},
		{"anything.badnet.example.", ActionNXDOMAIN, true},
		{"nodata.example.com.", ActionNODATA, true},
		{"allowed.example.com.", ActionPassthru, true},
		{"silent.example.com.", ActionDrop, true},
		{"garden.example.com.", ActionRedirect, true},
		{"rewrite.example.com.", ActionRewrite, true},
		{"unlisted.example.com.", ActionNone, false},
		// The RPZ zone's own SOA and NS must not become policy rules.
		{"rpz.athena.test.", ActionNone, false},
	}
	for _, tt := range tests {
		t.Run(tt.qname, func(t *testing.T) {
			t.Parallel()
			r, ok := set.Match(tt.qname)
			if ok != tt.wantOK {
				t.Fatalf("matched = %v, want %v", ok, tt.wantOK)
			}
			if ok && r.Action != tt.want {
				t.Errorf("action = %s, want %s", r.Action, tt.want)
			}
		})
	}
}

func TestParseDomainList(t *testing.T) {
	list := `
# a comment
! another comment style
malware.example.
*.tracker.example.
0.0.0.0 hosts-style.example.

`
	set, err := ParseDomainList(strings.NewReader(list), "rbl", ActionNXDOMAIN, nil)
	if err != nil {
		t.Fatalf("ParseDomainList: %v", err)
	}

	for _, qname := range []string{
		"malware.example.",
		"sub.malware.example.",
		"tracker.example.",
		"deep.sub.tracker.example.",
		"hosts-style.example.",
	} {
		if _, ok := set.Match(qname); !ok {
			t.Errorf("%s should be blocked", qname)
		}
	}
	if _, ok := set.Match("legitimate.example."); ok {
		t.Error("an unlisted name must not be blocked")
	}
}

func TestParseDomainList_RejectsGarbage(t *testing.T) {
	_, err := ParseDomainList(strings.NewReader("not a domain!!\n"), "rbl", ActionNXDOMAIN, nil)
	if err == nil {
		t.Error("expected a malformed entry to be rejected rather than silently skipped")
	}
}

// The central case: a subscriber's own allow list must beat a class feed that
// blocks the same name. Without this, an unblock means editing a shared feed.
func TestEnforcer_SubscriberWhitelistBeatsClassBlock(t *testing.T) {
	classRules := NewSet()
	classRules.AddExact("supplier.example.com.", Rule{Action: ActionNXDOMAIN, Feed: "curated-rbl"})
	classRules.AddWildcard("supplier.example.com.", Rule{Action: ActionNXDOMAIN, Feed: "curated-rbl"})

	reg := NewRegistry()
	reg.Replace(map[string]*Policy{
		"secure": {Class: "secure", Rules: classRules},
	})

	allow := NewSet()
	allow.AddExact("supplier.example.com.", Rule{Feed: "override"})
	reg.ReplaceOverrides(map[string]*Overrides{
		"acme-corp": {Allow: allow, Block: NewSet()},
	})

	cl := subscriber.New("default")
	cl.Replace([]subscriber.Entry{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Subscriber: subscriber.Subscriber{ID: "acme-corp", Class: "secure"}},
		{Prefix: netip.MustParsePrefix("198.51.101.0/24"), Subscriber: subscriber.Subscriber{ID: "other-corp", Class: "secure"}},
	})

	m := &Metrics{}
	next := &resolvedHandler{}
	e := NewEnforcer(Options{Classifier: cl, Registry: reg, Next: next, Log: quietLogger(), Metrics: m})

	t.Run("subscriber with the override reaches the name", func(t *testing.T) {
		next.called = false
		resp := e.ServeDNS(context.Background(), request(t, "198.51.100.7:1234", "supplier.example.com", dns.TypeA))
		if !next.called {
			t.Fatal("the whitelisted name should have been resolved normally")
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
		}
		if m.OverrideAllowed.Load() == 0 {
			t.Error("the override should have been counted")
		}
	})

	t.Run("another subscriber in the same class is still blocked", func(t *testing.T) {
		next.called = false
		resp := e.ServeDNS(context.Background(), request(t, "198.51.101.7:1234", "supplier.example.com", dns.TypeA))
		if next.called {
			t.Fatal("this subscriber has no override and must stay blocked")
		}
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
		}
	})
}

// An override may also add a block the class feeds do not have.
func TestEnforcer_SubscriberBlockList(t *testing.T) {
	reg := NewRegistry()
	reg.Replace(map[string]*Policy{"default": {Class: "default", Rules: NewSet()}})

	block := NewSet()
	block.AddWildcard("social.example.", Rule{Action: ActionNXDOMAIN, Feed: "parental"})
	reg.ReplaceOverrides(map[string]*Overrides{
		"family-1": {Allow: NewSet(), Block: block},
	})

	cl := subscriber.New("default")
	cl.Replace([]subscriber.Entry{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Subscriber: subscriber.Subscriber{ID: "family-1", Class: "default"}},
	})

	next := &resolvedHandler{}
	m := &Metrics{}
	e := NewEnforcer(Options{Classifier: cl, Registry: reg, Next: next, Log: quietLogger(), Metrics: m})

	resp := e.ServeDNS(context.Background(), request(t, "198.51.100.7:1234", "www.social.example", dns.TypeA))
	if next.called {
		t.Fatal("the subscriber's own block should have stopped resolution")
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if m.OverrideBlocked.Load() == 0 {
		t.Error("the override block should have been counted")
	}
}

func TestEnforcer_Actions(t *testing.T) {
	tests := []struct {
		name      string
		rule      Rule
		qtype     uint16
		wantRcode int
		wantNil   bool
		wantAnswr int
		reaches   bool
	}{
		{"nxdomain", Rule{Action: ActionNXDOMAIN}, dns.TypeA, dns.RcodeNameError, false, 0, false},
		{"nodata", Rule{Action: ActionNODATA}, dns.TypeA, dns.RcodeSuccess, false, 0, false},
		{"drop sends nothing", Rule{Action: ActionDrop}, dns.TypeA, 0, true, 0, false},
		{"redirect answers the garden address", Rule{Action: ActionRedirect, Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.100")}}, dns.TypeA, dns.RcodeSuccess, false, 1, false},
		{"rewrite answers a CNAME", Rule{Action: ActionRewrite, Target: "safe.example."}, dns.TypeA, dns.RcodeSuccess, false, 1, false},
		{"passthru resolves normally", Rule{Action: ActionPassthru}, dns.TypeA, dns.RcodeSuccess, false, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rules := NewSet()
			rules.AddExact("target.example.", tt.rule)

			reg := NewRegistry()
			reg.Replace(map[string]*Policy{"default": {Class: "default", Rules: rules}})

			cl := subscriber.New("default")
			next := &resolvedHandler{}
			e := NewEnforcer(Options{Classifier: cl, Registry: reg, Next: next, Log: quietLogger()})

			resp := e.ServeDNS(context.Background(), request(t, "198.51.100.7:1234", "target.example", tt.qtype))

			if tt.wantNil {
				if resp != nil {
					t.Fatal("a dropped query must produce no response at all")
				}
				return
			}
			if resp == nil {
				t.Fatal("expected a response")
			}
			if next.called != tt.reaches {
				t.Errorf("resolver reached = %v, want %v", next.called, tt.reaches)
			}
			if resp.Rcode != tt.wantRcode {
				t.Errorf("rcode = %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.wantRcode])
			}
			if len(resp.Answer) != tt.wantAnswr {
				t.Errorf("answers = %d, want %d", len(resp.Answer), tt.wantAnswr)
			}
		})
	}
}

// A synthesised policy answer was never validated, so it must not claim to be.
func TestEnforcer_NeverSetsAuthenticatedData(t *testing.T) {
	rules := NewSet()
	rules.AddExact("blocked.example.", Rule{Action: ActionNXDOMAIN})
	reg := NewRegistry()
	reg.Replace(map[string]*Policy{"default": {Class: "default", Rules: rules}})

	e := NewEnforcer(Options{
		Classifier: subscriber.New("default"),
		Registry:   reg,
		Next:       &resolvedHandler{},
		Log:        quietLogger(),
	})

	resp := e.ServeDNS(context.Background(), request(t, "198.51.100.7:1234", "blocked.example", dns.TypeA))
	if resp.AuthenticatedData {
		t.Error("a synthesised policy answer must never set AD")
	}
}

// A blocked answer carries an extended error, so a client can tell policy from
// a genuine NXDOMAIN.
func TestEnforcer_BlockedCarriesExtendedError(t *testing.T) {
	rules := NewSet()
	rules.AddExact("blocked.example.", Rule{Action: ActionNXDOMAIN})
	reg := NewRegistry()
	reg.Replace(map[string]*Policy{"default": {Class: "default", Rules: rules}})

	e := NewEnforcer(Options{
		Classifier: subscriber.New("default"),
		Registry:   reg,
		Next:       &resolvedHandler{},
		Log:        quietLogger(),
	})

	resp := e.ServeDNS(context.Background(), request(t, "198.51.100.7:1234", "blocked.example", dns.TypeA))
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("expected an OPT record")
	}
	found := false
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok && ede.InfoCode == dns.ExtendedErrorCodeBlocked {
			found = true
		}
	}
	if !found {
		t.Error("a policy block should carry EDE 15 (Blocked)")
	}
}

// A client matching no configured prefix still resolves, on the default class.
func TestEnforcer_UnknownClientUsesDefaultClass(t *testing.T) {
	reg := NewRegistry()
	reg.Replace(map[string]*Policy{"default": {Class: "default", Rules: NewSet()}})

	next := &resolvedHandler{}
	e := NewEnforcer(Options{
		Classifier: subscriber.New("default"),
		Registry:   reg,
		Next:       next,
		Log:        quietLogger(),
	})

	if resp := e.ServeDNS(context.Background(), request(t, "203.0.113.9:1234", "anything.example", dns.TypeA)); resp == nil {
		t.Fatal("expected a response")
	}
	if !next.called {
		t.Error("an unclassified client should still be resolved")
	}
}

func TestRegistry_ReplaceIsAtomic(t *testing.T) {
	reg := NewRegistry()
	if reg.For("nothing") != nil {
		t.Error("an empty registry should have no policies")
	}
	reg.Replace(map[string]*Policy{"Secure": {Class: "secure", Rules: NewSet()}})
	if reg.For("secure") == nil {
		t.Error("class lookup should be case insensitive")
	}
	if reg.SubscribersWithOverrides() != 0 {
		t.Error("no overrides were set")
	}
	reg.ReplaceOverrides(map[string]*Overrides{"a": {Allow: NewSet(), Block: NewSet()}})
	if reg.SubscribersWithOverrides() != 1 {
		t.Error("override count should reflect the replacement")
	}
	if reg.OverridesFor("") != nil {
		t.Error("an empty subscriber ID has no overrides")
	}
}

func BenchmarkSet_Match(b *testing.B) {
	s := NewSet()
	for i := 0; i < 100000; i++ {
		name := dns.Fqdn("blocked" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26)) + ".example")
		s.AddExact(name, Rule{Action: ActionNXDOMAIN})
		s.AddWildcard(name, Rule{Action: ActionNXDOMAIN})
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Match("www.legitimate.example.")
		}
	})
}
