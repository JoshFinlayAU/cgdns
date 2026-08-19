package policy

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/subscriber"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

type passthruHandler struct{ called bool }

func (h *passthruHandler) ServeDNS(_ context.Context, req *transport.Request) *dns.Msg {
	h.called = true
	m := new(dns.Msg)
	m.SetReply(req.Msg)
	return m
}

func ruleSetWith(name string, action Action) *Set {
	s := NewSet()
	s.AddExact(dns.CanonicalName(name), Rule{Action: action, Feed: "test", TTL: 60})
	return s
}

// A subscriber allow is deliberately powerful — it exists so one customer can
// be unblocked without editing a shared list. The compliance tier is the one
// thing it must not reach: where a jurisdiction requires a block, "the
// subscriber asked us not to" is not a defence.
func TestMandatoryBeatsASubscriberAllow(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	reg.ReplaceMandatory(&Policy{Rules: ruleSetWith("blocked.example.", ActionNXDOMAIN)})
	reg.ReplaceOverrides(map[string]*Overrides{
		"sub1": {Allow: ruleSetWith("blocked.example.", ActionPassthru), Block: NewSet()},
	})

	cls := subscriber.New("none")
	cls.Replace([]subscriber.Entry{{
		Prefix:     netip.MustParsePrefix("192.0.2.0/24"),
		Subscriber: subscriber.Subscriber{ID: "sub1", Class: "none"},
	}})

	next := &passthruHandler{}
	e := NewEnforcer(Options{Classifier: cls, Registry: reg, Next: next, Log: quietLogger(), Metrics: &Metrics{}})

	req := new(dns.Msg)
	req.SetQuestion("blocked.example.", dns.TypeA)
	resp := e.ServeDNS(context.Background(), &transport.Request{
		Msg:      req,
		Client:   netip.MustParseAddrPort("192.0.2.10:1234"),
		Received: time.Now(),
	})

	if next.called {
		t.Fatal("a subscriber allow reached past the compliance tier")
	}
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %v, want NXDOMAIN from the mandatory rule", resp)
	}
}

// A subscriber with no policy at all still gets the compliance tier: the
// obligation does not depend on which product tier somebody bought.
func TestMandatoryAppliesWithNoPolicy(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	reg.ReplaceMandatory(&Policy{Rules: ruleSetWith("blocked.example.", ActionNXDOMAIN)})

	cls := subscriber.New("none")
	next := &passthruHandler{}
	e := NewEnforcer(Options{Classifier: cls, Registry: reg, Next: next, Log: quietLogger(), Metrics: &Metrics{}})

	req := new(dns.Msg)
	req.SetQuestion("blocked.example.", dns.TypeA)
	resp := e.ServeDNS(context.Background(), &transport.Request{
		Msg:      req,
		Client:   netip.MustParseAddrPort("198.51.100.5:1234"),
		Received: time.Now(),
	})
	if next.called {
		t.Fatal("an unclassified client bypassed the compliance tier")
	}
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatal("the mandatory rule did not apply to a subscriber with no policy")
	}
}

// Everything not named by the compliance tier must pass through it untouched.
// A tier that cannot be overridden has to be narrow.
func TestMandatoryDoesNotTouchAnythingElse(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	reg.ReplaceMandatory(&Policy{Rules: ruleSetWith("blocked.example.", ActionNXDOMAIN)})

	cls := subscriber.New("none")
	next := &passthruHandler{}
	e := NewEnforcer(Options{Classifier: cls, Registry: reg, Next: next, Log: quietLogger(), Metrics: &Metrics{}})

	req := new(dns.Msg)
	req.SetQuestion("ordinary.example.", dns.TypeA)
	_ = e.ServeDNS(context.Background(), &transport.Request{
		Msg:      req,
		Client:   netip.MustParseAddrPort("198.51.100.5:1234"),
		Received: time.Now(),
	})
	if !next.called {
		t.Error("a name the compliance tier does not list was blocked anyway")
	}
}
