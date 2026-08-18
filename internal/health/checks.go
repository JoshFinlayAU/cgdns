package health

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// ResolveCheck answers "can this node actually resolve".
//
// It goes through the same transport.Handler that serves subscribers, so a
// failure here means real queries are failing too. Probing a private code path
// instead would prove only that the probe works — the node would keep
// advertising while every subscriber query returned SERVFAIL.
type ResolveCheck struct {
	// Name identifies the check in logs and the operator API.
	CheckName string
	// Handler is the live resolver.
	Handler transport.Handler
	// QName and QType are what to ask.
	QName string
	QType uint16
	// RequireAnswer fails the check when the response carries no answer
	// records. Leave false for probes where NOERROR alone is success.
	RequireAnswer bool
	// AcceptStale allows a stale answer (RFC 8767, EDE 3) to satisfy the check.
	//
	// It must stay false for any probe that decides anycast membership. Health
	// asks "can this node resolve", and serve-stale is designed to keep
	// answering when it cannot — so a probe that accepts stale data would let a
	// node cut off from the internet pass its checks forever on cached root
	// data, holding a prefix it can no longer serve while a working POP sits
	// idle.
	AcceptStale bool

	// Client is the source address the probe presents.
	//
	// The probe calls the handler directly, so listen.allow_query never sees
	// it. Subscriber policy does: the address decides which class the probe is
	// classified into, so pointing it at a filtered range would let a policy
	// block look like a health failure and withdraw the node.
	Client netip.AddrPort
}

// Name implements Checker.
func (c *ResolveCheck) Name() string {
	if c.CheckName != "" {
		return c.CheckName
	}
	return "resolve:" + c.QName
}

// Check implements Checker.
func (c *ResolveCheck) Check(ctx context.Context) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(c.QName), c.QType)
	m.RecursionDesired = true

	req := &transport.Request{
		Msg:             m,
		Client:          c.Client,
		Local:           c.Client.Addr(),
		Proto:           transport.ProtoUDP,
		Internal:        true,
		Received:        time.Now(),
		MaxResponseSize: dns.MaxMsgSize,
	}

	resp := c.Handler.ServeDNS(ctx, req)
	if resp == nil {
		return fmt.Errorf("resolver returned no response for %s %s", c.QName, dns.TypeToString[c.QType])
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("%s %s returned %s", c.QName, dns.TypeToString[c.QType], dns.RcodeToString[resp.Rcode])
	}
	if c.RequireAnswer && len(resp.Answer) == 0 {
		return fmt.Errorf("%s %s returned no answer records", c.QName, dns.TypeToString[c.QType])
	}
	if !c.AcceptStale && isStale(resp) {
		return fmt.Errorf("%s %s was answered from expired cache, so this node is not resolving", c.QName, dns.TypeToString[c.QType])
	}
	return nil
}

// isStale reports whether a response was served from expired data.
func isStale(resp *dns.Msg) bool {
	opt := resp.IsEdns0()
	if opt == nil {
		return false
	}
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok && ede.InfoCode == dns.ExtendedErrorCodeStaleAnswer {
			return true
		}
	}
	return false
}

// RootCheck probes the root zone.
//
// It is the most useful single check a recursive resolver can run: it exercises
// the root hints, outbound reachability, the delegation walk and — when
// validation is on — the trust anchor, without depending on any third party's
// zone staying up. A canary pointed at someone else's domain fails when their
// zone breaks, and withdrawing a healthy node because of someone else's outage
// is worse than not checking at all.
func RootCheck(h transport.Handler, client netip.AddrPort) *ResolveCheck {
	return &ResolveCheck{
		CheckName:     "root-ns",
		Handler:       h,
		QName:         ".",
		QType:         dns.TypeNS,
		RequireAnswer: true,
		Client:        client,
	}
}

// CanaryCheck probes an operator-chosen name.
//
// Use it in addition to RootCheck, never instead of it.
func CanaryCheck(h transport.Handler, name string, client netip.AddrPort) *ResolveCheck {
	return &ResolveCheck{
		CheckName:     "canary:" + name,
		Handler:       h,
		QName:         name,
		QType:         dns.TypeA,
		RequireAnswer: true,
		Client:        client,
	}
}

// FuncCheck adapts a function to Checker, for checks that are not queries.
type FuncCheck struct {
	CheckName string
	Fn        func(ctx context.Context) error
}

// Name implements Checker.
func (f *FuncCheck) Name() string { return f.CheckName }

// Check implements Checker.
func (f *FuncCheck) Check(ctx context.Context) error { return f.Fn(ctx) }
