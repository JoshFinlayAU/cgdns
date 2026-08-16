package health

import (
	"context"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// Serve-stale exists to keep answering when a node cannot resolve. A health
// probe that accepts a stale answer would therefore let a node cut off from the
// internet pass forever on cached root data, holding an anycast prefix it can
// no longer serve while a working POP sits idle.
func TestResolveCheck_RejectsStaleAnswers(t *testing.T) {
	staleRoot := func() *dns.Msg {
		m := new(dns.Msg)
		q := new(dns.Msg)
		q.SetQuestion(".", dns.TypeNS)
		m.SetReply(q)
		ns, err := dns.NewRR(". 30 IN NS a.root-servers.net.")
		if err != nil {
			t.Fatal(err)
		}
		m.Answer = []dns.RR{ns}
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeStaleAnswer})
		m.Extra = append(m.Extra, opt)
		return m
	}

	handler := transport.HandlerFunc(func(_ context.Context, _ *transport.Request) *dns.Msg {
		return staleRoot()
	})
	client := netip.MustParseAddrPort("127.0.0.1:0")

	if err := RootCheck(handler, client).Check(context.Background()); err == nil {
		t.Fatal("a stale root answer satisfied the health check, so a node that cannot resolve would keep advertising")
	}

	// An operator who deliberately wants stale to count can say so.
	lenient := RootCheck(handler, client)
	lenient.AcceptStale = true
	if err := lenient.Check(context.Background()); err != nil {
		t.Fatalf("AcceptStale did not take effect: %v", err)
	}
}

// A fresh answer must still pass, or the check would fail everything.
func TestResolveCheck_AcceptsFreshAnswers(t *testing.T) {
	handler := transport.HandlerFunc(func(_ context.Context, _ *transport.Request) *dns.Msg {
		m := new(dns.Msg)
		q := new(dns.Msg)
		q.SetQuestion(".", dns.TypeNS)
		m.SetReply(q)
		ns, _ := dns.NewRR(". 3600 IN NS a.root-servers.net.")
		m.Answer = []dns.RR{ns}
		return m
	})
	if err := RootCheck(handler, netip.MustParseAddrPort("127.0.0.1:0")).Check(context.Background()); err != nil {
		t.Fatalf("a fresh answer failed the check: %v", err)
	}
}
