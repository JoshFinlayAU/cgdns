package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// A DS RRset lives in the parent zone. Once a name's own delegation is cached —
// which any earlier lookup of that name does — a DS query must still be put to
// the parent, or the child is asked about its own delegation and refuses.
func TestDSIsAskedOfTheParent(t *testing.T) {
	t.Parallel()

	h := standardHierarchy(t)
	r := newTestRecursive(t, h)

	warm := new(dns.Msg)
	warm.SetQuestion("www.example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if resp := r.ServeDNS(ctx, &transport.Request{Msg: warm, Received: time.Now(), MaxResponseSize: 4096}); resp == nil {
		t.Fatal("warm-up query failed")
	}

	child := h.zone("example.com.")
	parent := h.zone("com.")
	childBefore, parentBefore := child.queries.Load(), parent.queries.Load()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeDS)
	if resp := r.ServeDNS(ctx, &transport.Request{Msg: q, Received: time.Now(), MaxResponseSize: 4096}); resp == nil {
		t.Fatal("no response to the DS query")
	}

	if got := parent.queries.Load() - parentBefore; got == 0 {
		t.Error("the parent was never asked for the DS; it is the only zone authoritative for it")
	}
	if got := child.queries.Load() - childBefore; got != 0 {
		t.Errorf("the child was asked %d question(s) about its own DS; it is not authoritative for that RRset", got)
	}
}
