package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
)

// A refresh must ignore the cached copy it exists to replace. Without this the
// prefetch is a no-op: the entry is still live, so the ordinary path answers
// from cache, never contacts the authoritative and never writes anything back,
// and the entry expires exactly as it would have without prefetching.
func TestRefreshBypassesTheCachedAnswer(t *testing.T) {
	up := newFakeUpstream(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr, err := dns.NewRR("cached.example. 300 IN A 192.0.2.1")
		if err != nil {
			t.Error(err)
			return
		}
		m.Answer = []dns.RR{rr}
		_ = w.WriteMsg(m)
	})

	c, err := cache.New(cache.Options{
		MaxEntries: 128, Shards: 4,
		MinTTL: time.Second, MaxTTL: time.Hour, MaxNegativeTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := newTestForwarder(t, c, up.addr)

	// First query populates the cache.
	if resp := f.ServeDNS(context.Background(), query("cached.example.", dns.TypeA)); resp == nil || len(resp.Answer) == 0 {
		t.Fatal("first query returned nothing")
	}
	afterFirst := up.queries.Load()
	if afterFirst != 1 {
		t.Fatalf("first query made %d upstream queries, want 1", afterFirst)
	}

	// An ordinary query is served from cache and must not go upstream.
	if resp := f.ServeDNS(context.Background(), query("cached.example.", dns.TypeA)); resp == nil {
		t.Fatal("cached query returned nothing")
	}
	if got := up.queries.Load(); got != afterFirst {
		t.Fatalf("a cached query went upstream %d times", got-afterFirst)
	}

	// A refresh must go upstream even though the entry is live.
	if resp := f.ServeDNS(WithRefresh(context.Background()), query("cached.example.", dns.TypeA)); resp == nil {
		t.Fatal("refresh returned nothing")
	}
	if got := up.queries.Load(); got != afterFirst+1 {
		t.Fatalf("a refresh made %d upstream queries, want 1; the prefetch is answering from the entry it means to replace", got-afterFirst)
	}
}

func TestIsRefresh(t *testing.T) {
	if isRefresh(context.Background()) {
		t.Fatal("a plain context reported as a refresh")
	}
	if !isRefresh(WithRefresh(context.Background())) {
		t.Fatal("WithRefresh did not mark the context")
	}
	// It must survive being wrapped, since the refresh runs under a timeout.
	ctx, cancel := context.WithTimeout(WithRefresh(context.Background()), time.Second)
	defer cancel()
	if !isRefresh(ctx) {
		t.Fatal("the refresh marker did not survive a derived context")
	}
}
