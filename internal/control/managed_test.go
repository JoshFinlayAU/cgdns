package control

import (
	"context"
	"net/netip"
	"testing"
)

// A list maintained through the CLI must reach the query path without anything
// being fetched: a compliance instruction arrives as a name and a deadline, and
// waiting for a refresh cycle is not an answer.
func TestPublisher_ManagedEntriesNeedNoFetch(t *testing.T) {
	store, _, registry, pub := newPublisher(t)

	mustPut(t, store, KindFeed, "compliance", FeedRecord{
		Name: "compliance", Format: "rpz", Managed: true, Category: "compliance",
		Entries: []ManagedEntry{
			{Name: "banned.example", Note: "notice 2026/114"},
			{Name: "redirected.example", Action: "redirect", To: []string{"203.0.113.10"}, Note: "notice 2026/115"},
		},
	})
	mustPut(t, store, KindClass, "filtered", ClassRecord{Name: "filtered", Feeds: []string{"compliance"}, Action: "nxdomain"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pub.Run(ctx)
	waitFor(t, func() bool { return pub.PublishedVersion() >= 2 })

	pol := registry.For("filtered")
	if pol == nil {
		t.Fatal("the managed list produced no policy")
	}
	if _, ok := pol.Rules.Match("banned.example."); !ok {
		t.Error("a managed entry did not reach the query path")
	}

	// An entry is meant to cover what sits beneath it; an order naming a site
	// that only caught its apex would not do what it says.
	if _, ok := pol.Rules.Match("www.banned.example."); !ok {
		t.Error("a managed entry did not cover a subdomain")
	}

	rule, ok := pol.Rules.Match("redirected.example.")
	if !ok {
		t.Fatal("the redirect entry did not reach the query path")
	}
	if len(rule.Addrs) != 1 || rule.Addrs[0] != netip.MustParseAddr("203.0.113.10") {
		t.Errorf("redirect went to %v, want 203.0.113.10", rule.Addrs)
	}
}

// A mandatory list applies to everybody, including an address with no
// assignment at all. That is the whole reason it exists separately.
func TestPublisher_MandatoryAppliesWithNoProfile(t *testing.T) {
	store, _, registry, pub := newPublisher(t)

	mustPut(t, store, KindFeed, "court-orders", FeedRecord{
		Name: "court-orders", Format: "rpz", Managed: true, Mandatory: true,
		Entries: []ManagedEntry{{Name: "ordered.example", Note: "s115A order"}},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pub.Run(ctx)
	waitFor(t, func() bool { return pub.PublishedVersion() >= 1 })

	forced := registry.Mandatory()
	if forced == nil {
		t.Fatal("the mandatory tier was not published")
	}
	if _, ok := forced.Rules.Match("ordered.example."); !ok {
		t.Error("a mandatory entry did not reach the query path")
	}

	// It must not also appear as a class an operator could assign or,
	// worse, delete.
	if registry.For(mandatoryClass) != nil {
		t.Error("the mandatory tier is exposed as an assignable class")
	}
}

// Removing the last mandatory list has to actually clear the tier. A filter
// that cannot be lifted is its own kind of fault.
func TestPublisher_MandatoryClearsWhenRemoved(t *testing.T) {
	store, _, registry, pub := newPublisher(t)

	mustPut(t, store, KindFeed, "court-orders", FeedRecord{
		Name: "court-orders", Format: "rpz", Managed: true, Mandatory: true,
		Entries: []ManagedEntry{{Name: "ordered.example"}},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pub.Run(ctx)
	waitFor(t, func() bool { return registry.Mandatory() != nil })

	if _, err := store.Delete(KindFeed, "court-orders"); err != nil {
		t.Fatalf("deleting the list: %v", err)
	}
	waitFor(t, func() bool { return registry.Mandatory() == nil })
}
