package control

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/policy"
	"github.com/JoshFinlayAU/cgdns/internal/subscriber"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func writeFeed(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testStore(t *testing.T, nodeID string) *Store {
	t.Helper()
	s, err := Open(StoreOptions{NodeID: nodeID})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// newPublisher wires a store to live query-path structures.
func newPublisher(t *testing.T) (*Store, *subscriber.Classifier, *policy.Registry, *Publisher) {
	t.Helper()
	s := testStore(t, "ns1")
	c := subscriber.New("default")
	r := policy.NewRegistry()
	p := NewPublisher(PublisherOptions{Store: s, Classifier: c, Registry: r, Log: quietLogger()})
	return s, c, r, p
}

func TestPublisher_PublishesState(t *testing.T) {
	dir := t.TempDir()
	feed := writeFeed(t, dir, "curated.txt", "malware.example\n")

	store, classifier, registry, pub := newPublisher(t)

	mustPut(t, store, KindFeed, "curated", FeedRecord{Name: "curated", Format: "domain-list", File: feed})
	mustPut(t, store, KindClass, "secure", ClassRecord{Name: "secure", Feeds: []string{"curated"}, Action: "nxdomain"})
	mustPut(t, store, KindSubscriber, "198.51.100.0/24", SubscriberRecord{Prefix: "198.51.100.0/24", ID: "acme", Class: "secure"})
	mustPut(t, store, KindOverride, "acme", OverrideRecord{SubscriberID: "acme", Allow: []string{"supplier.example.com"}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pub.Run(ctx)

	waitFor(t, func() bool { return pub.PublishedVersion() >= 4 })

	sub := classifier.Classify(netip.MustParseAddr("198.51.100.7"))
	if sub.ID != "acme" || sub.Class != "secure" {
		t.Errorf("classified as %+v, want acme/secure", sub)
	}

	pol := registry.For("secure")
	if pol == nil {
		t.Fatal("class policy was not published")
	}
	if _, ok := pol.Rules.Match("malware.example."); !ok {
		t.Error("the feed rule was not published")
	}

	ov := registry.OverridesFor("acme")
	if ov == nil {
		t.Fatal("overrides were not published")
	}
	if _, ok := ov.Allow.Match("supplier.example.com."); !ok {
		t.Error("the subscriber whitelist was not published")
	}
}

// A feed whose content this node does not hold must not drop the rest of the
// policy: filtering degrades for that feed alone.
func TestPublisher_SkipsUnfetchedFeed(t *testing.T) {
	dir := t.TempDir()
	good := writeFeed(t, dir, "good.txt", "blocked.example\n")

	store, _, registry, pub := newPublisher(t)

	mustPut(t, store, KindFeed, "good", FeedRecord{Name: "good", Format: "domain-list", File: good})
	mustPut(t, store, KindFeed, "remote", FeedRecord{Name: "remote", Format: "domain-list", URL: "https://feeds.test/not-fetched-yet"})
	mustPut(t, store, KindClass, "secure", ClassRecord{Name: "secure", Feeds: []string{"good", "remote"}, Action: "nxdomain"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pub.Run(ctx)

	waitFor(t, func() bool { return pub.PublishedVersion() >= 3 })

	pol := registry.For("secure")
	if pol == nil {
		t.Fatal("policy was not published at all; one unfetched feed must not drop the class")
	}
	if _, ok := pol.Rules.Match("blocked.example."); !ok {
		t.Error("the fetchable feed's rules should still be live")
	}
	if pub.Failures() != 0 {
		t.Errorf("failures = %d, want 0 — a missing feed is a warning, not a rebuild failure", pub.Failures())
	}
}

// A rebuild that cannot compile must leave the previous state serving.
func TestPublisher_KeepsPreviousOnFailure(t *testing.T) {
	dir := t.TempDir()
	feed := writeFeed(t, dir, "curated.txt", "malware.example\n")

	store, _, registry, pub := newPublisher(t)
	mustPut(t, store, KindFeed, "curated", FeedRecord{Name: "curated", Format: "domain-list", File: feed})
	mustPut(t, store, KindClass, "secure", ClassRecord{Name: "secure", Feeds: []string{"curated"}, Action: "nxdomain"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pub.Run(ctx)
	waitFor(t, func() bool { return pub.PublishedVersion() >= 2 })

	// Corrupt the feed content behind the daemon's back, then force a rebuild.
	if err := os.WriteFile(feed, []byte("this is not a domain!!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustPut(t, store, KindClass, "default", ClassRecord{Name: "default"})

	waitFor(t, func() bool { return pub.Failures() > 0 })

	pol := registry.For("secure")
	if pol == nil {
		t.Fatal("previous policy was dropped after a failed rebuild")
	}
	if _, ok := pol.Rules.Match("malware.example."); !ok {
		t.Error("previous rules should still be live after a failed rebuild")
	}
}

func TestPublisher_StopsWithContext(t *testing.T) {
	_, _, _, pub := newPublisher(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pub.Run(ctx); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return when its context was cancelled")
	}
}

// A deleted subscriber must disappear from the query path, not linger.
func TestPublisher_AppliesDeletes(t *testing.T) {
	store, classifier, _, pub := newPublisher(t)
	mustPut(t, store, KindSubscriber, "198.51.100.0/24", SubscriberRecord{Prefix: "198.51.100.0/24", ID: "acme", Class: "secure"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pub.Run(ctx)
	waitFor(t, func() bool { return classifier.Classify(netip.MustParseAddr("198.51.100.7")).ID == "acme" })

	if _, err := store.Delete(KindSubscriber, "198.51.100.0/24"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	waitFor(t, func() bool { return classifier.Classify(netip.MustParseAddr("198.51.100.7")).ID == "" })
}

func mustPut(t *testing.T, s *Store, kind RecordKind, key string, payload any) {
	t.Helper()
	if _, err := s.Put(kind, key, payload); err != nil {
		t.Fatalf("Put %s %q: %v", kind, key, err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met in time")
}
