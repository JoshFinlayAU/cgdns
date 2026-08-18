//go:build integration

package wiring

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Prefetch once refreshed an entry by reading the very entry it meant to renew,
// so it completed instantly, changed nothing, and reported success. Every unit
// test passed. The only thing that would have caught it is asking whether a
// refresh actually reached the upstream.
func TestPrefetchReachesTheUpstream(t *testing.T) {
	up := startUpstream(t)
	up.ttl.Store(2)

	d := start(t, up.addr, `
cache_extra:
  prefetch:
    enabled: true
    threshold: 0.9
    min_ttl: 1s
    max_concurrent: 8
`)

	// Warm the entry, then keep asking as it ages so the refresh window opens.
	for i := 0; i < 12; i++ {
		if _, err := d.query("popular.test.", dns.TypeA); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		time.Sleep(250 * time.Millisecond)
	}

	triggered := d.metric(t, "cgdns_prefetch_triggered_total")
	completed := d.metric(t, "cgdns_prefetch_completed_total")
	if triggered == 0 {
		t.Fatal("prefetch never triggered: it is configured but not connected to the serving path")
	}
	if completed == 0 {
		t.Fatalf("prefetch triggered %v times but completed none", triggered)
	}

	// The refresh has to be a real query. A prefetch that answers from the
	// entry it is renewing completes just as happily and achieves nothing.
	if up.queries.Load() < 2 {
		t.Fatalf("the upstream saw %d queries: the refresh never left the daemon", up.queries.Load())
	}
}

// Serve-stale is only worth having if it answers when resolution fails. The
// wiring question is whether the decorator sits in the serving path at all.
func TestServeStaleAnswersWhenUpstreamFails(t *testing.T) {
	up := startUpstream(t)
	up.ttl.Store(1)

	// Prefetch is off deliberately. It is on by default, and it refreshes an
	// entry near the end of its life — which for a one-second TTL lands inside
	// this test's own wait and hands the entry a fresh lease. The answer then
	// comes from a live cache entry rather than a stale one, and the test fails
	// intermittently for a reason that has nothing to do with serve-stale.
	d := start(t, up.addr, `
cache_extra:
  serve_stale:
    enabled: true
    max_stale: 1h
    answer_ttl: 30s
  prefetch:
    enabled: false
`)

	if _, err := d.query("cached.test.", dns.TypeA); err != nil {
		t.Fatalf("warming the cache: %v", err)
	}
	// Let the entry expire, then take the upstream away.
	time.Sleep(1500 * time.Millisecond)
	up.failing.Store(true)

	// Generous, because serve-stale answers only after resolution has failed:
	// the query timeout and its retries elapse first.
	resp, err := d.queryWithin("cached.test.", dns.TypeA, 15*time.Second)
	if err != nil {
		t.Fatalf("query with the upstream down: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("no stale answer: rcode %s, %d answers — serve-stale is configured but not in the serving path",
			dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	if resp.AuthenticatedData {
		t.Error("a stale answer set AD; expired data has not been validated now")
	}
	if served := d.metric(t, "cgdns_serve_stale_served_total"); served == 0 {
		t.Error("an answer came back but the serve-stale counter did not move")
	}
}

// Rate limiting protects the node and the zones it would otherwise amplify
// against. If the handler is not in the chain, the limits are decoration.
func TestRateLimitDropsUnderFlood(t *testing.T) {
	up := startUpstream(t)

	d := start(t, up.addr, `
rate_limit:
  enabled: true
  window: 1s
  denials_per_second: 5
  errors_per_second: 5
  responses_per_second: 0
  slip_ratio: 0
  ipv4_prefix_len: 32
  ipv6_prefix_len: 128
  max_buckets: 1000
`)

	// Distinct names under a zone that answers NXDOMAIN, which is the class the
	// denial limit governs. They must be well formed, or they are rejected as
	// malformed before the limiter is ever consulted.
	for i := 0; i < 300; i++ {
		d.flood(fmt.Sprintf("absent.n%d.test.", i), dns.TypeA)
	}

	evaluated := d.metric(t, "cgdns_ratelimit_evaluated_total")
	if evaluated == 0 {
		t.Fatal("the rate limiter evaluated nothing: it is configured but not in the serving path")
	}
	if dropped := d.metric(t, "cgdns_ratelimit_dropped_total"); dropped == 0 {
		t.Fatalf("evaluated %v queries under a 5/s denial limit and dropped none", evaluated)
	}
}

// The metrics endpoint is how an operator sees any of this. A feature that is
// enabled must be visible, or the first sign of trouble is a subscriber.
func TestEnabledFeaturesAreObservable(t *testing.T) {
	up := startUpstream(t)
	d := start(t, up.addr, `
cache_extra:
  prefetch:
    enabled: true
    threshold: 0.9
    min_ttl: 1s
    max_concurrent: 4
  serve_stale:
    enabled: true
    max_stale: 1h
    answer_ttl: 30s
rate_limit:
  enabled: true
  window: 1s
  denials_per_second: 50
  errors_per_second: 20
  responses_per_second: 0
  slip_ratio: 2
  ipv4_prefix_len: 24
  ipv6_prefix_len: 56
  max_buckets: 1000
`)

	if _, err := d.query("visible.test.", dns.TypeA); err != nil {
		t.Fatalf("query: %v", err)
	}

	// Each of these exists only when its feature was actually constructed.
	for _, name := range []string{
		"cgdns_queries_total",
		"cgdns_prefetch_triggered_total",
		"cgdns_serve_stale_served_total",
		"cgdns_ratelimit_evaluated_total",
	} {
		if got := d.metric(t, name); got < 0 {
			t.Errorf("%s is missing from /metrics", name)
		}
	}
	if q := d.metric(t, "cgdns_queries_total"); q == 0 {
		t.Error("cgdns_queries_total did not move after a query")
	}
}

// Cache hit ratio is the first number anyone asks a resolver for, and it was
// unreadable in production for days: the exported counter was fed by the
// forwarder, which a recursive POP never runs, so it read zero for ever while
// the cache underneath was working perfectly.
func TestCacheHitsAreCounted(t *testing.T) {
	up := startUpstream(t)
	up.ttl.Store(60)
	d := start(t, up.addr, "")

	for i := 0; i < 3; i++ {
		if _, err := d.query("repeat.test.", dns.TypeA); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}

	hits := d.metric(t, "cgdns_cache_lookup_hits_total")
	misses := d.metric(t, "cgdns_cache_lookup_misses_total")
	if hits == 0 {
		t.Errorf("asked the same name three times and the cache reported no lookup hits (misses=%v)", misses)
	}
	if misses == 0 {
		t.Error("the first query cannot have been a hit, so misses should have moved too")
	}

	// The ratio an operator reads is client queries that needed no outbound
	// query at all, which is a different number from cache lookups and the one
	// that was silently zero in production.
	if fromCache := d.metric(t, "cgdns_queries_from_cache_total"); fromCache == 0 {
		t.Error("repeat queries were served without any of them counting as answered from cache")
	}
}
