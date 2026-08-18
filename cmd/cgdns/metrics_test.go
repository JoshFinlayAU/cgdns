package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/acme"
	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/metrics"
	"github.com/JoshFinlayAU/cgdns/internal/resolver"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// Cache hit ratio read zero in production for days while the cache underneath
// was working: the exported counter was fed by the forwarder's own tally, and a
// recursive POP never runs the forwarder.
//
// The wiring tests could not catch this — they drive the daemon in forward mode,
// where that tally is kept — so it is asserted here, against the registration
// itself, where the mistake actually was.
func TestCacheMetricsReflectTheCache(t *testing.T) {
	t.Parallel()

	c, err := cache.New(cache.Options{
		MaxEntries:     100,
		Shards:         4,
		MinTTL:         time.Second,
		MaxTTL:         time.Hour,
		MaxNegativeTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("building a cache: %v", err)
	}

	key := cache.NewKey("example.com.", dns.TypeA, dns.ClassINET)
	if _, ok := c.Get(key); ok {
		t.Fatal("a fresh cache returned an entry")
	}
	c.PutRRset(key, []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
	}}, false)
	for i := 0; i < 3; i++ {
		if _, ok := c.Get(key); !ok {
			t.Fatal("the entry just written is not readable")
		}
	}

	stats := c.Stats()
	if stats.Hits == 0 || stats.Misses == 0 {
		t.Fatalf("the cache itself did not record activity: %+v", stats)
	}

	reg := metrics.NewRegistry()
	registerMetrics(reg, &transport.Metrics{}, &resolver.Metrics{}, c, &acme.Metrics{})
	snap := reg.Snapshot()

	if got := snap["cgdns_cache_lookup_hits_total"]; got != float64(stats.Hits) {
		t.Errorf("cgdns_cache_lookup_hits_total = %v, cache recorded %d — the metric is not reading the cache",
			got, stats.Hits)
	}
	if got := snap["cgdns_cache_lookup_misses_total"]; got != float64(stats.Misses) {
		t.Errorf("cgdns_cache_lookup_misses_total = %v, cache recorded %d", got, stats.Misses)
	}
	if got := snap["cgdns_cache_entries"]; got != float64(stats.Entries) {
		t.Errorf("cgdns_cache_entries = %v, cache holds %d", got, stats.Entries)
	}
}
