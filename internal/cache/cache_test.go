package cache

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// clock is a controllable time source; cache behaviour is almost entirely
// about time, and sleeping in tests makes them slow and flaky.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testOptions(clk *clock) Options {
	return Options{
		MaxEntries:     1024,
		Shards:         16,
		MinTTL:         5 * time.Second,
		MaxTTL:         time.Hour,
		MaxNegativeTTL: 10 * time.Minute,
		Now:            clk.Now,
	}
}

func aRecord(t *testing.T, name string, ttl uint32, ip string) dns.RR {
	t.Helper()
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	}
	if rr.A == nil {
		t.Fatalf("bad test IP %q", ip)
	}
	return rr
}

func TestNew_RejectsBadOptions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"shards not power of two", func(o *Options) { o.Shards = 15 }},
		{"zero shards", func(o *Options) { o.Shards = 0 }},
		{"max entries below shards", func(o *Options) { o.MaxEntries = 4; o.Shards = 16 }},
		{"zero max ttl", func(o *Options) { o.MaxTTL = 0 }},
		{"zero max negative ttl", func(o *Options) { o.MaxNegativeTTL = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := testOptions(newClock())
			tt.mutate(&opts)
			if _, err := New(opts); err == nil {
				t.Fatal("expected New to reject the options")
			}
		})
	}
}

func TestGetPut_RoundTrip(t *testing.T) {
	clk := newClock()
	c, err := New(testOptions(clk))
	if err != nil {
		t.Fatal(err)
	}

	key := NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{aRecord(t, "example.com.", 300, "192.0.2.1")}, false)

	entry, ok := c.Get(key)
	if !ok {
		t.Fatal("expected a cache hit")
	}
	if len(entry.RRs) != 1 {
		t.Fatalf("expected 1 RR, got %d", len(entry.RRs))
	}
	if entry.Kind != KindAnswer {
		t.Errorf("Kind = %v, want KindAnswer", entry.Kind)
	}
}

// A served answer must carry the TTL that remains, not the one we learned.
// Getting this wrong is what makes a shared or long-lived cache resurrect
// records that should have expired.
func TestRRsAt_CountsTTLDown(t *testing.T) {
	clk := newClock()
	c, _ := New(testOptions(clk))

	key := NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{aRecord(t, "example.com.", 300, "192.0.2.1")}, false)

	clk.Advance(100 * time.Second)

	entry, ok := c.Get(key)
	if !ok {
		t.Fatal("expected a hit")
	}
	if got := entry.TTLAt(clk.Now()); got != 200 {
		t.Errorf("TTLAt = %d, want 200", got)
	}
	rrs := entry.RRsAt(clk.Now())
	if got := rrs[0].Header().Ttl; got != 200 {
		t.Errorf("served TTL = %d, want 200", got)
	}
	// The cached original must be untouched, or the next reader sees a TTL
	// that has already been counted down once.
	if got := entry.RRs[0].Header().Ttl; got != 300 {
		t.Errorf("cached original TTL = %d, want it left at 300", got)
	}
}

func TestGet_ExpiredEntryIsAMiss(t *testing.T) {
	clk := newClock()
	c, _ := New(testOptions(clk))

	key := NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{aRecord(t, "example.com.", 60, "192.0.2.1")}, false)

	clk.Advance(61 * time.Second)

	if _, ok := c.Get(key); ok {
		t.Fatal("expired entry must not be a hit")
	}
	if st := c.Stats(); st.Expired != 1 {
		t.Errorf("Expired = %d, want 1", st.Expired)
	}
	// It should also have been reclaimed, not merely reported as a miss.
	if c.Len() != 0 {
		t.Errorf("expired entry should be removed, Len = %d", c.Len())
	}
}

func TestPut_ClampsTTL(t *testing.T) {
	tests := []struct {
		name    string
		ttl     uint32
		wantTTL uint32
	}{
		{"below min is raised", 1, 5},
		{"within range is kept", 300, 300},
		{"above max is capped", 999999, 3600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			clk := newClock()
			c, _ := New(testOptions(clk))
			key := NewKey("example.com.", dns.TypeA, dns.ClassINET)
			c.PutRRset(key, []dns.RR{aRecord(t, "example.com.", tt.ttl, "192.0.2.1")}, false)

			entry, ok := c.Get(key)
			if !ok {
				t.Fatal("expected a hit")
			}
			if got := entry.TTLAt(clk.Now()); got != tt.wantTTL {
				t.Errorf("TTL = %d, want %d", got, tt.wantTTL)
			}
		})
	}
}

// An RRset is only as fresh as its shortest-lived record.
func TestPutRRset_UsesSmallestTTL(t *testing.T) {
	clk := newClock()
	c, _ := New(testOptions(clk))
	key := NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{
		aRecord(t, "example.com.", 600, "192.0.2.1"),
		aRecord(t, "example.com.", 120, "192.0.2.2"),
		aRecord(t, "example.com.", 300, "192.0.2.3"),
	}, false)

	entry, _ := c.Get(key)
	if got := entry.TTLAt(clk.Now()); got != 120 {
		t.Errorf("TTL = %d, want 120 (the smallest in the set)", got)
	}
}

func TestPutNegative_CapsAtMaxNegativeTTL(t *testing.T) {
	clk := newClock()
	c, _ := New(testOptions(clk))
	key := NewKey("nope.example.com.", dns.TypeA, dns.ClassINET)

	c.PutNegative(key, dns.RcodeNameError, nil, 24*time.Hour, false)

	entry, ok := c.Get(key)
	if !ok {
		t.Fatal("expected a hit")
	}
	if entry.Kind != KindNegative {
		t.Errorf("Kind = %v, want KindNegative", entry.Kind)
	}
	if entry.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want NXDOMAIN", entry.Rcode)
	}
	if got := entry.TTLAt(clk.Now()); got != 600 {
		t.Errorf("negative TTL = %d, want it capped to 600", got)
	}
}

func TestPut_ZeroTTLIsNotCached(t *testing.T) {
	clk := newClock()
	opts := testOptions(clk)
	opts.MinTTL = 0
	c, _ := New(opts)

	key := NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{aRecord(t, "example.com.", 0, "192.0.2.1")}, false)

	if _, ok := c.Get(key); ok {
		t.Fatal("a zero-TTL record must not be cached")
	}
}

func TestLRU_EvictsLeastRecentlyUsed(t *testing.T) {
	clk := newClock()
	opts := testOptions(clk)
	// One shard so eviction order is deterministic and observable.
	opts.Shards = 1
	opts.MaxEntries = 3
	c, _ := New(opts)

	keys := make([]Key, 4)
	for i := range keys {
		keys[i] = NewKey(fmt.Sprintf("host%d.example.com.", i), dns.TypeA, dns.ClassINET)
		c.PutRRset(keys[i], []dns.RR{aRecord(t, fmt.Sprintf("host%d.example.com.", i), 300, "192.0.2.1")}, false)
	}

	// keys[0] was least recently used and should have gone.
	if _, ok := c.Get(keys[0]); ok {
		t.Error("least recently used entry should have been evicted")
	}
	for _, k := range keys[1:] {
		if _, ok := c.Get(k); !ok {
			t.Errorf("entry %q should still be cached", k.Name)
		}
	}
	if st := c.Stats(); st.Evictions != 1 {
		t.Errorf("Evictions = %d, want 1", st.Evictions)
	}
}

func TestLRU_GetRefreshesRecency(t *testing.T) {
	clk := newClock()
	opts := testOptions(clk)
	opts.Shards = 1
	opts.MaxEntries = 3
	c, _ := New(opts)

	mk := func(i int) Key { return NewKey(fmt.Sprintf("h%d.example.com.", i), dns.TypeA, dns.ClassINET) }
	for i := 0; i < 3; i++ {
		c.PutRRset(mk(i), []dns.RR{aRecord(t, fmt.Sprintf("h%d.example.com.", i), 300, "192.0.2.1")}, false)
	}
	// Touch the oldest so it is no longer the eviction candidate.
	if _, ok := c.Get(mk(0)); !ok {
		t.Fatal("expected a hit")
	}
	c.PutRRset(mk(3), []dns.RR{aRecord(t, "h3.example.com.", 300, "192.0.2.1")}, false)

	if _, ok := c.Get(mk(0)); !ok {
		t.Error("recently used entry should have survived eviction")
	}
	if _, ok := c.Get(mk(1)); ok {
		t.Error("h1 should have been evicted instead")
	}
}

// 0x20 randomisation means responses come back with mixed case. If cache keys
// were not canonicalised, every such answer would miss the cache forever.
func TestCanonicalName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"example.com.", "example.com."},
		{"ExAmPlE.CoM.", "example.com."},
		{"WWW.EXAMPLE.COM.", "www.example.com."},
		{"", ""},
		{"xn--80ak6aa92e.com.", "xn--80ak6aa92e.com."},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := CanonicalName(tt.in); got != tt.want {
				t.Errorf("CanonicalName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNewKey_IsCaseInsensitive(t *testing.T) {
	clk := newClock()
	c, _ := New(testOptions(clk))

	c.PutRRset(NewKey("example.com.", dns.TypeA, dns.ClassINET),
		[]dns.RR{aRecord(t, "example.com.", 300, "192.0.2.1")}, false)

	if _, ok := c.Get(NewKey("ExAmPlE.CoM.", dns.TypeA, dns.ClassINET)); !ok {
		t.Fatal("a 0x20-randomised response must hit the same cache entry")
	}
}

func TestRemove(t *testing.T) {
	clk := newClock()
	c, _ := New(testOptions(clk))
	key := NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{aRecord(t, "example.com.", 300, "192.0.2.1")}, false)

	if !c.Remove(key) {
		t.Error("Remove should report that it removed something")
	}
	if _, ok := c.Get(key); ok {
		t.Error("entry should be gone")
	}
	if c.Remove(key) {
		t.Error("removing a missing key should report false")
	}
}

// Run with -race: the daemon is heavily concurrent and this is the type most
// exposed to it.
func TestCache_ConcurrentAccess(t *testing.T) {
	c, _ := New(testOptions(newClock()))

	const goroutines = 16
	const iterations = 500

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				name := fmt.Sprintf("h%d.example.com.", i%64)
				k := NewKey(name, dns.TypeA, dns.ClassINET)
				if i%3 == 0 {
					c.PutRRset(k, []dns.RR{aRecord(t, name, 300, "192.0.2.1")}, false)
				} else {
					if e, ok := c.Get(k); ok {
						_ = e.RRsAt(time.Now())
					}
				}
			}
		}(g)
	}
	wg.Wait()
}

func BenchmarkCache_GetHit(b *testing.B) {
	c, _ := New(Options{
		MaxEntries: 100000, Shards: 256,
		MinTTL: time.Second, MaxTTL: time.Hour, MaxNegativeTTL: time.Hour,
	})
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.1"),
	}
	key := NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, []dns.RR{rr}, false)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok := c.Get(key); !ok {
				b.Fatal("expected a hit")
			}
		}
	})
}

func BenchmarkCache_GetMiss(b *testing.B) {
	c, _ := New(Options{
		MaxEntries: 100000, Shards: 256,
		MinTTL: time.Second, MaxTTL: time.Hour, MaxNegativeTTL: time.Hour,
	})
	key := NewKey("absent.example.com.", dns.TypeA, dns.ClassINET)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Get(key)
		}
	})
}

// The allocation cost of serving from cache is dominated by copying RRs, which
// is the first thing to attack if the hot path needs to get cheaper.
func BenchmarkEntry_RRsAt(b *testing.B) {
	c, _ := New(Options{
		MaxEntries: 1000, Shards: 16,
		MinTTL: time.Second, MaxTTL: time.Hour, MaxNegativeTTL: time.Hour,
	})
	rrs := make([]dns.RR, 4)
	for i := range rrs {
		rrs[i] = &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1"),
		}
	}
	key := NewKey("example.com.", dns.TypeA, dns.ClassINET)
	c.PutRRset(key, rrs, false)
	entry, _ := c.Get(key)
	now := time.Now()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entry.RRsAt(now)
	}
}

func BenchmarkCanonicalName(b *testing.B) {
	b.Run("already lowercase", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = CanonicalName("www.example.com.")
		}
	})
	b.Run("mixed case", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = CanonicalName("WwW.ExAmPlE.CoM.")
		}
	})
}
