package prefetch

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testInner(t *testing.T, clk *clock) *cache.Cache {
	t.Helper()
	c, err := cache.New(cache.Options{
		MaxEntries: 1024, Shards: 4,
		MinTTL: time.Second, MaxTTL: 24 * time.Hour, MaxNegativeTTL: time.Hour,
		Now: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func aRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func key(name string) cache.Key { return cache.NewKey(name, dns.TypeA, dns.ClassINET) }

// recorder captures which keys were refreshed.
type recorder struct {
	mu    sync.Mutex
	calls []cache.Key
	done  chan struct{}
	block chan struct{}
	count atomic.Int64
}

func newRecorder() *recorder {
	return &recorder{done: make(chan struct{}, 64)}
}

func (r *recorder) fn(ctx context.Context, k cache.Key) {
	r.count.Add(1)
	r.mu.Lock()
	r.calls = append(r.calls, k)
	r.mu.Unlock()
	if r.block != nil {
		select {
		case <-r.block:
		case <-ctx.Done():
		}
	}
	select {
	case r.done <- struct{}{}:
	default:
	}
}

func (r *recorder) seen() []cache.Key {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]cache.Key(nil), r.calls...)
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The point of the package: a name still being asked for is refreshed before it
// expires, so no client ever pays for the upstream round trip.
func TestRefreshesAnEntryCloseToExpiry(t *testing.T) {
	clk := &clock{t: time.Now()}
	inner := testInner(t, clk)
	rec := newRecorder()

	c := New(inner, Options{Threshold: 0.1, MinTTL: 30 * time.Second, Log: quietLogger(), Now: clk.now})
	c.SetRefresh(rec.fn)
	t.Cleanup(func() { _ = c.Close() })

	k := key("example.com.")
	c.PutRRset(k, []dns.RR{aRR(t, "example.com. 300 IN A 192.0.2.1")}, false)

	// Early in its life nothing should happen.
	clk.add(100 * time.Second)
	if _, ok := c.Get(k); !ok {
		t.Fatal("entry vanished")
	}
	time.Sleep(50 * time.Millisecond)
	if n := rec.count.Load(); n != 0 {
		t.Fatalf("refreshed %d times while the entry was still fresh", n)
	}

	// Inside the last 10% of a 300s TTL.
	clk.add(180 * time.Second)
	if _, ok := c.Get(k); !ok {
		t.Fatal("entry expired early")
	}
	waitFor(t, func() bool { return rec.count.Load() == 1 }, "the refresh to run")

	if seen := rec.seen(); len(seen) != 1 || seen[0] != k {
		t.Fatalf("refreshed %v, want just %v", seen, k)
	}
}

// An entry nobody asks for must expire quietly. Refreshing it would turn the
// cache into a crawler that keeps every name it ever saw alive forever.
func TestDoesNotRefreshWhatNobodyAsksFor(t *testing.T) {
	clk := &clock{t: time.Now()}
	inner := testInner(t, clk)
	rec := newRecorder()

	c := New(inner, Options{Threshold: 0.1, MinTTL: 30 * time.Second, Log: quietLogger(), Now: clk.now})
	c.SetRefresh(rec.fn)
	t.Cleanup(func() { _ = c.Close() })

	c.PutRRset(key("unread.example.com."), []dns.RR{aRR(t, "unread.example.com. 300 IN A 192.0.2.1")}, false)
	clk.add(295 * time.Second)
	time.Sleep(50 * time.Millisecond)

	if n := rec.count.Load(); n != 0 {
		t.Fatalf("refreshed %d times without the entry ever being read", n)
	}
}

// Chasing a ten-second record generates more upstream traffic than it saves.
func TestSkipsShortLivedRecords(t *testing.T) {
	clk := &clock{t: time.Now()}
	inner := testInner(t, clk)
	rec := newRecorder()

	c := New(inner, Options{Threshold: 0.5, MinTTL: 60 * time.Second, Log: quietLogger(), Now: clk.now})
	c.SetRefresh(rec.fn)
	t.Cleanup(func() { _ = c.Close() })

	k := key("short.example.com.")
	c.PutRRset(k, []dns.RR{aRR(t, "short.example.com. 10 IN A 192.0.2.1")}, false)
	clk.add(9 * time.Second)
	c.Get(k)
	time.Sleep(50 * time.Millisecond)

	if n := rec.count.Load(); n != 0 {
		t.Fatalf("refreshed a %ds record %d times despite MinTTL", 10, n)
	}
}

// A popular name is read constantly, so without dedup every one of those reads
// would start its own upstream query -- a stampede caused by the very thing
// meant to prevent one.
func TestDeduplicatesConcurrentRefreshes(t *testing.T) {
	clk := &clock{t: time.Now()}
	inner := testInner(t, clk)
	rec := newRecorder()
	rec.block = make(chan struct{})

	c := New(inner, Options{Threshold: 0.1, MinTTL: 30 * time.Second, Log: quietLogger(), Now: clk.now})
	c.SetRefresh(rec.fn)

	k := key("popular.example.com.")
	c.PutRRset(k, []dns.RR{aRR(t, "popular.example.com. 300 IN A 192.0.2.1")}, false)
	clk.add(295 * time.Second)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Get(k)
		}()
	}
	wg.Wait()
	waitFor(t, func() bool { return rec.count.Load() >= 1 }, "the first refresh to start")
	time.Sleep(50 * time.Millisecond)

	if n := rec.count.Load(); n != 1 {
		t.Fatalf("50 concurrent reads started %d refreshes, want 1", n)
	}
	if s := c.opts.Metrics.Suppressed.Load(); s == 0 {
		t.Fatal("no refreshes were recorded as suppressed")
	}

	close(rec.block)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

// Once a refresh finishes, a later read must be able to start another.
func TestAllowsAFurtherRefreshAfterOneCompletes(t *testing.T) {
	clk := &clock{t: time.Now()}
	inner := testInner(t, clk)
	rec := newRecorder()

	c := New(inner, Options{Threshold: 0.1, MinTTL: 30 * time.Second, Log: quietLogger(), Now: clk.now})
	c.SetRefresh(rec.fn)
	t.Cleanup(func() { _ = c.Close() })

	k := key("example.com.")
	c.PutRRset(k, []dns.RR{aRR(t, "example.com. 300 IN A 192.0.2.1")}, false)
	clk.add(295 * time.Second)

	c.Get(k)
	waitFor(t, func() bool { return rec.count.Load() == 1 }, "the first refresh")
	waitFor(t, func() bool { return c.opts.Metrics.InFlight.Load() == 0 }, "the first refresh to finish")

	c.Get(k)
	waitFor(t, func() bool { return rec.count.Load() == 2 }, "the second refresh")
}

// Prefetching is an optimisation, so it must never crowd out the client queries
// it exists to speed up.
func TestCapsConcurrency(t *testing.T) {
	clk := &clock{t: time.Now()}
	inner := testInner(t, clk)
	rec := newRecorder()
	rec.block = make(chan struct{})

	c := New(inner, Options{Threshold: 0.1, MinTTL: 30 * time.Second, MaxConcurrent: 2, Log: quietLogger(), Now: clk.now})
	c.SetRefresh(rec.fn)

	names := []string{"a.example.com.", "b.example.com.", "c.example.com.", "d.example.com."}
	for _, n := range names {
		c.PutRRset(key(n), []dns.RR{aRR(t, n+" 300 IN A 192.0.2.1")}, false)
	}
	clk.add(295 * time.Second)
	for _, n := range names {
		c.Get(key(n))
	}

	waitFor(t, func() bool { return c.opts.Metrics.InFlight.Load() == 2 }, "the cap to be reached")
	time.Sleep(50 * time.Millisecond)

	if n := c.opts.Metrics.InFlight.Load(); n != 2 {
		t.Fatalf("%d refreshes in flight, want the cap of 2", n)
	}
	if d := c.opts.Metrics.Dropped.Load(); d != 2 {
		t.Fatalf("dropped %d refreshes, want 2 (four names, cap of two)", d)
	}

	close(rec.block)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

// A denial is not made more available by asking again, and a random-subdomain
// flood produces enough of them that refreshing would turn the attack into
// outbound traffic of our own.
func TestNeverRefreshesDenials(t *testing.T) {
	clk := &clock{t: time.Now()}
	inner := testInner(t, clk)
	rec := newRecorder()

	c := New(inner, Options{Threshold: 0.5, MinTTL: time.Second, Log: quietLogger(), Now: clk.now})
	c.SetRefresh(rec.fn)
	t.Cleanup(func() { _ = c.Close() })

	k := key("gone.example.com.")
	soa := aRR(t, "example.com. 300 IN SOA ns.example.com. hm.example.com. 1 2 3 4 300")
	c.PutNegative(k, dns.RcodeNameError, []dns.RR{soa}, 300*time.Second, false)

	clk.add(295 * time.Second)
	c.Get(k)
	time.Sleep(50 * time.Millisecond)

	if n := rec.count.Load(); n != 0 {
		t.Fatalf("refreshed a denial %d times", n)
	}
}

// Until a refresh function is installed the decorator must be inert rather than
// panicking on a nil call.
func TestInertWithoutARefreshFunction(t *testing.T) {
	clk := &clock{t: time.Now()}
	inner := testInner(t, clk)

	c := New(inner, Options{Threshold: 0.1, MinTTL: 30 * time.Second, Log: quietLogger(), Now: clk.now})
	t.Cleanup(func() { _ = c.Close() })

	k := key("example.com.")
	c.PutRRset(k, []dns.RR{aRR(t, "example.com. 300 IN A 192.0.2.1")}, false)
	clk.add(295 * time.Second)

	if _, ok := c.Get(k); !ok {
		t.Fatal("entry vanished")
	}
}

// An expired entry is a miss, and refreshing it here would race the resolver
// that is about to fetch it anyway.
func TestDoesNotRefreshAnExpiredEntry(t *testing.T) {
	clk := &clock{t: time.Now()}
	inner := testInner(t, clk)
	rec := newRecorder()

	c := New(inner, Options{Threshold: 0.1, MinTTL: 30 * time.Second, Log: quietLogger(), Now: clk.now})
	c.SetRefresh(rec.fn)
	t.Cleanup(func() { _ = c.Close() })

	k := key("example.com.")
	c.PutRRset(k, []dns.RR{aRR(t, "example.com. 300 IN A 192.0.2.1")}, false)
	clk.add(400 * time.Second)

	if _, ok := c.Get(k); ok {
		t.Fatal("an expired entry was served")
	}
	time.Sleep(50 * time.Millisecond)
	if n := rec.count.Load(); n != 0 {
		t.Fatalf("refreshed an expired entry %d times", n)
	}
}

// Close cancels in-flight refreshes rather than awaiting them: shutdown must
// not be held up by an optimisation. It must still leave no goroutine behind.
func TestCloseCancelsInFlightRefreshes(t *testing.T) {
	clk := &clock{t: time.Now()}
	inner := testInner(t, clk)
	rec := newRecorder()
	rec.block = make(chan struct{})

	c := New(inner, Options{Threshold: 0.1, MinTTL: 30 * time.Second, Log: quietLogger(), Now: clk.now})
	c.SetRefresh(rec.fn)

	k := key("example.com.")
	c.PutRRset(k, []dns.RR{aRR(t, "example.com. 300 IN A 192.0.2.1")}, false)
	clk.add(295 * time.Second)
	c.Get(k)
	waitFor(t, func() bool { return c.opts.Metrics.InFlight.Load() == 1 }, "the refresh to start")

	// The refresh is parked on rec.block and would never finish on its own, so
	// a Close that returns proves it was cancelled rather than awaited.
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()

	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung on a refresh that was never going to finish by itself")
	}
	if n := c.opts.Metrics.InFlight.Load(); n != 0 {
		t.Fatalf("%d refreshes still in flight after Close returned", n)
	}
	close(rec.block)
}
