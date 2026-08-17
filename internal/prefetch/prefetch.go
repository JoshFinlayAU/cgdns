// Package prefetch refreshes popular cache entries just before they expire.
//
// A busy resolver spends much of its latency budget on the unlucky client whose
// query happens to arrive the moment a popular entry expires: everyone behind
// it waits on one upstream round trip. Refreshing shortly before expiry moves
// that work off the query path, so a name that is asked for constantly is
// answered from cache constantly.
//
// It is deliberately conservative. Only names that are actually being asked for
// are refreshed, so an idle entry expires normally and the cache does not grow
// into a crawler; refreshes are deduplicated and capped, so a popular name
// cannot start a stampede of its own.
package prefetch

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
)

// Metrics counts refresh activity.
type Metrics struct {
	// Triggered counts entries that entered the refresh window and were queued.
	Triggered atomic.Uint64
	// Completed counts refreshes that ran to completion.
	Completed atomic.Uint64
	// Suppressed counts refreshes skipped because one was already in flight.
	Suppressed atomic.Uint64
	// Dropped counts refreshes skipped because the concurrency cap was full.
	Dropped atomic.Uint64
	// InFlight is the number of refreshes running now.
	InFlight atomic.Int64
}

// Inner is the cache being decorated.
type Inner interface {
	Get(k cache.Key) (cache.Entry, bool)
	PutRRset(k cache.Key, rrs []dns.RR, authenticated bool)
	PutValidated(k cache.Key, rrs []dns.RR, authenticated bool)
	PutNegative(k cache.Key, rcode int, soa []dns.RR, ttl time.Duration, authenticated bool)
}

// RefreshFunc re-resolves a name. The cache fills as a side effect of the
// resolution, which is why this returns nothing.
type RefreshFunc func(ctx context.Context, k cache.Key)

// Cache refreshes entries that are close to expiry as they are read.
type Cache struct {
	inner   Inner
	refresh atomic.Pointer[RefreshFunc]
	opts    Options

	mu       sync.Mutex
	inflight map[cache.Key]struct{}

	sem chan struct{}

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// Options configures prefetching.
type Options struct {
	// Threshold is the fraction of an entry's original TTL that must remain
	// before a read triggers a refresh. 0.1 refreshes in the last tenth.
	Threshold float64

	// MinTTL skips entries whose original TTL was shorter than this. A record
	// that lives for ten seconds is meant to be re-fetched often, and chasing
	// it would generate more upstream traffic than it saves.
	MinTTL time.Duration

	// MaxConcurrent caps refreshes in flight. Prefetching is an optimisation,
	// so it must never be allowed to crowd out the client queries it exists to
	// speed up.
	MaxConcurrent int

	// Timeout bounds one refresh.
	Timeout time.Duration

	Log     *slog.Logger
	Metrics *Metrics
	Now     func() time.Time
}

// New wraps inner with prefetching.
//
// The refresh function is supplied later with SetRefresh, because the resolver
// that performs it is built around this cache and cannot exist yet.
func New(inner Inner, opts Options) *Cache {
	if opts.Threshold <= 0 || opts.Threshold >= 1 {
		opts.Threshold = 0.1
	}
	if opts.MinTTL <= 0 {
		opts.MinTTL = 30 * time.Second
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = 64
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Cache{
		inner:    inner,
		opts:     opts,
		inflight: make(map[cache.Key]struct{}),
		sem:      make(chan struct{}, opts.MaxConcurrent),
		stop:     make(chan struct{}),
	}
}

// SetRefresh installs the function that re-resolves a name. Until it is set,
// this type is a pass-through.
func (c *Cache) SetRefresh(f RefreshFunc) { c.refresh.Store(&f) }

// Get serves from the inner cache and refreshes the entry if it is close to
// expiry.
func (c *Cache) Get(k cache.Key) (cache.Entry, bool) {
	e, ok := c.inner.Get(k)
	if ok && c.due(e) {
		c.trigger(k)
	}
	return e, ok
}

// PutRRset stores a positive answer.
func (c *Cache) PutRRset(k cache.Key, rrs []dns.RR, authenticated bool) {
	c.inner.PutRRset(k, rrs, authenticated)
}

// PutValidated caches an answer whose DNSSEC status has been decided.
func (c *Cache) PutValidated(k cache.Key, rrs []dns.RR, authenticated bool) {
	c.inner.PutValidated(k, rrs, authenticated)
}

// PutNegative stores a denial.
//
// Denials are not prefetched. A name that does not exist is not made more
// available by asking again, and a random-subdomain flood produces enough of
// them that refreshing would turn the attack into outbound traffic of our own.
func (c *Cache) PutNegative(k cache.Key, rcode int, soa []dns.RR, ttl time.Duration, authenticated bool) {
	c.inner.PutNegative(k, rcode, soa, ttl, authenticated)
}

// due reports whether an entry has entered its refresh window.
func (c *Cache) due(e cache.Entry) bool {
	if e.Kind != cache.KindAnswer {
		return false
	}
	original := e.Expiry.Sub(e.Stored)
	if original < c.opts.MinTTL {
		return false
	}
	remaining := e.Expiry.Sub(c.opts.Now())
	if remaining <= 0 {
		return false
	}
	return float64(remaining) <= float64(original)*c.opts.Threshold
}

// trigger queues a refresh, dropping it rather than blocking the caller. This
// runs on the query path, so it must not wait for anything.
func (c *Cache) trigger(k cache.Key) {
	ref := c.refresh.Load()
	if ref == nil {
		return
	}

	c.mu.Lock()
	if _, busy := c.inflight[k]; busy {
		c.mu.Unlock()
		c.opts.Metrics.Suppressed.Add(1)
		return
	}
	c.inflight[k] = struct{}{}
	c.mu.Unlock()

	select {
	case c.sem <- struct{}{}:
	default:
		// At the cap. Prefetching is an optimisation and the entry is still
		// live, so the next client simply resolves it the ordinary way.
		c.release(k)
		c.opts.Metrics.Dropped.Add(1)
		return
	}

	select {
	case <-c.stop:
		<-c.sem
		c.release(k)
		return
	default:
	}

	c.opts.Metrics.Triggered.Add(1)
	c.wg.Add(1)
	go c.run(k, *ref)
}

func (c *Cache) run(k cache.Key, ref RefreshFunc) {
	defer c.wg.Done()
	defer func() {
		<-c.sem
		c.release(k)
	}()

	c.opts.Metrics.InFlight.Add(1)
	defer c.opts.Metrics.InFlight.Add(-1)

	// Detached from any client's context: the client that triggered this has
	// already been answered from cache and must not be kept waiting, nor should
	// its disconnection cancel a refresh others will benefit from.
	ctx, cancel := context.WithTimeout(context.Background(), c.opts.Timeout)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				c.opts.Log.Error("panic in prefetch", slog.Any("panic", r))
			}
		}()
		ref(ctx, k)
	}()

	select {
	case <-done:
		c.opts.Metrics.Completed.Add(1)
	case <-c.stop:
		cancel()
		<-done
	}
}

func (c *Cache) release(k cache.Key) {
	c.mu.Lock()
	delete(c.inflight, k)
	c.mu.Unlock()
}

// Close stops accepting refreshes, cancels those in flight and waits for them
// to unwind.
//
// They are cancelled rather than awaited: shutdown must not be delayed by an
// optimisation, and by this point the node has already withdrawn from the
// anycast set, so nothing is waiting on the answer.
func (c *Cache) Close() error {
	c.stopOnce.Do(func() { close(c.stop) })
	c.wg.Wait()
	return nil
}
