package peer

import (
	"log/slog"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
)

// Cache decorates the local cache with the pair link.
//
//   - A local miss consults the sibling before the resolver goes upstream. A
//     pair-link round trip is well under a millisecond against tens for an
//     authoritative.
//   - A local fill is offered to the sibling, so the surviving node of a pair
//     is already warm when its partner dies.
//
// Entries arriving *from* the peer are written straight to the underlying
// cache, never through this type. That is what stops a push loop: only fills
// this node resolved for itself are ever offered back.
type Cache struct {
	local   *cache.Cache
	client  *Client
	log     *slog.Logger
	metrics *Metrics
}

// CacheOptions configures the decorator.
type CacheOptions struct {
	Local   *cache.Cache
	Client  *Client
	Log     *slog.Logger
	Metrics *Metrics
}

// NewCache wraps a local cache.
func NewCache(opts CacheOptions) *Cache {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	return &Cache{local: opts.Local, client: opts.Client, log: opts.Log, metrics: opts.Metrics}
}

// Get serves locally, then falls back to the sibling.
//
// A peer that is slow, gone or wrong is indistinguishable from a miss here:
// the resolver simply proceeds upstream, which is what it would have done
// without a pair at all. Nothing about the pair link may delay or fail a query.
func (c *Cache) Get(k cache.Key) (cache.Entry, bool) {
	if e, ok := c.local.Get(k); ok {
		return e, true
	}
	if c.client == nil || !c.client.Connected() {
		return cache.Entry{}, false
	}

	e, ttl, ok := c.client.Fetch(k)
	if !ok {
		return cache.Entry{}, false
	}
	// Adopt it locally so the next query for this name costs nothing, writing
	// straight to the underlying cache so it is never offered back.
	c.local.Put(k, e, ttl)
	return e, true
}

// PutRRset caches an answer locally and offers it to the sibling.
func (c *Cache) PutRRset(k cache.Key, rrs []dns.RR, authenticated bool) {
	c.local.PutRRset(k, rrs, authenticated)
	c.offer(k)
}

// PutValidated caches an answer whose DNSSEC status has been decided.
func (c *Cache) PutValidated(k cache.Key, rrs []dns.RR, authenticated bool) {
	c.local.PutValidated(k, rrs, authenticated)
	c.offer(k)
}

// PutNegative caches a denial locally and offers it to the sibling.
//
// Denials are worth sharing: a random-subdomain flood generates far more
// negative entries than positive ones, and it is exactly when both nodes are
// under that load that neither should be resolving the same garbage twice.
func (c *Cache) PutNegative(k cache.Key, rcode int, soa []dns.RR, ttl time.Duration, authenticated bool) {
	c.local.PutNegative(k, rcode, soa, ttl, authenticated)
	c.offer(k)
}

// offer queues the freshly stored entry for the sibling.
func (c *Cache) offer(k cache.Key) {
	if c.client == nil || !c.client.Connected() {
		return
	}
	// Peek rather than Get: this is an internal read and must not count as a
	// cache hit.
	e, ok := c.local.Peek(k)
	if !ok {
		return
	}
	c.client.QueuePush(k, e)
}

// Local exposes the underlying cache, for the metrics endpoint and for the
// peer server, which inserts received entries without re-offering them.
func (c *Cache) Local() *cache.Cache { return c.local }
