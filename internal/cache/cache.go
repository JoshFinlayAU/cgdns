// Package cache implements the resolver's RRset cache and RFC 2308 negative
// cache.
//
// Entries are sharded, each shard with its own mutex and LRU list, and store an
// absolute expiry so an entry can be shared with a peer carrying its remaining
// TTL. Cached data is never part of the replicated control plane.
package cache

import (
	"hash/maphash"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Kind distinguishes a positive answer from a cached denial of existence.
type Kind uint8

const (
	KindAnswer Kind = iota
	KindNegative
)

// Key identifies an RRset. Name must already be canonical (lowercase, fully
// qualified) — use CanonicalName. It is a comparable struct so map lookups
// need no allocation and no string concatenation on the hot path.
type Key struct {
	Name  string
	Type  uint16
	Class uint16
}

// NewKey builds a Key, canonicalising the owner name. Responses arrive with
// mixed case whenever 0x20 randomisation is on, so this is not optional.
func NewKey(name string, qtype, qclass uint16) Key {
	return Key{Name: CanonicalName(name), Type: qtype, Class: qclass}
}

// Entry is a cached RRset or cached denial.
//
// Treat a returned Entry as read-only: RRs points at the cached records, so
// mutating them corrupts the cache for every other reader. Use RRsAt for safe
// copies with the TTL counted down.
type Entry struct {
	// RRs hold their original TTLs and must not be served directly. See RRsAt.
	RRs []dns.RR
	// Kind is KindAnswer or KindNegative.
	Kind Kind
	// Rcode carries the response code for negative entries (NXDOMAIN/NOERROR).
	Rcode int
	// Authenticated records whether the DNSSEC chain validated. Nothing else
	// may set AD on a response.
	Authenticated bool
	// Validated records that validation was actually run, as opposed to an
	// entry the delegation walk stored on its way past.
	//
	// The distinction matters because an entry keeps no signatures. Without it,
	// "not validated yet" and "validated, turned out insecure" look identical,
	// and a resolver that re-validates the first case fails for want of
	// evidence the cache never kept — turning one unvalidated insert into a
	// permanent SERVFAIL for that name.
	Validated bool
	// Stored and Expiry are absolute times.
	Stored time.Time
	Expiry time.Time
}

// TTLAt returns the seconds remaining at now, saturating at zero.
func (e *Entry) TTLAt(now time.Time) uint32 {
	d := e.Expiry.Sub(now)
	if d <= 0 {
		return 0
	}
	return uint32(d / time.Second)
}

// RRsAt returns copies of the cached records with TTLs counted down to what
// remains at now.
func (e *Entry) RRsAt(now time.Time) []dns.RR {
	if len(e.RRs) == 0 {
		return nil
	}
	ttl := e.TTLAt(now)
	out := make([]dns.RR, len(e.RRs))
	for i, rr := range e.RRs {
		c := dns.Copy(rr)
		c.Header().Ttl = ttl
		out[i] = c
	}
	return out
}

// Options configures a Cache. Zero values are rejected by New.
type Options struct {
	// MaxEntries is the total ceiling across all shards. It bounds a count,
	// not memory: an entry holding eight address records costs roughly two and
	// a half times one holding two, so a count alone cannot tell an operator
	// how much RAM the cache will take.
	MaxEntries int
	// MaxBytes bounds the estimated memory instead, which is what a VM is
	// sized against. Zero leaves memory unbounded and only the count applies.
	// Both are enforced when both are set, whichever binds first.
	MaxBytes int64
	// Shards must be a power of two.
	Shards int
	// MinTTL and MaxTTL clamp TTLs learned from the wire.
	MinTTL time.Duration
	MaxTTL time.Duration
	// MaxNegativeTTL caps RFC 2308 negative caching.
	MaxNegativeTTL time.Duration

	// MaxStale is how long an expired entry is kept so it can still answer
	// when the authoritative cannot be reached (RFC 8767). Zero drops entries
	// at expiry, which is the behaviour without serve-stale.
	//
	// It trades staleness for reachability: a longer window keeps subscribers
	// online through a longer outage, at the cost of answering with data that
	// may have moved. It never affects a normal lookup — Get still treats an
	// expired entry as a miss, so a reachable authoritative is always
	// preferred.
	MaxStale time.Duration

	// Now is injectable for tests. Defaults to time.Now.
	Now func() time.Time
}

// Stats is a point-in-time counter snapshot, summed across shards.
type Stats struct {
	Entries int
	// Bytes is the estimated heap the cached entries occupy. It is what
	// max_size bounds, and the number to size a VM against.
	Bytes     int64
	Hits      uint64
	Misses    uint64
	Expired   uint64
	Evictions uint64
	Inserts   uint64
}

// Cache is a sharded, LRU-evicting RRset cache. It is safe for concurrent use.
type Cache struct {
	shards []*shard
	mask   uint64
	seed   maphash.Seed
	opts   Options
	now    func() time.Time
}

type node struct {
	key   Key
	entry Entry
	// size is what this entry was charged against the shard's byte budget,
	// remembered so a replacement or an eviction can refund exactly what was
	// charged rather than recomputing against records that may have changed.
	size int64
	// Intrusive LRU links, avoiding a per-insert allocation.
	prev, next *node
}

// Per-entry and per-record costs, calibrated against real heap growth: a
// two-record A RRset measures about 400 bytes and an eight-record one about
// 970, which fits a fixed cost for the entry plus a fixed cost per record plus
// the record's own data.
//
// It is an estimate and says so. Go gives no cheap way to weigh a live object
// graph, and packing every RRset to measure it would put that cost on the hot
// path. The figure is used to bound memory, so it is better slightly high than
// slightly low.
const (
	entryBaseCost  = 176
	recordBaseCost = 72
	// rdataFallback is charged when a record carries no RDLENGTH, which happens
	// for records this daemon synthesised rather than read off the wire.
	rdataFallback = 24
)

// entrySize estimates the heap an entry occupies, including its key.
func entrySize(k Key, e Entry) int64 {
	size := int64(entryBaseCost) + int64(len(k.Name))
	for _, rr := range e.RRs {
		if rr == nil {
			continue
		}
		h := rr.Header()
		rdata := int64(h.Rdlength)
		if rdata == 0 {
			rdata = rdataFallback
		}
		size += int64(recordBaseCost) + int64(len(h.Name)) + rdata
	}
	return size
}

type shard struct {
	mu   sync.Mutex
	m    map[Key]*node
	head *node // most recently used
	tail *node // least recently used
	max  int
	// maxBytes is this shard's slice of the memory ceiling. Zero means the
	// count is the only bound.
	maxBytes int64
	bytes    int64

	hits      uint64
	misses    uint64
	expired   uint64
	evictions uint64
	inserts   uint64
}

// New builds a Cache, rejecting a nonsensical size rather than correcting it.
func New(opts Options) (*Cache, error) {
	if opts.Shards <= 0 || opts.Shards&(opts.Shards-1) != 0 {
		return nil, &OptionError{Field: "Shards", Msg: "must be a power of two"}
	}
	if opts.MaxEntries < opts.Shards {
		return nil, &OptionError{Field: "MaxEntries", Msg: "must be >= Shards"}
	}
	if opts.MaxTTL <= 0 {
		return nil, &OptionError{Field: "MaxTTL", Msg: "must be > 0"}
	}
	if opts.MaxNegativeTTL <= 0 {
		return nil, &OptionError{Field: "MaxNegativeTTL", Msg: "must be > 0"}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	perShard := opts.MaxEntries / opts.Shards
	perShardBytes := int64(0)
	if opts.MaxBytes > 0 {
		perShardBytes = opts.MaxBytes / int64(opts.Shards)
		if perShardBytes < 1 {
			perShardBytes = 1
		}
	}
	c := &Cache{
		shards: make([]*shard, opts.Shards),
		mask:   uint64(opts.Shards - 1),
		seed:   maphash.MakeSeed(),
		opts:   opts,
		now:    now,
	}
	for i := range c.shards {
		c.shards[i] = &shard{
			m:        make(map[Key]*node, perShard/4+1),
			max:      perShard,
			maxBytes: perShardBytes,
		}
	}
	return c, nil
}

// OptionError reports an invalid cache option.
type OptionError struct {
	Field string
	Msg   string
}

func (e *OptionError) Error() string { return "cache option " + e.Field + " " + e.Msg }

func (c *Cache) shardFor(k Key) *shard {
	var h maphash.Hash
	h.SetSeed(c.seed)
	_, _ = h.WriteString(k.Name)
	_, _ = h.Write([]byte{byte(k.Type >> 8), byte(k.Type), byte(k.Class >> 8), byte(k.Class)})
	return c.shards[h.Sum64()&c.mask]
}

// Get returns the live entry for k. A found-but-expired entry is removed and
// reported as a miss.
func (c *Cache) Get(k Key) (Entry, bool) {
	now := c.now()
	s := c.shardFor(k)

	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.m[k]
	if !ok {
		s.misses++
		return Entry{}, false
	}
	if !now.Before(n.entry.Expiry) {
		// Expired. Keep it only while it could still answer under serve-stale;
		// either way this is a miss, so a reachable authoritative always wins
		// over stale data.
		if c.opts.MaxStale <= 0 || !now.Before(n.entry.Expiry.Add(c.opts.MaxStale)) {
			s.remove(n)
		}
		s.expired++
		s.misses++
		return Entry{}, false
	}
	s.moveToFront(n)
	s.hits++
	return n.entry, true
}

// GetStale returns an entry that has expired but is still within the stale
// window, for use only when resolution has failed (RFC 8767).
//
// It deliberately does not consult live entries: the caller has already tried
// a normal lookup and gone upstream, so anything live would have been served
// there. It counts neither a hit nor a miss — serving stale is a failure
// signal, not cache performance, and it has its own metrics.
func (c *Cache) GetStale(k Key) (Entry, bool) {
	if c.opts.MaxStale <= 0 {
		return Entry{}, false
	}
	now := c.now()
	s := c.shardFor(k)

	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.m[k]
	if !ok {
		return Entry{}, false
	}
	if now.Before(n.entry.Expiry) {
		return Entry{}, false
	}
	if !now.Before(n.entry.Expiry.Add(c.opts.MaxStale)) {
		s.remove(n)
		return Entry{}, false
	}
	return n.entry, true
}

// StaleRRs returns the records of a stale entry stamped with ttl.
//
// A stale entry's own TTL is zero by definition, and a zero TTL tells a client
// never to cache the answer, which would send every one of them straight back
// to a resolver that is already failing to resolve.
func StaleRRs(e Entry, ttl time.Duration) []dns.RR {
	if len(e.RRs) == 0 {
		return nil
	}
	secs := uint32(ttl / time.Second)
	if secs == 0 {
		secs = 1
	}
	out := make([]dns.RR, len(e.RRs))
	for i, rr := range e.RRs {
		c := dns.Copy(rr)
		c.Header().Ttl = secs
		out[i] = c
	}
	return out
}

// Peek returns the live entry for k without counting a hit or a miss, and
// without promoting it in the LRU.
//
// Hit ratio is an operational signal about client traffic; internal readers
// such as the peer push path would distort it.
func (c *Cache) Peek(k Key) (Entry, bool) {
	now := c.now()
	s := c.shardFor(k)

	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.m[k]
	if !ok || !now.Before(n.entry.Expiry) {
		return Entry{}, false
	}
	return n.entry, true
}

// Put inserts or replaces an entry, clamping ttl into the configured bounds.
// A ttl that clamps to zero is not cached at all.
func (c *Cache) Put(k Key, e Entry, ttl time.Duration) {
	ttl = c.clamp(e.Kind, ttl)
	if ttl <= 0 {
		return
	}
	now := c.now()
	e.Stored = now
	e.Expiry = now.Add(ttl)

	s := c.shardFor(k)
	s.mu.Lock()
	defer s.mu.Unlock()

	size := entrySize(k, e)
	if n, ok := s.m[k]; ok {
		s.bytes += size - n.size
		n.entry = e
		n.size = size
		s.moveToFront(n)
		s.inserts++
		s.trim()
		return
	}
	n := &node{key: k, entry: e, size: size}
	s.m[k] = n
	s.pushFront(n)
	s.bytes += size
	s.inserts++
	s.trim()
}

// PutValidated caches an answer whose DNSSEC status has been decided, secure
// or insecure. Only this path may mark an entry as validated.
func (c *Cache) PutValidated(k Key, rrs []dns.RR, authenticated bool) {
	c.putRRset(k, rrs, authenticated, true)
}

func (c *Cache) putRRset(k Key, rrs []dns.RR, authenticated, validated bool) {
	if len(rrs) == 0 {
		return
	}
	min := rrs[0].Header().Ttl
	for _, rr := range rrs[1:] {
		if t := rr.Header().Ttl; t < min {
			min = t
		}
	}
	c.Put(k, Entry{
		RRs:           rrs,
		Kind:          KindAnswer,
		Rcode:         dns.RcodeSuccess,
		Authenticated: authenticated,
		Validated:     validated,
	}, time.Duration(min)*time.Second)
}

// PutRRset caches a positive answer, deriving the TTL from the smallest TTL in
// the set — an RRset is only as fresh as its shortest-lived record.
func (c *Cache) PutRRset(k Key, rrs []dns.RR, authenticated bool) {
	c.putRRset(k, rrs, authenticated, false)
}

// PutNegative caches a denial. ttl is the resolved RFC 2308 §5 negative TTL.
// soa may be nil.
func (c *Cache) PutNegative(k Key, rcode int, soa []dns.RR, ttl time.Duration, authenticated bool) {
	c.Put(k, Entry{
		RRs:           soa,
		Kind:          KindNegative,
		Rcode:         rcode,
		Authenticated: authenticated,
	}, ttl)
}

func (c *Cache) clamp(kind Kind, ttl time.Duration) time.Duration {
	if kind == KindNegative {
		if ttl > c.opts.MaxNegativeTTL {
			return c.opts.MaxNegativeTTL
		}
		return ttl
	}
	if ttl < c.opts.MinTTL {
		ttl = c.opts.MinTTL
	}
	if ttl > c.opts.MaxTTL {
		ttl = c.opts.MaxTTL
	}
	return ttl
}

// Remove drops an entry.
func (c *Cache) Remove(k Key) bool {
	s := c.shardFor(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.m[k]
	if !ok {
		return false
	}
	s.remove(n)
	return true
}

// Len reports the current number of live-or-expired entries held.
func (c *Cache) Len() int {
	n := 0
	for _, s := range c.shards {
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}

// Stats snapshots the counters. Not atomic across shards.
func (c *Cache) Stats() Stats {
	var st Stats
	for _, s := range c.shards {
		s.mu.Lock()
		st.Entries += len(s.m)
		st.Bytes += s.bytes
		st.Hits += s.hits
		st.Misses += s.misses
		st.Expired += s.expired
		st.Evictions += s.evictions
		st.Inserts += s.inserts
		s.mu.Unlock()
	}
	return st
}

func (s *shard) pushFront(n *node) {
	n.prev = nil
	n.next = s.head
	if s.head != nil {
		s.head.prev = n
	}
	s.head = n
	if s.tail == nil {
		s.tail = n
	}
}

func (s *shard) unlink(n *node) {
	if n.prev != nil {
		n.prev.next = n.next
	} else {
		s.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else {
		s.tail = n.prev
	}
	n.prev, n.next = nil, nil
}

func (s *shard) moveToFront(n *node) {
	if s.head == n {
		return
	}
	s.unlink(n)
	s.pushFront(n)
}

func (s *shard) remove(n *node) {
	s.unlink(n)
	delete(s.m, n.key)
	s.bytes -= n.size
	if s.bytes < 0 {
		s.bytes = 0
	}
}

// trim evicts the least recently used entries until both bounds are satisfied.
//
// The byte bound is checked as well as the count because they answer different
// questions: the count keeps the map from growing without limit, and the bytes
// keep the process inside the memory the VM was sized for.
func (s *shard) trim() {
	for s.tail != nil {
		overCount := len(s.m) > s.max
		overBytes := s.maxBytes > 0 && s.bytes > s.maxBytes
		if !overCount && !overBytes {
			return
		}
		// Never evict the only entry on a byte bound: a single RRset larger
		// than one shard's budget would otherwise be evicted the instant it was
		// stored, and the cache would thrash on it for ever.
		if overBytes && !overCount && len(s.m) <= 1 {
			return
		}
		s.remove(s.tail)
		s.evictions++
	}
}

// CanonicalName lowercases an owner name per RFC 4343, without allocating when
// it is already lowercase. Cache keys must be canonicalised on both sides,
// since 0x20 randomisation makes responses arrive mixed-case.
func CanonicalName(s string) string {
	upper := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			upper = true
			break
		}
	}
	if !upper {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
