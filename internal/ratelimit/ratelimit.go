// Package ratelimit implements response rate limiting.
//
// It defends two different victims, which is why it limits *responses* rather
// than queries:
//
//   - A third party whose address is being spoofed. They never sent the query,
//     so the only thing that helps them is us not sending the answer.
//   - The authoritative servers of a zone under a random-subdomain flood, and
//     our own outbound capacity along with them.
//
// The second only works because of how responses are grouped. A flood of
// random1.victim.com, random2.victim.com and so on produces a different QNAME
// every time, so keying a bucket on the QNAME would give every query its own
// bucket and limit nothing. Denials are therefore grouped by the zone that
// denied them — the SOA owner in the authority section — which collapses the
// whole flood into one bucket.
//
// Rate limiting applies to UDP only. TCP, DoT and DoH complete a handshake, so
// the source cannot be spoofed and there is no reflection to prevent; dropping
// there would only hurt real clients.
package ratelimit

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Class is how a response is grouped for limiting.
type Class uint8

// numClasses bounds the per-class rate arrays.
const numClasses = 3

const (
	// ClassAnswer is a positive answer, grouped by name and type.
	ClassAnswer Class = iota
	// ClassDenial is NXDOMAIN or NODATA, grouped by the zone that denied it.
	ClassDenial
	// ClassError is SERVFAIL, REFUSED and friends, grouped by client only:
	// an error carries no zone worth trusting.
	ClassError
)

// String implements fmt.Stringer.
func (c Class) String() string {
	switch c {
	case ClassAnswer:
		return "answer"
	case ClassDenial:
		return "denial"
	case ClassError:
		return "error"
	default:
		return "unknown"
	}
}

// Action is what to do with a response.
type Action uint8

const (
	// ActionAllow sends the response as-is.
	ActionAllow Action = iota
	// ActionDrop sends nothing. The client sees a timeout, and a spoofed
	// victim sees nothing at all.
	ActionDrop
	// ActionSlip sends a truncated, empty response so a legitimate client
	// retries over TCP, where it is not limited. It is small, so it is not
	// worth reflecting.
	ActionSlip
)

// String implements fmt.Stringer.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionDrop:
		return "drop"
	case ActionSlip:
		return "slip"
	default:
		return "unknown"
	}
}

// Key identifies a bucket.
type Key struct {
	// Prefix is the client address masked to the configured prefix length.
	// Limiting a single address would be useless: an attacker spoofs across
	// the whole range, and a real client behind CGNAT shares one.
	Prefix netip.Prefix
	Class  Class
	// Name is the zone for a denial, the QNAME for an answer, empty for an
	// error.
	Name string
	Type uint16
}

// Metrics counts limiter decisions.
type Metrics struct {
	Evaluated atomic.Uint64
	Allowed   atomic.Uint64
	Dropped   atomic.Uint64
	Slipped   atomic.Uint64
	Exempted  atomic.Uint64
	Buckets   atomic.Int64
	Evictions atomic.Uint64
}

// Options configures a Limiter.
type Options struct {
	// ResponsesPerSecond limits positive answers. Zero disables limiting for
	// that class.
	ResponsesPerSecond float64
	// DenialsPerSecond limits NXDOMAIN and NODATA. This is the one that stops
	// a random-subdomain flood, and is normally set well below the answer
	// rate: a real client asks for names that exist.
	DenialsPerSecond float64
	// ErrorsPerSecond limits SERVFAIL and friends.
	ErrorsPerSecond float64

	// Window is how much unused allowance a bucket may bank, expressed in
	// seconds of the rate. It lets a client burst after being quiet without
	// raising the sustained rate.
	Window time.Duration

	// SlipRatio sends every Nth over-limit response truncated instead of
	// dropping it. 0 always drops; 1 always slips; 2 is the usual compromise,
	// halving what a spoofed victim receives while letting a real client
	// discover TCP within a couple of retries.
	SlipRatio uint32

	// IPv4PrefixLen and IPv6PrefixLen mask the client address.
	IPv4PrefixLen int
	IPv6PrefixLen int

	// MaxBuckets bounds memory. An attacker spoofing across many prefixes
	// would otherwise make the table itself the attack.
	MaxBuckets int

	// Shards spreads lock contention across the hot path.
	Shards int

	Metrics *Metrics
	// Now is injectable for tests.
	Now func() time.Time
}

type bucket struct {
	credit float64
	last   time.Time
	// slipped counts over-limit responses for this bucket, so the slip ratio
	// is applied per bucket rather than globally.
	slipped uint32
}

type shard struct {
	mu      sync.Mutex
	buckets map[Key]*bucket
}

// Limiter decides what to do with each response.
type Limiter struct {
	opts        Options
	shards      []*shard
	shardMask   uint64
	perShardCap int
	// Indexed by Class rather than keyed by it: this is read on every response,
	// and a map lookup per packet is not worth paying for three constants.
	rates        [numClasses]float64
	windowCredit [numClasses]float64
}

// New builds a Limiter.
func New(opts Options) (*Limiter, error) {
	if opts.ResponsesPerSecond < 0 || opts.DenialsPerSecond < 0 || opts.ErrorsPerSecond < 0 {
		return nil, errors.New("ratelimit: rates must not be negative")
	}
	if opts.Window <= 0 {
		opts.Window = 15 * time.Second
	}
	if opts.IPv4PrefixLen <= 0 || opts.IPv4PrefixLen > 32 {
		opts.IPv4PrefixLen = 24
	}
	if opts.IPv6PrefixLen <= 0 || opts.IPv6PrefixLen > 128 {
		opts.IPv6PrefixLen = 56
	}
	if opts.MaxBuckets <= 0 {
		opts.MaxBuckets = 100000
	}
	if opts.Shards <= 0 {
		opts.Shards = 16
	}
	// Rounded up to a power of two so the shard index is a mask rather than a
	// division.
	opts.Shards = roundUpPow2(opts.Shards)
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	l := &Limiter{
		opts:        opts,
		shards:      make([]*shard, opts.Shards),
		shardMask:   uint64(opts.Shards - 1),
		perShardCap: max(1, opts.MaxBuckets/opts.Shards),
	}
	l.rates[ClassAnswer] = opts.ResponsesPerSecond
	l.rates[ClassDenial] = opts.DenialsPerSecond
	l.rates[ClassError] = opts.ErrorsPerSecond
	for class, rate := range l.rates {
		l.windowCredit[class] = rate * opts.Window.Seconds()
	}
	for i := range l.shards {
		l.shards[i] = &shard{buckets: make(map[Key]*bucket)}
	}
	return l, nil
}

// Mask reduces a client address to the prefix its bucket is keyed on.
func (l *Limiter) Mask(addr netip.Addr) netip.Prefix {
	bits := l.opts.IPv4PrefixLen
	if addr.Is6() && !addr.Is4In6() {
		bits = l.opts.IPv6PrefixLen
	}
	addr = addr.Unmap()
	p, err := addr.Prefix(bits)
	if err != nil {
		return netip.PrefixFrom(addr, addr.BitLen())
	}
	return p
}

// Allow decides what to do with one response.
//
// A class with a rate of zero is unlimited, which is how an operator turns off
// limiting for answers while keeping it for denials.
func (l *Limiter) Allow(key Key, now time.Time) Action {
	// Packet handling may not panic, and an unrecognised class would index past
	// the rate table. Allowing is the safe failure: limiting is a defence, not
	// a correctness requirement.
	if int(key.Class) >= numClasses {
		return ActionAllow
	}
	rate := l.rates[key.Class]
	if rate <= 0 {
		return ActionAllow
	}
	l.opts.Metrics.Evaluated.Add(1)

	s := l.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[key]
	if !ok {
		b = l.newBucketLocked(s, key, now, rate)
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.credit = min(b.credit+elapsed*rate, l.windowCredit[key.Class])
		}
		b.last = now
	}

	if b.credit >= 1 {
		b.credit--
		l.opts.Metrics.Allowed.Add(1)
		return ActionAllow
	}

	b.slipped++
	if l.opts.SlipRatio > 0 && b.slipped%l.opts.SlipRatio == 0 {
		l.opts.Metrics.Slipped.Add(1)
		return ActionSlip
	}
	l.opts.Metrics.Dropped.Add(1)
	return ActionDrop
}

// newBucketLocked creates a bucket, making room first if the shard is full.
func (l *Limiter) newBucketLocked(s *shard, key Key, now time.Time, rate float64) *bucket {
	if len(s.buckets) >= l.perShardCap {
		l.evictLocked(s, now)
	}
	// A new bucket starts with one second of allowance, not a full window.
	// The window exists so a client that has been well behaved may burst; a
	// source we have never seen has earned nothing. Starting it full would
	// hand every fresh prefix a free burst of rate*window, and an attacker
	// spoofing across prefixes would never see a single bucket twice.
	b := &bucket{credit: min(rate, l.windowCredit[key.Class]), last: now}
	s.buckets[key] = b
	l.opts.Metrics.Buckets.Add(1)
	return b
}

// evictLocked frees space, preferring buckets that have recovered their full
// allowance: those are idle clients, and forgetting them costs nothing.
//
// If none have, it evicts the least recently seen of a small sample. Refusing
// to create the bucket instead would be worse: an attacker who fills the table
// would then have found a way to switch limiting off.
func (l *Limiter) evictLocked(s *shard, now time.Time) {
	idle := now.Add(-2 * l.opts.Window)
	freed := 0
	for k, b := range s.buckets {
		if b.last.Before(idle) {
			delete(s.buckets, k)
			freed++
			if freed >= 64 {
				break
			}
		}
	}
	if freed > 0 {
		l.opts.Metrics.Buckets.Add(-int64(freed))
		l.opts.Metrics.Evictions.Add(uint64(freed))
		return
	}

	var oldestKey Key
	var oldest time.Time
	sampled := 0
	for k, b := range s.buckets {
		if sampled == 0 || b.last.Before(oldest) {
			oldestKey, oldest = k, b.last
		}
		sampled++
		if sampled >= 8 {
			break
		}
	}
	if sampled > 0 {
		delete(s.buckets, oldestKey)
		l.opts.Metrics.Buckets.Add(-1)
		l.opts.Metrics.Evictions.Add(1)
	}
}

// Sweep drops idle buckets. It is cheap enough to run on a timer and keeps the
// table proportional to active clients rather than to everything ever seen.
func (l *Limiter) Sweep(now time.Time) int {
	idle := now.Add(-2 * l.opts.Window)
	removed := 0
	for _, s := range l.shards {
		s.mu.Lock()
		for k, b := range s.buckets {
			if b.last.Before(idle) {
				delete(s.buckets, k)
				removed++
			}
		}
		s.mu.Unlock()
	}
	if removed > 0 {
		l.opts.Metrics.Buckets.Add(-int64(removed))
	}
	return removed
}

// Len reports how many buckets are held.
func (l *Limiter) Len() int {
	n := 0
	for _, s := range l.shards {
		s.mu.Lock()
		n += len(s.buckets)
		s.mu.Unlock()
	}
	return n
}

// shardFor spreads by client prefix, so all of one client's buckets share a
// shard and a flood from one source contends with nobody else.
func (l *Limiter) shardFor(key Key) *shard {
	addr := key.Prefix.Addr().As16()
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for _, b := range addr {
		h ^= uint64(b)
		h *= prime64
	}
	return l.shards[h&l.shardMask]
}

func roundUpPow2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}
