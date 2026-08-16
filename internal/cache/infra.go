package cache

import (
	"hash/maphash"
	"math"
	"net/netip"
	"sync"
	"time"
)

// Infra is the infrastructure cache: what is known about the authoritative
// servers themselves — smoothed RTT, current health, and EDNS0 quirks — so the
// recursion engine can pick a server cheaply on every delegation step.
//
// It is node-local and never replicated: RTT is a property of the path from
// this node, so sharing it across an anycast cluster would be wrong.
type Infra struct {
	shards []*infraShard
	mask   uint64
	seed   maphash.Seed
	opts   InfraOptions
	now    func() time.Time
}

// InfraOptions configures an Infra cache.
type InfraOptions struct {
	MaxEntries int
	Shards     int

	// InitialRTT is assumed for an unknown server: optimistic enough to get
	// tried, not so optimistic that it always outranks a known-good one.
	InitialRTT time.Duration
	// MaxRTT caps the penalty applied to a failing server.
	MaxRTT time.Duration
	// MaxBackoff caps how long a repeatedly-failing server is skipped.
	MaxBackoff time.Duration

	Now func() time.Time
}

// ServerStat is a snapshot of what we know about one server address.
type ServerStat struct {
	SRTT       time.Duration
	Failures   int
	DownUntil  time.Time
	EDNSBroken bool
	LastSeen   time.Time
}

type infraShard struct {
	mu         sync.Mutex
	m          map[netip.Addr]*infraNode
	head, tail *infraNode
	max        int
}

type infraNode struct {
	addr       netip.Addr
	stat       ServerStat
	prev, next *infraNode
}

// NewInfra builds an Infra cache.
func NewInfra(opts InfraOptions) (*Infra, error) {
	if opts.Shards <= 0 || opts.Shards&(opts.Shards-1) != 0 {
		return nil, &OptionError{Field: "Shards", Msg: "must be a power of two"}
	}
	if opts.MaxEntries < opts.Shards {
		return nil, &OptionError{Field: "MaxEntries", Msg: "must be >= Shards"}
	}
	if opts.InitialRTT <= 0 {
		opts.InitialRTT = 100 * time.Millisecond
	}
	if opts.MaxRTT <= 0 {
		opts.MaxRTT = 3 * time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 30 * time.Second
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	i := &Infra{
		shards: make([]*infraShard, opts.Shards),
		mask:   uint64(opts.Shards - 1),
		seed:   maphash.MakeSeed(),
		opts:   opts,
		now:    now,
	}
	per := opts.MaxEntries / opts.Shards
	for n := range i.shards {
		i.shards[n] = &infraShard{m: make(map[netip.Addr]*infraNode, per/4+1), max: per}
	}
	return i, nil
}

func (i *Infra) shardFor(addr netip.Addr) *infraShard {
	var h maphash.Hash
	h.SetSeed(i.seed)
	b := addr.As16()
	_, _ = h.Write(b[:])
	return i.shards[h.Sum64()&i.mask]
}

// Stat returns the record for addr, and whether it has been contacted before.
func (i *Infra) Stat(addr netip.Addr) (ServerStat, bool) {
	s := i.shardFor(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.m[addr]
	if !ok {
		return ServerStat{SRTT: i.opts.InitialRTT}, false
	}
	s.moveToFront(n)
	return n.stat, true
}

// RTT returns the smoothed round-trip estimate for addr, or InitialRTT.
func (i *Infra) RTT(addr netip.Addr) time.Duration {
	st, _ := i.Stat(addr)
	if st.SRTT <= 0 {
		return i.opts.InitialRTT
	}
	return st.SRTT
}

// Usable reports whether addr is worth trying right now — i.e. it is not in a
// failure backoff.
func (i *Infra) Usable(addr netip.Addr) bool {
	st, known := i.Stat(addr)
	if !known {
		return true
	}
	return !i.now().Before(st.DownUntil)
}

// Success records a successful exchange and its round-trip time.
func (i *Infra) Success(addr netip.Addr, rtt time.Duration) {
	i.update(addr, func(st *ServerStat) {
		if st.SRTT <= 0 {
			st.SRTT = rtt
		} else {
			st.SRTT = (st.SRTT*7 + rtt) / 8
		}
		st.Failures = 0
		st.DownUntil = time.Time{}
	})
}

// Failure records a failed or timed-out exchange, inflating the RTT estimate
// so selection moves away immediately and backing the server off once it keeps
// failing.
func (i *Infra) Failure(addr netip.Addr) {
	i.update(addr, func(st *ServerStat) {
		st.Failures++
		if st.SRTT <= 0 {
			st.SRTT = i.opts.InitialRTT
		}
		st.SRTT *= 2
		if st.SRTT > i.opts.MaxRTT {
			st.SRTT = i.opts.MaxRTT
		}
		if st.Failures >= 2 {
			backoff := time.Duration(math.Min(
				float64(time.Second)*math.Pow(2, float64(st.Failures-2)),
				float64(i.opts.MaxBackoff)))
			st.DownUntil = i.now().Add(backoff)
		}
	})
}

// MarkEDNSBroken records that a server mishandles EDNS0, so later queries skip
// the OPT record. Some authoritatives drop such queries rather than replying
// FORMERR, which otherwise looks like a dead server.
func (i *Infra) MarkEDNSBroken(addr netip.Addr) {
	i.update(addr, func(st *ServerStat) { st.EDNSBroken = true })
}

// EDNSBroken reports whether addr is known to mishandle EDNS0.
func (i *Infra) EDNSBroken(addr netip.Addr) bool {
	st, _ := i.Stat(addr)
	return st.EDNSBroken
}

func (i *Infra) update(addr netip.Addr, f func(*ServerStat)) {
	s := i.shardFor(addr)
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.m[addr]
	if !ok {
		n = &infraNode{addr: addr, stat: ServerStat{SRTT: i.opts.InitialRTT}}
		s.m[addr] = n
		s.pushFront(n)
		for len(s.m) > s.max && s.tail != nil {
			s.remove(s.tail)
		}
	} else {
		s.moveToFront(n)
	}
	f(&n.stat)
	n.stat.LastSeen = i.now()
}

// Len reports how many server addresses are tracked.
func (i *Infra) Len() int {
	n := 0
	for _, s := range i.shards {
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}

func (s *infraShard) pushFront(n *infraNode) {
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

func (s *infraShard) unlink(n *infraNode) {
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

func (s *infraShard) moveToFront(n *infraNode) {
	if s.head == n {
		return
	}
	s.unlink(n)
	s.pushFront(n)
}

func (s *infraShard) remove(n *infraNode) {
	s.unlink(n)
	delete(s.m, n.addr)
}
