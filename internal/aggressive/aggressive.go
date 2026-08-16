// Package aggressive answers from cached NSEC records instead of asking the
// authoritative again (RFC 8198).
//
// A signed denial does not just say "this name does not exist" — it says
// "nothing exists between these two names". Ordinary caching throws that away
// and re-asks for every new name in the gap; keeping it lets one denial answer
// for every name it covers, until it expires.
//
// The effect a carrier cares about is on random-subdomain floods. Once a zone's
// NSEC records are cached, a flood of made-up names under it is answered
// locally and never leaves the building — the authoritative under attack sees
// nothing from us, and neither does our own outbound capacity.
//
// Only NSEC is handled, not NSEC3. Synthesising from NSEC3 means hashing each
// candidate with the zone's parameters and reasoning about the closest
// encloser, which is a different piece of work; a zone using NSEC3 simply falls
// through to a normal lookup rather than being answered wrongly.
package aggressive

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/dnssec"
)

// Metrics counts synthesis activity.
type Metrics struct {
	// Stored counts NSEC records taken from validated denials.
	Stored atomic.Uint64
	// Synthesised counts denials answered from cached NSEC.
	Synthesised atomic.Uint64
	// Misses counts lookups with no covering NSEC held.
	Misses atomic.Uint64
	// Zones is how many zones have NSEC records cached.
	Zones atomic.Int64
	// Records is how many NSEC records are held in total.
	Records atomic.Int64
}

// record is one cached NSEC, the signature over it, and its expiry.
//
// The signature is kept because a client that set DO validates the denial
// itself, and an answer carrying NSEC without RRSIG would be bogus to it.
type record struct {
	nsec   *dns.NSEC
	rrs    []dns.RR
	expiry time.Time
}

// zone holds one zone's NSEC records, ordered canonically by owner so the one
// covering a name can be found by binary search, plus the SOA every negative
// answer from it must carry.
type zone struct {
	mu      sync.RWMutex
	records []record
	soa     []dns.RR
}

// Options configures the store.
type Options struct {
	// MaxZones and MaxRecordsPerZone bound memory. A resolver sees denials
	// from every zone its subscribers mistype, so this cannot be unbounded.
	MaxZones          int
	MaxRecordsPerZone int

	Metrics *Metrics
	Now     func() time.Time
}

// Store holds validated NSEC records and answers from them.
type Store struct {
	opts Options

	mu    sync.RWMutex
	zones map[string]*zone
}

// New builds a store.
func New(opts Options) *Store {
	if opts.MaxZones <= 0 {
		opts.MaxZones = 10000
	}
	if opts.MaxRecordsPerZone <= 0 {
		opts.MaxRecordsPerZone = 512
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{opts: opts, zones: make(map[string]*zone)}
}

// Put records the NSEC records from a denial.
//
// The caller must have validated them. An unvalidated NSEC is an attacker's
// assertion about what does not exist, and believing it would let them erase
// names from a zone for as long as we cached it.
func (s *Store) Put(denial []dns.RR, now time.Time) {
	// The SOA in the denial names the zone these NSECs belong to. Filing them
	// under it is what stops one zone's records being used to deny a name in
	// another, which would let any signed zone erase names it does not own.
	apex := ""
	for _, rr := range denial {
		if soa, ok := rr.(*dns.SOA); ok {
			apex = dns.CanonicalName(soa.Hdr.Name)
			break
		}
	}
	if apex == "" {
		return
	}

	soa := recordsFor(denial, apex, dns.TypeSOA)

	for _, rr := range denial {
		n, ok := rr.(*dns.NSEC)
		if !ok {
			continue
		}
		ttl := time.Duration(n.Hdr.Ttl) * time.Second
		if ttl <= 0 {
			continue
		}
		// An NSEC that is not inside the zone its own SOA names has no business
		// being filed under it.
		if !dns.IsSubDomain(apex, dns.CanonicalName(n.Hdr.Name)) {
			continue
		}
		proof := recordsFor(denial, dns.CanonicalName(n.Hdr.Name), dns.TypeNSEC)
		s.put(apex, n, proof, soa, now.Add(ttl))
	}
}

// recordsFor returns the RRset at name of type rtype together with the
// signatures covering it.
func recordsFor(rrs []dns.RR, name string, rtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if sig.TypeCovered == rtype && dns.CanonicalName(sig.Hdr.Name) == name {
				out = append(out, rr)
			}
			continue
		}
		if rr.Header().Rrtype == rtype && dns.CanonicalName(rr.Header().Name) == name {
			out = append(out, rr)
		}
	}
	return out
}

func (s *Store) put(apex string, n *dns.NSEC, proof, soa []dns.RR, expiry time.Time) {
	s.mu.Lock()
	z, ok := s.zones[apex]
	if !ok {
		if len(s.zones) >= s.opts.MaxZones {
			s.mu.Unlock()
			return
		}
		z = &zone{}
		s.zones[apex] = z
		s.opts.Metrics.Zones.Add(1)
	}
	s.mu.Unlock()

	z.mu.Lock()
	defer z.mu.Unlock()
	if len(soa) > 0 {
		z.soa = soa
	}
	for i := range z.records {
		if z.records[i].nsec.NextDomain == n.NextDomain {
			z.records[i] = record{nsec: n, rrs: proof, expiry: expiry}
			return
		}
	}
	if len(z.records) >= s.opts.MaxRecordsPerZone {
		return
	}
	z.records = append(z.records, record{nsec: n, rrs: proof, expiry: expiry})
	sort.Slice(z.records, func(i, j int) bool {
		return dnssec.CanonicalCompare(
			dns.CanonicalName(z.records[i].nsec.Hdr.Name),
			dns.CanonicalName(z.records[j].nsec.Hdr.Name)) < 0
	})
	s.opts.Metrics.Stored.Add(1)
	s.opts.Metrics.Records.Add(1)
}

// Denial is a synthesised NXDOMAIN.
type Denial struct {
	// Authority is the full authority section: the SOA a negative answer must
	// carry, the NSEC records proving the denial, and the signatures over both.
	Authority []dns.RR
	// TTL is the shortest remaining TTL of those records, which is how long
	// this answer may be trusted.
	TTL time.Duration
}

// ProveNXDOMAIN answers whether cached NSEC records prove name does not exist.
//
// It proves the full RFC 4035 case, not just the covering range: a name that
// no NSEC covers may still be synthesised by a wildcard, so the wildcard must
// be shown not to exist either. The proof itself is the validator's, so this
// cannot accept something the validator would reject.
func (s *Store) ProveNXDOMAIN(name string, now time.Time) (Denial, bool) {
	name = dns.CanonicalName(name)

	covering, z, ok := s.covering(name, now)
	if !ok {
		s.opts.Metrics.Misses.Add(1)
		return Denial{}, false
	}

	nsecs := []dns.RR{covering.nsec}
	authority := append([]dns.RR(nil), covering.rrs...)
	shortest := covering.expiry

	// The wildcard that could still synthesise this name must be denied too.
	wildcard := dnssec.WildcardOf(name)
	if !dnssec.NSECCovers(covering.nsec, wildcard) {
		wc, _, ok := s.covering(wildcard, now)
		if !ok {
			s.opts.Metrics.Misses.Add(1)
			return Denial{}, false
		}
		nsecs = append(nsecs, wc.nsec)
		authority = append(authority, wc.rrs...)
		if wc.expiry.Before(shortest) {
			shortest = wc.expiry
		}
	}

	if err := dnssec.ProveNXDOMAIN(nsecs, name); err != nil {
		s.opts.Metrics.Misses.Add(1)
		return Denial{}, false
	}

	ttl := shortest.Sub(now)
	if ttl <= 0 {
		s.opts.Metrics.Misses.Add(1)
		return Denial{}, false
	}

	// A negative answer without an SOA gives the client nothing to cache
	// against, so it would come straight back for the next name in the gap.
	z.mu.RLock()
	soa := append([]dns.RR(nil), z.soa...)
	z.mu.RUnlock()
	if len(soa) == 0 {
		s.opts.Metrics.Misses.Add(1)
		return Denial{}, false
	}

	s.opts.Metrics.Synthesised.Add(1)
	return Denial{Authority: withTTL(append(soa, authority...), ttl), TTL: ttl}, true
}

// covering finds a live NSEC whose range covers name, in the deepest cached
// zone that encloses it.
//
// Walking up name's own labels bounds this by the name's depth rather than by
// how many zones are cached, and means only a zone that actually encloses the
// name can answer for it.
func (s *Store) covering(name string, now time.Time) (record, *zone, bool) {
	for suffix := name; suffix != ""; {
		s.mu.RLock()
		z, ok := s.zones[suffix]
		s.mu.RUnlock()
		if ok {
			if r, found := z.covering(name, now); found {
				return r, z, true
			}
		}

		if suffix == "." {
			break
		}
		i, end := dns.NextLabel(suffix, 0)
		if end {
			break
		}
		suffix = suffix[i:]
	}
	return record{}, nil, false
}

// covering searches one zone's ordered records.
//
// Records are sorted by owner, so the only candidates are the last one whose
// owner sorts below the name and the final record in the zone — the latter
// because the last NSEC wraps around to the apex and covers everything after
// it.
func (z *zone) covering(name string, now time.Time) (record, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()

	if len(z.records) == 0 {
		return record{}, false
	}

	i := sort.Search(len(z.records), func(i int) bool {
		return dnssec.CanonicalCompare(dns.CanonicalName(z.records[i].nsec.Hdr.Name), name) >= 0
	})

	for _, candidate := range []int{i - 1, len(z.records) - 1} {
		if candidate < 0 || candidate >= len(z.records) {
			continue
		}
		r := z.records[candidate]
		if !now.Before(r.expiry) {
			continue
		}
		if dnssec.NSECCovers(r.nsec, name) {
			return r, true
		}
	}
	return record{}, false
}

// withTTL copies the proof with TTLs counted down, so a client caches the
// synthesised denial for no longer than the records backing it remain valid.
func withTTL(rrs []dns.RR, ttl time.Duration) []dns.RR {
	secs := uint32(ttl / time.Second)
	if secs == 0 {
		secs = 1
	}
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		c := dns.Copy(rr)
		c.Header().Ttl = secs
		out[i] = c
	}
	return out
}

// Sweep drops expired records and empty zones.
func (s *Store) Sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for name, z := range s.zones {
		z.mu.Lock()
		kept := z.records[:0]
		for _, r := range z.records {
			if now.Before(r.expiry) {
				kept = append(kept, r)
				continue
			}
			removed++
		}
		z.records = kept
		empty := len(z.records) == 0
		z.mu.Unlock()

		if empty {
			delete(s.zones, name)
			s.opts.Metrics.Zones.Add(-1)
		}
	}
	s.opts.Metrics.Records.Add(-int64(removed))
	return removed
}

// Len reports how many NSEC records are held.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := 0
	for _, z := range s.zones {
		z.mu.RLock()
		n += len(z.records)
		z.mu.RUnlock()
	}
	return n
}
