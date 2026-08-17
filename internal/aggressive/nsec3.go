package aggressive

import (
	"time"

	"github.com/miekg/dns"
)

// NSEC3 needs a different proof from NSEC, and a stricter one.
//
// An NSEC records a gap between two names, so one record can be checked
// directly against a name. NSEC3 records a gap between two *hashes*, and a
// hash reveals nothing about where the name sits in the zone. Proving a name
// does not exist therefore takes three records working together (RFC 5155 §8.4):
//
//   - one matching the closest encloser — the deepest ancestor that does exist;
//   - one covering the next closer name — the child of that ancestor on the way
//     to the query, showing the tree stops there;
//   - one covering the wildcard at the closest encloser, since a wildcard could
//     otherwise still answer for the name.
//
// maxNSEC3Iterations bounds the work an attacker can make this node do by
// pointing it at a zone signed with an absurd iteration count (RFC 9276 §3.1).
const maxNSEC3Iterations = 100

// n3record is one cached NSEC3 and its expiry.
type n3record struct {
	nsec3  *dns.NSEC3
	rrs    []dns.RR
	expiry time.Time
}

// optOut reports whether the record's opt-out flag is set.
//
// An opt-out span may contain unsigned delegations, so it does not prove that
// nothing exists in it — only that nothing *signed* does. RFC 8198 §5.2 is
// explicit that such a record must not be used to assume non-existence, and
// using one would let us deny names that are really there.
func optOut(n *dns.NSEC3) bool { return n.Flags&1 == 1 }

// usable rejects records this build will not reason about.
func usable(n *dns.NSEC3) bool {
	return n.Hash == dns.SHA1 && n.Iterations <= maxNSEC3Iterations
}

// putNSEC3 files an NSEC3 under its zone.
func (s *Store) putNSEC3(apex string, n *dns.NSEC3, proof []dns.RR, soa []dns.RR, expiry time.Time) {
	if !usable(n) {
		return
	}

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
	owner := dns.CanonicalName(n.Hdr.Name)
	for i := range z.nsec3 {
		if dns.CanonicalName(z.nsec3[i].nsec3.Hdr.Name) == owner {
			z.nsec3[i] = n3record{nsec3: n, rrs: proof, expiry: expiry}
			return
		}
	}
	if len(z.nsec3) >= s.opts.MaxRecordsPerZone {
		return
	}
	z.nsec3 = append(z.nsec3, n3record{nsec3: n, rrs: proof, expiry: expiry})
	s.opts.Metrics.Stored.Add(1)
	s.opts.Metrics.Records.Add(1)
}

// matching returns a live NSEC3 whose hash matches name.
func (z *zone) matching(name string, now time.Time) (n3record, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	for _, r := range z.nsec3 {
		if now.Before(r.expiry) && r.nsec3.Match(name) {
			return r, true
		}
	}
	return n3record{}, false
}

// coveringN3 returns a live NSEC3 whose span covers name.
//
// An opt-out record is skipped rather than accepted: its span may hold unsigned
// delegations, so it does not prove the name is absent.
func (z *zone) coveringN3(name string, now time.Time) (n3record, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	for _, r := range z.nsec3 {
		if !now.Before(r.expiry) || optOut(r.nsec3) {
			continue
		}
		if r.nsec3.Cover(name) {
			return r, true
		}
	}
	return n3record{}, false
}

// proveNSEC3 attempts the closest-encloser proof for name within one zone.
func (s *Store) proveNSEC3(z *zone, apex, name string, now time.Time) (Denial, bool) {
	z.mu.RLock()
	empty := len(z.nsec3) == 0
	z.mu.RUnlock()
	if empty {
		return Denial{}, false
	}

	// Walk up from the name looking for the deepest ancestor that exists. The
	// apex always does, so a zone whose records are cached will terminate here.
	closest := ""
	nextCloser := ""
	for suffix := name; ; {
		if _, ok := z.matching(suffix, now); ok {
			closest = suffix
			break
		}
		if suffix == apex || suffix == "." {
			return Denial{}, false
		}
		nextCloser = suffix
		i, end := dns.NextLabel(suffix, 0)
		if end {
			return Denial{}, false
		}
		suffix = suffix[i:]
	}

	// The name itself exists, so this is not an NXDOMAIN to synthesise. It may
	// be a NODATA, which is a different proof and not one made here.
	if closest == name || nextCloser == "" {
		return Denial{}, false
	}

	nc, ok := z.coveringN3(nextCloser, now)
	if !ok {
		return Denial{}, false
	}

	wildcard := "*." + closest
	if _, exists := z.matching(wildcard, now); exists {
		// A wildcard at the closest encloser would answer for this name, so it
		// does not not-exist.
		return Denial{}, false
	}
	wc, ok := z.coveringN3(wildcard, now)
	if !ok {
		return Denial{}, false
	}

	ce, _ := z.matching(closest, now)

	shortest := ce.expiry
	for _, e := range []time.Time{nc.expiry, wc.expiry} {
		if e.Before(shortest) {
			shortest = e
		}
	}
	ttl := shortest.Sub(now)
	if ttl <= 0 {
		return Denial{}, false
	}

	z.mu.RLock()
	soa := append([]dns.RR(nil), z.soa...)
	z.mu.RUnlock()
	if len(soa) == 0 {
		return Denial{}, false
	}

	authority := soa
	authority = append(authority, ce.rrs...)
	authority = append(authority, nc.rrs...)
	// The wildcard proof may be the same record as one already added; sending a
	// duplicate would be a malformed authority section.
	if !sameOwner(wc.rrs, ce.rrs) && !sameOwner(wc.rrs, nc.rrs) {
		authority = append(authority, wc.rrs...)
	}

	return Denial{Authority: withTTL(authority, ttl), TTL: ttl}, true
}

// sameOwner reports whether two record sets share an owner name.
func sameOwner(a, b []dns.RR) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return dns.CanonicalName(a[0].Header().Name) == dns.CanonicalName(b[0].Header().Name)
}
