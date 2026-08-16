package resolver

import (
	"context"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/dnssec"
)

// validateDenial verifies a negative answer.
//
// A denial needs validating as much as an answer does. An unvalidated NXDOMAIN
// is an assertion that a name does not exist, and accepting one on trust lets
// anyone who can answer for a zone — or forge a packet that looks like it —
// erase a name for as long as it stays cached. Without this the resolver would
// validate what exists and take on faith what does not.
func (r *Recursive) validateDenial(ctx context.Context, res *result, qname string, qtype uint16) (dnssec.Status, error) {
	if len(res.authority) == 0 {
		// Nothing to prove anything with. A signed zone would have sent an SOA
		// and its denial records, so this cannot be called secure.
		return dnssec.StatusInsecure, nil
	}

	zone := denialZone(res.authority)
	if zone == "" {
		return dnssec.StatusInsecure, nil
	}

	keys, status, err := r.opts.Validator.TrustedKeys(ctx, zone)
	if err != nil {
		return status, err
	}
	if status != dnssec.StatusSecure {
		// The zone is provably unsigned, so there is no proof to expect.
		return status, nil
	}

	// From here the zone is signed, so an absent or unverifiable proof is an
	// attack rather than an absence.
	//
	// Only the records that carry the denial are verified. A delegation's NS
	// records also live in the authority section and are legitimately unsigned
	// in the parent zone, so demanding a signature for everything present
	// would turn ordinary referrals into validation failures.
	sets, sigs := groupBySet(proofRecords(res.authority))
	verified := 0
	for id, rrs := range sets {
		s := sigs[id]
		if len(s) == 0 {
			return dnssec.StatusBogus, dnssec.ErrNoSignatures
		}
		if _, err := r.opts.Validator.VerifyRRset(rrs, s, keys); err != nil {
			return dnssec.StatusBogus, err
		}
		verified++
	}
	if verified == 0 {
		return dnssec.StatusBogus, dnssec.ErrNoSignatures
	}

	proof := res.authority
	if res.rcode == dns.RcodeNameError {
		if err := dnssec.ProveNXDOMAIN(proof, qname); err != nil {
			return dnssec.StatusBogus, err
		}
		return dnssec.StatusSecure, nil
	}
	if err := dnssec.ProveNODATA(proof, qname, qtype); err != nil {
		return dnssec.StatusBogus, err
	}
	return dnssec.StatusSecure, nil
}

// proofRecords returns only the records that carry a denial: the SOA, the
// NSEC/NSEC3 proving it, and the signatures over them.
func proofRecords(authority []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(authority))
	for _, rr := range authority {
		switch v := rr.(type) {
		case *dns.SOA, *dns.NSEC, *dns.NSEC3:
			out = append(out, rr)
		case *dns.RRSIG:
			switch v.TypeCovered {
			case dns.TypeSOA, dns.TypeNSEC, dns.TypeNSEC3:
				out = append(out, rr)
			}
		}
	}
	return out
}

// denialZone returns the zone a denial came from, named by its SOA.
func denialZone(authority []dns.RR) string {
	for _, rr := range authority {
		if soa, ok := rr.(*dns.SOA); ok {
			return dns.CanonicalName(soa.Hdr.Name)
		}
	}
	return ""
}

// setID identifies an RRset within a message.
type setID struct {
	name  string
	rtype uint16
}

// groupBySet splits records into RRsets and their covering signatures, since a
// signature verifies one RRset and an authority section carries several.
func groupBySet(rrs []dns.RR) (map[setID][]dns.RR, map[setID][]*dns.RRSIG) {
	sets := make(map[setID][]dns.RR)
	sigs := make(map[setID][]*dns.RRSIG)

	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			id := setID{name: dns.CanonicalName(sig.Hdr.Name), rtype: sig.TypeCovered}
			sigs[id] = append(sigs[id], sig)
			continue
		}
		id := setID{name: dns.CanonicalName(rr.Header().Name), rtype: rr.Header().Rrtype}
		sets[id] = append(sets[id], rr)
	}
	return sets, sigs
}
