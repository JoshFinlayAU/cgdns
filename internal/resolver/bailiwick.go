package resolver

import (
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// inBailiwick reports whether name is within zone — equal to it, or a
// subdomain of it. Both are canonicalised, so case never affects the decision.
func inBailiwick(name, zone string) bool {
	name = dns.CanonicalName(name)
	zone = dns.CanonicalName(zone)
	if zone == "." {
		return true
	}
	if name == zone {
		return true
	}
	return dns.IsSubDomain(zone, name)
}

// filterGlue returns only the address records whose owner name lies within
// zone. Out-of-bailiwick glue is the classic cache-poisoning vector, so it is
// discarded rather than merely distrusted.
func filterGlue(rrs []dns.RR, zone string) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
		default:
			continue
		}
		if inBailiwick(rr.Header().Name, zone) {
			out = append(out, rr)
		}
	}
	return out
}

// referralZone returns the delegated zone from a referral's authority section,
// or "" if the referral must be rejected.
//
// A referral is legitimate only if the delegated zone lies strictly below the
// zone queried and is a suffix of the QNAME, and only if it names a single cut
// point. Anything else walks the resolver into a zone the server has no
// authority over.
func referralZone(ns []dns.RR, currentZone, qname string) string {
	currentZone = dns.CanonicalName(currentZone)
	qname = dns.CanonicalName(qname)

	zone := ""
	for _, rr := range ns {
		rec, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := dns.CanonicalName(rec.Hdr.Name)
		if zone == "" {
			zone = owner
			continue
		}
		if owner != zone {
			return ""
		}
	}
	if zone == "" {
		return ""
	}

	if zone == currentZone || !inBailiwick(zone, currentZone) {
		return ""
	}
	if !inBailiwick(qname, zone) {
		return ""
	}
	return zone
}

// nameserversFrom builds the nameserver set for zone, keeping only
// in-bailiwick glue. A nameserver with no usable glue is returned with no
// addresses, for the caller to resolve separately.
func nameserversFrom(authority, additional []dns.RR, zone string) []Nameserver {
	var names []string
	for _, rr := range authority {
		if rec, ok := rr.(*dns.NS); ok && dns.CanonicalName(rec.Hdr.Name) == dns.CanonicalName(zone) {
			names = append(names, dns.CanonicalName(rec.Ns))
		}
	}
	if len(names) == 0 {
		return nil
	}

	glue := filterGlue(additional, zone)

	out := make([]Nameserver, 0, len(names))
	for _, name := range names {
		ns := Nameserver{Name: name}
		for _, rr := range glue {
			if dns.CanonicalName(rr.Header().Name) != name {
				continue
			}
			if a, ok := addrOfRR(rr); ok {
				ns.Addrs = append(ns.Addrs, a)
			}
		}
		out = append(out, ns)
	}
	return out
}

// answersFor returns the records that legitimately answer the question,
// following any CNAME chain. Records outside that chain are dropped.
func answersFor(answer []dns.RR, qname string, qtype uint16) ([]dns.RR, string) {
	target := dns.CanonicalName(qname)
	var (
		out   []dns.RR
		final = target
	)

	seen := map[string]bool{}
	for range answer {
		if seen[final] {
			break
		}
		seen[final] = true

		var (
			matched  []dns.RR
			nextName string
		)
		for _, rr := range answer {
			h := rr.Header()
			if dns.CanonicalName(h.Name) != final || h.Class != dns.ClassINET {
				continue
			}
			switch {
			case h.Rrtype == qtype:
				matched = append(matched, rr)
			case h.Rrtype == dns.TypeCNAME && qtype != dns.TypeCNAME:
				if c, ok := rr.(*dns.CNAME); ok {
					matched = append(matched, rr)
					nextName = dns.CanonicalName(c.Target)
				}
			}
		}
		if len(matched) == 0 {
			break
		}
		out = append(out, matched...)
		if nextName == "" {
			break
		}
		final = nextName
	}
	return out, final
}

// addrOfRR extracts the address from an A or AAAA record.
func addrOfRR(rr dns.RR) (netip.Addr, bool) {
	switch v := rr.(type) {
	case *dns.A:
		return addrFromIP(v.A)
	case *dns.AAAA:
		return addrFromIP(v.AAAA)
	default:
		return netip.Addr{}, false
	}
}

// addrFromIP converts a net.IP, unmapping v4-in-v6 so a host never appears
// under two identities in the infra cache.
func addrFromIP(ip net.IP) (netip.Addr, bool) {
	if v4 := ip.To4(); v4 != nil {
		a, ok := netip.AddrFromSlice(v4)
		return a, ok
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}
