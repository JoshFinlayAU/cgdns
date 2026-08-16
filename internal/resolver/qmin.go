package resolver

import (
	"github.com/miekg/dns"
)

// maxMinimiseSteps bounds the descent before the full QNAME is sent. RFC 9156
// §2.3 requires a bound: a deliberately deep name would otherwise turn one
// client query into one outbound query per label.
const maxMinimiseSteps = 10

// minimisedName returns the next outbound query name for a resolver at zone
// working toward qname: the zone plus one more label.
//
//	qname="www.example.com.", zone="."            => "com."
//	qname="www.example.com.", zone="com."         => "example.com."
//	qname="www.example.com.", zone="example.com." => "www.example.com."
func minimisedName(qname, zone string) string {
	qname = dns.CanonicalName(qname)
	zone = dns.CanonicalName(zone)

	if qname == zone {
		return qname
	}
	if !inBailiwick(qname, zone) {
		return qname
	}

	zoneLabels := 0
	if zone != "." {
		zoneLabels = dns.CountLabel(zone)
	}
	qLabels := dns.CountLabel(qname)
	if zoneLabels >= qLabels {
		return qname
	}

	skip := qLabels - zoneLabels - 1
	off := 0
	for i := 0; i < skip; i++ {
		next, end := dns.NextLabel(qname, off)
		if end {
			return qname
		}
		off = next
	}
	return qname[off:]
}

// minimiseQType chooses the type for a minimised probe. Intermediate probes
// use A, per RFC 9156 §2.3: many authoritatives mishandle NS queries for names
// that are not zone cuts, and only the referral matters here.
func minimiseQType(minName, qname string, qtype uint16) uint16 {
	if dns.CanonicalName(minName) == dns.CanonicalName(qname) {
		return qtype
	}
	return dns.TypeA
}

// shouldMinimise reports whether a query is a candidate for minimisation.
func shouldMinimise(qname, zone string) bool {
	qname = dns.CanonicalName(qname)
	zone = dns.CanonicalName(zone)
	if qname == zone {
		return false
	}
	return dns.CountLabel(qname) > dns.CountLabel(zone)+1
}
