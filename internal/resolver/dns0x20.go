package resolver

import (
	"math/rand/v2"

	"github.com/miekg/dns"
)

// randomiseCase applies a random 0x20 pattern to the ASCII letters of name,
// adding entropy against off-path spoofing. Only letters carry the bit, so it
// supplements source-port randomisation rather than replacing it.
func randomiseCase(name string) string {
	b := []byte(name)

	var bits uint64
	var have uint

	for i, c := range b {
		isUpper := c >= 'A' && c <= 'Z'
		isLower := c >= 'a' && c <= 'z'
		if !isUpper && !isLower {
			continue
		}
		if have == 0 {
			bits = rand.Uint64()
			have = 64
		}
		if bits&1 == 1 {
			b[i] = c | 0x20
		} else {
			b[i] = c &^ 0x20
		}
		bits >>= 1
		have--
	}
	return string(b)
}

// normaliseCase strips the 0x20 pattern from a verified response.
//
// Name compression makes the pattern reach RDATA as well as owner names. It
// must not be served to the client: it leaks the entropy, and stubs that
// compare answer names byte-for-byte reject the response. Lowercasing is safe
// under RFC 4343.
//
// DNSSEC validation must run before this — verification depends on the names
// as they arrived on the wire.
func normaliseCase(msg *dns.Msg) {
	for i := range msg.Question {
		msg.Question[i].Name = dns.CanonicalName(msg.Question[i].Name)
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			h := rr.Header()
			h.Name = dns.CanonicalName(h.Name)
			normaliseRDATA(rr)
		}
	}
}

// normaliseRDATA lowercases the name-valued RDATA that compression can
// contaminate, for the types the resolver acts on.
func normaliseRDATA(rr dns.RR) {
	switch v := rr.(type) {
	case *dns.CNAME:
		v.Target = dns.CanonicalName(v.Target)
	case *dns.DNAME:
		v.Target = dns.CanonicalName(v.Target)
	case *dns.NS:
		v.Ns = dns.CanonicalName(v.Ns)
	case *dns.PTR:
		v.Ptr = dns.CanonicalName(v.Ptr)
	case *dns.MX:
		v.Mx = dns.CanonicalName(v.Mx)
	case *dns.SRV:
		v.Target = dns.CanonicalName(v.Target)
	case *dns.SOA:
		v.Ns = dns.CanonicalName(v.Ns)
		v.Mbox = dns.CanonicalName(v.Mbox)
	}
}

// caseMatches reports whether a response echoed the queried name with the exact
// case pattern sent.
func caseMatches(sent, received string) bool {
	return sent == received
}
