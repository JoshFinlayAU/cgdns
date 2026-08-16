package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return rr
}

// A delegation's NS records live in the authority section and are legitimately
// unsigned in the parent zone. Demanding a signature for everything present
// turned ordinary referrals into validation failures.
func TestProofRecords_KeepsOnlyTheDenialAndItsSignatures(t *testing.T) {
	authority := []dns.RR{
		mustRR(t, "example.com. 300 IN SOA ns.example.com. hm.example.com. 1 2 3 4 300"),
		mustRR(t, "example.com. 300 IN RRSIG SOA 13 2 300 20260925224653 20260816214653 1234 example.com. AAAA"),
		mustRR(t, "sub.example.com. 300 IN NS ns1.elsewhere.net."),
		mustRR(t, "sub.example.com. 300 IN NS ns2.elsewhere.net."),
		mustRR(t, "abc.example.com. 300 IN NSEC def.example.com. A RRSIG NSEC"),
		mustRR(t, "abc.example.com. 300 IN RRSIG NSEC 13 3 300 20260925224653 20260816214653 1234 example.com. BBBB"),
		mustRR(t, "sub.example.com. 300 IN DS 1234 13 2 AABBCCDD"),
		mustRR(t, "sub.example.com. 300 IN RRSIG DS 13 3 300 20260925224653 20260816214653 1234 example.com. CCCC"),
	}

	got := proofRecords(authority)

	for _, rr := range got {
		switch v := rr.(type) {
		case *dns.SOA, *dns.NSEC, *dns.NSEC3:
		case *dns.RRSIG:
			switch v.TypeCovered {
			case dns.TypeSOA, dns.TypeNSEC, dns.TypeNSEC3:
			default:
				t.Fatalf("kept an RRSIG covering %s", dns.TypeToString[v.TypeCovered])
			}
		default:
			t.Fatalf("kept %s, which carries no part of a denial", dns.TypeToString[rr.Header().Rrtype])
		}
	}

	// Every set that survives must have a signature, or validation would
	// reject a perfectly ordinary response.
	sets, sigs := groupBySet(got)
	for id := range sets {
		if len(sigs[id]) == 0 {
			t.Fatalf("%s/%s survived the filter with no signature", id.name, dns.TypeToString[id.rtype])
		}
	}
	if len(sets) != 2 {
		t.Fatalf("kept %d sets, want the SOA and the NSEC", len(sets))
	}
}

func TestGroupBySet(t *testing.T) {
	rrs := []dns.RR{
		mustRR(t, "example.com. 300 IN SOA ns.example.com. hm.example.com. 1 2 3 4 300"),
		mustRR(t, "example.com. 300 IN RRSIG SOA 13 2 300 20260925224653 20260816214653 1 example.com. AA"),
		// A second signature over the same set, as a zone with two keys sends.
		mustRR(t, "example.com. 300 IN RRSIG SOA 8 2 300 20260925224653 20260816214653 2 example.com. BB"),
		mustRR(t, "abc.example.com. 300 IN NSEC def.example.com. A RRSIG NSEC"),
		mustRR(t, "abc.example.com. 300 IN RRSIG NSEC 13 3 300 20260925224653 20260816214653 1 example.com. CC"),
	}

	sets, sigs := groupBySet(rrs)
	if len(sets) != 2 {
		t.Fatalf("got %d sets, want 2", len(sets))
	}
	soa := setID{name: "example.com.", rtype: dns.TypeSOA}
	if len(sigs[soa]) != 2 {
		t.Fatalf("the SOA set has %d signatures, want both", len(sigs[soa]))
	}
	nsec := setID{name: "abc.example.com.", rtype: dns.TypeNSEC}
	if len(sets[nsec]) != 1 || len(sigs[nsec]) != 1 {
		t.Fatalf("NSEC set: %d records, %d signatures", len(sets[nsec]), len(sigs[nsec]))
	}
}

func TestDenialZone(t *testing.T) {
	if got := denialZone([]dns.RR{
		mustRR(t, "abc.example.com. 300 IN NSEC def.example.com. A RRSIG NSEC"),
		mustRR(t, "Example.COM. 300 IN SOA ns.example.com. hm.example.com. 1 2 3 4 300"),
	}); got != "example.com." {
		t.Fatalf("got %q, want the canonical SOA owner", got)
	}
	if got := denialZone([]dns.RR{mustRR(t, "sub.example.com. 300 IN NS ns.elsewhere.net.")}); got != "" {
		t.Fatalf("got %q for a referral with no SOA, want empty", got)
	}
}

// Negative caching keeps only the SOA (RFC 2308), so a cached denial no longer
// carries the NSEC and signatures that proved it. It must be stored as
// authenticated, or re-validating it on the way out fails for want of evidence
// we deliberately did not keep -- which turned every cached NXDOMAIN from a
// signed zone into SERVFAIL.
func TestCacheValidatedDenial_MarksItAuthenticated(t *testing.T) {
	c := testCache(t)
	r := &Recursive{opts: RecursiveOptions{Cache: c}}

	q := dns.Question{Name: "gone.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	res := &result{
		rcode: dns.RcodeNameError,
		authority: []dns.RR{
			mustRR(t, "example.com. 300 IN SOA ns.example.com. hm.example.com. 1 2 3 4 60"),
			mustRR(t, "abc.example.com. 300 IN NSEC def.example.com. A RRSIG NSEC"),
		},
	}
	r.cacheValidatedDenial(q, res)

	entry, ok := c.Get(cache.NewKey("gone.example.com.", dns.TypeA, dns.ClassINET))
	if !ok {
		t.Fatal("the validated denial was not cached")
	}
	if !entry.Authenticated {
		t.Fatal("the denial was cached unauthenticated, so a later hit would be re-validated without its proof and fail")
	}
	if entry.Rcode != dns.RcodeNameError {
		t.Fatalf("cached rcode %d, want NXDOMAIN", entry.Rcode)
	}
	// RFC 2308: the negative TTL is the lesser of the SOA TTL and its MINIMUM.
	if ttl := entry.TTLAt(time.Now()); ttl == 0 || ttl > 60 {
		t.Fatalf("negative TTL %d, want the SOA MINIMUM of 60", ttl)
	}
}

// A denial with no SOA gives no negative TTL, so there is nothing to cache.
func TestCacheValidatedDenial_IgnoresADenialWithNoSOA(t *testing.T) {
	c := testCache(t)
	r := &Recursive{opts: RecursiveOptions{Cache: c}}

	r.cacheValidatedDenial(
		dns.Question{Name: "gone.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		&result{rcode: dns.RcodeNameError, authority: []dns.RR{
			mustRR(t, "abc.example.com. 300 IN NSEC def.example.com. A RRSIG NSEC"),
		}},
	)

	if _, ok := c.Get(cache.NewKey("gone.example.com.", dns.TypeA, dns.ClassINET)); ok {
		t.Fatal("cached a denial with no SOA, so it had no negative TTL to honour")
	}
}
