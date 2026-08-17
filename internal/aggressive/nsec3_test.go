package aggressive

import (
	"sort"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const (
	testSalt = "aabbccdd"
	testIter = 10
)

// nsec3Chain builds the NSEC3 chain a signer would produce for a zone holding
// exactly the given names, so the fixtures hash the way real ones do rather
// than being hand-waved.
func nsec3Chain(t *testing.T, apex string, names []string, flags uint8) []dns.RR {
	t.Helper()

	hashes := make([]string, 0, len(names))
	for _, n := range names {
		hashes = append(hashes, dns.HashName(dns.CanonicalName(n), dns.SHA1, testIter, testSalt))
	}
	sort.Strings(hashes)

	out := make([]dns.RR, 0, len(hashes))
	for i, h := range hashes {
		next := hashes[(i+1)%len(hashes)]
		n := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   h + "." + apex,
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Hash:       dns.SHA1,
			Flags:      flags,
			Iterations: testIter,
			SaltLength: uint8(len(testSalt) / 2),
			Salt:       testSalt,
			HashLength: 20,
			NextDomain: next,
			TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
		}
		out = append(out, n)
	}
	return out
}

func nsec3Denial(t *testing.T, apex string, names []string, flags uint8) []dns.RR {
	t.Helper()
	denial := []dns.RR{
		rr(t, apex+" 3600 IN SOA ns."+apex+" hm."+apex+" 1 2 3 4 3600"),
	}
	return append(denial, nsec3Chain(t, apex, names, flags)...)
}

// The NSEC3 equivalent of the NSEC case: one cached denial answers for every
// name the chain proves absent, so a flood never reaches the authoritative.
func TestNSEC3_SynthesisesFromAClosestEncloserProof(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)

	// A zone holding only its apex and two names. Everything else is absent,
	// and the chain proves it.
	s.Put(nsec3Denial(t, "example.com.",
		[]string{"example.com.", "alpha.example.com.", "omega.example.com."}, 0), now)

	answered := 0
	for _, name := range []string{
		"beta.example.com.", "gamma.example.com.", "nonsense-4821.example.com.",
	} {
		d, ok := s.ProveNXDOMAIN(name, now)
		if !ok {
			continue
		}
		answered++
		if len(d.Authority) == 0 || d.TTL <= 0 {
			t.Fatalf("%s: denial is empty or has no TTL", name)
		}
		var soa, n3 int
		for _, r := range d.Authority {
			switch r.(type) {
			case *dns.SOA:
				soa++
			case *dns.NSEC3:
				n3++
			}
		}
		if soa != 1 {
			t.Fatalf("%s: %d SOA records in the authority section, want 1", name, soa)
		}
		if n3 < 2 {
			t.Fatalf("%s: %d NSEC3 records, want the closest encloser and the covering proofs", name, n3)
		}
	}
	if answered == 0 {
		t.Fatal("no name was denied from a chain that proves all of them absent")
	}
}

// An opt-out span may hold unsigned delegations, so it proves only that nothing
// *signed* is there. Using one would let us deny names that really exist.
func TestNSEC3_NeverUsesAnOptOutSpan(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)
	s.Put(nsec3Denial(t, "example.com.",
		[]string{"example.com.", "alpha.example.com.", "omega.example.com."}, 1), now)

	for _, name := range []string{"beta.example.com.", "gamma.example.com."} {
		if _, ok := s.ProveNXDOMAIN(name, now); ok {
			t.Fatalf("%s was denied using an opt-out span", name)
		}
	}
}

// A name the chain says exists must not be denied.
func TestNSEC3_DoesNotDenyANameThatExists(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)
	s.Put(nsec3Denial(t, "example.com.",
		[]string{"example.com.", "alpha.example.com.", "omega.example.com."}, 0), now)

	for _, name := range []string{"alpha.example.com.", "omega.example.com.", "example.com."} {
		if _, ok := s.ProveNXDOMAIN(name, now); ok {
			t.Fatalf("%s exists in the chain but was denied", name)
		}
	}
}

// A wildcard at the closest encloser would answer for the name, so it does not
// not-exist.
func TestNSEC3_DoesNotDenyWhenAWildcardCouldAnswer(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)
	s.Put(nsec3Denial(t, "example.com.",
		[]string{"example.com.", "*.example.com.", "alpha.example.com."}, 0), now)

	if _, ok := s.ProveNXDOMAIN("beta.example.com.", now); ok {
		t.Fatal("denied a name a wildcard could have synthesised")
	}
}

// RFC 9276: a high iteration count is a way to make a resolver burn CPU.
func TestNSEC3_RejectsExcessiveIterations(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)

	chain := nsec3Chain(t, "example.com.",
		[]string{"example.com.", "alpha.example.com.", "omega.example.com."}, 0)
	for _, r := range chain {
		r.(*dns.NSEC3).Iterations = maxNSEC3Iterations + 1
	}
	denial := append([]dns.RR{
		rr(t, "example.com. 3600 IN SOA ns.example.com. hm.example.com. 1 2 3 4 3600"),
	}, chain...)
	s.Put(denial, now)

	if n := s.Len(); n != 0 {
		t.Fatalf("stored %d records with excessive iterations", n)
	}
	if _, ok := s.ProveNXDOMAIN("beta.example.com.", now); ok {
		t.Fatal("synthesised from a chain with excessive iterations")
	}
}

// An algorithm this build does not implement must not be guessed at.
func TestNSEC3_RejectsUnknownHashAlgorithm(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)

	chain := nsec3Chain(t, "example.com.",
		[]string{"example.com.", "alpha.example.com.", "omega.example.com."}, 0)
	for _, r := range chain {
		r.(*dns.NSEC3).Hash = 99
	}
	s.Put(append([]dns.RR{
		rr(t, "example.com. 3600 IN SOA ns.example.com. hm.example.com. 1 2 3 4 3600"),
	}, chain...), now)

	if n := s.Len(); n != 0 {
		t.Fatalf("stored %d records with an unknown hash algorithm", n)
	}
}

// One zone's chain must never deny a name in another.
func TestNSEC3_NeverUsesAnotherZonesChain(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)
	s.Put(nsec3Denial(t, "evil.test.",
		[]string{"evil.test.", "aaa.evil.test.", "zzz.evil.test."}, 0), now)

	if _, ok := s.ProveNXDOMAIN("bank.example.com.", now); ok {
		t.Fatal("a name was denied using an unrelated zone's NSEC3 chain")
	}
}

func TestNSEC3_Expiry(t *testing.T) {
	base := time.Now()
	s := New(Options{Now: func() time.Time { return base }})
	s.Put(nsec3Denial(t, "example.com.",
		[]string{"example.com.", "alpha.example.com.", "omega.example.com."}, 0), base)

	if _, ok := s.ProveNXDOMAIN("beta.example.com.", base); !ok {
		t.Fatal("no denial while the chain was live")
	}
	if _, ok := s.ProveNXDOMAIN("beta.example.com.", base.Add(2*time.Hour)); ok {
		t.Fatal("synthesised from an expired chain")
	}
	if removed := s.Sweep(base.Add(2 * time.Hour)); removed == 0 {
		t.Fatal("the sweep did not drop expired NSEC3 records")
	}
	if s.Len() != 0 {
		t.Fatalf("%d records survived the sweep", s.Len())
	}
}

// The proof needs a record matching the closest encloser. Without one there is
// no anchor, and covering records alone say nothing about where the tree stops.
func TestNSEC3_WithoutAClosestEncloserProvesNothing(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)

	names := []string{"example.com.", "alpha.example.com.", "omega.example.com."}
	chain := nsec3Chain(t, "example.com.", names, 0)

	// Drop whichever record matches the apex, keeping the rest.
	apexHash := dns.HashName("example.com.", dns.SHA1, testIter, testSalt)
	kept := make([]dns.RR, 0, len(chain))
	for _, r := range chain {
		if dns.CanonicalName(r.Header().Name) != dns.CanonicalName(apexHash+".example.com.") {
			kept = append(kept, r)
		}
	}
	if len(kept) == len(chain) {
		t.Fatal("the fixture did not contain a record matching the apex")
	}

	s.Put(append([]dns.RR{
		rr(t, "example.com. 3600 IN SOA ns.example.com. hm.example.com. 1 2 3 4 3600"),
	}, kept...), now)

	if _, ok := s.ProveNXDOMAIN("beta.example.com.", now); ok {
		t.Fatal("synthesised a denial with no record matching the closest encloser")
	}
}

// A zone holding only its apex really does deny every other name: its single
// NSEC3 wraps the whole hash space. That is a complete proof, not a degenerate
// one, and refusing it would give up a legitimate answer.
func TestNSEC3_MinimalZoneStillProvesAbsence(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)
	s.Put(nsec3Denial(t, "example.com.", []string{"example.com."}, 0), now)

	if _, ok := s.ProveNXDOMAIN("beta.example.com.", now); !ok {
		t.Fatal("a single wrap-around NSEC3 should deny every other name in the zone")
	}
	if _, ok := s.ProveNXDOMAIN("example.com.", now); ok {
		t.Fatal("the apex itself was denied")
	}
}
