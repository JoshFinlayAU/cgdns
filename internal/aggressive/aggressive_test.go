package aggressive

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return r
}

// zoneDenial builds a denial for example.com. covering the gap between two
// names, as an authoritative would return it.
func zoneDenial(t *testing.T, owner, next string, types string) []dns.RR {
	t.Helper()
	return []dns.RR{
		rr(t, "example.com. 3600 IN SOA ns.example.com. hm.example.com. 1 2 3 4 3600"),
		rr(t, owner+" 3600 IN NSEC "+next+" "+types),
	}
}

func testStore(t *testing.T, now time.Time) *Store {
	t.Helper()
	return New(Options{Now: func() time.Time { return now }})
}

// The point of RFC 8198: one cached denial answers for every name in its gap,
// so a flood of made-up names never reaches the authoritative.
func TestSynthesisesFromACachedGap(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)

	// alpha.example.com. is followed by omega.example.com., so everything
	// between them is proven not to exist.
	s.Put(zoneDenial(t, "alpha.example.com.", "omega.example.com.", "A RRSIG NSEC"), now)
	// The wildcard *.example.com. must also be denied, which this second NSEC
	// does by covering the range containing it.
	s.Put([]dns.RR{
		rr(t, "example.com. 3600 IN SOA ns.example.com. hm.example.com. 1 2 3 4 3600"),
		rr(t, "example.com. 3600 IN NSEC alpha.example.com. A NS SOA RRSIG NSEC"),
	}, now)

	for _, name := range []string{
		"beta.example.com.",
		"gamma.example.com.",
		"nonsense-12345.example.com.",
	} {
		d, ok := s.ProveNXDOMAIN(name, now)
		if !ok {
			t.Fatalf("%s: no denial synthesised from a gap that covers it", name)
		}
		if len(d.Authority) == 0 {
			t.Fatalf("%s: denial carries no proof", name)
		}
		if d.TTL <= 0 {
			t.Fatalf("%s: denial has a non-positive TTL", name)
		}
	}

	if got := s.opts.Metrics.Synthesised.Load(); got != 3 {
		t.Fatalf("synthesised %d, want 3", got)
	}
}

// A name outside the cached gap must not be denied: we hold no proof about it,
// and inventing one would erase a name that exists.
func TestDoesNotDenyOutsideTheGap(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)
	s.Put(zoneDenial(t, "alpha.example.com.", "omega.example.com.", "A RRSIG NSEC"), now)

	for _, name := range []string{
		"omega.example.com.", // the next name itself exists
		"alpha.example.com.", // the owner exists
		"zulu.example.com.",  // beyond the gap
	} {
		if _, ok := s.ProveNXDOMAIN(name, now); ok {
			t.Fatalf("%s was denied despite being outside the cached gap", name)
		}
	}
}

// An NSEC from one zone must never deny a name in another, or any signed zone
// could erase names it does not own.
func TestNeverUsesAnotherZonesNSEC(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)

	s.Put([]dns.RR{
		rr(t, "evil.test. 3600 IN SOA ns.evil.test. hm.evil.test. 1 2 3 4 3600"),
		rr(t, "aaa.evil.test. 3600 IN NSEC zzz.evil.test. A RRSIG NSEC"),
	}, now)

	// The gap aaa..zzz would cover "bank" if zones were ignored.
	if _, ok := s.ProveNXDOMAIN("bank.example.com.", now); ok {
		t.Fatal("a name was denied using an unrelated zone's NSEC")
	}
}

// An NSEC that is not inside the zone its own SOA names must be discarded.
func TestRejectsOutOfZoneNSEC(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)

	s.Put([]dns.RR{
		rr(t, "example.com. 3600 IN SOA ns.example.com. hm.example.com. 1 2 3 4 3600"),
		rr(t, "aaa.victim.org. 3600 IN NSEC zzz.victim.org. A RRSIG NSEC"),
	}, now)

	if n := s.Len(); n != 0 {
		t.Fatalf("stored %d out-of-zone NSEC records, want 0", n)
	}
}

// A denial with no SOA names no zone, so there is nowhere safe to file it.
func TestIgnoresADenialWithNoSOA(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)
	s.Put([]dns.RR{rr(t, "alpha.example.com. 3600 IN NSEC omega.example.com. A RRSIG NSEC")}, now)
	if n := s.Len(); n != 0 {
		t.Fatalf("stored %d records from a denial with no SOA", n)
	}
}

// A wildcard could still synthesise the name, so a covering NSEC alone is not
// a proof of non-existence.
func TestRequiresTheWildcardToBeDeniedToo(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)

	// Covers beta but says nothing about *.example.com., which sorts before
	// alpha and is therefore outside this gap.
	s.Put(zoneDenial(t, "alpha.example.com.", "omega.example.com.", "A RRSIG NSEC"), now)

	if _, ok := s.ProveNXDOMAIN("beta.example.com.", now); ok {
		t.Fatal("denied a name without proving the wildcard does not exist")
	}

	// Supplying the wildcard denial completes the proof.
	s.Put([]dns.RR{
		rr(t, "example.com. 3600 IN SOA ns.example.com. hm.example.com. 1 2 3 4 3600"),
		rr(t, "example.com. 3600 IN NSEC alpha.example.com. A NS SOA RRSIG NSEC"),
	}, now)
	if _, ok := s.ProveNXDOMAIN("beta.example.com.", now); !ok {
		t.Fatal("a complete proof was rejected")
	}
}

// The synthesised answer must not outlive the records backing it.
func TestExpiry(t *testing.T) {
	base := time.Now()
	s := New(Options{Now: func() time.Time { return base }})

	s.Put([]dns.RR{
		rr(t, "example.com. 60 IN SOA ns.example.com. hm.example.com. 1 2 3 4 60"),
		rr(t, "example.com. 60 IN NSEC alpha.example.com. A NS SOA RRSIG NSEC"),
		rr(t, "alpha.example.com. 60 IN NSEC omega.example.com. A RRSIG NSEC"),
	}, base)

	d, ok := s.ProveNXDOMAIN("beta.example.com.", base)
	if !ok {
		t.Fatal("no denial synthesised while the records were live")
	}
	if d.TTL > time.Minute {
		t.Fatalf("denial TTL %s outlives the 60s records backing it", d.TTL)
	}
	for _, r := range d.Authority {
		if r.Header().Ttl > 60 {
			t.Fatalf("proof record TTL %d outlives its source", r.Header().Ttl)
		}
	}

	if _, ok := s.ProveNXDOMAIN("beta.example.com.", base.Add(2*time.Minute)); ok {
		t.Fatal("a denial was synthesised from expired NSEC records")
	}
}

func TestSweepDropsExpiredRecords(t *testing.T) {
	base := time.Now()
	s := New(Options{Now: func() time.Time { return base }})
	s.Put([]dns.RR{
		rr(t, "example.com. 60 IN SOA ns.example.com. hm.example.com. 1 2 3 4 60"),
		rr(t, "alpha.example.com. 60 IN NSEC omega.example.com. A RRSIG NSEC"),
	}, base)

	if s.Len() != 1 {
		t.Fatalf("held %d records, want 1", s.Len())
	}
	if removed := s.Sweep(base.Add(time.Second)); removed != 0 {
		t.Fatalf("swept %d live records", removed)
	}
	if removed := s.Sweep(base.Add(2 * time.Minute)); removed != 1 {
		t.Fatalf("swept %d expired records, want 1", removed)
	}
	if s.Len() != 0 {
		t.Fatalf("%d records survived the sweep", s.Len())
	}
	if z := s.opts.Metrics.Zones.Load(); z != 0 {
		t.Fatalf("%d empty zones survived the sweep", z)
	}
}

// The deepest enclosing zone must answer, so a child zone's own denial is not
// overridden by its parent's.
func TestUsesTheDeepestEnclosingZone(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)

	s.Put([]dns.RR{
		rr(t, "com. 3600 IN SOA a.gtld-servers.net. nstld.verisign-grs.com. 1 2 3 4 3600"),
		rr(t, "com. 3600 IN NSEC zzz.com. NS SOA RRSIG NSEC"),
	}, now)
	s.Put([]dns.RR{
		rr(t, "example.com. 3600 IN SOA ns.example.com. hm.example.com. 1 2 3 4 3600"),
		rr(t, "example.com. 3600 IN NSEC alpha.example.com. A NS SOA RRSIG NSEC"),
		rr(t, "alpha.example.com. 3600 IN NSEC omega.example.com. A RRSIG NSEC"),
	}, now)

	d, ok := s.ProveNXDOMAIN("beta.example.com.", now)
	if !ok {
		t.Fatal("no denial synthesised")
	}
	for _, r := range d.Authority {
		if !dns.IsSubDomain("example.com.", dns.CanonicalName(r.Header().Name)) {
			t.Fatalf("proof used %s, which is not from the enclosing zone", r.Header().Name)
		}
	}
}

// The table must stay bounded: a resolver sees denials from every zone its
// subscribers mistype.
func TestBoundsMemory(t *testing.T) {
	now := time.Now()
	s := New(Options{MaxZones: 4, MaxRecordsPerZone: 2, Now: func() time.Time { return now }})

	for i := range 50 {
		z := string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".test."
		s.Put([]dns.RR{
			rr(t, z+" 3600 IN SOA ns."+z+" hm."+z+" 1 2 3 4 3600"),
			rr(t, "aaa."+z+" 3600 IN NSEC bbb."+z+" A RRSIG NSEC"),
			rr(t, "ccc."+z+" 3600 IN NSEC ddd."+z+" A RRSIG NSEC"),
			rr(t, "eee."+z+" 3600 IN NSEC fff."+z+" A RRSIG NSEC"),
		}, now)
	}

	if z := s.opts.Metrics.Zones.Load(); z > 4 {
		t.Fatalf("held %d zones, want at most 4", z)
	}
	if n := s.Len(); n > 8 {
		t.Fatalf("held %d records, want at most 4 zones x 2 records", n)
	}
}

// Re-learning a range must replace it rather than accumulate duplicates.
func TestReplacesAnExistingRange(t *testing.T) {
	now := time.Now()
	s := testStore(t, now)
	for range 5 {
		s.Put(zoneDenial(t, "alpha.example.com.", "omega.example.com.", "A RRSIG NSEC"), now)
	}
	if n := s.Len(); n != 1 {
		t.Fatalf("held %d copies of one range, want 1", n)
	}
}
