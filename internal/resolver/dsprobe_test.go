package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The validator asks for DS to learn whether a name is a zone cut. When the
// name is a CNAME the parent's signed CNAME is the answer; chasing it returns
// the target zone's records, which then fail against the parent's keys. That
// SERVFAILed outlook.com intermittently through outlook.office365.com.
func TestFetchSignedDSDoesNotChaseCNAME(t *testing.T) {
	t.Parallel()

	root := newFakeAuth(".", "127.0.0.20").
		delegate("com.", map[string][]string{"ns.com.": {"127.0.0.21"}}).
		delegate("net.", map[string][]string{"ns.net.": {"127.0.0.23"}})
	com := newFakeAuth("com.", "127.0.0.21").
		delegate("example.com.", map[string][]string{"ns.example.com.": {"127.0.0.22"}})
	example := newFakeAuth("example.com.", "127.0.0.22").
		addA("ns.example.com.", "127.0.0.22", 3600).
		addCNAME("alias.example.com.", "target.other.net.", 300).
		addRRSIG("alias.example.com.", dns.TypeCNAME, "example.com.", 300)
	net := newFakeAuth("net.", "127.0.0.23").
		addA("target.other.net.", "192.0.2.80", 300)

	h := startHierarchy(t, root, com, example, net)
	r := newTestRecursive(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rrs, sigs, _, err := r.FetchSigned(ctx, "alias.example.com.", dns.TypeDS)
	if err != nil {
		t.Fatalf("FetchSigned: %v", err)
	}
	for _, rr := range rrs {
		if dns.CanonicalName(rr.Header().Name) != "alias.example.com." {
			t.Errorf("the alias was chased: got %s", rr)
		}
	}
	if len(rrs) != 1 || rrs[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatalf("got %v, want the parent's CNAME alone", rrs)
	}
	if len(sigs) == 0 {
		t.Error("the CNAME's signature was dropped")
	}
	for _, q := range net.observed() {
		if q == "target.other.net." {
			t.Error("the target zone was queried for a DS probe")
		}
	}
}

// A client asking for DS at an alias still gets the chain followed.
func TestClientDSQueryStillChasesCNAME(t *testing.T) {
	t.Parallel()

	root := newFakeAuth(".", "127.0.0.30").
		delegate("com.", map[string][]string{"ns.com.": {"127.0.0.31"}})
	com := newFakeAuth("com.", "127.0.0.31").
		delegate("example.com.", map[string][]string{"ns.example.com.": {"127.0.0.32"}})
	example := newFakeAuth("example.com.", "127.0.0.32").
		addA("ns.example.com.", "127.0.0.32", 3600).
		addCNAME("alias.example.com.", "target.example.com.", 300).
		addA("target.example.com.", "192.0.2.81", 300)

	h := startHierarchy(t, root, com, example)
	r := newTestRecursive(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st := &queryState{maxOutTrip: 64}
	if _, err := r.resolve(withState(ctx, st), "alias.example.com.", dns.TypeDS, st); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if st.cnames != 1 {
		t.Errorf("chased %d CNAMEs, want 1", st.cnames)
	}
}
