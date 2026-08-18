package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A CNAME chain is assembled from several responses, and the signatures have to
// travel with the records they cover.
//
// Dropping them on the join leaves every RRset in the chain looking unsigned.
// Validation then tries to build a chain of trust at the alias itself rather
// than at the zone that signed it, fails, and answers SERVFAIL — which is what
// a CDN-fronted name looks like, so it took out apps.apple.com,
// outlook.live.com and medlineplus.gov at once.
func TestCNAMEChainCarriesSignatures(t *testing.T) {
	t.Parallel()

	root := newFakeAuth(".", "127.0.0.10").
		delegate("com.", map[string][]string{"ns.com.": {"127.0.0.11"}})
	com := newFakeAuth("com.", "127.0.0.11").
		delegate("example.com.", map[string][]string{"ns.example.com.": {"127.0.0.12"}})
	example := newFakeAuth("example.com.", "127.0.0.12").
		addA("ns.example.com.", "127.0.0.12", 3600).
		addCNAME("alias.example.com.", "target.example.com.", 300).
		addRRSIG("alias.example.com.", dns.TypeCNAME, "example.com.", 300).
		addA("target.example.com.", "192.0.2.55", 300).
		addRRSIG("target.example.com.", dns.TypeA, "example.com.", 300)

	h := startHierarchy(t, root, com, example)
	r := newTestRecursive(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st := &queryState{maxOutTrip: 64}
	res, err := r.resolve(withState(ctx, st), "alias.example.com.", dns.TypeA, st)
	if err != nil {
		t.Fatalf("resolving the chain: %v", err)
	}

	var sawCNAME, sawA bool
	for _, rr := range res.answer {
		switch rr.(type) {
		case *dns.CNAME:
			sawCNAME = true
		case *dns.A:
			sawA = true
		}
	}
	if !sawCNAME || !sawA {
		t.Fatalf("the chain did not resolve end to end: cname=%t a=%t", sawCNAME, sawA)
	}

	covered := map[uint16]bool{}
	for _, sig := range res.sigs {
		covered[sig.TypeCovered] = true
	}
	if !covered[dns.TypeCNAME] {
		t.Error("the CNAME's signature was dropped on the join: the alias looks unsigned to validation")
	}
	if !covered[dns.TypeA] {
		t.Error("the target's signature was dropped on the join: the addresses look unsigned")
	}
}
