package resolver

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
)

// resolveA runs one query through the full handler and returns the response.
func resolveA(t *testing.T, r *Recursive, name string, qtype uint16) *dns.Msg {
	t.Helper()
	resp := r.ServeDNS(context.Background(), query(name, qtype))
	if resp == nil {
		t.Fatal("expected a response")
	}
	return resp
}

func TestRecursive_WalksDelegationChain(t *testing.T) {
	h := standardHierarchy(t)
	r := newTestRecursive(t, h)

	resp := resolveA(t, r, "www.example.com.", dns.TypeA)

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d: %v", len(resp.Answer), resp.Answer)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is %T, want *dns.A", resp.Answer[0])
	}
	if a.A.String() != "192.0.2.80" {
		t.Errorf("answer = %s, want 192.0.2.80", a.A)
	}

	// Every level of the hierarchy should have been consulted exactly once.
	for _, z := range []string{".", "com.", "example.com."} {
		if got := h.zone(z).queries.Load(); got != 1 {
			t.Errorf("zone %s saw %d queries, want 1", z, got)
		}
	}

	// Recursion does not validate, so it must not claim it did.
	if resp.AuthenticatedData {
		t.Error("AD must not be set — DNSSEC validation is not implemented yet")
	}
}

// A warm resolver starts from the deepest delegation it already knows, which
// is what keeps the root from being hammered.
func TestRecursive_WarmCacheStartsBelowRoot(t *testing.T) {
	h := standardHierarchy(t)
	r := newTestRecursive(t, h)

	resolveA(t, r, "www.example.com.", dns.TypeA)
	rootBefore := h.zone(".").queries.Load()
	comBefore := h.zone("com.").queries.Load()

	// A different name in the same zone.
	resp := resolveA(t, r, "mail.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("second query failed: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}

	if got := h.zone(".").queries.Load(); got != rootBefore {
		t.Errorf("root was queried again (%d -> %d); the cached delegation should have been used", rootBefore, got)
	}
	if got := h.zone("com.").queries.Load(); got != comBefore {
		t.Errorf("com. was queried again (%d -> %d); the cached delegation should have been used", comBefore, got)
	}
}

// The whole point of RFC 9156: the root must never learn the full name a
// subscriber asked for.
func TestRecursive_QNAMEMinimisationHidesFullNameFromRoot(t *testing.T) {
	h := standardHierarchy(t)
	r := newTestRecursive(t, h)

	resolveA(t, r, "www.example.com.", dns.TypeA)

	rootSaw := h.zone(".").observed()
	comSaw := h.zone("com.").observed()

	if slices.Contains(rootSaw, "www.example.com.") {
		t.Errorf("root learned the full QNAME: %v", rootSaw)
	}
	if !slices.Contains(rootSaw, "com.") {
		t.Errorf("root should have been asked for com., saw %v", rootSaw)
	}
	if slices.Contains(comSaw, "www.example.com.") {
		t.Errorf("com. learned the full QNAME: %v", comSaw)
	}
	if !slices.Contains(comSaw, "example.com.") {
		t.Errorf("com. should have been asked for example.com., saw %v", comSaw)
	}
	// The authoritative for the zone legitimately sees the whole name.
	if !slices.Contains(h.zone("example.com.").observed(), "www.example.com.") {
		t.Error("the authoritative should have been asked the real question")
	}
}

func TestRecursive_MinimisationDisabledLeaksFullName(t *testing.T) {
	h := standardHierarchy(t)
	r := newTestRecursive(t, h, func(o *RecursiveOptions) { o.QNAMEMinimisation = false })

	resolveA(t, r, "www.example.com.", dns.TypeA)

	// Control for the test above: with minimisation off the root does see it,
	// confirming the previous test measures the feature and not the fixture.
	if !slices.Contains(h.zone(".").observed(), "www.example.com.") {
		t.Errorf("with minimisation disabled the root should see the full name, saw %v", h.zone(".").observed())
	}
}

// Out-of-bailiwick glue is the classic cache-poisoning vector. A com. server
// volunteering an address for a name it has no authority over must be ignored.
func TestRecursive_RejectsOutOfBailiwickGlue(t *testing.T) {
	h := standardHierarchy(t)

	h.zone("com.").setMangle(func(req, resp *dns.Msg) *dns.Msg {
		// Smuggle an unrelated address record into the referral.
		resp.Extra = append(resp.Extra, &dns.A{
			Hdr: dns.RR_Header{Name: "victim.bank.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.ParseIP("198.51.100.66"),
		})
		return resp
	})

	c := testCache(t)
	r := newTestRecursive(t, h, func(o *RecursiveOptions) { o.Cache = c })

	resolveA(t, r, "www.example.com.", dns.TypeA)

	if _, ok := c.Get(cache.NewKey("victim.bank.example.net.", dns.TypeA, dns.ClassINET)); ok {
		t.Error("out-of-bailiwick glue was cached — this is a cache-poisoning hole")
	}
}

// A referral must move us toward the QNAME and stay inside the referring
// server's authority. Anything else is a redirection attempt.
func TestRecursive_RejectsBogusReferral(t *testing.T) {
	tests := []struct {
		name      string
		zoneClaim string
	}{
		{"sideways to an unrelated TLD", "net."},
		{"upward to the root", "."},
		{"to an unrelated zone", "evil.example.org."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := standardHierarchy(t)
			claim := tt.zoneClaim
			h.zone("com.").setMangle(func(req, resp *dns.Msg) *dns.Msg {
				// Rewrite the referral to delegate somewhere illegitimate.
				out := new(dns.Msg)
				out.SetReply(req)
				out.Authoritative = false
				out.Ns = []dns.RR{&dns.NS{
					Hdr: dns.RR_Header{Name: claim, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
					Ns:  "ns.attacker.test.",
				}}
				return out
			})

			m := &RecursiveMetrics{}
			r := newTestRecursive(t, h, func(o *RecursiveOptions) { o.Metrics = m })

			resp := resolveA(t, r, "www.example.com.", dns.TypeA)
			if resp.Rcode != dns.RcodeServerFailure {
				t.Errorf("rcode = %s, want SERVFAIL for a bogus referral", dns.RcodeToString[resp.Rcode])
			}
			if m.BogusReferrals.Load() == 0 {
				t.Error("expected the bogus referral to be counted")
			}
		})
	}
}

// Most real delegations use nameservers outside the delegated zone, so they
// arrive without glue and the resolver has to go and resolve the name.
func TestRecursive_GluelessDelegation(t *testing.T) {
	root := newFakeAuth(".", "127.0.0.10").
		delegate("com.", map[string][]string{"ns.com.": {"127.0.0.11"}}).
		delegate("test.", map[string][]string{"ns.test.": {"127.0.0.13"}})

	// No glue at all for example.com's nameserver.
	com := newFakeAuth("com.", "127.0.0.11").
		delegate("example.com.", map[string][]string{"ns1.other.test.": nil})

	tst := newFakeAuth("test.", "127.0.0.13").
		delegate("other.test.", map[string][]string{"ns.other.test.": {"127.0.0.14"}})

	other := newFakeAuth("other.test.", "127.0.0.14").
		addA("ns1.other.test.", "127.0.0.12", 3600).
		addA("ns.other.test.", "127.0.0.14", 3600)

	example := newFakeAuth("example.com.", "127.0.0.12").
		addA("www.example.com.", "192.0.2.80", 300)

	h := startHierarchy(t, root, com, tst, other, example)
	m := &RecursiveMetrics{}
	r := newTestRecursive(t, h, func(o *RecursiveOptions) { o.Metrics = m })

	resp := resolveA(t, r, "www.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	if m.GluelessLookups.Load() == 0 {
		t.Error("expected a glueless nameserver lookup to be counted")
	}
}

func TestRecursive_NXDOMAIN(t *testing.T) {
	h := standardHierarchy(t)
	r := newTestRecursive(t, h)

	resp := resolveA(t, r, "nothing-here.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	// The SOA must come back so the client knows how long the denial holds.
	foundSOA := false
	for _, rr := range resp.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Error("NXDOMAIN should carry the SOA in the authority section (RFC 2308 §3)")
	}
}

func TestRecursive_NODATA(t *testing.T) {
	h := standardHierarchy(t)
	r := newTestRecursive(t, h)

	// www.example.com. exists with A and AAAA but no MX.
	resp := resolveA(t, r, "www.example.com.", dns.TypeMX)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR for NODATA", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("NODATA must carry no answer, got %d records", len(resp.Answer))
	}
}

func TestRecursive_ResolvesAAAA(t *testing.T) {
	h := standardHierarchy(t)
	r := newTestRecursive(t, h)

	resp := resolveA(t, r, "www.example.com.", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("rcode=%s answers=%d, want NOERROR with 1 answer", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("answer is %T, want *dns.AAAA", resp.Answer[0])
	}
	if aaaa.AAAA.String() != "2001:db8::80" {
		t.Errorf("answer = %s, want 2001:db8::80", aaaa.AAAA)
	}
}

func TestRecursive_ChasesCNAME(t *testing.T) {
	root := newFakeAuth(".", "127.0.0.10").
		delegate("com.", map[string][]string{"ns.com.": {"127.0.0.11"}})
	com := newFakeAuth("com.", "127.0.0.11").
		delegate("example.com.", map[string][]string{"ns.example.com.": {"127.0.0.12"}})
	example := newFakeAuth("example.com.", "127.0.0.12").
		addCNAME("alias.example.com.", "target.example.com.", 300).
		addA("target.example.com.", "192.0.2.99", 300).
		addA("ns.example.com.", "127.0.0.12", 3600)

	h := startHierarchy(t, root, com, example)
	m := &RecursiveMetrics{}
	r := newTestRecursive(t, h, func(o *RecursiveOptions) { o.Metrics = m })

	resp := resolveA(t, r, "alias.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	var sawCNAME, sawA bool
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.CNAME:
			sawCNAME = true
		case *dns.A:
			sawA = true
			if v.A.String() != "192.0.2.99" {
				t.Errorf("A = %s, want 192.0.2.99", v.A)
			}
		}
	}
	if !sawCNAME {
		t.Error("response should include the CNAME that was followed")
	}
	if !sawA {
		t.Error("response should include the A record the CNAME resolved to")
	}
}

// The outbound cap is what stops one client query becoming an amplification
// lever against third parties, so it must be enforced strictly.
func TestRecursive_EnforcesOutboundBudget(t *testing.T) {
	h := standardHierarchy(t)
	m := &RecursiveMetrics{}
	r := newTestRecursive(t, h, func(o *RecursiveOptions) {
		// The walk needs three outbound queries; allow two.
		o.MaxOutbound = 2
		o.Metrics = m
	})

	resp := resolveA(t, r, "www.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL once the budget is spent", dns.RcodeToString[resp.Rcode])
	}
	if m.BudgetExceeded.Load() == 0 {
		t.Error("expected the budget exhaustion to be counted")
	}
	if got := m.OutboundQueries.Load(); got > 2 {
		t.Errorf("sent %d outbound queries, the cap was 2", got)
	}
}

func TestRecursive_EnforcesDepthLimit(t *testing.T) {
	h := standardHierarchy(t)
	m := &RecursiveMetrics{}
	r := newTestRecursive(t, h, func(o *RecursiveOptions) {
		o.MaxDepth = 1 // not enough to descend root -> com -> example.com
		o.Metrics = m
	})

	resp := resolveA(t, r, "www.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	if m.DepthExceeded.Load() == 0 {
		t.Error("expected the depth limit to be counted")
	}
}

// 0x20: a response that does not echo the exact case we sent did not come from
// the server we asked, and must be discarded rather than parsed.
func TestRecursive_RejectsMismatched0x20(t *testing.T) {
	h := standardHierarchy(t)
	h.zone("example.com.").setMangle(func(req, resp *dns.Msg) *dns.Msg {
		// Answer correctly but flatten the case, as a blind spoofer would.
		for i := range resp.Question {
			resp.Question[i].Name = strings.ToLower(resp.Question[i].Name)
		}
		return resp
	})

	m := &RecursiveMetrics{}
	r := newTestRecursive(t, h, func(o *RecursiveOptions) {
		o.CaseRandomisation = true
		o.Metrics = m
	})

	resp := resolveA(t, r, "WwW.ExAmPlE.cOm.", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL when 0x20 verification fails", dns.RcodeToString[resp.Rcode])
	}
	if m.CaseMismatch.Load() == 0 {
		t.Error("expected the 0x20 mismatch to be counted")
	}
}

// Same fixture with 0x20 disabled must succeed, proving the test above is
// measuring the check and not a broken fixture.
func TestRecursive_0x20DisabledAcceptsFlattenedCase(t *testing.T) {
	h := standardHierarchy(t)
	h.zone("example.com.").setMangle(func(req, resp *dns.Msg) *dns.Msg {
		for i := range resp.Question {
			resp.Question[i].Name = strings.ToLower(resp.Question[i].Name)
		}
		return resp
	})

	r := newTestRecursive(t, h, func(o *RecursiveOptions) { o.CaseRandomisation = false })

	resp := resolveA(t, r, "www.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR with 0x20 disabled", dns.RcodeToString[resp.Rcode])
	}
}

// A mixed-case query from a client must still hit the same cache entry as the
// lowercase form; otherwise a 0x20-using client would never get a cache hit.
func TestRecursive_CacheIsCaseInsensitiveToClientCase(t *testing.T) {
	h := standardHierarchy(t)
	r := newTestRecursive(t, h)

	resolveA(t, r, "www.example.com.", dns.TypeA)
	before := h.zone("example.com.").queries.Load()

	resp := resolveA(t, r, "WWW.EXAMPLE.COM.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("mixed-case query failed: rcode=%s answers=%d", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	if got := h.zone("example.com.").queries.Load(); got != before {
		t.Errorf("mixed-case query re-queried the authoritative (%d -> %d); cache keys must be canonical", before, got)
	}
}

// Regression: the 0x20 pattern we send must never reach the client. It leaked
// out through owner names and, via name compression, into RDATA — which both
// discloses our anti-spoofing entropy and breaks stub resolvers that compare
// the answer name to their question byte-for-byte.
func TestRecursive_DoesNotLeak0x20CaseToClient(t *testing.T) {
	root := newFakeAuth(".", "127.0.0.10").
		delegate("com.", map[string][]string{"ns.com.": {"127.0.0.11"}})
	com := newFakeAuth("com.", "127.0.0.11").
		delegate("example.com.", map[string][]string{"ns.example.com.": {"127.0.0.12"}})
	example := newFakeAuth("example.com.", "127.0.0.12").
		addA("ns.example.com.", "127.0.0.12", 3600).
		addCNAME("alias.example.com.", "target.example.com.", 300).
		addA("target.example.com.", "192.0.2.99", 300)

	h := startHierarchy(t, root, com, example)
	r := newTestRecursive(t, h, func(o *RecursiveOptions) { o.CaseRandomisation = true })

	resp := resolveA(t, r, "alias.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			name := rr.Header().Name
			if name != strings.ToLower(name) {
				t.Errorf("owner name leaked 0x20 case to the client: %q", name)
			}
			// Compression makes RDATA names inherit the question's case too.
			if c, ok := rr.(*dns.CNAME); ok {
				if c.Target != strings.ToLower(c.Target) {
					t.Errorf("CNAME target leaked 0x20 case to the client: %q", c.Target)
				}
			}
			if s, ok := rr.(*dns.SOA); ok {
				if s.Ns != strings.ToLower(s.Ns) || s.Mbox != strings.ToLower(s.Mbox) {
					t.Errorf("SOA RDATA leaked 0x20 case to the client: %q %q", s.Ns, s.Mbox)
				}
			}
		}
	}
}

func TestNormaliseCase(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("WwW.ExAmPlE.cOm.", dns.TypeA)
	m.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "WwW.ExAmPlE.cOm.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "TaRgEt.ExAmPlE.cOm.",
		},
	}
	m.Ns = []dns.RR{
		&dns.SOA{
			Hdr:  dns.RR_Header{Name: "ExAmPlE.cOm.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:   "Ns1.ExAmPlE.cOm.",
			Mbox: "HostMaster.ExAmPlE.cOm.",
		},
	}

	normaliseCase(m)

	if got := m.Question[0].Name; got != "www.example.com." {
		t.Errorf("question = %q, want lowercase", got)
	}
	cname := m.Answer[0].(*dns.CNAME)
	if cname.Hdr.Name != "www.example.com." {
		t.Errorf("owner = %q, want lowercase", cname.Hdr.Name)
	}
	if cname.Target != "target.example.com." {
		t.Errorf("CNAME target = %q, want lowercase", cname.Target)
	}
	soa := m.Ns[0].(*dns.SOA)
	if soa.Ns != "ns1.example.com." || soa.Mbox != "hostmaster.example.com." {
		t.Errorf("SOA RDATA = %q / %q, want lowercase", soa.Ns, soa.Mbox)
	}
}

// An empty non-terminal — a label that exists but holds no records — is normal
// in deep names and must not stop the descent.
func TestRecursive_HandlesEmptyNonTerminal(t *testing.T) {
	root := newFakeAuth(".", "127.0.0.10").
		delegate("com.", map[string][]string{"ns.com.": {"127.0.0.11"}})
	com := newFakeAuth("com.", "127.0.0.11").
		delegate("example.com.", map[string][]string{"ns.example.com.": {"127.0.0.12"}})
	example := newFakeAuth("example.com.", "127.0.0.12").
		addA("ns.example.com.", "127.0.0.12", 3600).
		addEmptyNonTerminal("b.example.com."). // exists, no records
		addA("a.b.example.com.", "192.0.2.77", 300)

	h := startHierarchy(t, root, com, example)
	r := newTestRecursive(t, h)

	resp := resolveA(t, r, "a.b.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR through an empty non-terminal", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
}

// A resolver restricted to one family must not attempt the other. Getting this
// wrong is how a v6-only deployment silently keeps working over v4.
func TestRecursive_RespectsAddressFamilySelection(t *testing.T) {
	h := standardHierarchy(t)
	// IPv6 only: the fixture is entirely IPv4, so there should be nothing
	// reachable and the resolver must fail rather than quietly use v4.
	r := newTestRecursive(t, h, func(o *RecursiveOptions) {
		o.UseIPv4 = false
		o.UseIPv6 = true
	})

	resp := resolveA(t, r, "www.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL — an IPv6-only resolver must not fall back to IPv4",
			dns.RcodeToString[resp.Rcode])
	}
	if got := h.zone(".").queries.Load(); got != 0 {
		t.Errorf("root was queried %d times over IPv4 despite UseIPv4=false", got)
	}
}

func TestRecursive_FailsOverBetweenNameservers(t *testing.T) {
	root := newFakeAuth(".", "127.0.0.10").
		delegate("com.", map[string][]string{"ns.com.": {"127.0.0.11"}})
	com := newFakeAuth("com.", "127.0.0.11").
		// First nameserver address is dead (nothing bound on .19).
		delegate("example.com.", map[string][]string{
			"ns1.example.com.": {"127.0.0.19"},
			"ns2.example.com.": {"127.0.0.12"},
		})
	example := newFakeAuth("example.com.", "127.0.0.12").
		addA("www.example.com.", "192.0.2.80", 300)

	h := startHierarchy(t, root, com, example)
	r := newTestRecursive(t, h)

	resp := resolveA(t, r, "www.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR after failing over to the live nameserver",
			dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Errorf("expected 1 answer, got %d", len(resp.Answer))
	}
}

func TestNewRecursive_RejectsBadOptions(t *testing.T) {
	c := testCache(t)
	i := testInfra(t)

	tests := []struct {
		name string
		opts RecursiveOptions
	}{
		{"no cache", RecursiveOptions{Infra: i, UseIPv4: true}},
		{"no infra", RecursiveOptions{Cache: c, UseIPv4: true}},
		{"no root hints", RecursiveOptions{Cache: c, Infra: i, UseIPv4: true}},
		{"no address family", RecursiveOptions{Cache: c, Infra: i}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewRecursive(tt.opts); err == nil {
				t.Error("expected NewRecursive to reject these options")
			}
		})
	}
}

// A cached delegation whose nameservers have no known addresses must not be
// used: the walk would try to resolve those names, which needs the very zone it
// is trying to reach. At the root that recursion never terminates, which is how
// a priming query for `. NS` used to break every subsequent lookup.
func TestRecursive_AddresslessDelegationFallsBackToHints(t *testing.T) {
	h := standardHierarchy(t)
	c := testCache(t)
	r := newTestRecursive(t, h, func(o *RecursiveOptions) { o.Cache = c })

	// Poison the cache with a root NS set naming servers we hold no address
	// for, exactly as a `. NS` answer without its additional section would.
	c.PutRRset(cache.NewKey(".", dns.TypeNS, dns.ClassINET), []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "unknown-root.example.",
		},
	}, false)

	resp := resolveA(t, r, "www.example.com.", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR — an unusable cached delegation must fall back to the root hints",
			dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Errorf("expected 1 answer, got %d", len(resp.Answer))
	}
}
