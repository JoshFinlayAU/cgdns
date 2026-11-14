package dnssec

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func loadCapture(t *testing.T, file string) *dns.Msg {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "dnssec", file))
	if err != nil {
		t.Fatalf("reading capture: %v", err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		t.Fatalf("unpacking capture: %v", err)
	}
	return m
}

// Real DS answers from ARIN and APNIC for empty non-terminals in the reverse
// tree. The parent proves "no DS" with an NSEC that covers the name and points
// at a name below it (RFC 4035 §3.1.3.2). Rejecting that SERVFAILed every PTR
// lookup under 160/8 and 1/8.
func TestEmptyNonTerminal_CapturedDenials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		file string
		name string
	}{
		{"ds-ent-30.160.in-addr.arpa.wire", "30.160.in-addr.arpa."},
		{"ds-ent-1.1.in-addr.arpa.wire", "1.1.in-addr.arpa."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msg := loadCapture(t, tc.file)
			if err := ProveNoDS(msg.Ns, tc.name); err != nil {
				t.Errorf("ProveNoDS(%s) = %v, want the denial to hold", tc.name, err)
			}
			cut, known := ZoneCutFromDenial(msg.Ns, tc.name)
			if cut || !known {
				t.Errorf("ZoneCutFromDenial(%s) = (cut=%t, known=%t), want (false, true)", tc.name, cut, known)
			}
		})
	}
}

func TestEmptyNonTerminal_ProofShape(t *testing.T) {
	t.Parallel()
	nsec := func(owner, next string) []dns.RR {
		return []dns.RR{&dns.NSEC{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: next,
			TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
		}}
	}
	tests := []struct {
		name      string
		denial    []dns.RR
		query     string
		wantProof bool
		wantKnown bool
	}{
		{
			name:      "covering NSEC pointing below the name proves an empty non-terminal",
			denial:    nsec("a.example.", "x.ent.example."),
			query:     "ent.example.",
			wantProof: true,
			wantKnown: true,
		},
		{
			name:      "covering NSEC pointing elsewhere proves only that the name is absent",
			denial:    nsec("a.example.", "zz.example."),
			query:     "ent.example.",
			wantProof: false,
			wantKnown: false,
		},
		{
			name:      "next name below a sibling is not below the query",
			denial:    nsec("a.example.", "x.entz.example."),
			query:     "ent.example.",
			wantProof: false,
			wantKnown: false,
		},
		{
			name:      "wrapping NSEC back to the apex proves nothing about a name above it",
			denial:    nsec("zz.sub.example.", "sub.example."),
			query:     "example.",
			wantProof: false,
			wantKnown: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ProveNoDS(tc.denial, tc.query)
			if tc.wantProof && err != nil {
				t.Errorf("ProveNoDS = %v, want the proof to hold", err)
			}
			if !tc.wantProof && err == nil {
				t.Error("ProveNoDS accepted a record that does not prove the absence of DS")
			}
			cut, known := ZoneCutFromDenial(tc.denial, tc.query)
			if cut || known != tc.wantKnown {
				t.Errorf("ZoneCutFromDenial = (cut=%t, known=%t), want (false, %t)", cut, known, tc.wantKnown)
			}
		})
	}
}

func signedChildOfRoot(t *testing.T) (*signedZone, *signedZone, *fakeFetcher) {
	t.Helper()
	root := newSignedZone(t, ".")
	child := newSignedZone(t, "example.")

	f := newFakeFetcher()
	f.set(".", dns.TypeDNSKEY, root.dnskeyRRset(), []*dns.RRSIG{root.signKeys(t)})
	dsSet := []dns.RR{child.ds(t)}
	dsSet[0].Header().Name = "example."
	f.set("example.", dns.TypeDS, dsSet, []*dns.RRSIG{root.sign(t, dsSet)})
	f.set("example.", dns.TypeDNSKEY, child.dnskeyRRset(), []*dns.RRSIG{child.signKeys(t)})
	return root, child, f
}

func TestTrustedKeys_EmptyNonTerminalKeepsParentKeys(t *testing.T) {
	t.Parallel()
	root, child, f := signedChildOfRoot(t)

	proof := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "x.ent.example.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	f.setDenial("ent.example.", dns.TypeDS, []dns.RR{proof, child.sign(t, []dns.RR{proof})})

	v := newValidator(t, []Anchor{root.anchor(t)}, f)
	keys, status, err := v.TrustedKeys(context.Background(), "ent.example.")
	if err != nil {
		t.Fatalf("chain walk failed: %v", err)
	}
	if status != StatusSecure {
		t.Fatalf("status = %s, want secure: the parent still signs an empty non-terminal", status)
	}
	rrset := []dns.RR{aRecord("x.ent.example.", "192.0.2.1", 300)}
	if _, err := v.VerifyRRset(rrset, []*dns.RRSIG{child.sign(t, rrset)}, keys); err != nil {
		t.Errorf("the parent's keys were not returned: %v", err)
	}
}

// outlook.office365.com is a CNAME inside office365.com. Asking its parent for a
// DS there returns the CNAME, signed by the parent, which settles that the
// name is not a zone cut.
func TestTrustedKeys_SignedCNAMEIsNotAZoneCut(t *testing.T) {
	t.Parallel()

	cname := []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.other.",
	}}

	t.Run("signed by the parent", func(t *testing.T) {
		t.Parallel()
		root, child, f := signedChildOfRoot(t)
		f.set("alias.example.", dns.TypeDS, cname, []*dns.RRSIG{child.sign(t, cname)})

		v := newValidator(t, []Anchor{root.anchor(t)}, f)
		_, status, err := v.TrustedKeys(context.Background(), "alias.example.")
		if err != nil || status != StatusSecure {
			t.Fatalf("TrustedKeys = (%s, %v), want secure with the parent's keys", status, err)
		}
		if !v.KeysWereInherited("alias.example.") {
			t.Error("keys for a CNAME owner must be marked as inherited from the parent")
		}
	})

	t.Run("signature from another zone", func(t *testing.T) {
		t.Parallel()
		root, _, f := signedChildOfRoot(t)
		other := newSignedZone(t, "example.")
		f.set("alias.example.", dns.TypeDS, cname, []*dns.RRSIG{other.sign(t, cname)})

		v := newValidator(t, []Anchor{root.anchor(t)}, f)
		_, status, _ := v.TrustedKeys(context.Background(), "alias.example.")
		if status != StatusBogus {
			t.Errorf("status = %s, want bogus: an unverifiable CNAME proves nothing", status)
		}
	})
}
