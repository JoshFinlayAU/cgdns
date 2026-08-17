package dnssec

import (
	"context"
	"crypto"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var testNow = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func nowFunc() time.Time { return testNow }

// signedZone is a miniature signed zone: a KSK, a ZSK, and the ability to sign
// RRsets the way a real signer would. Keys are generated per test rather than
// checked in, so nothing here expires or needs rotating.
type signedZone struct {
	name    string
	ksk     *dns.DNSKEY
	kskPriv crypto.Signer
	zsk     *dns.DNSKEY
	zskPriv crypto.Signer
}

func newSignedZone(t *testing.T, name string) *signedZone {
	t.Helper()
	name = dns.CanonicalName(name)

	mk := func(flags uint16) (*dns.DNSKEY, crypto.Signer) {
		k := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     flags,
			Protocol:  3,
			Algorithm: dns.ECDSAP256SHA256,
		}
		priv, err := k.Generate(256)
		if err != nil {
			t.Fatalf("generating key for %s: %v", name, err)
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			t.Fatalf("generated key is not a crypto.Signer")
		}
		return k, signer
	}

	ksk, kskPriv := mk(257)
	zsk, zskPriv := mk(256)
	return &signedZone{name: name, ksk: ksk, kskPriv: kskPriv, zsk: zsk, zskPriv: zskPriv}
}

// sign returns an RRSIG over rrset made with the zone signing key.
func (z *signedZone) sign(t *testing.T, rrset []dns.RR) *dns.RRSIG {
	t.Helper()
	return z.signWith(t, rrset, z.zsk, z.zskPriv, testNow.Add(-time.Hour), testNow.Add(24*time.Hour))
}

// signKeys signs the DNSKEY RRset with the key signing key, as a real zone does.
func (z *signedZone) signKeys(t *testing.T) *dns.RRSIG {
	t.Helper()
	return z.signWith(t, z.dnskeyRRset(), z.ksk, z.kskPriv, testNow.Add(-time.Hour), testNow.Add(24*time.Hour))
}

func (z *signedZone) signWith(t *testing.T, rrset []dns.RR, key *dns.DNSKEY, priv crypto.Signer, inception, expiration time.Time) *dns.RRSIG {
	t.Helper()
	if len(rrset) == 0 {
		t.Fatal("nothing to sign")
	}
	h := rrset[0].Header()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
		TypeCovered: h.Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(dns.CanonicalName(h.Name))),
		OrigTtl:     h.Ttl,
		Inception:   uint32(inception.Unix()),
		Expiration:  uint32(expiration.Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  z.name,
	}
	if err := sig.Sign(priv, rrset); err != nil {
		t.Fatalf("signing: %v", err)
	}
	return sig
}

func (z *signedZone) dnskeyRRset() []dns.RR { return []dns.RR{z.ksk, z.zsk} }

// ds returns the delegation signer the parent zone would publish.
func (z *signedZone) ds(t *testing.T) *dns.DS {
	t.Helper()
	ds := z.ksk.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("could not derive DS")
	}
	return ds
}

// anchor returns a trust anchor pinning this zone's KSK.
func (z *signedZone) anchor(t *testing.T) Anchor {
	t.Helper()
	ds := z.ds(t)
	return Anchor{
		Zone:       z.name,
		KeyTag:     ds.KeyTag,
		Algorithm:  ds.Algorithm,
		DigestType: ds.DigestType,
		Digest:     ds.Digest,
	}
}

func aRecord(name, ip string, ttl uint32) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.CanonicalName(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	}
}

// fakeFetcher answers chain-walk lookups from a static map.
type fakeFetcher struct {
	rrs    map[string][]dns.RR
	sigs   map[string][]*dns.RRSIG
	denial map[string][]dns.RR
	err    error
}

func newFakeFetcher() *fakeFetcher {
	return &fakeFetcher{
		rrs:    map[string][]dns.RR{},
		sigs:   map[string][]*dns.RRSIG{},
		denial: map[string][]dns.RR{},
	}
}

func fkey(name string, t uint16) string { return dns.CanonicalName(name) + "|" + dns.TypeToString[t] }

func (f *fakeFetcher) set(name string, qtype uint16, rrs []dns.RR, sigs []*dns.RRSIG) {
	k := fkey(name, qtype)
	f.rrs[k] = rrs
	f.sigs[k] = sigs
}

func (f *fakeFetcher) setDenial(name string, qtype uint16, denial []dns.RR) {
	f.denial[fkey(name, qtype)] = denial
}

func (f *fakeFetcher) FetchSigned(ctx context.Context, name string, qtype uint16) ([]dns.RR, []*dns.RRSIG, []dns.RR, error) {
	if f.err != nil {
		return nil, nil, nil, f.err
	}
	k := fkey(name, qtype)
	return f.rrs[k], f.sigs[k], f.denial[k], nil
}

func newValidator(t *testing.T, anchors []Anchor, f Fetcher) *Validator {
	t.Helper()
	v, err := New(Options{Anchors: anchors, Fetcher: f, Now: nowFunc})
	if err != nil {
		t.Fatalf("building validator: %v", err)
	}
	return v
}

func TestRootAnchors_Embedded(t *testing.T) {
	anchors, err := RootAnchors(testNow)
	if err != nil {
		t.Fatalf("embedded root anchors unusable: %v", err)
	}
	if len(anchors) == 0 {
		t.Fatal("no valid root anchors")
	}
	for _, a := range anchors {
		if a.Zone != "." {
			t.Errorf("anchor zone = %q, want the root", a.Zone)
		}
		if a.DigestType != dns.SHA256 {
			t.Errorf("anchor %d uses digest type %d, want SHA-256", a.KeyTag, a.DigestType)
		}
		if !a.Valid(testNow) {
			t.Errorf("anchor %d should be valid at %s", a.KeyTag, testNow)
		}
	}
}

// A retired KSK must not be able to validate anything.
func TestRootAnchors_DropsExpired(t *testing.T) {
	all, err := ParseAnchors(RawRootAnchors())
	if err != nil {
		t.Fatalf("ParseAnchors: %v", err)
	}
	valid, err := RootAnchors(testNow)
	if err != nil {
		t.Fatalf("RootAnchors: %v", err)
	}
	if len(valid) >= len(all) {
		t.Skip("no expired anchors in the shipped file")
	}
	for _, a := range valid {
		if !a.ValidUntil.IsZero() && testNow.After(a.ValidUntil) {
			t.Errorf("anchor %d expired at %s but was returned", a.KeyTag, a.ValidUntil)
		}
	}
}

func TestParseAnchors_Rejects(t *testing.T) {
	tests := []struct {
		name string
		xml  string
	}{
		{"not xml", "this is not xml"},
		{"no key digests", `<TrustAnchor><Zone>.</Zone></TrustAnchor>`},
		{"digest not hex", `<TrustAnchor><Zone>.</Zone><KeyDigest><KeyTag>1</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>ZZZZ</Digest></KeyDigest></TrustAnchor>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseAnchors([]byte(tt.xml)); err == nil {
				t.Error("expected ParseAnchors to reject this input")
			}
		})
	}
}

func TestVerifyRRset_ValidSignature(t *testing.T) {
	z := newSignedZone(t, "example.com.")
	rrset := []dns.RR{aRecord("www.example.com.", "192.0.2.1", 300)}
	sig := z.sign(t, rrset)

	v := newValidator(t, []Anchor{z.anchor(t)}, nil)
	if _, err := v.VerifyRRset(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.zsk}); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyRRset_Rejects(t *testing.T) {
	z := newSignedZone(t, "example.com.")
	other := newSignedZone(t, "example.com.")
	rrset := []dns.RR{aRecord("www.example.com.", "192.0.2.1", 300)}

	tests := []struct {
		name    string
		build   func() ([]dns.RR, []*dns.RRSIG, []*dns.DNSKEY)
		wantErr error
	}{
		{
			name: "signature from a different key",
			build: func() ([]dns.RR, []*dns.RRSIG, []*dns.DNSKEY) {
				return rrset, []*dns.RRSIG{other.sign(t, rrset)}, []*dns.DNSKEY{z.zsk}
			},
			wantErr: ErrNoMatchingKey,
		},
		{
			name: "no signatures at all",
			build: func() ([]dns.RR, []*dns.RRSIG, []*dns.DNSKEY) {
				return rrset, nil, []*dns.DNSKEY{z.zsk}
			},
			wantErr: ErrNoSignatures,
		},
		{
			name: "expired signature",
			build: func() ([]dns.RR, []*dns.RRSIG, []*dns.DNSKEY) {
				sig := z.signWith(t, rrset, z.zsk, z.zskPriv, testNow.Add(-48*time.Hour), testNow.Add(-24*time.Hour))
				return rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.zsk}
			},
			wantErr: ErrSignatureExpired,
		},
		{
			name: "not yet valid",
			build: func() ([]dns.RR, []*dns.RRSIG, []*dns.DNSKEY) {
				sig := z.signWith(t, rrset, z.zsk, z.zskPriv, testNow.Add(24*time.Hour), testNow.Add(48*time.Hour))
				return rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.zsk}
			},
			wantErr: ErrSignatureExpired,
		},
		{
			name: "tampered rrset",
			build: func() ([]dns.RR, []*dns.RRSIG, []*dns.DNSKEY) {
				sig := z.sign(t, rrset)
				tampered := []dns.RR{aRecord("www.example.com.", "198.51.100.66", 300)}
				return tampered, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.zsk}
			},
			wantErr: ErrSignatureFailed,
		},
		{
			name: "signer outside the owner name",
			build: func() ([]dns.RR, []*dns.RRSIG, []*dns.DNSKEY) {
				sig := z.sign(t, rrset)
				sig.SignerName = "attacker.test."
				return rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.zsk}
			},
			wantErr: ErrNoMatchingKey,
		},
		{
			name: "type covered does not match",
			build: func() ([]dns.RR, []*dns.RRSIG, []*dns.DNSKEY) {
				sig := z.sign(t, rrset)
				sig.TypeCovered = dns.TypeMX
				return rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.zsk}
			},
			wantErr: ErrNoMatchingKey,
		},
		{
			name: "key without the ZONE flag",
			build: func() ([]dns.RR, []*dns.RRSIG, []*dns.DNSKEY) {
				sig := z.sign(t, rrset)
				bad := *z.zsk
				bad.Flags = 0
				return rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{&bad}
			},
			wantErr: ErrNoMatchingKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := newValidator(t, []Anchor{z.anchor(t)}, nil)
			rrs, sigs, keys := tt.build()
			_, err := v.VerifyRRset(rrs, sigs, keys)
			if err == nil {
				t.Fatal("expected verification to fail")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// SHA-1 is no longer collision resistant, so it is refused unless explicitly
// enabled.
func TestVerifyRRset_RejectsSHA1ByDefault(t *testing.T) {
	z := newSignedZone(t, "example.com.")
	rrset := []dns.RR{aRecord("www.example.com.", "192.0.2.1", 300)}
	sig := z.sign(t, rrset)
	sig.Algorithm = dns.RSASHA1

	v := newValidator(t, []Anchor{z.anchor(t)}, nil)
	_, err := v.VerifyRRset(rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{z.zsk})
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("error = %v, want ErrUnsupportedAlg", err)
	}
}

func TestMatchDS(t *testing.T) {
	z := newSignedZone(t, "example.com.")
	other := newSignedZone(t, "example.com.")

	if !matchDS(z.ds(t), z.ksk) {
		t.Error("a zone's own DS should match its KSK")
	}
	if matchDS(z.ds(t), other.ksk) {
		t.Error("a DS must not match an unrelated key")
	}

	tampered := z.ds(t)
	tampered.Digest = strings.Repeat("aa", 32)
	if matchDS(tampered, z.ksk) {
		t.Error("a DS with a substituted digest must not match")
	}
}

// The full chain: root anchor -> root DNSKEY -> DS for example. -> its DNSKEY.
func TestTrustedKeys_SecureChain(t *testing.T) {
	root := newSignedZone(t, ".")
	child := newSignedZone(t, "example.")

	f := newFakeFetcher()
	f.set(".", dns.TypeDNSKEY, root.dnskeyRRset(), []*dns.RRSIG{root.signKeys(t)})

	dsSet := []dns.RR{child.ds(t)}
	dsSet[0].Header().Name = "example."
	f.set("example.", dns.TypeDS, dsSet, []*dns.RRSIG{root.sign(t, dsSet)})
	f.set("example.", dns.TypeDNSKEY, child.dnskeyRRset(), []*dns.RRSIG{child.signKeys(t)})

	v := newValidator(t, []Anchor{root.anchor(t)}, f)

	keys, status, err := v.TrustedKeys(context.Background(), "example.")
	if err != nil {
		t.Fatalf("chain walk failed: %v", err)
	}
	if status != StatusSecure {
		t.Fatalf("status = %s, want secure", status)
	}
	if len(keys) != 2 {
		t.Errorf("got %d keys, want the KSK and ZSK", len(keys))
	}

	// The validated keys must actually verify the child's data.
	rrset := []dns.RR{aRecord("www.example.", "192.0.2.1", 300)}
	if _, err := v.VerifyRRset(rrset, []*dns.RRSIG{child.sign(t, rrset)}, keys); err != nil {
		t.Errorf("data signed by the validated zone failed: %v", err)
	}
}

// A substituted DS must break the chain, not merely downgrade it.
func TestTrustedKeys_BogusOnDSMismatch(t *testing.T) {
	root := newSignedZone(t, ".")
	child := newSignedZone(t, "example.")
	impostor := newSignedZone(t, "example.")

	f := newFakeFetcher()
	f.set(".", dns.TypeDNSKEY, root.dnskeyRRset(), []*dns.RRSIG{root.signKeys(t)})

	// The parent publishes a DS for a key the child does not hold.
	dsSet := []dns.RR{impostor.ds(t)}
	dsSet[0].Header().Name = "example."
	f.set("example.", dns.TypeDS, dsSet, []*dns.RRSIG{root.sign(t, dsSet)})
	f.set("example.", dns.TypeDNSKEY, child.dnskeyRRset(), []*dns.RRSIG{child.signKeys(t)})

	v := newValidator(t, []Anchor{root.anchor(t)}, f)
	_, status, err := v.TrustedKeys(context.Background(), "example.")
	if status != StatusBogus {
		t.Errorf("status = %s, want bogus", status)
	}
	if !errors.Is(err, ErrDSMismatch) {
		t.Errorf("error = %v, want ErrDSMismatch", err)
	}
}

// An unsigned delegation is Insecure only when the parent proves the DS is
// absent. Without the proof it is indistinguishable from a stripped DS.
func TestTrustedKeys_InsecureNeedsProof(t *testing.T) {
	root := newSignedZone(t, ".")

	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "family.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}

	t.Run("with proof is insecure", func(t *testing.T) {
		f := newFakeFetcher()
		f.set(".", dns.TypeDNSKEY, root.dnskeyRRset(), []*dns.RRSIG{root.signKeys(t)})
		f.set("example.", dns.TypeDS, nil, nil)
		f.setDenial("example.", dns.TypeDS, []dns.RR{nsec, root.sign(t, []dns.RR{nsec})})

		v := newValidator(t, []Anchor{root.anchor(t)}, f)
		_, status, err := v.TrustedKeys(context.Background(), "example.")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if status != StatusInsecure {
			t.Errorf("status = %s, want insecure", status)
		}
	})

	t.Run("without proof is bogus", func(t *testing.T) {
		f := newFakeFetcher()
		f.set(".", dns.TypeDNSKEY, root.dnskeyRRset(), []*dns.RRSIG{root.signKeys(t)})
		f.set("example.", dns.TypeDS, nil, nil)

		v := newValidator(t, []Anchor{root.anchor(t)}, f)
		_, status, _ := v.TrustedKeys(context.Background(), "example.")
		if status != StatusBogus {
			t.Errorf("status = %s, want bogus — a stripped DS must not look unsigned", status)
		}
	})

	t.Run("unsigned proof is bogus", func(t *testing.T) {
		f := newFakeFetcher()
		f.set(".", dns.TypeDNSKEY, root.dnskeyRRset(), []*dns.RRSIG{root.signKeys(t)})
		f.set("example.", dns.TypeDS, nil, nil)
		f.setDenial("example.", dns.TypeDS, []dns.RR{nsec})

		v := newValidator(t, []Anchor{root.anchor(t)}, f)
		_, status, _ := v.TrustedKeys(context.Background(), "example.")
		if status != StatusBogus {
			t.Errorf("status = %s, want bogus — an unsigned proof proves nothing", status)
		}
	})
}

func TestProveNoDS(t *testing.T) {
	tests := []struct {
		name    string
		bitmap  []uint16
		wantErr bool
	}{
		{"NS without DS proves insecure delegation", []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}, false},
		{"DS present contradicts the claim", []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG}, true},
		{"SOA means this is the child apex", []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG}, true},
		// A minimal-covering NSEC asserts a fixed type set for the queried name
		// and omits NS. The bitmap is signed, so its absence is authenticated:
		// no DS exists here. Whether the name is a delegation is a separate
		// question, answered by ZoneCutFromDenial — and a name that is not one
		// keeps being signed by the parent, which is stricter than insecure.
		{"minimal-covering NSEC without NS still proves no DS", []uint16{dns.TypeA, dns.TypeRRSIG}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nsec := &dns.NSEC{
				Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
				NextDomain: "zz.example.com.",
				TypeBitMap: tt.bitmap,
			}
			err := ProveNoDS([]dns.RR{nsec}, "example.com.")
			if tt.wantErr && err == nil {
				t.Error("expected the proof to be rejected")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected the proof to hold, got %v", err)
			}
		})
	}
}

func TestProveNODATA(t *testing.T) {
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
		NextDomain: "zz.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}

	if err := ProveNODATA([]dns.RR{nsec}, "www.example.com.", dns.TypeMX); err != nil {
		t.Errorf("MX absence should be proven: %v", err)
	}
	if err := ProveNODATA([]dns.RR{nsec}, "www.example.com.", dns.TypeA); err == nil {
		t.Error("the bitmap asserts A exists, so NODATA must not be proven")
	}
	if err := ProveNODATA([]dns.RR{nsec}, "other.example.com.", dns.TypeMX); err == nil {
		t.Error("an NSEC for a different name proves nothing")
	}
}

// NXDOMAIN needs both halves: the name is covered, and no wildcard could have
// synthesised it.
func TestProveNXDOMAIN(t *testing.T) {
	covering := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
		NextDomain: "z.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	wildcardDenial := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
		NextDomain: "a.example.com.",
		TypeBitMap: []uint16{dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC},
	}

	t.Run("both halves present", func(t *testing.T) {
		t.Parallel()
		if err := ProveNXDOMAIN([]dns.RR{covering, wildcardDenial}, "m.example.com."); err != nil {
			t.Errorf("expected the denial to hold: %v", err)
		}
	})

	t.Run("wildcard half missing", func(t *testing.T) {
		t.Parallel()
		// Without denying *.example.com. a wildcard could have answered, so
		// the NXDOMAIN is not proven.
		if err := ProveNXDOMAIN([]dns.RR{covering}, "m.example.com."); err == nil {
			t.Error("expected the missing wildcard denial to be caught")
		}
	})

	t.Run("name not covered", func(t *testing.T) {
		t.Parallel()
		if err := ProveNXDOMAIN([]dns.RR{covering, wildcardDenial}, "zz.example.com."); err == nil {
			t.Error("a name outside the NSEC span is not denied by it")
		}
	})
}

// High NSEC3 iteration counts are a CPU-exhaustion vector aimed at validators.
func TestNSEC3_RejectsExcessiveIterations(t *testing.T) {
	n := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: "abcd.example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
		Hash:       dns.SHA1,
		Iterations: 5000,
		Salt:       "aabb",
	}
	err := ProveNoDS([]dns.RR{n}, "example.com.")
	if !errors.Is(err, ErrProofUnsupported) {
		t.Errorf("error = %v, want ErrProofUnsupported", err)
	}
}

func TestCanonicalCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"example.com.", "example.com.", 0},
		{"a.example.com.", "b.example.com.", -1},
		{"b.example.com.", "a.example.com.", 1},
		{"example.com.", "a.example.com.", -1},
		{"EXAMPLE.com.", "example.com.", 0},
		{"z.example.com.", "example.net.", -1},
		{".", "example.com.", -1},
	}
	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			t.Parallel()
			got := CanonicalCompare(tt.a, tt.b)
			if (got < 0) != (tt.want < 0) || (got > 0) != (tt.want > 0) || (got == 0) != (tt.want == 0) {
				t.Errorf("CanonicalCompare(%q, %q) = %d, want sign of %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		s    Status
		want string
	}{
		{StatusIndeterminate, "indeterminate"},
		{StatusInsecure, "insecure"},
		{StatusSecure, "secure"},
		{StatusBogus, "bogus"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Status(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestExtendedError(t *testing.T) {
	tests := []struct {
		err  error
		want uint16
	}{
		{ErrSignatureExpired, dns.ExtendedErrorCodeSignatureExpired},
		{ErrSignatureFailed, dns.ExtendedErrorCodeDNSBogus},
		{ErrNoSignatures, dns.ExtendedErrorCodeRRSIGsMissing},
		{ErrDSMismatch, dns.ExtendedErrorCodeDNSKEYMissing},
		{ErrUnsupportedAlg, dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm},
		{ErrNoProof, dns.ExtendedErrorCodeNSECMissing},
	}
	for _, tt := range tests {
		if got := ExtendedError(tt.err); got != tt.want {
			t.Errorf("ExtendedError(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}
