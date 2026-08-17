package dnssec

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Status is the security status of an answer (RFC 4033 §5).
type Status uint8

const (
	// StatusIndeterminate means no trust anchor covers the name.
	StatusIndeterminate Status = iota
	// StatusInsecure means the zone is provably unsigned.
	StatusInsecure
	// StatusSecure means the chain validated to a trust anchor.
	StatusSecure
	// StatusBogus means signatures or the chain failed. Never serve this as an
	// answer: it becomes SERVFAIL with an extended error.
	StatusBogus
)

// String implements fmt.Stringer.
func (s Status) String() string {
	switch s {
	case StatusInsecure:
		return "insecure"
	case StatusSecure:
		return "secure"
	case StatusBogus:
		return "bogus"
	default:
		return "indeterminate"
	}
}

// Errors describing why a chain failed. Each maps to an RFC 8914 extended
// error code via ExtendedError.
var (
	ErrNoSignatures     = errors.New("dnssec: rrset has no signatures")
	ErrNoMatchingKey    = errors.New("dnssec: no DNSKEY matches the signature")
	ErrSignatureFailed  = errors.New("dnssec: signature verification failed")
	ErrSignatureExpired = errors.New("dnssec: signature outside its validity period")
	ErrNoDNSKEY         = errors.New("dnssec: zone has no DNSKEY RRset")
	ErrDSMismatch       = errors.New("dnssec: no DNSKEY matches the delegation signer")
	ErrChainTooDeep     = errors.New("dnssec: chain of trust too deep")
	ErrUnsupportedAlg   = errors.New("dnssec: unsupported algorithm")
)

// Fetcher retrieves the records the chain walk needs. The resolver implements
// it; declaring it here keeps chain logic in one package.
type Fetcher interface {
	// FetchSigned returns the RRset for name/qtype together with its RRSIGs.
	// A name that does not exist returns an empty rrs with a nil error, plus
	// whatever denial records the server supplied.
	FetchSigned(ctx context.Context, name string, qtype uint16) (rrs []dns.RR, sigs []*dns.RRSIG, denial []dns.RR, err error)
}

// Options configures a Validator.
type Options struct {
	// Anchors are the points of trust. Required.
	Anchors []Anchor
	// Fetcher retrieves DNSKEY and DS records. Required for chain walking.
	Fetcher Fetcher
	// MaxDepth bounds how many zone cuts a chain may cross.
	MaxDepth int
	// Now is injectable for tests.
	Now func() time.Time
	// AcceptSHA1 permits RSASHA1 signatures. Off by default: SHA-1 is no
	// longer collision resistant, and a validator that accepts it undermines
	// the guarantee it exists to provide.
	AcceptSHA1 bool
}

// Validator verifies signatures and builds chains of trust.
type Validator struct {
	anchors []Anchor
	fetch   Fetcher
	maxDep  int
	now     func() time.Time
	sha1    bool
}

// New builds a Validator.
func New(opts Options) (*Validator, error) {
	if len(opts.Anchors) == 0 {
		return nil, errors.New("dnssec: at least one trust anchor is required")
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 16
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Validator{
		anchors: opts.Anchors,
		fetch:   opts.Fetcher,
		maxDep:  opts.MaxDepth,
		now:     opts.Now,
		sha1:    opts.AcceptSHA1,
	}, nil
}

// SetFetcher installs the Fetcher after construction.
//
// The resolver and the validator each need the other: the validator pulls
// DNSKEY and DS records back through the resolver's delegation walk, and the
// resolver consults the validator on every answer. One of the two has to be
// wired up second.
func (v *Validator) SetFetcher(f Fetcher) { v.fetch = f }

// AnchorsFor returns the trust anchors covering zone.
func (v *Validator) AnchorsFor(zone string) []Anchor {
	zone = dns.CanonicalName(zone)
	now := v.now()
	var out []Anchor
	for _, a := range v.anchors {
		if dns.CanonicalName(a.Zone) == zone && a.Valid(now) {
			out = append(out, a)
		}
	}
	return out
}

// VerifyRRset checks that rrset is covered by a valid signature made by one of
// keys. It performs the RFC 4035 §5.3.1 acceptance checks before attempting
// any cryptography, so a malformed or mismatched signature is rejected without
// spending a verification.
func (v *Validator) VerifyRRset(rrset []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY) (*dns.RRSIG, error) {
	if len(rrset) == 0 {
		return nil, ErrNoSignatures
	}
	if len(sigs) == 0 {
		return nil, ErrNoSignatures
	}

	now := v.now()
	owner := dns.CanonicalName(rrset[0].Header().Name)
	rrtype := rrset[0].Header().Rrtype

	var lastErr error = ErrNoMatchingKey
	for _, sig := range sigs {
		if sig.TypeCovered != rrtype {
			continue
		}
		signer := dns.CanonicalName(sig.SignerName)
		// The signer must be at or above the owner name; a zone cannot sign
		// for names outside itself.
		if !dns.IsSubDomain(signer, owner) {
			continue
		}
		if int(sig.Labels) > dns.CountLabel(owner) {
			continue
		}
		if !v.algorithmAllowed(sig.Algorithm) {
			lastErr = fmt.Errorf("%w: algorithm %d", ErrUnsupportedAlg, sig.Algorithm)
			continue
		}
		if !sig.ValidityPeriod(now) {
			lastErr = fmt.Errorf("%w: inception %d expiration %d",
				ErrSignatureExpired, sig.Inception, sig.Expiration)
			continue
		}

		for _, key := range keys {
			if key.Algorithm != sig.Algorithm || key.KeyTag() != sig.KeyTag {
				continue
			}
			if dns.CanonicalName(key.Hdr.Name) != signer {
				continue
			}
			// The ZONE flag must be set; a key without it is not a zone key
			// and may not sign zone data (RFC 4034 §2.1.1).
			if key.Flags&dns.ZONE == 0 {
				continue
			}
			if err := sig.Verify(key, rrset); err != nil {
				lastErr = fmt.Errorf("%w: %v", ErrSignatureFailed, err)
				continue
			}
			return sig, nil
		}
	}
	return nil, lastErr
}

func (v *Validator) algorithmAllowed(alg uint8) bool {
	switch alg {
	case dns.RSASHA256, dns.RSASHA512, dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519, dns.ED448:
		return true
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1:
		return v.sha1
	default:
		return false
	}
}

// WasWildcardExpanded reports whether sig proves the answer came from a
// wildcard. Such an answer is only valid alongside an NSEC/NSEC3 proof that no
// closer name exists, which the caller must check.
func WasWildcardExpanded(sig *dns.RRSIG, owner string) bool {
	return int(sig.Labels) < dns.CountLabel(dns.CanonicalName(owner))
}

// TrustedKeys returns the validated DNSKEY set for zone, walking the chain from
// the nearest trust anchor.
//
// A zone with no DS in its parent is Insecure, provided the parent proved the
// absence. An unproven absence is Bogus: without the proof, a downgrade attack
// is indistinguishable from an unsigned zone.
func (v *Validator) TrustedKeys(ctx context.Context, zone string) ([]*dns.DNSKEY, Status, error) {
	if v.fetch == nil {
		return nil, StatusIndeterminate, errors.New("dnssec: no fetcher configured")
	}
	return v.trustedKeys(ctx, dns.CanonicalName(zone), 0)
}

func (v *Validator) trustedKeys(ctx context.Context, zone string, depth int) ([]*dns.DNSKEY, Status, error) {
	if depth > v.maxDep {
		return nil, StatusBogus, ErrChainTooDeep
	}

	dsSet, parentKeys, status, err := v.delegationSigners(ctx, zone, depth)
	if errors.Is(err, errNotAZoneCut) {
		// Not cut from its parent, so it has no keys of its own: the records
		// sitting at this name are signed by the parent zone.
		return parentKeys, StatusSecure, nil
	}
	if err != nil || status != StatusSecure {
		return nil, status, err
	}

	keys, sigs, _, err := v.fetch.FetchSigned(ctx, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, StatusIndeterminate, fmt.Errorf("%w: fetching DNSKEY for %s: %w", ErrEvidenceUnavailable, zone, err)
	}
	dnskeys := make([]*dns.DNSKEY, 0, len(keys))
	for _, rr := range keys {
		if k, ok := rr.(*dns.DNSKEY); ok {
			dnskeys = append(dnskeys, k)
		}
	}
	if len(dnskeys) == 0 {
		return nil, StatusBogus, fmt.Errorf("%w: %s", ErrNoDNSKEY, zone)
	}

	// At least one key must hash to a DS we already trust. That key is the
	// entry point; the rest of the set is trusted only once the whole RRset
	// is verified with it.
	var entry []*dns.DNSKEY
	for _, k := range dnskeys {
		for _, ds := range dsSet {
			if matchDS(ds, k) {
				entry = append(entry, k)
				break
			}
		}
	}
	if len(entry) == 0 {
		return nil, StatusBogus, fmt.Errorf("%w: %s", ErrDSMismatch, zone)
	}

	rrset := make([]dns.RR, 0, len(dnskeys))
	for _, k := range dnskeys {
		rrset = append(rrset, k)
	}
	if _, err := v.VerifyRRset(rrset, sigs, entry); err != nil {
		return nil, StatusBogus, fmt.Errorf("verifying DNSKEY for %s: %w", zone, err)
	}
	return dnskeys, StatusSecure, nil
}

// delegationSigners returns the DS set securing zone, either from a trust
// anchor or from the validated parent zone.
// delegationSigners returns the DS set securing zone. When the name turns out
// not to be a zone cut it returns the parent's keys instead, since those are
// what sign records sitting at that name — refetching them would spend outbound
// queries the client's budget has to pay for.
func (v *Validator) delegationSigners(ctx context.Context, zone string, depth int) ([]*dns.DS, []*dns.DNSKEY, Status, error) {
	if anchors := v.AnchorsFor(zone); len(anchors) > 0 {
		out := make([]*dns.DS, 0, len(anchors))
		for _, a := range anchors {
			out = append(out, a.ToDS())
		}
		return out, nil, StatusSecure, nil
	}
	if zone == "." {
		return nil, nil, StatusIndeterminate, nil
	}

	parent := parentZone(zone)
	parentKeys, status, err := v.trustedKeys(ctx, parent, depth+1)
	if err != nil || status != StatusSecure {
		return nil, nil, status, err
	}

	rrs, sigs, denial, err := v.fetch.FetchSigned(ctx, zone, dns.TypeDS)
	if err != nil {
		return nil, nil, StatusIndeterminate, fmt.Errorf("%w: fetching DS for %s: %w", ErrEvidenceUnavailable, zone, err)
	}

	dsSet := make([]*dns.DS, 0, len(rrs))
	for _, rr := range rrs {
		if ds, ok := rr.(*dns.DS); ok {
			dsSet = append(dsSet, ds)
		}
	}

	if len(dsSet) == 0 {
		// No DS. The parent must prove it, otherwise an attacker who strips
		// the DS looks exactly like an unsigned delegation.
		if err := v.verifyDenial(denial, parentKeys, zone); err != nil {
			return nil, nil, StatusBogus, fmt.Errorf("unproven insecure delegation for %s: %w", zone, err)
		}
		if isCut, known := ZoneCutFromDenial(denial, zone); known && !isCut {
			return nil, parentKeys, StatusSecure, errNotAZoneCut
		}
		return nil, nil, StatusInsecure, nil
	}

	rrset := make([]dns.RR, 0, len(dsSet))
	for _, ds := range dsSet {
		rrset = append(rrset, ds)
	}
	if _, err := v.VerifyRRset(rrset, sigs, parentKeys); err != nil {
		return nil, nil, StatusBogus, fmt.Errorf("verifying DS for %s: %w", zone, err)
	}

	// A DS naming only algorithms we refuse leaves the zone unvalidatable.
	// Treating that as Insecure would be a downgrade, so it is Bogus.
	usable := false
	for _, ds := range dsSet {
		if v.algorithmAllowed(ds.Algorithm) {
			usable = true
			break
		}
	}
	if !usable {
		return nil, nil, StatusBogus, fmt.Errorf("%w: DS for %s names no supported algorithm", ErrUnsupportedAlg, zone)
	}
	return dsSet, nil, StatusSecure, nil
}

// verifyDenial checks that denial records prove name/qtype does not exist, and
// that those records are themselves signed by keys.
func (v *Validator) verifyDenial(denial []dns.RR, keys []*dns.DNSKEY, name string) error {
	if len(denial) == 0 {
		return errors.New("dnssec: no denial-of-existence records supplied")
	}
	if err := v.verifyDenialSignatures(denial, keys); err != nil {
		return err
	}
	return ProveNoDS(denial, name)
}

// verifyDenialSignatures verifies every NSEC/NSEC3 RRset present in the denial
// records. An unsigned proof proves nothing.
func (v *Validator) verifyDenialSignatures(denial []dns.RR, keys []*dns.DNSKEY) error {
	sigs := make([]*dns.RRSIG, 0, len(denial))
	for _, rr := range denial {
		if s, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, s)
		}
	}
	if len(sigs) == 0 {
		return ErrNoSignatures
	}

	groups := map[string][]dns.RR{}
	for _, rr := range denial {
		switch rr.(type) {
		case *dns.NSEC, *dns.NSEC3, *dns.SOA:
			h := rr.Header()
			k := fmt.Sprintf("%s|%d", dns.CanonicalName(h.Name), h.Rrtype)
			groups[k] = append(groups[k], rr)
		}
	}
	if len(groups) == 0 {
		return errors.New("dnssec: denial contains no NSEC or NSEC3 records")
	}
	for _, rrset := range groups {
		if _, err := v.VerifyRRset(rrset, sigs, keys); err != nil {
			return err
		}
	}
	return nil
}

// matchDS reports whether key hashes to ds.
func matchDS(ds *dns.DS, key *dns.DNSKEY) bool {
	if ds == nil || key == nil {
		return false
	}
	if key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
		return false
	}
	if key.Flags&dns.ZONE == 0 {
		return false
	}
	computed := key.ToDS(ds.DigestType)
	if computed == nil {
		return false
	}
	return equalFoldASCII(computed.Digest, ds.Digest)
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// parentZone strips the leftmost label. The root's parent is itself.
func parentZone(zone string) string {
	zone = dns.CanonicalName(zone)
	if zone == "." {
		return "."
	}
	i, end := dns.NextLabel(zone, 0)
	if end {
		return "."
	}
	return zone[i:]
}

// errNotAZoneCut signals that a name carries no DS because it is not a
// delegation point at all. It never escapes trustedKeys.
var errNotAZoneCut = errors.New("dnssec: name is not a zone cut")

// ExtendedError maps a validation failure to its RFC 8914 code, so a client
// learns why validation failed rather than just that it did.
func ExtendedError(err error) uint16 {
	switch {
	case errors.Is(err, ErrEvidenceUnavailable):
		return dns.ExtendedErrorCodeNoReachableAuthority
	case errors.Is(err, ErrSignatureExpired):
		return dns.ExtendedErrorCodeSignatureExpired
	case errors.Is(err, ErrSignatureFailed):
		return dns.ExtendedErrorCodeDNSBogus
	case errors.Is(err, ErrNoSignatures):
		return dns.ExtendedErrorCodeRRSIGsMissing
	case errors.Is(err, ErrDSMismatch):
		return dns.ExtendedErrorCodeDNSKEYMissing
	case errors.Is(err, ErrNoDNSKEY):
		return dns.ExtendedErrorCodeDNSKEYMissing
	case errors.Is(err, ErrNoMatchingKey):
		return dns.ExtendedErrorCodeDNSKEYMissing
	case errors.Is(err, ErrUnsupportedAlg):
		return dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm
	case errors.Is(err, ErrProofUnsupported):
		return dns.ExtendedErrorCodeUnsupportedNSEC3IterValue
	case errors.Is(err, ErrNoProof):
		return dns.ExtendedErrorCodeNSECMissing
	default:
		return dns.ExtendedErrorCodeDNSBogus
	}
}
