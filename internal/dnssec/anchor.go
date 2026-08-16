// Package dnssec validates the DNSSEC chain of trust (RFC 4033-4035) and
// denial of existence (RFC 4035 NSEC, RFC 5155 NSEC3).
//
// Validation is the only thing permitted to set AD on a response. A chain that
// fails validation is Bogus and must become SERVFAIL with an RFC 8914 extended
// error, never a silent downgrade to an unvalidated answer.
package dnssec

import (
	_ "embed"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

//go:embed root-anchors.xml
var rootAnchorsXML []byte

// Anchor is a configured point of trust: a DS-equivalent digest, and
// optionally the key itself, for a zone.
type Anchor struct {
	Zone       string
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string
	ValidFrom  time.Time
	ValidUntil time.Time
}

// Valid reports whether the anchor is usable at now. An anchor with no
// ValidUntil never expires.
func (a Anchor) Valid(now time.Time) bool {
	if !a.ValidFrom.IsZero() && now.Before(a.ValidFrom) {
		return false
	}
	if !a.ValidUntil.IsZero() && now.After(a.ValidUntil) {
		return false
	}
	return true
}

// MatchesDNSKEY reports whether key hashes to this anchor's digest.
func (a Anchor) MatchesDNSKEY(key *dns.DNSKEY) bool {
	if key == nil || key.KeyTag() != a.KeyTag || key.Algorithm != a.Algorithm {
		return false
	}
	ds := key.ToDS(a.DigestType)
	if ds == nil {
		return false
	}
	return strings.EqualFold(ds.Digest, a.Digest)
}

// ToDS renders the anchor as a DS record, so chain validation can treat a
// trust anchor and a delegation signer identically.
func (a Anchor) ToDS() *dns.DS {
	return &dns.DS{
		Hdr:        dns.RR_Header{Name: dns.CanonicalName(a.Zone), Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     a.KeyTag,
		Algorithm:  a.Algorithm,
		DigestType: a.DigestType,
		Digest:     strings.ToUpper(a.Digest),
	}
}

type xmlTrustAnchor struct {
	Zone       string `xml:"Zone"`
	KeyDigests []struct {
		ValidFrom  string `xml:"validFrom,attr"`
		ValidUntil string `xml:"validUntil,attr"`
		KeyTag     uint16 `xml:"KeyTag"`
		Algorithm  uint8  `xml:"Algorithm"`
		DigestType uint8  `xml:"DigestType"`
		Digest     string `xml:"Digest"`
	} `xml:"KeyDigest"`
}

// ParseAnchors reads IANA's root-anchors.xml format.
func ParseAnchors(raw []byte) ([]Anchor, error) {
	var ta xmlTrustAnchor
	if err := xml.Unmarshal(raw, &ta); err != nil {
		return nil, fmt.Errorf("parsing trust anchors: %w", err)
	}
	zone := dns.CanonicalName(ta.Zone)
	if zone == "" {
		zone = "."
	}

	out := make([]Anchor, 0, len(ta.KeyDigests))
	for _, kd := range ta.KeyDigests {
		digest := strings.TrimSpace(kd.Digest)
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("trust anchor %d: digest is not hex: %w", kd.KeyTag, err)
		}
		a := Anchor{
			Zone:       zone,
			KeyTag:     kd.KeyTag,
			Algorithm:  kd.Algorithm,
			DigestType: kd.DigestType,
			Digest:     digest,
		}
		if kd.ValidFrom != "" {
			t, err := time.Parse(time.RFC3339, kd.ValidFrom)
			if err != nil {
				return nil, fmt.Errorf("trust anchor %d: bad validFrom: %w", kd.KeyTag, err)
			}
			a.ValidFrom = t
		}
		if kd.ValidUntil != "" {
			t, err := time.Parse(time.RFC3339, kd.ValidUntil)
			if err != nil {
				return nil, fmt.Errorf("trust anchor %d: bad validUntil: %w", kd.KeyTag, err)
			}
			a.ValidUntil = t
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("parsing trust anchors: no key digests found")
	}
	return out, nil
}

// RootAnchors returns the anchors shipped in the package that are valid at now.
//
// Anchors that have passed their validUntil are dropped: a retired KSK must not
// be able to validate a chain. If every shipped anchor has expired the node
// cannot validate anything, so this is an error rather than an empty set.
func RootAnchors(now time.Time) ([]Anchor, error) {
	all, err := ParseAnchors(rootAnchorsXML)
	if err != nil {
		return nil, err
	}
	out := make([]Anchor, 0, len(all))
	for _, a := range all {
		if a.Valid(now) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no root trust anchor is valid at %s: the shipped anchors need refreshing from https://data.iana.org/root-anchors/root-anchors.xml", now.Format(time.RFC3339))
	}
	return out, nil
}

// RawRootAnchors returns the embedded anchor file verbatim.
func RawRootAnchors() []byte { return rootAnchorsXML }
