package dnssec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Denial-of-existence proofs: NSEC (RFC 4035 §5.4) and NSEC3 (RFC 5155 §8).
//
// These matter as much as signature verification. An attacker who can strip
// records turns a signed answer into "no such name" or a signed delegation into
// an unsigned one, so a negative answer is only trustworthy when the zone has
// proved the absence.

var (
	// ErrNoProof means the supplied records do not establish the denial.
	ErrNoProof = errors.New("dnssec: denial of existence not proven")
	// ErrProofUnsupported means the proof uses parameters we refuse.
	ErrProofUnsupported = errors.New("dnssec: unsupported denial parameters")
)

// maxNSEC3Iterations caps accepted NSEC3 iteration counts.
//
// Each iteration costs the validator a hash, so a zone naming a large count is
// a CPU-exhaustion vector aimed at resolvers. RFC 9276 §3.1 says use zero and
// treat high counts as unacceptable.
const maxNSEC3Iterations = 100

// ProveNoDS checks that the records prove there is no DS for name, which is
// what makes a delegation provably insecure rather than merely unsigned.
func ProveNoDS(denial []dns.RR, name string) error {
	name = dns.CanonicalName(name)

	for _, rr := range denial {
		nsec, ok := rr.(*dns.NSEC)
		if !ok {
			continue
		}
		if dns.CanonicalName(nsec.Hdr.Name) != name {
			continue
		}
		// The NSEC must come from the parent side of the cut: NS present,
		// DS absent, and no SOA (a SOA would make this the child's apex,
		// which cannot speak to its own delegation).
		if !HasType(nsec.TypeBitMap, dns.TypeNS) {
			continue
		}
		if HasType(nsec.TypeBitMap, dns.TypeSOA) {
			continue
		}
		if HasType(nsec.TypeBitMap, dns.TypeDS) {
			return fmt.Errorf("%w: NSEC for %s asserts a DS exists", ErrNoProof, name)
		}
		return nil
	}

	for _, rr := range denial {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		if err := checkNSEC3Params(nsec3); err != nil {
			return err
		}
		if nsec3.Match(name) {
			if !HasType(nsec3.TypeBitMap, dns.TypeNS) {
				continue
			}
			if HasType(nsec3.TypeBitMap, dns.TypeSOA) {
				continue
			}
			if HasType(nsec3.TypeBitMap, dns.TypeDS) {
				return fmt.Errorf("%w: NSEC3 for %s asserts a DS exists", ErrNoProof, name)
			}
			return nil
		}
	}

	// Opt-out (RFC 5155 §6): an NSEC3 with the opt-out flag covering the name
	// proves only that the name is not signed, which is exactly the assertion
	// needed for an insecure delegation.
	for _, rr := range denial {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok || nsec3.Flags&0x01 == 0 {
			continue
		}
		if err := checkNSEC3Params(nsec3); err != nil {
			return err
		}
		if nsec3.Cover(name) {
			return nil
		}
	}

	return fmt.Errorf("%w: no NSEC or NSEC3 covers the absence of DS for %s", ErrNoProof, name)
}

// ProveNODATA checks that the records prove name exists but holds no qtype.
func ProveNODATA(denial []dns.RR, name string, qtype uint16) error {
	name = dns.CanonicalName(name)

	for _, rr := range denial {
		nsec, ok := rr.(*dns.NSEC)
		if !ok || dns.CanonicalName(nsec.Hdr.Name) != name {
			continue
		}
		if HasType(nsec.TypeBitMap, qtype) {
			return fmt.Errorf("%w: NSEC for %s asserts %s exists", ErrNoProof, name, dns.TypeToString[qtype])
		}
		// A CNAME would have been followed instead of answering NODATA.
		if HasType(nsec.TypeBitMap, dns.TypeCNAME) {
			return fmt.Errorf("%w: NSEC for %s asserts a CNAME exists", ErrNoProof, name)
		}
		return nil
	}

	for _, rr := range denial {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok {
			continue
		}
		if err := checkNSEC3Params(nsec3); err != nil {
			return err
		}
		if !nsec3.Match(name) {
			continue
		}
		if HasType(nsec3.TypeBitMap, qtype) {
			return fmt.Errorf("%w: NSEC3 for %s asserts %s exists", ErrNoProof, name, dns.TypeToString[qtype])
		}
		if HasType(nsec3.TypeBitMap, dns.TypeCNAME) {
			return fmt.Errorf("%w: NSEC3 for %s asserts a CNAME exists", ErrNoProof, name)
		}
		return nil
	}

	return fmt.Errorf("%w: nothing proves NODATA for %s %s", ErrNoProof, name, dns.TypeToString[qtype])
}

// ProveNXDOMAIN checks that the records prove name does not exist.
//
// Two things must be shown: no NSEC/NSEC3 span contains the name, and no
// wildcard could have synthesised it. Omitting the wildcard half is a real
// hole — a zone with *.example.com would otherwise let a stripped answer look
// like NXDOMAIN.
func ProveNXDOMAIN(denial []dns.RR, name string) error {
	name = dns.CanonicalName(name)

	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, rr := range denial {
		switch v := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, v)
		case *dns.NSEC3:
			if err := checkNSEC3Params(v); err != nil {
				return err
			}
			nsec3s = append(nsec3s, v)
		}
	}

	if len(nsecs) > 0 {
		covered := false
		for _, n := range nsecs {
			if NSECCovers(n, name) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("%w: no NSEC covers %s", ErrNoProof, name)
		}

		wildcard := WildcardOf(name)
		for _, n := range nsecs {
			if NSECCovers(n, wildcard) || dns.CanonicalName(n.Hdr.Name) == wildcard {
				return nil
			}
		}
		return fmt.Errorf("%w: no NSEC denies the wildcard %s", ErrNoProof, wildcard)
	}

	if len(nsec3s) > 0 {
		covered := false
		for _, n := range nsec3s {
			if n.Cover(name) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("%w: no NSEC3 covers %s", ErrNoProof, name)
		}
		wildcard := WildcardOf(name)
		for _, n := range nsec3s {
			if n.Cover(wildcard) || n.Match(wildcard) {
				return nil
			}
		}
		return fmt.Errorf("%w: no NSEC3 denies the wildcard %s", ErrNoProof, wildcard)
	}

	return fmt.Errorf("%w: no NSEC or NSEC3 records supplied for %s", ErrNoProof, name)
}

func checkNSEC3Params(n *dns.NSEC3) error {
	if n.Hash != dns.SHA1 {
		return fmt.Errorf("%w: NSEC3 hash algorithm %d", ErrProofUnsupported, n.Hash)
	}
	if n.Iterations > maxNSEC3Iterations {
		return fmt.Errorf("%w: NSEC3 iterations %d exceeds %d (RFC 9276)",
			ErrProofUnsupported, n.Iterations, maxNSEC3Iterations)
	}
	return nil
}

// NSECCovers reports whether name falls strictly between the NSEC's owner and
// its next name, in canonical order.
// NSECCovers reports whether an NSEC's range proves name does not exist.
func NSECCovers(n *dns.NSEC, name string) bool {
	owner := dns.CanonicalName(n.Hdr.Name)
	next := dns.CanonicalName(n.NextDomain)
	name = dns.CanonicalName(name)

	if name == owner || name == next {
		return false
	}
	if CanonicalCompare(owner, next) < 0 {
		return CanonicalCompare(owner, name) < 0 && CanonicalCompare(name, next) < 0
	}
	// The last NSEC in a zone wraps around to the apex.
	return CanonicalCompare(owner, name) < 0 || CanonicalCompare(name, next) < 0
}

// WildcardOf returns the wildcard that could have synthesised name.
func WildcardOf(name string) string {
	name = dns.CanonicalName(name)
	i, end := dns.NextLabel(name, 0)
	if end {
		return "*."
	}
	return "*." + name[i:]
}

// CanonicalCompare orders two names per RFC 4034 §6.1: label by label from the
// right, each compared as case-insensitive octets.
func CanonicalCompare(a, b string) int {
	if a == b {
		return 0
	}
	al := splitLabels(a)
	bl := splitLabels(b)

	i, j := len(al)-1, len(bl)-1
	for i >= 0 && j >= 0 {
		if c := compareLabel(al[i], bl[j]); c != 0 {
			return c
		}
		i--
		j--
	}
	switch {
	case i < 0 && j < 0:
		return 0
	case i < 0:
		return -1
	default:
		return 1
	}
}

func splitLabels(name string) []string {
	name = dns.CanonicalName(name)
	if name == "." {
		return nil
	}
	labels := dns.SplitDomainName(name)
	return labels
}

func compareLabel(a, b string) int {
	a, b = strings.ToLower(a), strings.ToLower(b)
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) == len(b):
		return 0
	case len(a) < len(b):
		return -1
	default:
		return 1
	}
}

// HasType reports whether a type bitmap contains t.
func HasType(bitmap []uint16, t uint16) bool {
	for _, v := range bitmap {
		if v == t {
			return true
		}
	}
	return false
}
