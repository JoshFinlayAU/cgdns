package dnssec

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"math/big"
	"strings"

	"github.com/miekg/dns"
)

// RFC 3110 §2 allows an RSA public exponent of up to 4096 bits. Go's
// crypto/rsa refuses anything above 2^31-1 and miekg/dns anything over four
// bytes, yet signed zones such as nic.ai publish 2^32+1, and every other
// validator accepts it. Keys like that are verified here instead.
//
// The exponent is attacker-supplied and verification cost grows with its
// length, so it is capped well below what the RFC permits.
const maxRSAExponentBytes = 8

var digestInfoPrefix = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

type wideRSAKey struct {
	e, n *big.Int
	size int
}

func rsaHash(alg uint8) (crypto.Hash, bool) {
	switch alg {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1:
		return crypto.SHA1, true
	case dns.RSASHA256:
		return crypto.SHA256, true
	case dns.RSASHA512:
		return crypto.SHA512, true
	}
	return 0, false
}

// parseWideRSAKey decodes an RSA DNSKEY (RFC 3110 §2) whose exponent is too
// long for the standard libraries. It reports false for any other key.
func parseWideRSAKey(k *dns.DNSKEY) (wideRSAKey, bool) {
	if _, ok := rsaHash(k.Algorithm); !ok {
		return wideRSAKey{}, false
	}
	buf, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(buf) < 3 {
		return wideRSAKey{}, false
	}
	explen, off := int(buf[0]), 1
	if explen == 0 {
		explen, off = int(buf[1])<<8|int(buf[2]), 3
	}
	if explen <= 4 || explen > maxRSAExponentBytes || len(buf) < off+explen {
		return wideRSAKey{}, false
	}
	exp, mod := buf[off:off+explen], buf[off+explen:]
	if exp[0] == 0 || len(mod) < 64 || len(mod) > 512 || mod[0] == 0 {
		return wideRSAKey{}, false
	}
	return wideRSAKey{e: new(big.Int).SetBytes(exp), n: new(big.Int).SetBytes(mod), size: len(mod)}, true
}

// verifyWideRSA checks an RSA PKCS#1 v1.5 signature (RFC 3110 §3, RFC 5702
// §3) made with a key parseWideRSAKey accepts. It applies the same key and
// RRset checks as dns.RRSIG.Verify.
func verifyWideRSA(sig *dns.RRSIG, k *dns.DNSKEY, rrset []dns.RR) error {
	key, ok := parseWideRSAKey(k)
	if !ok {
		return dns.ErrKey
	}
	hash, _ := rsaHash(sig.Algorithm)

	if sig.KeyTag != k.KeyTag() || sig.Hdr.Class != k.Hdr.Class || sig.Algorithm != k.Algorithm ||
		dns.CanonicalName(sig.SignerName) != dns.CanonicalName(k.Hdr.Name) ||
		k.Protocol != 3 || k.Flags&dns.ZONE == 0 {
		return dns.ErrKey
	}
	if !dns.IsRRset(rrset) {
		return dns.ErrRRset
	}
	h0 := rrset[0].Header()
	if h0.Class != sig.Hdr.Class || h0.Rrtype != sig.TypeCovered ||
		dns.CountLabel(h0.Name) < int(sig.Labels) ||
		!strings.EqualFold(h0.Name, sig.Hdr.Name) ||
		!dns.IsSubDomain(dns.CanonicalName(sig.SignerName), dns.CanonicalName(h0.Name)) {
		return dns.ErrRRset
	}

	digest, err := signedDigest(sig, rrset)
	if err != nil {
		return err
	}

	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil || len(raw) != key.size {
		return dns.ErrSig
	}
	s := new(big.Int).SetBytes(raw)
	if s.Cmp(key.n) >= 0 {
		return dns.ErrSig
	}
	em := new(big.Int).Exp(s, key.e, key.n).FillBytes(make([]byte, key.size))

	want, ok := pkcs1v15Encode(key.size, hash, digest)
	if !ok || subtle.ConstantTimeCompare(em, want) != 1 {
		return dns.ErrSig
	}
	return nil
}

// signedDigest returns the hash dns.RRSIG.Verify would check, by running the
// library's own signing path over a copy of the signature. The library builds
// the canonical form (RFC 4034 §6, RFC 4035 §5.3.2) and hands the digest to
// the signer, which is all that is needed from it.
func signedDigest(sig *dns.RRSIG, rrset []dns.RR) ([]byte, error) {
	c := dns.Copy(sig).(*dns.RRSIG)
	set := make([]dns.RR, len(rrset))
	for i, rr := range rrset {
		set[i] = dns.Copy(rr)
		set[i].Header().Ttl = sig.OrigTtl
	}

	// Sign derives Labels from the owner name, so a wildcard expansion is
	// signed under the wildcard it came from (RFC 4035 §5.3.2).
	owner := dns.CanonicalName(set[0].Header().Name)
	if labels := dns.SplitDomainName(owner); int(sig.Labels) < len(labels) {
		wildcard := "*." + dns.Fqdn(strings.Join(labels[len(labels)-int(sig.Labels):], "."))
		if sig.Labels == 0 {
			wildcard = "*."
		}
		for _, rr := range set {
			rr.Header().Name = wildcard
		}
	}

	var capture digestCapture
	if err := c.Sign(&capture, set); err != nil {
		return nil, err
	}
	if c.Labels != sig.Labels || capture.digest == nil {
		return nil, dns.ErrRRset
	}
	return capture.digest, nil
}

func pkcs1v15Encode(size int, hash crypto.Hash, digest []byte) ([]byte, bool) {
	prefix, ok := digestInfoPrefix[hash]
	if !ok || len(digest) != hash.Size() {
		return nil, false
	}
	tLen := len(prefix) + len(digest)
	if size < tLen+11 {
		return nil, false
	}
	em := make([]byte, size)
	em[1] = 0x01
	copy(em[2:size-tLen-1], bytes.Repeat([]byte{0xff}, size-tLen-3))
	copy(em[size-tLen:], prefix)
	copy(em[size-len(digest):], digest)
	return em, true
}

type digestCapture struct{ digest []byte }

func (d *digestCapture) Public() crypto.PublicKey { return nil }

func (d *digestCapture) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	d.digest = append([]byte(nil), digest...)
	return []byte{0}, nil
}
