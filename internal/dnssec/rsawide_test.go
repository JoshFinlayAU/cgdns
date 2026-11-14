package dnssec

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// nic.ai publishes RSA keys with exponent 2^32+1, which both miekg/dns and
// crypto/rsa refuse. Every query under it SERVFAILed with "dns: bad key".
func TestWideRSA_CapturedNicAI(t *testing.T) {
	t.Parallel()
	msg := loadCapture(t, "dnskey-nic.ai-wide-exponent.wire")

	var keys []dns.RR
	var sigs []*dns.RRSIG
	var ksk *dns.DNSKEY
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			keys = append(keys, v)
			if v.Flags&dns.SEP != 0 {
				ksk = v
			}
		case *dns.RRSIG:
			sigs = append(sigs, v)
		}
	}
	if ksk == nil || len(sigs) == 0 {
		t.Fatal("capture holds no KSK or no RRSIG")
	}
	sig := sigs[0]

	if err := sig.Verify(ksk, keys); !errors.Is(err, dns.ErrKey) {
		t.Fatalf("miekg/dns now accepts this key (err=%v); the wide-exponent path may be redundant", err)
	}
	if err := verifyWideRSA(sig, ksk, keys); err != nil {
		t.Fatalf("verifyWideRSA = %v, want the real signature to verify", err)
	}

	at := time.Unix(int64(sig.Inception), 0).Add(time.Hour)
	v, err := New(Options{Anchors: []Anchor{{Zone: "."}}, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	dnskeys := []*dns.DNSKEY{}
	for _, rr := range keys {
		dnskeys = append(dnskeys, rr.(*dns.DNSKEY))
	}
	if _, err := v.VerifyRRset(keys, sigs, dnskeys); err != nil {
		t.Errorf("VerifyRRset = %v, want the nic.ai DNSKEY set to verify", err)
	}

	tampered := dns.Copy(keys[0]).(*dns.DNSKEY)
	tampered.Hdr.Ttl++
	tampered.Flags ^= dns.REVOKE
	if err := verifyWideRSA(sig, ksk, append([]dns.RR{tampered}, keys[1:]...)); err == nil {
		t.Error("a modified RRset verified")
	}
}

type wideTestKey struct {
	dnskey *dns.DNSKEY
	n, d   *big.Int
}

func newWideTestKey(t *testing.T, owner string) *wideTestKey {
	t.Helper()
	e := new(big.Int).SetUint64(1<<32 + 1)
	one := big.NewInt(1)
	for {
		p, err := rand.Prime(rand.Reader, 512)
		if err != nil {
			t.Fatal(err)
		}
		q, err := rand.Prime(rand.Reader, 512)
		if err != nil {
			t.Fatal(err)
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != 1024 {
			continue
		}
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}
		buf := append([]byte{byte(len(e.Bytes()))}, e.Bytes()...)
		buf = append(buf, n.Bytes()...)
		return &wideTestKey{
			dnskey: &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: owner, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.RSASHA256,
				PublicKey: base64.StdEncoding.EncodeToString(buf),
			},
			n: n,
			d: d,
		}
	}
}

func (k *wideTestKey) Public() crypto.PublicKey { return nil }

func (k *wideTestKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	size := (k.n.BitLen() + 7) / 8
	em, ok := pkcs1v15Encode(size, opts.HashFunc(), digest)
	if !ok {
		return nil, errors.New("cannot encode digest")
	}
	s := new(big.Int).Exp(new(big.Int).SetBytes(em), k.d, k.n)
	return s.FillBytes(make([]byte, size)), nil
}

func (k *wideTestKey) sign(t *testing.T, rrset []dns.RR) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Ttl: 300},
		Algorithm:  dns.RSASHA256,
		KeyTag:     k.dnskey.KeyTag(),
		SignerName: k.dnskey.Hdr.Name,
		Inception:  uint32(testNow.Add(-time.Hour).Unix()),
		Expiration: uint32(testNow.Add(time.Hour).Unix()),
	}
	if err := sig.Sign(k, rrset); err != nil {
		t.Fatalf("signing: %v", err)
	}
	return sig
}

func TestWideRSA_SignedRRsets(t *testing.T) {
	t.Parallel()
	key := newWideTestKey(t, "example.")
	v := newValidator(t, []Anchor{{Zone: "."}}, nil)
	keys := []*dns.DNSKEY{key.dnskey}

	t.Run("plain RRset", func(t *testing.T) {
		t.Parallel()
		rrset := []dns.RR{aRecord("www.example.", "192.0.2.1", 300)}
		sig := key.sign(t, rrset)
		if _, err := v.VerifyRRset(rrset, []*dns.RRSIG{sig}, keys); err != nil {
			t.Errorf("VerifyRRset = %v", err)
		}
		rrset[0].(*dns.A).A[3] = 2
		if _, err := v.VerifyRRset(rrset, []*dns.RRSIG{sig}, keys); err == nil {
			t.Error("a modified RRset verified")
		}
	})

	t.Run("TTL decremented in transit", func(t *testing.T) {
		t.Parallel()
		rrset := []dns.RR{aRecord("www.example.", "192.0.2.1", 300)}
		sig := key.sign(t, rrset)
		rrset[0].Header().Ttl = 17
		if _, err := v.VerifyRRset(rrset, []*dns.RRSIG{sig}, keys); err != nil {
			t.Errorf("VerifyRRset = %v: the original TTL is what was signed", err)
		}
	})

	t.Run("wildcard expansion", func(t *testing.T) {
		t.Parallel()
		signed := []dns.RR{aRecord("*.example.", "192.0.2.9", 300)}
		sig := key.sign(t, signed)
		expanded := []dns.RR{aRecord("host.example.", "192.0.2.9", 300)}
		sig.Hdr.Name = "host.example."
		if _, err := v.VerifyRRset(expanded, []*dns.RRSIG{sig}, keys); err != nil {
			t.Errorf("VerifyRRset = %v, want the wildcard-signed answer to verify", err)
		}
	})
}

func TestWideRSA_ParseLimits(t *testing.T) {
	t.Parallel()
	mod := make([]byte, 128)
	mod[0] = 0xc1
	key := func(alg uint8, exp []byte) *dns.DNSKEY {
		buf := append([]byte{byte(len(exp))}, exp...)
		return &dns.DNSKEY{Algorithm: alg, PublicKey: base64.StdEncoding.EncodeToString(append(buf, mod...))}
	}
	tests := []struct {
		name string
		key  *dns.DNSKEY
		want bool
	}{
		{"65537 is left to the standard path", key(dns.RSASHA256, []byte{1, 0, 1}), false},
		{"2^32+1 is wide", key(dns.RSASHA256, []byte{1, 0, 0, 0, 1}), true},
		{"eight bytes is the cap", key(dns.RSASHA512, []byte{1, 0, 0, 0, 0, 0, 0, 1}), true},
		{"nine bytes is refused", key(dns.RSASHA256, []byte{1, 0, 0, 0, 0, 0, 0, 0, 1}), false},
		{"leading zero is refused", key(dns.RSASHA256, []byte{0, 1, 0, 0, 1}), false},
		{"not RSA", key(dns.ECDSAP256SHA256, []byte{1, 0, 0, 0, 1}), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, got := parseWideRSAKey(tc.key); got != tc.want {
				t.Errorf("parseWideRSAKey = %t, want %t", got, tc.want)
			}
		})
	}
}
