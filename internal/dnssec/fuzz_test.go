package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

// seedDenial gives the fuzzer a few real shapes to mutate, so it spends its
// time on the interesting edges rather than rediscovering the wire format.
func seedDenial(f *testing.F) {
	f.Helper()

	mk := func(build func(m *dns.Msg)) []byte {
		m := new(dns.Msg)
		m.SetQuestion("www.example.com.", dns.TypeA)
		build(m)
		raw, err := m.Pack()
		if err != nil {
			f.Fatalf("packing a seed: %v", err)
		}
		return raw
	}

	// An NSEC denial.
	f.Add(mk(func(m *dns.Msg) {
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{
			&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns: "ns.example.com.", Mbox: "hostmaster.example.com.", Serial: 1, Minttl: 300},
			&dns.NSEC{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "z.example.com.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}},
		}
	}))

	// An NSEC3 denial, opt-out set.
	f.Add(mk(func(m *dns.Msg) {
		m.Ns = []dns.RR{
			&dns.NSEC3{Hdr: dns.RR_Header{Name: "00000000000000000000000000000000.example.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
				Hash: dns.SHA1, Flags: 1, Iterations: 0, SaltLength: 0,
				HashLength: 20, NextDomain: "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV",
				TypeBitMap: []uint16{dns.TypeNS}},
		}
	}))

	// A minimal-covering NSEC, the shape a synthesising signer emits.
	f.Add(mk(func(m *dns.Msg) {
		m.Ns = []dns.RR{
			&dns.NSEC{Hdr: dns.RR_Header{Name: "cdn.example.net.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "\\000.cdn.example.net.",
				TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC}},
		}
	}))

	f.Add([]byte{})
	f.Add([]byte{0x00})
}

// The proof functions decide whether a name is securely absent, from records an
// attacker supplies. They must never panic, and they must never report a proof
// held when the very record they were reading contradicts it.
func FuzzDenialProofs(f *testing.F) {
	seedDenial(f)

	f.Fuzz(func(t *testing.T, raw []byte) {
		msg := new(dns.Msg)
		if err := msg.Unpack(raw); err != nil {
			return
		}
		name := "www.example.com."
		if len(msg.Question) > 0 {
			name = dns.CanonicalName(msg.Question[0].Name)
		}
		if _, ok := dns.IsDomainName(name); !ok {
			return
		}

		_ = ProveNXDOMAIN(msg.Ns, name)
		_ = ProveNODATA(msg.Ns, name, dns.TypeA)

		// A held no-DS proof must not be contradicted by a DS in the very
		// records that were read. Getting this wrong is a downgrade: the
		// resolver would call a signed delegation insecure and stop validating
		// everything beneath it.
		if err := ProveNoDS(msg.Ns, name); err == nil {
			for _, rr := range msg.Ns {
				ds, ok := rr.(*dns.DS)
				if ok && dns.CanonicalName(ds.Hdr.Name) == name {
					t.Fatalf("ProveNoDS held while a DS for %s was present in the same records", name)
				}
			}
		}

		// Reading the zone-cut hint must agree with itself: a claim of "known"
		// has to come from a record that actually matches the name.
		if isCut, known := ZoneCutFromDenial(msg.Ns, name); known {
			matched := false
			for _, rr := range msg.Ns {
				switch v := rr.(type) {
				case *dns.NSEC:
					if dns.CanonicalName(v.Hdr.Name) == name {
						matched = true
					}
				case *dns.NSEC3:
					if v.Match(name) {
						matched = true
					}
				}
			}
			if !matched {
				t.Fatalf("ZoneCutFromDenial reported known=%t/cut=%t for %s with no matching record",
					known, isCut, name)
			}
		}
	})
}

// Anchors come from a file an operator supplies, but a corrupted or truncated
// one must fail rather than take the daemon down with it.
func FuzzParseAnchors(f *testing.F) {
	f.Add([]byte(`<?xml version="1.0" encoding="UTF-8"?><TrustAnchor></TrustAnchor>`))
	f.Add([]byte(". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, raw []byte) {
		anchors, err := ParseAnchors(raw)
		if err != nil {
			return
		}
		// Anything accepted has to be usable, or it would fail later at a point
		// far from the input that caused it.
		for _, a := range anchors {
			if a.Zone == "" {
				t.Fatal("accepted an anchor with no zone")
			}
			if a.Digest == "" {
				t.Fatalf("accepted an anchor for %s with no digest", a.Zone)
			}
		}
	})
}
