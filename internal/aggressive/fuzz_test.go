package aggressive

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The store synthesises NXDOMAIN answers from records it was given. Those
// records arrive from the network, so the store must never panic on them, and
// must never claim a denial it cannot back with a SOA and a live TTL — a
// synthesised answer with neither is an assertion the resolver cannot support.
func FuzzStore(f *testing.F) {
	mk := func(build func(m *dns.Msg)) []byte {
		m := new(dns.Msg)
		m.SetQuestion("absent.example.com.", dns.TypeA)
		build(m)
		raw, err := m.Pack()
		if err != nil {
			f.Fatalf("packing a seed: %v", err)
		}
		return raw
	}

	f.Add(mk(func(m *dns.Msg) {
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{
			&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns: "ns.example.com.", Mbox: "hostmaster.example.com.", Serial: 1, Minttl: 300},
			&dns.NSEC{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
				NextDomain: "z.example.com.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}},
		}
	}))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		msg := new(dns.Msg)
		if err := msg.Unpack(raw); err != nil {
			return
		}
		name := "absent.example.com."
		if len(msg.Question) > 0 {
			name = dns.CanonicalName(msg.Question[0].Name)
		}
		if _, ok := dns.IsDomainName(name); !ok {
			return
		}

		now := time.Unix(1700000000, 0)
		s := New(Options{
			MaxZones:          16,
			MaxRecordsPerZone: 32,
			Now:               func() time.Time { return now },
		})
		s.Put(msg.Ns, now)

		denial, ok := s.ProveNXDOMAIN(name, now)
		if !ok {
			return
		}
		if denial.TTL <= 0 {
			t.Fatalf("synthesised a denial for %s with a non-positive TTL", name)
		}
		soa := false
		for _, rr := range denial.Authority {
			if _, is := rr.(*dns.SOA); is {
				soa = true
			}
		}
		if !soa {
			t.Fatalf("synthesised a denial for %s with no SOA; a negative answer needs one (RFC 2308)", name)
		}
	})
}
