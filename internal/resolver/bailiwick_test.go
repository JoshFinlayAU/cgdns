package resolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestInBailiwick(t *testing.T) {
	tests := []struct {
		name string
		sub  string
		zone string
		want bool
	}{
		{"exact match", "example.com.", "example.com.", true},
		{"subdomain", "www.example.com.", "example.com.", true},
		{"deep subdomain", "a.b.c.example.com.", "example.com.", true},
		{"everything is under the root", "example.com.", ".", true},
		{"parent is not under child", "example.com.", "www.example.com.", false},
		{"sibling", "example.net.", "example.com.", false},
		{"suffix but not a label boundary", "notexample.com.", "example.com.", false},
		{"case insensitive", "WWW.EXAMPLE.COM.", "example.com.", true},
		{"case insensitive zone", "www.example.com.", "EXAMPLE.COM.", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := inBailiwick(tt.sub, tt.zone); got != tt.want {
				t.Errorf("inBailiwick(%q, %q) = %v, want %v", tt.sub, tt.zone, got, tt.want)
			}
		})
	}
}

func a(name, ip string) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP(ip),
	}
}

func ns(zone, target string) dns.RR {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  target,
	}
}

// Glue is only believable when the server handing it out has authority over
// the name. This is the check that stops classic cache poisoning.
func TestFilterGlue(t *testing.T) {
	in := []dns.RR{
		a("ns1.example.com.", "192.0.2.1"),        // in bailiwick
		a("ns2.example.com.", "192.0.2.2"),        // in bailiwick
		a("victim.bank.example.net.", "10.0.0.1"), // NOT in bailiwick
		a("example.com.", "192.0.2.3"),            // the zone apex itself
		ns("example.com.", "ns1.example.com."),    // not an address record
	}

	got := filterGlue(in, "example.com.")

	if len(got) != 3 {
		t.Fatalf("expected 3 in-bailiwick address records, got %d: %v", len(got), got)
	}
	for _, rr := range got {
		if !inBailiwick(rr.Header().Name, "example.com.") {
			t.Errorf("filterGlue kept an out-of-bailiwick record: %s", rr.Header().Name)
		}
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
		default:
			t.Errorf("filterGlue kept a non-address record: %T", rr)
		}
	}
}

func TestReferralZone(t *testing.T) {
	tests := []struct {
		name        string
		ns          []dns.RR
		currentZone string
		qname       string
		want        string
	}{
		{
			name:        "normal delegation",
			ns:          []dns.RR{ns("example.com.", "ns1.example.com.")},
			currentZone: "com.",
			qname:       "www.example.com.",
			want:        "example.com.",
		},
		{
			name:        "root delegating a tld",
			ns:          []dns.RR{ns("com.", "a.gtld-servers.net.")},
			currentZone: ".",
			qname:       "www.example.com.",
			want:        "com.",
		},
		{
			name:        "several nameservers for one zone is fine",
			ns:          []dns.RR{ns("example.com.", "ns1.example.com."), ns("example.com.", "ns2.example.com.")},
			currentZone: "com.",
			qname:       "www.example.com.",
			want:        "example.com.",
		},
		{
			// A server re-delegating its own zone would loop forever.
			name:        "self delegation rejected",
			ns:          []dns.RR{ns("com.", "ns1.com.")},
			currentZone: "com.",
			qname:       "www.example.com.",
			want:        "",
		},
		{
			// com. has no authority to delegate net.
			name:        "sideways delegation rejected",
			ns:          []dns.RR{ns("net.", "ns1.attacker.test.")},
			currentZone: "com.",
			qname:       "www.example.com.",
			want:        "",
		},
		{
			name:        "upward delegation rejected",
			ns:          []dns.RR{ns(".", "ns1.attacker.test.")},
			currentZone: "com.",
			qname:       "www.example.com.",
			want:        "",
		},
		{
			// Legitimate zone, but it does not move us toward the QNAME.
			name:        "irrelevant delegation rejected",
			ns:          []dns.RR{ns("other.com.", "ns1.other.com.")},
			currentZone: "com.",
			qname:       "www.example.com.",
			want:        "",
		},
		{
			name:        "multiple cut points rejected",
			ns:          []dns.RR{ns("example.com.", "ns1.example.com."), ns("other.com.", "ns1.other.com.")},
			currentZone: "com.",
			qname:       "www.example.com.",
			want:        "",
		},
		{
			name:        "no NS records",
			ns:          nil,
			currentZone: "com.",
			qname:       "www.example.com.",
			want:        "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := referralZone(tt.ns, tt.currentZone, tt.qname); got != tt.want {
				t.Errorf("referralZone = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNameserversFrom(t *testing.T) {
	authority := []dns.RR{
		ns("example.com.", "ns1.example.com."),
		ns("example.com.", "ns2.elsewhere.net."), // out-of-zone nameserver
	}
	additional := []dns.RR{
		a("ns1.example.com.", "192.0.2.1"),
		a("ns2.elsewhere.net.", "198.51.100.1"), // glue we may NOT trust
	}

	got := nameserversFrom(authority, additional, "example.com.")
	if len(got) != 2 {
		t.Fatalf("expected 2 nameservers, got %d", len(got))
	}

	byName := map[string][]string{}
	for _, n := range got {
		for _, addr := range n.Addrs {
			byName[n.Name] = append(byName[n.Name], addr.String())
		}
	}

	if len(byName["ns1.example.com."]) != 1 {
		t.Errorf("in-bailiwick glue should have been kept, got %v", byName["ns1.example.com."])
	}
	// The com. server cannot vouch for an address under elsewhere.net., so the
	// nameserver must come back address-less and be resolved separately.
	if len(byName["ns2.elsewhere.net."]) != 0 {
		t.Errorf("out-of-bailiwick glue must be discarded, got %v", byName["ns2.elsewhere.net."])
	}
}

func TestAnswersFor(t *testing.T) {
	t.Run("direct answer", func(t *testing.T) {
		t.Parallel()
		in := []dns.RR{a("www.example.com.", "192.0.2.1")}
		got, final := answersFor(in, "www.example.com.", dns.TypeA)
		if len(got) != 1 {
			t.Fatalf("expected 1 record, got %d", len(got))
		}
		if final != "www.example.com." {
			t.Errorf("final = %q, want www.example.com.", final)
		}
	})

	t.Run("smuggled unrelated record dropped", func(t *testing.T) {
		t.Parallel()
		in := []dns.RR{
			a("www.example.com.", "192.0.2.1"),
			a("login.yourbank.com.", "198.51.100.9"), // not what we asked
		}
		got, _ := answersFor(in, "www.example.com.", dns.TypeA)
		if len(got) != 1 {
			t.Fatalf("expected the unrelated record to be dropped, got %d records", len(got))
		}
		if got[0].Header().Name != "www.example.com." {
			t.Errorf("kept the wrong record: %s", got[0].Header().Name)
		}
	})

	t.Run("cname chain followed", func(t *testing.T) {
		t.Parallel()
		in := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "target.example.com.",
			},
			a("target.example.com.", "192.0.2.5"),
		}
		got, final := answersFor(in, "alias.example.com.", dns.TypeA)
		if len(got) != 2 {
			t.Fatalf("expected CNAME plus target, got %d: %v", len(got), got)
		}
		if final != "target.example.com." {
			t.Errorf("final = %q, want target.example.com.", final)
		}
	})

	t.Run("cname loop terminates", func(t *testing.T) {
		t.Parallel()
		in := []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "b.example.com.",
			},
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "b.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "a.example.com.",
			},
		}
		// Must return rather than spin. The assertion is that we get here.
		got, _ := answersFor(in, "a.example.com.", dns.TypeA)
		if len(got) > 4 {
			t.Errorf("loop produced %d records; it should have been cut short", len(got))
		}
	})

	t.Run("wrong class ignored", func(t *testing.T) {
		t.Parallel()
		rr := a("www.example.com.", "192.0.2.1")
		rr.Header().Class = dns.ClassCHAOS
		got, _ := answersFor([]dns.RR{rr}, "www.example.com.", dns.TypeA)
		if len(got) != 0 {
			t.Errorf("a record in the wrong class must be ignored, got %d", len(got))
		}
	})
}

func TestSplitFirstLabel(t *testing.T) {
	tests := []struct {
		in         string
		wantFirst  string
		wantParent string
	}{
		{"www.example.com.", "www", "example.com."},
		{"example.com.", "example", "com."},
		{"com.", "com", "."},
		{".", "", "."},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			first, parent := splitFirstLabel(tt.in)
			if first != tt.wantFirst || parent != tt.wantParent {
				t.Errorf("splitFirstLabel(%q) = (%q, %q), want (%q, %q)",
					tt.in, first, parent, tt.wantFirst, tt.wantParent)
			}
		})
	}
}
