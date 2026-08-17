package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

// A name with no DS is only an insecure delegation if it is a delegation.
// Labels that sit inside their parent zone — go.jp within jp, co.uk within uk —
// carry no DS and are not zone cuts, and reading them as insecure delegations
// declares every signed zone beneath them insecure.
func TestZoneCutFromDenial(t *testing.T) {
	t.Parallel()

	nsec := func(owner string, types ...uint16) dns.RR {
		return &dns.NSEC{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: "next.example.",
			TypeBitMap: types,
		}
	}

	tests := []struct {
		name      string
		denial    []dns.RR
		query     string
		wantCut   bool
		wantKnown bool
	}{
		{
			name:      "delegation without DS is a zone cut",
			denial:    []dns.RR{nsec("child.example.", dns.TypeNS, dns.TypeRRSIG)},
			query:     "child.example.",
			wantCut:   true,
			wantKnown: true,
		},
		{
			name:      "name inside the parent zone is not a zone cut",
			denial:    []dns.RR{nsec("go.jp.", dns.TypeRRSIG, dns.TypeNSEC)},
			query:     "go.jp.",
			wantCut:   false,
			wantKnown: true,
		},
		{
			name:      "apex carries NS and SOA, so it is the zone not a cut below it",
			denial:    []dns.RR{nsec("example.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG)},
			query:     "example.",
			wantCut:   false,
			wantKnown: true,
		},
		{
			name:      "no record for the name says nothing either way",
			denial:    []dns.RR{nsec("other.example.", dns.TypeNS)},
			query:     "child.example.",
			wantCut:   false,
			wantKnown: false,
		},
		{
			name:      "empty denial says nothing",
			denial:    nil,
			query:     "child.example.",
			wantCut:   false,
			wantKnown: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cut, known := ZoneCutFromDenial(tc.denial, tc.query)
			if cut != tc.wantCut || known != tc.wantKnown {
				t.Errorf("ZoneCutFromDenial(%s) = (cut=%t, known=%t), want (cut=%t, known=%t)",
					tc.query, cut, known, tc.wantCut, tc.wantKnown)
			}
		})
	}
}
