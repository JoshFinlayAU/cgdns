package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMinimalCovering(t *testing.T) {
	t.Parallel()
	tests := []struct {
		owner, next string
		want        bool
	}{
		{"cdn.cloudflare.net.", "\\000.cdn.cloudflare.net.", true},
		{"example.", "a.example.", false},
		{"example.com.", "www.example.com.", false},
		{"example.com.", "zz.example.com.", false},
		{"a.example.", "b.example.", false},
	}
	for _, tt := range tests {
		n := &dns.NSEC{
			Hdr:        dns.RR_Header{Name: tt.owner, Rrtype: dns.TypeNSEC},
			NextDomain: tt.next,
		}
		if got := minimalCovering(n); got != tt.want {
			t.Errorf("minimalCovering(%s -> %s) = %t, want %t", tt.owner, tt.next, got, tt.want)
		}
	}
}
