package privacy

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		name  string
		qname string
		want  string
	}{
		{"deep subdomain reduced to registrable", "very.secret.host.example.com.", "example.com."},
		{"single subdomain reduced", "www.example.com.", "example.com."},
		{"registrable domain unchanged", "example.com.", "example.com."},
		{"multi-part suffix", "shop.example.co.uk.", "example.co.uk."},
		{"australian suffix", "private.customer.example.com.au.", "example.com.au."},
		{"case normalised", "WWW.EXAMPLE.COM.", "example.com."},
		{"tld alone", "com.", "com."},
		{"root", ".", "."},
		{"empty", "", "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Redact(tt.qname); got != tt.want {
				t.Errorf("Redact(%q) = %q, want %q", tt.qname, got, tt.want)
			}
		})
	}
}

// The point of the package: whatever a subscriber actually asked for must not
// survive into a log line.
func TestRedact_DropsTheIdentifyingLabels(t *testing.T) {
	secret := "embarrassing-medical-search.private.example.com."
	got := Redact(secret)

	if strings.Contains(got, "embarrassing-medical-search") {
		t.Errorf("Redact leaked the subscriber-identifying label: %q", got)
	}
	if strings.Contains(got, "private") {
		t.Errorf("Redact leaked an intermediate label: %q", got)
	}
	if got != "example.com." {
		t.Errorf("Redact = %q, want %q", got, "example.com.")
	}
}

func TestHash_IsStableAndCaseInsensitive(t *testing.T) {
	a := Hash("www.example.com.")
	b := Hash("WWW.EXAMPLE.COM.")
	c := Hash("other.example.com.")

	if a != b {
		t.Errorf("Hash should be case insensitive: %q vs %q", a, b)
	}
	if a == c {
		t.Error("different names should hash differently")
	}
	if len(a) != 12 {
		t.Errorf("Hash length = %d, want 12 hex chars", len(a))
	}
	if strings.Contains(a, "example") {
		t.Errorf("Hash must not contain the plaintext name: %q", a)
	}
}

func TestRedactAddr(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"v4 host", "192.0.2.55", "192.0.2.0/24"},
		{"v4 with port", "192.0.2.55:34567", "192.0.2.0/24"},
		{"v6 host", "2001:db8:1234:5678::1", "2001:db8:1234::/48"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := RedactAddr(tt.addr); got != tt.want {
				t.Errorf("RedactAddr(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

// Redact runs on error paths that can fire at high rate during an incident, so
// it must not be expensive enough to make an outage worse.
func BenchmarkRedact(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Redact("very.deep.subdomain.example.com.")
	}
}
