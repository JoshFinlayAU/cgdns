package resolver

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestMinimisedName(t *testing.T) {
	tests := []struct {
		name  string
		qname string
		zone  string
		want  string
	}{
		{"from root reveals only the tld", "www.example.com.", ".", "com."},
		{"from tld reveals the registrable domain", "www.example.com.", "com.", "example.com."},
		{"from the zone reveals the full name", "www.example.com.", "example.com.", "www.example.com."},
		{"deep name descends one label", "a.b.c.example.com.", "example.com.", "c.example.com."},
		{"already at the name", "example.com.", "example.com.", "example.com."},
		{"zone not an ancestor falls back to the full name", "www.example.com.", "example.net.", "www.example.com."},
		{"tld from root", "com.", ".", "com."},
		{"case normalised", "WWW.EXAMPLE.COM.", "com.", "example.com."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := minimisedName(tt.qname, tt.zone); got != tt.want {
				t.Errorf("minimisedName(%q, %q) = %q, want %q", tt.qname, tt.zone, got, tt.want)
			}
		})
	}
}

// The minimised name must never reveal more than one label beyond the zone —
// that is the entire privacy property.
func TestMinimisedName_NeverRevealsMoreThanOneExtraLabel(t *testing.T) {
	qname := "very.secret.private.host.example.com."
	for _, zone := range []string{".", "com.", "example.com.", "host.example.com."} {
		got := minimisedName(qname, zone)
		zoneLabels := 0
		if zone != "." {
			zoneLabels = dns.CountLabel(zone)
		}
		if gotLabels := dns.CountLabel(got); gotLabels > zoneLabels+1 {
			t.Errorf("from zone %q the probe %q reveals %d labels, want at most %d",
				zone, got, gotLabels, zoneLabels+1)
		}
	}
}

func TestMinimiseQType(t *testing.T) {
	tests := []struct {
		name    string
		minName string
		qname   string
		qtype   uint16
		want    uint16
	}{
		{"intermediate probe uses A", "com.", "www.example.com.", dns.TypeMX, dns.TypeA},
		{"final step uses the real type", "www.example.com.", "www.example.com.", dns.TypeMX, dns.TypeMX},
		{"final step with AAAA", "www.example.com.", "www.example.com.", dns.TypeAAAA, dns.TypeAAAA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := minimiseQType(tt.minName, tt.qname, tt.qtype); got != tt.want {
				t.Errorf("minimiseQType = %s, want %s", dns.TypeToString[got], dns.TypeToString[tt.want])
			}
		})
	}
}

func TestShouldMinimise(t *testing.T) {
	tests := []struct {
		qname string
		zone  string
		want  bool
	}{
		{"www.example.com.", ".", true},
		{"www.example.com.", "com.", true},
		{"www.example.com.", "example.com.", false}, // only one label left
		{"example.com.", "example.com.", false},
		{"com.", ".", false}, // one label from the root: nothing to hide
	}
	for _, tt := range tests {
		t.Run(tt.qname+"@"+tt.zone, func(t *testing.T) {
			t.Parallel()
			if got := shouldMinimise(tt.qname, tt.zone); got != tt.want {
				t.Errorf("shouldMinimise(%q, %q) = %v, want %v", tt.qname, tt.zone, got, tt.want)
			}
		})
	}
}

func TestRandomiseCase(t *testing.T) {
	const name = "www.example.com."

	// Case must vary between calls, or there is no added entropy at all.
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		seen[randomiseCase(name)] = true
	}
	if len(seen) < 10 {
		t.Errorf("randomiseCase produced only %d distinct patterns over 200 calls; entropy is too low", len(seen))
	}

	// Every variant must still be the same name, case-insensitively.
	for got := range seen {
		if !strings.EqualFold(got, name) {
			t.Errorf("randomiseCase changed the name itself: %q", got)
		}
		if len(got) != len(name) {
			t.Errorf("randomiseCase changed the length: %q", got)
		}
	}
}

func TestRandomiseCase_LeavesNonLettersAlone(t *testing.T) {
	const name = "123.456-789."
	for i := 0; i < 20; i++ {
		if got := randomiseCase(name); got != name {
			t.Errorf("randomiseCase altered a name with no letters: %q", got)
		}
	}
}

func TestCaseMatches(t *testing.T) {
	tests := []struct {
		name     string
		sent     string
		received string
		want     bool
	}{
		{"exact echo", "WwW.ExAmPlE.cOm.", "WwW.ExAmPlE.cOm.", true},
		{"flattened to lowercase", "WwW.ExAmPlE.cOm.", "www.example.com.", false},
		{"flattened to uppercase", "WwW.ExAmPlE.cOm.", "WWW.EXAMPLE.COM.", false},
		{"different name entirely", "WwW.ExAmPlE.cOm.", "WwW.ExAmPlE.nEt.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := caseMatches(tt.sent, tt.received); got != tt.want {
				t.Errorf("caseMatches(%q, %q) = %v, want %v", tt.sent, tt.received, got, tt.want)
			}
		})
	}
}

func BenchmarkRandomiseCase(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = randomiseCase("www.example.com.")
	}
}

func BenchmarkMinimisedName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = minimisedName("a.b.c.example.com.", "example.com.")
	}
}
