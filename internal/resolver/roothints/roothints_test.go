package roothints

import (
	"strings"
	"testing"
)

// The hints file is a shipped build artefact. If it is malformed or truncated,
// a recursive node cannot bootstrap at all, so this is checked at build time
// rather than discovered on a cold start in production.
func TestDefault_EmbeddedHintsAreUsable(t *testing.T) {
	servers, err := Default()
	if err != nil {
		t.Fatalf("embedded root hints are unparseable: %v", err)
	}

	// There have been 13 root server letters since the 1990s. A parse that
	// yields fewer means the file was truncated or the parser dropped records.
	if len(servers) != 13 {
		t.Errorf("got %d root servers, want 13", len(servers))
	}

	for _, s := range servers {
		if !strings.HasSuffix(s.Name, ".") {
			t.Errorf("server name %q is not fully qualified", s.Name)
		}
		if len(s.Addrs) == 0 {
			t.Errorf("server %s has no addresses; it is useless as a hint", s.Name)
		}

		// Both families for every letter. A v4-only hints file would leave a
		// v6-only node unable to bootstrap, which is exactly the silent
		// failure mode this project treats as unacceptable.
		var v4, v6 int
		for _, a := range s.Addrs {
			if a.Is4() {
				v4++
			} else {
				v6++
			}
		}
		if v4 == 0 {
			t.Errorf("server %s has no IPv4 address", s.Name)
		}
		if v6 == 0 {
			t.Errorf("server %s has no IPv6 address", s.Name)
		}
	}
}

func TestParse_RejectsUnusableInput(t *testing.T) {
	tests := []struct {
		name string
		zone string
	}{
		{"empty", ""},
		{"comments only", "; nothing here\n; still nothing\n"},
		{
			// An NS with no corresponding address cannot be used to prime:
			// there is no root to ask in order to resolve its name.
			name: "NS records with no glue",
			zone: ".  3600000  NS  A.ROOT-SERVERS.NET.\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(tt.zone); err == nil {
				t.Error("expected Parse to reject input with no usable servers")
			}
		})
	}
}

func TestParse_IgnoresNonRootNS(t *testing.T) {
	// Only the root's own NS records are hints. Anything else in the file must
	// not be promoted into the bootstrap set.
	zone := `
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
example.com.             3600000      NS    ns1.attacker.test.
ns1.attacker.test.       3600000      A     198.51.100.1
`
	servers, err := Parse(zone)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want only the root NS", len(servers))
	}
	if servers[0].Name != "a.root-servers.net." {
		t.Errorf("server = %q, want a.root-servers.net.", servers[0].Name)
	}
	if len(servers[0].Addrs) != 2 {
		t.Errorf("got %d addresses, want 2 (v4 and v6)", len(servers[0].Addrs))
	}
}

func TestRaw_ReturnsTheShippedFile(t *testing.T) {
	raw := Raw()
	if !strings.Contains(raw, "A.ROOT-SERVERS.NET.") {
		t.Error("Raw() does not look like the shipped hints file")
	}
	if !strings.Contains(raw, "last update:") {
		t.Error("Raw() should include the InterNIC header so operators can see how old it is")
	}
}
