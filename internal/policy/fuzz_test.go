package policy

import (
	"net/netip"
	"strings"
	"testing"
)

// A policy feed is fetched from a third party. It is hash-pinned, but a
// publisher can still ship something malformed, and a parser that panics on it
// takes the resolver down for every subscriber rather than just failing the
// feed.
func FuzzParseRPZ(f *testing.F) {
	f.Add("$ORIGIN rpz.example.\n@ SOA ns.example. hostmaster.example. 1 3600 600 604800 60\nbad.example CNAME .\n")
	f.Add("blocked.example CNAME *.\n")
	f.Add("")
	f.Add("\x00\x00")

	f.Fuzz(func(t *testing.T, body string) {
		set, err := ParseRPZ(strings.NewReader(body), "rpz.example.", "fuzz")
		if err != nil {
			return
		}
		if set == nil {
			t.Fatal("ParseRPZ returned no error and no set")
		}
	})
}

// A plain domain list is the other feed shape, and the likelier one to be
// hand-edited.
func FuzzParseDomainList(f *testing.F) {
	f.Add("example.com\n# a comment\nsub.example.net\n")
	f.Add("0.0.0.0 blocked.example\n")
	f.Add("")
	f.Add(strings.Repeat("a", 300) + ".example\n")

	redirect := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	f.Fuzz(func(t *testing.T, body string) {
		set, err := ParseDomainList(strings.NewReader(body), "fuzz", ActionNXDOMAIN, redirect)
		if err != nil {
			return
		}
		if set == nil {
			t.Fatal("ParseDomainList returned no error and no set")
		}
	})
}
