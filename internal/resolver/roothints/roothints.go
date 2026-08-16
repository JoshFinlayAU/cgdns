// Package roothints ships and parses the root name server hints.
//
// named.root is embedded verbatim as IANA publishes it, and is refreshed by
// replacing the file from https://www.internic.net/domain/named.root.
//
// Hints only bootstrap the walk; the root NS RRset learned from the first
// priming query is what gets cached. Stale hints are survivable as long as one
// address still answers, which is why all 13 servers and both families ship.
package roothints

import (
	_ "embed"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

//go:embed named.root
var namedRoot string

// Server is a root name server and its addresses.
type Server struct {
	Name  string
	Addrs []netip.Addr
}

// Parse reads a BIND-format root hints file.
func Parse(zone string) ([]Server, error) {
	var (
		nsNames []string
		addrs   = map[string][]netip.Addr{}
	)

	zp := dns.NewZoneParser(strings.NewReader(zone), ".", "named.root")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch v := rr.(type) {
		case *dns.NS:
			if dns.CanonicalName(v.Hdr.Name) != "." {
				continue
			}
			nsNames = append(nsNames, dns.CanonicalName(v.Ns))
		case *dns.A:
			name := dns.CanonicalName(v.Hdr.Name)
			if a, ok := netip.AddrFromSlice(v.A.To4()); ok {
				addrs[name] = append(addrs[name], a)
			}
		case *dns.AAAA:
			name := dns.CanonicalName(v.Hdr.Name)
			if a, ok := netip.AddrFromSlice(v.AAAA.To16()); ok {
				addrs[name] = append(addrs[name], a)
			}
		}
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("parsing root hints: %w", err)
	}

	out := make([]Server, 0, len(nsNames))
	for _, name := range nsNames {
		a := addrs[name]
		if len(a) == 0 {
			continue
		}
		out = append(out, Server{Name: name, Addrs: a})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("parsing root hints: no usable root servers found")
	}
	return out, nil
}

// Default returns the embedded root hints.
func Default() ([]Server, error) { return Parse(namedRoot) }

// MustDefault is Default, panicking on failure. The embedded file is a build
// artefact, so a parse failure is a broken build.
func MustDefault() []Server {
	s, err := Default()
	if err != nil {
		panic("roothints: embedded named.root is unparseable: " + err.Error())
	}
	return s
}

// Raw returns the embedded hints file verbatim.
func Raw() string { return namedRoot }
