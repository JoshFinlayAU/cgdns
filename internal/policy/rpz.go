package policy

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// DefaultTTL is applied to synthesised policy answers when a feed does not say.
//
// It is short on purpose: a policy change should reach subscribers in seconds,
// and a blocked name that stays cached for hours after an unblock generates
// support calls.
const DefaultTTL = 60

// ParseRPZ compiles an RPZ zone into a Set.
//
// Rules are triggered on QNAME. The action comes from the RDATA, following the
// conventional RPZ encoding:
//
//	CNAME .                 NXDOMAIN
//	CNAME *.                NODATA
//	CNAME rpz-passthru.     explicitly allow
//	CNAME rpz-drop.         send nothing
//	CNAME <target>          rewrite to target
//	A / AAAA                redirect to the walled garden
//
// zoneName is the RPZ zone's own name, which is stripped from each owner to
// recover the name being policed. It may be empty, in which case the zone's own
// SOA names it: a published feed can rename its zone between refreshes, and a
// stale name in config strips nothing, which yields an empty policy rather than
// an error.
func ParseRPZ(r io.Reader, zoneName, feed string) (*Set, error) {
	origin := dns.CanonicalName(zoneName)
	if origin == "." {
		origin = "rpz.invalid."
	}
	set := NewSet()

	zp := dns.NewZoneParser(r, origin, feed)
	zp.SetIncludeAllowed(false)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		owner := dns.CanonicalName(rr.Header().Name)
		if soa, isSOA := rr.(*dns.SOA); isSOA {
			if zoneName == "" {
				origin = dns.CanonicalName(soa.Hdr.Name)
			}
			continue
		}
		if _, isNS := rr.(*dns.NS); isNS {
			continue
		}

		policed, wildcard, ok := stripZone(owner, origin)
		if !ok {
			continue
		}

		rule, ok := ruleFromRR(rr, feed)
		if !ok {
			continue
		}
		if wildcard {
			set.AddWildcard(policed, rule)
		} else {
			set.AddExact(policed, rule)
		}
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("parsing RPZ feed %s: %w", feed, err)
	}
	return set, nil
}

// stripZone removes the RPZ zone suffix from an owner name, reporting whether
// the rule was a wildcard.
func stripZone(owner, zone string) (policed string, wildcard bool, ok bool) {
	if owner == zone {
		return "", false, false
	}
	if !strings.HasSuffix(owner, "."+zone) && !strings.HasSuffix(owner, zone) {
		return "", false, false
	}
	trimmed := strings.TrimSuffix(owner, zone)
	trimmed = strings.TrimSuffix(trimmed, ".")
	if trimmed == "" {
		return "", false, false
	}
	if strings.HasPrefix(trimmed, "*.") {
		return dns.Fqdn(strings.TrimPrefix(trimmed, "*.")), true, true
	}
	return dns.Fqdn(trimmed), false, true
}

func ruleFromRR(rr dns.RR, feed string) (Rule, bool) {
	ttl := rr.Header().Ttl
	if ttl == 0 {
		ttl = DefaultTTL
	}

	switch v := rr.(type) {
	case *dns.CNAME:
		target := dns.CanonicalName(v.Target)
		switch target {
		case ".":
			return Rule{Action: ActionNXDOMAIN, Feed: feed, TTL: ttl}, true
		case "*.":
			return Rule{Action: ActionNODATA, Feed: feed, TTL: ttl}, true
		case "rpz-passthru.":
			return Rule{Action: ActionPassthru, Feed: feed, TTL: ttl}, true
		case "rpz-drop.":
			return Rule{Action: ActionDrop, Feed: feed, TTL: ttl}, true
		}
		if strings.HasPrefix(target, "rpz-") {
			// An RPZ control name we do not implement. Ignoring it is safer
			// than guessing: applying the wrong action to a policy rule either
			// blocks something legitimate or fails to block something.
			return Rule{}, false
		}
		return Rule{Action: ActionRewrite, Target: target, Feed: feed, TTL: ttl}, true

	case *dns.A:
		a, ok := netip.AddrFromSlice(v.A.To4())
		if !ok {
			return Rule{}, false
		}
		return Rule{Action: ActionRedirect, Addrs: []netip.Addr{a}, Feed: feed, TTL: ttl}, true

	case *dns.AAAA:
		a, ok := netip.AddrFromSlice(v.AAAA.To16())
		if !ok {
			return Rule{}, false
		}
		return Rule{Action: ActionRedirect, Addrs: []netip.Addr{a.Unmap()}, Feed: feed, TTL: ttl}, true
	}
	return Rule{}, false
}

// ParseDomainList compiles a plain "one domain per line" blocklist, the format
// most RBL feeds ship in.
//
// Each entry blocks the name and everything below it, since a feed listing
// evil.example never means "but its subdomains are fine". A leading "*." is
// accepted and treated the same way.
func ParseDomainList(r io.Reader, feed string, action Action, redirect []netip.Addr) (*Set, error) {
	set := NewSet()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, "!") {
			continue
		}
		// Hosts-file style feeds prefix each entry with an address.
		if fields := strings.Fields(text); len(fields) == 2 {
			if _, err := netip.ParseAddr(fields[0]); err == nil {
				text = fields[1]
			}
		}
		text = strings.TrimPrefix(text, "*.")
		if text == "" || text == "." {
			continue
		}
		if !plausibleDomain(text) {
			return nil, fmt.Errorf("parsing feed %s line %d: %q is not a domain name", feed, line, text)
		}

		name := dns.CanonicalName(text)
		rule := Rule{Action: action, Addrs: redirect, Feed: feed, TTL: DefaultTTL}
		set.AddExact(name, rule)
		set.AddWildcard(name, rule)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading feed %s: %w", feed, err)
	}
	return set, nil
}

// plausibleDomain reports whether text looks like a domain name.
//
// dns.IsDomainName is deliberately permissive because DNS labels are
// binary-safe, which makes it useless for validating a feed: a fetch that
// returned an HTML error page would parse as millions of "valid" rules. A feed
// carrying anything outside the hostname character set is a format mismatch,
// and failing the load is safer than ingesting it.
func plausibleDomain(text string) bool {
	if text == "" || len(text) > 253 {
		return false
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return strings.Contains(strings.TrimSuffix(text, "."), ".")
}

// Merge folds other into s. Rules already present win, so the caller controls
// precedence by merging the most specific feed first.
func (s *Set) Merge(other *Set) {
	if other == nil {
		return
	}
	for k, v := range other.exact {
		if _, exists := s.exact[k]; !exists {
			s.exact[k] = v
		}
	}
	for k, v := range other.wild {
		if _, exists := s.wild[k]; !exists {
			s.wild[k] = v
		}
	}
}
