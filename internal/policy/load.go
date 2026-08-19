package policy

import (
	"bufio"
	"fmt"
	"net/netip"

	"github.com/miekg/dns"
	"os"
	"strings"
)

// FeedSpec describes one blocklist source.
//
// File is the dev path. In production a feed's content is fetched out-of-band
// and hash-verified; the control store carries only the metadata naming it,
// because feed content runs to millions of rows and replicating it would
// dominate the pair link.
type FeedSpec struct {
	Name   string
	Format string
	File   string
	// RPZZone is the zone name to strip from owners. Empty takes it from the SOA.
	RPZZone string

	// Entries are rules held in the control plane rather than a file, for a
	// list maintained by hand. They apply on top of File when both are set.
	Entries []Entry
}

// Entry is one hand-maintained rule.
type Entry struct {
	Name   string
	Action Action
	To     []netip.Addr
}

// Feed formats.
const (
	FormatDomainList = "domain-list"
	FormatRPZ        = "rpz"
)

// ClassSpec describes the policy for one subscriber class.
type ClassSpec struct {
	Name       string
	Feeds      []string
	Action     Action
	RedirectTo []netip.Addr
}

// Compile builds the per-class policies from feed and class specs.
//
// A failure here is fatal at startup and non-fatal on reload: the caller keeps
// the previously compiled Registry, so a broken feed degrades filtering rather
// than resolution.
func Compile(feeds []FeedSpec, classes []ClassSpec) (map[string]*Policy, error) {
	compiled := make(map[string]*Set, len(feeds))
	for _, f := range feeds {
		set, err := compileFeed(f)
		if err != nil {
			return nil, err
		}
		compiled[f.Name] = set
	}

	out := make(map[string]*Policy, len(classes))
	for _, c := range classes {
		rules := NewSet()
		for _, name := range c.Feeds {
			set, ok := compiled[name]
			if !ok {
				return nil, fmt.Errorf("class %q subscribes to unknown feed %q", c.Name, name)
			}
			rules.Merge(set)
		}
		out[c.Name] = &Policy{
			Class:      c.Name,
			Rules:      rules,
			RedirectTo: c.RedirectTo,
			Feeds:      c.Feeds,
		}
	}
	return out, nil
}

func compileFeed(f FeedSpec) (*Set, error) {
	if f.File == "" {
		return entrySet(f), nil
	}
	set, err := compileFeedFile(f)
	if err != nil {
		return nil, err
	}
	set.Merge(entrySet(f))
	return set, nil
}

// entrySet turns hand-maintained entries into rules. Each covers the name and
// everything beneath it: an entry naming a site is meant to reach its
// subdomains, and a compliance list that blocked only the apex would not do
// what the instruction behind it says.
func entrySet(f FeedSpec) *Set {
	set := NewSet()
	for _, e := range f.Entries {
		rule := Rule{Action: e.Action, Feed: f.Name, Addrs: e.To}
		set.AddExact(dns.CanonicalName(e.Name), rule)
		set.AddWildcard(dns.CanonicalName(e.Name), rule)
	}
	return set
}

func compileFeedFile(f FeedSpec) (*Set, error) {
	file, err := os.Open(f.File)
	if err != nil {
		return nil, fmt.Errorf("opening feed %q: %w", f.Name, err)
	}
	defer func() { _ = file.Close() }()

	switch f.Format {
	case FormatRPZ:
		return ParseRPZ(file, f.RPZZone, f.Name)
	case FormatDomainList, "":
		return ParseDomainList(file, f.Name, ActionNXDOMAIN, nil)
	default:
		return nil, fmt.Errorf("feed %q has unknown format %q", f.Name, f.Format)
	}
}

// LoadOverridesFile reads per-subscriber rules, one per line:
//
//	<subscriber-id> allow|block <domain>
//
// An allow entry unblocks a name for that subscriber alone, whatever the class
// feeds say.
func LoadOverridesFile(path string) (map[string]*Overrides, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening subscriber overrides %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	out := map[string]*Overrides{}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s:%d: expected \"<subscriber-id> allow|block <domain>\", got %q", path, line, text)
		}
		id, verb, domain := fields[0], strings.ToLower(fields[1]), fields[2]

		domain = strings.TrimPrefix(domain, "*.")
		if !plausibleDomain(domain) {
			return nil, fmt.Errorf("%s:%d: %q is not a domain name", path, line, fields[2])
		}

		ov, ok := out[id]
		if !ok {
			ov = &Overrides{Allow: NewSet(), Block: NewSet()}
			out[id] = ov
		}

		switch verb {
		case "allow":
			r := Rule{Action: ActionPassthru, Feed: "override:" + id}
			ov.Allow.AddExact(domain, r)
			ov.Allow.AddWildcard(domain, r)
		case "block":
			r := Rule{Action: ActionNXDOMAIN, Feed: "override:" + id}
			ov.Block.AddExact(domain, r)
			ov.Block.AddWildcard(domain, r)
		default:
			return nil, fmt.Errorf("%s:%d: verb must be allow or block, got %q", path, line, fields[1])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return out, nil
}

// ParseAction converts a config action name.
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "nxdomain", "":
		return ActionNXDOMAIN, nil
	case "nodata":
		return ActionNODATA, nil
	case "redirect":
		return ActionRedirect, nil
	case "drop":
		return ActionDrop, nil
	default:
		return ActionNone, fmt.Errorf("unknown policy action %q", s)
	}
}
