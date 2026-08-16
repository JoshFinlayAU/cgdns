// Package policy implements subscriber content policy: RPZ-style response
// rewriting driven by feeds a subscriber's class is subscribed to.
//
// A feed fetch that fails leaves the previously loaded rules in place and never
// blocks resolution. Failing closed here would let a dead blocklist server take
// a carrier's DNS down, which is a far worse outcome than briefly serving
// unfiltered answers.
package policy

import (
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// Action is what to do with a query that matches a rule.
type Action uint8

const (
	// ActionNone means no rule matched.
	ActionNone Action = iota
	// ActionNXDOMAIN answers as though the name does not exist.
	ActionNXDOMAIN
	// ActionNODATA answers with an empty answer section.
	ActionNODATA
	// ActionPassthru explicitly allows the name, overriding a broader block.
	ActionPassthru
	// ActionDrop sends nothing at all.
	ActionDrop
	// ActionRedirect answers with the configured walled-garden addresses.
	ActionRedirect
	// ActionRewrite answers with a CNAME to another name.
	ActionRewrite
)

// String implements fmt.Stringer.
func (a Action) String() string {
	switch a {
	case ActionNXDOMAIN:
		return "nxdomain"
	case ActionNODATA:
		return "nodata"
	case ActionPassthru:
		return "passthru"
	case ActionDrop:
		return "drop"
	case ActionRedirect:
		return "redirect"
	case ActionRewrite:
		return "rewrite"
	default:
		return "none"
	}
}

// Rule is one policy decision.
type Rule struct {
	Action Action
	// Addrs answers an ActionRedirect.
	Addrs []netip.Addr
	// Target answers an ActionRewrite.
	Target string
	// Feed names the source, for metrics and operator diagnosis.
	Feed string
	// TTL is applied to synthesised answers.
	TTL uint32
}

// Set is a compiled collection of rules, keyed for lookup.
//
// A Set is immutable once built. Feeds are recompiled into a fresh Set and
// swapped in, so a reload never leaves the query path looking at half a table.
type Set struct {
	exact map[string]Rule
	wild  map[string]Rule
}

// NewSet returns an empty Set.
func NewSet() *Set {
	return &Set{exact: map[string]Rule{}, wild: map[string]Rule{}}
}

// Len reports how many rules the Set holds.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.exact) + len(s.wild)
}

// AddExact adds a rule matching name and nothing below it.
func (s *Set) AddExact(name string, r Rule) {
	s.exact[dns.CanonicalName(name)] = r
}

// AddWildcard adds a rule matching every name strictly below parent.
func (s *Set) AddWildcard(parent string, r Rule) {
	s.wild[dns.CanonicalName(parent)] = r
}

// Match returns the most specific rule covering qname.
//
// An exact rule beats a wildcard, and a deeper wildcard beats a shallower one,
// which is what lets a specific passthru punch a hole in a broad block.
func (s *Set) Match(qname string) (Rule, bool) {
	if s == nil {
		return Rule{}, false
	}
	name := dns.CanonicalName(qname)
	if r, ok := s.exact[name]; ok {
		return r, true
	}
	if len(s.wild) == 0 {
		return Rule{}, false
	}

	for cur := name; ; {
		parent := parentOf(cur)
		if parent == "" {
			break
		}
		if r, ok := s.wild[parent]; ok {
			return r, true
		}
		if parent == "." {
			break
		}
		cur = parent
	}
	return Rule{}, false
}

// parentOf strips the leftmost label, returning "" once past the root.
func parentOf(name string) string {
	if name == "" || name == "." {
		return ""
	}
	i, end := dns.NextLabel(name, 0)
	if end {
		return "."
	}
	return name[i:]
}

// Policy is the compiled rule set and settings for one subscriber class.
type Policy struct {
	Class string
	Rules *Set
	// RedirectTo is the walled-garden answer for rules that block by
	// redirection rather than by NXDOMAIN.
	RedirectTo []netip.Addr
	// Feeds names the feeds compiled into Rules.
	Feeds []string
}

// Overrides are one subscriber's personal rules, which take precedence over
// every class feed.
//
// This is what makes a blocklist operable at carrier scale: feeds are curated
// by someone else and will eventually block something a customer legitimately
// needs, and the answer to that has to be an unblock for that customer alone,
// not an edit to the shared feed or a support ticket to the feed vendor.
type Overrides struct {
	// Allow names the subscriber may reach regardless of any class rule.
	Allow *Set
	// Block names the subscriber may not reach, on top of the class rules.
	Block *Set
}

// Len reports the total number of override rules.
func (o *Overrides) Len() int {
	if o == nil {
		return 0
	}
	return o.Allow.Len() + o.Block.Len()
}

// Match applies the subscriber's own rules, allow list first.
func (o *Overrides) Match(qname string) (Rule, bool) {
	if o == nil {
		return Rule{}, false
	}
	if r, ok := o.Allow.Match(qname); ok {
		r.Action = ActionPassthru
		return r, true
	}
	return o.Block.Match(qname)
}

// Registry holds the policy for each class and the overrides for each
// subscriber. Lookups are lock-free; Replace swaps the whole map.
type Registry struct {
	classes   atomic.Pointer[map[string]*Policy]
	overrides atomic.Pointer[map[string]*Overrides]
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	r := &Registry{}
	r.classes.Store(&map[string]*Policy{})
	r.overrides.Store(&map[string]*Overrides{})
	return r
}

// Replace swaps in a new set of class policies.
func (r *Registry) Replace(policies map[string]*Policy) {
	m := make(map[string]*Policy, len(policies))
	for k, v := range policies {
		m[strings.ToLower(k)] = v
	}
	r.classes.Store(&m)
}

// ReplaceOverrides swaps in a new set of per-subscriber overrides.
func (r *Registry) ReplaceOverrides(overrides map[string]*Overrides) {
	m := make(map[string]*Overrides, len(overrides))
	for k, v := range overrides {
		m[k] = v
	}
	r.overrides.Store(&m)
}

// For returns the policy for a class, or nil when the class has none.
func (r *Registry) For(class string) *Policy {
	return (*r.classes.Load())[strings.ToLower(class)]
}

// OverridesFor returns a subscriber's own rules, or nil.
func (r *Registry) OverridesFor(subscriberID string) *Overrides {
	if subscriberID == "" {
		return nil
	}
	return (*r.overrides.Load())[subscriberID]
}

// Classes returns the configured class names.
func (r *Registry) Classes() []string {
	m := *r.classes.Load()
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// SubscribersWithOverrides reports how many subscribers have personal rules.
func (r *Registry) SubscribersWithOverrides() int { return len(*r.overrides.Load()) }
