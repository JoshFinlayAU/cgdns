// Package subscriber maps a client address to the subscriber it belongs to and
// the policy class that applies to them.
//
// Identity is by source prefix: a longest-prefix match over a v4+v6 trie. The
// trie is replaced wholesale rather than mutated, so a policy push never pauses
// the query path and a reader always sees a coherent table.
package subscriber

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"

	"github.com/JoshFinlayAU/cgdns/internal/prefixmap"
)

// Subscriber is the identity a client address resolves to.
//
// ID is what per-subscriber overrides key on, so it must be stable across
// address reassignment; Class selects the shared feed subscription.
type Subscriber struct {
	ID    string
	Class string
}

// Entry assigns a subscriber to a prefix.
type Entry struct {
	Prefix netip.Prefix
	Subscriber
}

// Classifier resolves client addresses to subscribers. It is safe for
// concurrent use, and Replace may be called while queries are in flight.
type Classifier struct {
	table        atomic.Pointer[prefixmap.Map[Subscriber]]
	defaultClass string
	entries      atomic.Int64
}

// New returns a Classifier that reports defaultClass for unmatched addresses.
func New(defaultClass string) *Classifier {
	c := &Classifier{defaultClass: defaultClass}
	c.table.Store(prefixmap.New[Subscriber]())
	return c
}

// Replace swaps in a new prefix table.
func (c *Classifier) Replace(entries []Entry) {
	m := prefixmap.New[Subscriber]()
	for _, e := range entries {
		s := e.Subscriber
		if s.Class == "" {
			s.Class = c.defaultClass
		}
		m.Insert(e.Prefix, s)
	}
	c.table.Store(m)
	c.entries.Store(int64(m.Len()))
}

// Classify returns the subscriber for addr. An address matching no prefix gets
// the default class and an empty ID, so it is still resolvable but has no
// per-subscriber overrides.
func (c *Classifier) Classify(addr netip.Addr) Subscriber {
	if s, ok := c.table.Load().Lookup(addr); ok {
		return s
	}
	return Subscriber{Class: c.defaultClass}
}

// DefaultClass returns the class used for unmatched addresses.
func (c *Classifier) DefaultClass() string { return c.defaultClass }

// Len reports how many prefixes are loaded.
func (c *Classifier) Len() int { return int(c.entries.Load()) }

// LoadFile reads "prefix class [subscriber-id]" lines, ignoring blanks and
// # comments.
func LoadFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening subscriber prefixes %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var out []Entry
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) < 2 || len(fields) > 3 {
			return nil, fmt.Errorf("%s:%d: expected \"prefix class [subscriber-id]\", got %q", path, line, text)
		}
		p, err := netip.ParsePrefix(fields[0])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %q is not a valid CIDR prefix: %w", path, line, fields[0], err)
		}
		if p.Masked() != p {
			return nil, fmt.Errorf("%s:%d: %q has host bits set; write it as %q", path, line, fields[0], p.Masked())
		}
		e := Entry{Prefix: p, Subscriber: Subscriber{Class: fields[1]}}
		if len(fields) == 3 {
			e.ID = fields[2]
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return out, nil
}
