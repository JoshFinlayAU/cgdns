// Package prefixmap provides longest-prefix-match lookup from an IP address to
// a value, over IPv4 and IPv6 together. It serves subscriber classification and
// the source ACLs, both on hot paths.
//
// A Map is built once and then read concurrently without locking. Insert is NOT
// safe against a concurrent Lookup: build a fresh Map and swap it in behind an
// atomic.Pointer.
package prefixmap

import (
	"net/netip"
)

// Map is a binary radix trie keyed by IP prefix. The zero value is not usable;
// use New.
type Map[V any] struct {
	v4  *node[V]
	v6  *node[V]
	len int
}

type node[V any] struct {
	child [2]*node[V]
	val   V
	has   bool
}

// New returns an empty Map.
func New[V any]() *Map[V] {
	return &Map[V]{v4: &node[V]{}, v6: &node[V]{}}
}

// Len reports how many prefixes have been inserted.
func (m *Map[V]) Len() int { return m.len }

// Insert adds or replaces the value for p. Host bits in p are ignored (the
// prefix is masked first). Inserting the same prefix twice replaces the value.
func (m *Map[V]) Insert(p netip.Prefix, v V) {
	p = p.Masked()
	addr := p.Addr()
	bits := p.Bits()

	root := m.v6
	var key []byte
	if addr.Is4() {
		root = m.v4
		a := addr.As4()
		key = a[:]
	} else {
		a := addr.As16()
		key = a[:]
	}

	cur := root
	for i := 0; i < bits; i++ {
		b := bitAt(key, i)
		next := cur.child[b]
		if next == nil {
			next = &node[V]{}
			cur.child[b] = next
		}
		cur = next
	}
	if !cur.has {
		m.len++
	}
	cur.val = v
	cur.has = true
}

// Lookup returns the value of the most specific prefix containing addr. A
// v4-mapped v6 address is unmapped first, so a client arriving over a
// dual-stack socket still matches the configured IPv4 prefixes.
func (m *Map[V]) Lookup(addr netip.Addr) (V, bool) {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	root := m.v6
	var key []byte
	var bits int
	if addr.Is4() {
		root = m.v4
		a := addr.As4()
		key = a[:]
		bits = 32
	} else {
		a := addr.As16()
		key = a[:]
		bits = 128
	}

	var (
		best   V
		bestOK bool
		cur    = root
	)
	if cur.has {
		best, bestOK = cur.val, true
	}
	for i := 0; i < bits; i++ {
		cur = cur.child[bitAt(key, i)]
		if cur == nil {
			break
		}
		if cur.has {
			best, bestOK = cur.val, true
		}
	}
	return best, bestOK
}

// Contains reports whether any inserted prefix covers addr.
func (m *Map[V]) Contains(addr netip.Addr) bool {
	_, ok := m.Lookup(addr)
	return ok
}

func bitAt(b []byte, i int) int {
	return int(b[i>>3]>>(7-uint(i&7))) & 1
}
