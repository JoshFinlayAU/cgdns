package prefixmap

import (
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad test prefix %q: %v", s, err)
	}
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad test address %q: %v", s, err)
	}
	return a
}

func TestLookup_LongestPrefixWins(t *testing.T) {
	m := New[string]()
	for _, e := range []struct {
		prefix string
		class  string
	}{
		{"10.0.0.0/8", "wholesale"},
		{"10.1.0.0/16", "business"},
		{"10.1.2.0/24", "secure-dns"},
		{"2001:db8::/32", "v6-wholesale"},
		{"2001:db8:1::/48", "v6-business"},
	} {
		m.Insert(mustPrefix(t, e.prefix), e.class)
	}

	tests := []struct {
		name  string
		addr  string
		want  string
		found bool
	}{
		{"most specific v4 wins", "10.1.2.5", "secure-dns", true},
		{"next most specific v4", "10.1.3.5", "business", true},
		{"least specific v4", "10.9.9.9", "wholesale", true},
		{"unmatched v4", "192.0.2.1", "", false},
		{"most specific v6 wins", "2001:db8:1::1", "v6-business", true},
		{"less specific v6", "2001:db8:2::1", "v6-wholesale", true},
		{"unmatched v6", "2001:db9::1", "", false},
		{"v4 address does not match v6 tree", "10.1.2.5", "secure-dns", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := m.Lookup(mustAddr(t, tt.addr))
			if ok != tt.found {
				t.Fatalf("Lookup(%s) found = %v, want %v", tt.addr, ok, tt.found)
			}
			if got != tt.want {
				t.Errorf("Lookup(%s) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

// A client arriving over a dual-stack socket presents as ::ffff:a.b.c.d. If
// that did not unmap, it would silently miss every IPv4 prefix the operator
// configured — an ACL that looks correct and is not.
func TestLookup_UnmapsV4In6(t *testing.T) {
	m := New[string]()
	m.Insert(mustPrefix(t, "192.0.2.0/24"), "subscriber")

	got, ok := m.Lookup(mustAddr(t, "::ffff:192.0.2.7"))
	if !ok || got != "subscriber" {
		t.Errorf("v4-mapped lookup = (%q, %v), want (\"subscriber\", true)", got, ok)
	}
}

func TestLookup_DefaultRoute(t *testing.T) {
	m := New[string]()
	m.Insert(mustPrefix(t, "0.0.0.0/0"), "any-v4")
	m.Insert(mustPrefix(t, "::/0"), "any-v6")
	m.Insert(mustPrefix(t, "10.0.0.0/8"), "internal")

	tests := []struct {
		addr string
		want string
	}{
		{"10.1.1.1", "internal"},
		{"8.8.8.8", "any-v4"},
		{"2001:db8::1", "any-v6"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			t.Parallel()
			got, ok := m.Lookup(mustAddr(t, tt.addr))
			if !ok || got != tt.want {
				t.Errorf("Lookup(%s) = (%q, %v), want (%q, true)", tt.addr, got, ok, tt.want)
			}
		})
	}
}

func TestInsert_MasksHostBits(t *testing.T) {
	m := New[string]()
	// An operator writing 10.1.2.5/24 means the /24; silently matching only
	// the host would be a surprising and dangerous reading.
	m.Insert(netip.MustParsePrefix("10.1.2.5/24"), "class")

	if got, ok := m.Lookup(mustAddr(t, "10.1.2.99")); !ok || got != "class" {
		t.Errorf("expected the whole /24 to match, got (%q, %v)", got, ok)
	}
}

func TestInsert_ReplacesExisting(t *testing.T) {
	m := New[string]()
	p := mustPrefix(t, "10.0.0.0/8")
	m.Insert(p, "old")
	m.Insert(p, "new")

	if got, _ := m.Lookup(mustAddr(t, "10.1.1.1")); got != "new" {
		t.Errorf("Lookup = %q, want %q", got, "new")
	}
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1 (replacement, not duplicate)", m.Len())
	}
}

func TestContains(t *testing.T) {
	m := New[struct{}]()
	m.Insert(mustPrefix(t, "203.0.113.0/24"), struct{}{})

	if !m.Contains(mustAddr(t, "203.0.113.1")) {
		t.Error("expected the address to be contained")
	}
	if m.Contains(mustAddr(t, "203.0.114.1")) {
		t.Error("did not expect the address to be contained")
	}
}

func TestEmptyMap_MatchesNothing(t *testing.T) {
	m := New[string]()
	if m.Contains(mustAddr(t, "10.0.0.1")) {
		t.Error("an empty map must match nothing — default deny depends on it")
	}
}

// Subscriber classification runs on every query, so this is a hot path.
func BenchmarkLookup(b *testing.B) {
	m := New[string]()
	// Roughly the shape of a carrier's assignment table: many /24s and /48s.
	for i := 0; i < 1000; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}), 24)
		m.Insert(p, "class")
	}
	addr := netip.AddrFrom4([4]byte{10, 2, 3, 4})

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Lookup(addr)
		}
	})
}

func BenchmarkLookupV6(b *testing.B) {
	m := New[string]()
	for i := 0; i < 1000; i++ {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i / 256), byte(i % 256)})
		m.Insert(netip.PrefixFrom(a, 48), "class")
	}
	addr := netip.MustParseAddr("2001:db8:203::1")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Lookup(addr)
		}
	})
}
