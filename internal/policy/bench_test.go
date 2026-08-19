package policy

import (
	"fmt"
	"os"
	"testing"

	"github.com/miekg/dns"
)

// benchSet builds a rule set at production scale.
//
// Real feed content is used when CGDNS_BENCH_RPZ names a directory holding it,
// because synthetic names share prefixes in ways real domains do not and that
// flatters the lookup. Without it the shape is approximated, which is enough to
// catch a regression but not to quote a figure.
func benchSet(b *testing.B) (*Set, bool) {
	b.Helper()

	dir := os.Getenv("CGDNS_BENCH_RPZ")
	if dir == "" {
		set := NewSet()
		for i := 0; i < 440000; i++ {
			name := dns.Fqdn(fmt.Sprintf("n%d-%d.blocked%d.example", i, i*7919, i%9973))
			set.AddExact(name, Rule{Action: ActionNXDOMAIN, Feed: "synthetic"})
			set.AddWildcard(name, Rule{Action: ActionNXDOMAIN, Feed: "synthetic"})
		}
		return set, false
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		b.Fatalf("reading %s: %v", dir, err)
	}
	set := NewSet()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		f, err := os.Open(dir + "/" + e.Name())
		if err != nil {
			b.Fatalf("opening %s: %v", e.Name(), err)
		}
		part, err := ParseRPZ(f, "", e.Name())
		_ = f.Close()
		if err != nil {
			b.Fatalf("parsing %s: %v", e.Name(), err)
		}
		set.Merge(part)
	}
	if set.Len() == 0 {
		b.Fatalf("no rules loaded from %s", dir)
	}
	return set, true
}

// The question policy has to answer for every single query is "is this name
// filtered", and for almost every query the answer is no. That path is the one
// that decides whether filtering is affordable, so it is measured separately
// from the hit — and separately again for a deep name, where a wildcard match
// has the most labels to walk before it can conclude nothing matches.
func BenchmarkSet_Match_Scale(b *testing.B) {
	set, real := benchSet(b)
	b.Logf("%d rules, real feed content: %v", set.Len(), real)

	cases := []struct {
		name  string
		qname string
	}{
		{"miss_shallow", "example.com."},
		{"miss_deep", "a.b.c.d.e.f.g.h.example.com."},
		{"miss_long_label", "very-long-single-label-that-nothing-will-ever-match.example.com."},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					set.Match(tc.qname)
				}
			})
		})
	}
}

// A hit costs what a miss costs plus the rule, so it is the cheaper case. It is
// measured anyway: if a hit ever became dramatically more expensive than a miss
// somebody could tell blocked names from unblocked ones by timing alone.
func BenchmarkSet_Match_Hit(b *testing.B) {
	set, _ := benchSet(b)

	var name string
	for n := range set.exact {
		if _, wild := set.wild[n]; wild {
			name = n
			break
		}
	}
	if name == "" {
		b.Skip("no rule carrying both an exact and a wildcard match")
	}
	b.Logf("hitting %s", name)

	b.Run("exact", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				set.Match(name)
			}
		})
	})
	b.Run("wildcard_subdomain", func(b *testing.B) {
		sub := "deep.sub." + name
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				set.Match(sub)
			}
		})
	})
}
