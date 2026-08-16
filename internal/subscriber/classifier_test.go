package subscriber

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func entry(prefix, class, id string) Entry {
	return Entry{
		Prefix:     netip.MustParsePrefix(prefix),
		Subscriber: Subscriber{ID: id, Class: class},
	}
}

func TestClassify(t *testing.T) {
	c := New("default")
	c.Replace([]Entry{
		entry("10.0.0.0/8", "wholesale", ""),
		entry("10.1.0.0/16", "business", "biz-1"),
		entry("10.1.2.0/24", "secure", "acme-corp"),
		entry("2001:db8::/32", "wholesale", ""),
		entry("2001:db8:1::/48", "secure", "acme-corp"),
	})

	tests := []struct {
		name      string
		addr      string
		wantClass string
		wantID    string
	}{
		{"most specific v4 wins", "10.1.2.5", "secure", "acme-corp"},
		{"next most specific", "10.1.3.5", "business", "biz-1"},
		{"least specific", "10.9.9.9", "wholesale", ""},
		{"unmatched falls back to default", "192.0.2.1", "default", ""},
		{"most specific v6 wins", "2001:db8:1::1", "secure", "acme-corp"},
		{"less specific v6", "2001:db8:2::1", "wholesale", ""},
		{"v4-mapped matches the v4 rule", "::ffff:10.1.2.5", "secure", "acme-corp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := c.Classify(netip.MustParseAddr(tt.addr))
			if got.Class != tt.wantClass {
				t.Errorf("class = %q, want %q", got.Class, tt.wantClass)
			}
			if got.ID != tt.wantID {
				t.Errorf("id = %q, want %q", got.ID, tt.wantID)
			}
		})
	}
}

// An entry with no class inherits the default rather than an empty string,
// which would silently match no policy at all.
func TestReplace_FillsEmptyClass(t *testing.T) {
	c := New("default")
	c.Replace([]Entry{entry("10.0.0.0/8", "", "sub-1")})

	got := c.Classify(netip.MustParseAddr("10.1.1.1"))
	if got.Class != "default" {
		t.Errorf("class = %q, want the default", got.Class)
	}
	if got.ID != "sub-1" {
		t.Errorf("id = %q, want sub-1", got.ID)
	}
}

// Replace must be safe against readers, since a policy push happens while
// queries are in flight.
func TestReplace_ConcurrentWithClassify(t *testing.T) {
	c := New("default")
	c.Replace([]Entry{entry("10.0.0.0/8", "one", "a")})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := netip.MustParseAddr("10.1.1.1")
			for {
				select {
				case <-stop:
					return
				default:
					if s := c.Classify(addr); s.Class == "" {
						t.Error("classification returned an empty class")
						return
					}
				}
			}
		}()
	}

	for i := 0; i < 200; i++ {
		class := "one"
		if i%2 == 0 {
			class = "two"
		}
		c.Replace([]Entry{entry("10.0.0.0/8", class, "a")})
	}
	close(stop)
	wg.Wait()
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefixes")
	content := `
# subscriber prefix map
10.0.0.0/8      wholesale
10.1.2.0/24     secure       acme-corp
2001:db8::/32   business     globex

`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	c := New("default")
	c.Replace(entries)
	if got := c.Classify(netip.MustParseAddr("10.1.2.9")); got.ID != "acme-corp" || got.Class != "secure" {
		t.Errorf("got %+v, want secure/acme-corp", got)
	}
	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3", c.Len())
	}
}

func TestLoadFile_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{"bad prefix", "notacidr secure\n", "not a valid CIDR"},
		{"host bits set", "10.0.0.5/24 secure\n", "host bits set"},
		{"missing class", "10.0.0.0/8\n", "expected"},
		{"too many fields", "10.0.0.0/8 a b c\n", "expected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "prefixes")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadFile(path)
			if err == nil {
				t.Fatal("expected the file to be rejected")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFile_Missing(t *testing.T) {
	if _, err := LoadFile("/nonexistent/prefixes"); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func BenchmarkClassify(b *testing.B) {
	c := New("default")
	entries := make([]Entry, 0, 10000)
	for i := 0; i < 10000; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}), 24)
		entries = append(entries, Entry{Prefix: p, Subscriber: Subscriber{ID: "sub", Class: "secure"}})
	}
	c.Replace(entries)
	addr := netip.AddrFrom4([4]byte{10, 20, 30, 40})

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Classify(addr)
		}
	})
}
