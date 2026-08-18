package cache

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func rrset(name string, n int) []dns.RR {
	out := make([]dns.RR, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300, Rdlength: 4},
			A:   net.IPv4(10, 0, byte(i), 1),
		})
	}
	return out
}

// A count cannot bound memory, which is the whole reason max_size exists: the
// cache has to stop at the byte ceiling even when the entry ceiling is nowhere
// near.
func TestEvictsOnByteCeiling(t *testing.T) {
	t.Parallel()

	const budget = 256 << 10 // 256KiB across all shards
	c, err := New(Options{
		MaxEntries: 1000000, // far out of reach, so only bytes can bind
		MaxBytes:   budget,
		Shards:     8,
		MinTTL:     time.Second, MaxTTL: time.Hour, MaxNegativeTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 20000; i++ {
		name := fmt.Sprintf("host%d.example.com.", i)
		c.PutRRset(NewKey(name, dns.TypeA, dns.ClassINET), rrset(name, 2), false)
	}

	st := c.Stats()
	if st.Evictions == 0 {
		t.Fatal("nothing was evicted: the byte ceiling is not being enforced")
	}
	if st.Entries >= 20000 {
		t.Fatalf("held %d entries; the byte ceiling did not bind", st.Entries)
	}
	// Per-shard budgets mean the total can sit a little above, never wildly.
	if st.Bytes > budget*2 {
		t.Errorf("holding %d bytes against a %d budget", st.Bytes, budget)
	}
	t.Logf("settled at %d entries, %d bytes against a %d budget", st.Entries, st.Bytes, budget)
}

// Removing an entry must give its bytes back, or the accounting drifts upward
// and the cache slowly starves itself.
func TestByteAccountingIsReturned(t *testing.T) {
	t.Parallel()

	c, err := New(Options{
		MaxEntries: 1000, MaxBytes: 1 << 20, Shards: 4,
		MinTTL: time.Second, MaxTTL: time.Hour, MaxNegativeTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 200; i++ {
		name := fmt.Sprintf("h%d.example.com.", i)
		c.PutRRset(NewKey(name, dns.TypeA, dns.ClassINET), rrset(name, 2), false)
	}
	filled := c.Stats().Bytes
	if filled <= 0 {
		t.Fatal("nothing was charged for 200 entries")
	}

	// Overwriting must charge the difference, not the whole thing again.
	for i := 0; i < 200; i++ {
		name := fmt.Sprintf("h%d.example.com.", i)
		c.PutRRset(NewKey(name, dns.TypeA, dns.ClassINET), rrset(name, 2), false)
	}
	if again := c.Stats().Bytes; again != filled {
		t.Errorf("rewriting the same entries changed the total from %d to %d", filled, again)
	}

	for i := 0; i < 200; i++ {
		c.Remove(NewKey(fmt.Sprintf("h%d.example.com.", i), dns.TypeA, dns.ClassINET))
	}
	if left := c.Stats().Bytes; left != 0 {
		t.Errorf("after removing everything the cache still claims %d bytes", left)
	}
}

// A single entry larger than one shard's budget must still be servable rather
// than evicted the moment it lands.
func TestOversizedEntryIsKept(t *testing.T) {
	t.Parallel()

	c, err := New(Options{
		MaxEntries: 1000, MaxBytes: 8 << 10, Shards: 8, // 1KiB per shard
		MinTTL: time.Second, MaxTTL: time.Hour, MaxNegativeTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	name := "big.example.com."
	k := NewKey(name, dns.TypeA, dns.ClassINET)
	c.PutRRset(k, rrset(name, 60), false)

	if _, ok := c.Get(k); !ok {
		t.Error("an entry bigger than its shard's budget was dropped immediately; the cache would thrash on it")
	}
}

// The byte ceiling is only as good as the estimate behind it. If the estimate
// drifts far from reality the setting stops meaning what an operator was told
// it means, so the constants are checked against real heap growth.
func TestEntrySizeTracksRealMemory(t *testing.T) {
	for _, records := range []int{2, 8} {
		c, err := New(Options{
			MaxEntries: 300000, Shards: 256,
			MinTTL: time.Second, MaxTTL: time.Hour, MaxNegativeTTL: time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}

		const n = 150000
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		for i := 0; i < n; i++ {
			name := fmt.Sprintf("host%d.example%d.com.", i, i%5000)
			c.PutRRset(NewKey(name, dns.TypeA, dns.ClassINET), rrset(name, records), false)
		}

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(c)

		measured := float64(after.HeapAlloc - before.HeapAlloc)
		claimed := float64(c.Stats().Bytes)
		ratio := claimed / measured

		t.Logf("%d records/entry: estimate %.0f MB, measured %.0f MB, ratio %.2f",
			records, claimed/(1<<20), measured/(1<<20), ratio)

		// Within a third either way. Closer than that is not achievable without
		// weighing live objects, and further than that would make the setting
		// misleading.
		if ratio < 0.67 || ratio > 1.5 {
			t.Errorf("%d records/entry: estimate is %.2f× the real heap; the constants need recalibrating",
				records, ratio)
		}
	}
}
