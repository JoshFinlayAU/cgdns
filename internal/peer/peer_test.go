package peer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/control"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// pairTLS builds a private CA and a certificate both halves trust, which is
// what the pair link requires: the peer may insert into this node's cache, so
// an unauthenticated peer could poison it.
func pairTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cgdns pair CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cgdns node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"peer.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	cert := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}

	return &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		}, &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			ServerName:   "peer.test",
			MinVersion:   tls.VersionTLS12,
		}
}

func testCache(t *testing.T) *cache.Cache {
	t.Helper()
	c, err := cache.New(cache.Options{
		MaxEntries: 1024, Shards: 16,
		MinTTL: time.Second, MaxTTL: time.Hour, MaxNegativeTTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func aRecord(name, ip string, ttl uint32) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	}
}

// node is one half of a test pair.
type node struct {
	id     string
	cache  *cache.Cache
	store  *control.Store
	server *Server
	client *Client
	metric *Metrics
}

// startPair brings up two fully connected nodes over real TLS sockets.
func startPair(t *testing.T) (ns1, ns2 *node) {
	t.Helper()
	sCfg, cCfg := pairTLS(t)

	mk := func(id string) *node {
		st, err := control.Open(control.StoreOptions{NodeID: id})
		if err != nil {
			t.Fatal(err)
		}
		c := testCache(t)
		m := &Metrics{}
		srv, err := NewServer(ServerOptions{
			NodeID: id, Addr: "127.0.0.1:0", TLS: sCfg,
			Cache: c, Store: st, Log: quietLogger(), Metrics: m,
		})
		if err != nil {
			t.Fatalf("NewServer(%s): %v", id, err)
		}
		return &node{id: id, cache: c, store: st, server: srv, metric: m}
	}

	ns1, ns2 = mk("ns1"), mk("ns2")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, n := range []*node{ns1, ns2} {
		go func(n *node) { _ = n.server.Serve(ctx) }(n)
	}

	link := func(from, to *node) {
		cl, err := NewClient(ClientOptions{
			NodeID: from.id, Addr: to.server.Addr(), TLS: cCfg,
			Store: from.store, Log: quietLogger(), Metrics: from.metric,
			PushInterval: 20 * time.Millisecond, SyncInterval: time.Hour,
		})
		if err != nil {
			t.Fatalf("NewClient(%s): %v", from.id, err)
		}
		from.client = cl
		go func() { _ = cl.Run(ctx) }()
	}
	link(ns1, ns2)
	link(ns2, ns1)

	waitFor(t, func() bool { return ns1.client.Connected() && ns2.client.Connected() }, "pair link to come up")
	return ns1, ns2
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestPair_Connects(t *testing.T) {
	ns1, ns2 := startPair(t)
	if !ns1.client.Connected() || !ns2.client.Connected() {
		t.Fatal("both halves should be connected")
	}
	waitFor(t, func() bool { return ns1.server.Connected() && ns2.server.Connected() }, "inbound links")
}

// A fill on one node should reach the sibling, so the survivor of a pair is
// already warm.
func TestPair_PushOnFill(t *testing.T) {
	ns1, ns2 := startPair(t)

	dec := NewCache(CacheOptions{Local: ns1.cache, Client: ns1.client, Log: quietLogger(), Metrics: ns1.metric})
	k := cache.NewKey("www.example.com.", dns.TypeA, dns.ClassINET)
	dec.PutRRset(k, []dns.RR{aRecord("www.example.com.", "192.0.2.10", 300)}, false)

	waitFor(t, func() bool { _, ok := ns2.cache.Peek(k); return ok }, "the entry to reach ns2")

	e, ok := ns2.cache.Peek(k)
	if !ok {
		t.Fatal("ns2 never received the entry")
	}
	if len(e.RRs) != 1 {
		t.Fatalf("ns2 holds %d records, want 1", len(e.RRs))
	}
	if got := e.RRs[0].(*dns.A).A.String(); got != "192.0.2.10" {
		t.Errorf("ns2 holds %s, want 192.0.2.10", got)
	}
}

// A local miss should be served from the sibling rather than going upstream.
func TestPair_PullOnMiss(t *testing.T) {
	ns1, ns2 := startPair(t)

	k := cache.NewKey("only-on-ns2.example.", dns.TypeA, dns.ClassINET)
	ns2.cache.PutRRset(k, []dns.RR{aRecord("only-on-ns2.example.", "192.0.2.20", 300)}, false)

	dec := NewCache(CacheOptions{Local: ns1.cache, Client: ns1.client, Log: quietLogger(), Metrics: ns1.metric})
	e, ok := dec.Get(k)
	if !ok {
		t.Fatal("ns1 should have fetched the entry from ns2")
	}
	if got := e.RRs[0].(*dns.A).A.String(); got != "192.0.2.20" {
		t.Errorf("fetched %s, want 192.0.2.20", got)
	}
	// And it should now be local, so a second lookup costs nothing.
	if _, ok := ns1.cache.Peek(k); !ok {
		t.Error("the fetched entry should have been adopted locally")
	}
}

// An entry received from the peer must never be pushed back, or the two nodes
// ping-pong every entry forever.
func TestPair_NoPushLoop(t *testing.T) {
	ns1, ns2 := startPair(t)

	dec := NewCache(CacheOptions{Local: ns1.cache, Client: ns1.client, Log: quietLogger(), Metrics: ns1.metric})
	k := cache.NewKey("loop.example.", dns.TypeA, dns.ClassINET)
	dec.PutRRset(k, []dns.RR{aRecord("loop.example.", "192.0.2.30", 300)}, false)

	waitFor(t, func() bool { _, ok := ns2.cache.Peek(k); return ok }, "the entry to reach ns2")
	time.Sleep(300 * time.Millisecond)

	// ns2 received one push and must not have echoed it back.
	if sent := ns2.metric.CachePushSent.Load(); sent != 0 {
		t.Errorf("ns2 pushed %d entries back; a received entry must not be re-offered", sent)
	}
}

// TTLs must be sent as the time remaining, or a shared entry outlives its own
// expiry on the peer.
func TestPair_TTLDecrementsInTransit(t *testing.T) {
	ns1, ns2 := startPair(t)

	k := cache.NewKey("ttl.example.", dns.TypeA, dns.ClassINET)
	ns1.cache.PutRRset(k, []dns.RR{aRecord("ttl.example.", "192.0.2.40", 300)}, false)

	time.Sleep(1100 * time.Millisecond)

	e, _ := ns1.cache.Peek(k)
	ns1.client.QueuePush(k, e)
	waitFor(t, func() bool { _, ok := ns2.cache.Peek(k); return ok }, "the entry to reach ns2")

	got, _ := ns2.cache.Peek(k)
	remaining := got.TTLAt(time.Now())
	if remaining >= 300 {
		t.Errorf("ns2 TTL = %d, want less than the original 300 — TTL must decrement in transit", remaining)
	}
	if remaining == 0 {
		t.Error("ns2 TTL should still be positive")
	}
}

// Config written on either node must converge on both.
func TestPair_ConfigConverges(t *testing.T) {
	ns1, ns2 := startPair(t)

	if _, err := ns1.store.Put(control.KindClass, "secure", control.ClassRecord{Name: "secure", Action: "nxdomain"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ns2.store.Put(control.KindSubscriber, "198.51.100.0/24",
		control.SubscriberRecord{Prefix: "198.51.100.0/24", ID: "acme", Class: "secure"}); err != nil {
		t.Fatal(err)
	}

	ns1.client.Sync(context.Background())
	ns2.client.Sync(context.Background())

	waitFor(t, func() bool { return ns1.store.Hash() == ns2.store.Hash() }, "config to converge")
	if got := len(ns1.store.Records()); got != 2 {
		t.Errorf("ns1 holds %d records, want 2", got)
	}
	if got := len(ns2.store.Records()); got != 2 {
		t.Errorf("ns2 holds %d records, want 2", got)
	}
}

// A node written to while its sibling was unreachable must bring it up to date
// once the link returns.
func TestPair_CatchesUpAfterOutage(t *testing.T) {
	ns1, ns2 := startPair(t)

	// Take ns2's listener away, so ns1 cannot reach it.
	_ = ns2.server.Close()
	waitFor(t, func() bool {
		ns1.client.Sync(context.Background())
		return !ns1.client.Connected()
	}, "ns1 to notice ns2 is gone")

	for _, k := range []string{"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"} {
		if _, err := ns1.store.Put(control.KindSubscriber, k,
			control.SubscriberRecord{Prefix: k, ID: "acme", Class: "secure"}); err != nil {
			t.Fatal(err)
		}
	}

	// ns2 returns. The anti-entropy exchange is what repairs the gap: ns2 sends
	// its digests, ns1 answers with everything ns2 is missing.
	adopted := ns2.store.Merge(ns1.store.Missing(ns2.store.Digests()))
	if adopted != 3 {
		t.Errorf("ns2 adopted %d records on catch-up, want 3", adopted)
	}
	if ns1.store.Hash() != ns2.store.Hash() {
		t.Error("the pair did not converge after catch-up")
	}
}

// The pair link must never be able to fail or delay a query. With the sibling
// gone, a miss is simply a miss.
func TestPair_DegradesToMissWhenPeerGone(t *testing.T) {
	ns1, ns2 := startPair(t)
	_ = ns2.server.Close()

	dec := NewCache(CacheOptions{Local: ns1.cache, Client: ns1.client, Log: quietLogger(), Metrics: ns1.metric})
	k := cache.NewKey("nowhere.example.", dns.TypeA, dns.ClassINET)

	start := time.Now()
	if _, ok := dec.Get(k); ok {
		t.Error("expected a miss with the sibling gone")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("a miss took %s; the pair link must not delay a query", elapsed)
	}

	// Writes must still work locally.
	dec.PutRRset(k, []dns.RR{aRecord("nowhere.example.", "192.0.2.50", 60)}, false)
	if _, ok := ns1.cache.Peek(k); !ok {
		t.Error("a local fill must still work with the sibling gone")
	}
}

func TestServer_RequiresClientCert(t *testing.T) {
	sCfg, _ := pairTLS(t)
	sCfg.ClientAuth = tls.NoClientCert

	_, err := NewServer(ServerOptions{NodeID: "ns1", Addr: "127.0.0.1:0", TLS: sCfg})
	if err == nil {
		t.Fatal("a pair link that does not verify the client certificate must be refused")
	}
}

func TestEncodeDecodeEntry(t *testing.T) {
	tests := []struct {
		name  string
		build func() (cache.Key, cache.Entry)
	}{
		{
			name: "positive answer",
			build: func() (cache.Key, cache.Entry) {
				c := testCache(t)
				k := cache.NewKey("a.example.", dns.TypeA, dns.ClassINET)
				c.PutRRset(k, []dns.RR{aRecord("a.example.", "192.0.2.1", 300)}, true)
				e, _ := c.Peek(k)
				return k, e
			},
		},
		{
			name: "negative answer",
			build: func() (cache.Key, cache.Entry) {
				c := testCache(t)
				k := cache.NewKey("nope.example.", dns.TypeA, dns.ClassINET)
				soa := &dns.SOA{
					Hdr:    dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 120},
					Ns:     "ns.example.",
					Mbox:   "hostmaster.example.",
					Minttl: 120,
				}
				c.PutNegative(k, dns.RcodeNameError, []dns.RR{soa}, 120*time.Second, false)
				e, _ := c.Peek(k)
				return k, e
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k, e := tt.build()
			blob, err := encodeEntry(k, e, time.Now())
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			gotKey, gotEntry, ttl, err := decodeEntry(blob)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if gotKey != k {
				t.Errorf("key = %+v, want %+v", gotKey, k)
			}
			if gotEntry.Kind != e.Kind {
				t.Errorf("kind = %v, want %v", gotEntry.Kind, e.Kind)
			}
			if gotEntry.Rcode != e.Rcode {
				t.Errorf("rcode = %d, want %d", gotEntry.Rcode, e.Rcode)
			}
			if gotEntry.Authenticated != e.Authenticated {
				t.Errorf("authenticated = %v, want %v", gotEntry.Authenticated, e.Authenticated)
			}
			if ttl <= 0 {
				t.Errorf("ttl = %s, want positive", ttl)
			}
		})
	}
}

func TestDecodeEntry_RejectsGarbage(t *testing.T) {
	if _, _, _, err := decodeEntry([]byte{0xde, 0xad}); err == nil {
		t.Error("expected malformed input to be rejected")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf net.Buffers
	_ = buf

	pr, pw := net.Pipe()
	go func() {
		_ = writeFrame(pw, MsgCachePush, []byte("payload"))
		_ = pw.Close()
	}()

	t.Cleanup(func() { _ = pr.Close() })
	typ, payload, err := readFrame(pr)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if typ != MsgCachePush {
		t.Errorf("type = %s, want cache-push", typ)
	}
	if string(payload) != "payload" {
		t.Errorf("payload = %q", payload)
	}
}

// A reconnect overlaps: the replacement connection is serving while the old one
// waits out its idle timeout. The server must not report the link down when the
// stale connection finally closes.
func TestServer_StaysUpAcrossOverlappingConnections(t *testing.T) {
	sCfg, cCfg := pairTLS(t)

	st, err := control.Open(control.StoreOptions{NodeID: "ns1"})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerOptions{
		NodeID: "ns1", Addr: "127.0.0.1:0", TLS: sCfg,
		Cache: testCache(t), Store: st, Log: quietLogger(), Metrics: &Metrics{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	dialPeer := func(id string) *Client {
		t.Helper()
		cl, err := NewClient(ClientOptions{
			NodeID: id, Addr: srv.Addr(), TLS: cCfg,
			Store: st, Log: quietLogger(), Metrics: &Metrics{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := cl.dial(ctx); err != nil {
			t.Fatalf("dial(%s): %v", id, err)
		}
		return cl
	}

	stale := dialPeer("ns2")
	waitFor(t, srv.Connected, "the first connection to attach")

	fresh := dialPeer("ns2")
	waitFor(t, func() bool { return srv.active.Load() == 2 }, "both connections to attach")

	if err := stale.Close(); err != nil {
		t.Fatalf("closing the stale connection: %v", err)
	}
	waitFor(t, func() bool { return srv.active.Load() == 1 }, "the stale connection to drop")

	if !srv.Connected() {
		t.Fatal("server reports the link down while the replacement connection is still serving")
	}

	if err := fresh.Close(); err != nil {
		t.Fatalf("closing the fresh connection: %v", err)
	}
	waitFor(t, func() bool { return !srv.Connected() }, "the link to go down once both closed")
}
