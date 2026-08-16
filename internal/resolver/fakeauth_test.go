package resolver

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
)

// This file builds a real, if miniature, DNS hierarchy on loopback: separate
// authoritative servers for the root, for a TLD and for a leaf zone, each on
// its own 127.0.0.x address, all speaking UDP and TCP on the same port.
//
// Recursion is almost entirely about how a resolver reacts to what servers
// send back — referrals, glue, empty non-terminals, lies — so testing it
// against mocked exchanges would test the mock. Running a genuine delegation
// chain is the only way these tests mean anything.

// fakeAuth is a minimal authoritative server for one zone.
type fakeAuth struct {
	zone string
	addr netip.Addr
	soa  *dns.SOA

	// delegations maps a child zone to its nameservers. An entry with no
	// addresses is a glueless delegation, which the resolver must handle by
	// resolving the nameserver's name separately.
	delegations map[string]map[string][]netip.Addr

	// records maps "name|TYPE" to the RRset served for it.
	records map[string][]dns.RR
	// exists names every owner name in the zone, so the server can tell
	// NODATA (name exists, no such type) from NXDOMAIN (no such name).
	exists map[string]bool

	queries atomic.Int64

	mu sync.Mutex
	// seen records the QNAMEs asked of this server.
	seen []string
	// mangle optionally rewrites a response, for testing how the resolver
	// reacts to a misbehaving or hostile authoritative. It is set after the
	// server is already serving, so it is guarded like any other shared state.
	mangle func(req, resp *dns.Msg) *dns.Msg
}

// setMangle installs a response rewriter. Safe to call while serving.
func (f *fakeAuth) setMangle(fn func(req, resp *dns.Msg) *dns.Msg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mangle = fn
}

func (f *fakeAuth) currentMangle() func(req, resp *dns.Msg) *dns.Msg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mangle
}

func newFakeAuth(zone, ip string) *fakeAuth {
	return &fakeAuth{
		zone:        dns.CanonicalName(zone),
		addr:        netip.MustParseAddr(ip),
		delegations: map[string]map[string][]netip.Addr{},
		records:     map[string][]dns.RR{},
		exists:      map[string]bool{},
		soa: &dns.SOA{
			Hdr:     dns.RR_Header{Name: dns.CanonicalName(zone), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns." + dns.CanonicalName(zone),
			Mbox:    "hostmaster." + dns.CanonicalName(zone),
			Serial:  1,
			Refresh: 7200, Retry: 3600, Expire: 1209600,
			Minttl: 300,
		},
	}
}

// delegate adds a child zone served by nameservers. Passing no addresses for a
// nameserver makes the delegation glueless.
func (f *fakeAuth) delegate(child string, ns map[string][]string) *fakeAuth {
	m := map[string][]netip.Addr{}
	for name, ips := range ns {
		addrs := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			addrs = append(addrs, netip.MustParseAddr(ip))
		}
		m[dns.CanonicalName(name)] = addrs
	}
	f.delegations[dns.CanonicalName(child)] = m
	return f
}

// addA adds an A record and marks the name as existing.
func (f *fakeAuth) addA(name, ip string, ttl uint32) *fakeAuth {
	n := dns.CanonicalName(name)
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: n, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	}
	f.records[key(n, dns.TypeA)] = append(f.records[key(n, dns.TypeA)], rr)
	f.exists[n] = true
	return f
}

// addAAAA adds an AAAA record.
func (f *fakeAuth) addAAAA(name, ip string, ttl uint32) *fakeAuth {
	n := dns.CanonicalName(name)
	rr := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: n, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: net.ParseIP(ip),
	}
	f.records[key(n, dns.TypeAAAA)] = append(f.records[key(n, dns.TypeAAAA)], rr)
	f.exists[n] = true
	return f
}

// addCNAME adds a CNAME.
func (f *fakeAuth) addCNAME(name, target string, ttl uint32) *fakeAuth {
	n := dns.CanonicalName(name)
	rr := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: n, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
		Target: dns.CanonicalName(target),
	}
	f.records[key(n, dns.TypeCNAME)] = append(f.records[key(n, dns.TypeCNAME)], rr)
	f.exists[n] = true
	return f
}

// addEmptyNonTerminal marks a name as existing with no records of its own,
// which is what an intermediate label in a deep name looks like.
func (f *fakeAuth) addEmptyNonTerminal(name string) *fakeAuth {
	f.exists[dns.CanonicalName(name)] = true
	return f
}

func key(name string, t uint16) string { return dns.CanonicalName(name) + "|" + dns.TypeToString[t] }

// observed returns the QNAMEs this server was asked for, lowercased.
func (f *fakeAuth) observed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.seen))
	copy(out, f.seen)
	return out
}

// delegationFor returns the most specific child zone containing qname.
func (f *fakeAuth) delegationFor(qname string) (string, map[string][]netip.Addr) {
	best := ""
	var bestNS map[string][]netip.Addr
	for child, ns := range f.delegations {
		if !inBailiwick(qname, child) {
			continue
		}
		if len(child) > len(best) {
			best, bestNS = child, ns
		}
	}
	return best, bestNS
}

func (f *fakeAuth) handle(w dns.ResponseWriter, req *dns.Msg) {
	f.queries.Add(1)
	q := req.Question[0]
	qname := dns.CanonicalName(q.Name)

	f.mu.Lock()
	f.seen = append(f.seen, qname)
	f.mu.Unlock()

	resp := new(dns.Msg)
	// SetReply copies the question verbatim, preserving 0x20 case — which is
	// exactly what a real authoritative does.
	resp.SetReply(req)
	resp.Authoritative = true

	switch {
	case !inBailiwick(qname, f.zone):
		// Not our zone at all.
		resp.Rcode = dns.RcodeRefused

	default:
		if child, ns := f.delegationFor(qname); child != "" {
			// Referral: NS in authority, glue in additional, not authoritative.
			resp.Authoritative = false
			for name, addrs := range ns {
				resp.Ns = append(resp.Ns, &dns.NS{
					Hdr: dns.RR_Header{Name: child, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
					Ns:  name,
				})
				for _, a := range addrs {
					resp.Extra = append(resp.Extra, addrRR(name, a, 3600))
				}
			}
			break
		}

		if rrs, ok := f.records[key(qname, q.Qtype)]; ok {
			resp.Answer = append(resp.Answer, rrs...)
			break
		}
		// A CNAME answers any type.
		if rrs, ok := f.records[key(qname, dns.TypeCNAME)]; ok && q.Qtype != dns.TypeCNAME {
			resp.Answer = append(resp.Answer, rrs...)
			break
		}
		if f.exists[qname] {
			resp.Ns = append(resp.Ns, f.soa) // NODATA
			break
		}
		resp.Rcode = dns.RcodeNameError
		resp.Ns = append(resp.Ns, f.soa)
	}

	if m := f.currentMangle(); m != nil {
		resp = m(req, resp)
	}
	if resp != nil {
		_ = w.WriteMsg(resp)
	}
}

func addrRR(name string, a netip.Addr, ttl uint32) dns.RR {
	if a.Is4() {
		return &dns.A{
			Hdr: dns.RR_Header{Name: dns.CanonicalName(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.IP(a.AsSlice()),
		}
	}
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: dns.CanonicalName(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: net.IP(a.AsSlice()),
	}
}

// start binds the server on its address for both UDP and TCP.
func (f *fakeAuth) start(t *testing.T, port uint16) {
	t.Helper()

	hostport := netip.AddrPortFrom(f.addr, port).String()
	handler := dns.HandlerFunc(f.handle)

	pc, err := net.ListenPacket("udp", hostport)
	if err != nil {
		t.Fatalf("binding fake auth %s udp: %v", f.zone, err)
	}
	udpStarted := make(chan struct{})
	udpSrv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(udpStarted) }}
	go func() { _ = udpSrv.ActivateAndServe() }()

	ln, err := net.Listen("tcp", hostport)
	if err != nil {
		t.Fatalf("binding fake auth %s tcp: %v", f.zone, err)
	}
	tcpStarted := make(chan struct{})
	tcpSrv := &dns.Server{Listener: ln, Handler: handler, NotifyStartedFunc: func() { close(tcpStarted) }}
	go func() { _ = tcpSrv.ActivateAndServe() }()

	for _, ch := range []chan struct{}{udpStarted, tcpStarted} {
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatalf("fake auth %s did not start", f.zone)
		}
	}
	t.Cleanup(func() {
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
	})
}

// freePort finds a port free on every loopback address the hierarchy uses.
func freePort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer func() { _ = c.Close() }()
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		t.Fatalf("parsing free port: %v", err)
	}
	return ap.Port()
}

// hierarchy is a started set of fake authoritatives plus the root hints that
// point at them.
type hierarchy struct {
	port  uint16
	zones map[string]*fakeAuth
	hints []Nameserver
}

func (h *hierarchy) zone(name string) *fakeAuth {
	z, ok := h.zones[dns.CanonicalName(name)]
	if !ok {
		panic("no such fake zone: " + name)
	}
	return z
}

// startHierarchy starts every supplied zone and builds root hints for the one
// serving ".".
func startHierarchy(t *testing.T, zones ...*fakeAuth) *hierarchy {
	t.Helper()

	// Verify the loopback aliases are usable before relying on them, so a
	// constrained environment produces a clear skip rather than a confusing
	// cascade of resolution failures.
	for _, z := range zones {
		if z.addr.Is4() && z.addr.String() != "127.0.0.1" {
			c, err := net.ListenPacket("udp", netip.AddrPortFrom(z.addr, 0).String())
			if err != nil {
				t.Skipf("SKIPPING: cannot bind loopback alias %s in this environment (%v)", z.addr, err)
			}
			_ = c.Close()
		}
	}

	port := freePort(t)
	h := &hierarchy{port: port, zones: map[string]*fakeAuth{}}
	for _, z := range zones {
		z.start(t, port)
		h.zones[z.zone] = z
	}

	root, ok := h.zones["."]
	if !ok {
		t.Fatal("hierarchy needs a root zone")
	}
	h.hints = []Nameserver{{Name: "a.root-servers.test.", Addrs: []netip.Addr{root.addr}}}
	return h
}

// newTestRecursive builds a Recursive wired to a hierarchy.
func newTestRecursive(t *testing.T, h *hierarchy, tune ...func(*RecursiveOptions)) *Recursive {
	t.Helper()

	c := testCache(t)
	infra := testInfra(t)

	opts := RecursiveOptions{
		Cache:             c,
		Infra:             infra,
		RootHints:         h.hints,
		ServerPort:        h.port,
		QueryTimeout:      2 * time.Second,
		QNAMEMinimisation: true,
		CaseRandomisation: true,
		UseIPv4:           true,
		UseIPv6:           true,
		Log:               quietLogger(),
		Metrics:           &RecursiveMetrics{},
	}
	for _, f := range tune {
		f(&opts)
	}

	r, err := NewRecursive(opts)
	if err != nil {
		t.Fatalf("building recursive resolver: %v", err)
	}
	return r
}

// standardHierarchy is the common three-level fixture:
//
//	.            served by 127.0.0.10, delegates com.
//	com.         served by 127.0.0.11, delegates example.com.
//	example.com. served by 127.0.0.12, holds the actual records
func standardHierarchy(t *testing.T) *hierarchy {
	t.Helper()

	root := newFakeAuth(".", "127.0.0.10").
		delegate("com.", map[string][]string{"ns.com.": {"127.0.0.11"}})

	com := newFakeAuth("com.", "127.0.0.11").
		delegate("example.com.", map[string][]string{"ns.example.com.": {"127.0.0.12"}})

	example := newFakeAuth("example.com.", "127.0.0.12").
		addA("www.example.com.", "192.0.2.80", 300).
		addAAAA("www.example.com.", "2001:db8::80", 300).
		addA("ns.example.com.", "127.0.0.12", 3600).
		addA("mail.example.com.", "192.0.2.81", 300)

	return startHierarchy(t, root, com, example)
}

// testInfra builds an infrastructure cache for tests.
func testInfra(t *testing.T) *cache.Infra {
	t.Helper()
	i, err := cache.NewInfra(cache.InfraOptions{
		MaxEntries: 1024,
		Shards:     16,
		// Short, so a test that exercises failure backoff does not have to
		// wait out a production-sized one.
		InitialRTT: 10 * time.Millisecond,
		MaxRTT:     time.Second,
		MaxBackoff: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("building infra cache: %v", err)
	}
	return i
}
