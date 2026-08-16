package transport

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/netacl"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// requireIPv6 skips a test when the environment has no IPv6 loopback.
//
// IPv6 is not optional for this project — a resolver that only works over v4
// fails on v6-only authoritatives — so these tests exist and must run in CI on
// a dual-stack host. Skipping is only for constrained sandboxes, and it is
// deliberately noisy about it rather than quietly passing.
func requireIPv6(t *testing.T) {
	t.Helper()
	c, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("SKIPPING IPv6 COVERAGE: no IPv6 loopback in this environment (%v). "+
			"This test must run on a dual-stack host before release.", err)
	}
	_ = c.Close()
}

func allowLoopback(t *testing.T) *netacl.ACL {
	t.Helper()
	return netacl.New([]netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}, false)
}

// echoHandler answers every query with a fixed A record.
func echoHandler() Handler {
	return HandlerFunc(func(ctx context.Context, req *Request) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req.Msg)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		})
		return m
	})
}

// startUDP brings up a UDP listener on an ephemeral port and returns its address.
func startUDP(t *testing.T, opts UDPOptions) (netip.AddrPort, *Metrics) {
	t.Helper()
	if opts.Log == nil {
		opts.Log = quietLogger()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	// One socket so the ephemeral port is unambiguous.
	opts.SocketsPerAddr = 1

	u, err := NewUDP(opts)
	if err != nil {
		t.Fatalf("NewUDP: %v", err)
	}
	addrs := u.LocalAddrs()
	if len(addrs) == 0 {
		t.Fatal("no bound UDP addresses")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = u.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("UDP listener did not shut down")
		}
	})
	return addrs[0], opts.Metrics
}

func startTCP(t *testing.T, opts TCPOptions) (netip.AddrPort, *Metrics) {
	t.Helper()
	if opts.Log == nil {
		opts.Log = quietLogger()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	tcp, err := NewTCP(opts)
	if err != nil {
		t.Fatalf("NewTCP: %v", err)
	}
	addrs := tcp.LocalAddrs()
	if len(addrs) == 0 {
		t.Fatal("no bound TCP addresses")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = tcp.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("TCP listener did not shut down")
		}
	})
	return addrs[0], opts.Metrics
}

func ask(t *testing.T, network string, addr netip.AddrPort, name string) (*dns.Msg, error) {
	t.Helper()
	c := &dns.Client{Net: network, Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.RecursionDesired = true
	resp, _, err := c.Exchange(m, addr.String())
	return resp, err
}

// Every listener must work on both families. An IPv4-only lab silently hides
// the class of bug where a resolver never works over IPv6 at all.
func TestUDP_AnswersOnBothFamilies(t *testing.T) {
	tests := []struct {
		name string
		addr string
		v6   bool
	}{
		{"IPv4", "127.0.0.1:0", false},
		{"IPv6", "[::1]:0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.v6 {
				requireIPv6(t)
			}
			addr, _ := startUDP(t, UDPOptions{
				Addrs:      []netip.AddrPort{netip.MustParseAddrPort(tt.addr)},
				AllowQuery: allowLoopback(t),
				Handler:    echoHandler(),
			})

			resp, err := ask(t, "udp", addr, "example.com.")
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
			}
			if len(resp.Answer) != 1 {
				t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
			}
		})
	}
}

func TestTCP_AnswersOnBothFamilies(t *testing.T) {
	tests := []struct {
		name string
		addr string
		v6   bool
	}{
		{"IPv4", "127.0.0.1:0", false},
		{"IPv6", "[::1]:0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.v6 {
				requireIPv6(t)
			}
			addr, _ := startTCP(t, TCPOptions{
				Addrs:      []netip.AddrPort{netip.MustParseAddrPort(tt.addr)},
				AllowQuery: allowLoopback(t),
				Handler:    echoHandler(),
			})

			resp, err := ask(t, "tcp", addr, "example.com.")
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			if len(resp.Answer) != 1 {
				t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
			}
		})
	}
}

// A client outside allow_query gets REFUSED, which is smaller than the query
// and therefore not useful for amplification.
func TestUDP_RefusesClientOutsideACL(t *testing.T) {
	addr, _ := startUDP(t, UDPOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		AllowQuery: netacl.New([]netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")}, false),
		Handler:    echoHandler(),
	})

	resp, err := ask(t, "udp", addr, "example.com.")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Error("a refused query must not carry an answer")
	}
}

func TestTCP_DropsConnectionOutsideACL(t *testing.T) {
	addr, metrics := startTCP(t, TCPOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		AllowQuery: netacl.New([]netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")}, false),
		Handler:    echoHandler(),
	})

	if _, err := ask(t, "tcp", addr, "example.com."); err == nil {
		t.Error("expected the connection to be dropped for a disallowed client")
	}
	// Give the accept loop a moment to record it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && metrics.TCPRefused.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if metrics.TCPRefused.Load() == 0 {
		t.Error("expected the refusal to be counted")
	}
}

// Garbage on the wire must be dropped silently. Replying to it would make the
// resolver a reflector for any spoofed source.
func TestUDP_MalformedPacketIsDroppedSilently(t *testing.T) {
	addr, metrics := startUDP(t, UDPOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		AllowQuery: allowLoopback(t),
		Handler:    echoHandler(),
	})

	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 512)
	if n, err := conn.Read(buf); err == nil {
		t.Errorf("expected no reply to a malformed packet, got %d bytes", n)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && metrics.ParseErrors.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if metrics.ParseErrors.Load() == 0 {
		t.Error("expected the malformed packet to be counted")
	}
}

// A panic in the handler must be contained: counted, answered with SERVFAIL,
// and the daemon keeps serving. Everything here is attacker-controlled.
func TestUDP_HandlerPanicBecomesServfail(t *testing.T) {
	addr, metrics := startUDP(t, UDPOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		AllowQuery: allowLoopback(t),
		Handler: HandlerFunc(func(ctx context.Context, req *Request) *dns.Msg {
			panic("simulated handler bug")
		}),
	})

	resp, err := ask(t, "udp", addr, "example.com.")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	if metrics.Panics.Load() != 1 {
		t.Errorf("Panics = %d, want 1", metrics.Panics.Load())
	}

	// Still serving afterwards.
	if _, err := ask(t, "udp", addr, "example.com."); err != nil {
		t.Errorf("listener should keep serving after a recovered panic: %v", err)
	}
}

// An oversized answer must come back with TC set so the client retries over
// TCP, rather than being silently short.
func TestUDP_TruncatesOversizedResponse(t *testing.T) {
	big := HandlerFunc(func(ctx context.Context, req *Request) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req.Msg)
		for i := 0; i < 200; i++ {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, byte(i%256)),
			})
		}
		return m
	})

	addr, metrics := startUDP(t, UDPOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		AllowQuery: allowLoopback(t),
		UDPSize:    1232,
		Handler:    big,
	})

	// Measure the datagram off the wire rather than trusting Msg.Len(): Len()
	// recomputes an UNCOMPRESSED length, so a reparsed message reports far
	// more than the bytes that actually crossed the network. Only the real
	// datagram size tells us whether the 512-byte limit was honoured.
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA) // no EDNS0 => 512-byte limit
	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(packed); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n > 512 {
		t.Errorf("response datagram is %d bytes, want <= 512", n)
	}

	var resp dns.Msg
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if !resp.Truncated {
		t.Error("expected TC to be set on an oversized response")
	}
	if len(resp.Answer) == 0 {
		t.Error("a truncated response should still carry the records that fit")
	}
	if len(resp.Answer) >= 200 {
		t.Errorf("expected records to be dropped, still got %d", len(resp.Answer))
	}
	if metrics.Truncated.Load() == 0 {
		t.Error("expected the truncation to be counted")
	}
}

// TCP is a stream transport, so the same large answer must arrive whole.
func TestTCP_DoesNotTruncateLargeResponse(t *testing.T) {
	big := HandlerFunc(func(ctx context.Context, req *Request) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req.Msg)
		for i := 0; i < 200; i++ {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: req.Msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, byte(i%256)),
			})
		}
		return m
	})

	addr, _ := startTCP(t, TCPOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		AllowQuery: allowLoopback(t),
		Handler:    big,
	})

	resp, err := ask(t, "tcp", addr, "example.com.")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.Truncated {
		t.Error("TCP responses must not be truncated")
	}
	if len(resp.Answer) != 200 {
		t.Errorf("got %d answers, want 200", len(resp.Answer))
	}
}

// RFC 7766: a client may send several queries on one connection.
func TestTCP_HandlesMultipleQueriesPerConnection(t *testing.T) {
	addr, _ := startTCP(t, TCPOptions{
		Addrs:       []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		AllowQuery:  allowLoopback(t),
		IdleTimeout: 5 * time.Second,
		Handler:     echoHandler(),
	})

	c := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	conn, err := c.Dial(addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	for i := 0; i < 3; i++ {
		m := new(dns.Msg)
		m.SetQuestion("example.com.", dns.TypeA)
		if err := conn.WriteMsg(m); err != nil {
			t.Fatalf("query %d write: %v", i, err)
		}
		resp, err := conn.ReadMsg()
		if err != nil {
			t.Fatalf("query %d read: %v", i, err)
		}
		if len(resp.Answer) != 1 {
			t.Errorf("query %d: expected 1 answer, got %d", i, len(resp.Answer))
		}
	}
}

// A wildcard bind loses the destination address and breaks anycast source
// selection, so config rejects it — but NewUDP is also reachable directly.
func TestNewUDP_RequiresHandler(t *testing.T) {
	_, err := NewUDP(UDPOptions{Addrs: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")}})
	if err == nil {
		t.Error("expected NewUDP to require a handler")
	}
}

func TestNewUDP_BindFailureIsFatal(t *testing.T) {
	// Port 1 is privileged; binding it as a normal user must fail rather than
	// leave the daemon partially listening.
	_, err := NewUDP(UDPOptions{
		Addrs:   []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")},
		Handler: echoHandler(),
		Log:     quietLogger(),
	})
	if err == nil {
		t.Skip("running with privileges to bind port 1; skipping")
	}
}

func TestResponseSizeFor(t *testing.T) {
	tests := []struct {
		name  string
		proto Proto
		edns  uint16 // 0 means no OPT record
		limit uint16
		want  int
	}{
		{"udp without edns is 512", ProtoUDP, 0, 1232, 512},
		{"udp with edns takes the client size", ProtoUDP, 1232, 1232, 1232},
		{"udp clamps to the operator limit", ProtoUDP, 4096, 1232, 1232},
		{"udp raises a silly small advertisement", ProtoUDP, 100, 1232, 512},
		{"tcp uses the stream ceiling", ProtoTCP, 0, 1232, dns.MaxMsgSize},
		{"doh uses the stream ceiling", ProtoDoH, 0, 1232, dns.MaxMsgSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := new(dns.Msg)
			m.SetQuestion("example.com.", dns.TypeA)
			if tt.edns > 0 {
				m.SetEdns0(tt.edns, false)
			}
			if got := responseSizeFor(m, tt.proto, tt.limit); got != tt.want {
				t.Errorf("responseSizeFor = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestProtoString(t *testing.T) {
	tests := []struct {
		p    Proto
		want string
	}{
		{ProtoUDP, "udp"},
		{ProtoTCP, "tcp"},
		{ProtoDoT, "dot"},
		{ProtoDoH, "doh"},
		{Proto(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.p.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
