package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/JoshFinlayAU/cgdns/internal/netacl"
)

// startDoQ brings up a listener on a free loopback port.
func startDoQ(t *testing.T, h Handler, tune ...func(*DoQOptions)) (*DoQ, string, *Metrics) {
	t.Helper()

	m := &Metrics{}
	opts := DoQOptions{
		Addrs:        []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		TLS:          testTLS(t),
		Handler:      h,
		Log:          quietLogger(),
		Metrics:      m,
		ClientBudget: 3 * time.Second,
	}
	for _, f := range tune {
		f(&opts)
	}

	d, err := NewDoQ(opts)
	if err != nil {
		t.Fatalf("starting doq: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = d.Close() })
	go func() { _ = d.Serve(ctx) }()

	return d, d.Addrs()[0], m
}

// doqDial connects a client the way RFC 9250 says one must.
func doqDial(t *testing.T, addr string, alpn ...string) *quic.Conn {
	t.Helper()
	protos := []string{ALPNDoQ}
	if len(alpn) > 0 {
		protos = alpn
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         protos,
	}, &quic.Config{MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("dialling doq: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	return conn
}

// doqQuery sends one query on its own stream and reads the response.
func doqQuery(t *testing.T, conn *quic.Conn, m *dns.Msg) (*dns.Msg, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}
	if err := writePrefixed(stream, packed); err != nil {
		return nil, err
	}
	// The client signals it is done sending, which is what lets the server
	// answer without waiting for an idle timeout.
	if err := stream.Close(); err != nil {
		return nil, err
	}

	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, err := readPrefixed(stream)
	if err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(raw); err != nil {
		return nil, err
	}
	return resp, nil
}

func answerHandler(t *testing.T) Handler {
	t.Helper()
	return HandlerFunc(func(_ context.Context, req *Request) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req.Msg)
		rr, err := dns.NewRR("example.com. 300 IN A 192.0.2.1")
		if err != nil {
			t.Error(err)
			return nil
		}
		m.Answer = []dns.RR{rr}
		return m
	})
}

func query0(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	// RFC 9250 §4.2.1: zero, because a stream carries exactly one exchange.
	m.Id = 0
	return m
}

func TestDoQ_AnswersAQuery(t *testing.T) {
	_, addr, m := startDoQ(t, answerHandler(t))
	conn := doqDial(t, addr)

	resp, err := doqQuery(t, conn, query0("example.com", dns.TypeA))
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.1" {
		t.Fatalf("got %v", resp.Answer[0])
	}
	if resp.Id != 0 {
		t.Fatalf("response ID is %d, want 0", resp.Id)
	}
	if got := m.Queries.Load(); got != 1 {
		t.Fatalf("counted %d queries", got)
	}
}

// The point of QUIC here: each query has its own stream, so a slow answer does
// not stall the ones behind it the way it would on one TCP connection.
func TestDoQ_ConcurrentStreamsDoNotBlockEachOther(t *testing.T) {
	slow := make(chan struct{})
	h := HandlerFunc(func(_ context.Context, req *Request) *dns.Msg {
		if req.Msg.Question[0].Name == "slow.example.com." {
			<-slow
		}
		m := new(dns.Msg)
		m.SetReply(req.Msg)
		rr, _ := dns.NewRR(req.Msg.Question[0].Name + " 300 IN A 192.0.2.1")
		m.Answer = []dns.RR{rr}
		return m
	})

	_, addr, _ := startDoQ(t, h)
	conn := doqDial(t, addr)

	done := make(chan error, 1)
	go func() {
		_, err := doqQuery(t, conn, query0("slow.example.com", dns.TypeA))
		done <- err
	}()

	// The fast query must complete while the slow one is still parked.
	time.Sleep(100 * time.Millisecond)
	if _, err := doqQuery(t, conn, query0("fast.example.com", dns.TypeA)); err != nil {
		t.Fatalf("a fast query was blocked behind a slow one: %v", err)
	}

	close(slow)
	if err := <-done; err != nil {
		t.Fatalf("the slow query failed: %v", err)
	}
}

// RFC 9250 §4.2.1. Answering a non-zero ID would invite clients to treat a
// stream as a TCP connection and multiplex on it.
func TestDoQ_RejectsNonZeroMessageID(t *testing.T) {
	_, addr, m := startDoQ(t, answerHandler(t))
	conn := doqDial(t, addr)

	q := query0("example.com", dns.TypeA)
	q.Id = 0x1234
	if _, err := doqQuery(t, conn, q); err == nil {
		t.Fatal("a query with a non-zero message ID was answered")
	}
	if got := m.ParseErrors.Load(); got == 0 {
		t.Fatal("the protocol error was not counted")
	}
}

// RFC 9250 §5.5.2: QUIC has its own idle timeout, so the option is meaningless
// and its presence is a protocol error.
func TestDoQ_RejectsEDNSTCPKeepalive(t *testing.T) {
	_, addr, _ := startDoQ(t, answerHandler(t))
	conn := doqDial(t, addr)

	q := query0("example.com", dns.TypeA)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE})
	q.Extra = append(q.Extra, opt)

	if _, err := doqQuery(t, conn, q); err == nil {
		t.Fatal("a query carrying edns-tcp-keepalive was answered")
	}
}

// A client that does not offer the doq ALPN is not a DoQ client.
func TestDoQ_RequiresTheDoQALPN(t *testing.T) {
	_, addr, _ := startDoQ(t, answerHandler(t))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := quic.DialAddr(ctx, addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}, &quic.Config{})
	if err == nil {
		t.Fatal("a connection offering only h3 was accepted")
	}
}

func TestDoQ_EnforcesAllowQuery(t *testing.T) {
	_, addr, m := startDoQ(t, answerHandler(t), func(o *DoQOptions) {
		// Nothing is permitted, so the local client is refused.
		// Permits only a range this loopback client is not in.
		o.AllowQuery = netacl.New([]netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")}, false)
	})

	conn := doqDial(t, addr)
	if _, err := doqQuery(t, conn, query0("example.com", dns.TypeA)); err == nil {
		t.Fatal("a client outside allow_query was served")
	}
	if got := m.DoQRefused.Load(); got != 1 {
		t.Fatalf("refused count is %d, want 1", got)
	}
}

// A malformed length prefix must not be turned into a query.
func TestDoQ_RejectsGarbage(t *testing.T) {
	_, addr, m := startDoQ(t, answerHandler(t))
	conn := doqDial(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A length prefix promising far more than follows.
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], 4096)
	if _, err := stream.Write(append(hdr[:], 0x01, 0x02)); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()

	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readPrefixed(stream); err == nil {
		t.Fatal("a truncated message produced a response")
	}
	if got := m.ParseErrors.Load(); got == 0 {
		t.Fatal("the parse error was not counted")
	}
}

// A dropped query must send nothing at all rather than an empty response.
func TestDoQ_NilResponseSendsNothing(t *testing.T) {
	_, addr, m := startDoQ(t, HandlerFunc(func(context.Context, *Request) *dns.Msg { return nil }))
	conn := doqDial(t, addr)

	_, err := doqQuery(t, conn, query0("example.com", dns.TypeA))
	if err == nil {
		t.Fatal("a dropped query produced a response")
	}
	if !errors.Is(err, io.EOF) && !isTimeout(err) {
		t.Logf("dropped query ended with: %v", err)
	}
	if got := m.Dropped.Load(); got != 1 {
		t.Fatalf("dropped count is %d, want 1", got)
	}
}

// The request must be marked as DoQ, since subscriber policy and rate limiting
// both key off the protocol.
func TestDoQ_RequestCarriesTheProtocol(t *testing.T) {
	seen := make(chan Proto, 1)
	_, addr, _ := startDoQ(t, HandlerFunc(func(_ context.Context, req *Request) *dns.Msg {
		seen <- req.Proto
		m := new(dns.Msg)
		m.SetReply(req.Msg)
		return m
	}))

	conn := doqDial(t, addr)
	if _, err := doqQuery(t, conn, query0("example.com", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-seen:
		if p != ProtoDoQ {
			t.Fatalf("handler saw proto %s, want doq", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the handler was never called")
	}
}

func TestNewDoQ_Rejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts DoQOptions
	}{
		{"no address", DoQOptions{TLS: testTLS(t), Handler: answerHandler(t)}},
		{"no TLS", DoQOptions{Addrs: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")}, Handler: answerHandler(t)}},
		{"no handler", DoQOptions{Addrs: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")}, TLS: testTLS(t)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewDoQ(tc.opts); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
