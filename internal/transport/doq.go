package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/JoshFinlayAU/cgdns/internal/netacl"
)

// ALPNDoQ is the token RFC 9250 assigns to DNS over QUIC. A connection that
// does not offer it is not a DoQ client and is refused during the handshake.
const ALPNDoQ = "doq"

// DoQ application error codes (RFC 9250 §4.3).
const (
	doqNoError       quic.ApplicationErrorCode = 0x0
	doqInternalError quic.ApplicationErrorCode = 0x1
	doqProtocolError quic.ApplicationErrorCode = 0x2
	// doqExcessiveLoad is the code for shedding a client that is too much.
	doqExcessiveLoad quic.ApplicationErrorCode = 0x4
)

// DoQ serves DNS over QUIC (RFC 9250).
//
// QUIC gives each query its own stream, so head-of-line blocking between
// concurrent queries disappears — the problem DoT has, where one slow answer
// stalls everything behind it on the same TCP connection.
type DoQ struct {
	opts      DoQOptions
	listeners []*quic.Listener
	conns     []net.PacketConn

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// DoQOptions configures the DoQ listener.
type DoQOptions struct {
	// Addrs are bound individually, never a wildcard, for the same reason the
	// UDP listener is: a reply has to leave from the address it arrived on.
	Addrs []netip.AddrPort

	// TLS must carry the server certificate. ALPN is set here rather than
	// taken from the caller, since a DoQ listener that negotiated anything
	// else would not be a DoQ listener.
	TLS *tls.Config

	// MaxIdleTimeout closes a connection that has gone quiet.
	MaxIdleTimeout time.Duration
	// MaxStreamsPerConn caps concurrent queries on one connection, which is
	// what stops a single client opening unbounded work.
	MaxStreamsPerConn int64
	// ClientBudget is the wall clock one query may consume.
	ClientBudget time.Duration

	AllowQuery *netacl.ACL
	Handler    Handler
	Log        *slog.Logger
	Metrics    *Metrics
}

// NewDoQ binds the QUIC listeners.
func NewDoQ(opts DoQOptions) (*DoQ, error) {
	if len(opts.Addrs) == 0 {
		return nil, errors.New("transport: doq needs at least one listen address")
	}
	if opts.TLS == nil {
		return nil, errors.New("transport: doq requires TLS")
	}
	if opts.Handler == nil {
		return nil, errors.New("transport: doq needs a handler")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.MaxIdleTimeout <= 0 {
		opts.MaxIdleTimeout = 30 * time.Second
	}
	if opts.MaxStreamsPerConn <= 0 {
		opts.MaxStreamsPerConn = 256
	}
	if opts.ClientBudget <= 0 {
		opts.ClientBudget = 5 * time.Second
	}

	tlsCfg := opts.TLS.Clone()
	tlsCfg.NextProtos = []string{ALPNDoQ}

	qc := &quic.Config{
		MaxIdleTimeout:        opts.MaxIdleTimeout,
		MaxIncomingStreams:    opts.MaxStreamsPerConn,
		MaxIncomingUniStreams: -1, // DoQ uses bidirectional streams only.
		// 0-RTT is left off. Its data can be replayed by anyone who captured
		// it, and RFC 9250 §4.4 puts the burden of tolerating that on the
		// server. A resolver gains a round trip and takes on a replay problem.
		Allow0RTT: false,
	}

	d := &DoQ{opts: opts}
	for _, ap := range opts.Addrs {
		pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
		if err != nil {
			_ = d.Close()
			return nil, fmt.Errorf("binding doq %s: %w", ap, err)
		}
		ln, err := quic.Listen(pc, tlsCfg, qc)
		if err != nil {
			_ = pc.Close()
			_ = d.Close()
			return nil, fmt.Errorf("starting quic on %s: %w", ap, err)
		}
		d.conns = append(d.conns, pc)
		d.listeners = append(d.listeners, ln)
	}
	return d, nil
}

// Addrs reports the bound addresses.
func (d *DoQ) Addrs() []string {
	out := make([]string, 0, len(d.listeners))
	for _, l := range d.listeners {
		out = append(out, l.Addr().String())
	}
	return out
}

// Serve accepts connections until ctx is cancelled.
func (d *DoQ) Serve(ctx context.Context) error {
	d.opts.Log.Info("doq listeners started",
		slog.Any("addrs", d.Addrs()),
		slog.Duration("idle_timeout", d.opts.MaxIdleTimeout),
		slog.Int64("max_streams_per_conn", d.opts.MaxStreamsPerConn))

	errCh := make(chan error, len(d.listeners))
	for _, ln := range d.listeners {
		d.wg.Add(1)
		go func(ln *quic.Listener) {
			defer d.wg.Done()
			errCh <- d.accept(ctx, ln)
		}(ln)
	}

	select {
	case <-ctx.Done():
		_ = d.Close()
		d.wg.Wait()
		return nil
	case err := <-errCh:
		_ = d.Close()
		return err
	}
}

func (d *DoQ) accept(ctx context.Context, ln *quic.Listener) error {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			return err
		}

		remote, ok := addrPortOf(conn.RemoteAddr())
		if ok && d.opts.AllowQuery != nil && !d.opts.AllowQuery.Allows(remote.Addr()) {
			// Refused after the handshake rather than before it: QUIC has no
			// earlier point to refuse at, and the cost is one handshake.
			d.opts.Metrics.DoQRefused.Add(1)
			_ = conn.CloseWithError(doqNoError, "not permitted by allow_query")
			continue
		}

		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.serveConn(ctx, conn)
		}()
	}
}

// serveConn reads queries from a connection's streams until it goes away.
func (d *DoQ) serveConn(ctx context.Context, conn *quic.Conn) {
	defer func() { _ = conn.CloseWithError(doqNoError, "") }()

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.serveStream(ctx, conn, stream)
		}()
	}
}

// serveStream answers one query.
//
// RFC 9250 §4.2: one query and its response per bidirectional stream, each
// prefixed with a two-octet length as over TCP, and the server closes the
// stream when the response is sent.
func (d *DoQ) serveStream(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
	m := d.opts.Metrics
	received := time.Now()

	defer func() {
		if r := recover(); r != nil {
			m.Panics.Add(1)
			d.opts.Log.Error("panic in doq handler",
				slog.Any("panic", r), slog.String("stack", string(stack())))
			stream.CancelWrite(quic.StreamErrorCode(doqInternalError))
		}
		_ = stream.Close()
	}()

	if err := stream.SetReadDeadline(received.Add(d.opts.ClientBudget)); err != nil {
		return
	}

	query, err := readPrefixed(stream)
	if err != nil {
		m.ParseErrors.Add(1)
		stream.CancelRead(quic.StreamErrorCode(doqProtocolError))
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(query); err != nil {
		m.ParseErrors.Add(1)
		stream.CancelRead(quic.StreamErrorCode(doqProtocolError))
		return
	}
	if req.Response || len(req.Question) != 1 {
		m.ParseErrors.Add(1)
		stream.CancelRead(quic.StreamErrorCode(doqProtocolError))
		return
	}

	// RFC 9250 §4.2.1: the message ID must be zero, because a stream carries
	// exactly one exchange and there is nothing to correlate. A non-zero ID
	// means the client is treating this as TCP, and answering anyway would
	// invite an implementation that multiplexes on one stream.
	if req.Id != 0 {
		m.ParseErrors.Add(1)
		_ = conn.CloseWithError(doqProtocolError, "DNS message ID must be 0 over DoQ")
		return
	}
	// §5.5.2: the EDNS TCP Keepalive option is meaningless here and its
	// presence is a protocol error, since QUIC has its own idle timeout.
	if opt := req.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if o.Option() == dns.EDNS0TCPKEEPALIVE {
				m.ParseErrors.Add(1)
				_ = conn.CloseWithError(doqProtocolError, "edns-tcp-keepalive is not allowed over DoQ")
				return
			}
		}
	}

	m.Queries.Add(1)

	local, _ := addrPortOf(conn.LocalAddr())
	remote, _ := addrPortOf(conn.RemoteAddr())

	qctx, cancel := context.WithDeadline(ctx, received.Add(d.opts.ClientBudget))
	defer cancel()

	resp := d.opts.Handler.ServeDNS(qctx, &Request{
		Msg:      req,
		Client:   remote,
		Local:    local.Addr(),
		Proto:    ProtoDoQ,
		Received: received,
		// QUIC frames the response itself, so there is no 512-byte ceiling and
		// nothing to truncate against.
		MaxResponseSize: dns.MaxMsgSize,
	})
	if resp == nil {
		m.Dropped.Add(1)
		return
	}
	// The response carries the ID it was asked with, which is zero.
	resp.Id = req.Id

	out, err := resp.Pack()
	if err != nil {
		m.WriteErrors.Add(1)
		stream.CancelWrite(quic.StreamErrorCode(doqInternalError))
		return
	}
	if err := stream.SetWriteDeadline(time.Now().Add(d.opts.ClientBudget)); err != nil {
		return
	}
	if err := writePrefixed(stream, out); err != nil {
		m.WriteErrors.Add(1)
	}
}

// readPrefixed reads one two-octet length-prefixed message.
func readPrefixed(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return nil, errors.New("transport: zero-length doq message")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writePrefixed writes one two-octet length-prefixed message.
func writePrefixed(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return fmt.Errorf("transport: doq response is %d bytes", len(msg))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// Close stops the listeners.
func (d *DoQ) Close() error {
	d.closeOnce.Do(func() {
		for _, l := range d.listeners {
			_ = l.Close()
		}
		for _, c := range d.conns {
			_ = c.Close()
		}
	})
	return nil
}
