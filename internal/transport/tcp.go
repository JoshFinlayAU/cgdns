package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/netacl"
)

// TCPOptions configures the TCP listener set.
type TCPOptions struct {
	Addrs []netip.AddrPort
	// MaxConns bounds concurrent client connections across all addresses, the
	// main guard against slow-loris style exhaustion.
	MaxConns int
	// IdleTimeout closes a connection that has gone quiet. RFC 7766 §6.2.3
	// expects a resolver to reclaim idle connections.
	IdleTimeout time.Duration
	// ClientBudget is the total wall-clock allowed per client query.
	ClientBudget time.Duration

	// AllowQuery restricts who may query. See UDPOptions.AllowQuery.
	AllowQuery *netacl.ACL

	// TLS, when set, wraps every accepted connection, making this a DoT
	// listener (RFC 7858). The framing is identical to plain TCP DNS, so the
	// only difference is the handshake and the protocol label on the request.
	TLS *tls.Config

	Handler Handler
	Log     *slog.Logger
	Metrics *Metrics
}

// TCP is a set of TCP DNS listeners.
type TCP struct {
	opts      TCPOptions
	proto     Proto
	lns       []net.Listener
	locals    []netip.Addr
	sem       chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewTCP binds every listener immediately, so a bind failure is a startup
// failure.
func NewTCP(opts TCPOptions) (*TCP, error) {
	if opts.Handler == nil {
		return nil, errors.New("transport: TCPOptions.Handler is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = 4096
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 10 * time.Second
	}
	if opts.ClientBudget <= 0 {
		opts.ClientBudget = 5 * time.Second
	}

	t := &TCP{opts: opts, proto: ProtoTCP, sem: make(chan struct{}, opts.MaxConns)}
	if opts.TLS != nil {
		t.proto = ProtoDoT
	}

	lc := net.ListenConfig{Control: reusePortControl}
	for _, ap := range opts.Addrs {
		network := "tcp6"
		if ap.Addr().Is4() {
			network = "tcp4"
		}
		ln, err := lc.Listen(context.Background(), network, ap.String())
		if err != nil {
			t.closeListeners()
			return nil, fmt.Errorf("binding tcp %s: %w", ap, err)
		}
		if opts.TLS != nil {
			ln = tls.NewListener(ln, opts.TLS)
		}
		t.lns = append(t.lns, ln)
		t.locals = append(t.locals, ap.Addr())
	}
	if len(t.lns) == 0 {
		return nil, errors.New("transport: no TCP addresses configured")
	}
	return t, nil
}

// LocalAddrs reports the bound addresses.
func (t *TCP) LocalAddrs() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(t.lns))
	for _, ln := range t.lns {
		if ap, ok := addrPortOf(ln.Addr()); ok {
			out = append(out, ap)
		}
	}
	return out
}

// Serve runs until ctx is cancelled.
func (t *TCP) Serve(ctx context.Context) error {
	for i, ln := range t.lns {
		t.wg.Add(1)
		go func(ln net.Listener, local netip.Addr) {
			defer t.wg.Done()
			t.acceptLoop(ctx, ln, local)
		}(ln, t.locals[i])
	}

	t.opts.Log.Info("stream listeners started",
		slog.String("proto", t.proto.String()),
		slog.Int("listeners", len(t.lns)),
		slog.Int("max_conns", t.opts.MaxConns))

	<-ctx.Done()
	t.closeListeners()
	t.wg.Wait()
	return nil
}

// Close stops the listeners. Safe to call more than once.
func (t *TCP) Close() error {
	t.closeListeners()
	return nil
}

func (t *TCP) closeListeners() {
	t.closeOnce.Do(func() {
		for _, ln := range t.lns {
			if ln != nil {
				_ = ln.Close()
			}
		}
	})
}

func (t *TCP) acceptLoop(ctx context.Context, ln net.Listener, local netip.Addr) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			t.opts.Log.Debug("tcp accept error", slog.String("err", err.Error()))
			continue
		}

		from, _ := addrPortOf(c.RemoteAddr())
		if t.opts.AllowQuery != nil && !t.opts.AllowQuery.Allows(from.Addr()) {
			t.opts.Metrics.TCPRefused.Add(1)
			_ = c.Close()
			continue
		}

		select {
		case t.sem <- struct{}{}:
		default:
			t.opts.Metrics.TCPRefused.Add(1)
			_ = c.Close()
			continue
		}

		t.opts.Metrics.TCPAccepted.Add(1)
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			defer func() { <-t.sem }()
			t.serveConn(ctx, c, local, from)
		}()
	}
}

// serveConn handles queries on one connection until it goes idle or errors.
// Queries are handled one at a time; RFC 7766 §6.2.1.1 also permits
// out-of-order pipelined responses.
func (t *TCP) serveConn(ctx context.Context, c net.Conn, local netip.Addr, from netip.AddrPort) {
	defer func() { _ = c.Close() }()

	co := &dns.Conn{Conn: c}
	for {
		if ctx.Err() != nil {
			return
		}
		if err := c.SetReadDeadline(time.Now().Add(t.opts.IdleTimeout)); err != nil {
			return
		}

		req, err := co.ReadMsg()
		received := time.Now()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				t.opts.Metrics.ParseErrors.Add(1)
			}
			return
		}
		if req.Response || len(req.Question) != 1 {
			t.opts.Metrics.ParseErrors.Add(1)
			return
		}
		t.opts.Metrics.Queries.Add(1)

		resp := t.dispatch(ctx, req, from, local, received)
		if resp == nil {
			continue
		}
		if err := c.SetWriteDeadline(time.Now().Add(t.opts.IdleTimeout)); err != nil {
			return
		}
		if err := co.WriteMsg(resp); err != nil {
			t.opts.Metrics.WriteErrors.Add(1)
			return
		}
	}
}

func (t *TCP) dispatch(ctx context.Context, req *dns.Msg, from netip.AddrPort, local netip.Addr, received time.Time) (resp *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			t.opts.Metrics.Panics.Add(1)
			t.opts.Log.Error("panic in tcp handler",
				slog.Any("panic", r),
				slog.String("proto", t.proto.String()),
				slog.String("stack", string(stack())))
			resp = errorResponse(req, dns.RcodeServerFailure)
		}
	}()

	deadline := received.Add(t.opts.ClientBudget)
	qctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	return t.opts.Handler.ServeDNS(qctx, &Request{
		Msg:             req,
		Client:          from,
		Local:           local,
		Proto:           t.proto,
		Received:        received,
		MaxResponseSize: dns.MaxMsgSize,
	})
}

func addrPortOf(a net.Addr) (netip.AddrPort, bool) {
	if ta, ok := a.(*net.TCPAddr); ok {
		if ap, ok := netip.AddrFromSlice(ta.IP); ok {
			return netip.AddrPortFrom(ap.Unmap(), uint16(ta.Port)), true
		}
	}
	// QUIC connections report a UDP address.
	if ua, ok := a.(*net.UDPAddr); ok {
		if ap, ok := netip.AddrFromSlice(ua.IP); ok {
			return netip.AddrPortFrom(ap.Unmap(), uint16(ua.Port)), true
		}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}
