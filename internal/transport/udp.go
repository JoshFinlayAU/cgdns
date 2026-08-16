package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/netacl"
)

// UDPOptions configures the UDP listener set.
type UDPOptions struct {
	// Addrs are the explicit addresses to bind. Wildcards are rejected by
	// config validation; see the package doc for why.
	Addrs []netip.AddrPort
	// SocketsPerAddr is how many SO_REUSEPORT sockets to open per address.
	// Zero means one per CPU.
	SocketsPerAddr int
	// Workers is the number of handler goroutines per socket, sized for
	// I/O-bound resolution. Zero takes a default.
	Workers int
	// QueueDepth is the per-socket backlog before packets are dropped. Zero
	// takes a default.
	QueueDepth int

	// UDPSize is the operator's ceiling on response size, clamping whatever
	// the client advertises via EDNS0.
	UDPSize uint16
	// ClientBudget is the total wall-clock allowed per client query.
	ClientBudget time.Duration

	// AllowQuery restricts who may query. A recursive resolver reachable from
	// the internet is an amplification source.
	AllowQuery *netacl.ACL

	Handler Handler
	Log     *slog.Logger
	Metrics *Metrics
}

// UDP is a set of UDP DNS listeners.
type UDP struct {
	opts  UDPOptions
	socks []*udpSocket
	pool  sync.Pool
	wg    sync.WaitGroup

	closeOnce sync.Once
}

type udpSocket struct {
	conn  *net.UDPConn
	local netip.Addr
	queue chan *packet
}

type packet struct {
	buf      []byte
	n        int
	from     netip.AddrPort
	local    netip.Addr
	received time.Time
}

// NewUDP binds every socket immediately, so a bind failure is a startup
// failure. Anycast routes traffic to an address whether or not it is served.
func NewUDP(opts UDPOptions) (*UDP, error) {
	if opts.Handler == nil {
		return nil, errors.New("transport: UDPOptions.Handler is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.SocketsPerAddr <= 0 {
		opts.SocketsPerAddr = runtime.NumCPU()
	}
	if !reusePortSupported {
		opts.SocketsPerAddr = 1
	}
	if opts.Workers <= 0 {
		opts.Workers = 32
	}
	if opts.QueueDepth <= 0 {
		opts.QueueDepth = 1024
	}
	if opts.UDPSize == 0 {
		opts.UDPSize = 1232
	}
	if opts.ClientBudget <= 0 {
		opts.ClientBudget = 5 * time.Second
	}

	u := &UDP{opts: opts}
	u.pool.New = func() any { return &packet{buf: make([]byte, maxPacket)} }

	lc := net.ListenConfig{Control: reusePortControl}
	for _, ap := range opts.Addrs {
		for i := 0; i < opts.SocketsPerAddr; i++ {
			pc, err := lc.ListenPacket(context.Background(), networkFor(ap), ap.String())
			if err != nil {
				u.closeSockets()
				return nil, fmt.Errorf("binding udp %s (socket %d/%d): %w", ap, i+1, opts.SocketsPerAddr, err)
			}
			conn, ok := pc.(*net.UDPConn)
			if !ok {
				_ = pc.Close()
				u.closeSockets()
				return nil, fmt.Errorf("binding udp %s: unexpected conn type %T", ap, pc)
			}
			u.socks = append(u.socks, &udpSocket{
				conn:  conn,
				local: ap.Addr(),
				queue: make(chan *packet, opts.QueueDepth),
			})
		}
	}
	if len(u.socks) == 0 {
		return nil, errors.New("transport: no UDP addresses configured")
	}
	return u, nil
}

// networkFor pins the socket to one address family, keeping a v6 socket from
// accepting v4-mapped traffic so an IPv6-only path is genuinely testable.
func networkFor(ap netip.AddrPort) string {
	if ap.Addr().Is4() {
		return "udp4"
	}
	return "udp6"
}

// LocalAddrs reports the bound addresses, one per socket, so an address with
// several sockets appears more than once.
func (u *UDP) LocalAddrs() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(u.socks))
	for _, s := range u.socks {
		if ap, err := netip.ParseAddrPort(s.conn.LocalAddr().String()); err == nil {
			out = append(out, ap)
		}
	}
	return out
}

// Serve runs until ctx is cancelled, then drains and closes.
func (u *UDP) Serve(ctx context.Context) error {
	for _, s := range u.socks {
		for i := 0; i < u.opts.Workers; i++ {
			u.wg.Add(1)
			go func(s *udpSocket) {
				defer u.wg.Done()
				u.worker(ctx, s)
			}(s)
		}
		u.wg.Add(1)
		go func(s *udpSocket) {
			defer u.wg.Done()
			u.readLoop(s)
		}(s)
	}

	u.opts.Log.Info("udp listeners started",
		slog.Int("sockets", len(u.socks)),
		slog.Int("sockets_per_addr", u.opts.SocketsPerAddr),
		slog.Int("workers_per_socket", u.opts.Workers))

	<-ctx.Done()
	u.closeSockets()
	u.wg.Wait()
	return nil
}

// Close stops the listeners. Safe to call more than once.
func (u *UDP) Close() error {
	u.closeSockets()
	return nil
}

func (u *UDP) closeSockets() {
	u.closeOnce.Do(func() {
		for _, s := range u.socks {
			if s.conn != nil {
				_ = s.conn.Close()
			}
		}
	})
}

func (u *UDP) readLoop(s *udpSocket) {
	for {
		p := u.pool.Get().(*packet)
		n, from, err := s.conn.ReadFromUDPAddrPort(p.buf)
		if err != nil {
			u.pool.Put(p)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			u.opts.Log.Debug("udp read error", slog.String("err", err.Error()))
			continue
		}
		p.n = n
		p.from = from
		p.local = s.local
		p.received = time.Now()

		select {
		case s.queue <- p:
		default:
			// Queuing deeper only builds latency the client has stopped
			// waiting for; dropping is the correct response under overload.
			u.pool.Put(p)
			u.opts.Metrics.Dropped.Add(1)
		}
	}
}

func (u *UDP) worker(ctx context.Context, s *udpSocket) {
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-s.queue:
			if !ok {
				return
			}
			u.handle(ctx, s, p)
			u.pool.Put(p)
		}
	}
}

// handle processes one datagram. It never lets a panic escape: everything in
// here is driven by attacker-controlled bytes.
func (u *UDP) handle(ctx context.Context, s *udpSocket, p *packet) {
	m := u.opts.Metrics
	m.Queries.Add(1)

	req := new(dns.Msg)
	if err := req.Unpack(p.buf[:p.n]); err != nil {
		// No reliable ID or question to answer. Replying to garbage from a
		// spoofed source would make this a reflector.
		m.ParseErrors.Add(1)
		return
	}
	if req.Response || len(req.Question) != 1 {
		m.ParseErrors.Add(1)
		return
	}

	var resp *dns.Msg
	if u.opts.AllowQuery != nil && !u.opts.AllowQuery.Allows(p.from.Addr()) {
		resp = refusedResponse(req)
	} else {
		resp = u.dispatch(ctx, req, p)
	}
	if resp == nil {
		return
	}

	size := responseSizeFor(req, ProtoUDP, u.opts.UDPSize)
	if resp.Len() > size {
		resp.Truncate(size)
		m.Truncated.Add(1)
	}

	out, err := resp.Pack()
	if err != nil {
		m.WriteErrors.Add(1)
		u.opts.Log.Warn("packing udp response failed", slog.String("err", err.Error()))
		return
	}
	if _, err := s.conn.WriteToUDPAddrPort(out, p.from); err != nil {
		m.WriteErrors.Add(1)
	}
}

// dispatch calls the handler under a recover and a deadline.
func (u *UDP) dispatch(ctx context.Context, req *dns.Msg, p *packet) (resp *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			u.opts.Metrics.Panics.Add(1)
			u.opts.Log.Error("panic in udp handler",
				slog.Any("panic", r),
				slog.String("proto", "udp"),
				slog.String("stack", string(stack())))
			resp = errorResponse(req, dns.RcodeServerFailure)
		}
	}()

	deadline := p.received.Add(u.opts.ClientBudget)
	if !time.Now().Before(deadline) {
		u.opts.Metrics.Dropped.Add(1)
		return nil
	}
	qctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	return u.opts.Handler.ServeDNS(qctx, &Request{
		Msg:             req,
		Client:          p.from,
		Local:           p.local,
		Proto:           ProtoUDP,
		Received:        p.received,
		MaxResponseSize: responseSizeFor(req, ProtoUDP, u.opts.UDPSize),
	})
}

func stack() []byte {
	b := make([]byte, 8192)
	return b[:runtime.Stack(b, false)]
}
