package transport

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"

	"github.com/JoshFinlayAU/cgdns/internal/netacl"
	"github.com/JoshFinlayAU/cgdns/internal/prefixmap"
)

// maxDoHBody caps an accepted DoH request body. A DNS message cannot exceed
// 65535 bytes, so anything larger is not a query.
const maxDoHBody = 65535

// DoHOptions configures the DoH listener set (RFC 8484).
type DoHOptions struct {
	Addrs []netip.AddrPort
	// Path is the query endpoint, conventionally /dns-query.
	Path string
	// TLS is required: DoH without TLS defeats its purpose.
	TLS *tls.Config

	MaxConns     int
	IdleTimeout  time.Duration
	ClientBudget time.Duration
	UDPSize      uint16

	AllowQuery *netacl.ACL

	// TrustedProxies are the sources whose forwarding headers may be believed.
	//
	// Behind an L7 proxy the TCP peer is the proxy, not the subscriber, so
	// without this every DoH client classifies as the proxy and gets the wrong
	// policy. Trusting the header from an untrusted source is worse: any client
	// could then spoof any subscriber's identity and inherit their filtering.
	// Empty means never believe a forwarding header.
	TrustedProxies []netip.Prefix

	Handler Handler
	Log     *slog.Logger
	Metrics *Metrics
}

// DoH serves DNS over HTTPS.
type DoH struct {
	opts    DoHOptions
	trusted *prefixmap.Map[struct{}]
	lns     []net.Listener
	srvs    []*http.Server

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewDoH binds every listener immediately, so a bind failure is a startup
// failure.
func NewDoH(opts DoHOptions) (*DoH, error) {
	if opts.Handler == nil {
		return nil, errors.New("transport: DoHOptions.Handler is required")
	}
	if opts.TLS == nil {
		return nil, errors.New("transport: DoH requires TLS")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.Path == "" {
		opts.Path = "/dns-query"
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = 4096
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 30 * time.Second
	}
	if opts.ClientBudget <= 0 {
		opts.ClientBudget = 5 * time.Second
	}

	d := &DoH{opts: opts, trusted: prefixmap.New[struct{}]()}
	for _, p := range opts.TrustedProxies {
		d.trusted.Insert(p, struct{}{})
	}

	mux := http.NewServeMux()
	mux.HandleFunc(opts.Path, d.serveHTTP)

	lc := net.ListenConfig{Control: reusePortControl}
	for _, ap := range opts.Addrs {
		network := "tcp6"
		if ap.Addr().Is4() {
			network = "tcp4"
		}
		ln, err := lc.Listen(context.Background(), network, ap.String())
		if err != nil {
			d.closeAll()
			return nil, fmt.Errorf("binding doh %s: %w", ap, err)
		}
		ln = tls.NewListener(ln, opts.TLS)
		if opts.AllowQuery != nil {
			ln = netacl.Listener(ln, opts.AllowQuery, opts.Log)
		}

		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       opts.IdleTimeout,
			ErrorLog:          nil,
		}
		if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
			d.closeAll()
			return nil, fmt.Errorf("configuring http/2 for doh %s: %w", ap, err)
		}

		d.lns = append(d.lns, ln)
		d.srvs = append(d.srvs, srv)
	}
	if len(d.lns) == 0 {
		return nil, errors.New("transport: no DoH addresses configured")
	}
	return d, nil
}

// LocalAddrs reports the bound addresses.
func (d *DoH) LocalAddrs() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(d.lns))
	for _, ln := range d.lns {
		if ap, ok := addrPortOf(ln.Addr()); ok {
			out = append(out, ap)
		}
	}
	return out
}

// Serve runs until ctx is cancelled.
func (d *DoH) Serve(ctx context.Context) error {
	for i := range d.lns {
		ln, srv := d.lns[i], d.srvs[i]
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
				d.opts.Log.Error("doh server stopped", slog.String("err", err.Error()))
			}
		}()
	}

	d.opts.Log.Info("doh listeners started",
		slog.Int("listeners", len(d.lns)),
		slog.String("path", d.opts.Path),
		slog.Int("trusted_proxies", d.trusted.Len()))

	<-ctx.Done()
	d.shutdown()
	d.wg.Wait()
	return nil
}

// Close stops the listeners. Safe to call more than once.
func (d *DoH) Close() error {
	d.shutdown()
	return nil
}

func (d *DoH) shutdown() {
	d.closeOnce.Do(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, srv := range d.srvs {
			_ = srv.Shutdown(shutCtx)
		}
	})
}

func (d *DoH) closeAll() {
	for _, ln := range d.lns {
		_ = ln.Close()
	}
}

func (d *DoH) serveHTTP(w http.ResponseWriter, r *http.Request) {
	received := time.Now()
	m := d.opts.Metrics

	raw, err := d.readQuery(r)
	if err != nil {
		m.ParseErrors.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil || req.Response || len(req.Question) != 1 {
		m.ParseErrors.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	m.Queries.Add(1)

	client := d.clientAddr(r)
	if d.opts.AllowQuery != nil && !d.opts.AllowQuery.Allows(client.Addr()) {
		d.write(w, refusedResponse(req), received)
		return
	}

	local, _ := addrPortOf(localAddrOf(r))
	resp := d.dispatch(r.Context(), req, client, local.Addr(), received)
	if resp == nil {
		http.Error(w, "no response", http.StatusInternalServerError)
		return
	}
	d.write(w, resp, received)
}

// readQuery extracts the wire-format query from a GET or POST (RFC 8484 §4.1).
func (d *DoH) readQuery(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			return nil, errors.New("missing dns parameter")
		}
		// base64url without padding.
		raw, err := base64.RawURLEncoding.DecodeString(q)
		if err != nil {
			return nil, err
		}
		if len(raw) > maxDoHBody {
			return nil, errors.New("query too large")
		}
		return raw, nil

	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			return nil, fmt.Errorf("unsupported content type %q", ct)
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxDoHBody+1))
		if err != nil {
			return nil, err
		}
		if len(raw) > maxDoHBody {
			return nil, errors.New("body too large")
		}
		return raw, nil

	default:
		return nil, fmt.Errorf("method %s not allowed", r.Method)
	}
}

// clientAddr resolves the subscriber's address.
//
// The transport peer wins unless it is a configured trusted proxy, in which
// case the forwarding header is believed. An untrusted client's headers are
// ignored entirely — honouring them would let anyone claim any subscriber's
// identity and inherit their policy.
func (d *DoH) clientAddr(r *http.Request) netip.AddrPort {
	peer, ok := addrPortOf2(r.RemoteAddr)
	if !ok {
		return netip.AddrPort{}
	}
	if d.trusted.Len() == 0 || !d.trusted.Contains(peer.Addr()) {
		return peer
	}
	if fwd := forwardedFor(r); fwd.IsValid() {
		return netip.AddrPortFrom(fwd, 0)
	}
	return peer
}

func forwardedFor(r *http.Request) netip.Addr {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		// The left-most entry is the original client.
		for i := 0; i < len(v); i++ {
			if v[i] == ',' {
				v = v[:i]
				break
			}
		}
		if a, err := netip.ParseAddr(trimSpace(v)); err == nil {
			return a.Unmap()
		}
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		if a, err := netip.ParseAddr(trimSpace(v)); err == nil {
			return a.Unmap()
		}
	}
	return netip.Addr{}
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func localAddrOf(r *http.Request) net.Addr {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		return a
	}
	return &net.TCPAddr{}
}

func (d *DoH) dispatch(ctx context.Context, req *dns.Msg, client netip.AddrPort, local netip.Addr, received time.Time) (resp *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			d.opts.Metrics.Panics.Add(1)
			d.opts.Log.Error("panic in doh handler",
				slog.Any("panic", r),
				slog.String("proto", "doh"),
				slog.String("stack", string(stack())))
			resp = errorResponse(req, dns.RcodeServerFailure)
		}
	}()

	qctx, cancel := context.WithDeadline(ctx, received.Add(d.opts.ClientBudget))
	defer cancel()

	return d.opts.Handler.ServeDNS(qctx, &Request{
		Msg:             req,
		Client:          client,
		Local:           local,
		Proto:           ProtoDoH,
		Received:        received,
		MaxResponseSize: dns.MaxMsgSize,
	})
}

// write emits the response, setting Cache-Control from the smallest TTL so an
// HTTP cache between client and resolver cannot outlive the DNS data.
func (d *DoH) write(w http.ResponseWriter, resp *dns.Msg, received time.Time) {
	packed, err := resp.Pack()
	if err != nil {
		d.opts.Metrics.WriteErrors.Add(1)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", strconv.Itoa(len(packed)))
	w.Header().Set("Cache-Control", "max-age="+strconv.FormatUint(uint64(minTTL(resp)), 10))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(packed); err != nil {
		d.opts.Metrics.WriteErrors.Add(1)
	}
}

// minTTL returns the smallest TTL in a response, or zero when it carries none.
func minTTL(resp *dns.Msg) uint32 {
	var (
		min   uint32
		found bool
	)
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			ttl := rr.Header().Ttl
			if !found || ttl < min {
				min, found = ttl, true
			}
		}
	}
	if !found {
		return 0
	}
	return min
}

func addrPortOf2(hostport string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}
