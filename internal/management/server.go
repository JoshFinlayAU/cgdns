package management

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/control"
	"github.com/JoshFinlayAU/cgdns/internal/netacl"
)

// Server exposes the operator API — and, when enabled, the WebUI — on the
// management addresses and nowhere else.
//
// That is the whole point of this type: there is exactly one listener path for
// the admin plane, so enabling the UI can never quietly add a second one. The
// config layer refuses a wildcard bind, refuses an address shared with a DNS
// listener, and refuses anything inside an anycast prefix; this type refuses a
// non-loopback bind without TLS and filters every connection at accept.
type Server struct {
	opts      ServerOptions
	http      *http.Server
	listeners []net.Listener

	mu     sync.Mutex
	closed bool
}

// ServerOptions configures the management listener.
type ServerOptions struct {
	// Listen holds the management addresses. Each is bound separately: a
	// wildcard bind would put the admin plane on the anycast address, which is
	// the one thing this plane must never be reachable from.
	Listen []string

	// TLS is required unless every listen address is loopback.
	TLS *tls.Config

	// ACL is the default-deny source filter, enforced at Accept so a refused
	// client never reaches TLS or HTTP.
	ACL *netacl.ACL

	Handler http.Handler
	Log     *slog.Logger

	// ReadTimeout and WriteTimeout bound a slow client.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// NewServer binds the management listeners.
func NewServer(opts ServerOptions) (*Server, error) {
	if len(opts.Listen) == 0 {
		return nil, errors.New("management: at least one listen address is required")
	}
	if opts.Handler == nil {
		return nil, errors.New("management: a handler is required")
	}
	if opts.ACL == nil {
		return nil, errors.New("management: a source ACL is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = 15 * time.Second
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 30 * time.Second
	}

	s := &Server{
		opts: opts,
		http: &http.Server{
			Handler:           opts.Handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       opts.ReadTimeout,
			WriteTimeout:      opts.WriteTimeout,
			ErrorLog:          nil,
		},
	}

	for _, addr := range opts.Listen {
		if err := s.bind(addr); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	return s, nil
}

func (s *Server) bind(addr string) error {
	loopback, err := isLoopback(addr)
	if err != nil {
		return err
	}
	if s.opts.TLS == nil && !loopback {
		// Enforced in config validation too, but a plaintext admin plane on a
		// routable address is bad enough to refuse twice.
		return fmt.Errorf("management: %s is not loopback and has no TLS", addr)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("binding management %s: %w", addr, err)
	}
	ln = netacl.Listener(ln, s.opts.ACL, s.opts.Log)
	if s.opts.TLS != nil {
		ln = tls.NewListener(ln, s.opts.TLS)
	}

	s.listeners = append(s.listeners, ln)
	s.opts.Log.Info("management listening",
		slog.String("addr", ln.Addr().String()),
		slog.Bool("tls", s.opts.TLS != nil),
		slog.Int("acl_prefixes", s.opts.ACL.Len()))
	return nil
}

func isLoopback(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, fmt.Errorf("management: parsing listen address %q: %w", addr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false, fmt.Errorf("management: listen address %q is not an IP", addr)
	}
	return ip.IsLoopback(), nil
}

// Addrs reports the bound addresses.
func (s *Server) Addrs() []string {
	out := make([]string, 0, len(s.listeners))
	for _, ln := range s.listeners {
		out = append(out, ln.Addr().String())
	}
	return out
}

// Serve accepts until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	errs := make(chan error, len(s.listeners))
	for _, ln := range s.listeners {
		go func(ln net.Listener) {
			err := s.http.Serve(ln)
			if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
				err = nil
			}
			errs <- err
		}(ln)
	}

	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shutdown)
		_ = s.Close()
		return nil
	case err := <-errs:
		return err
	}
}

// Close stops the listeners.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	return nil
}

// Bootstrap mints a first admin token when the node has none, writing the
// secret to path.
//
// A node with no token has no way to be managed, and the alternatives are worse:
// a default credential is a permanent hole, and a manual out-of-band step is
// the sort of thing that gets skipped. The secret lands in a root-only file the
// operator is expected to read once and remove.
//
// A node that has a token — including one adopted from its sibling — does
// nothing here, so a rejoining node does not mint a second credential.
func Bootstrap(store *control.Store, path string, now time.Time, log *slog.Logger) error {
	if path == "" {
		return nil
	}
	if HasTokens(store) {
		return nil
	}

	t, secret, err := Mint("bootstrap", []Scope{ScopeAdmin}, 0, now)
	if err != nil {
		return fmt.Errorf("management: minting the bootstrap token: %w", err)
	}
	if err := SaveToken(store, t); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("management: creating the bootstrap token directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		return fmt.Errorf("management: writing the bootstrap token to %s: %w", path, err)
	}

	log.Warn("no API token existed, so a bootstrap admin token was minted",
		slog.String("id", t.ID), slog.String("file", path),
		slog.String("action", "read it once, then delete the file"))
	return nil
}
