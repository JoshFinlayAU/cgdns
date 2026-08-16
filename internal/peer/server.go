package peer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/control"
)

// Metrics counts pair-link activity.
type Metrics struct {
	CachePushSent     atomic.Uint64
	CachePushReceived atomic.Uint64
	CacheFetchSent    atomic.Uint64
	CacheFetchHits    atomic.Uint64
	CacheFetchMisses  atomic.Uint64
	CacheFetchErrors  atomic.Uint64
	RecordsSent       atomic.Uint64
	RecordsReceived   atomic.Uint64
	SyncRuns          atomic.Uint64
	SyncErrors        atomic.Uint64
	Connects          atomic.Uint64
	Disconnects       atomic.Uint64
	Rejected          atomic.Uint64
}

// Server answers requests from the sibling node.
type Server struct {
	opts ServerOptions
	ln   net.Listener

	wg        sync.WaitGroup
	closeOnce sync.Once

	// active counts attached peers rather than flagging one, because a
	// reconnect overlaps: the old connection lingers until its idle timeout
	// while the replacement is already serving. A bool would be cleared by the
	// dying connection and report the live one as down.
	active atomic.Int64

	// Established connections are tracked so Close drops them too. Closing
	// only the listener would leave the peer believing the link is up until
	// its idle timeout, delaying its failover by minutes.
	connMu sync.Mutex
	conns  map[net.Conn]struct{}
}

// ServerOptions configures the inbound half of the pair link.
type ServerOptions struct {
	// NodeID identifies this node in the handshake.
	NodeID string
	// Addr is the pair-link listen address, on the pair VLAN.
	Addr string
	// TLS must require and verify a client certificate: the peer is trusted to
	// insert into this node's cache, so an unauthenticated peer could poison it.
	TLS *tls.Config

	// Cache receives pushed entries and answers fetches.
	Cache *cache.Cache
	// Store receives replicated config records.
	Store *control.Store

	// IdleTimeout closes a connection that has gone quiet.
	IdleTimeout time.Duration

	Log     *slog.Logger
	Metrics *Metrics
}

// NewServer binds the pair-link listener.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.NodeID == "" {
		return nil, errors.New("peer: node ID is required")
	}
	if opts.Addr == "" {
		return nil, errors.New("peer: listen address is required")
	}
	if opts.TLS == nil {
		return nil, errors.New("peer: TLS is required on the pair link")
	}
	if opts.TLS.ClientAuth != tls.RequireAndVerifyClientCert {
		return nil, errors.New("peer: the pair link must require and verify a client certificate")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 2 * time.Minute
	}

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("binding pair link %s: %w", opts.Addr, err)
	}
	return &Server{
		opts:  opts,
		ln:    tls.NewListener(ln, opts.TLS),
		conns: map[net.Conn]struct{}{},
	}, nil
}

// Addr reports the bound address.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Connected reports whether a peer is currently attached.
func (s *Server) Connected() bool { return s.active.Load() > 0 }

// Serve accepts peer connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	s.opts.Log.Info("pair link listening", slog.String("addr", s.Addr()))

	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			s.opts.Log.Debug("pair link accept failed", slog.String("err", err.Error()))
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

// Close stops the listener and drops established connections.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		_ = s.ln.Close()
		s.connMu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.conns = map[net.Conn]struct{}{}
		s.connMu.Unlock()
	})
	return nil
}

func (s *Server) track(c net.Conn) {
	s.connMu.Lock()
	s.conns[c] = struct{}{}
	s.connMu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.connMu.Lock()
	delete(s.conns, c)
	s.connMu.Unlock()
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	s.track(conn)
	defer func() {
		s.untrack(conn)
		_ = conn.Close()
	}()

	remote := conn.RemoteAddr().String()
	if err := s.handshake(conn); err != nil {
		s.opts.Metrics.Rejected.Add(1)
		s.opts.Log.Warn("pair link handshake refused",
			slog.String("remote", remote), slog.String("err", err.Error()))
		return
	}

	s.opts.Metrics.Connects.Add(1)
	s.active.Add(1)
	s.opts.Log.Info("pair link established", slog.String("remote", remote))
	defer func() {
		s.active.Add(-1)
		s.opts.Metrics.Disconnects.Add(1)
		s.opts.Log.Info("pair link closed", slog.String("remote", remote))
	}()

	for {
		if ctx.Err() != nil {
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout)); err != nil {
			return
		}
		t, payload, err := readFrame(conn)
		if err != nil {
			if !errors.Is(err, ErrPeerClosed) && ctx.Err() == nil {
				s.opts.Log.Debug("pair link read failed", slog.String("err", err.Error()))
			}
			return
		}
		if err := conn.SetWriteDeadline(time.Now().Add(s.opts.IdleTimeout)); err != nil {
			return
		}
		if err := s.dispatch(conn, t, payload); err != nil {
			s.opts.Log.Debug("pair link request failed",
				slog.String("type", t.String()), slog.String("err", err.Error()))
			return
		}
	}
}

// handshake exchanges identity and refuses a version this build cannot speak.
func (s *Server) handshake(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	t, payload, err := readFrame(conn)
	if err != nil {
		return err
	}
	if t != MsgHello {
		return fmt.Errorf("expected hello, got %s", t)
	}
	var h Hello
	if err := json.Unmarshal(payload, &h); err != nil {
		return fmt.Errorf("decoding hello: %w", err)
	}
	if h.Version != ProtocolVersion {
		return fmt.Errorf("peer speaks protocol %d, this build speaks %d", h.Version, ProtocolVersion)
	}
	if h.NodeID == s.opts.NodeID {
		// Both halves of a pair sharing an ID would make the Lamport tiebreak
		// meaningless and let a node replicate with itself.
		return fmt.Errorf("peer announces this node's own ID %q", h.NodeID)
	}
	return writeJSON(conn, MsgHello, Hello{Version: ProtocolVersion, NodeID: s.opts.NodeID})
}

func (s *Server) dispatch(conn net.Conn, t MsgType, payload []byte) error {
	switch t {
	case MsgCacheFetch:
		return s.serveCacheFetch(conn, payload)
	case MsgCachePush:
		return s.serveCachePush(conn, payload)
	case MsgDigests:
		return s.serveDigests(conn, payload)
	case MsgRecords:
		return s.serveRecords(conn, payload)
	default:
		return writeJSON(conn, MsgError, map[string]string{"error": "unsupported message " + t.String()})
	}
}

// serveCacheFetch answers from cache only. It must never resolve on the peer's
// behalf: that would double the upstream work for one client query and add a
// pair-link round trip to the latency of doing it.
func (s *Server) serveCacheFetch(conn net.Conn, payload []byte) error {
	var w CacheKeyWire
	if err := json.Unmarshal(payload, &w); err != nil {
		return err
	}
	entry, ok := s.opts.Cache.Get(w.key())
	if !ok {
		s.opts.Metrics.CacheFetchMisses.Add(1)
		return writeFrame(conn, MsgCacheMiss, nil)
	}
	blob, err := encodeEntry(w.key(), entry, time.Now())
	if err != nil {
		return writeFrame(conn, MsgCacheMiss, nil)
	}
	s.opts.Metrics.CacheFetchHits.Add(1)
	return writeFrame(conn, MsgCacheHit, blob)
}

func (s *Server) serveCachePush(conn net.Conn, payload []byte) error {
	var push CachePush
	if err := json.Unmarshal(payload, &push); err != nil {
		return err
	}
	for _, blob := range push.Entries {
		k, e, ttl, err := decodeEntry(blob)
		if err != nil {
			// One malformed entry does not poison the batch or drop the link.
			continue
		}
		s.opts.Cache.Put(k, e, ttl)
		s.opts.Metrics.CachePushReceived.Add(1)
	}
	return writeFrame(conn, MsgOK, nil)
}

// serveDigests answers an anti-entropy probe with everything the peer's
// digests show it is missing or holding an older version of.
func (s *Server) serveDigests(conn net.Conn, payload []byte) error {
	var batch DigestBatch
	if err := json.Unmarshal(payload, &batch); err != nil {
		return err
	}
	missing := s.opts.Store.Missing(batch.Digests)
	s.opts.Metrics.RecordsSent.Add(uint64(len(missing)))
	return writeJSON(conn, MsgRecords, RecordBatch{Records: missing})
}

func (s *Server) serveRecords(conn net.Conn, payload []byte) error {
	var batch RecordBatch
	if err := json.Unmarshal(payload, &batch); err != nil {
		return err
	}
	adopted := s.opts.Store.Merge(batch.Records)
	s.opts.Metrics.RecordsReceived.Add(uint64(adopted))
	if adopted > 0 {
		s.opts.Log.Info("adopted config records from the peer", slog.Int("count", adopted))
	}
	return writeFrame(conn, MsgOK, nil)
}
