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

// Client is the outbound half of the pair link.
//
// One connection is held open to the sibling and reused. Requests are
// serialised over it, because the protocol is request/response and a pair link
// carries nothing like the volume that would justify multiplexing.
type Client struct {
	opts ClientOptions

	mu   sync.Mutex
	conn net.Conn

	connected atomic.Bool
	closed    atomic.Bool

	pushMu    sync.Mutex
	pushQueue [][]byte
}

// ClientOptions configures the outbound half.
type ClientOptions struct {
	NodeID string
	// Addr is the sibling's pair-link address.
	Addr string
	TLS  *tls.Config

	// Timeout bounds a config request.
	Timeout time.Duration
	// FetchTimeout bounds a cache fetch, which sits directly on the query
	// path. It is deliberately far shorter than Timeout: going upstream costs
	// tens of milliseconds, so waiting longer than that for the sibling makes
	// the pair link a pessimisation.
	FetchTimeout time.Duration
	// PushInterval is how often queued cache entries are flushed.
	PushInterval time.Duration
	// PushBatch caps entries per flush.
	PushBatch int
	// QueueLimit caps queued entries. Beyond it the oldest are dropped: cache
	// sharing is best-effort, and memory pressure here would be self-inflicted.
	QueueLimit int
	// SyncInterval is how often config anti-entropy runs.
	SyncInterval time.Duration

	Store *control.Store

	Log     *slog.Logger
	Metrics *Metrics
}

// NewClient builds the outbound half. It does not dial; Run does.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.NodeID == "" {
		return nil, errors.New("peer: node ID is required")
	}
	if opts.Addr == "" {
		return nil, errors.New("peer: peer address is required")
	}
	if opts.TLS == nil {
		return nil, errors.New("peer: TLS is required on the pair link")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.FetchTimeout <= 0 {
		opts.FetchTimeout = 150 * time.Millisecond
	}
	if opts.PushInterval <= 0 {
		opts.PushInterval = 200 * time.Millisecond
	}
	if opts.PushBatch <= 0 {
		opts.PushBatch = 256
	}
	if opts.QueueLimit <= 0 {
		opts.QueueLimit = 4096
	}
	if opts.SyncInterval <= 0 {
		opts.SyncInterval = 30 * time.Second
	}
	return &Client{opts: opts}, nil
}

// Connected reports whether the outbound link is up.
func (c *Client) Connected() bool { return c.connected.Load() }

// Run maintains the connection, flushes queued pushes and runs config sync.
func (c *Client) Run(ctx context.Context) error {
	push := time.NewTicker(c.opts.PushInterval)
	defer push.Stop()
	sync := time.NewTicker(c.opts.SyncInterval)
	defer sync.Stop()
	redial := time.NewTicker(2 * time.Second)
	defer redial.Stop()

	for {
		select {
		case <-ctx.Done():
			c.closed.Store(true)
			c.dropConn()
			return nil
		case <-redial.C:
			if !c.connected.Load() {
				if err := c.dial(ctx); err == nil {
					// A fresh connection means the peer may have been away, so
					// reconcile config before anything else.
					c.Sync(ctx)
				}
			}
		case <-push.C:
			c.flushPushes(ctx)
		case <-sync.C:
			c.Sync(ctx)
		}
	}
}

func (c *Client) dial(ctx context.Context) error {
	d := &net.Dialer{Timeout: c.opts.Timeout}
	raw, err := d.DialContext(ctx, "tcp", c.opts.Addr)
	if err != nil {
		return err
	}
	conn := tls.Client(raw, c.opts.TLS)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		_ = conn.Close()
		return err
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return err
	}

	if err := writeJSON(conn, MsgHello, Hello{Version: ProtocolVersion, NodeID: c.opts.NodeID}); err != nil {
		_ = conn.Close()
		return err
	}
	t, payload, err := readFrame(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	if t != MsgHello {
		_ = conn.Close()
		return fmt.Errorf("peer: expected hello, got %s", t)
	}
	var h Hello
	if err := json.Unmarshal(payload, &h); err != nil {
		_ = conn.Close()
		return err
	}
	if h.Version != ProtocolVersion {
		_ = conn.Close()
		return fmt.Errorf("peer: sibling speaks protocol %d, this build speaks %d", h.Version, ProtocolVersion)
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	c.connected.Store(true)
	c.opts.Metrics.Connects.Add(1)
	c.opts.Log.Info("pair link up", slog.String("peer", h.NodeID), slog.String("addr", c.opts.Addr))
	return nil
}

func (c *Client) dropConn() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	if c.connected.Swap(false) {
		c.opts.Metrics.Disconnects.Add(1)
		c.opts.Log.Warn("pair link down", slog.String("addr", c.opts.Addr))
	}
}

// request sends one frame and reads the reply, holding the connection lock.
func (c *Client) request(t MsgType, payload []byte) (MsgType, []byte, error) {
	return c.requestWithin(t, payload, c.opts.Timeout)
}

func (c *Client) requestWithin(t MsgType, payload []byte, timeout time.Duration) (MsgType, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return 0, nil, ErrPeerClosed
	}
	deadline := time.Now().Add(timeout)
	if err := c.conn.SetDeadline(deadline); err != nil {
		return 0, nil, err
	}
	if err := writeFrame(c.conn, t, payload); err != nil {
		return 0, nil, err
	}
	return readFrame(c.conn)
}

// Fetch asks the peer for an entry. A failure is reported as a miss: the
// caller resolves it normally, which is exactly what would have happened
// without a peer at all.
func (c *Client) Fetch(k cache.Key) (cache.Entry, time.Duration, bool) {
	if !c.connected.Load() {
		return cache.Entry{}, 0, false
	}
	c.opts.Metrics.CacheFetchSent.Add(1)

	payload, err := json.Marshal(wireKey(k))
	if err != nil {
		return cache.Entry{}, 0, false
	}
	t, resp, err := c.requestWithin(MsgCacheFetch, payload, c.opts.FetchTimeout)
	if err != nil {
		c.opts.Metrics.CacheFetchErrors.Add(1)
		c.dropConn()
		return cache.Entry{}, 0, false
	}
	if t != MsgCacheHit {
		c.opts.Metrics.CacheFetchMisses.Add(1)
		return cache.Entry{}, 0, false
	}
	_, e, ttl, err := decodeEntry(resp)
	if err != nil {
		c.opts.Metrics.CacheFetchErrors.Add(1)
		return cache.Entry{}, 0, false
	}
	c.opts.Metrics.CacheFetchHits.Add(1)
	return e, ttl, true
}

// QueuePush offers an entry to the peer. It never blocks and never fails: the
// entry is dropped if the queue is full, because a full queue means the peer
// is slow or gone, and neither is worth delaying a client query for.
func (c *Client) QueuePush(k cache.Key, e cache.Entry) {
	if c.closed.Load() {
		return
	}
	blob, err := encodeEntry(k, e, time.Now())
	if err != nil {
		return
	}

	c.pushMu.Lock()
	defer c.pushMu.Unlock()
	if len(c.pushQueue) >= c.opts.QueueLimit {
		c.pushQueue = c.pushQueue[1:]
	}
	c.pushQueue = append(c.pushQueue, blob)
}

func (c *Client) flushPushes(ctx context.Context) {
	if !c.connected.Load() {
		// Drop what is queued rather than let it age: by the time the peer
		// returns these TTLs are stale, and anti-entropy does not apply to
		// cache.
		c.pushMu.Lock()
		c.pushQueue = nil
		c.pushMu.Unlock()
		return
	}

	c.pushMu.Lock()
	if len(c.pushQueue) == 0 {
		c.pushMu.Unlock()
		return
	}
	n := min(len(c.pushQueue), c.opts.PushBatch)
	batch := c.pushQueue[:n]
	c.pushQueue = c.pushQueue[n:]
	c.pushMu.Unlock()

	payload, err := json.Marshal(CachePush{Entries: batch})
	if err != nil {
		return
	}
	if _, _, err := c.request(MsgCachePush, payload); err != nil {
		c.dropConn()
		return
	}
	c.opts.Metrics.CachePushSent.Add(uint64(len(batch)))
}

// Sync runs one config anti-entropy round: send our digests, adopt whatever the
// peer says we are missing, then push whatever it is missing.
func (c *Client) Sync(ctx context.Context) {
	if !c.connected.Load() || c.opts.Store == nil {
		return
	}
	c.opts.Metrics.SyncRuns.Add(1)

	ours := c.opts.Store.Digests()
	payload, err := json.Marshal(DigestBatch{Digests: ours})
	if err != nil {
		c.opts.Metrics.SyncErrors.Add(1)
		return
	}
	t, resp, err := c.request(MsgDigests, payload)
	if err != nil {
		c.opts.Metrics.SyncErrors.Add(1)
		c.dropConn()
		return
	}
	if t != MsgRecords {
		c.opts.Metrics.SyncErrors.Add(1)
		return
	}

	var batch RecordBatch
	if err := json.Unmarshal(resp, &batch); err != nil {
		c.opts.Metrics.SyncErrors.Add(1)
		return
	}
	if adopted := c.opts.Store.Merge(batch.Records); adopted > 0 {
		c.opts.Metrics.RecordsReceived.Add(uint64(adopted))
		c.opts.Log.Info("adopted config records from the peer", slog.Int("count", adopted))
	}

	// The exchange is not symmetric: the peer answered from our digests, so it
	// still has no idea what we hold that it does not. Push that half.
	c.pushOurRecords(batch.Records)
}

// pushOurRecords sends the peer anything it is missing.
func (c *Client) pushOurRecords(theirs []control.Record) {
	digests := make([]control.Digest, 0, len(theirs))
	for _, r := range theirs {
		digests = append(digests, control.Digest{Kind: r.Kind, Key: r.Key, Lamport: r.Lamport, Origin: r.Origin})
	}

	// Ask the store what we hold that is newer than everything just received,
	// then send the peer our full set for it to filter. For a pair-sized store
	// this is cheaper than another round trip.
	ours := c.opts.Store.All()
	if len(ours) == 0 {
		return
	}
	payload, err := json.Marshal(RecordBatch{Records: ours})
	if err != nil {
		return
	}
	if _, _, err := c.request(MsgRecords, payload); err != nil {
		c.dropConn()
		return
	}
	c.opts.Metrics.RecordsSent.Add(uint64(len(ours)))
}

// Close tears the link down.
func (c *Client) Close() error {
	c.closed.Store(true)
	c.dropConn()
	return nil
}
