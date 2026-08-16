// Package peer implements the link between the two resolvers in a POP.
//
// It carries two payloads with deliberately different guarantees, over one
// mutually authenticated TLS connection:
//
//   - **Config replication** is reliable and converging. Losing a config
//     update is a bug, so records are acknowledged and any gap is repaired by
//     an anti-entropy exchange when the link returns.
//   - **Cache sharing** is best-effort. Losing a cache push is a cache miss,
//     which the peer resolves for itself; it is never worth blocking a query
//     or holding memory to retry one.
//
// Cache sharing is strictly within a POP. Cloud and CDN authoritatives answer
// on where the resolver sits, so replicating an entry between POPs would serve
// one region's endpoints to another.
package peer

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/control"
)

// ProtocolVersion is the wire version. A peer announcing a higher version is
// refused rather than guessed at: two nodes disagreeing about the format would
// silently diverge their config.
const ProtocolVersion uint8 = 1

// MsgType identifies a frame.
type MsgType uint8

const (
	// MsgHello opens a connection and exchanges node identity.
	MsgHello MsgType = 1
	// MsgOK is a bare acknowledgement.
	MsgOK MsgType = 2
	// MsgError carries a failure string.
	MsgError MsgType = 3

	// MsgCacheFetch asks the peer for one cache entry.
	MsgCacheFetch MsgType = 10
	// MsgCacheHit returns an entry.
	MsgCacheHit MsgType = 11
	// MsgCacheMiss reports the peer does not hold it.
	MsgCacheMiss MsgType = 12
	// MsgCachePush offers entries to the peer, unsolicited.
	MsgCachePush MsgType = 13

	// MsgDigests carries the sender's full record summary.
	MsgDigests MsgType = 20
	// MsgRecords carries control records.
	MsgRecords MsgType = 21
	// MsgWantRecords asks for everything the sender is missing, given digests.
	MsgWantRecords MsgType = 22
)

// String implements fmt.Stringer.
func (m MsgType) String() string {
	switch m {
	case MsgHello:
		return "hello"
	case MsgOK:
		return "ok"
	case MsgError:
		return "error"
	case MsgCacheFetch:
		return "cache-fetch"
	case MsgCacheHit:
		return "cache-hit"
	case MsgCacheMiss:
		return "cache-miss"
	case MsgCachePush:
		return "cache-push"
	case MsgDigests:
		return "digests"
	case MsgRecords:
		return "records"
	case MsgWantRecords:
		return "want-records"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(m))
	}
}

// maxFrame caps a single frame. Config sync sends records in batches rather
// than one enormous frame, so this bounds memory a hostile or broken peer can
// make the other side allocate.
const maxFrame = 8 << 20

// ErrPeerClosed means the peer hung up.
var ErrPeerClosed = errors.New("peer: connection closed")

// Hello is the opening handshake payload.
type Hello struct {
	Version uint8  `json:"version"`
	NodeID  string `json:"node_id"`
	POP     string `json:"pop,omitempty"`
}

// writeFrame emits one length-prefixed frame.
func writeFrame(w io.Writer, t MsgType, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("peer: %s frame is %d bytes, over the %d limit", t, len(payload), maxFrame)
	}
	var hdr [5]byte
	hdr[0] = byte(t)
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one frame.
func readFrame(r io.Reader) (MsgType, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, ErrPeerClosed
		}
		return 0, nil, err
	}
	t := MsgType(hdr[0])
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("peer: %s frame claims %d bytes, over the %d limit", t, n, maxFrame)
	}
	if n == 0 {
		return t, nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return t, buf, nil
}

func writeJSON(w io.Writer, t MsgType, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("peer: encoding %s: %w", t, err)
	}
	return writeFrame(w, t, b)
}

// CacheKeyWire identifies an entry across the link.
type CacheKeyWire struct {
	Name  string `json:"n"`
	Type  uint16 `json:"t"`
	Class uint16 `json:"c"`
}

func wireKey(k cache.Key) CacheKeyWire {
	return CacheKeyWire{Name: k.Name, Type: k.Type, Class: k.Class}
}

func (w CacheKeyWire) key() cache.Key {
	return cache.NewKey(w.Name, w.Type, w.Class)
}

// encodeEntry packs a cache entry as a DNS message.
//
// Reusing the wire format rather than inventing an encoding keeps this cheap
// and means the RRs are already in the form both sides need. TTLs are written
// as the time *remaining*, never the original: a shared entry that carried its
// original TTL would be resurrected on the peer and outlive its own expiry.
func encodeEntry(k cache.Key, e cache.Entry, now time.Time) ([]byte, error) {
	if e.TTLAt(now) == 0 {
		return nil, fmt.Errorf("peer: entry for %s has expired", k.Name)
	}

	m := new(dns.Msg)
	m.SetQuestion(k.Name, k.Type)
	m.Question[0].Qclass = k.Class
	m.Rcode = e.Rcode
	m.Response = true
	// AD carries whether the sender validated the chain. The receiver trusts
	// it because the link is mutually authenticated and the pair is one trust
	// domain; see the package doc for what that concedes.
	m.AuthenticatedData = e.Authenticated

	rrs := e.RRsAt(now)
	switch e.Kind {
	case cache.KindAnswer:
		m.Answer = rrs
	case cache.KindNegative:
		m.Ns = rrs
	}
	return m.Pack()
}

// decodeEntry unpacks what encodeEntry produced.
func decodeEntry(b []byte) (cache.Key, cache.Entry, time.Duration, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return cache.Key{}, cache.Entry{}, 0, fmt.Errorf("peer: decoding entry: %w", err)
	}
	if len(m.Question) != 1 {
		return cache.Key{}, cache.Entry{}, 0, errors.New("peer: entry carries no question")
	}

	q := m.Question[0]
	k := cache.NewKey(q.Name, q.Qtype, q.Qclass)

	e := cache.Entry{Rcode: m.Rcode, Authenticated: m.AuthenticatedData}
	var rrs []dns.RR
	switch {
	case len(m.Answer) > 0:
		e.Kind = cache.KindAnswer
		rrs = m.Answer
	case len(m.Ns) > 0:
		e.Kind = cache.KindNegative
		rrs = m.Ns
	default:
		return cache.Key{}, cache.Entry{}, 0, errors.New("peer: entry carries no records")
	}
	e.RRs = rrs

	// The smallest remaining TTL governs the whole set.
	var min uint32
	for i, rr := range rrs {
		ttl := rr.Header().Ttl
		if i == 0 || ttl < min {
			min = ttl
		}
	}
	if min == 0 {
		return cache.Key{}, cache.Entry{}, 0, errors.New("peer: entry arrived already expired")
	}
	return k, e, time.Duration(min) * time.Second, nil
}

// CachePush is a batch of entries offered to the peer.
type CachePush struct {
	Entries [][]byte `json:"e"`
}

// RecordBatch carries control records.
type RecordBatch struct {
	Records []control.Record `json:"r"`
}

// DigestBatch carries a full record summary for anti-entropy.
type DigestBatch struct {
	Digests []control.Digest `json:"d"`
}
