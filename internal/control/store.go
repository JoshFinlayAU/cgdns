package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// RecordKind names the sort of thing a record holds.
type RecordKind uint8

const (
	// KindSubscriber maps a client prefix to a subscriber and class.
	KindSubscriber RecordKind = 1
	// KindOverride holds one subscriber's personal allow and block lists.
	KindOverride RecordKind = 2
	// KindFeed holds a blocklist's metadata.
	KindFeed RecordKind = 3
	// KindClass holds a subscriber class definition.
	KindClass RecordKind = 4
	// KindToken holds an API token's hash and scopes. Only the hash is stored,
	// so replicating it to the sibling — which is what lets an operator manage
	// the pair from either node — never moves the secret itself.
	KindToken RecordKind = 5
	// KindUser holds an operator's WebUI login: password hash, scopes and
	// second factor.
	//
	// These values are persisted and replicated, so they are fixed: renumbering
	// one would make a node read every existing record of that kind as
	// something else.
	KindUser RecordKind = 6
)

// String implements fmt.Stringer.
func (k RecordKind) String() string {
	switch k {
	case KindSubscriber:
		return "subscriber"
	case KindOverride:
		return "override"
	case KindFeed:
		return "feed"
	case KindClass:
		return "class"
	case KindToken:
		return "token"
	case KindUser:
		return "user"
	default:
		return "unknown"
	}
}

// Record is one replicated control-plane entry.
//
// Lamport and Origin order writes without depending on synchronised clocks:
// a write sets Lamport to one past the highest it has seen, and Origin breaks
// ties deterministically, so both nodes in a pair converge on the same winner
// whatever order updates arrive in.
type Record struct {
	Kind    RecordKind      `json:"kind"`
	Key     string          `json:"key"`
	Lamport uint64          `json:"lamport"`
	Origin  string          `json:"origin"`
	Deleted bool            `json:"deleted,omitempty"`
	Updated time.Time       `json:"updated"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// ID is the record's identity within the store.
func (r Record) ID() string { return fmt.Sprintf("%d:%s", r.Kind, r.Key) }

// newerThan reports whether r supersedes other under last-write-wins.
func (r Record) newerThan(other Record) bool {
	if r.Lamport != other.Lamport {
		return r.Lamport > other.Lamport
	}
	// Same logical time: the higher node ID wins, so both sides agree.
	return r.Origin > other.Origin
}

// Digest is the minimum needed to decide whether a peer holds something newer.
type Digest struct {
	Kind    RecordKind `json:"kind"`
	Key     string     `json:"key"`
	Lamport uint64     `json:"lamport"`
	Origin  string     `json:"origin"`
}

// TombstoneTTL is how long a delete is remembered.
//
// A delete has to outlive any realistic outage: if a tombstone is collected
// while the peer is still down, that peer resurrects the record when it
// rejoins, because from its point of view the record simply still exists.
const TombstoneTTL = 7 * 24 * time.Hour

// Store is a node's durable control-plane state.
//
// It is safe for concurrent use. Writes are persisted by an atomic
// rename, so a crash mid-write leaves the previous file intact.
type Store struct {
	mu      sync.RWMutex
	records map[string]Record
	lamport uint64
	nodeID  string
	path    string
	version uint64

	changed *sync.Cond
	dirty   bool
}

// StoreOptions configures a Store.
type StoreOptions struct {
	// NodeID must be unique within the pair; it is the tiebreak for
	// concurrent writes.
	NodeID string
	// Path is the JSON file backing the store. Empty keeps it in memory.
	Path string
}

// Open loads a store from disk, creating it when absent.
func Open(opts StoreOptions) (*Store, error) {
	if opts.NodeID == "" {
		return nil, fmt.Errorf("control: node ID is required")
	}
	s := &Store{
		records: map[string]Record{},
		nodeID:  opts.NodeID,
		path:    opts.Path,
	}
	s.changed = sync.NewCond(&s.mu)

	if opts.Path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(opts.Path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading control store %s: %w", opts.Path, err)
	}

	var records []Record
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("parsing control store %s: %w", opts.Path, err)
	}
	for _, r := range records {
		s.records[r.ID()] = r
		if r.Lamport > s.lamport {
			s.lamport = r.Lamport
		}
	}
	return s, nil
}

// Put writes a record locally, stamping it with the next logical time.
// It returns the stored record so the caller can replicate it to the peer.
func (s *Store) Put(kind RecordKind, key string, payload any) (Record, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Record{}, fmt.Errorf("encoding %s %q: %w", kind, key, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.lamport++
	r := Record{
		Kind:    kind,
		Key:     key,
		Lamport: s.lamport,
		Origin:  s.nodeID,
		Updated: time.Now().UTC(),
		Payload: raw,
	}
	s.records[r.ID()] = r
	s.bumpLocked()
	return r, nil
}

// Delete tombstones a record. The tombstone is what stops a peer that was down
// during the delete from resurrecting the record when it rejoins.
func (s *Store) Delete(kind RecordKind, key string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lamport++
	r := Record{
		Kind:    kind,
		Key:     key,
		Lamport: s.lamport,
		Origin:  s.nodeID,
		Deleted: true,
		Updated: time.Now().UTC(),
	}
	s.records[r.ID()] = r
	s.bumpLocked()
	return r, nil
}

// Merge applies records received from the peer, keeping whichever version wins.
// It returns how many were actually adopted.
func (s *Store) Merge(incoming []Record) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	adopted := 0
	for _, r := range incoming {
		// Track the peer's logical time so a subsequent local write sorts
		// after anything already seen.
		if r.Lamport > s.lamport {
			s.lamport = r.Lamport
		}
		existing, ok := s.records[r.ID()]
		if ok && !r.newerThan(existing) {
			continue
		}
		s.records[r.ID()] = r
		adopted++
	}
	if adopted > 0 {
		s.bumpLocked()
	}
	return adopted
}

// Digests summarises every record, for the anti-entropy exchange on reconnect.
func (s *Store) Digests() []Digest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Digest, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, Digest{Kind: r.Kind, Key: r.Key, Lamport: r.Lamport, Origin: r.Origin})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// Missing returns the records this store holds that the peer's digests show as
// absent or older, which is exactly what the peer needs to catch up.
func (s *Store) Missing(peer []Digest) []Record {
	have := make(map[string]Digest, len(peer))
	for _, d := range peer {
		have[fmt.Sprintf("%d:%s", d.Kind, d.Key)] = d
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Record, 0)
	for id, r := range s.records {
		d, ok := have[id]
		if !ok {
			out = append(out, r)
			continue
		}
		theirs := Record{Lamport: d.Lamport, Origin: d.Origin}
		if r.newerThan(theirs) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Records returns every live record, ordered.
func (s *Store) Records() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.recordsLocked(false)
}

// All returns every record including tombstones, ordered.
func (s *Store) All() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.recordsLocked(true)
}

func (s *Store) recordsLocked(includeDeleted bool) []Record {
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		if r.Deleted && !includeDeleted {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Version reports how many times the store has changed.
func (s *Store) Version() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// Hash returns a content hash of the live records.
//
// This is the drift detector that replaces consensus: two nodes serving a POP
// should report the same hash, and monitoring alerts when they do not, catching
// a provisioning push that reached one node and not the other.
func (s *Store) Hash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	h := sha256.New()
	var buf bytes.Buffer
	for _, r := range s.recordsLocked(true) {
		fmt.Fprintf(h, "%s|%d|%s|%t|", r.ID(), r.Lamport, r.Origin, r.Deleted)
		// Compare content, not formatting: a payload that has been through an
		// indented file, or arrived from a peer that encodes differently, must
		// hash the same or the drift detector cries wolf on every restart.
		buf.Reset()
		if len(r.Payload) > 0 && json.Compact(&buf, r.Payload) == nil {
			h.Write(buf.Bytes())
		} else {
			h.Write(r.Payload)
		}
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// CollectTombstones drops tombstones older than TombstoneTTL.
func (s *Store) CollectTombstones(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for id, r := range s.records {
		if r.Deleted && now.Sub(r.Updated) > TombstoneTTL {
			delete(s.records, id)
			removed++
		}
	}
	if removed > 0 {
		s.bumpLocked()
	}
	return removed
}

// Flush persists the store, replacing the file atomically so a crash mid-write
// cannot truncate it.
func (s *Store) Flush() error {
	s.mu.Lock()
	if s.path == "" || !s.dirty {
		s.mu.Unlock()
		return nil
	}
	records := s.recordsLocked(true)
	s.dirty = false
	s.mu.Unlock()

	raw, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding control store: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return fmt.Errorf("creating control store dir: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("writing control store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replacing control store: %w", err)
	}
	return nil
}

// WaitForChange blocks until the version moves past known, or stop closes.
func (s *Store) WaitForChange(known uint64, stop <-chan struct{}) uint64 {
	done := make(chan struct{})
	go func() {
		select {
		case <-stop:
			s.mu.Lock()
			s.changed.Broadcast()
			s.mu.Unlock()
		case <-done:
		}
	}()
	defer close(done)

	s.mu.Lock()
	defer s.mu.Unlock()
	for s.version == known {
		select {
		case <-stop:
			return s.version
		default:
		}
		s.changed.Wait()
	}
	return s.version
}

func (s *Store) bumpLocked() {
	s.version++
	s.dirty = true
	s.changed.Broadcast()
}

// State projects the records into the typed view the publisher consumes.
func (s *Store) State() (*State, uint64) {
	s.mu.RLock()
	records := s.recordsLocked(false)
	version := s.version
	s.mu.RUnlock()

	state := NewState()
	for _, r := range records {
		switch r.Kind {
		case KindSubscriber:
			var v SubscriberRecord
			if json.Unmarshal(r.Payload, &v) == nil {
				_ = state.setSubscriber(v)
			}
		case KindOverride:
			var v OverrideRecord
			if json.Unmarshal(r.Payload, &v) == nil {
				_ = state.setOverride(v)
			}
		case KindFeed:
			var v FeedRecord
			if json.Unmarshal(r.Payload, &v) == nil {
				_ = state.setFeed(v)
			}
		case KindClass:
			var v ClassRecord
			if json.Unmarshal(r.Payload, &v) == nil {
				_ = state.setClass(v)
			}
		}
	}
	return state, version
}

// RunFlusher persists the store whenever it changes, until ctx is cancelled.
//
// Writes are held in memory and flushed by this loop rather than written
// through on every Put, because anti-entropy with the sibling can adopt a burst
// of records at once and each would otherwise be a separate rewrite of the
// whole file.
//
// It always flushes once more on the way out. A node that took a config change
// and was then restarted before the next flush would come back without it and,
// worse, would look converged to an operator reading a stale file.
func (s *Store) RunFlusher(ctx context.Context, minInterval time.Duration) error {
	if s.path == "" {
		<-ctx.Done()
		return nil
	}
	if minInterval <= 0 {
		minInterval = time.Second
	}

	stop := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stop)
	}()

	// Flush before waiting, never after. Writes land before this loop starts —
	// the daemon mints its bootstrap token during startup — and a wait-first
	// loop would sit on them until some later change happened to arrive.
	known := s.Version()
	for {
		if err := s.Flush(); err != nil {
			return err
		}
		known = s.WaitForChange(known, stop)
		if ctx.Err() != nil {
			break
		}
		// Coalesce a burst rather than rewriting the file per record.
		select {
		case <-time.After(minInterval):
		case <-stop:
		}
	}
	return s.Flush()
}
