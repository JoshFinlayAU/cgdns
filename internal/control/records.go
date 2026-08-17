// Package control holds a node's local control-plane state: subscriber
// mappings, per-subscriber overrides, feed metadata and class definitions.
//
// There is no consensus. Each node is written to independently by the
// provisioning system, which is the single source of truth, so records are
// idempotent and last-write-wins. Two nodes serving the same POP are kept in
// step by pushing the same records to both; Store.Hash exposes a content hash
// so monitoring can detect a push that reached one and not the other.
//
// The query path never reads this state directly. It is published into the
// lock-free structures the resolver uses, so a store that is stale or mid-write
// never affects resolution.
package control

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// SubscriberRecord maps a client prefix to a subscriber and their class.
type SubscriberRecord struct {
	Prefix string `json:"prefix"`
	ID     string `json:"id,omitempty"`
	Class  string `json:"class"`
}

// OverrideRecord holds one subscriber's personal allow and block lists.
type OverrideRecord struct {
	SubscriberID string   `json:"subscriber_id"`
	Allow        []string `json:"allow,omitempty"`
	Block        []string `json:"block,omitempty"`
}

// FeedRecord is a blocklist's metadata. Content is never replicated; SHA256 is
// what lets a node verify the copy it fetched is the one this record names.
type FeedRecord struct {
	Name    string `json:"name"`
	Format  string `json:"format"`
	URL     string `json:"url,omitempty"`
	File    string `json:"file,omitempty"`
	RPZZone string `json:"rpz_zone,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Version uint64 `json:"version"`
}

// ClassRecord binds feeds and a block action to a subscriber class.
type ClassRecord struct {
	Name       string   `json:"name"`
	Feeds      []string `json:"feeds,omitempty"`
	Action     string   `json:"action,omitempty"`
	RedirectTo []string `json:"redirect_to,omitempty"`
}

// State is the replicated control-plane state.
//
// It is stored in maps for cheap application, but every path that produces an
// ordered result sorts explicitly: an FSM that let map iteration order leak
// into its output would diverge between nodes.
type State struct {
	subscribers map[string]SubscriberRecord
	overrides   map[string]OverrideRecord
	feeds       map[string]FeedRecord
	classes     map[string]ClassRecord
}

// NewState returns empty state.
func NewState() *State {
	return &State{
		subscribers: map[string]SubscriberRecord{},
		overrides:   map[string]OverrideRecord{},
		feeds:       map[string]FeedRecord{},
		classes:     map[string]ClassRecord{},
	}
}

// Clone deep-copies the state, so a published snapshot cannot be mutated by
// subsequent applies.
func (s *State) Clone() *State {
	out := NewState()
	for k, v := range s.subscribers {
		out.subscribers[k] = v
	}
	for k, v := range s.overrides {
		cp := v
		cp.Allow = append([]string(nil), v.Allow...)
		cp.Block = append([]string(nil), v.Block...)
		out.overrides[k] = cp
	}
	for k, v := range s.feeds {
		out.feeds[k] = v
	}
	for k, v := range s.classes {
		cp := v
		cp.Feeds = append([]string(nil), v.Feeds...)
		cp.RedirectTo = append([]string(nil), v.RedirectTo...)
		out.classes[k] = cp
	}
	return out
}

// Subscribers returns every subscriber record, ordered by prefix.
func (s *State) Subscribers() []SubscriberRecord {
	out := make([]SubscriberRecord, 0, len(s.subscribers))
	for _, v := range s.subscribers {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// Overrides returns every override record, ordered by subscriber ID.
func (s *State) Overrides() []OverrideRecord {
	out := make([]OverrideRecord, 0, len(s.overrides))
	for _, v := range s.overrides {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SubscriberID < out[j].SubscriberID })
	return out
}

// Feeds returns every feed record, ordered by name.
func (s *State) Feeds() []FeedRecord {
	out := make([]FeedRecord, 0, len(s.feeds))
	for _, v := range s.feeds {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Classes returns every class record, ordered by name.
func (s *State) Classes() []ClassRecord {
	out := make([]ClassRecord, 0, len(s.classes))
	for _, v := range s.classes {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Counts reports how many records of each kind are held.
func (s *State) Counts() (subscribers, overrides, feeds, classes int) {
	return len(s.subscribers), len(s.overrides), len(s.feeds), len(s.classes)
}

// setSubscriber validates and stores a subscriber record.
func (s *State) setSubscriber(r SubscriberRecord) error {
	p, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return fmt.Errorf("subscriber prefix %q: %w", r.Prefix, err)
	}
	if p.Masked() != p {
		return fmt.Errorf("subscriber prefix %q has host bits set", r.Prefix)
	}
	if r.Class == "" {
		return fmt.Errorf("subscriber %q has no class", r.Prefix)
	}
	r.Prefix = p.String()
	s.subscribers[r.Prefix] = r
	return nil
}

func (s *State) deleteSubscriber(prefix string) error {
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		return fmt.Errorf("subscriber prefix %q: %w", prefix, err)
	}
	delete(s.subscribers, p.Masked().String())
	return nil
}

func (s *State) setOverride(r OverrideRecord) error {
	if r.SubscriberID == "" {
		return fmt.Errorf("override has no subscriber id")
	}
	r.Allow = normaliseNames(r.Allow)
	r.Block = normaliseNames(r.Block)
	s.overrides[r.SubscriberID] = r
	return nil
}

func (s *State) deleteOverride(id string) error {
	if id == "" {
		return fmt.Errorf("override has no subscriber id")
	}
	delete(s.overrides, id)
	return nil
}

func (s *State) setFeed(r FeedRecord) error {
	if r.Name == "" {
		return fmt.Errorf("feed has no name")
	}
	switch r.Format {
	case "", "domain-list", "rpz":
	default:
		return fmt.Errorf("feed %q has unknown format %q", r.Name, r.Format)
	}
	if r.Format == "rpz" && r.RPZZone == "" {
		return fmt.Errorf("feed %q is rpz format but names no zone", r.Name)
	}
	if r.URL == "" && r.File == "" {
		return fmt.Errorf("feed %q names neither a url nor a file", r.Name)
	}
	s.feeds[r.Name] = r
	return nil
}

func (s *State) deleteFeed(name string) error {
	if name == "" {
		return fmt.Errorf("feed has no name")
	}
	delete(s.feeds, name)
	return nil
}

func (s *State) setClass(r ClassRecord) error {
	if r.Name == "" {
		return fmt.Errorf("class has no name")
	}
	r.Name = strings.ToLower(r.Name)
	sort.Strings(r.Feeds)
	s.classes[r.Name] = r
	return nil
}

func (s *State) deleteClass(name string) error {
	if name == "" {
		return fmt.Errorf("class has no name")
	}
	delete(s.classes, strings.ToLower(name))
	return nil
}

// normaliseNames lowercases and sorts a name list, so two nodes that received
// the same logical update hold byte-identical records.
func normaliseNames(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, n := range in {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// KeyFor returns the store key a record payload must be filed under, so an API
// cannot file a subscriber for 10.0.0.0/8 under the key 192.0.2.0/24 and leave
// the store keyed inconsistently with its own contents.
func KeyFor(kind RecordKind, payload []byte) (string, error) {
	switch kind {
	case KindSubscriber:
		var v SubscriberRecord
		if err := json.Unmarshal(payload, &v); err != nil {
			return "", err
		}
		p, err := netip.ParsePrefix(v.Prefix)
		if err != nil {
			return "", fmt.Errorf("subscriber prefix %q: %w", v.Prefix, err)
		}
		return p.Masked().String(), nil
	case KindOverride:
		var v OverrideRecord
		if err := json.Unmarshal(payload, &v); err != nil {
			return "", err
		}
		return v.SubscriberID, nil
	case KindFeed:
		var v FeedRecord
		if err := json.Unmarshal(payload, &v); err != nil {
			return "", err
		}
		return v.Name, nil
	case KindClass:
		var v ClassRecord
		if err := json.Unmarshal(payload, &v); err != nil {
			return "", err
		}
		return strings.ToLower(v.Name), nil
	default:
		return "", fmt.Errorf("control: %s records have no derived key", kind)
	}
}

// Canonical validates a payload and returns it in the exact form the publish
// path will hold.
//
// Two things make this mandatory rather than tidiness. The publish path drops a
// bad record silently — correct, since a malformed record must never break
// resolution — so without validation here an operator gets a success response
// for something that will never take effect. And the publish path normalises
// (lowercases, sorts, dedupes), so storing the payload as typed would leave the
// store disagreeing with the policy actually in force. That last one is worse
// than it looks: Store.Hash is the drift detector between the two nodes in a
// pair, so the same policy entered as "Example.COM" on one node and
// "example.com" on the other would report drift forever.
func Canonical(kind RecordKind, payload []byte) ([]byte, error) {
	s := NewState()
	switch kind {
	case KindSubscriber:
		var v SubscriberRecord
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		if err := s.setSubscriber(v); err != nil {
			return nil, err
		}
		return json.Marshal(s.Subscribers()[0])
	case KindOverride:
		var v OverrideRecord
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		if err := s.setOverride(v); err != nil {
			return nil, err
		}
		return json.Marshal(s.Overrides()[0])
	case KindFeed:
		var v FeedRecord
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		if err := s.setFeed(v); err != nil {
			return nil, err
		}
		return json.Marshal(s.Feeds()[0])
	case KindClass:
		var v ClassRecord
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		if err := s.setClass(v); err != nil {
			return nil, err
		}
		return json.Marshal(s.Classes()[0])
	default:
		return nil, fmt.Errorf("control: cannot validate a %s record", kind)
	}
}

// Validate reports whether a payload is acceptable, discarding the canonical
// form.
func Validate(kind RecordKind, payload []byte) error {
	_, err := Canonical(kind, payload)
	return err
}
