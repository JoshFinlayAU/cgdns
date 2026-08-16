// Package management serves the operator API for a node.
//
// It is deliberately reachable only where the config says it is: bound to the
// management addresses, filtered by a default-deny source ACL, and TLS unless
// every listener is loopback. A carrier's resolver answers the world on port
// 53; nothing about that should imply the admin plane is reachable from it.
//
// State written here goes into the control store, so it replicates to the
// sibling and a pair can be managed from either node.
package management

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/control"
)

// Scope is a permission an API token carries.
type Scope string

const (
	// ScopeRead permits reading state and metrics.
	ScopeRead Scope = "read"
	// ScopeWrite permits changing subscribers, overrides, feeds and classes.
	ScopeWrite Scope = "write"
	// ScopeAdmin permits managing tokens themselves.
	ScopeAdmin Scope = "admin"
)

// Valid reports whether s is a scope this build understands. An unknown scope
// is refused at mint time rather than ignored: silently dropping a scope an
// operator asked for grants less than they think, and silently keeping one this
// build cannot enforce grants more.
func (s Scope) Valid() bool {
	switch s {
	case ScopeRead, ScopeWrite, ScopeAdmin:
		return true
	default:
		return false
	}
}

// implies reports whether holding s grants want.
//
// Admin implies write implies read. An operator who can mint tokens can already
// grant themselves anything, so pretending otherwise would only make the API
// awkward without making it safer.
func (s Scope) implies(want Scope) bool {
	switch s {
	case ScopeAdmin:
		return true
	case ScopeWrite:
		return want == ScopeWrite || want == ScopeRead
	case ScopeRead:
		return want == ScopeRead
	}
	return false
}

// Token is the stored half of an API credential. The secret is never here.
type Token struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Hash    string    `json:"hash"`
	Scopes  []Scope   `json:"scopes"`
	Created time.Time `json:"created"`
	// Expires is zero for a token that does not expire.
	Expires time.Time `json:"expires,omitempty"`
}

// secretBytes is the entropy behind a token secret.
//
// 256 bits means the hash can be a plain SHA-256 rather than a slow password
// KDF: there is no dictionary to attack, so the only route is brute force
// against the full keyspace. Human-chosen passwords get different treatment.
const secretBytes = 32

// ErrTokenNotFound means no token with that ID exists.
var ErrTokenNotFound = errors.New("management: token not found")

// ErrTokenExpired means the token exists but its lifetime has passed.
var ErrTokenExpired = errors.New("management: token expired")

// Mint creates a token, returning the record to store and the secret to show
// the operator. The secret is returned exactly once and never recoverable.
func Mint(name string, scopes []Scope, ttl time.Duration, now time.Time) (Token, string, error) {
	if strings.TrimSpace(name) == "" {
		return Token{}, "", errors.New("management: a token needs a name")
	}
	if len(scopes) == 0 {
		return Token{}, "", errors.New("management: a token needs at least one scope")
	}
	for _, s := range scopes {
		if !s.Valid() {
			return Token{}, "", fmt.Errorf("management: unknown scope %q", s)
		}
	}

	idRaw := make([]byte, 8)
	if _, err := rand.Read(idRaw); err != nil {
		return Token{}, "", fmt.Errorf("management: generating token id: %w", err)
	}
	secretRaw := make([]byte, secretBytes)
	if _, err := rand.Read(secretRaw); err != nil {
		return Token{}, "", fmt.Errorf("management: generating token secret: %w", err)
	}

	id := hex.EncodeToString(idRaw)
	secret := hex.EncodeToString(secretRaw)

	t := Token{
		ID:      id,
		Name:    name,
		Hash:    hashSecret(secret),
		Scopes:  scopes,
		Created: now.UTC(),
	}
	if ttl > 0 {
		t.Expires = now.Add(ttl).UTC()
	}
	// The presented form carries the ID so verification is a single lookup
	// rather than a scan over every token.
	return t, id + "." + secret, nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// splitPresented separates the ID from the secret.
func splitPresented(presented string) (id, secret string, ok bool) {
	id, secret, ok = strings.Cut(presented, ".")
	if !ok || id == "" || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

// Verify resolves a presented token against the store.
//
// Comparison is constant time, and an unknown ID is compared against a dummy
// hash so a missing token costs the same as a wrong secret. That keeps the
// response time from distinguishing "no such token" from "bad secret", which
// would otherwise let an attacker enumerate valid IDs.
func Verify(store *control.Store, presented string, now time.Time) (Token, error) {
	id, secret, ok := splitPresented(presented)
	if !ok {
		compareHash(hashSecret(""), hashSecret("x"))
		return Token{}, ErrTokenNotFound
	}

	t, err := LoadToken(store, id)
	if err != nil {
		compareHash(hashSecret(secret), strings.Repeat("0", sha256.Size*2))
		return Token{}, ErrTokenNotFound
	}
	if !compareHash(hashSecret(secret), t.Hash) {
		return Token{}, ErrTokenNotFound
	}
	if !t.Expires.IsZero() && now.After(t.Expires) {
		return Token{}, ErrTokenExpired
	}
	return t, nil
}

func compareHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Allows reports whether the token grants want.
func (t Token) Allows(want Scope) bool {
	for _, s := range t.Scopes {
		if s.implies(want) {
			return true
		}
	}
	return false
}

// LoadToken reads one token from the store.
func LoadToken(store *control.Store, id string) (Token, error) {
	for _, r := range store.Records() {
		if r.Kind != control.KindToken || r.Key != id {
			continue
		}
		var t Token
		if err := json.Unmarshal(r.Payload, &t); err != nil {
			return Token{}, fmt.Errorf("management: decoding token %s: %w", id, err)
		}
		return t, nil
	}
	return Token{}, ErrTokenNotFound
}

// ListTokens returns every token, without secrets or hashes.
func ListTokens(store *control.Store) ([]Token, error) {
	var out []Token
	for _, r := range store.Records() {
		if r.Kind != control.KindToken {
			continue
		}
		var t Token
		if err := json.Unmarshal(r.Payload, &t); err != nil {
			return nil, fmt.Errorf("management: decoding token %s: %w", r.Key, err)
		}
		t.Hash = ""
		out = append(out, t)
	}
	return out, nil
}

// SaveToken writes a token to the store, replicating it to the sibling.
func SaveToken(store *control.Store, t Token) error {
	if _, err := store.Put(control.KindToken, t.ID, t); err != nil {
		return fmt.Errorf("management: storing token %s: %w", t.ID, err)
	}
	return nil
}

// RevokeToken deletes a token. The tombstone is what stops the sibling
// resurrecting it on rejoin, so a revocation survives an outage.
func RevokeToken(store *control.Store, id string) error {
	if _, err := LoadToken(store, id); err != nil {
		return err
	}
	if _, err := store.Delete(control.KindToken, id); err != nil {
		return fmt.Errorf("management: revoking token %s: %w", id, err)
	}
	return nil
}

// HasTokens reports whether any token exists, which decides whether a node
// needs to bootstrap one.
func HasTokens(store *control.Store) bool {
	for _, r := range store.Records() {
		if r.Kind == control.KindToken {
			return true
		}
	}
	return false
}
