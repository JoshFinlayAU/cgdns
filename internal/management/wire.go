package management

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/control"
)

// The API's request and response bodies live here so the server and the client
// cannot drift apart: cgdnsctl decodes the same types the daemon encodes.

// ListResponse is a list of record payloads of one kind.
type ListResponse struct {
	Items []json.RawMessage `json:"items"`
	Count int               `json:"count"`
}

// WriteResponse acknowledges a stored record.
//
// Hash is the store hash *after* the write, which is what makes a provisioning
// system able to confirm both nodes of a pair converged on the same state.
type WriteResponse struct {
	Kind    string `json:"kind"`
	Key     string `json:"key"`
	Lamport uint64 `json:"lamport"`
	Hash    string `json:"hash"`
}

// DeleteResponse acknowledges a tombstoned record.
type DeleteResponse struct {
	Deleted string `json:"deleted"`
	Hash    string `json:"hash"`
}

// RecordsResponse is the raw store dump.
type RecordsResponse struct {
	Records []control.Record `json:"records"`
	Hash    string           `json:"hash"`
}

// TokenListResponse lists tokens, without hashes.
type TokenListResponse struct {
	Tokens []Token `json:"tokens"`
	Count  int     `json:"count"`
}

// MintedToken is the only time a secret is ever disclosed.
type MintedToken struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Scopes []Scope `json:"scopes"`
	// Token is the credential to present. It is not recoverable afterwards.
	Token   string     `json:"token"`
	Expires *time.Time `json:"expires"`
}

// RevokeResponse acknowledges a revocation.
type RevokeResponse struct {
	Revoked string `json:"revoked"`
}

// ErrorResponse is the body of every non-2xx reply.
type ErrorResponse struct {
	Error string `json:"error"`
}

// APIError is a non-2xx reply, surfaced to the caller with its status.
type APIError struct {
	Status  int
	Message string
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("management: server returned %d", e.Status)
	}
	return e.Message
}

// NotFound reports whether the server said the record does not exist, which a
// caller usually wants to treat as a normal outcome rather than a failure.
func (e *APIError) NotFound() bool { return e.Status == 404 }

// pathFor maps a record kind to its URL segment.
func pathFor(kind control.RecordKind) (string, error) {
	for path, k := range kindPaths {
		if k == kind {
			return path, nil
		}
	}
	return "", fmt.Errorf("management: %s records are not exposed over the API", kind)
}

// KindFor maps a CLI noun to the record kind it manages.
func KindFor(noun string) (control.RecordKind, bool) {
	k, ok := kindPaths[noun]
	return k, ok
}

// Nouns lists the record kinds the API exposes, for help text.
func Nouns() []string {
	out := make([]string, 0, len(kindPaths))
	for path := range kindPaths {
		out = append(out, path)
	}
	return out
}
