package management

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/control"
)

// Status is what a node reports about itself.
type Status struct {
	NodeID  string `json:"node_id"`
	POP     string `json:"pop,omitempty"`
	Version string `json:"version"`
	Uptime  string `json:"uptime"`

	// StoreHash is the control-store content hash. Both nodes in a pair should
	// report the same value; a lasting disagreement means a provisioning push
	// reached one node and not the other.
	StoreHash    string `json:"store_hash"`
	StoreVersion uint64 `json:"store_version"`
	Records      int    `json:"records"`

	PeerOutboundUp bool `json:"peer_outbound_up"`
	PeerInboundUp  bool `json:"peer_inbound_up"`

	Advertised bool `json:"anycast_advertised"`
	Healthy    bool `json:"healthy"`
}

// StatusFunc reports live node status.
type StatusFunc func() Status

// API routes the operator interface.
type API struct {
	store    *control.Store
	status   StatusFunc
	log      *slog.Logger
	now      func() time.Time
	sessions *SessionStore
	issuer   string
}

// APIOptions configures the API.
type APIOptions struct {
	Store  *control.Store
	Status StatusFunc
	Log    *slog.Logger
	// Now is injectable so token expiry is testable.
	Now func() time.Time
	// SessionTTL bounds a WebUI login.
	SessionTTL time.Duration
	// Issuer names this node in an authenticator app.
	Issuer string
}

// NewAPI builds the operator API.
func NewAPI(opts APIOptions) (*API, error) {
	if opts.Store == nil {
		return nil, errors.New("management: a control store is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Status == nil {
		opts.Status = func() Status { return Status{} }
	}
	if opts.Issuer == "" {
		opts.Issuer = "cgdns"
	}
	return &API{
		store:    opts.Store,
		status:   opts.Status,
		log:      opts.Log,
		now:      opts.Now,
		sessions: NewSessionStore(opts.SessionTTL, opts.Now),
		issuer:   opts.Issuer,
	}, nil
}

// Sessions exposes the session store, for the metrics endpoint and for sweeping.
func (a *API) Sessions() *SessionStore { return a.sessions }

// kindPaths maps the URL segment to the record kind it manages.
var kindPaths = map[string]control.RecordKind{
	"subscribers": control.KindSubscriber,
	"overrides":   control.KindOverride,
	"feeds":       control.KindFeed,
	"classes":     control.KindClass,
}

// Handler returns the routed API, already wrapped in authentication.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /api/v1/status", a.guard(ScopeRead, a.handleStatus))
	mux.Handle("GET /api/v1/records", a.guard(ScopeRead, a.handleRecords))

	for path, kind := range kindPaths {
		mux.Handle("GET /api/v1/"+path, a.guard(ScopeRead, a.listRecords(kind)))
		mux.Handle("GET /api/v1/"+path+"/{key...}", a.guard(ScopeRead, a.getRecord(kind)))
		mux.Handle("PUT /api/v1/"+path+"/{key...}", a.guard(ScopeWrite, a.putRecord(kind)))
		mux.Handle("POST /api/v1/"+path, a.guard(ScopeWrite, a.postRecord(kind)))
		mux.Handle("DELETE /api/v1/"+path+"/{key...}", a.guard(ScopeWrite, a.deleteRecord(kind)))
	}

	// Login is the only unauthenticated endpoint. Everything else needs either
	// an API token or a session.
	mux.HandleFunc("POST /api/v1/login", a.handleLogin)
	mux.Handle("POST /api/v1/logout", a.guard(ScopeRead, a.handleLogout))
	mux.Handle("GET /api/v1/me", a.guard(ScopeRead, a.handleMe))
	mux.Handle("POST /api/v1/me/totp", a.guard(ScopeRead, a.handleTOTPEnrol))
	mux.Handle("POST /api/v1/me/totp/confirm", a.guard(ScopeRead, a.handleTOTPConfirm))
	mux.Handle("POST /api/v1/me/password", a.guard(ScopeRead, a.handleChangePassword))

	mux.Handle("GET /api/v1/users", a.guard(ScopeAdmin, a.handleListUsers))
	mux.Handle("POST /api/v1/users", a.guard(ScopeAdmin, a.handleCreateUser))
	mux.Handle("DELETE /api/v1/users/{name}", a.guard(ScopeAdmin, a.handleDeleteUser))

	mux.Handle("GET /api/v1/tokens", a.guard(ScopeAdmin, a.handleListTokens))
	mux.Handle("POST /api/v1/tokens", a.guard(ScopeAdmin, a.handleCreateToken))
	mux.Handle("DELETE /api/v1/tokens/{id}", a.guard(ScopeAdmin, a.handleRevokeToken))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such endpoint")
	})
	return mux
}

// guard authenticates and authorises before running h.
func (a *API) guard(want Scope, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A browser session is the other way in. It is checked first only
		// because a WebUI request carries no Authorization header.
		if sess, id, ok := a.sessionFrom(r); ok {
			if !csrfOK(r, sess) {
				a.log.Warn("management CSRF check failed",
					slog.String("user", sess.user), slog.String("path", r.URL.Path))
				writeError(w, http.StatusForbidden, "missing or invalid CSRF token")
				return
			}
			if !scopesAllow(sess.scopes, want) {
				writeError(w, http.StatusForbidden, "session lacks the "+string(want)+" scope")
				return
			}
			h(w, r.WithContext(withSession(r.Context(), sess, id)))
			return
		}

		presented, ok := bearer(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="cgdns"`)
			writeError(w, http.StatusUnauthorized, "an API token or a session is required")
			return
		}
		t, err := Verify(a.store, presented, a.now())
		if err != nil {
			// The reason is deliberately not reported: distinguishing an
			// unknown token from a wrong secret helps only an attacker.
			a.log.Warn("management auth failed",
				slog.String("remote", r.RemoteAddr), slog.String("path", r.URL.Path))
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		if !t.Allows(want) {
			a.log.Warn("management scope denied",
				slog.String("token", t.ID), slog.String("want", string(want)),
				slog.String("path", r.URL.Path))
			writeError(w, http.StatusForbidden, "token lacks the "+string(want)+" scope")
			return
		}
		h(w, r)
	})
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", false
	}
	return rest, true
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	s := a.status()
	s.StoreHash = a.store.Hash()
	s.StoreVersion = a.store.Version()
	s.Records = len(a.store.Records())
	writeJSON(w, http.StatusOK, s)
}

func (a *API) handleRecords(w http.ResponseWriter, r *http.Request) {
	records := a.store.Records()
	// Token payloads carry a secret hash, which has no business leaving the
	// node even to an authenticated reader.
	out := make([]control.Record, 0, len(records))
	for _, rec := range records {
		if rec.Kind == control.KindToken {
			rec.Payload = nil
		}
		out = append(out, rec)
	}
	writeJSON(w, http.StatusOK, RecordsResponse{Records: out, Hash: a.store.Hash()})
}

func (a *API) listRecords(kind control.RecordKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := []json.RawMessage{}
		for _, rec := range a.store.Records() {
			if rec.Kind == kind {
				out = append(out, rec.Payload)
			}
		}
		writeJSON(w, http.StatusOK, ListResponse{Items: out, Count: len(out)})
	}
}

func (a *API) getRecord(kind control.RecordKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := normaliseKey(kind, r.PathValue("key"))
		for _, rec := range a.store.Records() {
			if rec.Kind == kind && rec.Key == key {
				writeRaw(w, http.StatusOK, rec.Payload)
				return
			}
		}
		writeError(w, http.StatusNotFound, "no such "+kind.String())
	}
}

// putRecord stores a record under the key in the path.
func (a *API) putRecord(kind control.RecordKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.writeRecord(w, r, kind, normaliseKey(kind, r.PathValue("key")))
	}
}

// postRecord stores a record under the key derived from its own payload.
func (a *API) postRecord(kind control.RecordKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.writeRecord(w, r, kind, "")
	}
}

func (a *API) writeRecord(w http.ResponseWriter, r *http.Request, kind control.RecordKind, key string) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Store the canonical form, not what was typed: the publish path normalises,
	// and a store that disagrees with the policy in force would also make the
	// two nodes in a pair report drift for identical configuration.
	body, err = control.Canonical(kind, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	derived, err := control.KeyFor(kind, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if key == "" {
		key = derived
	} else if key != derived {
		// Filing a record under a key its own contents contradict would leave
		// the store keyed inconsistently with what it holds, and the publish
		// path — which keys off the payload — would disagree with the API.
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("path key %q does not match the record's own key %q", key, derived))
		return
	}

	var payload json.RawMessage = body
	rec, err := a.store.Put(kind, key, payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.log.Info("control record written",
		slog.String("kind", kind.String()), slog.String("key", key),
		slog.Uint64("lamport", rec.Lamport), slog.String("remote", r.RemoteAddr))
	writeJSON(w, http.StatusOK, WriteResponse{
		Kind: kind.String(), Key: key, Lamport: rec.Lamport, Hash: a.store.Hash(),
	})
}

func (a *API) deleteRecord(kind control.RecordKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := normaliseKey(kind, r.PathValue("key"))
		found := false
		for _, rec := range a.store.Records() {
			if rec.Kind == kind && rec.Key == key {
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusNotFound, "no such "+kind.String())
			return
		}
		if _, err := a.store.Delete(kind, key); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.log.Info("control record deleted",
			slog.String("kind", kind.String()), slog.String("key", key),
			slog.String("remote", r.RemoteAddr))
		writeJSON(w, http.StatusOK, DeleteResponse{Deleted: key, Hash: a.store.Hash()})
	}
}

// normaliseKey applies the same canonicalisation the store does, so a lookup
// by "10.0.0.0/8" finds a record filed from a payload saying "10.0.0.1/8".
func normaliseKey(kind control.RecordKind, key string) string {
	key = strings.TrimSpace(key)
	switch kind {
	case control.KindSubscriber:
		if p, err := netip.ParsePrefix(key); err == nil {
			return p.Masked().String()
		}
	case control.KindClass:
		return strings.ToLower(key)
	}
	return key
}

// TokenRequest asks for a new token.
type TokenRequest struct {
	Name   string  `json:"name"`
	Scopes []Scope `json:"scopes"`
	// TTL is a duration string; empty means the token does not expire.
	TTL string `json:"ttl,omitempty"`
}

func (a *API) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := ListTokens(a.store)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tokens == nil {
		tokens = []Token{}
	}
	writeJSON(w, http.StatusOK, TokenListResponse{Tokens: tokens, Count: len(tokens)})
}

func (a *API) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req TokenRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "decoding request: "+err.Error())
		return
	}

	var ttl time.Duration
	if req.TTL != "" {
		ttl, err = time.ParseDuration(req.TTL)
		if err != nil {
			writeError(w, http.StatusBadRequest, "ttl: "+err.Error())
			return
		}
		if ttl <= 0 {
			writeError(w, http.StatusBadRequest, "ttl must be positive")
			return
		}
	}

	t, secret, err := Mint(req.Name, req.Scopes, ttl, a.now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := SaveToken(a.store, t); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.log.Info("api token minted",
		slog.String("id", t.ID), slog.String("name", t.Name),
		slog.String("remote", r.RemoteAddr))

	// The secret appears here and nowhere else, ever.
	minted := MintedToken{ID: t.ID, Name: t.Name, Scopes: t.Scopes, Token: secret}
	if !t.Expires.IsZero() {
		expires := t.Expires
		minted.Expires = &expires
	}
	writeJSON(w, http.StatusCreated, minted)
}

func (a *API) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := RevokeToken(a.store, id); err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			writeError(w, http.StatusNotFound, "no such token")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.log.Info("api token revoked", slog.String("id", id), slog.String("remote", r.RemoteAddr))
	writeJSON(w, http.StatusOK, RevokeResponse{Revoked: id})
}

// maxBody caps a request body. The admin plane handles small records, so this
// bounds what a client can make the node allocate.
const maxBody = 1 << 20

func readBody(r *http.Request) (json.RawMessage, error) {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, fmt.Errorf("request body exceeds %d bytes", maxBody)
		}
		return nil, fmt.Errorf("reading request body: %w", err)
	}
	if len(body) == 0 {
		return nil, errors.New("a request body is required")
	}
	if !json.Valid(body) {
		return nil, errors.New("request body is not valid JSON")
	}
	return body, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRaw(w http.ResponseWriter, code int, payload json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(payload)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, ErrorResponse{Error: msg})
}
