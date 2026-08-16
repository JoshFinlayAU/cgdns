package management

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Sessions are node-local and held in memory.
//
// They are deliberately not replicated to the sibling. A session is a bearer
// credential with a short life, and copying one across the link would widen its
// exposure to buy very little: each node has its own management address, so an
// operator who moves to the sibling simply logs in again. Losing them on
// restart is the same trade.
type session struct {
	user    string
	scopes  []Scope
	csrf    string
	expires time.Time
}

// SessionStore holds live WebUI sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]session
	ttl      time.Duration
	now      func() time.Time

	// Active is the number of live sessions.
	Active atomic.Int64
}

// sessionCookie is the cookie name. The __Host- prefix is enforced by browsers:
// it requires Secure, Path=/ and no Domain, so the cookie cannot be planted by
// a sibling host or scoped to a parent domain.
const sessionCookie = "__Host-cgdns_session"

// csrfHeader carries the token that proves a state-changing request came from
// the WebUI rather than from another origin that happens to hold the cookie.
const csrfHeader = "X-CGDNS-CSRF"

// NewSessionStore builds a session store.
func NewSessionStore(ttl time.Duration, now func() time.Time) *SessionStore {
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	if now == nil {
		now = time.Now
	}
	return &SessionStore{sessions: make(map[string]session), ttl: ttl, now: now}
}

// Create starts a session and returns its ID and CSRF token.
func (s *SessionStore) Create(u User) (id, csrf string, err error) {
	if id, err = randomToken(); err != nil {
		return "", "", err
	}
	if csrf, err = randomToken(); err != nil {
		return "", "", err
	}

	s.mu.Lock()
	s.sessions[id] = session{
		user:    u.Name,
		scopes:  append([]Scope(nil), u.Scopes...),
		csrf:    csrf,
		expires: s.now().Add(s.ttl),
	}
	s.mu.Unlock()
	s.Active.Add(1)
	return id, csrf, nil
}

// Lookup returns a live session.
func (s *SessionStore) Lookup(id string) (session, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return session{}, false
	}
	if !s.now().Before(sess.expires) {
		s.Destroy(id)
		return session{}, false
	}
	return sess, true
}

// Destroy ends a session.
func (s *SessionStore) Destroy(id string) {
	s.mu.Lock()
	_, existed := s.sessions[id]
	delete(s.sessions, id)
	s.mu.Unlock()
	if existed {
		s.Active.Add(-1)
	}
}

// DestroyUser ends every session belonging to a user, so disabling or deleting
// an account takes effect immediately rather than at the next expiry.
func (s *SessionStore) DestroyUser(name string) int {
	s.mu.Lock()
	n := 0
	for id, sess := range s.sessions {
		if sess.user == name {
			delete(s.sessions, id)
			n++
		}
	}
	s.mu.Unlock()
	s.Active.Add(-int64(n))
	return n
}

// Sweep drops expired sessions.
func (s *SessionStore) Sweep() int {
	now := s.now()
	s.mu.Lock()
	n := 0
	for id, sess := range s.sessions {
		if !now.Before(sess.expires) {
			delete(s.sessions, id)
			n++
		}
	}
	s.mu.Unlock()
	s.Active.Add(-int64(n))
	return n
}

// randomToken returns 256 bits of hex.
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// setCookie writes the session cookie.
//
// Secure is always set, which is why the plane refuses to run off loopback
// without TLS: a session cookie that can travel in clear is not a session.
func setCookie(w http.ResponseWriter, id string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearCookie expires the session cookie.
func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// sessionFrom resolves the session on a request, if any.
func (a *API) sessionFrom(r *http.Request) (session, string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return session{}, "", false
	}
	sess, ok := a.sessions.Lookup(c.Value)
	if !ok {
		return session{}, "", false
	}
	return sess, c.Value, true
}

// csrfOK checks the double-submit token on a state-changing request.
//
// SameSite=Strict already keeps another origin from causing the browser to send
// this cookie, but it is one flag away from being the only thing standing
// between a cross-site form post and an authenticated write. The token is not
// automatically attached by the browser, so a cross-origin request cannot
// produce it whatever the cookie policy does.
func csrfOK(r *http.Request, sess session) bool {
	if !stateChanging(r.Method) {
		return true
	}
	presented := r.Header.Get(csrfHeader)
	if presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(sess.csrf)) == 1
}

func stateChanging(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}
