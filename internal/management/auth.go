package management

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/JoshFinlayAU/cgdns/internal/control"
)

// sessionCtxKey carries the authenticated session into a handler.
type sessionCtxKey struct{}

type sessionCtx struct {
	sess session
	id   string
}

func withSession(ctx context.Context, s session, id string) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, sessionCtx{sess: s, id: id})
}

func sessionOf(ctx context.Context) (sessionCtx, bool) {
	v, ok := ctx.Value(sessionCtxKey{}).(sessionCtx)
	return v, ok
}

// scopesAllow reports whether any scope in the set grants want.
func scopesAllow(have []Scope, want Scope) bool {
	for _, s := range have {
		if s.implies(want) {
			return true
		}
	}
	return false
}

// LoginRequest is a WebUI login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// Code is the TOTP code, required once enrolment is confirmed.
	Code string `json:"code,omitempty"`
}

// LoginResponse tells the UI who it is and how to make writes.
type LoginResponse struct {
	User   string  `json:"user"`
	Scopes []Scope `json:"scopes"`
	// CSRF must be echoed in the X-CGDNS-CSRF header on state-changing
	// requests. It is returned in the body rather than a cookie precisely so
	// that a browser will not attach it automatically.
	CSRF string `json:"csrf"`
	// TOTPEnrolled reports whether a second factor is active, so the UI can
	// prompt for enrolment.
	TOTPEnrolled bool `json:"totp_enrolled"`
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req LoginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "decoding request: "+err.Error())
		return
	}

	u, err := Authenticate(a.store, req.Username, req.Password, req.Code, a.now())
	switch {
	case errors.Is(err, ErrTOTPRequired):
		// Distinguishing "needs a code" from "wrong credentials" is safe: the
		// password was already correct, so it reveals nothing the caller does
		// not know.
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":         "a TOTP code is required",
			"totp_required": true,
		})
		return
	case err != nil:
		a.log.Warn("management login failed",
			slog.String("user", strings.ToLower(req.Username)),
			slog.String("remote", r.RemoteAddr))
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	id, csrf, err := a.sessions.Create(u)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	setCookie(w, id, a.sessions.ttl)

	u.LastLogin = a.now().UTC()
	if err := SaveUser(a.store, u); err != nil {
		// Advisory only; a failure here must not deny a valid login.
		a.log.Warn("recording last login failed", slog.String("err", err.Error()))
	}

	a.log.Info("management login",
		slog.String("user", u.Name), slog.String("remote", r.RemoteAddr))
	writeJSON(w, http.StatusOK, LoginResponse{
		User: u.Name, Scopes: u.Scopes, CSRF: csrf, TOTPEnrolled: u.TOTPConfirmed,
	})
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sc, ok := sessionOf(r.Context()); ok {
		a.sessions.Destroy(sc.id)
		a.log.Info("management logout", slog.String("user", sc.sess.user))
	}
	clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// Identity describes the caller.
type Identity struct {
	// Kind is "session" or "token".
	Kind         string  `json:"kind"`
	Name         string  `json:"name"`
	Scopes       []Scope `json:"scopes"`
	TOTPEnrolled bool    `json:"totp_enrolled"`
}

func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	sc, ok := sessionOf(r.Context())
	if !ok {
		// A token holder has no user record; report what is known.
		writeJSON(w, http.StatusOK, Identity{Kind: "token"})
		return
	}
	id := Identity{Kind: "session", Name: sc.sess.user, Scopes: sc.sess.scopes}
	if u, err := LoadUser(a.store, sc.sess.user); err == nil {
		id.TOTPEnrolled = u.TOTPConfirmed
	}
	writeJSON(w, http.StatusOK, id)
}

// TOTPEnrolment is handed to the operator once, to put into an authenticator.
type TOTPEnrolment struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// handleTOTPEnrol issues a secret. It does not take effect until confirmed, so
// an abandoned enrolment cannot lock anyone out.
func (a *API) handleTOTPEnrol(w http.ResponseWriter, r *http.Request) {
	sc, ok := sessionOf(r.Context())
	if !ok {
		writeError(w, http.StatusForbidden, "TOTP enrolment needs a logged-in session, not an API token")
		return
	}
	u, err := LoadUser(a.store, sc.sess.user)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}
	if u.TOTPConfirmed {
		// Re-enrolling would silently invalidate the operator's existing
		// authenticator entry.
		writeError(w, http.StatusConflict, "TOTP is already enrolled; remove it first")
		return
	}

	secret, err := NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	u.TOTPSecret = secret
	u.TOTPConfirmed = false
	if err := SaveUser(a.store, u); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, TOTPEnrolment{Secret: secret, URI: TOTPURI(a.issuer, u.Name, secret)})
}

// handleTOTPConfirm activates a second factor once the operator proves they can
// generate codes from it.
func (a *API) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	sc, ok := sessionOf(r.Context())
	if !ok {
		writeError(w, http.StatusForbidden, "TOTP enrolment needs a logged-in session")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "decoding request: "+err.Error())
		return
	}

	u, err := LoadUser(a.store, sc.sess.user)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}
	if u.TOTPSecret == "" {
		writeError(w, http.StatusBadRequest, "no enrolment in progress")
		return
	}
	if !digitsOnly(req.Code) || !VerifyTOTP(u.TOTPSecret, req.Code, a.now()) {
		writeError(w, http.StatusUnauthorized, "that code does not match the secret")
		return
	}

	u.TOTPConfirmed = true
	if err := SaveUser(a.store, u); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.log.Info("TOTP enrolled", slog.String("user", u.Name))
	writeJSON(w, http.StatusOK, map[string]bool{"totp_enrolled": true})
}

func (a *API) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	sc, ok := sessionOf(r.Context())
	if !ok {
		writeError(w, http.StatusForbidden, "changing a password needs a logged-in session")
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "decoding request: "+err.Error())
		return
	}

	u, err := LoadUser(a.store, sc.sess.user)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such user")
		return
	}
	// The current password is required even though the session is already
	// authenticated: a session left open on an unlocked screen must not be
	// enough to take the account over.
	if !VerifyPassword(u.Hash, req.Current) {
		writeError(w, http.StatusUnauthorized, "the current password is wrong")
		return
	}

	hash, err := HashPassword(req.New)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u.Hash = hash
	if err := SaveUser(a.store, u); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Every other session for this user dies with the old password.
	a.sessions.DestroyUser(u.Name)
	clearCookie(w)
	a.log.Info("password changed", slog.String("user", u.Name))
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed, log in again"})
}

// CreateUserRequest creates an operator account.
type CreateUserRequest struct {
	Name     string  `json:"name"`
	Password string  `json:"password"`
	Scopes   []Scope `json:"scopes"`
}

func (a *API) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := ListUsers(a.store)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if users == nil {
		users = []User{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users, "count": len(users)})
}

func (a *API) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req CreateUserRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "decoding request: "+err.Error())
		return
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []Scope{ScopeRead}
	}

	hash, err := HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u := User{Name: req.Name, Hash: hash, Scopes: req.Scopes, Created: a.now().UTC()}
	if err := SaveUser(a.store, u); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	a.log.Info("operator account created",
		slog.String("user", u.Name), slog.String("remote", r.RemoteAddr))
	writeJSON(w, http.StatusCreated, map[string]any{
		"name": strings.ToLower(strings.TrimSpace(req.Name)), "scopes": req.Scopes,
	})
}

func (a *API) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSpace(r.PathValue("name")))

	// Removing the last admin would leave the pair with no way to be managed
	// through the UI at all.
	if last, err := isLastAdmin(a.store, name); err == nil && last {
		writeError(w, http.StatusConflict, "that is the only admin account left; create another before removing it")
		return
	}

	if err := DeleteUser(a.store, name); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "no such user")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Their sessions go with them, rather than living on until expiry.
	a.sessions.DestroyUser(name)
	a.log.Info("operator account deleted",
		slog.String("user", name), slog.String("remote", r.RemoteAddr))
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

// isLastAdmin reports whether name is the only account holding admin.
func isLastAdmin(store *control.Store, name string) (bool, error) {
	users, err := ListUsers(store)
	if err != nil {
		return false, err
	}
	admins := 0
	isAdmin := false
	for _, u := range users {
		if u.Disabled || !scopesAllow(u.Scopes, ScopeAdmin) {
			continue
		}
		admins++
		if u.Name == name {
			isAdmin = true
		}
	}
	return isAdmin && admins == 1, nil
}
