package management

import (
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/control"
)

const testPassword = "a perfectly fine password"

// uiAPI returns a handler with one admin operator account.
func uiAPI(t *testing.T) (*API, http.Handler, *control.Store) {
	t.Helper()
	st := testStore(t)
	api, err := NewAPI(APIOptions{Store: st, Log: quietLogger(), Issuer: "cgdns-test"})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveUser(st, User{Name: "jo", Hash: hash, Scopes: []Scope{ScopeAdmin}}); err != nil {
		t.Fatal(err)
	}
	return api, api.Handler(), st
}

// login performs a login and returns the session cookie and CSRF token.
func login(t *testing.T, h http.Handler, user, pass, code string) (*http.Cookie, string, int) {
	t.Helper()
	body, _ := json.Marshal(LoginRequest{Username: user, Password: pass, Code: code})
	r := httptest.NewRequest("POST", "/api/v1/login", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		return nil, "", w.Code
	}
	var resp LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			return c, resp.CSRF, w.Code
		}
	}
	t.Fatal("login returned no session cookie")
	return nil, "", 0
}

// asSession issues a request carrying the session cookie and CSRF token.
func asSession(t *testing.T, h http.Handler, c *http.Cookie, csrf, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if c != nil {
		r.AddCookie(c)
	}
	if csrf != "" {
		r.Header.Set(csrfHeader, csrf)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestLogin_Succeeds(t *testing.T) {
	_, h, _ := uiAPI(t)
	c, csrf, code := login(t, h, "jo", testPassword, "")
	if code != http.StatusOK {
		t.Fatalf("login returned %d", code)
	}
	if c.Value == "" || csrf == "" {
		t.Fatal("login returned an empty session or CSRF token")
	}

	// The cookie must not be readable by script, must not travel in clear, and
	// must not be sent on cross-site requests.
	if !c.HttpOnly {
		t.Fatal("session cookie is not HttpOnly, so script can read it")
	}
	if !c.Secure {
		t.Fatal("session cookie is not Secure, so it can travel in clear")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatal("session cookie is not SameSite=Strict")
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Fatalf("cookie %q lacks the __Host- prefix, so it can be planted by a sibling host", c.Name)
	}
}

func TestLogin_RejectsBadCredentials(t *testing.T) {
	_, h, _ := uiAPI(t)
	for _, tc := range []struct{ name, user, pass string }{
		{"wrong password", "jo", "not the password at all"},
		{"unknown user", "nobody", testPassword},
		{"empty password", "jo", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, code := login(t, h, tc.user, tc.pass, ""); code != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", code)
			}
		})
	}
}

// A session must work exactly like a token for reads.
func TestSession_AuthenticatesRequests(t *testing.T) {
	_, h, _ := uiAPI(t)
	c, csrf, _ := login(t, h, "jo", testPassword, "")

	if w := asSession(t, h, c, "", "GET", "/api/v1/status", ""); w.Code != http.StatusOK {
		t.Fatalf("GET with a session returned %d", w.Code)
	}
	w := asSession(t, h, c, csrf, "POST", "/api/v1/subscribers", `{"prefix":"203.0.113.0/24","class":"default"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST with a session and CSRF returned %d: %s", w.Code, w.Body)
	}
}

// The whole point of the CSRF token: another origin may be able to make the
// browser send the cookie, but it cannot produce this header.
func TestSession_WriteWithoutCSRFIsRefused(t *testing.T) {
	_, h, _ := uiAPI(t)
	c, csrf, _ := login(t, h, "jo", testPassword, "")

	for _, tc := range []struct{ name, token string }{
		{"absent", ""},
		{"wrong", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"another session's", func() string { _, other, _ := login(t, h, "jo", testPassword, ""); return other }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := asSession(t, h, c, tc.token, "POST", "/api/v1/subscribers", `{"prefix":"203.0.113.0/24","class":"default"}`)
			if w.Code != http.StatusForbidden {
				t.Fatalf("got %d, want 403", w.Code)
			}
		})
	}

	// Reads are unaffected: they change nothing.
	if w := asSession(t, h, c, "", "GET", "/api/v1/subscribers", ""); w.Code != http.StatusOK {
		t.Fatalf("a read without CSRF returned %d", w.Code)
	}
	_ = csrf
}

func TestSession_ScopesAreEnforced(t *testing.T) {
	st := testStore(t)
	api, err := NewAPI(APIOptions{Store: st, Log: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveUser(st, User{Name: "reader", Hash: hash, Scopes: []Scope{ScopeRead}}); err != nil {
		t.Fatal(err)
	}
	h := api.Handler()

	c, csrf, _ := login(t, h, "reader", testPassword, "")
	if w := asSession(t, h, c, "", "GET", "/api/v1/status", ""); w.Code != http.StatusOK {
		t.Fatalf("read returned %d", w.Code)
	}
	if w := asSession(t, h, c, csrf, "POST", "/api/v1/subscribers", `{"prefix":"203.0.113.0/24","class":"default"}`); w.Code != http.StatusForbidden {
		t.Fatalf("a read-only session wrote: %d", w.Code)
	}
	if w := asSession(t, h, c, "", "GET", "/api/v1/users", ""); w.Code != http.StatusForbidden {
		t.Fatalf("a read-only session listed users: %d", w.Code)
	}
}

func TestLogout_EndsTheSession(t *testing.T) {
	_, h, _ := uiAPI(t)
	c, csrf, _ := login(t, h, "jo", testPassword, "")

	if w := asSession(t, h, c, csrf, "POST", "/api/v1/logout", ""); w.Code != http.StatusOK {
		t.Fatalf("logout returned %d", w.Code)
	}
	if w := asSession(t, h, c, "", "GET", "/api/v1/status", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("the session still worked after logout: %d", w.Code)
	}
}

func TestSession_Expires(t *testing.T) {
	st := testStore(t)
	base := time.Now()
	api, err := NewAPI(APIOptions{
		Store: st, Log: quietLogger(),
		Now:        func() time.Time { return base },
		SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := HashPassword(testPassword)
	if err := SaveUser(st, User{Name: "jo", Hash: hash, Scopes: []Scope{ScopeAdmin}}); err != nil {
		t.Fatal(err)
	}
	h := api.Handler()

	c, _, _ := login(t, h, "jo", testPassword, "")
	if w := asSession(t, h, c, "", "GET", "/api/v1/status", ""); w.Code != http.StatusOK {
		t.Fatalf("fresh session returned %d", w.Code)
	}

	base = base.Add(2 * time.Hour)
	if w := asSession(t, h, c, "", "GET", "/api/v1/status", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("an expired session still worked: %d", w.Code)
	}
	if n := api.Sessions().Active.Load(); n != 0 {
		t.Fatalf("%d sessions still counted as active", n)
	}
}

// TOTP enrolment must not gate logins until the operator has proved they can
// generate codes, or a half-finished enrolment locks them out.
func TestTOTPEnrolmentFlow(t *testing.T) {
	api, h, st := uiAPI(t)
	c, csrf, _ := login(t, h, "jo", testPassword, "")

	w := asSession(t, h, c, csrf, "POST", "/api/v1/me/totp", "")
	if w.Code != http.StatusOK {
		t.Fatalf("enrolment returned %d: %s", w.Code, w.Body)
	}
	var enrol TOTPEnrolment
	if err := json.Unmarshal(w.Body.Bytes(), &enrol); err != nil {
		t.Fatal(err)
	}
	if enrol.Secret == "" || !strings.Contains(enrol.URI, "otpauth://totp/") {
		t.Fatalf("enrolment returned %+v", enrol)
	}

	// Still unconfirmed: logging in without a code must work.
	if _, _, code := login(t, h, "jo", testPassword, ""); code != http.StatusOK {
		t.Fatalf("login during enrolment returned %d", code)
	}

	// A wrong code must not confirm it.
	if w := asSession(t, h, c, csrf, "POST", "/api/v1/me/totp/confirm", `{"code":"000001"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong confirmation code returned %d", w.Code)
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrol.Secret)
	if err != nil {
		t.Fatal(err)
	}
	good := hotp(key, api.now().Unix()/30)
	if w := asSession(t, h, c, csrf, "POST", "/api/v1/me/totp/confirm", `{"code":"`+good+`"}`); w.Code != http.StatusOK {
		t.Fatalf("confirmation returned %d: %s", w.Code, w.Body)
	}

	// Now a code is mandatory.
	if _, _, code := login(t, h, "jo", testPassword, ""); code != http.StatusUnauthorized {
		t.Fatalf("login without a code returned %d, want 401", code)
	}
	if _, _, code := login(t, h, "jo", testPassword, hotp(key, api.now().Unix()/30)); code != http.StatusOK {
		t.Fatalf("login with a valid code returned %d", code)
	}

	u, err := LoadUser(st, "jo")
	if err != nil {
		t.Fatal(err)
	}
	if !u.TOTPConfirmed {
		t.Fatal("the user record does not record the enrolment")
	}
}

// Re-enrolling would silently invalidate the operator's existing authenticator
// entry, which is a good way to lock someone out by accident.
func TestTOTP_RefusesToReEnrolWhileActive(t *testing.T) {
	api, h, st := uiAPI(t)
	u, _ := LoadUser(st, "jo")
	secret, _ := NewTOTPSecret()
	u.TOTPSecret, u.TOTPConfirmed = secret, true
	if err := SaveUser(st, u); err != nil {
		t.Fatal(err)
	}

	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	c, csrf, code := login(t, h, "jo", testPassword, hotp(key, api.now().Unix()/30))
	if code != http.StatusOK {
		t.Fatalf("login returned %d", code)
	}
	if w := asSession(t, h, c, csrf, "POST", "/api/v1/me/totp", ""); w.Code != http.StatusConflict {
		t.Fatalf("re-enrolment returned %d, want 409", w.Code)
	}
}

// A session left open on an unlocked screen must not be enough to take the
// account over.
func TestChangePassword_RequiresTheCurrentOne(t *testing.T) {
	_, h, _ := uiAPI(t)
	c, csrf, _ := login(t, h, "jo", testPassword, "")

	w := asSession(t, h, c, csrf, "POST", "/api/v1/me/password",
		`{"current":"the wrong one entirely","new":"a brand new fine password"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("changing without the current password returned %d", w.Code)
	}

	w = asSession(t, h, c, csrf, "POST", "/api/v1/me/password",
		`{"current":"`+testPassword+`","new":"a brand new fine password"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("password change returned %d: %s", w.Code, w.Body)
	}

	// The old sessions die with the old password.
	if w := asSession(t, h, c, "", "GET", "/api/v1/status", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("the old session survived a password change: %d", w.Code)
	}
	if _, _, code := login(t, h, "jo", "a brand new fine password", ""); code != http.StatusOK {
		t.Fatalf("login with the new password returned %d", code)
	}
	if _, _, code := login(t, h, "jo", testPassword, ""); code != http.StatusUnauthorized {
		t.Fatal("the old password still works")
	}
}

// Removing the last admin would leave the pair with no way to be managed
// through the UI at all.
func TestDeleteUser_RefusesTheLastAdmin(t *testing.T) {
	_, h, _ := uiAPI(t)
	c, csrf, _ := login(t, h, "jo", testPassword, "")

	if w := asSession(t, h, c, csrf, "DELETE", "/api/v1/users/jo", ""); w.Code != http.StatusConflict {
		t.Fatalf("deleting the only admin returned %d, want 409", w.Code)
	}

	// With a second admin it is allowed.
	w := asSession(t, h, c, csrf, "POST", "/api/v1/users",
		`{"name":"sam","password":"another fine password","scopes":["admin"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating a second admin returned %d: %s", w.Code, w.Body)
	}
	if w := asSession(t, h, c, csrf, "DELETE", "/api/v1/users/jo", ""); w.Code != http.StatusOK {
		t.Fatalf("deleting one of two admins returned %d", w.Code)
	}
}

// Deleting an account must end its sessions at once, not at the next expiry.
func TestDeleteUser_EndsTheirSessions(t *testing.T) {
	_, h, _ := uiAPI(t)
	admin, adminCSRF, _ := login(t, h, "jo", testPassword, "")

	w := asSession(t, h, admin, adminCSRF, "POST", "/api/v1/users",
		`{"name":"sam","password":"another fine password","scopes":["read"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating the user returned %d: %s", w.Code, w.Body)
	}

	sam, _, _ := login(t, h, "sam", "another fine password", "")
	if w := asSession(t, h, sam, "", "GET", "/api/v1/status", ""); w.Code != http.StatusOK {
		t.Fatalf("sam's session did not work: %d", w.Code)
	}

	if w := asSession(t, h, admin, adminCSRF, "DELETE", "/api/v1/users/sam", ""); w.Code != http.StatusOK {
		t.Fatalf("deleting sam returned %d", w.Code)
	}
	if w := asSession(t, h, sam, "", "GET", "/api/v1/status", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("a deleted user's session still worked: %d", w.Code)
	}
}

// The user listing must never disclose a hash or a TOTP secret.
func TestListUsers_DisclosesNoSecrets(t *testing.T) {
	_, h, st := uiAPI(t)
	u, _ := LoadUser(st, "jo")
	secret, _ := NewTOTPSecret()
	u.TOTPSecret = secret
	if err := SaveUser(st, u); err != nil {
		t.Fatal(err)
	}

	c, _, _ := login(t, h, "jo", testPassword, "")
	w := asSession(t, h, c, "", "GET", "/api/v1/users", "")
	if w.Code != http.StatusOK {
		t.Fatalf("listing returned %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "$argon2id$") {
		t.Fatal("the listing disclosed a password hash")
	}
	if strings.Contains(body, secret) {
		t.Fatal("the listing disclosed a TOTP secret")
	}
}

// An API token must not be able to enrol a second factor for a user, since it
// is not a user.
func TestTOTPEnrol_RefusesATokenCaller(t *testing.T) {
	st := testStore(t)
	api, err := NewAPI(APIOptions{Store: st, Log: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	tok, secret, err := Mint("cli", []Scope{ScopeAdmin}, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveToken(st, tok); err != nil {
		t.Fatal(err)
	}

	h := api.Handler()
	r := httptest.NewRequest("POST", "/api/v1/me/totp", nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("a token enrolled TOTP: %d", w.Code)
	}
}
