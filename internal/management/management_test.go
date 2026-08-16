package management

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/control"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testStore(t *testing.T) *control.Store {
	t.Helper()
	st, err := control.Open(control.StoreOptions{NodeID: "ns1", Path: filepath.Join(t.TempDir(), "control.json")})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// testAPI returns a handler plus a secret for each scope level.
func testAPI(t *testing.T) (http.Handler, *control.Store, map[Scope]string) {
	t.Helper()
	st := testStore(t)
	api, err := NewAPI(APIOptions{Store: st, Log: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}

	secrets := map[Scope]string{}
	for _, s := range []Scope{ScopeRead, ScopeWrite, ScopeAdmin} {
		tok, secret, err := Mint(string(s)+"-token", []Scope{s}, 0, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := SaveToken(st, tok); err != nil {
			t.Fatal(err)
		}
		secrets[s] = secret
	}
	return api.Handler(), st, secrets
}

func do(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const subJSON = `{"prefix":"203.0.113.0/24","id":"sub-1","class":"default"}`

func TestAPI_RejectsUnauthenticated(t *testing.T) {
	h, _, _ := testAPI(t)

	for _, tc := range []struct{ name, method, path, body string }{
		{"status", "GET", "/api/v1/status", ""},
		{"list", "GET", "/api/v1/subscribers", ""},
		{"write", "PUT", "/api/v1/subscribers/203.0.113.0/24", subJSON},
		{"delete", "DELETE", "/api/v1/subscribers/203.0.113.0/24", ""},
		{"tokens", "GET", "/api/v1/tokens", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, h, tc.method, tc.path, "", tc.body)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("no token: got %d, want 401", w.Code)
			}
		})
	}
}

func TestAPI_RejectsMalformedCredentials(t *testing.T) {
	h, _, secrets := testAPI(t)
	good := secrets[ScopeAdmin]
	id, secret, _ := strings.Cut(good, ".")

	for _, tc := range []struct{ name, header string }{
		{"empty bearer", "Bearer "},
		{"wrong scheme", "Basic " + good},
		{"no separator", "Bearer " + id + secret},
		{"unknown id", "Bearer deadbeefdeadbeef." + secret},
		{"wrong secret", "Bearer " + id + "." + strings.Repeat("a", 64)},
		{"secret as whole token", "Bearer " + secret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/v1/status", nil)
			r.Header.Set("Authorization", tc.header)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s: got %d, want 401", tc.name, w.Code)
			}
		})
	}
}

// A read token must not be able to change anything, and a write token must not
// be able to mint itself more privilege.
func TestAPI_EnforcesScopes(t *testing.T) {
	h, _, secrets := testAPI(t)

	for _, tc := range []struct {
		name, method, path, body string
		token                    Scope
		want                     int
	}{
		{"read reads", "GET", "/api/v1/subscribers", "", ScopeRead, http.StatusOK},
		{"read cannot write", "POST", "/api/v1/subscribers", subJSON, ScopeRead, http.StatusForbidden},
		{"read cannot delete", "DELETE", "/api/v1/subscribers/203.0.113.0/24", "", ScopeRead, http.StatusForbidden},
		{"read cannot list tokens", "GET", "/api/v1/tokens", "", ScopeRead, http.StatusForbidden},
		{"write writes", "POST", "/api/v1/subscribers", subJSON, ScopeWrite, http.StatusOK},
		{"write cannot mint tokens", "POST", "/api/v1/tokens", `{"name":"x","scopes":["admin"]}`, ScopeWrite, http.StatusForbidden},
		{"admin implies read", "GET", "/api/v1/subscribers", "", ScopeAdmin, http.StatusOK},
		{"admin implies write", "POST", "/api/v1/subscribers", subJSON, ScopeAdmin, http.StatusOK},
		{"admin mints tokens", "POST", "/api/v1/tokens", `{"name":"x","scopes":["read"]}`, ScopeAdmin, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, h, tc.method, tc.path, secrets[tc.token], tc.body)
			if w.Code != tc.want {
				t.Fatalf("%s: got %d, want %d (%s)", tc.name, w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestAPI_RecordLifecycle(t *testing.T) {
	h, st, secrets := testAPI(t)
	admin := secrets[ScopeAdmin]

	if w := do(t, h, "POST", "/api/v1/subscribers", admin, subJSON); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}

	w := do(t, h, "GET", "/api/v1/subscribers/203.0.113.0/24", admin, "")
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	var got control.SubscriberRecord
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "sub-1" || got.Class != "default" {
		t.Fatalf("got %+v", got)
	}

	// The record must reach the published state, not just the store.
	state, _ := st.State()
	if subs := state.Subscribers(); len(subs) != 1 || subs[0].Prefix != "203.0.113.0/24" {
		t.Fatalf("record did not reach published state: %+v", subs)
	}

	if w := do(t, h, "DELETE", "/api/v1/subscribers/203.0.113.0/24", admin, ""); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, h, "GET", "/api/v1/subscribers/203.0.113.0/24", admin, ""); w.Code != http.StatusNotFound {
		t.Fatalf("get after delete: %d", w.Code)
	}
	if w := do(t, h, "DELETE", "/api/v1/subscribers/203.0.113.0/24", admin, ""); w.Code != http.StatusNotFound {
		t.Fatalf("second delete: %d", w.Code)
	}
}

// The publish path drops invalid records silently, so the API has to be the
// thing that says no. A 200 for a record that never takes effect is the bug
// this guards.
func TestAPI_RejectsRecordsThePublishPathWouldDrop(t *testing.T) {
	h, st, secrets := testAPI(t)
	admin := secrets[ScopeAdmin]

	for _, tc := range []struct{ name, path, body string }{
		{"host bits set", "/api/v1/subscribers", `{"prefix":"203.0.113.5/24","class":"default"}`},
		{"no class", "/api/v1/subscribers", `{"prefix":"203.0.113.0/24"}`},
		{"bad prefix", "/api/v1/subscribers", `{"prefix":"not-a-prefix","class":"default"}`},
		{"override without id", "/api/v1/overrides", `{"allow":["example.com"]}`},
		{"feed without name", "/api/v1/feeds", `{"format":"rpz"}`},
		{"feed bad format", "/api/v1/feeds", `{"name":"f","format":"nonsense"}`},
		{"class without name", "/api/v1/classes", `{"action":"nxdomain"}`},
		{"not json", "/api/v1/subscribers", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := do(t, h, "POST", tc.path, admin, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: got %d, want 400 (%s)", tc.name, w.Code, w.Body.String())
			}
		})
	}

	if n := len(st.Records()); n != 3 {
		t.Fatalf("a rejected record reached the store: %d records, want the 3 tokens", n)
	}
}

// Filing a record under a key its own payload contradicts would leave the store
// disagreeing with the publish path, which keys off the payload.
func TestAPI_RejectsKeyMismatch(t *testing.T) {
	h, _, secrets := testAPI(t)
	w := do(t, h, "PUT", "/api/v1/subscribers/198.51.100.0/24", secrets[ScopeAdmin], subJSON)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "does not match") {
		t.Fatalf("unhelpful error: %s", w.Body.String())
	}
}

// A prefix with host bits is canonicalised by the store, so a lookup by the
// canonical form must find it.
func TestAPI_KeysAreCanonical(t *testing.T) {
	h, _, secrets := testAPI(t)
	admin := secrets[ScopeAdmin]

	if w := do(t, h, "POST", "/api/v1/classes", admin, `{"name":"Filtered","action":"nxdomain"}`); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	// The store lowercases class names, so either case must resolve.
	for _, key := range []string{"filtered", "FILTERED", "Filtered"} {
		if w := do(t, h, "GET", "/api/v1/classes/"+key, admin, ""); w.Code != http.StatusOK {
			t.Fatalf("get %q: %d", key, w.Code)
		}
	}
}

func TestToken_ExpiryIsEnforced(t *testing.T) {
	st := testStore(t)
	base := time.Now()
	api, err := NewAPI(APIOptions{Store: st, Log: quietLogger(), Now: func() time.Time { return base }})
	if err != nil {
		t.Fatal(err)
	}
	h := api.Handler()

	tok, secret, err := Mint("short", []Scope{ScopeRead}, time.Hour, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveToken(st, tok); err != nil {
		t.Fatal(err)
	}

	if w := do(t, h, "GET", "/api/v1/status", secret, ""); w.Code != http.StatusOK {
		t.Fatalf("before expiry: %d", w.Code)
	}

	base = base.Add(2 * time.Hour)
	if w := do(t, h, "GET", "/api/v1/status", secret, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("after expiry: got %d, want 401", w.Code)
	}
}

func TestToken_RevocationTakesEffect(t *testing.T) {
	h, st, secrets := testAPI(t)
	admin := secrets[ScopeAdmin]

	w := do(t, h, "POST", "/api/v1/tokens", admin, `{"name":"temp","scopes":["read"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint: %d %s", w.Code, w.Body.String())
	}
	var minted struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	if minted.Token == "" || minted.ID == "" {
		t.Fatal("mint returned no credential")
	}

	if w := do(t, h, "GET", "/api/v1/status", minted.Token, ""); w.Code != http.StatusOK {
		t.Fatalf("new token should work: %d", w.Code)
	}
	if w := do(t, h, "DELETE", "/api/v1/tokens/"+minted.ID, admin, ""); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if w := do(t, h, "GET", "/api/v1/status", minted.Token, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token still works: %d", w.Code)
	}

	// A revocation must be a tombstone, or the sibling resurrects the token on
	// rejoin and the credential comes back from the dead.
	var tombstoned bool
	for _, rec := range st.All() {
		if rec.Kind == control.KindToken && rec.Key == minted.ID && rec.Deleted {
			tombstoned = true
		}
	}
	if !tombstoned {
		t.Fatal("revoked token left no tombstone, so a peer would resurrect it")
	}
}

// A token's hash must never leave the node, even to an authenticated reader.
func TestAPI_NeverDisclosesTokenSecrets(t *testing.T) {
	h, _, secrets := testAPI(t)
	admin := secrets[ScopeAdmin]

	knownHash := hashSecret(strings.SplitN(admin, ".", 2)[1])

	for _, path := range []string{"/api/v1/tokens", "/api/v1/records"} {
		w := do(t, h, "GET", path, admin, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, w.Code)
		}
		body := w.Body.String()
		if strings.Contains(body, knownHash) {
			t.Fatalf("%s disclosed a token hash", path)
		}
		if strings.Contains(body, strings.SplitN(admin, ".", 2)[1]) {
			t.Fatalf("%s disclosed a token secret", path)
		}
	}
}

func TestMint_Rejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tname  string
		scopes []Scope
	}{
		{"no name", "", []Scope{ScopeRead}},
		{"blank name", "   ", []Scope{ScopeRead}},
		{"no scopes", "x", nil},
		{"unknown scope", "x", []Scope{Scope("root")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := Mint(tc.tname, tc.scopes, 0, time.Now()); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// Two mints must never collide, and a secret must never be derivable from the
// ID that accompanies it.
func TestMint_ProducesDistinctCredentials(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		tok, secret, err := Mint("x", []Scope{ScopeRead}, 0, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok.ID] {
			t.Fatalf("duplicate token ID %s", tok.ID)
		}
		seen[tok.ID] = true

		id, sec, ok := splitPresented(secret)
		if !ok || id != tok.ID {
			t.Fatalf("presented form %q does not carry the ID", secret)
		}
		if len(sec) != secretBytes*2 {
			t.Fatalf("secret is %d chars, want %d", len(sec), secretBytes*2)
		}
		if tok.Hash != hashSecret(sec) {
			t.Fatal("stored hash does not match the secret")
		}
	}
}

func TestBootstrap(t *testing.T) {
	st := testStore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "bootstrap.token")

	if err := Bootstrap(st, path, time.Now(), quietLogger()); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimSpace(string(raw))

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("bootstrap token file is %o, want 600", perm)
	}

	tok, err := Verify(st, secret, time.Now())
	if err != nil {
		t.Fatalf("bootstrap secret does not authenticate: %v", err)
	}
	if !tok.Allows(ScopeAdmin) {
		t.Fatal("bootstrap token is not admin")
	}

	// A node that already has a token must not mint a second one, or a
	// rejoining node would grow a credential every restart.
	before := len(st.Records())
	if err := Bootstrap(st, filepath.Join(dir, "again.token"), time.Now(), quietLogger()); err != nil {
		t.Fatal(err)
	}
	if len(st.Records()) != before {
		t.Fatal("bootstrap minted a second token")
	}
	if _, err := os.Stat(filepath.Join(dir, "again.token")); !os.IsNotExist(err) {
		t.Fatal("bootstrap wrote a token file despite having a token")
	}
}

// A token adopted from the sibling counts, so a rejoining node does not mint
// its own credential the operator does not know about.
func TestBootstrap_SkipsWhenPeerSuppliedAToken(t *testing.T) {
	st := testStore(t)
	tok, _, err := Mint("from-peer", []Scope{ScopeAdmin}, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveToken(st, tok); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "bootstrap.token")
	if err := Bootstrap(st, path, time.Now(), quietLogger()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("bootstrapped despite the peer having supplied a token")
	}
}

func TestScope_Implies(t *testing.T) {
	for _, tc := range []struct {
		have, want Scope
		ok         bool
	}{
		{ScopeAdmin, ScopeAdmin, true},
		{ScopeAdmin, ScopeWrite, true},
		{ScopeAdmin, ScopeRead, true},
		{ScopeWrite, ScopeWrite, true},
		{ScopeWrite, ScopeRead, true},
		{ScopeWrite, ScopeAdmin, false},
		{ScopeRead, ScopeRead, true},
		{ScopeRead, ScopeWrite, false},
		{ScopeRead, ScopeAdmin, false},
		{Scope("bogus"), ScopeRead, false},
	} {
		if got := tc.have.implies(tc.want); got != tc.ok {
			t.Fatalf("%s implies %s = %v, want %v", tc.have, tc.want, got, tc.ok)
		}
	}
}

func TestAPI_RejectsOversizedBody(t *testing.T) {
	h, _, secrets := testAPI(t)
	huge := `{"prefix":"203.0.113.0/24","class":"` + strings.Repeat("a", maxBody) + `"}`
	w := do(t, h, "POST", "/api/v1/subscribers", secrets[ScopeAdmin], huge)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", w.Code)
	}
}

func TestAPI_UnknownEndpoint(t *testing.T) {
	h, _, secrets := testAPI(t)
	w := do(t, h, "GET", "/api/v1/nonsense", secrets[ScopeAdmin], "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}

// The store must hold what the publish path will hold. If it holds what was
// typed instead, the API lies about the policy in force, and two nodes given
// the same policy in different case report drift against each other forever.
func TestAPI_StoresTheCanonicalForm(t *testing.T) {
	h, st, secrets := testAPI(t)
	admin := secrets[ScopeAdmin]

	body := `{"subscriber_id":"acme","allow":["Zebra.example","Example.COM","example.com"],"block":["Malware.Test"]}`
	if w := do(t, h, "POST", "/api/v1/overrides", admin, body); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}

	w := do(t, h, "GET", "/api/v1/overrides/acme", admin, "")
	var got control.OverrideRecord
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}

	want := []string{"example.com", "zebra.example"}
	if len(got.Allow) != len(want) {
		t.Fatalf("allow = %v, want %v (lowercased, sorted, deduped)", got.Allow, want)
	}
	for i := range want {
		if got.Allow[i] != want[i] {
			t.Fatalf("allow = %v, want %v", got.Allow, want)
		}
	}
	if len(got.Block) != 1 || got.Block[0] != "malware.test" {
		t.Fatalf("block = %v, want [malware.test]", got.Block)
	}

	// What the API returns must equal what the resolver will enforce.
	state, _ := st.State()
	published := state.Overrides()
	if len(published) != 1 {
		t.Fatalf("published %d overrides, want 1", len(published))
	}
	if fmt.Sprint(published[0]) != fmt.Sprint(got) {
		t.Fatalf("store holds %+v but the publish path holds %+v", got, published[0])
	}
}

// Two nodes given the same policy in different case must agree on the store
// hash, because that hash is the only drift detector a pair has.
func TestAPI_HashAgreesAcrossEquivalentInput(t *testing.T) {
	mk := func(nodeID, body string) string {
		st, err := control.Open(control.StoreOptions{NodeID: nodeID, Path: filepath.Join(t.TempDir(), "control.json")})
		if err != nil {
			t.Fatal(err)
		}
		api, err := NewAPI(APIOptions{Store: st, Log: quietLogger()})
		if err != nil {
			t.Fatal(err)
		}
		tok, secret, err := Mint("admin", []Scope{ScopeAdmin}, 0, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := SaveToken(st, tok); err != nil {
			t.Fatal(err)
		}
		h := api.Handler()
		if w := do(t, h, "POST", "/api/v1/overrides", secret, body); w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", nodeID, w.Code, w.Body.String())
		}
		// Hash only the override, so the differing token records do not mask
		// the comparison.
		for _, rec := range st.Records() {
			if rec.Kind == control.KindOverride {
				return string(rec.Payload)
			}
		}
		t.Fatal("no override stored")
		return ""
	}

	a := mk("ns1", `{"subscriber_id":"acme","allow":["Example.COM","zebra.example"]}`)
	b := mk("ns2", `{"subscriber_id":"acme","allow":["zebra.EXAMPLE","example.com"]}`)
	if a != b {
		t.Fatalf("equivalent policy stored differently:\n ns1 %s\n ns2 %s", a, b)
	}
}
