package management

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/control"
)

// liveClient starts a real server and returns a client wired to it, so the
// client is tested against the encoder it has to agree with rather than a
// hand-written fixture that could drift from it.
func liveClient(t *testing.T, scope Scope) (*Client, *control.Store) {
	t.Helper()
	st := testStore(t)
	api, err := NewAPI(APIOptions{
		Store: st, Log: quietLogger(),
		Status: func() Status { return Status{NodeID: "ns1", Version: "test", Healthy: true} },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	tok, secret, err := Mint("cli", []Scope{scope}, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveToken(st, tok); err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(ClientOptions{Addr: srv.URL, Token: secret})
	if err != nil {
		t.Fatal(err)
	}
	return c, st
}

func TestClient_StatusAndRecordLifecycle(t *testing.T) {
	c, _ := liveClient(t, ScopeAdmin)

	s, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if s.NodeID != "ns1" || !s.Healthy {
		t.Fatalf("status did not round-trip: %+v", s)
	}

	sub := control.SubscriberRecord{Prefix: "203.0.113.0/24", ID: "acme", Class: "default"}
	payload, err := json.Marshal(sub)
	if err != nil {
		t.Fatal(err)
	}
	wrote, err := c.Put(control.KindSubscriber, payload)
	if err != nil {
		t.Fatal(err)
	}
	if wrote.Key != "203.0.113.0/24" || wrote.Hash == "" {
		t.Fatalf("write response: %+v", wrote)
	}

	// A key containing a slash must survive the round trip.
	raw, err := c.Get(control.KindSubscriber, "203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	var got control.SubscriberRecord
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got != sub {
		t.Fatalf("got %+v, want %+v", got, sub)
	}

	items, err := c.List(control.KindSubscriber)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("list returned %d items, want 1", len(items))
	}

	del, err := c.Delete(control.KindSubscriber, "203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if del.Deleted != "203.0.113.0/24" {
		t.Fatalf("delete response: %+v", del)
	}

	if _, err := c.Get(control.KindSubscriber, "203.0.113.0/24"); err == nil {
		t.Fatal("expected a not-found error after delete")
	}
}

// An IPv6 prefix key carries colons as well as a slash, and IPv6 is not an
// afterthought anywhere else either.
func TestClient_IPv6PrefixKey(t *testing.T) {
	c, _ := liveClient(t, ScopeAdmin)

	sub := control.SubscriberRecord{Prefix: "2001:db8::/32", ID: "v6", Class: "default"}
	payload, _ := json.Marshal(sub)
	if _, err := c.Put(control.KindSubscriber, payload); err != nil {
		t.Fatal(err)
	}

	raw, err := c.Get(control.KindSubscriber, "2001:db8::/32")
	if err != nil {
		t.Fatalf("fetching an IPv6 prefix key: %v", err)
	}
	var got control.SubscriberRecord
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Prefix != "2001:db8::/32" {
		t.Fatalf("got %q", got.Prefix)
	}

	if _, err := c.Delete(control.KindSubscriber, "2001:db8::/32"); err != nil {
		t.Fatalf("deleting an IPv6 prefix key: %v", err)
	}
}

// A server error must reach the caller as an APIError carrying the status, so
// the CLI can tell "does not exist" from "cannot talk to the node".
func TestClient_SurfacesAPIErrors(t *testing.T) {
	c, _ := liveClient(t, ScopeAdmin)

	_, err := c.Get(control.KindSubscriber, "203.0.113.0/24")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T, want *APIError", err)
	}
	if !apiErr.NotFound() {
		t.Fatalf("status %d, want 404", apiErr.Status)
	}
	if apiErr.Message == "" {
		t.Fatal("error carried no message")
	}
}

func TestClient_SurfacesScopeDenial(t *testing.T) {
	c, _ := liveClient(t, ScopeRead)

	payload, _ := json.Marshal(control.SubscriberRecord{Prefix: "203.0.113.0/24", Class: "default"})
	_, err := c.Put(control.KindSubscriber, payload)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("got %T, want *APIError", err)
	}
	if apiErr.Status != 403 {
		t.Fatalf("status %d, want 403", apiErr.Status)
	}
}

func TestClient_TokenLifecycle(t *testing.T) {
	c, _ := liveClient(t, ScopeAdmin)

	minted, err := c.CreateToken(TokenRequest{Name: "cli-made", Scopes: []Scope{ScopeRead}})
	if err != nil {
		t.Fatal(err)
	}
	if minted.Token == "" || minted.ID == "" {
		t.Fatalf("mint returned no credential: %+v", minted)
	}
	if minted.Expires != nil {
		t.Fatalf("a token with no TTL should not expire: %v", minted.Expires)
	}

	tokens, err := c.Tokens()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tok := range tokens {
		if tok.ID == minted.ID {
			found = true
			if tok.Hash != "" {
				t.Fatal("the listing disclosed a token hash")
			}
		}
	}
	if !found {
		t.Fatal("the minted token is not in the listing")
	}

	if err := c.RevokeToken(minted.ID); err != nil {
		t.Fatal(err)
	}

	// The revoked credential must stop working.
	revoked, err := NewClient(ClientOptions{Addr: c.Addr(), Token: minted.Token})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revoked.Status(); err == nil {
		t.Fatal("a revoked token still authenticates")
	}
}

func TestClient_TokenWithTTLReportsExpiry(t *testing.T) {
	c, _ := liveClient(t, ScopeAdmin)

	minted, err := c.CreateToken(TokenRequest{Name: "temp", Scopes: []Scope{ScopeRead}, TTL: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if minted.Expires == nil {
		t.Fatal("a token minted with a TTL reported no expiry")
	}
	if time.Until(*minted.Expires) < 30*time.Minute {
		t.Fatalf("expiry %v is not about an hour away", minted.Expires)
	}
}

func TestNewClient_Rejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts ClientOptions
	}{
		{"no address", ClientOptions{Token: "x"}},
		{"no token", ClientOptions{Addr: "127.0.0.1:8443"}},
		{"bad CA path", ClientOptions{Addr: "127.0.0.1:8443", Token: "x", CAFile: "/nonexistent/ca.pem"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewClient(tc.opts); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// A bare host:port must be treated as HTTPS. Defaulting to plaintext would send
// the credential in the clear the first time someone omitted the scheme.
func TestNewClient_DefaultsToHTTPS(t *testing.T) {
	c, err := NewClient(ClientOptions{Addr: "10.0.0.1:8443", Token: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Addr(); got != "https://10.0.0.1:8443" {
		t.Fatalf("got %q, want https://10.0.0.1:8443", got)
	}
}

func TestPathFor(t *testing.T) {
	for kind, want := range map[control.RecordKind]string{
		control.KindSubscriber: "subscribers",
		control.KindOverride:   "overrides",
		control.KindFeed:       "feeds",
		control.KindClass:      "classes",
	} {
		got, err := pathFor(kind)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s -> %q, want %q", kind, got, want)
		}
	}

	// Tokens have their own endpoints and must not be reachable through the
	// generic record routes, which carry only the write scope.
	if _, err := pathFor(control.KindToken); err == nil {
		t.Fatal("tokens should not be exposed as a generic record kind")
	}
}
