package acme

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func portOpen(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// The port exists for the challenge and for nothing else. A resolver's
// addresses are reachable by subscribers and, through the covering prefix, by
// the internet, so a listener left running between renewals is standing attack
// surface.
func TestHTTP01OpensOnlyForTheChallenge(t *testing.T) {
	addr := freeAddr(t)
	h := &HTTP01{Addrs: []string{addr}, Timeout: 30 * time.Second, Log: quiet()}

	if portOpen(addr) {
		t.Fatal("the port is open before any challenge has started")
	}

	cleanup, err := h.Present(context.Background(), "dns1.example.", "tok123", "tok123.keyauth")
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !portOpen(addr) {
		t.Fatal("the port is not open during the challenge")
	}

	resp, err := http.Get("http://" + addr + challengePrefix + "tok123")
	if err != nil {
		t.Fatalf("fetching the challenge: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if got := string(body); got != "tok123.keyauth" {
		t.Errorf("challenge body = %q, want the key authorization", got)
	}

	cleanup()
	deadline := time.Now().Add(3 * time.Second)
	for portOpen(addr) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if portOpen(addr) {
		t.Error("the port is still open after the challenge finished")
	}
}

// The responder serves exactly one file. Anything else is a 404, so it cannot
// be used to probe the host while it is briefly up.
func TestHTTP01ServesNothingElse(t *testing.T) {
	addr := freeAddr(t)
	h := &HTTP01{Addrs: []string{addr}, Timeout: 30 * time.Second, Log: quiet()}
	cleanup, err := h.Present(context.Background(), "dns1.example.", "right", "right.keyauth")
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	defer cleanup()

	for _, path := range []string{
		challengePrefix + "wrong",
		"/",
		"/index.html",
		"/../etc/passwd",
	} {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			continue
		}
		code := resp.StatusCode
		_ = resp.Body.Close()
		if code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, code)
		}
	}
}

// A stalled validation must not leave the port open. The timeout is independent
// of the caller remembering to clean up.
func TestHTTP01ClosesOnTimeout(t *testing.T) {
	addr := freeAddr(t)
	h := &HTTP01{Addrs: []string{addr}, Timeout: 300 * time.Millisecond, Log: quiet()}

	if _, err := h.Present(context.Background(), "dns1.example.", "tok", "tok.keyauth"); err != nil {
		t.Fatalf("Present: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for portOpen(addr) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if portOpen(addr) {
		t.Error("the port outlived its timeout")
	}
}

// Cancelling the order closes the port too.
func TestHTTP01ClosesOnContextCancel(t *testing.T) {
	addr := freeAddr(t)
	h := &HTTP01{Addrs: []string{addr}, Timeout: time.Minute, Log: quiet()}

	ctx, cancel := context.WithCancel(context.Background())
	if _, err := h.Present(ctx, "dns1.example.", "tok", "tok.keyauth"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	cancel()

	deadline := time.Now().Add(5 * time.Second)
	for portOpen(addr) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if portOpen(addr) {
		t.Error("the port survived cancellation of the order")
	}
}

// Two orders must not race for the port.
func TestHTTP01SerialisesChallenges(t *testing.T) {
	addr := freeAddr(t)
	h := &HTTP01{Addrs: []string{addr}, Timeout: 5 * time.Second, Log: quiet()}

	first, err := h.Present(context.Background(), "a.example.", "one", "one.key")
	if err != nil {
		t.Fatalf("first Present: %v", err)
	}

	started := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(started)
		second, err := h.Present(context.Background(), "b.example.", "two", "two.key")
		if err != nil {
			t.Errorf("second Present: %v", err)
			return
		}
		second()
	}()

	<-started
	time.Sleep(100 * time.Millisecond)
	first()
	wg.Wait()
}

type fakeCFRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

// cloudflareStub is enough of the API to exercise the provider.
func cloudflareStub(t *testing.T, records *[]fakeCFRecord, token *string) *httptest.Server {
	t.Helper()
	mu := &sync.Mutex{}
	next := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if token != nil {
			*token = r.Header.Get("Authorization")
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			name := r.URL.Query().Get("name")
			if name != "example.com" {
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []any{}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  []map[string]string{{"id": "zone1", "name": "example.com"}},
			})

		case r.Method == http.MethodPost:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			next++
			*records = append(*records, fakeCFRecord{
				ID:      fmt.Sprintf("rec%d", next),
				Name:    body["name"].(string),
				Content: body["content"].(string),
			})
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{}})

		case r.Method == http.MethodGet:
			name := r.URL.Query().Get("name")
			var out []fakeCFRecord
			for _, rec := range *records {
				if rec.Name == name {
					out = append(out, rec)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": out})

		case r.Method == http.MethodDelete:
			id := filepath.Base(r.URL.Path)
			kept := (*records)[:0]
			for _, rec := range *records {
				if rec.ID != id {
					kept = append(kept, rec)
				}
			}
			*records = kept
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{}})
		}
	}))
}

func TestCloudflarePublishesAndWithdraws(t *testing.T) {
	var records []fakeCFRecord
	var seenToken string
	srv := cloudflareStub(t, &records, &seenToken)
	defer srv.Close()

	cf := &Cloudflare{Token: "secret-token", BaseURL: srv.URL, Client: srv.Client()}
	ctx := context.Background()

	if err := cf.Present(ctx, "_acme-challenge.dns1.example.com.", "value-one"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records after Present = %d, want 1", len(records))
	}
	if records[0].Name != "_acme-challenge.dns1.example.com" {
		t.Errorf("record name = %q", records[0].Name)
	}
	if seenToken != "Bearer secret-token" {
		t.Errorf("authorization header = %q", seenToken)
	}

	if err := cf.Cleanup(ctx, "_acme-challenge.dns1.example.com.", "value-one"); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("records after Cleanup = %d, want 0", len(records))
	}
}

// A concurrent order for another name has its own record in the same zone, and
// cleaning up one must not delete the other.
func TestCloudflareCleanupLeavesOtherOrdersAlone(t *testing.T) {
	var records []fakeCFRecord
	srv := cloudflareStub(t, &records, nil)
	defer srv.Close()

	cf := &Cloudflare{Token: "t", BaseURL: srv.URL, Client: srv.Client()}
	ctx := context.Background()
	name := "_acme-challenge.dns1.example.com."

	if err := cf.Present(ctx, name, "mine"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cf.Present(ctx, name, "theirs"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := cf.Cleanup(ctx, name, "mine"); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(records) != 1 || records[0].Content != "theirs" {
		t.Errorf("cleanup removed the wrong record: %+v", records)
	}
}

func TestNeedsRenewal(t *testing.T) {
	dir := t.TempDir()
	base := Options{
		Domains:        []string{"dns1.example."},
		CertFile:       filepath.Join(dir, "cert.pem"),
		KeyFile:        filepath.Join(dir, "key.pem"),
		AccountKeyFile: filepath.Join(dir, "acct.key"),
		RenewBefore:    30 * 24 * time.Hour,
		Solver:         &HTTP01{Addrs: []string{"127.0.0.1:0"}},
		Log:            quiet(),
	}

	tests := []struct {
		name  string
		setup func(m *Manager)
		want  bool
	}{
		{
			name:  "no certificate at all",
			setup: func(m *Manager) { m.cert = nil },
			want:  true,
		},
		{
			name: "expiring inside the renewal window",
			setup: func(m *Manager) {
				c, pool, err := caIssued("dns1.example.", time.Now().Add(10*24*time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				m.opts.Roots = pool
				m.cert = &c
			},
			want: true,
		},
		{
			name: "placeholder no public CA vouches for, however long it runs",
			setup: func(m *Manager) {
				c, err := selfSigned("dns1.example.", time.Now().Add(800*24*time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				m.cert = &c
			},
			want: true,
		},
		{
			name: "good for months",
			setup: func(m *Manager) {
				c, pool, err := caIssued("dns1.example.", time.Now().Add(80*24*time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				m.opts.Roots = pool
				m.cert = &c
			},
			want: false,
		},
		{
			name: "valid but for the wrong name",
			setup: func(m *Manager) {
				c, pool, err := caIssued("somewhere.else.", time.Now().Add(80*24*time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				m.opts.Roots = pool
				m.cert = &c
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := New(base)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			tc.setup(m)
			if got := m.NeedsRenewal(); got != tc.want {
				t.Errorf("NeedsRenewal() = %t, want %t", got, tc.want)
			}
		})
	}
}

// The account key is the identity the CA rate-limits and warns, so it has to
// survive a restart rather than being regenerated each time.
func TestAccountKeyIsStableAndPrivate(t *testing.T) {
	dir := t.TempDir()
	opts := Options{
		Domains:        []string{"dns1.example."},
		CertFile:       filepath.Join(dir, "cert.pem"),
		KeyFile:        filepath.Join(dir, "key.pem"),
		AccountKeyFile: filepath.Join(dir, "sub", "acct.key"),
		Solver:         &HTTP01{Addrs: []string{"127.0.0.1:0"}},
		Log:            quiet(),
	}
	m, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	first, err := m.accountKey()
	if err != nil {
		t.Fatalf("accountKey: %v", err)
	}
	second, err := m.accountKey()
	if err != nil {
		t.Fatalf("accountKey again: %v", err)
	}
	a, err := x509.MarshalPKIXPublicKey(first.Public())
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalPKIXPublicKey(second.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("the account key changed between calls; the CA would see a new account each restart")
	}

	info, err := os.Stat(opts.AccountKeyFile)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("account key mode = %o, want 600", perm)
	}
}
