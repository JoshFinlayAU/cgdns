package management

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// A request on the local socket is authorised by the socket's mode, so the
// guard must let it through without a token — that is the whole point of it.
func TestLocalSocketNeedsNoToken(t *testing.T) {
	t.Parallel()

	reached := false
	h := (&API{log: quietLogger()}).guard(ScopeAdmin, func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	req, err := http.NewRequestWithContext(withLocal(context.Background()), http.MethodGet, "/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	h.ServeHTTP(rec, req)

	if !reached {
		t.Fatalf("a local-socket request was rejected with %d; it should need no token", rec.code)
	}
}

// Everything else still has to present one. The marker is applied at accept
// time for a verified root peer, so an unmarked request is either from the
// network or from a peer that failed that check.
func TestUnmarkedRequestStillNeedsAToken(t *testing.T) {
	t.Parallel()

	reached := false
	h := (&API{log: quietLogger()}).guard(ScopeAdmin, func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})

	req, err := http.NewRequest(http.MethodGet, "/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	h.ServeHTTP(rec, req)

	if reached {
		t.Error("a request with no token and no local marker reached the handler")
	}
	if rec.code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.code)
	}
}

// The socket is the credential, so its mode is load-bearing: anything looser
// than owner-only hands the admin plane to every user on the box.
func TestSocketIsOwnerOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "control.sock")
	s := &Server{opts: ServerOptions{Log: quietLogger()}}
	if err := s.bindLocal(path); err != nil {
		t.Fatalf("bindLocal: %v", err)
	}
	defer func() { _ = s.localLn.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != localSocketMode {
		t.Errorf("socket mode = %#o, want %#o", perm, localSocketMode)
	}
}

// A socket file outlives the process that made it, so an unclean shutdown must
// not stop the daemon starting again.
func TestStaleSocketIsReplaced(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "control.sock")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &Server{opts: ServerOptions{Log: quietLogger()}}
	if err := s.bindLocal(path); err != nil {
		t.Fatalf("a stale socket should be replaced, not fatal: %v", err)
	}
	_ = s.localLn.Close()
}

type recorder struct {
	code   int
	header http.Header
}

func (r *recorder) Header() http.Header {
	if r.header == nil {
		r.header = http.Header{}
	}
	return r.header
}
func (r *recorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *recorder) WriteHeader(c int)           { r.code = c }
