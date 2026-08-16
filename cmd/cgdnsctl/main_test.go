package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JoshFinlayAU/cgdns/internal/management"
)

func TestPlural(t *testing.T) {
	for in, want := range map[string]string{
		"subscriber":  "subscribers",
		"subscribers": "subscribers",
		"override":    "overrides",
		"overrides":   "overrides",
		"feed":        "feeds",
		"feeds":       "feeds",
		"class":       "classes",
		"classes":     "classes",
		"nonsense":    "nonsense",
	} {
		if got := plural(in); got != want {
			t.Fatalf("plural(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseScopes(t *testing.T) {
	got := parseScopes("read, write ,admin")
	want := []management.Scope{management.ScopeRead, management.ScopeWrite, management.ScopeAdmin}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if n := len(parseScopes("")); n != 0 {
		t.Fatalf("empty scopes produced %d entries", n)
	}
}

// Every one of these must fail before any network call, so a typo never reaches
// a live node half-formed.
func TestRun_RejectsBadInvocations(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no command", []string{}},
		{"unknown command", []string{"frobnicate"}},
		{"noun with no subcommand", []string{"subscriber"}},
		{"unknown subcommand", []string{"subscriber", "frobnicate"}},
		{"get without key", []string{"subscriber", "get"}},
		{"set without payload", []string{"subscriber", "set"}},
		{"delete without key", []string{"subscriber", "delete"}},
		{"status with arguments", []string{"status", "extra"}},
		{"drift with no addresses", []string{"drift"}},
		{"drift with one address", []string{"drift", "10.0.0.1:8443"}},
		{"token with no subcommand", []string{"token"}},
		{"token create without name", []string{"token", "create"}},
		{"token revoke without id", []string{"token", "revoke"}},
		{"allow without domains", []string{"allow", "acme"}},
		{"block without domains", []string{"block", "acme"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A token that cannot be read would also fail, so point at a real
			// one: the invocation must be rejected on its own merits.
			args := append([]string{"-token", "deadbeef.cafe"}, tc.args...)
			if err := run(args); err == nil {
				t.Fatalf("run(%v) succeeded, want an error", tc.args)
			}
		})
	}
}

// The absence of a token must be reported as a usable instruction rather than a
// bare file-not-found from somewhere deep in the client.
func TestClientFor_ExplainsAMissingToken(t *testing.T) {
	g := globals{addr: "127.0.0.1:8443", tokenFile: filepath.Join(t.TempDir(), "absent.token")}
	_, err := g.client()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"-token", "CGDNS_TOKEN", "-token-file"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

func TestClientFor_ReadsTheTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(path, []byte("  abcd1234.secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g := globals{addr: "127.0.0.1:8443", tokenFile: path}
	c, err := g.client()
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr() != "https://127.0.0.1:8443" {
		t.Fatalf("addr = %q", c.Addr())
	}
}

func TestReadPayload(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "rec.json")
	if err := os.WriteFile(file, []byte(`{"name":"from-file"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	inline, err := readPayload(`{"name":"inline"}`)
	if err != nil || string(inline) != `{"name":"inline"}` {
		t.Fatalf("inline: %q %v", inline, err)
	}

	fromFile, err := readPayload("@" + file)
	if err != nil || string(fromFile) != `{"name":"from-file"}` {
		t.Fatalf("file: %q %v", fromFile, err)
	}

	if _, err := readPayload("@" + filepath.Join(dir, "absent.json")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestCompact(t *testing.T) {
	got := compact([]byte("{\n  \"b\": 1,\n  \"a\": 2\n}"))
	if got != `{"a":2,"b":1}` {
		t.Fatalf("got %q", got)
	}
	// Anything that is not JSON is passed through rather than swallowed.
	if got := compact([]byte("not json")); got != "not json" {
		t.Fatalf("got %q", got)
	}
}
