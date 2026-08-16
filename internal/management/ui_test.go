package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func uiHandlerFor(t *testing.T, enabled bool) http.Handler {
	t.Helper()
	st := testStore(t)
	api, err := NewAPI(APIOptions{Store: st, Log: quietLogger(), UI: enabled})
	if err != nil {
		t.Fatal(err)
	}
	return api.Handler()
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}

func TestUI_ServesTheConsole(t *testing.T) {
	h := uiHandlerFor(t, true)

	for _, tc := range []struct{ path, contains, ctype string }{
		{"/", "<title>cgdns</title>", "text/html"},
		{"/ui/app.js", "cgdns operator console", "javascript"},
		{"/ui/style.css", "--accent", "text/css"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := get(t, h, tc.path)
			if w.Code != http.StatusOK {
				t.Fatalf("got %d", w.Code)
			}
			if !strings.Contains(w.Body.String(), tc.contains) {
				t.Fatalf("body does not contain %q", tc.contains)
			}
			if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, tc.ctype) {
				t.Fatalf("content type %q, want %q", ct, tc.ctype)
			}
		})
	}
}

// The console is a shell with no data in it, so it loads without a session.
// Everything it then asks for does need one.
func TestUI_LoadsWithoutASessionButItsDataDoesNot(t *testing.T) {
	h := uiHandlerFor(t, true)

	if w := get(t, h, "/"); w.Code != http.StatusOK {
		t.Fatalf("console returned %d without a session", w.Code)
	}
	for _, path := range []string{
		"/api/v1/status", "/api/v1/metrics", "/api/v1/subscribers",
		"/api/v1/tokens", "/api/v1/users", "/api/v1/me",
	} {
		if w := get(t, h, path); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s returned %d without a session, want 401", path, w.Code)
		}
	}
}

// Every response carries them, API included: an error body is still something
// a browser could be talked into rendering.
func TestUI_SecurityHeadersOnEveryResponse(t *testing.T) {
	h := uiHandlerFor(t, true)

	for _, path := range []string{"/", "/ui/app.js", "/api/v1/status", "/nonsense"} {
		t.Run(path, func(t *testing.T) {
			w := get(t, h, path)
			csp := w.Header().Get("Content-Security-Policy")
			if csp == "" {
				t.Fatal("no Content-Security-Policy")
			}
			// These two are what turn an injected record value into script.
			if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
				t.Fatalf("CSP permits unsafe script: %q", csp)
			}
			if !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Fatalf("CSP allows framing: %q", csp)
			}
			for h2, want := range map[string]string{
				"X-Content-Type-Options": "nosniff",
				"X-Frame-Options":        "DENY",
				"Referrer-Policy":        "no-referrer",
			} {
				if got := w.Header().Get(h2); got != want {
					t.Fatalf("%s = %q, want %q", h2, got, want)
				}
			}
		})
	}
}

// With the UI off, the management plane is an API and nothing else.
func TestUI_DisabledServesNoConsole(t *testing.T) {
	h := uiHandlerFor(t, false)

	for _, path := range []string{"/", "/ui/app.js", "/ui/style.css"} {
		if w := get(t, h, path); w.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d with the UI disabled, want 404", path, w.Code)
		}
	}
	// The API is unaffected.
	if w := get(t, h, "/api/v1/status"); w.Code != http.StatusUnauthorized {
		t.Fatalf("the API returned %d, want 401", w.Code)
	}
}

// The console must not be able to reach outside its own directory.
func TestUI_NoPathTraversal(t *testing.T) {
	h := uiHandlerFor(t, true)

	for _, path := range []string{
		"/ui/../api/v1/status",
		"/ui/%2e%2e/%2e%2e/etc/passwd",
		"/ui/../../go.mod",
	} {
		w := get(t, h, path)
		if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "module ") {
			t.Fatalf("%s escaped the embedded filesystem", path)
		}
	}
}

func TestUI_MetricsAreServedToTheConsole(t *testing.T) {
	st := testStore(t)
	api, err := NewAPI(APIOptions{
		Store: st, Log: quietLogger(), UI: true,
		Metrics: func() map[string]float64 {
			return map[string]float64{"cgdns_queries_total": 42}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := api.Handler()

	tok, secret, err := Mint("ui", []Scope{ScopeRead}, 0, api.now())
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveToken(st, tok); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "/api/v1/metrics", nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "cgdns_queries_total") {
		t.Fatalf("metrics body: %s", w.Body.String())
	}
}
