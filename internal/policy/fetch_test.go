package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func testFetcher(t *testing.T, tune ...func(*FetcherOptions)) (*Fetcher, *FetchMetrics) {
	t.Helper()
	m := &FetchMetrics{}
	opts := FetcherOptions{Dir: t.TempDir(), Metrics: m, Log: quietLogger(), Timeout: 5 * time.Second}
	for _, f := range tune {
		f(&opts)
	}
	f, err := NewFetcher(opts)
	if err != nil {
		t.Fatal(err)
	}
	return f, m
}

// serveBody returns an HTTPS test server serving body.
func serveBody(t *testing.T, body *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(*body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// clientFor trusts the test server's certificate.
func clientFor(srv *httptest.Server) *http.Client { return srv.Client() }

func TestFetch_DownloadsAndStores(t *testing.T) {
	body := "malware.example\nphishing.example\n"
	srv := serveBody(t, &body)
	f, m := testFetcher(t, func(o *FetcherOptions) { o.Client = clientFor(srv) })

	results := f.Refresh(context.Background(), []Feed{{Name: "malware", URL: srv.URL}})
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("refresh: %+v", results)
	}
	if !results[0].Updated {
		t.Fatal("first fetch did not report an update")
	}

	got, err := os.ReadFile(f.Path("malware"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("stored %q, want %q", got, body)
	}
	if m.Updated.Load() != 1 {
		t.Fatalf("updated count is %d", m.Updated.Load())
	}
}

// Refetching identical content must not report a change, or every refresh
// would swap the query path's tables for nothing.
func TestFetch_UnchangedContentIsNotAnUpdate(t *testing.T) {
	body := "malware.example\n"
	srv := serveBody(t, &body)
	f, m := testFetcher(t, func(o *FetcherOptions) { o.Client = clientFor(srv) })

	f.Refresh(context.Background(), []Feed{{Name: "malware", URL: srv.URL}})
	results := f.Refresh(context.Background(), []Feed{{Name: "malware", URL: srv.URL}})

	if results[0].Updated {
		t.Fatal("identical content was reported as an update")
	}
	if m.Unchanged.Load() != 1 {
		t.Fatalf("unchanged count is %d", m.Unchanged.Load())
	}
}

func TestFetch_DetectsChangedContent(t *testing.T) {
	body := "one.example\n"
	srv := serveBody(t, &body)
	f, _ := testFetcher(t, func(o *FetcherOptions) { o.Client = clientFor(srv) })

	f.Refresh(context.Background(), []Feed{{Name: "malware", URL: srv.URL}})
	body = "one.example\ntwo.example\n"
	results := f.Refresh(context.Background(), []Feed{{Name: "malware", URL: srv.URL}})

	if !results[0].Updated {
		t.Fatal("changed content was not reported as an update")
	}
	got, _ := os.ReadFile(f.Path("malware"))
	if string(got) != body {
		t.Fatalf("stored %q", got)
	}
}

// A blocklist decides what subscribers may resolve. Content that does not match
// its pinned digest has been changed by someone, and must not be installed.
func TestFetch_RefusesContentFailingItsPinnedHash(t *testing.T) {
	body := "malware.example\n"
	srv := serveBody(t, &body)
	f, m := testFetcher(t, func(o *FetcherOptions) { o.Client = clientFor(srv) })

	feed := Feed{Name: "malware", URL: srv.URL, SHA256: sha256Of(body)}
	if r := f.Refresh(context.Background(), []Feed{feed})[0]; r.Err != nil {
		t.Fatalf("matching content was rejected: %v", r.Err)
	}

	// The publisher changes the content without the control plane being told.
	body = "malware.example\nbank.example\n"
	r := f.Refresh(context.Background(), []Feed{feed})[0]
	if !errors.Is(r.Err, ErrHashMismatch) {
		t.Fatalf("got %v, want ErrHashMismatch", r.Err)
	}
	if m.HashMismatches.Load() != 1 {
		t.Fatal("the mismatch was not counted")
	}

	// The previous, verified content is still what serves.
	got, _ := os.ReadFile(f.Path("malware"))
	if !strings.Contains(string(got), "malware.example") || strings.Contains(string(got), "bank.example") {
		t.Fatalf("the rejected content was installed: %q", got)
	}
}

// A feed over plain HTTP can be rewritten by anyone on the path, so it is only
// accepted when a digest pins what it must be.
func TestFetch_RefusesPlainHTTPWithoutAPinnedHash(t *testing.T) {
	body := "malware.example\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	f, _ := testFetcher(t)

	r := f.Refresh(context.Background(), []Feed{{Name: "malware", URL: srv.URL}})[0]
	if !errors.Is(r.Err, ErrInsecureFeed) {
		t.Fatalf("got %v, want ErrInsecureFeed", r.Err)
	}

	// With a digest it is acceptable, because the content is verified even
	// though the transport is not.
	r = f.Refresh(context.Background(), []Feed{{Name: "malware", URL: srv.URL, SHA256: sha256Of(body)}})[0]
	if r.Err != nil {
		t.Fatalf("a pinned http feed was rejected: %v", r.Err)
	}
}

// A source that streams forever would otherwise fill the disk of every node
// subscribed to it.
func TestFetch_EnforcesTheSizeCap(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := strings.Repeat("a.example\n", 1024)
		for range 64 {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	f, _ := testFetcher(t, func(o *FetcherOptions) {
		o.Client = clientFor(srv)
		o.MaxBytes = 4096
	})

	r := f.Refresh(context.Background(), []Feed{{Name: "huge", URL: srv.URL}})[0]
	if r.Err == nil {
		t.Fatal("an oversized feed was accepted")
	}
	if _, err := os.Stat(f.Path("huge")); err == nil {
		t.Fatal("the oversized feed was written to the feed directory")
	}
}

// An empty feed would silently unblock everything it used to block.
func TestFetch_RefusesAnEmptyFeed(t *testing.T) {
	body := ""
	srv := serveBody(t, &body)
	f, _ := testFetcher(t, func(o *FetcherOptions) { o.Client = clientFor(srv) })

	if r := f.Refresh(context.Background(), []Feed{{Name: "malware", URL: srv.URL}})[0]; r.Err == nil {
		t.Fatal("an empty feed was accepted")
	}
}

func TestFetch_RefusesAnErrorResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	f, _ := testFetcher(t, func(o *FetcherOptions) { o.Client = clientFor(srv) })
	if r := f.Refresh(context.Background(), []Feed{{Name: "malware", URL: srv.URL}})[0]; r.Err == nil {
		t.Fatal("an HTTP 404 was treated as feed content")
	}
}

// A failing feed must not stop the others refreshing.
func TestFetch_OneBadFeedDoesNotStopTheRest(t *testing.T) {
	body := "good.example\n"
	good := serveBody(t, &body)
	f, _ := testFetcher(t, func(o *FetcherOptions) { o.Client = clientFor(good) })

	results := f.Refresh(context.Background(), []Feed{
		{Name: "broken", URL: "https://127.0.0.1:1/nothing"},
		{Name: "good", URL: good.URL},
	})
	if len(results) != 2 {
		t.Fatalf("got %d results", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("the unreachable feed reported success")
	}
	if results[1].Err != nil || !results[1].Updated {
		t.Fatalf("the good feed did not refresh: %+v", results[1])
	}
}

// Feed names come from the control plane, but a traversal in one would be a way
// to write anywhere the daemon can reach.
func TestFetch_NameCannotEscapeTheFeedDirectory(t *testing.T) {
	f, _ := testFetcher(t)
	for _, name := range []string{"../escape", "../../etc/passwd", "a/b/c", ".."} {
		p := f.Path(name)
		if filepath.Dir(p) != strings.TrimSuffix(f.opts.Dir, "/") {
			t.Fatalf("name %q produced path %q, outside the feed directory", name, p)
		}
	}
}

func TestFetch_SkipsFeedsWithNoURL(t *testing.T) {
	f, m := testFetcher(t)
	results := f.Refresh(context.Background(), []Feed{{Name: "local-only"}})
	if len(results) != 0 {
		t.Fatalf("a feed with no URL produced %d results", len(results))
	}
	if m.Attempts.Load() != 0 {
		t.Fatal("a feed with no URL was fetched")
	}
}

func TestNewFetcher_RejectsAMissingDirectory(t *testing.T) {
	if _, err := NewFetcher(FetcherOptions{}); err == nil {
		t.Fatal("expected an error with no directory")
	}
}
