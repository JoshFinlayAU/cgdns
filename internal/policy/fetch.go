package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// A feed decides what subscribers are allowed to resolve, so fetching one is a
// control-plane operation wearing the clothes of a download.
//
// Two rules follow from that. A feed served over plain HTTP can be rewritten by
// anyone on the path, so one is only accepted when the record pins a SHA-256 to
// check it against. And a fetch that fails, times out, overruns its size cap or
// fails its hash leaves the previous content in place: filtering goes stale,
// which is a far better failure than filtering going wrong.

// FetchMetrics counts feed refresh activity.
type FetchMetrics struct {
	Attempts  atomic.Uint64
	Updated   atomic.Uint64
	Unchanged atomic.Uint64
	Failures  atomic.Uint64
	// Rejected counts refreshes refused by the guard. Any of these is worth an
	// alert: filtering is now running on yesterday's copy, deliberately.
	Rejected atomic.Uint64
	// Protected counts rules dropped for naming something that must not be
	// blocked.
	Protected atomic.Uint64
	// HashMismatches counts content that did not match its pinned digest.
	// Any of these is worth an alert: the feed was tampered with, or the
	// publisher changed it without the control plane being told.
	HashMismatches atomic.Uint64
	LastSuccess    atomic.Int64
}

// Feed is what the fetcher needs to know about one source.
type Feed struct {
	Name string
	URL  string
	// SHA256 pins the content. Required for an http:// URL, optional for
	// https://, and checked whenever it is set.
	SHA256 string
}

// FetcherOptions configures a Fetcher.
type FetcherOptions struct {
	// Dir is where fetched content lands, one file per feed.
	Dir string
	// MaxBytes caps a single feed. A source that streams forever would
	// otherwise fill the disk of every node subscribed to it.
	MaxBytes int64
	// Timeout bounds one fetch.
	Timeout time.Duration

	Client  *http.Client
	Log     *slog.Logger
	Metrics *FetchMetrics

	// Guard decides whether fetched content may replace what is live. These
	// lists cannot be pinned to a hash — they are published daily — so this is
	// the only thing standing between a publisher's bad build and every
	// subscriber the feed applies to.
	Guard Guard
}

// Fetcher downloads feed content to local files.
type Fetcher struct {
	opts FetcherOptions
}

// ErrHashMismatch means the content did not match its pinned digest.
var ErrHashMismatch = errors.New("policy: feed content does not match its pinned sha256")

// ErrInsecureFeed means an http:// feed carried no digest to check it against.
var ErrInsecureFeed = errors.New("policy: an http feed requires a sha256 to pin its content")

// NewFetcher builds a Fetcher.
func NewFetcher(opts FetcherOptions) (*Fetcher, error) {
	if opts.Dir == "" {
		return nil, errors.New("policy: a feed directory is required")
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 256 << 20
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Minute
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &FetchMetrics{}
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: opts.Timeout}
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("policy: creating feed directory %s: %w", opts.Dir, err)
	}
	return &Fetcher{opts: opts}, nil
}

// Path is where a feed's content lives on this node.
func (f *Fetcher) Path(name string) string {
	return filepath.Join(f.opts.Dir, sanitiseName(name))
}

// sanitiseName keeps a feed name from escaping the feed directory. Names come
// from the control plane, which is trusted, but a path traversal in a name
// would be a way to write anywhere the daemon can reach.
func sanitiseName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return "unnamed"
	}
	return out
}

// Result reports what one refresh did.
type Result struct {
	Name    string
	Path    string
	Updated bool
	Err     error
}

// Refresh fetches every feed that has a URL, returning one result per feed.
//
// A failure is reported rather than returned: one broken feed must not stop the
// others from refreshing.
func (f *Fetcher) Refresh(ctx context.Context, feeds []Feed) []Result {
	out := make([]Result, 0, len(feeds))
	for _, feed := range feeds {
		if feed.URL == "" {
			continue
		}
		updated, err := f.fetchOne(ctx, feed)
		if err != nil {
			f.opts.Metrics.Failures.Add(1)
			f.opts.Log.Warn("feed refresh failed, keeping the previous content",
				slog.String("feed", feed.Name), slog.String("err", err.Error()))
		}
		out = append(out, Result{Name: feed.Name, Path: f.Path(feed.Name), Updated: updated, Err: err})
	}
	return out
}

func (f *Fetcher) fetchOne(ctx context.Context, feed Feed) (bool, error) {
	f.opts.Metrics.Attempts.Add(1)

	u, err := url.Parse(feed.URL)
	if err != nil {
		return false, fmt.Errorf("parsing feed URL: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if feed.SHA256 == "" {
			return false, ErrInsecureFeed
		}
	default:
		return false, fmt.Errorf("policy: feed URL scheme %q is not fetchable", u.Scheme)
	}

	ctx, cancel := context.WithTimeout(ctx, f.opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feed.URL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "cgdns")
	req.Header.Set("Accept", "text/plain, */*")

	resp, err := f.opts.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("policy: feed returned HTTP %d", resp.StatusCode)
	}

	// The content is written to a temporary file and hashed as it goes, so an
	// oversized or tampered feed never reaches the path the compiler reads.
	tmp, err := os.CreateTemp(f.opts.Dir, ".fetch-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	digest := sha256.New()
	limited := io.LimitReader(resp.Body, f.opts.MaxBytes+1)
	written, err := io.Copy(io.MultiWriter(tmp, digest), limited)
	if err != nil {
		return false, fmt.Errorf("reading feed: %w", err)
	}
	if written > f.opts.MaxBytes {
		return false, fmt.Errorf("policy: feed exceeds %d bytes", f.opts.MaxBytes)
	}
	if written == 0 {
		// An empty feed would silently unblock everything it used to block.
		return false, errors.New("policy: feed is empty")
	}

	got := hex.EncodeToString(digest.Sum(nil))
	if feed.SHA256 != "" && !strings.EqualFold(got, feed.SHA256) {
		f.opts.Metrics.HashMismatches.Add(1)
		return false, fmt.Errorf("%w: got %s, expected %s", ErrHashMismatch, got, feed.SHA256)
	}

	dst := f.Path(feed.Name)
	if same, err := hashOfFile(dst); err == nil && strings.EqualFold(same, got) {
		f.opts.Metrics.Unchanged.Add(1)
		f.opts.Metrics.LastSuccess.Store(time.Now().Unix())
		return false, nil
	}

	// Judged before it is allowed anywhere near the live path.
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	verdict, err := f.opts.Guard.Check(tmp, dst)
	if err != nil {
		return false, fmt.Errorf("checking the fetched feed: %w", err)
	}
	if !verdict.Accepted {
		f.opts.Metrics.Rejected.Add(1)
		f.opts.Log.Error("refusing a feed refresh, keeping the copy already live",
			slog.String("feed", feed.Name),
			slog.String("reason", verdict.Reason),
			slog.Int("live_rules", verdict.OldRules),
			slog.Int("offered_rules", verdict.NewRules))
		return false, fmt.Errorf("policy: feed %s rejected: %s", feed.Name, verdict.Reason)
	}
	if len(verdict.Stripped) > 0 {
		f.opts.Metrics.Protected.Add(uint64(len(verdict.Stripped)))
		f.opts.Log.Warn("a feed tried to block a protected name; the rules were dropped",
			slog.String("feed", feed.Name),
			slog.Any("names", verdict.Stripped))

		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
		clean, err := os.CreateTemp(f.opts.Dir, ".strip-*")
		if err != nil {
			return false, err
		}
		cleanName := clean.Name()
		defer func() { _ = os.Remove(cleanName) }()
		if _, err := StripProtected(tmp, clean, f.opts.Guard.Protected); err != nil {
			_ = clean.Close()
			return false, err
		}
		if err := clean.Close(); err != nil {
			return false, err
		}
		if err := os.Chmod(cleanName, 0o640); err != nil {
			return false, err
		}
		if err := os.Rename(cleanName, dst); err != nil {
			return false, err
		}
		f.opts.Metrics.Updated.Add(1)
		f.opts.Metrics.LastSuccess.Store(time.Now().Unix())
		return true, nil
	}

	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return false, err
	}
	// Renamed into place, so a reader either sees the whole old feed or the
	// whole new one and never a half-written file.
	if err := os.Rename(tmpName, dst); err != nil {
		return false, err
	}

	f.opts.Metrics.Updated.Add(1)
	f.opts.Metrics.LastSuccess.Store(time.Now().Unix())
	f.opts.Log.Info("feed updated",
		slog.String("feed", feed.Name),
		slog.Int64("bytes", written),
		slog.String("sha256", got[:16]))
	return true, nil
}

// hashOfFile returns the SHA-256 of an existing file.
func hashOfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
