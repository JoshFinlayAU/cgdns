package policy

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// A feed is a supply chain into the resolver.
//
// These lists are published daily and cannot be pinned to a hash, so every
// refresh is a fresh download from a third party that can NXDOMAIN any name it
// chooses. A publisher mistake — a build that emits an empty file, or one that
// accidentally includes a TLD — becomes an outage for every subscriber the feed
// applies to, and it arrives automatically at whatever hour the refresh runs.
//
// Two guards sit between a download and the live rules. Neither judges whether
// the content is correct, which is not knowable here; both refuse changes that
// no legitimate update looks like.

// Guard decides whether fetched content may replace what is already live.
type Guard struct {
	// MaxChangeRatio rejects a refresh that adds or removes more than this
	// fraction of the current rules. A list that doubles or halves overnight is
	// either a publisher accident or a compromise; either way the old copy is
	// the safer one to keep serving. Zero disables the check.
	MaxChangeRatio float64
	// MinRules rejects a feed that arrives nearly empty. An empty list is
	// indistinguishable from a successful fetch of nothing, and it silently
	// switches filtering off rather than failing.
	MinRules int
	// Protected names must never be blocked. A feed that tries is not rejected
	// outright — one bad entry should not discard an otherwise good list — but
	// the entry is dropped and counted, because the alternative is a bank or a
	// government service going dark for every subscriber.
	Protected []string
}

// GuardResult reports what a check decided.
type GuardResult struct {
	Accepted bool
	Reason   string
	NewRules int
	OldRules int
	// Stripped counts protected names removed from the incoming content.
	Stripped []string
}

// Check compares incoming content against what is live.
func (g Guard) Check(incoming io.Reader, livePath string) (GuardResult, error) {
	newCount, hits, err := scan(incoming, g.Protected)
	if err != nil {
		return GuardResult{}, err
	}
	res := GuardResult{NewRules: newCount, Stripped: hits}

	if g.MinRules > 0 && newCount < g.MinRules {
		res.Reason = fmt.Sprintf("only %d rules, below the %d minimum: an almost-empty feed turns filtering off rather than failing", newCount, g.MinRules)
		return res, nil
	}

	oldCount := 0
	if f, err := os.Open(livePath); err == nil {
		oldCount, _, _ = scan(f, nil)
		_ = f.Close()
	}
	res.OldRules = oldCount

	// Nothing live to compare against: a first fetch has no baseline, and
	// refusing it would mean a new node never starts filtering at all.
	if oldCount == 0 {
		res.Accepted = true
		return res, nil
	}

	if g.MaxChangeRatio > 0 {
		delta := float64(newCount-oldCount) / float64(oldCount)
		if delta < 0 {
			delta = -delta
		}
		if delta > g.MaxChangeRatio {
			res.Reason = fmt.Sprintf("rule count moved %.0f%% (%d to %d), beyond the %.0f%% a refresh should ever move: keeping the copy already live",
				delta*100, oldCount, newCount, g.MaxChangeRatio*100)
			return res, nil
		}
	}

	res.Accepted = true
	return res, nil
}

// scan counts the meaningful lines and reports which protected names appear.
func scan(r io.Reader, protected []string) (int, []string, error) {
	want := make(map[string]bool, len(protected))
	for _, p := range protected {
		want[dns.CanonicalName(p)] = true
	}

	var hits []string
	count := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "$") || strings.HasPrefix(line, "@") {
			continue
		}
		count++
		if len(want) == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := dns.CanonicalName(strings.TrimSuffix(fields[0], "."))
		if want[name] {
			hits = append(hits, name)
		}
	}
	return count, hits, sc.Err()
}

// StripProtected removes rules for protected names from RPZ content.
//
// It is applied on the way in rather than at query time so the cost is paid
// once per refresh instead of once per query, and so an operator can see in the
// logs that a feed tried to block something it must not.
func StripProtected(in io.Reader, out io.Writer, protected []string) (int, error) {
	want := make(map[string]bool, len(protected))
	for _, p := range protected {
		want[dns.CanonicalName(p)] = true
	}

	removed := 0
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	w := bufio.NewWriter(out)
	defer func() { _ = w.Flush() }()

	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, ";") && !strings.HasPrefix(trimmed, "#") {
			if fields := strings.Fields(trimmed); len(fields) > 0 {
				name := dns.CanonicalName(strings.TrimSuffix(fields[0], "."))
				if want[name] || coveredByProtected(name, want) {
					removed++
					continue
				}
			}
		}
		if _, err := w.WriteString(line + "\n"); err != nil {
			return removed, err
		}
	}
	return removed, sc.Err()
}

// coveredByProtected reports whether name sits at or under a protected name, so
// protecting example.com also protects www.example.com.
func coveredByProtected(name string, want map[string]bool) bool {
	for suffix := name; suffix != "." && suffix != ""; {
		if want[suffix] {
			return true
		}
		i, end := dns.NextLabel(suffix, 0)
		if end {
			return false
		}
		suffix = suffix[i:]
	}
	return false
}
