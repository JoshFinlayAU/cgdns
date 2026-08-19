package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rpzWith(names ...string) string {
	var b strings.Builder
	b.WriteString("$TTL 3600\n@ SOA localhost. root.localhost. 1 43200 3600 259200 3600\n  NS localhost.\n; a comment\n")
	for _, n := range names {
		fmt.Fprintf(&b, "%s CNAME .\n", n)
	}
	return b.String()
}

func manyNames(n int, prefix string) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s%d.example", prefix, i))
	}
	return out
}

func writeLive(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "live.rpz")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A feed that arrives nearly empty is indistinguishable from a successful fetch
// of nothing, and accepting it turns filtering off without failing.
func TestGuardRejectsAnEmptyFeed(t *testing.T) {
	t.Parallel()

	live := writeLive(t, rpzWith(manyNames(1000, "bad")...))
	g := Guard{MaxChangeRatio: 0.3, MinRules: 100}

	res, err := g.Check(strings.NewReader(rpzWith("one.example")), live)
	if err != nil {
		t.Fatal(err)
	}
	if res.Accepted {
		t.Error("a feed with one rule replaced a thousand live ones")
	}
	if !strings.Contains(res.Reason, "minimum") {
		t.Errorf("reason = %q, expected it to name the minimum", res.Reason)
	}
}

// A list that doubles or halves overnight is a publisher accident or a
// compromise. Either way the copy already serving is the safer one.
func TestGuardRejectsAWildSwing(t *testing.T) {
	t.Parallel()

	live := writeLive(t, rpzWith(manyNames(1000, "bad")...))
	g := Guard{MaxChangeRatio: 0.3, MinRules: 10}

	for _, tc := range []struct {
		name  string
		count int
		want  bool
	}{
		{"a normal daily drift", 1050, true},
		{"a large but plausible addition", 1250, true},
		{"a doubling", 2100, false},
		{"a collapse", 300, false},
	} {
		res, err := g.Check(strings.NewReader(rpzWith(manyNames(tc.count, "bad")...)), live)
		if err != nil {
			t.Fatal(err)
		}
		if res.Accepted != tc.want {
			t.Errorf("%s (%d rules against 1000): accepted = %t, want %t — %s",
				tc.name, tc.count, res.Accepted, tc.want, res.Reason)
		}
	}
}

// A node with nothing live yet has no baseline, and refusing the first fetch
// would mean it never starts filtering at all.
func TestGuardAllowsTheFirstFetch(t *testing.T) {
	t.Parallel()

	g := Guard{MaxChangeRatio: 0.3, MinRules: 10}
	res, err := g.Check(strings.NewReader(rpzWith(manyNames(500, "bad")...)),
		filepath.Join(t.TempDir(), "absent.rpz"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted {
		t.Errorf("the first fetch was refused: %s", res.Reason)
	}
}

// One bad entry should not discard an otherwise good list, but it must not be
// allowed to take a bank or a government service off the air either.
func TestProtectedNamesAreStrippedNotFatal(t *testing.T) {
	t.Parallel()

	protected := []string{"commbank.com.au", "my.gov.au"}
	content := rpzWith("tracker.example", "commbank.com.au", "ads.example", "login.my.gov.au")

	g := Guard{MaxChangeRatio: 0.5, MinRules: 1, Protected: protected}
	res, err := g.Check(strings.NewReader(content), filepath.Join(t.TempDir(), "absent.rpz"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted {
		t.Fatalf("a feed with one protected name was rejected outright: %s", res.Reason)
	}
	if len(res.Stripped) == 0 {
		t.Error("the protected name was not reported")
	}

	var out bytes.Buffer
	removed, err := StripProtected(strings.NewReader(content), &out, protected)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Errorf("removed %d rules, want 2 (the name and the one beneath it)", removed)
	}
	got := out.String()
	for _, must := range []string{"tracker.example", "ads.example"} {
		if !strings.Contains(got, must) {
			t.Errorf("stripping removed %s, which was not protected", must)
		}
	}
	for _, mustNot := range []string{"commbank.com.au", "login.my.gov.au"} {
		if strings.Contains(got, mustNot) {
			t.Errorf("%s survived stripping", mustNot)
		}
	}
}
