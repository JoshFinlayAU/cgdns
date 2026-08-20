// Package consistency checks that the things which name a metric, a config key
// or a command agree with the code that defines them.
//
// Nothing here exercises behaviour. It exists because a name that no longer
// resolves fails silently everywhere it is used: a dashboard tile renders
// blank, a Prometheus expression returns no data and its alert simply never
// fires, and documentation describes a flag nobody can type. None of that
// breaks a build or a test, and none of it is visible until somebody needs the
// thing that stopped working. Two such references were already live when this
// was written — one of them in the alert whose whole purpose was to notice a
// cache counter reading zero.
package consistency

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var metricRef = regexp.MustCompile(`cgdns_[a-z0-9_]+`)

// registered finds every metric the daemon actually exposes, by reading the
// Source literals it registers. Parsing the source is crude, but the alternative
// is booting a node with every subsystem enabled just to list names, and this
// has to hold for metrics whose subsystem is off in any given config.
func registered(t *testing.T) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	name := regexp.MustCompile(`Name:\s*"(cgdns_[a-z0-9_]+)"`)
	for _, path := range goFiles(t) {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, m := range name.FindAllSubmatch(body, -1) {
			out[string(m[1])] = true
		}
	}
	if len(out) < 50 {
		t.Fatalf("only found %d registered metrics, which means the scan is broken rather than the code", len(out))
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not a git checkout: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func goFiles(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "dist" || d.Name() == "bin") {
			return filepath.SkipDir
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repo: %v", err)
	}
	return out
}

// The console reads metrics by name over the API. A name that no longer exists
// renders an empty tile, which looks like a quiet resolver rather than a broken
// dashboard.
func TestConsoleMetricsExist(t *testing.T) {
	have := registered(t)
	path := filepath.Join(repoRoot(t), "internal/management/ui/app.js")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no console to check: %v", err)
	}
	assertResolves(t, "console", metricRef.FindAllString(string(body), -1), have)
}

// A Prometheus expression naming a metric that does not exist returns no data,
// so the alert never fires and nobody is told anything. It is the worst failure
// mode available to monitoring: silence that looks like health.
func TestAlertRuleMetricsExist(t *testing.T) {
	have := registered(t)

	// cgdns-probe is a separate binary that renders its own metrics by hand, so
	// its names are not in the daemon's registry and are collected separately.
	probe, err := os.ReadFile(filepath.Join(repoRoot(t), "cmd/cgdns-probe/main.go"))
	if err == nil {
		for _, m := range metricRef.FindAllString(string(probe), -1) {
			have[m] = true
		}
	}

	path := filepath.Join(repoRoot(t), "deploy/prometheus/cgdns-alerts.yml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no alert rules to check: %v", err)
	}

	// Only expressions name metrics; prose in an annotation may reasonably
	// mention one that was renamed, or one this build does not have.
	var refs []string
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "expr:") {
			continue
		}
		refs = append(refs, metricRef.FindAllString(trimmed, -1)...)
	}
	assertResolves(t, "alert rules", refs, have)
}

// Documentation that names a metric an operator cannot query sends them looking
// for a fault in their own monitoring.
func TestDocumentedMetricsExist(t *testing.T) {
	have := registered(t)
	root := repoRoot(t)

	probe, err := os.ReadFile(filepath.Join(root, "cmd/cgdns-probe/main.go"))
	if err == nil {
		for _, m := range metricRef.FindAllString(string(probe), -1) {
			have[m] = true
		}
	}

	// The decision record deliberately quotes names that never existed, because
	// recording a measurement mistake means naming what was measured wrongly.
	skip := map[string]bool{"docs/LOUIS.md": true}

	for _, rel := range []string{"README.md", "docs/OVERVIEW.md", "docs/policy.md", "docs/provisioning.md", "docs/LOUIS.md"} {
		if skip[rel] {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		assertResolves(t, rel, metricRef.FindAllString(string(body), -1), have)
	}
}

func assertResolves(t *testing.T, what string, refs []string, have map[string]bool) {
	t.Helper()

	missing := map[string]bool{}
	for _, r := range refs {
		if !have[r] {
			missing[r] = true
		}
	}
	if len(missing) == 0 {
		return
	}
	names := make([]string, 0, len(missing))
	for m := range missing {
		names = append(names, m)
	}
	sort.Strings(names)
	t.Errorf("%s names %d metric(s) that are not registered: %s",
		what, len(names), strings.Join(names, ", "))
}
