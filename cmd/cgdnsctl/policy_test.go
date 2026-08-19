package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// Flags typed after the subject must still be seen. The standard parser stops
// at the first positional, which would build a profile from no categories at
// all and report success, so this is the one place worth pinning down.
func TestParseFlags_AcceptsFlagsAfterPositionals(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantCategories []string
		wantAction     string
		wantForce      bool
		wantPositional []string
	}{
		{
			name:           "flags after the name",
			args:           []string{"family", "--category", "security", "--category", "adult"},
			wantCategories: []string{"security", "adult"},
			wantPositional: []string{"family"},
		},
		{
			name:           "flags before the name",
			args:           []string{"--category", "security", "family"},
			wantCategories: []string{"security"},
			wantPositional: []string{"family"},
		},
		{
			name:           "flags either side",
			args:           []string{"--action", "nxdomain", "family", "--category", "ads"},
			wantCategories: []string{"ads"},
			wantAction:     "nxdomain",
			wantPositional: []string{"family"},
		},
		{
			name:           "equals form",
			args:           []string{"family", "--category=security"},
			wantCategories: []string{"security"},
			wantPositional: []string{"family"},
		},
		{
			name:           "a bool flag does not swallow the next word",
			args:           []string{"compliance-list", "--mandatory", "extra"},
			wantForce:      true,
			wantPositional: []string{"compliance-list", "extra"},
		},
		{
			name:           "everything after -- is positional",
			args:           []string{"list", "--", "--category"},
			wantPositional: []string{"list", "--category"},
		},
		{
			name:           "several domains keep their order",
			args:           []string{"au-compliance", "a.example", "b.example", "--action", "nodata"},
			wantAction:     "nodata",
			wantPositional: []string{"au-compliance", "a.example", "b.example"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			var categories repeatable
			fs.Var(&categories, "category", "")
			action := fs.String("action", "", "")
			force := fs.Bool("mandatory", false, "")

			got, err := parseFlags(fs, tc.args)
			if err != nil {
				t.Fatalf("parseFlags: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(tc.wantPositional, ",") {
				t.Errorf("positional = %v, want %v", got, tc.wantPositional)
			}
			if strings.Join(categories, ",") != strings.Join(tc.wantCategories, ",") {
				t.Errorf("categories = %v, want %v", categories, tc.wantCategories)
			}
			if *action != tc.wantAction {
				t.Errorf("action = %q, want %q", *action, tc.wantAction)
			}
			if *force != tc.wantForce {
				t.Errorf("mandatory = %v, want %v", *force, tc.wantForce)
			}
		})
	}
}

// A category with no default tier must be refused by name rather than quietly
// contributing nothing to the profile.
func TestResolveFeeds_RefusesWhatItCannotName(t *testing.T) {
	if _, err := resolveFeeds([]string{"tracking"}, nil); err == nil {
		t.Error("a category with no default tier was accepted")
	} else if !strings.Contains(err.Error(), "--feed") {
		t.Errorf("error does not say what to do instead: %v", err)
	}

	if _, err := resolveFeeds([]string{"nonsense"}, nil); err == nil {
		t.Error("an unknown category was accepted")
	}
	if _, err := resolveFeeds(nil, []string{"nonsense"}); err == nil {
		t.Error("an unknown feed id was accepted")
	}

	got, err := resolveFeeds([]string{"security"}, []string{"hagezi-tif-mini"})
	if err != nil {
		t.Fatalf("resolveFeeds: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("naming a category and its default tier produced %d feeds, want 1 deduped", len(got))
	}
}
