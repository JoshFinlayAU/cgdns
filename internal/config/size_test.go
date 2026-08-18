package config

import "testing"

// A typo in a size must fail loudly. Read as zero it would leave the cache
// unbounded, which is the exact failure the setting exists to prevent.
func TestParseSize(t *testing.T) {
	t.Parallel()

	ok := []struct {
		in   string
		want Size
	}{
		{"1024", 1024},
		{"512MiB", 512 << 20},
		{"2GiB", 2 << 30},
		{"1GB", 1_000_000_000},
		{"1.5GiB", Size(1.5 * (1 << 30))},
		{"256M", 256 << 20},
		{" 64MiB ", 64 << 20},
		{"", 0},
	}
	for _, tc := range ok {
		got, err := ParseSize(tc.in)
		if err != nil {
			t.Errorf("ParseSize(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}

	for _, bad := range []string{"lots", "512 megs", "-1GiB", "MiB", "1.2.3MB"} {
		if got, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) = %d, want an error", bad, got)
		}
	}
}
