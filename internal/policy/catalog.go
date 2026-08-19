package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Categories are what an operator sells and what a support agent explains. A
// profile is assembled from these, not from feed names, so nobody building a
// product tier needs to know which upstream list covers what — and swapping the
// list behind a category later changes nothing that was configured.
const (
	CategorySecurity   = "security"
	CategoryAds        = "ads"
	CategoryTracking   = "tracking"
	CategoryGambling   = "gambling"
	CategoryAdult      = "adult"
	CategoryCompliance = "compliance"
)

// CatalogEntry is a filter list this build knows how to fetch.
//
// Rules and Heap are measured, not estimated, and they are here because the
// question that decides whether a list can be enabled is "will the node still
// fit in memory", which nothing at configuration time can otherwise answer. A
// refresh holds the old and new copies at once, so a list costs twice Heap for
// the moment it is swapped.
type CatalogEntry struct {
	ID       string
	Category string
	Title    string
	Detail   string
	URL      string
	Rules    int
	Heap     int64

	// Default marks the tier chosen when a profile asks for the category by
	// name. Every category that can sensibly be turned on as a whole has one,
	// and it is always the conservative tier: a subscriber noticing nothing is
	// a better failure than a subscriber losing a site they needed.
	Default bool
}

const hagezi = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/rpz/"

// Catalog is the built-in list of feeds, ordered within each category from
// least to most aggressive. Sizes were measured on 2026-08-19; these lists are
// rebuilt daily and grow, so treat them as the right order of magnitude rather
// than a current figure.
//
// Overlapping tiers of the same family are deliberately all present. Picking
// one is an operator's judgement about false positives, and that judgement
// differs between a business customer and a family filter.
func Catalog() []CatalogEntry {
	return []CatalogEntry{
		{ID: "hagezi-light", Category: CategoryAds, Title: "Ads and tracking, conservative",
			Detail: "Well-known ad and telemetry hosts only. The safe default: breaks least.",
			URL:    hagezi + "light.txt", Rules: 85286, Heap: 14 << 20, Default: true},
		{ID: "hagezi-multi", Category: CategoryAds, Title: "Ads and tracking, balanced",
			Detail: "Broader coverage, still aimed at not breaking sites.",
			URL:    hagezi + "multi.txt", Rules: 372906, Heap: 56 << 20},
		{ID: "hagezi-pro", Category: CategoryAds, Title: "Ads and tracking, aggressive",
			Detail: "Expect occasional false positives worth an allow-list entry.",
			URL:    hagezi + "pro.txt", Rules: 450000, Heap: 96 << 20},
		{ID: "hagezi-pro-plus", Category: CategoryAds, Title: "Ads and tracking, very aggressive",
			Detail: "For subscribers who have asked for it. Not a default.",
			URL:    hagezi + "pro.plus.txt", Rules: 490886, Heap: 106 << 20},
		{ID: "hagezi-popupads", Category: CategoryAds, Title: "Pop-up and redirect ad hosts",
			Detail: "Narrow supplement to any of the above.",
			URL:    hagezi + "popupads.txt", Rules: 180000, Heap: 34 << 20},

		{ID: "hagezi-native-apple", Category: CategoryTracking, Title: "Apple device telemetry",
			Detail: "Vendor telemetry endpoints. Blocking these can affect device features.",
			URL:    hagezi + "native.apple.txt", Rules: 90, Heap: 1 << 20},
		{ID: "hagezi-native-amazon", Category: CategoryTracking, Title: "Amazon device telemetry",
			URL: hagezi + "native.amazon.txt", Rules: 80, Heap: 1 << 20},
		{ID: "hagezi-native-tiktok", Category: CategoryTracking, Title: "TikTok telemetry",
			URL: hagezi + "native.tiktok.txt", Rules: 60, Heap: 1 << 20},
		{ID: "hagezi-native-winoffice", Category: CategoryTracking, Title: "Windows and Office telemetry",
			URL: hagezi + "native.winoffice.txt", Rules: 400, Heap: 1 << 20},

		{ID: "hagezi-tif-mini", Category: CategorySecurity, Title: "Threat intelligence, minimal",
			Detail: "Malware, phishing and cryptojacking. The one category worth enabling for everybody.",
			URL:    hagezi + "tif.mini.txt", Rules: 350000, Heap: 52 << 20, Default: true},
		{ID: "hagezi-tif-medium", Category: CategorySecurity, Title: "Threat intelligence, medium",
			Detail: "Wider threat coverage. The practical ceiling on a 4 GB node.",
			URL:    hagezi + "tif.medium.txt", Rules: 831186, Heap: 113 << 20},
		{ID: "hagezi-fake", Category: CategorySecurity, Title: "Fake shops and scam sites",
			URL: hagezi + "fake.txt", Rules: 12000, Heap: 3 << 20},
		{ID: "hagezi-doh", Category: CategorySecurity, Title: "Public DoH and DoT endpoints",
			Detail: "Stops clients bypassing this resolver. Also breaks browsers configured to use them, deliberately.",
			URL:    hagezi + "doh.txt", Rules: 2500, Heap: 1 << 20},
		{ID: "hagezi-dyndns", Category: CategorySecurity, Title: "Dynamic DNS providers",
			Detail: "Common in malware command and control. Also used legitimately; check before enabling.",
			URL:    hagezi + "dyndns.txt", Rules: 15000, Heap: 3 << 20},

		{ID: "hagezi-gambling", Category: CategoryGambling, Title: "Gambling, conservative",
			URL: hagezi + "gambling.txt", Rules: 900000, Heap: 120 << 20, Default: true},
		{ID: "hagezi-gambling-medium", Category: CategoryGambling, Title: "Gambling, broader",
			URL: hagezi + "gambling.medium.txt", Rules: 1100000, Heap: 150 << 20},

		{ID: "hagezi-nsfw", Category: CategoryAdult, Title: "Adult content",
			Detail: "Domain-level only. It is a filter, not a guarantee, and should be sold as one.",
			URL:    hagezi + "nsfw.txt", Rules: 90000, Heap: 15 << 20, Default: true},
	}
}

// CatalogFor returns the entries in a category, and whether the category exists
// at all — a typo should be a refusal, not an empty profile that silently
// filters nothing.
func CatalogFor(category string) ([]CatalogEntry, bool) {
	category = strings.ToLower(strings.TrimSpace(category))
	if category == CategoryCompliance {
		return nil, true
	}
	var out []CatalogEntry
	for _, e := range Catalog() {
		if e.Category == category {
			out = append(out, e)
		}
	}
	return out, len(out) > 0
}

// CatalogEntryByID finds one entry.
func CatalogEntryByID(id string) (CatalogEntry, bool) {
	for _, e := range Catalog() {
		if e.ID == id {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// Categories lists every category, compliance included even though it has no
// built-in feeds: it is where an operator's own managed list belongs, and
// leaving it out of the listing hides the mechanism.
func Categories() []string {
	seen := map[string]bool{CategoryCompliance: true}
	for _, e := range Catalog() {
		seen[e.Category] = true
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// FormatHeap renders a measured size for an operator deciding what fits.
func FormatHeap(b int64) string {
	if b >= 1<<20 {
		return fmt.Sprintf("%d MiB", b>>20)
	}
	return fmt.Sprintf("%d KiB", b>>10)
}

// DefaultFor returns the tier used when a profile names a category rather than
// a feed.
func DefaultFor(category string) (CatalogEntry, bool) {
	entries, ok := CatalogFor(category)
	if !ok {
		return CatalogEntry{}, false
	}
	for _, e := range entries {
		if e.Default {
			return e, true
		}
	}
	return CatalogEntry{}, false
}
