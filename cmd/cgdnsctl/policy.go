package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/JoshFinlayAU/cgdns/internal/control"
	"github.com/JoshFinlayAU/cgdns/internal/management"
	"github.com/JoshFinlayAU/cgdns/internal/policy"
)

func policyUsage() {
	fmt.Fprint(os.Stderr, `cgdnsctl policy - decide what gets filtered, and for whom

  Nothing is filtered by default. A profile names what to filter; an assignment
  says which client addresses get that profile. An address with no assignment
  resolves unfiltered.

Discovering what can be filtered:
  policy categories                       what can be filtered
  policy catalog [category]               the lists behind each category, and what they cost

Building profiles:
  policy profiles                         profiles defined here
  policy profile set <name> [flags]       create or replace a profile
      --category <name>       include a category at its default tier (repeatable)
      --feed <id>             include one specific list (repeatable)
      --action <what>         nxdomain (default), nodata, or redirect
      --redirect <ip>         where redirect sends clients (repeatable, v4 and v6)
  policy profile delete <name>

Assigning them:
  policy assign <cidr> <profile> [--id <name>]
  policy unassign <cidr>
  policy assignments
  policy show <ip>                        what applies to this address, and why

Lists you maintain yourself:
  policy list create <name> [flags]       --category, --mandatory, --url <rpz>
  policy list add <name> <domain> [--redirect <ip>] [--note <why>]
  policy list remove <name> <domain>
  policy list show <name>
  policy lists

  A list marked --mandatory applies to every client, above every profile and
  above a subscriber's own allow list. That is what compliance filtering needs
  and it is the only thing here a subscriber cannot opt out of, so mark a list
  that way deliberately.
`)
}

func cmdPolicy(g globals, args []string) error {
	if len(args) == 0 {
		policyUsage()
		return errors.New("policy needs a subcommand")
	}
	switch args[0] {
	case "categories":
		return policyCategories(g)
	case "catalog":
		return policyCatalog(g, args[1:])
	case "profiles":
		return policyProfiles(g)
	case "profile":
		return policyProfile(g, args[1:])
	case "assign":
		return policyAssign(g, args[1:])
	case "unassign":
		return policyUnassign(g, args[1:])
	case "assignments":
		return policyAssignments(g)
	case "show":
		return policyShow(g, args[1:])
	case "lists":
		return policyLists(g)
	case "list":
		return policyList(g, args[1:])
	case "help":
		policyUsage()
		return nil
	default:
		policyUsage()
		return fmt.Errorf("unknown policy subcommand %q", args[0])
	}
}

func policyCategories(g globals) error {
	type row struct {
		Category string `json:"category"`
		Feeds    int    `json:"feeds"`
		Default  string `json:"default,omitempty"`
		Note     string `json:"note,omitempty"`
	}
	var rows []row
	for _, c := range policy.Categories() {
		entries, _ := policy.CatalogFor(c)
		r := row{Category: c, Feeds: len(entries)}
		if d, ok := policy.DefaultFor(c); ok {
			r.Default = d.ID
		}
		switch c {
		case policy.CategoryCompliance:
			r.Note = "no built-in lists; this is where a list you maintain belongs"
		case policy.CategoryTracking:
			r.Note = "no default tier; name a feed with --feed"
		}
		rows = append(rows, r)
	}
	if g.jsonOut {
		return emitJSON(rows)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CATEGORY\tLISTS\tDEFAULT TIER\t")
	for _, r := range rows {
		def := r.Default
		if def == "" {
			def = "-"
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", r.Category, r.Feeds, def, r.Note)
	}
	return w.Flush()
}

func policyCatalog(g globals, args []string) error {
	entries := policy.Catalog()
	if len(args) > 0 {
		filtered, ok := policy.CatalogFor(args[0])
		if !ok {
			return fmt.Errorf("no category %q; try: %s", args[0], strings.Join(policy.Categories(), ", "))
		}
		entries = filtered
	}
	if g.jsonOut {
		return emitJSON(entries)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tCATEGORY\tRULES\tMEMORY\tWHAT IT IS\t")
	for _, e := range entries {
		title := e.Title
		if e.Default {
			title += " (default tier)"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", e.ID, e.Category, e.Rules, policy.FormatHeap(e.Heap), title)
		if e.Detail != "" {
			fmt.Fprintf(w, "\t\t\t\t%s\n", e.Detail)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "\nmemory is the steady-state cost; a refresh holds the old and new copy at once, so budget double while one swaps.")
	return nil
}

// resolveFeeds turns categories and feed ids into catalog entries, refusing
// anything it cannot name. A profile that silently drops an unrecognised
// category would filter less than the operator believes it does.
func resolveFeeds(categories, feedIDs []string) ([]policy.CatalogEntry, error) {
	var out []policy.CatalogEntry
	seen := map[string]bool{}
	for _, c := range categories {
		entry, ok := policy.DefaultFor(c)
		if !ok {
			if _, known := policy.CatalogFor(c); known {
				return nil, fmt.Errorf("category %q has no default tier; name a list with --feed (see: cgdnsctl policy catalog %s)", c, c)
			}
			return nil, fmt.Errorf("no category %q; try: %s", c, strings.Join(policy.Categories(), ", "))
		}
		if !seen[entry.ID] {
			seen[entry.ID] = true
			out = append(out, entry)
		}
	}
	for _, id := range feedIDs {
		entry, ok := policy.CatalogEntryByID(id)
		if !ok {
			return nil, fmt.Errorf("no list %q in the catalog; see: cgdnsctl policy catalog", id)
		}
		if !seen[entry.ID] {
			seen[entry.ID] = true
			out = append(out, entry)
		}
	}
	return out, nil
}

type repeatable []string

func (r *repeatable) String() string     { return strings.Join(*r, ",") }
func (r *repeatable) Set(v string) error { *r = append(*r, v); return nil }

func policyProfile(g globals, args []string) error {
	if len(args) == 0 {
		return errors.New("policy profile needs set or delete")
	}
	switch args[0] {
	case "set":
		return policyProfileSet(g, args[1:])
	case "delete":
		return policyProfileDelete(g, args[1:])
	default:
		return fmt.Errorf("unknown policy profile subcommand %q", args[0])
	}
}

func policyProfileSet(g globals, args []string) error {
	fs := flag.NewFlagSet("policy profile set", flag.ContinueOnError)
	var categories, feedIDs, redirects, lists repeatable
	fs.Var(&categories, "category", "include a category at its default tier (repeatable)")
	fs.Var(&feedIDs, "feed", "include one catalog list by id (repeatable)")
	fs.Var(&lists, "list", "include a list you maintain, by name (repeatable)")
	fs.Var(&redirects, "redirect", "address a redirect action sends clients to (repeatable)")
	action := fs.String("action", "nxdomain", "what a match does: nxdomain, nodata or redirect")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("policy profile set needs exactly one profile name")
	}
	name := strings.ToLower(rest[0])

	switch *action {
	case "nxdomain", "nodata", "redirect":
	default:
		return fmt.Errorf("unknown action %q: use nxdomain, nodata or redirect", *action)
	}
	if *action == "redirect" && len(redirects) == 0 {
		return errors.New("--action redirect needs at least one --redirect address")
	}
	for _, r := range redirects {
		if _, err := netip.ParseAddr(r); err != nil {
			return fmt.Errorf("--redirect %q is not an address", r)
		}
	}

	entries, err := resolveFeeds(categories, feedIDs)
	if err != nil {
		return err
	}
	if len(entries) == 0 && len(lists) == 0 {
		return errors.New("a profile with no categories, feeds or lists filters nothing; assign no profile instead")
	}

	c, err := g.client()
	if err != nil {
		return err
	}

	// Creating the feed records here is the point of the command: naming a
	// category should be enough, without the operator having to know the URL
	// behind it or write the record by hand.
	feedNames := make([]string, 0, len(entries)+len(lists))
	var total int64
	for _, e := range entries {
		if err := ensureFeed(c, e); err != nil {
			return err
		}
		feedNames = append(feedNames, e.ID)
		total += e.Heap
	}
	for _, l := range lists {
		if _, err := c.Get(control.KindFeed, l); err != nil {
			var apiErr *management.APIError
			if errors.As(err, &apiErr) && apiErr.NotFound() {
				return fmt.Errorf("no list named %q; create it with: cgdnsctl policy list create %s", l, l)
			}
			return err
		}
		feedNames = append(feedNames, l)
	}

	rec := control.ClassRecord{Name: name, Feeds: feedNames, Action: *action, RedirectTo: redirects}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := c.Put(control.KindClass, payload); err != nil {
		return err
	}

	stored, err := c.Get(control.KindClass, name)
	if err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(json.RawMessage(stored))
	}
	fmt.Printf("profile %s: %s, action %s\n", name, strings.Join(feedNames, ", "), *action)
	if total > 0 {
		fmt.Printf("adds roughly %s of rules once every list has been fetched\n", policy.FormatHeap(total))
	}
	fmt.Printf("nothing uses it yet — assign it with: cgdnsctl policy assign <cidr> %s\n", name)
	return nil
}

// ensureFeed creates a catalog feed's record if the node has not got it, and
// leaves an existing one alone: an operator may have pointed it at a mirror or
// changed its refresh, and re-running a profile command should not undo that.
func ensureFeed(c *management.Client, e policy.CatalogEntry) error {
	if _, err := c.Get(control.KindFeed, e.ID); err == nil {
		return nil
	} else {
		var apiErr *management.APIError
		if !errors.As(err, &apiErr) || !apiErr.NotFound() {
			return err
		}
	}
	rec := control.FeedRecord{
		Name:     e.ID,
		Format:   "rpz",
		URL:      e.URL,
		Category: e.Category,
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = c.Put(control.KindFeed, payload)
	return err
}

func policyProfileDelete(g globals, args []string) error {
	if len(args) != 1 {
		return errors.New("policy profile delete needs one profile name")
	}
	name := strings.ToLower(args[0])
	c, err := g.client()
	if err != nil {
		return err
	}

	// Deleting a profile that addresses still point at would leave them naming
	// something that does not exist, which resolves to no filtering without
	// saying so.
	subs, err := loadSubscribers(c)
	if err != nil {
		return err
	}
	var users []string
	for _, s := range subs {
		if strings.EqualFold(s.Class, name) {
			users = append(users, s.Prefix)
		}
	}
	if len(users) > 0 {
		sort.Strings(users)
		return fmt.Errorf("%s is still assigned to %s; unassign them first", name, strings.Join(users, ", "))
	}

	if _, err := c.Delete(control.KindClass, name); err != nil {
		return err
	}
	fmt.Printf("deleted profile %s\n", name)
	return nil
}

func loadSubscribers(c *management.Client) ([]control.SubscriberRecord, error) {
	raws, err := c.List(control.KindSubscriber)
	if err != nil {
		return nil, err
	}
	out := make([]control.SubscriberRecord, 0, len(raws))
	for _, raw := range raws {
		var rec control.SubscriberRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("decoding a subscriber record: %w", err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func loadClasses(c *management.Client) (map[string]control.ClassRecord, error) {
	raws, err := c.List(control.KindClass)
	if err != nil {
		return nil, err
	}
	out := make(map[string]control.ClassRecord, len(raws))
	for _, raw := range raws {
		var rec control.ClassRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("decoding a class record: %w", err)
		}
		out[rec.Name] = rec
	}
	return out, nil
}

func loadFeeds(c *management.Client) (map[string]control.FeedRecord, error) {
	raws, err := c.List(control.KindFeed)
	if err != nil {
		return nil, err
	}
	out := make(map[string]control.FeedRecord, len(raws))
	for _, raw := range raws {
		var rec control.FeedRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("decoding a feed record: %w", err)
		}
		out[rec.Name] = rec
	}
	return out, nil
}

func policyProfiles(g globals) error {
	c, err := g.client()
	if err != nil {
		return err
	}
	classes, err := loadClasses(c)
	if err != nil {
		return err
	}
	subs, err := loadSubscribers(c)
	if err != nil {
		return err
	}
	assigned := map[string]int{}
	for _, s := range subs {
		assigned[strings.ToLower(s.Class)]++
	}

	names := make([]string, 0, len(classes))
	for n := range classes {
		names = append(names, n)
	}
	sort.Strings(names)

	if g.jsonOut {
		ordered := make([]control.ClassRecord, 0, len(names))
		for _, n := range names {
			ordered = append(ordered, classes[n])
		}
		return emitJSON(ordered)
	}
	if len(names) == 0 {
		fmt.Println("no profiles defined; nothing is filtered")
		fmt.Println("build one with: cgdnsctl policy profile set <name> --category security")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tACTION\tASSIGNED\tLISTS\t")
	for _, n := range names {
		cl := classes[n]
		action := cl.Action
		if action == "" {
			action = "nxdomain"
		}
		if action == "redirect" {
			action += " " + strings.Join(cl.RedirectTo, ",")
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", n, action, assigned[n], strings.Join(cl.Feeds, ", "))
	}
	return w.Flush()
}

func policyAssign(g globals, args []string) error {
	fs := flag.NewFlagSet("policy assign", flag.ContinueOnError)
	id := fs.String("id", "", "subscriber name for this prefix; defaults to the prefix itself")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 2 {
		return errors.New("policy assign needs a CIDR and a profile")
	}
	prefix, err := parsePrefixArg(rest[0])
	if err != nil {
		return err
	}
	profile := strings.ToLower(rest[1])

	c, err := g.client()
	if err != nil {
		return err
	}
	classes, err := loadClasses(c)
	if err != nil {
		return err
	}
	if _, ok := classes[profile]; !ok {
		known := make([]string, 0, len(classes))
		for n := range classes {
			known = append(known, n)
		}
		sort.Strings(known)
		if len(known) == 0 {
			return fmt.Errorf("no profile %q exists, and none are defined; create one with: cgdnsctl policy profile set %s --category security", profile, profile)
		}
		return fmt.Errorf("no profile %q; defined: %s", profile, strings.Join(known, ", "))
	}

	name := *id
	if name == "" {
		name = prefix.String()
	}
	rec := control.SubscriberRecord{Prefix: prefix.String(), ID: name, Class: profile}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := c.Put(control.KindSubscriber, payload); err != nil {
		return err
	}
	fmt.Printf("%s now uses profile %s (subscriber %s)\n", prefix, profile, name)
	return nil
}

// parsePrefixArg accepts a bare address as well as a CIDR, because assigning a
// profile to one customer is the common case and /32 is noise to type.
func parsePrefixArg(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is neither an address nor a CIDR", s)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func policyUnassign(g globals, args []string) error {
	if len(args) != 1 {
		return errors.New("policy unassign needs one CIDR")
	}
	prefix, err := parsePrefixArg(args[0])
	if err != nil {
		return err
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	if _, err := c.Delete(control.KindSubscriber, prefix.String()); err != nil {
		return err
	}
	fmt.Printf("%s is no longer assigned a profile and resolves unfiltered\n", prefix)
	return nil
}

func policyAssignments(g globals) error {
	c, err := g.client()
	if err != nil {
		return err
	}
	subs, err := loadSubscribers(c)
	if err != nil {
		return err
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Prefix < subs[j].Prefix })
	if g.jsonOut {
		return emitJSON(subs)
	}
	if len(subs) == 0 {
		fmt.Println("no assignments; every client resolves unfiltered")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PREFIX\tPROFILE\tSUBSCRIBER\t")
	for _, s := range subs {
		fmt.Fprintf(w, "%s\t%s\t%s\n", s.Prefix, s.Class, s.ID)
	}
	return w.Flush()
}

// policyShow answers the question a support call actually starts with: this
// address is seeing something blocked, why. It reports the assignment, the
// profile behind it, the lists in that profile, the subscriber's own overrides
// and anything mandatory — in the order the resolver consults them.
func policyShow(g globals, args []string) error {
	if len(args) != 1 {
		return errors.New("policy show needs one address")
	}
	addr, err := netip.ParseAddr(args[0])
	if err != nil {
		return fmt.Errorf("%q is not an address", args[0])
	}

	c, err := g.client()
	if err != nil {
		return err
	}
	subs, err := loadSubscribers(c)
	if err != nil {
		return err
	}
	classes, err := loadClasses(c)
	if err != nil {
		return err
	}
	feeds, err := loadFeeds(c)
	if err != nil {
		return err
	}

	// Longest match wins, the same way the resolver's classifier decides, so a
	// /32 exception inside an assigned /24 reads here as it behaves there.
	var best netip.Prefix
	var match *control.SubscriberRecord
	for i := range subs {
		p, err := netip.ParsePrefix(subs[i].Prefix)
		if err != nil || !p.Contains(addr) {
			continue
		}
		if match == nil || p.Bits() > best.Bits() {
			best, match = p, &subs[i]
		}
	}

	var mandatory []control.FeedRecord
	for _, f := range feeds {
		if f.Mandatory {
			mandatory = append(mandatory, f)
		}
	}
	sort.Slice(mandatory, func(i, j int) bool { return mandatory[i].Name < mandatory[j].Name })

	for _, f := range mandatory {
		fmt.Printf("mandatory  %s (%s) — applies to everyone, cannot be overridden\n", f.Name, f.Category)
	}

	if match == nil {
		if len(mandatory) == 0 {
			fmt.Printf("%s matches no assignment: it resolves unfiltered\n", addr)
		} else {
			fmt.Printf("%s matches no assignment: nothing beyond the mandatory lists above applies\n", addr)
		}
		return nil
	}

	fmt.Printf("%s matches %s (subscriber %s), profile %s\n", addr, best, match.ID, match.Class)

	cl, ok := classes[strings.ToLower(match.Class)]
	if !ok {
		fmt.Printf("  profile %s does not exist on this node — nothing from it is applied\n", match.Class)
		return nil
	}
	action := cl.Action
	if action == "" {
		action = "nxdomain"
	}
	if action == "redirect" {
		action += " to " + strings.Join(cl.RedirectTo, ", ")
	}
	fmt.Printf("  a match returns %s\n", action)
	for _, name := range cl.Feeds {
		f, ok := feeds[name]
		if !ok {
			fmt.Printf("  list %s is named by the profile but has no record here\n", name)
			continue
		}
		kind := f.Category
		if kind == "" {
			kind = "uncategorised"
		}
		if f.Managed {
			fmt.Printf("  list %s (%s, maintained here, %d entries)\n", name, kind, len(f.Entries))
		} else {
			fmt.Printf("  list %s (%s)\n", name, kind)
		}
	}

	raw, err := c.Get(control.KindOverride, match.ID)
	if err != nil {
		var apiErr *management.APIError
		if errors.As(err, &apiErr) && apiErr.NotFound() {
			return nil
		}
		return err
	}
	var ov control.OverrideRecord
	if err := json.Unmarshal(raw, &ov); err != nil {
		return err
	}
	if len(ov.Allow) > 0 {
		fmt.Printf("  allowed regardless of the lists: %s\n", strings.Join(ov.Allow, ", "))
	}
	if len(ov.Block) > 0 {
		fmt.Printf("  blocked regardless of the lists: %s\n", strings.Join(ov.Block, ", "))
	}
	return nil
}

// parseFlags parses a command's flags whatever order they were typed in.
//
// The standard flag package stops at the first argument that is not a flag, so
// "profile set family --category security" would parse zero flags and build a
// profile that filters nothing — with no error, because the flags it never saw
// simply keep their defaults. Nobody types the flags first, so the parser has
// to accept both.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		if strings.Contains(a, "=") {
			continue
		}
		f := fs.Lookup(strings.TrimLeft(a, "-"))
		if f == nil {
			continue
		}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return positional, nil
}
