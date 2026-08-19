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

func policyList(g globals, args []string) error {
	if len(args) == 0 {
		return errors.New("policy list needs create, add, remove or show")
	}
	switch args[0] {
	case "create":
		return policyListCreate(g, args[1:])
	case "add":
		return policyListAdd(g, args[1:])
	case "remove":
		return policyListRemove(g, args[1:])
	case "show":
		return policyListShow(g, args[1:])
	case "delete":
		return policyListDelete(g, args[1:])
	default:
		return fmt.Errorf("unknown policy list subcommand %q", args[0])
	}
}

func policyListCreate(g globals, args []string) error {
	fs := flag.NewFlagSet("policy list create", flag.ContinueOnError)
	category := fs.String("category", policy.CategoryCompliance, "what this list filters")
	mandatory := fs.Bool("mandatory", false, "apply to every client, above every profile and every subscriber allow list")
	url := fs.String("url", "", "fetch rules from this RPZ URL as well as the entries kept here")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("policy list create needs one name")
	}
	name := rest[0]

	c, err := g.client()
	if err != nil {
		return err
	}
	if _, err := c.Get(control.KindFeed, name); err == nil {
		return fmt.Errorf("a list named %q already exists", name)
	} else {
		var apiErr *management.APIError
		if !errors.As(err, &apiErr) || !apiErr.NotFound() {
			return err
		}
	}

	rec := control.FeedRecord{
		Name:      name,
		Format:    "rpz",
		URL:       *url,
		Category:  *category,
		Mandatory: *mandatory,
		Managed:   true,
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := c.Put(control.KindFeed, payload); err != nil {
		return err
	}

	fmt.Printf("created list %s (%s)\n", name, *category)
	if *mandatory {
		fmt.Println("it is mandatory: every client is subject to it and no allow list overrides it")
	} else {
		fmt.Printf("include it in a profile with: cgdnsctl policy profile set <profile> --list %s\n", name)
	}
	if *url != "" {
		fmt.Printf("it also fetches %s; entries added here apply on top\n", *url)
	}
	return nil
}

func policyListAdd(g globals, args []string) error {
	fs := flag.NewFlagSet("policy list add", flag.ContinueOnError)
	var redirects repeatable
	fs.Var(&redirects, "redirect", "send this name to an address instead of refusing it (repeatable)")
	note := fs.String("note", "", "why this entry exists — the order, ticket or authority behind it")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(rest) < 2 {
		return errors.New("policy list add needs a list name and at least one domain")
	}
	name, domains := rest[0], rest[1:]

	action := ""
	if len(redirects) > 0 {
		action = "redirect"
		for _, r := range redirects {
			if _, err := netip.ParseAddr(r); err != nil {
				return fmt.Errorf("--redirect %q is not an address", r)
			}
		}
	}

	c, err := g.client()
	if err != nil {
		return err
	}
	rec, err := fetchManagedList(c, name)
	if err != nil {
		return err
	}

	byName := map[string]int{}
	for i, e := range rec.Entries {
		byName[e.Name] = i
	}
	added, updated := 0, 0
	for _, d := range domains {
		entry := control.ManagedEntry{
			Name:   strings.ToLower(strings.TrimSuffix(d, ".")),
			Action: action,
			To:     redirects,
			Note:   *note,
		}
		if i, ok := byName[entry.Name]; ok {
			rec.Entries[i] = entry
			updated++
			continue
		}
		rec.Entries = append(rec.Entries, entry)
		added++
	}

	if err := putList(c, rec); err != nil {
		return err
	}
	if *note == "" && rec.Mandatory {
		fmt.Fprintln(os.Stderr, "warning: no --note on a mandatory entry; there is then no record of whose authority it was added under")
	}
	fmt.Printf("%s: %d added, %d updated, %d entries total\n", name, added, updated, len(rec.Entries))
	return nil
}

func policyListRemove(g globals, args []string) error {
	if len(args) < 2 {
		return errors.New("policy list remove needs a list name and at least one domain")
	}
	name, domains := args[0], args[1:]

	c, err := g.client()
	if err != nil {
		return err
	}
	rec, err := fetchManagedList(c, name)
	if err != nil {
		return err
	}

	drop := map[string]bool{}
	for _, d := range domains {
		drop[strings.ToLower(strings.TrimSuffix(d, "."))] = true
	}
	kept := rec.Entries[:0]
	removed := 0
	for _, e := range rec.Entries {
		if drop[e.Name] {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	rec.Entries = kept

	if removed == 0 {
		return fmt.Errorf("%s holds none of those names", name)
	}
	if err := putList(c, rec); err != nil {
		return err
	}
	fmt.Printf("%s: %d removed, %d entries remain\n", name, removed, len(rec.Entries))
	return nil
}

func policyListShow(g globals, args []string) error {
	if len(args) != 1 {
		return errors.New("policy list show needs one name")
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	rec, err := fetchManagedList(c, args[0])
	if err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(rec)
	}

	fmt.Printf("%s — %s", rec.Name, rec.Category)
	if rec.Mandatory {
		fmt.Print(", mandatory for every client")
	}
	fmt.Println()
	if rec.URL != "" {
		fmt.Printf("also fetches %s\n", rec.URL)
	}
	if len(rec.Entries) == 0 {
		fmt.Println("no entries")
		return nil
	}
	sort.Slice(rec.Entries, func(i, j int) bool { return rec.Entries[i].Name < rec.Entries[j].Name })
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tACTION\tAUTHORITY\t")
	for _, e := range rec.Entries {
		action := e.Action
		if action == "" {
			action = "nxdomain"
		}
		if action == "redirect" {
			action += " " + strings.Join(e.To, ",")
		}
		note := e.Note
		if note == "" {
			note = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", e.Name, action, note)
	}
	return w.Flush()
}

func policyListDelete(g globals, args []string) error {
	if len(args) != 1 {
		return errors.New("policy list delete needs one name")
	}
	name := args[0]
	c, err := g.client()
	if err != nil {
		return err
	}
	rec, err := fetchManagedList(c, name)
	if err != nil {
		return err
	}

	classes, err := loadClasses(c)
	if err != nil {
		return err
	}
	var users []string
	for _, cl := range classes {
		for _, f := range cl.Feeds {
			if f == name {
				users = append(users, cl.Name)
			}
		}
	}
	if len(users) > 0 {
		sort.Strings(users)
		return fmt.Errorf("%s is used by profile %s; remove it from them first", name, strings.Join(users, ", "))
	}
	if rec.Mandatory && len(rec.Entries) > 0 {
		return fmt.Errorf("%s is mandatory and holds %d entries; empty it first if that is really the intent", name, len(rec.Entries))
	}

	if _, err := c.Delete(control.KindFeed, name); err != nil {
		return err
	}
	fmt.Printf("deleted list %s\n", name)
	return nil
}

func policyLists(g globals) error {
	c, err := g.client()
	if err != nil {
		return err
	}
	feeds, err := loadFeeds(c)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(feeds))
	for n := range feeds {
		names = append(names, n)
	}
	sort.Strings(names)
	if g.jsonOut {
		ordered := make([]control.FeedRecord, 0, len(names))
		for _, n := range names {
			ordered = append(ordered, feeds[n])
		}
		return emitJSON(ordered)
	}
	if len(names) == 0 {
		fmt.Println("no lists on this node")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tCATEGORY\tSOURCE\tENTRIES\tSCOPE\t")
	for _, n := range names {
		f := feeds[n]
		source := "fetched"
		switch {
		case f.Managed && f.URL != "":
			source = "fetched + maintained here"
		case f.Managed:
			source = "maintained here"
		case f.File != "":
			source = "file"
		}
		entries := "-"
		if f.Managed {
			entries = fmt.Sprintf("%d", len(f.Entries))
		}
		scope := "by profile"
		if f.Mandatory {
			scope = "everyone"
		}
		category := f.Category
		if category == "" {
			category = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", n, category, source, entries, scope)
	}
	return w.Flush()
}

// fetchManagedList loads a list and refuses one that is not maintained here.
// Editing entries into a fetched feed would work until the next refresh
// replaced the file and silently dropped them.
func fetchManagedList(c *management.Client, name string) (control.FeedRecord, error) {
	raw, err := c.Get(control.KindFeed, name)
	if err != nil {
		var apiErr *management.APIError
		if errors.As(err, &apiErr) && apiErr.NotFound() {
			return control.FeedRecord{}, fmt.Errorf("no list named %q; create it with: cgdnsctl policy list create %s", name, name)
		}
		return control.FeedRecord{}, err
	}
	var rec control.FeedRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return control.FeedRecord{}, fmt.Errorf("decoding list %s: %w", name, err)
	}
	if !rec.Managed {
		return control.FeedRecord{}, fmt.Errorf("%s is a fetched feed, not one maintained here; its next refresh would discard anything added", name)
	}
	return rec, nil
}

func putList(c *management.Client, rec control.FeedRecord) error {
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = c.Put(control.KindFeed, payload)
	return err
}
