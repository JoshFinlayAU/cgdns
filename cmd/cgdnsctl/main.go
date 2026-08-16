// Command cgdnsctl is the operator CLI for a cgdns node.
//
// It is a client of the node's management API and holds no privileged state of
// its own, so anything it can do can equally be done by a provisioning system
// over HTTP. Because a POP pair replicates its control plane, pointing this at
// either node of a pair is equivalent.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/JoshFinlayAU/cgdns/internal/control"
	"github.com/JoshFinlayAU/cgdns/internal/management"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// defaultTokenFile is where the daemon writes its bootstrap token, so cgdnsctl
// run on the node itself needs no configuration.
const defaultTokenFile = "/var/lib/cgdns/bootstrap.token"

func main() {
	if err := run(os.Args[1:]); err != nil {
		var apiErr *management.APIError
		if errors.As(err, &apiErr) && apiErr.NotFound() {
			fmt.Fprintf(os.Stderr, "cgdnsctl: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "cgdnsctl: %v\n", err)
		os.Exit(1)
	}
}

type globals struct {
	addr      string
	token     string
	tokenFile string
	caFile    string
	insecure  bool
	timeout   time.Duration
	jsonOut   bool
}

func run(args []string) error {
	var g globals
	fs := flag.NewFlagSet("cgdnsctl", flag.ContinueOnError)
	fs.StringVar(&g.addr, "addr", envOr("CGDNS_ADDR", "127.0.0.1:8443"), "node management address (env CGDNS_ADDR)")
	fs.StringVar(&g.token, "token", os.Getenv("CGDNS_TOKEN"), "API token (env CGDNS_TOKEN)")
	fs.StringVar(&g.tokenFile, "token-file", envOr("CGDNS_TOKEN_FILE", defaultTokenFile), "read the token from this file (env CGDNS_TOKEN_FILE)")
	fs.StringVar(&g.caFile, "ca", os.Getenv("CGDNS_CA"), "CA certificate that signs the node's certificate (env CGDNS_CA)")
	fs.BoolVar(&g.insecure, "insecure", false, "skip TLS verification (lab only: the plane can be impersonated and the token is sent in a header)")
	fs.DurationVar(&g.timeout, "timeout", 10*time.Second, "request timeout")
	fs.BoolVar(&g.jsonOut, "json", false, "emit raw JSON instead of a table")
	showVer := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() { usage(fs) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *showVer {
		fmt.Printf("cgdnsctl %s\n", version)
		return nil
	}

	rest := fs.Args()
	if len(rest) == 0 {
		usage(fs)
		return errors.New("a command is required")
	}

	switch rest[0] {
	case "status":
		return cmdStatus(g, rest[1:])
	case "drift":
		return cmdDrift(g, rest[1:])
	case "records":
		return cmdRecords(g, rest[1:])
	case "token":
		return cmdToken(g, rest[1:])
	case "user":
		return cmdUser(g, rest[1:])
	case "allow", "block":
		return cmdOverrideList(g, rest[0], rest[1:])
	case "help":
		usage(fs)
		return nil
	default:
		if _, ok := management.KindFor(plural(rest[0])); ok {
			return cmdRecord(g, plural(rest[0]), rest[1:])
		}
		usage(fs)
		return fmt.Errorf("unknown command %q", rest[0])
	}
}

func usage(fs *flag.FlagSet) {
	nouns := management.Nouns()
	sort.Strings(nouns)
	fmt.Fprintf(os.Stderr, `cgdnsctl - operate a cgdns node

  A POP pair replicates its control plane, so pointing this at either node of a
  pair is equivalent.

Usage:
  cgdnsctl [flags] <command> [args]

Commands:
  status                          node health, pair link and store hash
  drift <addr> [<addr>...]        compare the store hash across a pair
  records                         dump every control record
  token list                      list API tokens
  token create <name> <scopes>    mint a token (scopes: read,write,admin)
  token revoke <id>               revoke a token
  user list                       list operator accounts (WebUI logins)
  user create <name> <scopes>     add one; the password is prompted for
  user delete <name>              remove one

  <noun> list                     list records        (nouns: %s)
  <noun> get <key>                show one record
  <noun> set <json>               create or replace a record
  <noun> delete <key>             delete a record

  allow <subscriber> <domain>...  add domains to a subscriber's allow list
  block <subscriber> <domain>...  add domains to a subscriber's block list

Flags:
`, strings.Join(nouns, ", "))
	fs.PrintDefaults()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// plural lets an operator type the singular noun.
func plural(noun string) string {
	if _, ok := management.KindFor(noun); ok {
		return noun
	}
	if _, ok := management.KindFor(noun + "s"); ok {
		return noun + "s"
	}
	if noun == "class" {
		return "classes"
	}
	return noun
}

// client resolves the token and builds an API client.
func (g globals) client() (*management.Client, error) {
	return g.clientFor(g.addr)
}

func (g globals) clientFor(addr string) (*management.Client, error) {
	token := g.token
	if token == "" && g.tokenFile != "" {
		raw, err := os.ReadFile(g.tokenFile)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("no token: pass -token, set CGDNS_TOKEN, or point -token-file at a readable file (tried %s)", g.tokenFile)
			}
			return nil, fmt.Errorf("reading %s: %w", g.tokenFile, err)
		}
		token = strings.TrimSpace(string(raw))
	}
	return management.NewClient(management.ClientOptions{
		Addr: addr, Token: token, CAFile: g.caFile, Insecure: g.insecure, Timeout: g.timeout,
	})
}

func cmdStatus(g globals, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("status takes no arguments")
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	s, err := c.Status()
	if err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(s)
	}

	fmt.Printf("node        %s\n", s.NodeID)
	fmt.Printf("version     %s\n", s.Version)
	fmt.Printf("uptime      %s\n", s.Uptime)
	fmt.Printf("healthy     %s\n", yesNo(s.Healthy))
	fmt.Printf("advertised  %s\n", yesNo(s.Advertised))
	fmt.Printf("pair link   out=%s in=%s\n", upDown(s.PeerOutboundUp), upDown(s.PeerInboundUp))
	fmt.Printf("records     %d\n", s.Records)
	fmt.Printf("store hash  %s\n", s.StoreHash)
	return nil
}

// cmdDrift compares the store hash across the nodes of a pair.
//
// The hash is the only drift detector a pair has, since there is no consensus
// to appeal to: a lasting disagreement means a provisioning write reached one
// node and not the other.
func cmdDrift(g globals, args []string) error {
	addrs := args
	if len(addrs) == 0 {
		return errors.New("drift needs the addresses of the nodes to compare")
	}
	if len(addrs) == 1 {
		return errors.New("drift compares nodes, so it needs at least two addresses")
	}

	type result struct {
		Addr   string `json:"addr"`
		Node   string `json:"node,omitempty"`
		Hash   string `json:"hash,omitempty"`
		Errord string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(addrs))
	for _, addr := range addrs {
		c, err := g.clientFor(addr)
		if err != nil {
			results = append(results, result{Addr: addr, Errord: err.Error()})
			continue
		}
		s, err := c.Status()
		if err != nil {
			results = append(results, result{Addr: addr, Errord: err.Error()})
			continue
		}
		results = append(results, result{Addr: addr, Node: s.NodeID, Hash: s.StoreHash})
	}

	if g.jsonOut {
		return emitJSON(results)
	}

	reachable := 0
	hashes := map[string]bool{}
	for _, r := range results {
		if r.Errord != "" {
			fmt.Printf("%-24s unreachable: %s\n", r.Addr, r.Errord)
			continue
		}
		reachable++
		hashes[r.Hash] = true
		fmt.Printf("%-24s %-10s %s\n", r.Addr, r.Node, r.Hash)
	}

	switch {
	case reachable < 2:
		// Not a verdict: one node answering says nothing about whether the pair
		// agrees, and reporting "in step" here would be a lie of omission.
		return errors.New("fewer than two nodes answered, so drift cannot be determined")
	case len(hashes) == 1:
		fmt.Println("\nin step")
		return nil
	default:
		fmt.Println("\nDRIFT: the nodes disagree; a provisioning write reached some and not others")
		return errors.New("store hashes disagree")
	}
}

func cmdRecords(g globals, args []string) error {
	if len(args) > 0 {
		return errors.New("records takes no arguments")
	}
	c, err := g.client()
	if err != nil {
		return err
	}
	resp, err := c.Records()
	if err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(resp)
	}

	fmt.Printf("%-12s %-30s %-8s %-14s %s\n", "KIND", "KEY", "LAMPORT", "ORIGIN", "STATE")
	for _, r := range resp.Records {
		state := "live"
		if r.Deleted {
			state = "tombstone"
		}
		fmt.Printf("%-12s %-30s %-8d %-14s %s\n", r.Kind, r.Key, r.Lamport, r.Origin, state)
	}
	fmt.Printf("\nstore hash %s\n", resp.Hash)
	return nil
}

func cmdRecord(g globals, noun string, args []string) error {
	kind, ok := management.KindFor(noun)
	if !ok {
		return fmt.Errorf("unknown record type %q", noun)
	}
	if len(args) == 0 {
		return fmt.Errorf("%s needs a subcommand: list, get, set or delete", noun)
	}

	c, err := g.client()
	if err != nil {
		return err
	}

	switch args[0] {
	case "list":
		items, err := c.List(kind)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return emitJSON(items)
		}
		if len(items) == 0 {
			fmt.Printf("no %s\n", noun)
			return nil
		}
		for _, item := range items {
			fmt.Println(compact(item))
		}
		return nil

	case "get":
		if len(args) != 2 {
			return fmt.Errorf("%s get needs a key", noun)
		}
		raw, err := c.Get(kind, args[1])
		if err != nil {
			return err
		}
		return emitJSON(json.RawMessage(raw))

	case "set":
		if len(args) != 2 {
			return fmt.Errorf("%s set needs a JSON record", noun)
		}
		payload, err := readPayload(args[1])
		if err != nil {
			return err
		}
		resp, err := c.Put(kind, payload)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return emitJSON(resp)
		}
		fmt.Printf("wrote %s %s (lamport %d)\nstore hash %s\n", resp.Kind, resp.Key, resp.Lamport, resp.Hash)
		return nil

	case "delete":
		if len(args) != 2 {
			return fmt.Errorf("%s delete needs a key", noun)
		}
		resp, err := c.Delete(kind, args[1])
		if err != nil {
			return err
		}
		if g.jsonOut {
			return emitJSON(resp)
		}
		fmt.Printf("deleted %s\nstore hash %s\n", resp.Deleted, resp.Hash)
		return nil

	default:
		return fmt.Errorf("unknown %s subcommand %q", noun, args[0])
	}
}

// cmdOverrideList adds domains to a subscriber's allow or block list.
//
// It reads the current record and writes it back, because the API replaces a
// record rather than patching it. Two operators editing the same subscriber at
// the same moment can therefore lose one edit; that is the same last-write-wins
// the control plane has everywhere, and provisioning is normally the only
// writer.
func cmdOverrideList(g globals, which string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("%s needs a subscriber and at least one domain", which)
	}
	subscriber, domains := args[0], args[1:]

	c, err := g.client()
	if err != nil {
		return err
	}

	rec := control.OverrideRecord{SubscriberID: subscriber}
	raw, err := c.Get(control.KindOverride, subscriber)
	if err != nil {
		var apiErr *management.APIError
		if !errors.As(err, &apiErr) || !apiErr.NotFound() {
			return err
		}
	} else if err := json.Unmarshal(raw, &rec); err != nil {
		return fmt.Errorf("decoding the existing override: %w", err)
	}

	if which == "allow" {
		rec.Allow = append(rec.Allow, domains...)
	} else {
		rec.Block = append(rec.Block, domains...)
	}

	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	resp, err := c.Put(control.KindOverride, payload)
	if err != nil {
		return err
	}

	// Read back rather than echo what was sent: the server lowercases, sorts and
	// dedupes, so what was sent is not necessarily what is now in force.
	stored, err := c.Get(control.KindOverride, subscriber)
	if err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(json.RawMessage(stored))
	}
	fmt.Printf("%s now:\n", subscriber)
	fmt.Println(compact(stored))
	fmt.Printf("store hash %s\n", resp.Hash)
	return nil
}

func cmdToken(g globals, args []string) error {
	if len(args) == 0 {
		return errors.New("token needs a subcommand: list, create or revoke")
	}
	c, err := g.client()
	if err != nil {
		return err
	}

	switch args[0] {
	case "list":
		tokens, err := c.Tokens()
		if err != nil {
			return err
		}
		if g.jsonOut {
			return emitJSON(tokens)
		}
		fmt.Printf("%-18s %-20s %-18s %s\n", "ID", "NAME", "SCOPES", "EXPIRES")
		for _, t := range tokens {
			expires := "never"
			if !t.Expires.IsZero() {
				expires = t.Expires.Format(time.RFC3339)
			}
			fmt.Printf("%-18s %-20s %-18s %s\n", t.ID, t.Name, joinScopes(t.Scopes), expires)
		}
		return nil

	case "create":
		if len(args) < 2 {
			return errors.New("token create needs a name, and optionally scopes (default: read)")
		}
		req := management.TokenRequest{Name: args[1], Scopes: []management.Scope{management.ScopeRead}}
		if len(args) >= 3 {
			req.Scopes = parseScopes(args[2])
		}
		if len(args) >= 4 {
			req.TTL = args[3]
		}
		minted, err := c.CreateToken(req)
		if err != nil {
			return err
		}
		if g.jsonOut {
			return emitJSON(minted)
		}
		fmt.Printf("id     %s\n", minted.ID)
		fmt.Printf("name   %s\n", minted.Name)
		fmt.Printf("scopes %s\n", joinScopes(minted.Scopes))
		if minted.Expires != nil {
			fmt.Printf("expires %s\n", minted.Expires.Format(time.RFC3339))
		}
		fmt.Printf("\ntoken  %s\n", minted.Token)
		fmt.Fprintln(os.Stderr, "\nthis is the only time the token is shown; it cannot be recovered")
		return nil

	case "revoke":
		if len(args) != 2 {
			return errors.New("token revoke needs a token ID")
		}
		if err := c.RevokeToken(args[1]); err != nil {
			return err
		}
		fmt.Printf("revoked %s\n", args[1])
		return nil

	default:
		return fmt.Errorf("unknown token subcommand %q", args[0])
	}
}

func cmdUser(g globals, args []string) error {
	if len(args) == 0 {
		return errors.New("user needs a subcommand: list, create or delete")
	}
	c, err := g.client()
	if err != nil {
		return err
	}

	switch args[0] {
	case "list":
		users, err := c.Users()
		if err != nil {
			return err
		}
		if g.jsonOut {
			return emitJSON(users)
		}
		fmt.Printf("%-16s %-18s %-6s %s\n", "NAME", "SCOPES", "TOTP", "LAST LOGIN")
		for _, u := range users {
			last := "never"
			if !u.LastLogin.IsZero() {
				last = u.LastLogin.Format(time.RFC3339)
			}
			state := "no"
			if u.TOTPConfirmed {
				state = "yes"
			}
			if u.Disabled {
				state += " (disabled)"
			}
			fmt.Printf("%-16s %-18s %-6s %s\n", u.Name, joinScopes(u.Scopes), state, last)
		}
		return nil

	case "create":
		if len(args) < 2 {
			return errors.New("user create needs a name, and optionally scopes (default: read)")
		}
		scopes := []management.Scope{management.ScopeRead}
		if len(args) >= 3 {
			scopes = parseScopes(args[2])
		}
		// Read the password from the terminal rather than take it as an
		// argument: an argument lands in the shell history and in ps output.
		password, err := readPassword("password for " + args[1] + ": ")
		if err != nil {
			return err
		}
		again, err := readPassword("repeat: ")
		if err != nil {
			return err
		}
		if password != again {
			return errors.New("the two passwords do not match")
		}
		if err := c.CreateUser(args[1], password, scopes); err != nil {
			return err
		}
		fmt.Printf("created %s with scopes %s\n", args[1], joinScopes(scopes))
		fmt.Fprintln(os.Stderr, "they should enrol a second factor from the WebUI at first login")
		return nil

	case "delete":
		if len(args) != 2 {
			return errors.New("user delete needs a name")
		}
		if err := c.DeleteUser(args[1]); err != nil {
			return err
		}
		fmt.Printf("deleted %s\n", args[1])
		return nil

	default:
		return fmt.Errorf("unknown user subcommand %q", args[0])
	}
}

// stdin is buffered once, so successive prompts read successive lines.
var stdin = bufio.NewReader(os.Stdin)

// readPassword reads without echoing when stdin is a terminal, so a password
// does not end up on screen or in a scrollback buffer.
func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	defer fmt.Fprintln(os.Stderr)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		raw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	// Not a terminal: read a line, which is what a scripted invocation feeds.
	// The reader is shared across calls, because a fresh one would buffer every
	// line piped in and leave the next call with nothing.
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func parseScopes(csv string) []management.Scope {
	var out []management.Scope
	for _, s := range strings.Split(csv, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, management.Scope(s))
		}
	}
	return out
}

func joinScopes(scopes []management.Scope) string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, string(s))
	}
	return strings.Join(out, ",")
}

// readPayload accepts JSON inline, from a file with @path, or on stdin with -.
func readPayload(arg string) ([]byte, error) {
	switch {
	case arg == "-":
		return readAllStdin()
	case strings.HasPrefix(arg, "@"):
		return os.ReadFile(strings.TrimPrefix(arg, "@"))
	default:
		return []byte(arg), nil
	}
}

func readAllStdin() ([]byte, error) {
	var buf []byte
	chunk := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			break
		}
		if len(buf) > 1<<20 {
			return nil, errors.New("stdin payload is too large")
		}
	}
	return buf, nil
}

func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func compact(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func upDown(b bool) string {
	if b {
		return "up"
	}
	return "down"
}
