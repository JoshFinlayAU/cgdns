// Package config defines the single cgdns configuration struct and its
// validation. One struct, one YAML file, validated fully at startup: a bad
// config must fail loudly at boot rather than silently defaulting into a
// resolver that behaves differently to the one the operator described.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrInvalid is the sentinel wrapping every validation failure. Callers that
// only need "was this the operator's fault" can errors.Is against it.
var ErrInvalid = errors.New("invalid config")

// Config is the whole of cgdns's configuration. Every field is validated by
// Validate; there is no lazily-defaulted state hiding elsewhere in the daemon.
type Config struct {
	Node       Node       `yaml:"node"`
	Listen     Listen     `yaml:"listen"`
	Resolver   Resolver   `yaml:"resolver"`
	Cache      Cache      `yaml:"cache"`
	Subscriber Subscriber `yaml:"subscriber"`
	Policy     Policy     `yaml:"policy"`
	Health     Health     `yaml:"health"`
	Management Management `yaml:"management"`
	Metrics    Metrics    `yaml:"metrics"`
	Log        Log        `yaml:"log"`
}

// Node identifies this daemon within a cluster.
type Node struct {
	// ID must be unique across the cluster; it becomes the raft server ID and
	// the memberlist node name once clustering lands.
	ID string `yaml:"id"`
	// StateDir holds RFC 5011 trust-anchor state, raft logs and snapshots.
	// Wiping it is not harmless — it re-bootstraps the trust anchor.
	StateDir string `yaml:"state_dir"`
}

// Listen describes the client-facing sockets.
//
// Addresses are always explicit — never a wildcard. A wildcard PacketConn
// loses the destination address, so an anycast reply can leave from the wrong
// source IP. Binding each address individually keeps the source correct.
type Listen struct {
	UDP []string `yaml:"udp"`
	TCP []string `yaml:"tcp"`

	// UDPSocketsPerAddr is how many SO_REUSEPORT sockets to open per UDP
	// address. The kernel load-balances across them, which lets us scale past
	// the single-socket receive-queue ceiling. 0 means one per GOMAXPROCS CPU.
	UDPSocketsPerAddr int `yaml:"udp_sockets_per_addr"`

	MaxTCPConns    int           `yaml:"max_tcp_conns"`
	TCPIdleTimeout time.Duration `yaml:"tcp_idle_timeout"`

	// DoT serves DNS over TLS (RFC 7858), conventionally on 853.
	DoT []string `yaml:"dot"`
	// DoH serves DNS over HTTPS (RFC 8484), conventionally on 443.
	DoH []string `yaml:"doh"`
	// DoHPath is the DoH query endpoint.
	DoHPath string `yaml:"doh_path"`
	// TLS is the certificate for DoT and DoH. Required when either is set.
	TLS TLS `yaml:"tls"`
	// DoHTrustedProxies are sources whose forwarding headers may be believed
	// for the client address. Behind an L7 proxy the TCP peer is the proxy, so
	// without this every DoH client classifies as the proxy; trusting the
	// header from anywhere else lets a client spoof another subscriber.
	DoHTrustedProxies []string `yaml:"doh_trusted_proxies"`

	// AllowQuery is the source-prefix allow list for DNS clients. Default
	// deny, and required: a recursive resolver reachable from the internet is
	// a reflection/amplification source, and the operator must state which
	// subscriber ranges may use it rather than inherit a permissive default.
	AllowQuery []string `yaml:"allow_query"`
}

// ResolverMode selects the query strategy.
type ResolverMode string

const (
	ModeForward   ResolverMode = "forward"
	ModeRecursive ResolverMode = "recursive"
)

// Resolver holds the query-path budgets and protocol toggles.
type Resolver struct {
	Mode ResolverMode `yaml:"mode"`

	// Upstreams is required in forward mode, ignored in recursive mode.
	Upstreams []string `yaml:"upstreams"`

	// ClientBudget is the total wall-clock a client query may consume. Every
	// outbound query derives its deadline from what is left of this.
	ClientBudget time.Duration `yaml:"client_budget"`
	// QueryTimeout bounds a single outbound exchange within that budget.
	QueryTimeout time.Duration `yaml:"query_timeout"`

	// MaxDelegationDepth and MaxOutboundPerQuery kill referral loops and
	// amplification via deep delegation chains.
	MaxDelegationDepth  int `yaml:"max_delegation_depth"`
	MaxOutboundPerQuery int `yaml:"max_outbound_per_query"`
	// MaxCNAMEChain caps how far a CNAME chain is followed.
	MaxCNAMEChain int `yaml:"max_cname_chain"`

	// RootHintsFile overrides the root hints shipped in the package. Empty
	// uses the embedded copy, which is the normal case — a node that has been
	// down for months may need a fresher one.
	RootHintsFile string `yaml:"root_hints_file"`

	// UseIPv4 and UseIPv6 select the outbound families for recursion. Both
	// default true and disabling IPv6 should be a temporary workaround, not a
	// deployment choice: v6-only authoritatives exist and a v4-only resolver
	// fails on them.
	UseIPv4 bool `yaml:"use_ipv4"`
	UseIPv6 bool `yaml:"use_ipv6"`

	// DNSSEC enables validation. A failed chain becomes SERVFAIL with an
	// RFC 8914 extended error; there is no downgrade to an unvalidated answer.
	DNSSEC bool `yaml:"dnssec"`
	// TrustAnchorFile overrides the root anchors shipped in the package. A node
	// down long enough to miss a KSK rollover needs a fresh copy.
	TrustAnchorFile string `yaml:"trust_anchor_file"`
	// AcceptSHA1 permits RSASHA1 signatures. SHA-1 is not collision resistant;
	// enabling it weakens the guarantee validation exists to provide.
	AcceptSHA1 bool `yaml:"accept_sha1"`

	// UDPBufferSize is the EDNS0 advertised buffer. 1232 avoids fragmentation
	// on paths with a 1280-byte IPv6 MTU (DNS Flag Day 2020).
	UDPBufferSize uint16 `yaml:"udp_buffer_size"`

	// QNAMEMinimisation (RFC 9156) and CaseRandomisation (0x20) default on,
	// with an escape hatch for authoritatives that break under them.
	QNAMEMinimisation bool `yaml:"qname_minimisation"`
	CaseRandomisation bool `yaml:"case_randomisation"`
}

// Cache sizes the RRset and negative caches.
type Cache struct {
	// MaxEntries is a per-cache ceiling, enforced by LRU eviction.
	MaxEntries int `yaml:"max_entries"`
	// Shards must be a power of two; lookups mask the hash rather than
	// dividing. More shards means less lock contention across cores.
	Shards int `yaml:"shards"`

	// MinTTL and MaxTTL clamp what an authoritative tells us. MinTTL protects
	// upstreams from TTL-0 records; MaxTTL bounds how stale we can get.
	MinTTL time.Duration `yaml:"min_ttl"`
	MaxTTL time.Duration `yaml:"max_ttl"`
	// MaxNegativeTTL caps RFC 2308 negative caching independently — an
	// operator usually wants NXDOMAIN forgotten sooner than a positive answer.
	MaxNegativeTTL time.Duration `yaml:"max_negative_ttl"`

	// Infra sizes the infrastructure cache: what we know about authoritative
	// servers themselves (RTT, health, EDNS quirks) as opposed to their data.
	Infra InfraCache `yaml:"infra"`
}

// InfraCache configures the per-nameserver infrastructure cache.
type InfraCache struct {
	MaxEntries int `yaml:"max_entries"`
	Shards     int `yaml:"shards"`
	// InitialRTT is assumed for a server we have never spoken to.
	InitialRTT time.Duration `yaml:"initial_rtt"`
	// MaxBackoff caps how long a repeatedly-failing server is skipped.
	MaxBackoff time.Duration `yaml:"max_backoff"`
}

// Subscriber configures how a client address maps to a policy class.
//
// Identity is by source prefix: a longest-prefix match over a v4+v6 trie. In
// production the trie is populated from raft; PrefixFile is the dev path in.
type Subscriber struct {
	// DefaultClass applies to any client that matches no configured prefix.
	DefaultClass string `yaml:"default_class"`
	// PrefixFile is an optional "prefix class" file loaded at startup.
	PrefixFile string `yaml:"prefix_file"`
}

// Policy configures subscriber content filtering.
//
// Feed content is never carried in raft: it runs to millions of rows and would
// stall snapshots. Raft holds only the metadata naming a feed and the classes
// subscribed to it; each node fetches the content and verifies it.
type Policy struct {
	Enabled bool          `yaml:"enabled"`
	Feeds   []PolicyFeed  `yaml:"feeds"`
	Classes []PolicyClass `yaml:"classes"`
	// OverridesFile holds per-subscriber allow and block rules. A subscriber's
	// allow list beats every class feed, which is what lets one customer be
	// unblocked without editing a shared list.
	OverridesFile string `yaml:"overrides_file"`
}

// PolicyFeed is one blocklist source.
type PolicyFeed struct {
	Name string `yaml:"name"`
	// Format is domain-list or rpz.
	Format string `yaml:"format"`
	File   string `yaml:"file"`
	// RPZZone is required for rpz feeds.
	RPZZone string `yaml:"rpz_zone"`
}

// PolicyClass binds feeds and a block action to a subscriber class.
type PolicyClass struct {
	Name  string   `yaml:"name"`
	Feeds []string `yaml:"feeds"`
	// Action is nxdomain, nodata, redirect or drop.
	Action string `yaml:"action"`
	// RedirectTo is the walled-garden address set for the redirect action.
	RedirectTo []string `yaml:"redirect_to"`
}

// Health configures the anycast health decision.
//
// Withdrawal is fast and re-advertisement is dampened: a dead node costs only
// the traffic heading to it, while a flapping prefix reconverges the whole
// anycast set every time it moves.
type Health struct {
	Enabled bool `yaml:"enabled"`

	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`

	FailureThreshold int `yaml:"failure_threshold"`
	SuccessThreshold int `yaml:"success_threshold"`

	MinHold     time.Duration `yaml:"min_hold"`
	MaxHold     time.Duration `yaml:"max_hold"`
	StableAfter time.Duration `yaml:"stable_after"`

	// Canary is an optional extra name to probe, in addition to the root NS
	// check. Pointing it at a third party means their outage withdraws this
	// node, so choose something you operate.
	Canary string `yaml:"canary"`

	// AnycastPrefixes are the routes this node originates when healthy.
	AnycastPrefixes []string `yaml:"anycast_prefixes"`

	// GoBGPTarget is gobgpd's gRPC address.
	GoBGPTarget string `yaml:"gobgp_target"`
}

// Management configures the operator plane: REST API, CLI backend and WebUI.
//
// This is an administrative surface on a carrier resolver, so it is locked
// down by construction rather than by convention:
//
//   - Bind addresses are explicit and are expected to be management-interface
//     addresses. Wildcards are rejected.
//   - A management listener may never share an address with a DNS listener.
//     DNS service addresses are anycast; binding management to one means the
//     admin plane follows the anycast route to an arbitrary node, and exposes
//     it wherever the prefix is advertised. Validate treats this as fatal.
//   - The source ACL is default-deny. An empty allow list is a config error,
//     not "allow everything" — an operator who forgets the ACL gets a failed
//     boot, never a world-reachable admin API.
//   - TLS is mandatory off loopback.
type Management struct {
	Enabled bool     `yaml:"enabled"`
	Listen  []string `yaml:"listen"`

	// TLS is required unless every listen address is loopback.
	TLS TLS `yaml:"tls"`

	// AllowFrom is the source-prefix allow list (CIDR, v4 and v6). Default
	// deny: a client whose address matches no prefix is refused before any
	// TLS or HTTP work happens.
	AllowFrom []string `yaml:"allow_from"`

	// TrustProxyHeaders makes the ACL and audit log believe X-Forwarded-For.
	// Defaults false and should stay false: a spoofable client address on the
	// admin plane is an ACL bypass, which is a much worse version of the same
	// problem DoH has with subscriber policy.
	TrustProxyHeaders bool `yaml:"trust_proxy_headers"`
	// TrustedProxies must be non-empty when TrustProxyHeaders is set.
	TrustedProxies []string `yaml:"trusted_proxies"`

	// UI serves the embedded WebUI in addition to the API.
	UI bool `yaml:"ui"`

	// SessionTimeout bounds an authenticated WebUI session.
	SessionTimeout time.Duration `yaml:"session_timeout"`
}

// TLS is a certificate/key pair.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// MinVersion is "1.2" or "1.3".
	MinVersion string `yaml:"min_version"`
}

// Metrics configures the Prometheus endpoint.
//
// Same reasoning as Management: /metrics leaks subscriber-adjacent operational
// detail and must not ride on an anycast service address.
type Metrics struct {
	Listen string `yaml:"listen"`
	Path   string `yaml:"path"`
	// AllowFrom is the source-prefix allow list. Empty means loopback only.
	AllowFrom []string `yaml:"allow_from"`
}

// Log configures slog.
type Log struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // text | json
}

// Default returns a config with every optional field populated. Load starts
// from this, so a field absent from the YAML takes the documented default
// rather than a zero value.
func Default() Config {
	return Config{
		Node: Node{
			StateDir: "/var/lib/cgdns",
		},
		Listen: Listen{
			UDPSocketsPerAddr: 0,
			MaxTCPConns:       4096,
			TCPIdleTimeout:    10 * time.Second,
		},
		Resolver: Resolver{
			Mode:                ModeForward,
			ClientBudget:        5 * time.Second,
			QueryTimeout:        2 * time.Second,
			MaxDelegationDepth:  16,
			MaxOutboundPerQuery: 32,
			MaxCNAMEChain:       8,
			UDPBufferSize:       1232,
			QNAMEMinimisation:   true,
			CaseRandomisation:   true,
			UseIPv4:             true,
			UseIPv6:             true,
			DNSSEC:              true,
		},
		Cache: Cache{
			MaxEntries:     1_000_000,
			Shards:         256,
			MinTTL:         5 * time.Second,
			MaxTTL:         24 * time.Hour,
			MaxNegativeTTL: time.Hour,
			Infra: InfraCache{
				MaxEntries: 100_000,
				Shards:     64,
				InitialRTT: 100 * time.Millisecond,
				MaxBackoff: 30 * time.Second,
			},
		},
		Subscriber: Subscriber{
			DefaultClass: "default",
		},
		Health: Health{
			Interval:         5 * time.Second,
			Timeout:          2 * time.Second,
			FailureThreshold: 2,
			SuccessThreshold: 3,
			MinHold:          30 * time.Second,
			MaxHold:          5 * time.Minute,
			StableAfter:      5 * time.Minute,
			GoBGPTarget:      "127.0.0.1:50051",
		},
		Management: Management{
			Enabled:        true,
			Listen:         []string{"127.0.0.1:8443"},
			TLS:            TLS{MinVersion: "1.3"},
			UI:             true,
			SessionTimeout: 8 * time.Hour,
		},
		Metrics: Metrics{
			Listen: "127.0.0.1:9153",
			Path:   "/metrics",
		},
		Log: Log{
			Level:  "info",
			Format: "text",
		},
	}
}

// Load reads, parses and fully validates a config file.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config %s: %w", path, err)
	}
	return Parse(raw)
}

// Parse decodes and validates YAML config bytes.
func Parse(raw []byte) (Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks every field and reports all problems at once, so an operator
// fixing a config sees the whole list rather than peeling them off one boot at
// a time.
func (c *Config) Validate() error {
	var problems []string
	bad := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.Node.ID == "" {
		bad("node.id is required and must be unique across the cluster")
	}
	if c.Node.StateDir == "" {
		bad("node.state_dir is required")
	}

	if len(c.Listen.UDP) == 0 && len(c.Listen.TCP) == 0 && len(c.Listen.DoT) == 0 && len(c.Listen.DoH) == 0 {
		bad("listen: at least one of listen.udp, listen.tcp, listen.dot or listen.doh must be set")
	}
	if len(c.Listen.DoT) > 0 || len(c.Listen.DoH) > 0 {
		if c.Listen.TLS.CertFile == "" || c.Listen.TLS.KeyFile == "" {
			bad("listen.tls.cert_file and listen.tls.key_file are required when listen.dot or listen.doh is set")
		} else {
			for _, f := range []string{c.Listen.TLS.CertFile, c.Listen.TLS.KeyFile} {
				if _, err := os.Stat(f); err != nil {
					bad("listen.tls: %q is not readable: %v", f, err)
				}
			}
		}
		switch c.Listen.TLS.MinVersion {
		case "", "1.2", "1.3":
		default:
			bad("listen.tls.min_version must be 1.2 or 1.3, got %q", c.Listen.TLS.MinVersion)
		}
	}
	if len(c.Listen.DoH) > 0 && !strings.HasPrefix(c.Listen.DoHPath, "/") {
		bad("listen.doh_path must start with /, got %q", c.Listen.DoHPath)
	}
	checkPrefixes(bad, "listen.doh_trusted_proxies", c.Listen.DoHTrustedProxies)
	for _, group := range []struct {
		field string
		addrs []string
	}{{"listen.udp", c.Listen.UDP}, {"listen.tcp", c.Listen.TCP}} {
		for _, a := range group.addrs {
			ap, err := netip.ParseAddrPort(a)
			switch {
			case err != nil:
				bad("%s: %q is not a valid host:port (IPv6 needs brackets): %v", group.field, a, err)
			case ap.Addr().IsUnspecified():
				bad("%s: %q is a wildcard address; bind each address explicitly so anycast replies keep the right source IP", group.field, a)
			case ap.Port() == 0:
				bad("%s: %q must specify a non-zero port", group.field, a)
			}
		}
	}
	if c.Listen.UDPSocketsPerAddr < 0 {
		bad("listen.udp_sockets_per_addr must be >= 0 (0 means one per CPU)")
	}
	if c.Listen.MaxTCPConns <= 0 {
		bad("listen.max_tcp_conns must be > 0")
	}
	if c.Listen.TCPIdleTimeout <= 0 {
		bad("listen.tcp_idle_timeout must be > 0")
	}
	if len(c.Listen.AllowQuery) == 0 {
		bad("listen.allow_query must list the client prefixes permitted to query this resolver (default deny; use 0.0.0.0/0 and ::/0 only if you genuinely intend an open resolver)")
	}
	checkPrefixes(bad, "listen.allow_query", c.Listen.AllowQuery)

	switch c.Resolver.Mode {
	case ModeForward:
		if len(c.Resolver.Upstreams) == 0 {
			bad("resolver.upstreams is required when resolver.mode is %q", ModeForward)
		}
		for _, u := range c.Resolver.Upstreams {
			if _, err := netip.ParseAddrPort(u); err != nil {
				bad("resolver.upstreams: %q is not a valid host:port (IPv6 needs brackets): %v", u, err)
			}
		}
	case ModeRecursive:
		if len(c.Resolver.Upstreams) > 0 {
			bad("resolver.upstreams must be empty when resolver.mode is %q — recursion talks to authoritatives directly", ModeRecursive)
		}
		if !c.Resolver.UseIPv4 && !c.Resolver.UseIPv6 {
			bad("resolver.use_ipv4 and resolver.use_ipv6 cannot both be false")
		}
		if c.Resolver.MaxCNAMEChain <= 0 {
			bad("resolver.max_cname_chain must be > 0")
		}
		if c.Resolver.RootHintsFile != "" {
			if _, err := os.Stat(c.Resolver.RootHintsFile); err != nil {
				bad("resolver.root_hints_file %q is not readable: %v", c.Resolver.RootHintsFile, err)
			}
		}
		if c.Resolver.TrustAnchorFile != "" {
			if _, err := os.Stat(c.Resolver.TrustAnchorFile); err != nil {
				bad("resolver.trust_anchor_file %q is not readable: %v", c.Resolver.TrustAnchorFile, err)
			}
		}
		if c.Resolver.AcceptSHA1 && !c.Resolver.DNSSEC {
			bad("resolver.accept_sha1 has no meaning when resolver.dnssec is false")
		}

	default:
		bad("resolver.mode must be %q or %q, got %q", ModeForward, ModeRecursive, c.Resolver.Mode)
	}
	if c.Resolver.ClientBudget <= 0 {
		bad("resolver.client_budget must be > 0")
	}
	if c.Resolver.QueryTimeout <= 0 {
		bad("resolver.query_timeout must be > 0")
	}
	if c.Resolver.QueryTimeout > c.Resolver.ClientBudget {
		bad("resolver.query_timeout (%s) must not exceed resolver.client_budget (%s)",
			c.Resolver.QueryTimeout, c.Resolver.ClientBudget)
	}
	if c.Resolver.MaxDelegationDepth <= 0 {
		bad("resolver.max_delegation_depth must be > 0")
	}
	if c.Resolver.MaxOutboundPerQuery <= 0 {
		bad("resolver.max_outbound_per_query must be > 0")
	}
	if c.Resolver.UDPBufferSize < 512 || c.Resolver.UDPBufferSize > 4096 {
		bad("resolver.udp_buffer_size must be between 512 and 4096 (1232 recommended), got %d", c.Resolver.UDPBufferSize)
	}

	if c.Cache.MaxEntries <= 0 {
		bad("cache.max_entries must be > 0")
	}
	if c.Cache.Shards <= 0 || c.Cache.Shards&(c.Cache.Shards-1) != 0 {
		bad("cache.shards must be a power of two, got %d", c.Cache.Shards)
	}
	if c.Cache.Shards > c.Cache.MaxEntries {
		bad("cache.shards (%d) must not exceed cache.max_entries (%d)", c.Cache.Shards, c.Cache.MaxEntries)
	}
	if c.Cache.MinTTL < 0 {
		bad("cache.min_ttl must be >= 0")
	}
	if c.Cache.MaxTTL <= 0 {
		bad("cache.max_ttl must be > 0")
	}
	if c.Cache.MinTTL > c.Cache.MaxTTL {
		bad("cache.min_ttl (%s) must not exceed cache.max_ttl (%s)", c.Cache.MinTTL, c.Cache.MaxTTL)
	}
	if c.Cache.MaxNegativeTTL <= 0 {
		bad("cache.max_negative_ttl must be > 0")
	}
	if c.Cache.Infra.MaxEntries <= 0 {
		bad("cache.infra.max_entries must be > 0")
	}
	if c.Cache.Infra.Shards <= 0 || c.Cache.Infra.Shards&(c.Cache.Infra.Shards-1) != 0 {
		bad("cache.infra.shards must be a power of two, got %d", c.Cache.Infra.Shards)
	}
	if c.Cache.Infra.Shards > c.Cache.Infra.MaxEntries {
		bad("cache.infra.shards (%d) must not exceed cache.infra.max_entries (%d)", c.Cache.Infra.Shards, c.Cache.Infra.MaxEntries)
	}
	if c.Cache.Infra.InitialRTT <= 0 {
		bad("cache.infra.initial_rtt must be > 0")
	}
	if c.Cache.Infra.MaxBackoff <= 0 {
		bad("cache.infra.max_backoff must be > 0")
	}

	if c.Subscriber.DefaultClass == "" {
		bad("subscriber.default_class is required — every client must map to some class")
	}
	if c.Subscriber.PrefixFile != "" {
		if _, err := os.Stat(c.Subscriber.PrefixFile); err != nil {
			bad("subscriber.prefix_file %q is not readable: %v", c.Subscriber.PrefixFile, err)
		}
	}

	if c.Policy.Enabled {
		feeds := map[string]bool{}
		for i, f := range c.Policy.Feeds {
			if f.Name == "" {
				bad("policy.feeds[%d].name is required", i)
				continue
			}
			if feeds[f.Name] {
				bad("policy.feeds: %q is defined more than once", f.Name)
			}
			feeds[f.Name] = true
			switch f.Format {
			case "", "domain-list":
			case "rpz":
				if f.RPZZone == "" {
					bad("policy.feeds %q is rpz format but sets no rpz_zone", f.Name)
				}
			default:
				bad("policy.feeds %q has unknown format %q (want domain-list or rpz)", f.Name, f.Format)
			}
			if f.File == "" {
				bad("policy.feeds %q sets no file", f.Name)
			} else if _, err := os.Stat(f.File); err != nil {
				bad("policy.feeds %q file %q is not readable: %v", f.Name, f.File, err)
			}
		}

		seen := map[string]bool{}
		for i, cl := range c.Policy.Classes {
			if cl.Name == "" {
				bad("policy.classes[%d].name is required", i)
				continue
			}
			if seen[cl.Name] {
				bad("policy.classes: %q is defined more than once", cl.Name)
			}
			seen[cl.Name] = true
			for _, f := range cl.Feeds {
				if !feeds[f] {
					bad("policy.classes %q subscribes to unknown feed %q", cl.Name, f)
				}
			}
			switch strings.ToLower(cl.Action) {
			case "", "nxdomain", "nodata", "drop":
			case "redirect":
				if len(cl.RedirectTo) == 0 {
					bad("policy.classes %q uses the redirect action but sets no redirect_to addresses", cl.Name)
				}
			default:
				bad("policy.classes %q has unknown action %q", cl.Name, cl.Action)
			}
			for _, a := range cl.RedirectTo {
				if _, err := netip.ParseAddr(a); err != nil {
					bad("policy.classes %q redirect_to %q is not an IP address: %v", cl.Name, a, err)
				}
			}
		}
		if c.Policy.OverridesFile != "" {
			if _, err := os.Stat(c.Policy.OverridesFile); err != nil {
				bad("policy.overrides_file %q is not readable: %v", c.Policy.OverridesFile, err)
			}
		}
	}

	dnsAddrs := make(map[netip.Addr]bool)
	serviceAddrs := append(append([]string{}, c.Listen.UDP...), c.Listen.TCP...)
	serviceAddrs = append(serviceAddrs, c.Listen.DoT...)
	serviceAddrs = append(serviceAddrs, c.Listen.DoH...)
	for _, a := range serviceAddrs {
		if ap, err := netip.ParseAddrPort(a); err == nil {
			dnsAddrs[ap.Addr()] = true
		}
	}

	if c.Management.Enabled {
		if len(c.Management.Listen) == 0 {
			bad("management.listen is required when management.enabled is true")
		}
		allLoopback := true
		for _, a := range c.Management.Listen {
			ap, err := netip.ParseAddrPort(a)
			switch {
			case err != nil:
				bad("management.listen: %q is not a valid host:port (IPv6 needs brackets): %v", a, err)
				allLoopback = false
				continue
			case ap.Addr().IsUnspecified():
				bad("management.listen: %q is a wildcard address; bind the management interface address explicitly so the admin plane is never exposed on a service or anycast address", a)
				allLoopback = false
				continue
			case ap.Port() == 0:
				bad("management.listen: %q must specify a non-zero port", a)
			}
			if dnsAddrs[ap.Addr()] && !ap.Addr().IsLoopback() {
				bad("management.listen: %q shares an address with a DNS listener; the admin plane must not ride on a service/anycast address", a)
			}
			if !ap.Addr().IsLoopback() {
				allLoopback = false
			}
		}

		if !allLoopback {
			if len(c.Management.AllowFrom) == 0 {
				bad("management.allow_from must list the management source prefixes when management.listen is not loopback-only (default deny; there is no allow-all)")
			}
			if c.Management.TLS.CertFile == "" || c.Management.TLS.KeyFile == "" {
				bad("management.tls.cert_file and management.tls.key_file are required when management.listen is not loopback-only")
			}
		}
		checkPrefixes(bad, "management.allow_from", c.Management.AllowFrom)

		switch c.Management.TLS.MinVersion {
		case "", "1.2", "1.3":
		default:
			bad("management.tls.min_version must be 1.2 or 1.3, got %q", c.Management.TLS.MinVersion)
		}

		if c.Management.TrustProxyHeaders && len(c.Management.TrustedProxies) == 0 {
			bad("management.trusted_proxies must be set when management.trust_proxy_headers is true, otherwise any client can spoof its source address and bypass management.allow_from")
		}
		checkPrefixes(bad, "management.trusted_proxies", c.Management.TrustedProxies)

		if c.Management.SessionTimeout <= 0 {
			bad("management.session_timeout must be > 0")
		}
	}

	if c.Health.Enabled {
		if len(c.Health.AnycastPrefixes) == 0 {
			bad("health.anycast_prefixes is required when health.enabled is true — there is nothing to advertise or withdraw otherwise")
		}
		checkPrefixes(bad, "health.anycast_prefixes", c.Health.AnycastPrefixes)
		if c.Health.Interval <= 0 {
			bad("health.interval must be > 0")
		}
		if c.Health.Timeout <= 0 {
			bad("health.timeout must be > 0")
		}
		if c.Health.Timeout >= c.Health.Interval {
			bad("health.timeout (%s) must be shorter than health.interval (%s), or checks overlap", c.Health.Timeout, c.Health.Interval)
		}
		if c.Health.FailureThreshold <= 0 {
			bad("health.failure_threshold must be > 0")
		}
		if c.Health.SuccessThreshold <= 0 {
			bad("health.success_threshold must be > 0")
		}
		if c.Health.SuccessThreshold < c.Health.FailureThreshold {
			bad("health.success_threshold (%d) must be at least health.failure_threshold (%d): recovery must be harder than failure, or the node flaps",
				c.Health.SuccessThreshold, c.Health.FailureThreshold)
		}
		if c.Health.MinHold <= 0 {
			bad("health.min_hold must be > 0")
		}
		if c.Health.MaxHold < c.Health.MinHold {
			bad("health.max_hold (%s) must not be below health.min_hold (%s)", c.Health.MaxHold, c.Health.MinHold)
		}
		if c.Health.GoBGPTarget == "" {
			bad("health.gobgp_target is required when health.enabled is true")
		} else if _, err := netip.ParseAddrPort(c.Health.GoBGPTarget); err != nil {
			bad("health.gobgp_target %q is not a valid host:port: %v", c.Health.GoBGPTarget, err)
		}
	}

	if c.Metrics.Listen != "" {
		ap, err := netip.ParseAddrPort(c.Metrics.Listen)
		switch {
		case err != nil:
			bad("metrics.listen: %q is not a valid host:port: %v", c.Metrics.Listen, err)
		case ap.Addr().IsUnspecified():
			bad("metrics.listen: %q is a wildcard address; bind it to the management interface explicitly", c.Metrics.Listen)
		default:
			if dnsAddrs[ap.Addr()] && !ap.Addr().IsLoopback() {
				bad("metrics.listen: %q shares an address with a DNS listener; metrics must not ride on a service/anycast address", c.Metrics.Listen)
			}
			if !ap.Addr().IsLoopback() && len(c.Metrics.AllowFrom) == 0 {
				bad("metrics.allow_from must list source prefixes when metrics.listen is not loopback (default deny)")
			}
		}
		if !strings.HasPrefix(c.Metrics.Path, "/") {
			bad("metrics.path must start with /, got %q", c.Metrics.Path)
		}
		checkPrefixes(bad, "metrics.allow_from", c.Metrics.AllowFrom)
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		bad("log.level must be one of debug|info|warn|error, got %q", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		bad("log.format must be text or json, got %q", c.Log.Format)
	}

	if len(problems) > 0 {
		return fmt.Errorf("%w:\n  - %s", ErrInvalid, strings.Join(problems, "\n  - "))
	}
	return nil
}

// UDPAddrs returns the parsed UDP listen addresses. Only valid after Validate.
func (c *Config) UDPAddrs() []netip.AddrPort { return mustParseAll(c.Listen.UDP) }

// TCPAddrs returns the parsed TCP listen addresses. Only valid after Validate.
func (c *Config) TCPAddrs() []netip.AddrPort { return mustParseAll(c.Listen.TCP) }

// UpstreamAddrs returns the parsed upstreams. Only valid after Validate.
func (c *Config) UpstreamAddrs() []netip.AddrPort { return mustParseAll(c.Resolver.Upstreams) }

// DoTAddrs returns the parsed DoT listen addresses.
func (c *Config) DoTAddrs() []netip.AddrPort { return mustParseAll(c.Listen.DoT) }

// DoHAddrs returns the parsed DoH listen addresses.
func (c *Config) DoHAddrs() []netip.AddrPort { return mustParseAll(c.Listen.DoH) }

// DoHTrustedProxyPrefixes returns the parsed DoH proxy allow list.
func (c *Config) DoHTrustedProxyPrefixes() []netip.Prefix {
	return mustParsePrefixes(c.Listen.DoHTrustedProxies)
}

// AllowQueryPrefixes returns the parsed DNS client ACL.
func (c *Config) AllowQueryPrefixes() []netip.Prefix { return mustParsePrefixes(c.Listen.AllowQuery) }

// IsOpenResolver reports whether allow_query contains a default route, i.e.
// this node will answer recursive queries from anywhere.
//
// This is legal and occasionally intended (a public resolver service), but it
// is never something an operator should discover by accident — the daemon logs
// a warning at startup when it is true.
func (c *Config) IsOpenResolver() bool {
	for _, p := range c.AllowQueryPrefixes() {
		if p.Bits() == 0 {
			return true
		}
	}
	return false
}

// IsIPv6Disabled reports whether outbound recursion will skip IPv6.
//
// Legal and occasionally necessary, but it silently breaks resolution of
// IPv6-only zones, so the daemon warns loudly at startup rather than letting an
// operator discover it during an incident.
func (c *Config) IsIPv6Disabled() bool {
	return c.Resolver.Mode == ModeRecursive && !c.Resolver.UseIPv6
}

// AnycastPrefixes returns the parsed anycast routes.
func (c *Config) AnycastPrefixes() []netip.Prefix { return mustParsePrefixes(c.Health.AnycastPrefixes) }

// IsValidationDisabled reports whether a recursive node is serving without
// DNSSEC validation, which means AD is never set and forged answers from a
// compromised authoritative are indistinguishable from genuine ones.
func (c *Config) IsValidationDisabled() bool {
	return c.Resolver.Mode == ModeRecursive && !c.Resolver.DNSSEC
}

// ManagementAddrs returns the parsed management listen addresses.
func (c *Config) ManagementAddrs() []netip.AddrPort { return mustParseAll(c.Management.Listen) }

// ManagementAllowFrom returns the parsed management source ACL.
func (c *Config) ManagementAllowFrom() []netip.Prefix {
	return mustParsePrefixes(c.Management.AllowFrom)
}

// MetricsAllowFrom returns the parsed metrics source ACL.
func (c *Config) MetricsAllowFrom() []netip.Prefix { return mustParsePrefixes(c.Metrics.AllowFrom) }

// checkPrefixes validates a CIDR list, insisting on masked form so an operator
// never writes 10.0.0.5/24 and wonders why the ACL matched more than expected.
func checkPrefixes(bad func(string, ...any), field string, in []string) {
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			bad("%s: %q is not a valid CIDR prefix: %v", field, s, err)
			continue
		}
		if p.Masked() != p {
			bad("%s: %q has host bits set; write it masked as %q", field, s, p.Masked().String())
		}
	}
}

func mustParsePrefixes(in []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic(fmt.Sprintf("config: %q passed validation but does not parse: %v", s, err))
		}
		out = append(out, p.Masked())
	}
	return out
}

func mustParseAll(in []string) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(in))
	for _, s := range in {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			panic(fmt.Sprintf("config: %q passed validation but does not parse: %v", s, err))
		}
		out = append(out, ap)
	}
	return out
}
