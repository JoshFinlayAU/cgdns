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
	Control    Control    `yaml:"control"`
	RateLimit  RateLimit  `yaml:"rate_limit"`
	Peer       Peer       `yaml:"peer"`
	Health     Health     `yaml:"health"`
	Management Management `yaml:"management"`
	Metrics    Metrics    `yaml:"metrics"`
	Log        Log        `yaml:"log"`
}

// Node identifies this daemon within a cluster.
type Node struct {
	// ID must be unique within the pair. It identifies the node on the pair
	// link and breaks ties between concurrent control-plane writes, so two
	// nodes sharing an ID would make convergence undefined.
	ID string `yaml:"id"`
	// StateDir holds RFC 5011 trust-anchor state and the control store.
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
	// UDPWorkersPerSocket is how many handler goroutines drain each socket.
	// It bounds in-flight queries per socket: too few and the receive queue
	// backs up under load, too many and a slow upstream turns into a pile of
	// goroutines all waiting on it. 0 uses the built-in default.
	UDPWorkersPerSocket int `yaml:"udp_workers_per_socket"`

	MaxTCPConns    int           `yaml:"max_tcp_conns"`
	TCPIdleTimeout time.Duration `yaml:"tcp_idle_timeout"`

	// DoT serves DNS over TLS (RFC 7858), conventionally on 853.
	DoT []string `yaml:"dot"`
	// DoH serves DNS over HTTPS (RFC 8484), conventionally on 443.
	DoH []string `yaml:"doh"`
	// DoQ serves DNS over QUIC (RFC 9250), conventionally on 853 over UDP.
	// It shares the port number with DoT but not the socket: one is TCP, the
	// other UDP.
	DoQ []string `yaml:"doq"`
	// DoQMaxIdleTimeout closes a QUIC connection that has gone quiet.
	DoQMaxIdleTimeout time.Duration `yaml:"doq_max_idle_timeout"`
	// DoQMaxStreamsPerConn caps concurrent queries on one connection, which is
	// what stops a single client opening unbounded work.
	DoQMaxStreamsPerConn int `yaml:"doq_max_streams_per_conn"`
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

	// OutboundSourceV4 and OutboundSourceV6 pin the local address outbound
	// queries leave from.
	//
	// Under anycast this matters: the service address is shared with the
	// sibling node, so a query sourced from it invites the reply back to
	// whichever node the return path picks. Pin these to an address unique to
	// this node — its loopback — so replies come home, and so upstream filters
	// have one address to permit. Empty keeps the kernel's choice.
	OutboundSourceV4 string `yaml:"outbound_source_v4"`
	OutboundSourceV6 string `yaml:"outbound_source_v6"`

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
	// AggressiveNSEC reuses a validated denial to answer for every name its
	// NSEC range covers (RFC 8198), instead of asking the authoritative again.
	// It is the strongest defence there is against a random-subdomain flood
	// aimed at a signed zone: the flood never leaves this node.
	AggressiveNSEC bool `yaml:"aggressive_nsec"`
	// AggressiveNSECMaxZones and AggressiveNSECMaxRecords bound that store.
	AggressiveNSECMaxZones   int `yaml:"aggressive_nsec_max_zones"`
	AggressiveNSECMaxRecords int `yaml:"aggressive_nsec_max_records_per_zone"`

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

	// ServeStale answers from expired data when the authoritative cannot be
	// reached (RFC 8767).
	ServeStale ServeStale `yaml:"serve_stale"`

	// Prefetch refreshes popular entries shortly before they expire.
	Prefetch Prefetch `yaml:"prefetch"`
}

// Prefetch configures refreshing entries that are close to expiry.
type Prefetch struct {
	Enabled bool `yaml:"enabled"`

	// Threshold is the fraction of an entry's original TTL that must remain
	// before a read triggers a refresh. 0.1 refreshes in the last tenth.
	Threshold float64 `yaml:"threshold"`

	// MinTTL skips records too short-lived to be worth chasing: refreshing
	// them would cost more upstream traffic than it saves.
	MinTTL time.Duration `yaml:"min_ttl"`

	// MaxConcurrent caps refreshes in flight, so an optimisation can never
	// crowd out the client queries it exists to speed up.
	MaxConcurrent int `yaml:"max_concurrent"`

	// Timeout bounds one refresh.
	Timeout time.Duration `yaml:"timeout"`
}

// ServeStale configures RFC 8767 stale answers.
type ServeStale struct {
	Enabled bool `yaml:"enabled"`

	// MaxStale is how long past expiry an entry is kept for this purpose. It
	// trades staleness for reachability: longer keeps subscribers online
	// through a longer outage, at the cost of answering with data that may
	// have moved. RFC 8767 recommends capping it at a day or so.
	MaxStale time.Duration `yaml:"max_stale"`

	// AnswerTTL is stamped on a stale answer. Short on purpose: the client
	// should come back soon, because by then the authoritative may have
	// recovered.
	AnswerTTL time.Duration `yaml:"answer_ttl"`
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
// production the trie is populated from the control store; PrefixFile is the
// dev path in.
type Subscriber struct {
	// DefaultClass applies to any client that matches no configured prefix.
	DefaultClass string `yaml:"default_class"`
	// PrefixFile is an optional "prefix class" file loaded at startup.
	PrefixFile string `yaml:"prefix_file"`
}

// Policy configures subscriber content filtering.
//
// Feed content is never replicated: it runs to millions of rows and would
// dominate the pair link. The control store holds only the metadata naming a
// feed and the classes subscribed to it; each node fetches the content and
// verifies it against the recorded hash.
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

// RateLimit configures response rate limiting on UDP.
type RateLimit struct {
	Enabled bool `yaml:"enabled"`

	// ResponsesPerSecond limits positive answers per client prefix. Zero
	// leaves that class unlimited.
	ResponsesPerSecond float64 `yaml:"responses_per_second"`
	// DenialsPerSecond limits NXDOMAIN and NODATA, grouped by the zone that
	// denied them. This is the one that stops a random-subdomain flood, and it
	// belongs well below the answer rate: a real client asks for names that
	// exist.
	DenialsPerSecond float64 `yaml:"denials_per_second"`
	// ErrorsPerSecond limits SERVFAIL and friends.
	ErrorsPerSecond float64 `yaml:"errors_per_second"`

	// Window is how much unused allowance a client may bank, so a quiet client
	// can burst without raising its sustained rate.
	Window time.Duration `yaml:"window"`

	// SlipRatio sends every Nth over-limit response truncated rather than
	// dropping it, so a real client retries over TCP where it is not limited.
	// 0 always drops, 1 always slips.
	SlipRatio uint32 `yaml:"slip_ratio"`

	// IPv4PrefixLen and IPv6PrefixLen decide how much of a client address a
	// bucket covers. Limiting single addresses would be useless: an attacker
	// spoofs across a range, and real subscribers share one behind CGNAT.
	IPv4PrefixLen int `yaml:"ipv4_prefix_len"`
	IPv6PrefixLen int `yaml:"ipv6_prefix_len"`

	// MaxBuckets bounds the table, so an attacker spoofing across many
	// prefixes cannot make the limiter itself the attack.
	MaxBuckets int `yaml:"max_buckets"`
	Shards     int `yaml:"shards"`

	// ExemptClients are never limited. Default deny applies here in reverse:
	// an empty list exempts nobody.
	ExemptClients []string `yaml:"exempt_clients"`
}

// Control configures the local control-plane store.
type Control struct {
	// StoreFile is the durable record store. Empty keeps it in memory, which
	// means the node relies entirely on its sibling to repopulate after a
	// restart.
	StoreFile string `yaml:"store_file"`
}

// Peer configures the link to the other resolver in this POP.
//
// It carries config replication, which is reliable, and cache sharing, which is
// best-effort. Cache sharing is POP-local by design: CDN and cloud
// authoritatives answer on where the resolver sits, so sharing entries between
// POPs would serve one region's endpoints to another.
type Peer struct {
	Enabled bool `yaml:"enabled"`

	// Listen is this node's pair-link address, on the pair VLAN.
	Listen string `yaml:"listen"`
	// Remote is the sibling's pair-link address.
	Remote string `yaml:"remote"`

	// TLS is mutual: the peer may insert into this node's cache, so an
	// unauthenticated peer could poison it. CAFile is required.
	TLS    TLS    `yaml:"tls"`
	CAFile string `yaml:"ca_file"`

	// FetchTimeout bounds a cache fetch, which sits on the query path. Keep it
	// well below what going upstream costs — beyond that the sibling is a
	// pessimisation rather than an optimisation.
	FetchTimeout time.Duration `yaml:"fetch_timeout"`
	// Timeout bounds a config request, which is off the query path.
	Timeout time.Duration `yaml:"timeout"`

	// PushInterval and PushBatch control how queued cache entries are flushed.
	PushInterval time.Duration `yaml:"push_interval"`
	PushBatch    int           `yaml:"push_batch"`
	// QueueLimit caps queued entries; beyond it the oldest are dropped.
	QueueLimit int `yaml:"queue_limit"`
	// SyncInterval is how often config anti-entropy runs.
	SyncInterval time.Duration `yaml:"sync_interval"`
	// IdleTimeout closes a pair connection that has gone quiet.
	IdleTimeout time.Duration `yaml:"idle_timeout"`

	// PullOnMiss consults the sibling before going upstream. Disable to make
	// the link push-only, which removes the sibling from the query path
	// entirely at the cost of a colder peer.
	PullOnMiss bool `yaml:"pull_on_miss"`
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

	// The WebUI is served here and nowhere else, and it needs HTTPS even on
	// loopback: its session cookie is Secure, so a browser will not store it
	// over plain HTTP. When no certificate is configured the daemon generates a
	// self-signed one into node.state_dir, which is enough for the browser and
	// expects real TLS to be terminated in front — a tunnel, or a reverse proxy.
	//
	// BootstrapTokenFile receives an admin token when the node starts with no
	// token at all. The alternatives are worse: a default credential is a
	// permanent hole, and a manual out-of-band step gets skipped. A node that
	// already holds a token — including one replicated from its sibling — never
	// writes here. Set it empty to refuse bootstrapping entirely.
	BootstrapTokenFile string `yaml:"bootstrap_token_file"`

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
			UDPSocketsPerAddr:    0,
			MaxTCPConns:          4096,
			DoQMaxIdleTimeout:    30 * time.Second,
			DoQMaxStreamsPerConn: 256,
			TCPIdleTimeout:       10 * time.Second,
		},
		Resolver: Resolver{
			Mode:                     ModeForward,
			ClientBudget:             5 * time.Second,
			QueryTimeout:             2 * time.Second,
			MaxDelegationDepth:       16,
			MaxOutboundPerQuery:      32,
			MaxCNAMEChain:            8,
			UDPBufferSize:            1232,
			QNAMEMinimisation:        true,
			CaseRandomisation:        true,
			AggressiveNSEC:           true,
			AggressiveNSECMaxZones:   10000,
			AggressiveNSECMaxRecords: 512,
			UseIPv4:                  true,
			UseIPv6:                  true,
			DNSSEC:                   true,
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
			ServeStale: ServeStale{
				Enabled:   true,
				MaxStale:  time.Hour,
				AnswerTTL: 30 * time.Second,
			},
			Prefetch: Prefetch{
				Enabled:       true,
				Threshold:     0.1,
				MinTTL:        30 * time.Second,
				MaxConcurrent: 64,
				Timeout:       5 * time.Second,
			},
		},
		Subscriber: Subscriber{
			DefaultClass: "default",
		},
		Control: Control{
			StoreFile: "/var/lib/cgdns/control.json",
		},
		RateLimit: RateLimit{
			Enabled: true,
			// Answers are left unlimited by default. A subscriber legitimately
			// asks for names that exist, and limiting that class is how an
			// operator breaks their own customers.
			ResponsesPerSecond: 0,
			DenialsPerSecond:   50,
			ErrorsPerSecond:    20,
			Window:             15 * time.Second,
			SlipRatio:          2,
			IPv4PrefixLen:      24,
			IPv6PrefixLen:      56,
			MaxBuckets:         100000,
			Shards:             16,
		},
		Peer: Peer{
			FetchTimeout: 150 * time.Millisecond,
			Timeout:      2 * time.Second,
			PushInterval: 200 * time.Millisecond,
			PushBatch:    256,
			QueueLimit:   4096,
			SyncInterval: 30 * time.Second,
			IdleTimeout:  2 * time.Minute,
			PullOnMiss:   true,
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
			Enabled:            true,
			Listen:             []string{"127.0.0.1:8443"},
			TLS:                TLS{MinVersion: "1.3"},
			UI:                 true,
			SessionTimeout:     8 * time.Hour,
			BootstrapTokenFile: "/var/lib/cgdns/bootstrap.token",
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
		bad("node.id is required and must differ from the sibling's: it identifies this node on the pair link and breaks ties between concurrent control-plane writes")
	}
	if c.Node.StateDir == "" {
		bad("node.state_dir is required")
	}

	if len(c.Listen.UDP) == 0 && len(c.Listen.TCP) == 0 && len(c.Listen.DoT) == 0 &&
		len(c.Listen.DoH) == 0 && len(c.Listen.DoQ) == 0 {
		bad("listen: at least one of listen.udp, listen.tcp, listen.dot, listen.doh or listen.doq must be set")
	}
	if len(c.Listen.DoQ) > 0 {
		if c.Listen.DoQMaxIdleTimeout <= 0 {
			bad("listen.doq_max_idle_timeout must be > 0")
		}
		if c.Listen.DoQMaxStreamsPerConn <= 0 {
			bad("listen.doq_max_streams_per_conn must be > 0: an unbounded stream count lets one client open unbounded work")
		}
	}
	if len(c.Listen.DoT) > 0 || len(c.Listen.DoH) > 0 || len(c.Listen.DoQ) > 0 {
		if c.Listen.TLS.CertFile == "" || c.Listen.TLS.KeyFile == "" {
			bad("listen.tls.cert_file and listen.tls.key_file are required when listen.dot, listen.doh or listen.doq is set")
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
	}{{"listen.udp", c.Listen.UDP}, {"listen.tcp", c.Listen.TCP}, {"listen.doq", c.Listen.DoQ}} {
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
	if c.Listen.UDPWorkersPerSocket < 0 {
		bad("listen.udp_workers_per_socket must be >= 0 (0 uses the default)")
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
			if p, covered := anycastCovers(c.Health.AnycastPrefixes, ap.Addr()); covered {
				bad("management.listen: %q is inside the anycast prefix %s; the operator interface and WebUI must be reachable only on the management interface, never on an address the whole internet routes to and that moves between nodes", a, p)
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

	for _, f := range []struct {
		name, val string
		want4     bool
	}{
		{"resolver.outbound_source_v4", c.Resolver.OutboundSourceV4, true},
		{"resolver.outbound_source_v6", c.Resolver.OutboundSourceV6, false},
	} {
		if f.val == "" {
			continue
		}
		addr, err := netip.ParseAddr(f.val)
		switch {
		case err != nil:
			bad("%s: %q is not a valid IP address: %v", f.name, f.val, err)
			continue
		case addr.Is4() != f.want4 && !(f.want4 && addr.Is4In6()):
			bad("%s: %q is not an IPv%d address", f.name, f.val, map[bool]int{true: 4, false: 6}[f.want4])
			continue
		case addr.IsUnspecified():
			bad("%s: %q is the unspecified address, which is the same as leaving it empty", f.name, f.val)
		case addr.IsMulticast():
			bad("%s: %q is a multicast address and cannot source a query", f.name, f.val)
		}
		if anyPrefix, covered := anycastCovers(c.Health.AnycastPrefixes, addr); covered {
			bad("%s: %q is inside the anycast prefix %s; sourcing outbound queries from a shared address invites replies back to whichever node the return path picks, so use an address unique to this node",
				f.name, f.val, anyPrefix)
		}
	}

	if c.Resolver.AggressiveNSEC {
		if !c.Resolver.DNSSEC {
			bad("resolver.aggressive_nsec requires resolver.dnssec: reusing an unvalidated NSEC would let anyone who can answer for a zone erase names from it for as long as we cached the claim")
		}
		if c.Resolver.AggressiveNSECMaxZones < 1 {
			bad("resolver.aggressive_nsec_max_zones must be > 0")
		}
		if c.Resolver.AggressiveNSECMaxRecords < 1 {
			bad("resolver.aggressive_nsec_max_records_per_zone must be > 0")
		}
	}

	if c.Cache.Prefetch.Enabled {
		if c.Cache.Prefetch.Threshold <= 0 || c.Cache.Prefetch.Threshold >= 1 {
			bad("cache.prefetch.threshold must be between 0 and 1 exclusive (it is a fraction of the original TTL), got %v", c.Cache.Prefetch.Threshold)
		}
		if c.Cache.Prefetch.MinTTL <= 0 {
			bad("cache.prefetch.min_ttl must be > 0")
		}
		if c.Cache.Prefetch.MaxConcurrent <= 0 {
			bad("cache.prefetch.max_concurrent must be > 0: unbounded prefetching would let an optimisation crowd out client queries")
		}
		if c.Cache.Prefetch.Timeout <= 0 {
			bad("cache.prefetch.timeout must be > 0")
		}
	}

	if c.Cache.ServeStale.Enabled {
		if c.Cache.ServeStale.MaxStale <= 0 {
			bad("cache.serve_stale.max_stale must be > 0 when serve-stale is enabled")
		}
		if c.Cache.ServeStale.AnswerTTL <= 0 {
			bad("cache.serve_stale.answer_ttl must be > 0")
		}
		if c.Cache.ServeStale.AnswerTTL >= c.Cache.ServeStale.MaxStale {
			bad("cache.serve_stale.answer_ttl (%s) must be shorter than max_stale (%s): a client told to cache a stale answer for longer than we are willing to keep it would outlast our own copy",
				c.Cache.ServeStale.AnswerTTL, c.Cache.ServeStale.MaxStale)
		}
	}

	if c.RateLimit.Enabled {
		for _, f := range []struct {
			name string
			val  float64
		}{
			{"rate_limit.responses_per_second", c.RateLimit.ResponsesPerSecond},
			{"rate_limit.denials_per_second", c.RateLimit.DenialsPerSecond},
			{"rate_limit.errors_per_second", c.RateLimit.ErrorsPerSecond},
		} {
			if f.val < 0 {
				bad("%s must not be negative (0 means unlimited)", f.name)
			}
		}
		if c.RateLimit.ResponsesPerSecond == 0 && c.RateLimit.DenialsPerSecond == 0 && c.RateLimit.ErrorsPerSecond == 0 {
			bad("rate_limit.enabled is true but every rate is 0, which limits nothing; set at least one rate or set rate_limit.enabled to false")
		}
		if c.RateLimit.Window <= 0 {
			bad("rate_limit.window must be > 0")
		}
		if c.RateLimit.IPv4PrefixLen < 1 || c.RateLimit.IPv4PrefixLen > 32 {
			bad("rate_limit.ipv4_prefix_len must be between 1 and 32, got %d", c.RateLimit.IPv4PrefixLen)
		}
		if c.RateLimit.IPv6PrefixLen < 1 || c.RateLimit.IPv6PrefixLen > 128 {
			bad("rate_limit.ipv6_prefix_len must be between 1 and 128, got %d", c.RateLimit.IPv6PrefixLen)
		}
		if c.RateLimit.MaxBuckets < 1 {
			bad("rate_limit.max_buckets must be > 0: the table has to be bounded or an attacker spoofing across many prefixes makes the limiter itself the attack")
		}
		if c.RateLimit.Shards < 1 {
			bad("rate_limit.shards must be > 0")
		}
		checkPrefixes(bad, "rate_limit.exempt_clients", c.RateLimit.ExemptClients)
	}

	if c.Peer.Enabled {
		for _, f := range []struct {
			name, val string
		}{{"peer.listen", c.Peer.Listen}, {"peer.remote", c.Peer.Remote}} {
			if f.val == "" {
				bad("%s is required when peer.enabled is true", f.name)
			} else if _, err := netip.ParseAddrPort(f.val); err != nil {
				bad("%s: %q is not a valid host:port (IPv6 needs brackets): %v", f.name, f.val, err)
			}
		}
		if c.Peer.Listen != "" && c.Peer.Listen == c.Peer.Remote {
			bad("peer.listen and peer.remote are the same address; a node cannot pair with itself")
		}
		// Mutual TLS is not optional here: the sibling writes into this node's
		// cache, so an unauthenticated peer could poison it.
		if c.Peer.TLS.CertFile == "" || c.Peer.TLS.KeyFile == "" {
			bad("peer.tls.cert_file and peer.tls.key_file are required when peer.enabled is true")
		}
		if c.Peer.CAFile == "" {
			bad("peer.ca_file is required: the pair link uses mutual TLS, and without a CA the peer cannot be verified")
		}
		for _, f := range []string{c.Peer.TLS.CertFile, c.Peer.TLS.KeyFile, c.Peer.CAFile} {
			if f == "" {
				continue
			}
			if _, err := os.Stat(f); err != nil {
				bad("peer: %q is not readable: %v", f, err)
			}
		}
		if c.Peer.FetchTimeout <= 0 {
			bad("peer.fetch_timeout must be > 0")
		}
		if c.Peer.FetchTimeout > c.Resolver.QueryTimeout {
			bad("peer.fetch_timeout (%s) exceeds resolver.query_timeout (%s): consulting the sibling would cost more than resolving upstream",
				c.Peer.FetchTimeout, c.Resolver.QueryTimeout)
		}
		if c.Peer.Timeout <= 0 {
			bad("peer.timeout must be > 0")
		}
		if c.Peer.PushInterval <= 0 {
			bad("peer.push_interval must be > 0")
		}
		if c.Peer.PushBatch <= 0 {
			bad("peer.push_batch must be > 0")
		}
		if c.Peer.QueueLimit <= 0 {
			bad("peer.queue_limit must be > 0")
		}
		if c.Peer.SyncInterval <= 0 {
			bad("peer.sync_interval must be > 0")
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
			if p, covered := anycastCovers(c.Health.AnycastPrefixes, ap.Addr()); covered {
				bad("metrics.listen: %q is inside the anycast prefix %s; metrics must be reachable only on the management interface", c.Metrics.Listen, p)
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

// DoQAddrs returns the parsed DoQ listen addresses.
func (c *Config) DoQAddrs() []netip.AddrPort { return mustParseAll(c.Listen.DoQ) }

// ManagementAddrs returns the parsed management listen addresses.
func (c *Config) ManagementAddrs() []netip.AddrPort { return mustParseAll(c.Management.Listen) }

// OutboundSources returns the parsed egress source addresses. An unset family
// yields the zero Addr, which means "let the kernel choose".
func (c *Config) OutboundSources() (v4, v6 netip.Addr) {
	if c.Resolver.OutboundSourceV4 != "" {
		v4, _ = netip.ParseAddr(c.Resolver.OutboundSourceV4)
	}
	if c.Resolver.OutboundSourceV6 != "" {
		v6, _ = netip.ParseAddr(c.Resolver.OutboundSourceV6)
	}
	return v4, v6
}

// RateLimitExempt returns the parsed rate-limit exemption prefixes.
func (c *Config) RateLimitExempt() []netip.Prefix {
	return mustParsePrefixes(c.RateLimit.ExemptClients)
}

// ManagementAllowFrom returns the parsed management source ACL.
func (c *Config) ManagementAllowFrom() []netip.Prefix {
	return mustParsePrefixes(c.Management.AllowFrom)
}

// MetricsAllowFrom returns the parsed metrics source ACL.
func (c *Config) MetricsAllowFrom() []netip.Prefix { return mustParsePrefixes(c.Metrics.AllowFrom) }

// checkPrefixes validates a CIDR list, insisting on masked form so an operator
// never writes 10.0.0.5/24 and wonders why the ACL matched more than expected.
// anycastCovers reports whether addr falls inside one of the anycast prefixes
// this node originates.
//
// An anycast address is by definition reachable from anywhere the route is
// carried, and it moves between nodes. Binding an admin plane there would put
// the operator interface on the internet-facing service address and make which
// node you reached a matter of routing.
func anycastCovers(prefixes []string, addr netip.Addr) (netip.Prefix, bool) {
	for _, raw := range prefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		if p.Contains(addr) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

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
