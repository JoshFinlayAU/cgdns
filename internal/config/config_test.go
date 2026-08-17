package config

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// valid returns a Config that passes Validate, for tests to perturb one field
// at a time.
func valid() Config {
	c := Default()
	c.Node.ID = "cgdns-test-01"
	c.Listen.UDP = []string{"127.0.0.1:5353", "[::1]:5353"}
	c.Listen.TCP = []string{"127.0.0.1:5353", "[::1]:5353"}
	c.Listen.AllowQuery = []string{"127.0.0.0/8", "::1/128"}
	c.Resolver.Upstreams = []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"}
	return c
}

func TestValidate_AcceptsValidConfig(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid config to pass, got: %v", err)
	}
}

func TestValidate_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name:    "missing node id",
			mutate:  func(c *Config) { c.Node.ID = "" },
			wantErr: "node.id is required",
		},
		{
			name:    "wildcard udp listener",
			mutate:  func(c *Config) { c.Listen.UDP = []string{"0.0.0.0:53"} },
			wantErr: "wildcard address",
		},
		{
			name:    "wildcard v6 udp listener",
			mutate:  func(c *Config) { c.Listen.UDP = []string{"[::]:53"} },
			wantErr: "wildcard address",
		},
		{
			name:    "unbracketed v6 listener",
			mutate:  func(c *Config) { c.Listen.UDP = []string{"::1:53"} },
			wantErr: "not a valid host:port",
		},
		{
			name:    "no listeners at all",
			mutate:  func(c *Config) { c.Listen.UDP = nil; c.Listen.TCP = nil },
			wantErr: "at least one of listen.udp, listen.tcp, listen.dot, listen.doh or listen.doq",
		},
		{
			// An open recursive resolver is an amplification source. There is
			// no allow-all default; forgetting the ACL must fail the boot.
			name:    "empty allow_query",
			mutate:  func(c *Config) { c.Listen.AllowQuery = nil },
			wantErr: "listen.allow_query must list the client prefixes",
		},
		{
			name:    "allow_query with host bits set",
			mutate:  func(c *Config) { c.Listen.AllowQuery = []string{"10.0.0.5/24"} },
			wantErr: "has host bits set",
		},
		{
			name:    "forward mode with no upstreams",
			mutate:  func(c *Config) { c.Resolver.Upstreams = nil },
			wantErr: "resolver.upstreams is required",
		},
		{
			// Leaving upstreams set in recursive mode would let an operator
			// believe traffic is forwarded when it is not.
			name:    "recursive mode with upstreams still set",
			mutate:  func(c *Config) { c.Resolver.Mode = ModeRecursive },
			wantErr: "resolver.upstreams must be empty",
		},
		{
			name: "recursive mode with no address family",
			mutate: func(c *Config) {
				c.Resolver.Mode = ModeRecursive
				c.Resolver.Upstreams = nil
				c.Resolver.UseIPv4 = false
				c.Resolver.UseIPv6 = false
			},
			wantErr: "cannot both be false",
		},
		{
			name: "recursive mode with an unreadable root hints file",
			mutate: func(c *Config) {
				c.Resolver.Mode = ModeRecursive
				c.Resolver.Upstreams = nil
				c.Resolver.RootHintsFile = "/nonexistent/named.root"
			},
			wantErr: "root_hints_file",
		},
		{
			name:    "infra shards not a power of two",
			mutate:  func(c *Config) { c.Cache.Infra.Shards = 100 },
			wantErr: "cache.infra.shards must be a power of two",
		},
		{
			name:    "unknown resolver mode",
			mutate:  func(c *Config) { c.Resolver.Mode = "sideways" },
			wantErr: "resolver.mode must be",
		},
		{
			name:    "query timeout exceeds client budget",
			mutate:  func(c *Config) { c.Resolver.QueryTimeout = c.Resolver.ClientBudget * 2 },
			wantErr: "must not exceed resolver.client_budget",
		},
		{
			name:    "udp buffer too large",
			mutate:  func(c *Config) { c.Resolver.UDPBufferSize = 65535 },
			wantErr: "udp_buffer_size must be between",
		},
		{
			name:    "shards not power of two",
			mutate:  func(c *Config) { c.Cache.Shards = 100 },
			wantErr: "must be a power of two",
		},
		{
			name:    "min ttl above max ttl",
			mutate:  func(c *Config) { c.Cache.MinTTL = c.Cache.MaxTTL * 2 },
			wantErr: "must not exceed cache.max_ttl",
		},
		{
			// The whole point of the management plane rules: the admin API
			// must never ride on a service (presumed anycast) address, even
			// on a different port.
			name: "management shares a DNS service address",
			mutate: func(c *Config) {
				c.Listen.UDP = []string{"10.20.0.5:53"}
				c.Listen.TCP = []string{"10.20.0.5:53"}
				c.Management.Listen = []string{"10.20.0.5:8443"}
				c.Management.AllowFrom = []string{"10.20.0.0/24"}
				c.Management.TLS.CertFile = "/etc/cgdns/tls.crt"
				c.Management.TLS.KeyFile = "/etc/cgdns/tls.key"
			},
			wantErr: "shares an address with a DNS listener",
		},
		{
			name: "management wildcard",
			mutate: func(c *Config) {
				c.Management.Listen = []string{"0.0.0.0:8443"}
			},
			wantErr: "management.listen: \"0.0.0.0:8443\" is a wildcard",
		},
		{
			name: "non-loopback management without ACL",
			mutate: func(c *Config) {
				c.Management.Listen = []string{"10.20.0.5:8443"}
				c.Management.TLS.CertFile = "/etc/cgdns/tls.crt"
				c.Management.TLS.KeyFile = "/etc/cgdns/tls.key"
			},
			wantErr: "management.allow_from must list",
		},
		{
			name: "non-loopback management without TLS",
			mutate: func(c *Config) {
				c.Management.Listen = []string{"10.20.0.5:8443"}
				c.Management.AllowFrom = []string{"10.20.0.0/24"}
			},
			wantErr: "management.tls.cert_file and management.tls.key_file are required",
		},
		{
			name: "proxy headers trusted with no trusted proxies",
			mutate: func(c *Config) {
				c.Management.TrustProxyHeaders = true
			},
			wantErr: "management.trusted_proxies must be set",
		},
		{
			name: "metrics on a DNS service address",
			mutate: func(c *Config) {
				c.Listen.UDP = []string{"10.20.0.5:53"}
				c.Listen.TCP = []string{"10.20.0.5:53"}
				c.Metrics.Listen = "10.20.0.5:9153"
				c.Metrics.AllowFrom = []string{"10.20.0.0/24"}
			},
			wantErr: "shares an address with a DNS listener",
		},
		{
			name: "non-loopback metrics without ACL",
			mutate: func(c *Config) {
				c.Metrics.Listen = "10.20.0.5:9153"
			},
			wantErr: "metrics.allow_from must list source prefixes",
		},
		{
			name:    "bad log level",
			mutate:  func(c *Config) { c.Log.Level = "chatty" },
			wantErr: "log.level must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := valid()
			tt.mutate(&c)

			err := c.Validate()
			if err == nil {
				t.Fatalf("expected validation to fail with %q, got nil", tt.wantErr)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error should wrap ErrInvalid, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// Validate reports every problem at once so an operator fixing a config is not
// forced to rediscover the next fault on the next boot.
func TestValidate_ReportsAllProblemsAtOnce(t *testing.T) {
	c := valid()
	c.Node.ID = ""
	c.Cache.Shards = 100
	c.Log.Level = "loud"

	err := c.Validate()
	if err == nil {
		t.Fatal("expected failure")
	}
	for _, want := range []string{"node.id", "power of two", "log.level"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("combined error missing %q:\n%v", want, err)
		}
	}
}

// Loopback is never anycast, so co-locating the admin and DNS planes on it
// (separated by port) is legitimate — and is what every dev config does.
// The anycast rule must not fire there.
func TestValidate_AllowsLoopbackCoLocation(t *testing.T) {
	c := valid()
	c.Listen.UDP = []string{"127.0.0.1:5353"}
	c.Listen.TCP = []string{"127.0.0.1:5353"}
	c.Management.Listen = []string{"127.0.0.1:8443"}
	c.Metrics.Listen = "127.0.0.1:9153"

	if err := c.Validate(); err != nil {
		t.Fatalf("loopback co-location must be allowed, got: %v", err)
	}
}

// Recursive mode is a supported configuration now, not a stub.
func TestValidate_AcceptsRecursiveMode(t *testing.T) {
	c := valid()
	c.Resolver.Mode = ModeRecursive
	c.Resolver.Upstreams = nil

	if err := c.Validate(); err != nil {
		t.Fatalf("recursive mode should validate, got: %v", err)
	}
}

// Disabling IPv6 is permitted but must be surfaced, since it silently breaks
// resolution of IPv6-only zones.
func TestIsIPv6Disabled(t *testing.T) {
	tests := []struct {
		name string
		mode ResolverMode
		v6   bool
		want bool
	}{
		{"recursive with v6", ModeRecursive, true, false},
		{"recursive without v6", ModeRecursive, false, true},
		{"forward mode is unaffected", ModeForward, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := valid()
			c.Resolver.Mode = tt.mode
			c.Resolver.UseIPv6 = tt.v6
			if tt.mode == ModeRecursive {
				c.Resolver.Upstreams = nil
			}
			if err := c.Validate(); err != nil {
				t.Fatalf("config should be valid: %v", err)
			}
			if got := c.IsIPv6Disabled(); got != tt.want {
				t.Errorf("IsIPv6Disabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsOpenResolver(t *testing.T) {
	tests := []struct {
		name  string
		allow []string
		want  bool
	}{
		{"subscriber ranges only", []string{"10.0.0.0/8", "2001:db8::/32"}, false},
		{"v4 default route", []string{"0.0.0.0/0"}, true},
		{"v6 default route", []string{"::/0"}, true},
		{"loopback only", []string{"127.0.0.0/8"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := valid()
			c.Listen.AllowQuery = tt.allow
			if err := c.Validate(); err != nil {
				t.Fatalf("config should be valid: %v", err)
			}
			if got := c.IsOpenResolver(); got != tt.want {
				t.Errorf("IsOpenResolver() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParse_RejectsUnknownFields(t *testing.T) {
	// A typo'd key must be an error, never a silently ignored setting.
	_, err := Parse([]byte("node:\n  id: x\n  nonsense: true\n"))
	if err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
	if !strings.Contains(err.Error(), "nonsense") {
		t.Errorf("error should name the unknown field, got: %v", err)
	}
}

// Every shipped config must actually be valid — they are the first things
// anyone runs, and the examples every production config gets copied from.
func TestParse_ShippedConfigsAreValid(t *testing.T) {
	// The shipped configs name their feed and prefix files relative to the
	// repo root, which is where the Makefile runs the daemon from.
	t.Chdir("../..")

	tests := []struct {
		path     string
		wantMode ResolverMode
	}{
		{"deploy/dev/cgdns.yaml", ModeForward},
		{"deploy/dev/cgdns-recursive.yaml", ModeRecursive},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			raw, err := os.ReadFile(tt.path)
			if err != nil {
				t.Skipf("config not readable: %v", err)
			}
			cfg, err := Parse(raw)
			if err != nil {
				t.Fatalf("%s is invalid: %v", tt.path, err)
			}
			if cfg.Node.ID == "" {
				t.Error("config should set node.id")
			}
			if cfg.Resolver.Mode != tt.wantMode {
				t.Errorf("mode = %q, want %q", cfg.Resolver.Mode, tt.wantMode)
			}
			if cfg.IsOpenResolver() {
				t.Error("a shipped config must never be an open resolver")
			}
			if tt.wantMode == ModeRecursive {
				// Shipping a v4-only example would propagate the exact failure
				// mode the project treats as non-negotiable.
				if cfg.IsIPv6Disabled() {
					t.Error("the shipped recursive config must have IPv6 enabled")
				}
				if !cfg.Resolver.QNAMEMinimisation {
					t.Error("the shipped recursive config must enable QNAME minimisation")
				}
				if !cfg.Resolver.CaseRandomisation {
					t.Error("the shipped recursive config must enable 0x20 randomisation")
				}
			}
		})
	}
}

func TestDefault_IsNotUsableWithoutOperatorInput(t *testing.T) {
	// Defaults deliberately do not constitute a runnable config: node.id,
	// listeners, the client ACL and upstreams must all be stated explicitly.
	c := Default()
	if err := c.Validate(); err == nil {
		t.Fatal("bare defaults must not validate; operator input is required")
	}
}

// The operator interface and the WebUI must be reachable only on the management
// interface. An anycast address is the opposite of that: the whole internet
// routes to it, and which node answers is a matter of BGP.
func TestValidate_RejectsAdminPlanesOnAnycastAddresses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*Config)
		want  string
	}{
		{
			name: "management inside the anycast v4 prefix",
			apply: func(c *Config) {
				c.Management.Listen = []string{"10.255.0.53:8443"}
				c.Management.AllowFrom = []string{"10.20.0.0/24"}
				c.Management.TLS.CertFile = "/etc/cgdns/tls/mgmt.pem"
				c.Management.TLS.KeyFile = "/etc/cgdns/tls/mgmt.key"
			},
			want: "management.listen",
		},
		{
			name: "management inside the anycast v6 prefix",
			apply: func(c *Config) {
				c.Management.Listen = []string{"[fd51:13:53::53]:8443"}
				c.Management.AllowFrom = []string{"fd00::/8"}
				c.Management.TLS.CertFile = "/etc/cgdns/tls/mgmt.pem"
				c.Management.TLS.KeyFile = "/etc/cgdns/tls/mgmt.key"
			},
			want: "management.listen",
		},
		{
			name: "metrics inside the anycast prefix",
			apply: func(c *Config) {
				c.Metrics.Listen = "10.255.0.53:9153"
				c.Metrics.AllowFrom = []string{"10.20.0.0/24"}
			},
			want: "metrics.listen",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			c.Health.Enabled = true
			c.Health.AnycastPrefixes = []string{"10.255.0.53/32", "fd51:13:53::53/128"}
			c.Health.GoBGPTarget = "127.0.0.1:50051"
			tc.apply(&c)

			err := c.Validate()
			if err == nil {
				t.Fatal("an admin plane bound to an anycast address was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not name %s: %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "anycast") {
				t.Fatalf("error does not explain the anycast problem: %v", err)
			}
		})
	}
}

// The management interface address itself must still be accepted, or the rule
// would leave nowhere valid to bind.
func TestValidate_AcceptsAdminPlaneOnTheManagementAddress(t *testing.T) {
	c := valid()
	c.Health.Enabled = true
	c.Health.AnycastPrefixes = []string{"10.255.0.53/32", "fd51:13:53::53/128"}
	c.Health.GoBGPTarget = "127.0.0.1:50051"
	c.Management.Listen = []string{"10.20.0.7:8443"}
	c.Management.AllowFrom = []string{"10.20.0.0/24"}
	c.Management.TLS.CertFile = "/etc/cgdns/tls/mgmt.pem"
	c.Management.TLS.KeyFile = "/etc/cgdns/tls/mgmt.key"
	c.Metrics.Listen = "10.20.0.7:9153"
	c.Metrics.AllowFrom = []string{"10.20.0.0/24"}

	if err := c.Validate(); err != nil {
		t.Fatalf("management on a dedicated management address was rejected: %v", err)
	}
}

// Enabling the WebUI must not create a second listener anywhere: it is served
// by the management server, on the management addresses, or not at all.
func TestValidate_UIAddsNoListenerOfItsOwn(t *testing.T) {
	c := valid()
	c.Management.UI = true
	if err := c.Validate(); err != nil {
		t.Fatalf("UI on loopback management was rejected: %v", err)
	}

	c.Management.Listen = []string{"0.0.0.0:8443"}
	if err := c.Validate(); err == nil {
		t.Fatal("a wildcard management bind was accepted, which would expose the WebUI on every address including anycast")
	}
}
