// Command cgdns is the carrier recursive DNS daemon.
//
// Startup is intolerant: config is validated in full and every socket bound
// before the daemon reports ready, and either failing is fatal. Anycast routes
// production traffic to a node whether or not it is serving correctly.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/config"
	"github.com/JoshFinlayAU/cgdns/internal/control"
	"github.com/JoshFinlayAU/cgdns/internal/dnssec"
	"github.com/JoshFinlayAU/cgdns/internal/health"
	"github.com/JoshFinlayAU/cgdns/internal/management"
	"github.com/JoshFinlayAU/cgdns/internal/metrics"
	"github.com/JoshFinlayAU/cgdns/internal/netacl"
	"github.com/JoshFinlayAU/cgdns/internal/peer"
	"github.com/JoshFinlayAU/cgdns/internal/policy"
	"github.com/JoshFinlayAU/cgdns/internal/resolver"
	"github.com/JoshFinlayAU/cgdns/internal/resolver/roothints"
	"github.com/JoshFinlayAU/cgdns/internal/subscriber"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		configPath = flag.String("config", "/etc/cgdns/cgdns.yaml", "path to the configuration file")
		logLevel   = flag.String("log-level", "", "override log.level from config (debug|info|warn|error)")
		checkOnly  = flag.Bool("check", false, "validate the configuration and exit")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("cgdns %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}

	if err := run(*configPath, *logLevel, *checkOnly); err != nil {
		fmt.Fprintf(os.Stderr, "cgdns: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath, logLevelOverride string, checkOnly bool) error {
	startedAt := time.Now()
	ctx0 := context.Background()
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if logLevelOverride != "" {
		cfg.Log.Level = logLevelOverride
		if err := cfg.Validate(); err != nil {
			return err
		}
	}
	if checkOnly {
		fmt.Printf("cgdns: %s is valid\n", configPath)
		return nil
	}

	log := newLogger(cfg.Log)
	slog.SetDefault(log)
	log.Info("starting cgdns",
		slog.String("version", version),
		slog.String("node_id", cfg.Node.ID),
		slog.String("mode", string(cfg.Resolver.Mode)))

	if cfg.IsOpenResolver() {
		log.Warn("listen.allow_query contains a default route: this node will answer recursive queries from ANY source and can be used for reflection/amplification")
	}
	if cfg.IsValidationDisabled() {
		log.Warn("resolver.dnssec is false: answers are served unvalidated, AD is never set, and forged records from a compromised authoritative cannot be detected")
	}
	if cfg.IsIPv6Disabled() {
		log.Warn("resolver.use_ipv6 is false: this node cannot reach IPv6-only authoritative servers and will SERVFAIL for zones served only over IPv6")
	}

	rrCache, err := cache.New(cache.Options{
		MaxEntries:     cfg.Cache.MaxEntries,
		Shards:         cfg.Cache.Shards,
		MinTTL:         cfg.Cache.MinTTL,
		MaxTTL:         cfg.Cache.MaxTTL,
		MaxNegativeTTL: cfg.Cache.MaxNegativeTTL,
	})
	if err != nil {
		return fmt.Errorf("building cache: %w", err)
	}

	infraCache, err := cache.NewInfra(cache.InfraOptions{
		MaxEntries: cfg.Cache.Infra.MaxEntries,
		Shards:     cfg.Cache.Infra.Shards,
		InitialRTT: cfg.Cache.Infra.InitialRTT,
		MaxBackoff: cfg.Cache.Infra.MaxBackoff,
	})
	if err != nil {
		return fmt.Errorf("building infra cache: %w", err)
	}

	store, err := control.Open(control.StoreOptions{NodeID: cfg.Node.ID, Path: cfg.Control.StoreFile})
	if err != nil {
		return err
	}

	var (
		peerServer *peer.Server
		peerClient *peer.Client
	)
	peerMetrics := &peer.Metrics{}
	resolverCache := resolver.Cache(rrCache)

	if cfg.Peer.Enabled {
		serverTLS, clientTLS, err := loadPeerTLS(cfg.Peer)
		if err != nil {
			return err
		}
		peerServer, err = peer.NewServer(peer.ServerOptions{
			NodeID: cfg.Node.ID, Addr: cfg.Peer.Listen, TLS: serverTLS,
			Cache: rrCache, Store: store, IdleTimeout: cfg.Peer.IdleTimeout,
			Log: log, Metrics: peerMetrics,
		})
		if err != nil {
			return err
		}
		defer func() { _ = peerServer.Close() }()

		peerClient, err = peer.NewClient(peer.ClientOptions{
			NodeID: cfg.Node.ID, Addr: cfg.Peer.Remote, TLS: clientTLS,
			Timeout: cfg.Peer.Timeout, FetchTimeout: cfg.Peer.FetchTimeout,
			PushInterval: cfg.Peer.PushInterval, PushBatch: cfg.Peer.PushBatch,
			QueueLimit: cfg.Peer.QueueLimit, SyncInterval: cfg.Peer.SyncInterval,
			Store: store, Log: log, Metrics: peerMetrics,
		})
		if err != nil {
			return err
		}
		defer func() { _ = peerClient.Close() }()

		fetchClient := peerClient
		if !cfg.Peer.PullOnMiss {
			// Push-only: the sibling stays warm but never sits on the query
			// path.
			fetchClient = nil
		}
		resolverCache = peer.NewCache(peer.CacheOptions{
			Local: rrCache, Client: fetchClient, Log: log, Metrics: peerMetrics,
		})
		log.Info("pair link configured",
			slog.String("listen", cfg.Peer.Listen),
			slog.String("remote", cfg.Peer.Remote),
			slog.Bool("pull_on_miss", cfg.Peer.PullOnMiss),
			slog.Duration("fetch_timeout", cfg.Peer.FetchTimeout))
	}

	resMetrics := &resolver.Metrics{}
	recMetrics := &resolver.RecursiveMetrics{}

	handler, err := buildHandler(cfg, resolverCache, infraCache, resMetrics, recMetrics, log)
	if err != nil {
		return fmt.Errorf("building resolver: %w", err)
	}

	polMetrics := &policy.Metrics{}
	classifier, registry, err := buildPolicy(cfg, log)
	if err != nil {
		return err
	}

	var publisher *control.Publisher
	if classifier != nil {
		publisher = control.NewPublisher(control.PublisherOptions{
			Store: store, Classifier: classifier, Registry: registry, Log: log,
		})
	}
	if classifier != nil {
		handler = policy.NewEnforcer(policy.Options{
			Classifier: classifier,
			Registry:   registry,
			Next:       handler,
			Log:        log,
			Metrics:    polMetrics,
		})
	}

	queryACL := netacl.New(cfg.AllowQueryPrefixes(), false)

	txMetrics := &transport.Metrics{}

	udp, err := transport.NewUDP(transport.UDPOptions{
		Addrs:          cfg.UDPAddrs(),
		SocketsPerAddr: cfg.Listen.UDPSocketsPerAddr,
		UDPSize:        cfg.Resolver.UDPBufferSize,
		ClientBudget:   cfg.Resolver.ClientBudget,
		AllowQuery:     queryACL,
		Handler:        handler,
		Log:            log,
		Metrics:        txMetrics,
	})
	if err != nil {
		return err
	}
	defer func() { _ = udp.Close() }()

	tcp, err := transport.NewTCP(transport.TCPOptions{
		Addrs:        cfg.TCPAddrs(),
		MaxConns:     cfg.Listen.MaxTCPConns,
		IdleTimeout:  cfg.Listen.TCPIdleTimeout,
		ClientBudget: cfg.Resolver.ClientBudget,
		AllowQuery:   queryACL,
		Handler:      handler,
		Log:          log,
		Metrics:      txMetrics,
	})
	if err != nil {
		return err
	}
	defer func() { _ = tcp.Close() }()

	var (
		dot *transport.TCP
		doh *transport.DoH
	)
	if len(cfg.Listen.DoT) > 0 || len(cfg.Listen.DoH) > 0 {
		tlsCfg, err := loadTLS(cfg.Listen.TLS)
		if err != nil {
			return err
		}
		if len(cfg.Listen.DoT) > 0 {
			dot, err = transport.NewTCP(transport.TCPOptions{
				Addrs:        cfg.DoTAddrs(),
				MaxConns:     cfg.Listen.MaxTCPConns,
				IdleTimeout:  cfg.Listen.TCPIdleTimeout,
				ClientBudget: cfg.Resolver.ClientBudget,
				AllowQuery:   queryACL,
				TLS:          tlsCfg,
				Handler:      handler,
				Log:          log,
				Metrics:      txMetrics,
			})
			if err != nil {
				return err
			}
			defer func() { _ = dot.Close() }()
		}
		if len(cfg.Listen.DoH) > 0 {
			doh, err = transport.NewDoH(transport.DoHOptions{
				Addrs:          cfg.DoHAddrs(),
				Path:           cfg.Listen.DoHPath,
				TLS:            tlsCfg,
				MaxConns:       cfg.Listen.MaxTCPConns,
				IdleTimeout:    cfg.Listen.TCPIdleTimeout,
				ClientBudget:   cfg.Resolver.ClientBudget,
				UDPSize:        cfg.Resolver.UDPBufferSize,
				AllowQuery:     queryACL,
				TrustedProxies: cfg.DoHTrustedProxyPrefixes(),
				Handler:        handler,
				Log:            log,
				Metrics:        txMetrics,
			})
			if err != nil {
				return err
			}
			defer func() { _ = doh.Close() }()
		}
	}

	var (
		monitor    *health.Monitor
		advertiser *health.GoBGP
	)
	healthMetrics := &health.Metrics{}
	if cfg.Health.Enabled {
		advertiser, err = health.NewGoBGP(ctx0, health.GoBGPOptions{
			Target:   cfg.Health.GoBGPTarget,
			Prefixes: cfg.AnycastPrefixes(),
			Log:      log,
		})
		if err != nil {
			return fmt.Errorf("connecting to the routing daemon: %w", err)
		}
		defer func() { _ = advertiser.Close() }()

		// The probe presents a loopback source. It bypasses listen.allow_query
		// (it calls the handler directly) but is still classified for policy,
		// so it must not land in a filtered class.
		probeClient := netip.MustParseAddrPort("127.0.0.1:0")
		checks := []health.Checker{health.RootCheck(handler, probeClient)}
		if cfg.Health.Canary != "" {
			checks = append(checks, health.CanaryCheck(handler, cfg.Health.Canary, probeClient))
		}

		monitor, err = health.New(health.Options{
			Checks:           checks,
			Advertiser:       advertiser,
			Interval:         cfg.Health.Interval,
			Timeout:          cfg.Health.Timeout,
			FailureThreshold: cfg.Health.FailureThreshold,
			SuccessThreshold: cfg.Health.SuccessThreshold,
			MinHold:          cfg.Health.MinHold,
			MaxHold:          cfg.Health.MaxHold,
			StableAfter:      cfg.Health.StableAfter,
			Log:              log,
			Metrics:          healthMetrics,
		})
		if err != nil {
			return fmt.Errorf("building the health monitor: %w", err)
		}
		log.Info("anycast health monitoring enabled",
			slog.Any("prefixes", cfg.Health.AnycastPrefixes),
			slog.String("gobgp", cfg.Health.GoBGPTarget),
			slog.Duration("interval", cfg.Health.Interval))
	}

	reg := metrics.NewRegistry()
	registerMetrics(reg, txMetrics, resMetrics, rrCache)
	if classifier != nil {
		registerPolicyMetrics(reg, polMetrics, classifier, registry)
	}
	if monitor != nil {
		registerHealthMetrics(reg, healthMetrics, monitor)
	}
	if cfg.Peer.Enabled {
		registerPeerMetrics(reg, peerMetrics, peerClient, peerServer, store)
	}
	if cfg.Resolver.Mode == config.ModeRecursive {
		registerRecursiveMetrics(reg, recMetrics, infraCache)
	}

	var mgmt *management.Server
	if cfg.Management.Enabled {
		if store == nil {
			return errors.New("management is enabled but there is no control store to manage")
		}
		if err := management.Bootstrap(store, cfg.Management.BootstrapTokenFile, time.Now(), log); err != nil {
			return err
		}

		api, err := management.NewAPI(management.APIOptions{
			Store: store,
			Log:   log,
			Status: func() management.Status {
				s := management.Status{
					NodeID:  cfg.Node.ID,
					Version: version,
					Uptime:  time.Since(startedAt).Round(time.Second).String(),
				}
				if peerClient != nil {
					s.PeerOutboundUp = peerClient.Connected()
				}
				if peerServer != nil {
					s.PeerInboundUp = peerServer.Connected()
				}
				if monitor != nil {
					s.Healthy = monitor.State() == health.StateHealthy
					s.Advertised = s.Healthy
				}
				return s
			},
		})
		if err != nil {
			return err
		}

		var mgmtTLS *tls.Config
		if cfg.Management.TLS.CertFile != "" {
			if mgmtTLS, err = loadTLS(cfg.Management.TLS); err != nil {
				return fmt.Errorf("loading management TLS: %w", err)
			}
		}

		mgmt, err = management.NewServer(management.ServerOptions{
			Listen:  cfg.Management.Listen,
			TLS:     mgmtTLS,
			ACL:     netacl.New(cfg.ManagementAllowFrom(), true),
			Handler: api.Handler(),
			Log:     log,
		})
		if err != nil {
			return err
		}
		defer func() { _ = mgmt.Close() }()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	_ = ctx0

	var wg sync.WaitGroup
	errCh := make(chan error, 8)

	if monitor != nil {
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- monitor.Run(ctx) }()
	}
	if peerServer != nil {
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- peerServer.Serve(ctx) }()
	}
	if peerClient != nil {
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- peerClient.Run(ctx) }()
	}
	if publisher != nil {
		wg.Add(1)
		go func() { defer wg.Done(); publisher.Run(ctx) }()
	}
	if mgmt != nil {
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- mgmt.Serve(ctx) }()
	}
	if cfg.Control.StoreFile != "" {
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- store.RunFlusher(ctx, time.Second) }()
	}

	wg.Add(1)
	go func() { defer wg.Done(); errCh <- udp.Serve(ctx) }()
	wg.Add(1)
	go func() { defer wg.Done(); errCh <- tcp.Serve(ctx) }()
	if dot != nil {
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- dot.Serve(ctx) }()
	}
	if doh != nil {
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- doh.Serve(ctx) }()
	}

	if cfg.Metrics.Listen != "" {
		srv, err := metricsServer(cfg, reg, log)
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutCtx)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(srv.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("metrics server: %w", err)
			}
		}()
	}

	log.Info("cgdns ready",
		slog.Any("udp", cfg.Listen.UDP),
		slog.Any("tcp", cfg.Listen.TCP),
		slog.Any("dot", cfg.Listen.DoT),
		slog.Any("doh", cfg.Listen.DoH),
		slog.Int("allow_query_prefixes", queryACL.Len()))

	<-ctx.Done()
	log.Info("shutting down")
	stop()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		log.Warn("shutdown timed out; exiting anyway")
	}

	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// buildPolicy assembles subscriber classification and the policy registry.
//
// Feed and override problems are fatal here because this runs at startup, where
// the project's rule is to fail loudly rather than serve a configuration the
// operator did not describe. A reload, once the management plane can trigger
// one, keeps the previous registry instead — a broken feed must degrade
// filtering, never resolution.
func buildPolicy(cfg config.Config, log *slog.Logger) (*subscriber.Classifier, *policy.Registry, error) {
	if !cfg.Policy.Enabled {
		return nil, nil, nil
	}

	classifier := subscriber.New(cfg.Subscriber.DefaultClass)
	if cfg.Subscriber.PrefixFile != "" {
		entries, err := subscriber.LoadFile(cfg.Subscriber.PrefixFile)
		if err != nil {
			return nil, nil, err
		}
		classifier.Replace(entries)
	}

	feeds := make([]policy.FeedSpec, 0, len(cfg.Policy.Feeds))
	for _, f := range cfg.Policy.Feeds {
		feeds = append(feeds, policy.FeedSpec{Name: f.Name, Format: f.Format, File: f.File, RPZZone: f.RPZZone})
	}

	classes := make([]policy.ClassSpec, 0, len(cfg.Policy.Classes))
	for _, c := range cfg.Policy.Classes {
		action, err := policy.ParseAction(c.Action)
		if err != nil {
			return nil, nil, fmt.Errorf("class %q: %w", c.Name, err)
		}
		addrs := make([]netip.Addr, 0, len(c.RedirectTo))
		for _, a := range c.RedirectTo {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				return nil, nil, fmt.Errorf("class %q redirect_to %q: %w", c.Name, a, err)
			}
			addrs = append(addrs, addr)
		}
		classes = append(classes, policy.ClassSpec{Name: c.Name, Feeds: c.Feeds, Action: action, RedirectTo: addrs})
	}

	policies, err := policy.Compile(feeds, classes)
	if err != nil {
		return nil, nil, fmt.Errorf("compiling policy: %w", err)
	}

	registry := policy.NewRegistry()
	registry.Replace(policies)

	if cfg.Policy.OverridesFile != "" {
		overrides, err := policy.LoadOverridesFile(cfg.Policy.OverridesFile)
		if err != nil {
			return nil, nil, err
		}
		registry.ReplaceOverrides(overrides)
	}

	rules := 0
	for _, p := range policies {
		rules += p.Rules.Len()
	}
	log.Info("subscriber policy loaded",
		slog.Int("prefixes", classifier.Len()),
		slog.Int("classes", len(policies)),
		slog.Int("rules", rules),
		slog.Int("subscribers_with_overrides", registry.SubscribersWithOverrides()))

	return classifier, registry, nil
}

// registerHealthMetrics exposes the anycast health counters.
func registerHealthMetrics(reg *metrics.Registry, m *health.Metrics, mon *health.Monitor) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	reg.Register(
		// 1 when this node is in the anycast set. The single most useful series
		// for an operator: it answers "is this node taking traffic".
		metrics.Source{Name: "cgdns_anycast_advertised", Help: "1 when this node is advertising the anycast prefixes.", Kind: metrics.Gauge,
			Read: func() float64 {
				if mon.State() == health.StateHealthy {
					return 1
				}
				return 0
			}},
		metrics.Source{Name: "cgdns_health_checks_total", Help: "Health evaluations performed.", Kind: metrics.Counter, Read: u64(m.Checks.Load)},
		metrics.Source{Name: "cgdns_health_check_failures_total", Help: "Health evaluations with at least one failing check.", Kind: metrics.Counter, Read: u64(m.CheckFailures.Load)},
		metrics.Source{Name: "cgdns_anycast_advertisements_total", Help: "Times the anycast prefixes were advertised.", Kind: metrics.Counter, Read: u64(m.Advertisements.Load)},
		metrics.Source{Name: "cgdns_anycast_withdrawals_total", Help: "Times the anycast prefixes were withdrawn.", Kind: metrics.Counter, Read: u64(m.Withdrawals.Load)},
		// A rising flap count means dampening is escalating; investigate before
		// the node damps itself out for MaxHold.
		metrics.Source{Name: "cgdns_anycast_flaps_total", Help: "Withdrawals that followed a healthy state.", Kind: metrics.Counter, Read: u64(m.Flaps.Load)},
		metrics.Source{Name: "cgdns_anycast_advertise_errors_total", Help: "Failures talking to the routing daemon.", Kind: metrics.Counter, Read: u64(m.AdvertiseErrs.Load)},
	)
}

// registerPolicyMetrics exposes the policy counters.
func registerPolicyMetrics(reg *metrics.Registry, m *policy.Metrics, c *subscriber.Classifier, r *policy.Registry) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	reg.Register(
		metrics.Source{Name: "cgdns_policy_evaluated_total", Help: "Queries evaluated against subscriber policy.", Kind: metrics.Counter, Read: u64(m.Evaluated.Load)},
		metrics.Source{Name: "cgdns_policy_blocked_total", Help: "Queries blocked by policy.", Kind: metrics.Counter, Read: u64(m.Blocked.Load)},
		metrics.Source{Name: "cgdns_policy_redirected_total", Help: "Queries redirected to a walled garden.", Kind: metrics.Counter, Read: u64(m.Redirected.Load)},
		metrics.Source{Name: "cgdns_policy_rewritten_total", Help: "Queries rewritten to another name.", Kind: metrics.Counter, Read: u64(m.Rewritten.Load)},
		metrics.Source{Name: "cgdns_policy_dropped_total", Help: "Queries dropped by policy.", Kind: metrics.Counter, Read: u64(m.Dropped.Load)},
		metrics.Source{Name: "cgdns_policy_passthru_total", Help: "Queries explicitly allowed by a passthru rule.", Kind: metrics.Counter, Read: u64(m.Passthru.Load)},
		metrics.Source{Name: "cgdns_policy_override_allowed_total", Help: "Queries allowed by a per-subscriber whitelist.", Kind: metrics.Counter, Read: u64(m.OverrideAllowed.Load)},
		metrics.Source{Name: "cgdns_policy_override_blocked_total", Help: "Queries blocked by a per-subscriber block list.", Kind: metrics.Counter, Read: u64(m.OverrideBlocked.Load)},
		metrics.Source{Name: "cgdns_subscriber_prefixes", Help: "Subscriber prefixes loaded.", Kind: metrics.Gauge, Read: func() float64 { return float64(c.Len()) }},
		metrics.Source{Name: "cgdns_subscribers_with_overrides", Help: "Subscribers holding personal allow or block rules.", Kind: metrics.Gauge, Read: func() float64 { return float64(r.SubscribersWithOverrides()) }},
	)
}

// buildHandler selects the resolution strategy named in the config. Both
// satisfy transport.Handler, so the listeners are unaffected by the choice.
func buildHandler(
	cfg config.Config,
	rrCache resolver.Cache,
	infra *cache.Infra,
	fwdMetrics *resolver.Metrics,
	recMetrics *resolver.RecursiveMetrics,
	log *slog.Logger,
) (transport.Handler, error) {
	switch cfg.Resolver.Mode {
	case config.ModeForward:
		return resolver.NewForwarder(resolver.ForwardOptions{
			Upstreams:    cfg.UpstreamAddrs(),
			Cache:        rrCache,
			QueryTimeout: cfg.Resolver.QueryTimeout,
			UDPSize:      cfg.Resolver.UDPBufferSize,
			Log:          log,
			Metrics:      fwdMetrics,
		})

	case config.ModeRecursive:
		hints, err := loadRootHints(cfg.Resolver.RootHintsFile)
		if err != nil {
			return nil, err
		}
		log.Info("loaded root hints",
			slog.Int("servers", len(hints)),
			slog.String("source", rootHintsSource(cfg.Resolver.RootHintsFile)))

		var validator *dnssec.Validator
		if cfg.Resolver.DNSSEC {
			anchors, err := loadTrustAnchors(cfg.Resolver.TrustAnchorFile)
			if err != nil {
				return nil, err
			}
			validator, err = dnssec.New(dnssec.Options{
				Anchors:    anchors,
				MaxDepth:   cfg.Resolver.MaxDelegationDepth,
				AcceptSHA1: cfg.Resolver.AcceptSHA1,
			})
			if err != nil {
				return nil, fmt.Errorf("building DNSSEC validator: %w", err)
			}
			tags := make([]string, 0, len(anchors))
			for _, a := range anchors {
				tags = append(tags, strconv.Itoa(int(a.KeyTag)))
			}
			log.Info("DNSSEC validation enabled",
				slog.String("trust_anchors", strings.Join(tags, ",")),
				slog.String("source", rootHintsSource(cfg.Resolver.TrustAnchorFile)))
		}

		rec, err := resolver.NewRecursive(resolver.RecursiveOptions{
			Cache:             rrCache,
			Infra:             infra,
			RootHints:         hints,
			MaxDepth:          cfg.Resolver.MaxDelegationDepth,
			MaxOutbound:       cfg.Resolver.MaxOutboundPerQuery,
			MaxCNAME:          cfg.Resolver.MaxCNAMEChain,
			QueryTimeout:      cfg.Resolver.QueryTimeout,
			UDPSize:           cfg.Resolver.UDPBufferSize,
			QNAMEMinimisation: cfg.Resolver.QNAMEMinimisation,
			CaseRandomisation: cfg.Resolver.CaseRandomisation,
			UseIPv4:           cfg.Resolver.UseIPv4,
			UseIPv6:           cfg.Resolver.UseIPv6,
			Validator:         validator,
			Log:               log,
			Metrics:           recMetrics,
		})
		if err != nil {
			return nil, err
		}
		if validator != nil {
			// The validator pulls DNSKEY and DS records back through the same
			// delegation walk, so the wiring is circular by construction.
			validator.SetFetcher(rec)
		}
		return rec, nil

	default:
		return nil, fmt.Errorf("unknown resolver mode %q", cfg.Resolver.Mode)
	}
}

// loadPeerTLS builds the mutual-TLS pair for the pair link.
//
// Both directions verify: this node presents a certificate when dialling the
// sibling, and requires one when the sibling dials in. The sibling can insert
// into this node's cache, so an unverified peer could poison it.
func loadPeerTLS(p config.Peer) (server, client *tls.Config, err error) {
	cert, err := tls.LoadX509KeyPair(p.TLS.CertFile, p.TLS.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("loading pair-link keypair: %w", err)
	}
	caPEM, err := os.ReadFile(p.CAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading pair-link CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("pair-link CA %s contains no usable certificate", p.CAFile)
	}

	minVersion := uint16(tls.VersionTLS13)
	if p.TLS.MinVersion == "1.2" {
		minVersion = tls.VersionTLS12
	}

	host, _, err := net.SplitHostPort(p.Remote)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing peer.remote: %w", err)
	}

	return &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   minVersion,
		}, &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			ServerName:   host,
			MinVersion:   minVersion,
		}, nil
}

// registerPeerMetrics exposes the pair-link counters.
func registerPeerMetrics(reg *metrics.Registry, m *peer.Metrics, c *peer.Client, s *peer.Server, store *control.Store) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	bo := func(f func() bool) func() float64 {
		return func() float64 {
			if f() {
				return 1
			}
			return 0
		}
	}
	reg.Register(
		metrics.Source{Name: "cgdns_peer_outbound_up", Help: "1 when the outbound pair link is established.", Kind: metrics.Gauge, Read: bo(c.Connected)},
		metrics.Source{Name: "cgdns_peer_inbound_up", Help: "1 when the sibling is attached inbound.", Kind: metrics.Gauge, Read: bo(s.Connected)},
		metrics.Source{Name: "cgdns_peer_cache_push_sent_total", Help: "Cache entries offered to the sibling.", Kind: metrics.Counter, Read: u64(m.CachePushSent.Load)},
		metrics.Source{Name: "cgdns_peer_cache_push_received_total", Help: "Cache entries accepted from the sibling.", Kind: metrics.Counter, Read: u64(m.CachePushReceived.Load)},
		metrics.Source{Name: "cgdns_peer_cache_fetch_hits_total", Help: "Local misses served by the sibling.", Kind: metrics.Counter, Read: u64(m.CacheFetchHits.Load)},
		metrics.Source{Name: "cgdns_peer_cache_fetch_misses_total", Help: "Local misses the sibling could not serve.", Kind: metrics.Counter, Read: u64(m.CacheFetchMisses.Load)},
		metrics.Source{Name: "cgdns_peer_cache_fetch_errors_total", Help: "Cache fetches that failed on the pair link.", Kind: metrics.Counter, Read: u64(m.CacheFetchErrors.Load)},
		metrics.Source{Name: "cgdns_peer_records_sent_total", Help: "Config records sent to the sibling.", Kind: metrics.Counter, Read: u64(m.RecordsSent.Load)},
		metrics.Source{Name: "cgdns_peer_records_received_total", Help: "Config records adopted from the sibling.", Kind: metrics.Counter, Read: u64(m.RecordsReceived.Load)},
		metrics.Source{Name: "cgdns_peer_sync_errors_total", Help: "Config anti-entropy rounds that failed.", Kind: metrics.Counter, Read: u64(m.SyncErrors.Load)},
		metrics.Source{Name: "cgdns_peer_rejected_total", Help: "Pair-link handshakes refused.", Kind: metrics.Counter, Read: u64(m.Rejected.Load)},
		metrics.Source{Name: "cgdns_control_records", Help: "Live control-plane records held.", Kind: metrics.Gauge, Read: func() float64 { return float64(len(store.Records())) }},
	)
}

// loadTLS builds the TLS configuration for the encrypted transports.
func loadTLS(t config.TLS) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS keypair: %w", err)
	}
	min := uint16(tls.VersionTLS13)
	if t.MinVersion == "1.2" {
		min = tls.VersionTLS12
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   min,
		// DoH needs h2 offered in ALPN; DoT negotiates "dot" per RFC 7858 §3.2.
		NextProtos: []string{"h2", "http/1.1", "dot"},
	}, nil
}

// loadTrustAnchors reads the operator's anchor file, or the embedded copy.
func loadTrustAnchors(path string) ([]dnssec.Anchor, error) {
	now := time.Now()
	if path == "" {
		return dnssec.RootAnchors(now)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading trust anchors %s: %w", path, err)
	}
	all, err := dnssec.ParseAnchors(raw)
	if err != nil {
		return nil, err
	}
	out := make([]dnssec.Anchor, 0, len(all))
	for _, a := range all {
		if a.Valid(now) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no trust anchor in %s is valid right now", path)
	}
	return out, nil
}

// loadRootHints reads the operator's hints file, or the embedded copy.
func loadRootHints(path string) ([]resolver.Nameserver, error) {
	var (
		servers []roothints.Server
		err     error
	)
	if path == "" {
		servers, err = roothints.Default()
	} else {
		var raw []byte
		raw, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading root hints %s: %w", path, err)
		}
		servers, err = roothints.Parse(string(raw))
	}
	if err != nil {
		return nil, fmt.Errorf("loading root hints: %w", err)
	}

	out := make([]resolver.Nameserver, 0, len(servers))
	for _, s := range servers {
		out = append(out, resolver.Nameserver{Name: s.Name, Addrs: s.Addrs})
	}
	return out, nil
}

func rootHintsSource(path string) string {
	if path == "" {
		return "embedded"
	}
	return path
}

// aclServer bundles an http.Server with the listener it must serve, so the ACL
// wrapper cannot be forgotten at the call site.
type aclServer struct {
	*http.Server
	listener net.Listener
}

// metricsServer builds the /metrics endpoint behind its source ACL.
//
// The scrape endpoint is treated as an administrative surface, not a public
// one: it reveals query volumes, cache behaviour and upstream health, which is
// reconnaissance for anyone deciding whether this node is worth attacking.
func metricsServer(cfg config.Config, reg *metrics.Registry, log *slog.Logger) (*aclServer, error) {
	acl := netacl.New(cfg.MetricsAllowFrom(), true)

	mux := http.NewServeMux()
	mux.Handle(cfg.Metrics.Path, reg.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	ln, err := net.Listen("tcp", cfg.Metrics.Listen)
	if err != nil {
		return nil, fmt.Errorf("binding metrics listener %s: %w", cfg.Metrics.Listen, err)
	}

	return &aclServer{
		Server: &http.Server{
			Handler:           netacl.Middleware(acl, log, mux),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		listener: netacl.Listener(ln, acl, log),
	}, nil
}

func registerMetrics(reg *metrics.Registry, tx *transport.Metrics, res *resolver.Metrics, c *cache.Cache) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	reg.Register(
		metrics.Source{Name: "cgdns_queries_total", Help: "DNS queries received.", Kind: metrics.Counter, Read: u64(tx.Queries.Load)},
		metrics.Source{Name: "cgdns_query_parse_errors_total", Help: "Queries dropped as malformed.", Kind: metrics.Counter, Read: u64(tx.ParseErrors.Load)},
		metrics.Source{Name: "cgdns_query_dropped_total", Help: "Queries dropped due to overload or an expired budget.", Kind: metrics.Counter, Read: u64(tx.Dropped.Load)},
		metrics.Source{Name: "cgdns_handler_panics_total", Help: "Panics recovered at the transport boundary.", Kind: metrics.Counter, Read: u64(tx.Panics.Load)},
		metrics.Source{Name: "cgdns_responses_truncated_total", Help: "Responses truncated with TC set.", Kind: metrics.Counter, Read: u64(tx.Truncated.Load)},
		metrics.Source{Name: "cgdns_response_write_errors_total", Help: "Failures writing a response.", Kind: metrics.Counter, Read: u64(tx.WriteErrors.Load)},
		metrics.Source{Name: "cgdns_tcp_accepted_total", Help: "TCP connections accepted.", Kind: metrics.Counter, Read: u64(tx.TCPAccepted.Load)},
		metrics.Source{Name: "cgdns_tcp_refused_total", Help: "TCP connections refused by ACL or connection limit.", Kind: metrics.Counter, Read: u64(tx.TCPRefused.Load)},

		metrics.Source{Name: "cgdns_cache_hits_total", Help: "Queries answered from cache.", Kind: metrics.Counter, Read: u64(res.CacheHits.Load)},
		metrics.Source{Name: "cgdns_cache_misses_total", Help: "Queries that missed cache.", Kind: metrics.Counter, Read: u64(res.CacheMisses.Load)},
		metrics.Source{Name: "cgdns_upstream_queries_total", Help: "Outbound queries to upstream resolvers.", Kind: metrics.Counter, Read: u64(res.Upstream.Load)},
		metrics.Source{Name: "cgdns_upstream_failures_total", Help: "Outbound queries that failed.", Kind: metrics.Counter, Read: u64(res.UpstreamFail.Load)},
		metrics.Source{Name: "cgdns_tcp_fallback_total", Help: "Upstream exchanges retried over TCP after TC.", Kind: metrics.Counter, Read: u64(res.TCPFallback.Load)},
		metrics.Source{Name: "cgdns_servfail_total", Help: "Responses returned as SERVFAIL.", Kind: metrics.Counter, Read: u64(res.ServFail.Load)},
		metrics.Source{Name: "cgdns_timeouts_total", Help: "Queries that exhausted the client budget.", Kind: metrics.Counter, Read: u64(res.Timeouts.Load)},

		metrics.Source{Name: "cgdns_cache_entries", Help: "Entries currently held in the RRset cache.", Kind: metrics.Gauge, Read: func() float64 { return float64(c.Stats().Entries) }},
		metrics.Source{Name: "cgdns_cache_evictions_total", Help: "Entries evicted by LRU pressure.", Kind: metrics.Counter, Read: func() float64 { return float64(c.Stats().Evictions) }},
		metrics.Source{Name: "cgdns_cache_expired_total", Help: "Entries found expired on lookup.", Kind: metrics.Counter, Read: func() float64 { return float64(c.Stats().Expired) }},
	)
}

// registerRecursiveMetrics exposes the recursion-specific series. These are
// only registered in recursive mode, so a forwarding node does not publish a
// wall of permanently-zero counters.
func registerRecursiveMetrics(reg *metrics.Registry, m *resolver.RecursiveMetrics, infra *cache.Infra) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	reg.Register(
		metrics.Source{Name: "cgdns_recursion_referrals_total", Help: "Delegation referrals followed.", Kind: metrics.Counter, Read: u64(m.Referrals.Load)},
		metrics.Source{Name: "cgdns_recursion_bogus_referrals_total", Help: "Referrals rejected by the bailiwick check.", Kind: metrics.Counter, Read: u64(m.BogusReferrals.Load)},
		metrics.Source{Name: "cgdns_recursion_outbound_total", Help: "Queries sent to authoritative servers.", Kind: metrics.Counter, Read: u64(m.OutboundQueries.Load)},
		metrics.Source{Name: "cgdns_recursion_outbound_failures_total", Help: "Outbound queries that failed or timed out.", Kind: metrics.Counter, Read: u64(m.OutboundFailures.Load)},
		metrics.Source{Name: "cgdns_recursion_depth_exceeded_total", Help: "Queries abandoned at the delegation depth cap.", Kind: metrics.Counter, Read: u64(m.DepthExceeded.Load)},
		metrics.Source{Name: "cgdns_recursion_budget_exceeded_total", Help: "Queries abandoned at the outbound query cap.", Kind: metrics.Counter, Read: u64(m.BudgetExceeded.Load)},
		metrics.Source{Name: "cgdns_recursion_case_mismatch_total", Help: "Responses discarded for failing 0x20 verification (possible spoofing).", Kind: metrics.Counter, Read: u64(m.CaseMismatch.Load)},
		metrics.Source{Name: "cgdns_recursion_glueless_lookups_total", Help: "Nameserver names resolved because a delegation carried no usable glue.", Kind: metrics.Counter, Read: u64(m.GluelessLookups.Load)},
		metrics.Source{Name: "cgdns_recursion_edns_downgrades_total", Help: "Servers found to mishandle EDNS0 and retried without it.", Kind: metrics.Counter, Read: u64(m.EDNSDowngrades.Load)},
		metrics.Source{Name: "cgdns_recursion_tcp_fallbacks_total", Help: "Outbound exchanges retried over TCP after truncation.", Kind: metrics.Counter, Read: u64(m.TCPFallbacks.Load)},
		metrics.Source{Name: "cgdns_recursion_cname_chased_total", Help: "CNAME chains followed.", Kind: metrics.Counter, Read: u64(m.CNAMEChased.Load)},
		metrics.Source{Name: "cgdns_recursion_minimise_fallback_total", Help: "QNAME minimisation abandoned after an intermediate NXDOMAIN.", Kind: metrics.Counter, Read: u64(m.MinimiseFallback.Load)},
		metrics.Source{Name: "cgdns_dnssec_secure_total", Help: "Answers validated to a trust anchor.", Kind: metrics.Counter, Read: u64(m.Secure.Load)},
		metrics.Source{Name: "cgdns_dnssec_insecure_total", Help: "Answers from provably unsigned zones.", Kind: metrics.Counter, Read: u64(m.Insecure.Load)},
		// A rising bogus rate is either a broken zone or an attack in progress.
		metrics.Source{Name: "cgdns_dnssec_bogus_total", Help: "Answers rejected because DNSSEC validation failed.", Kind: metrics.Counter, Read: u64(m.Bogus.Load)},
		metrics.Source{Name: "cgdns_infra_servers", Help: "Authoritative server addresses tracked in the infrastructure cache.", Kind: metrics.Gauge, Read: func() float64 { return float64(infra.Len()) }},
	)
}

func newLogger(cfg config.Log) *slog.Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.Format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}
