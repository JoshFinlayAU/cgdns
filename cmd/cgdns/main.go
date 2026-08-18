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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/acme"
	"github.com/JoshFinlayAU/cgdns/internal/aggressive"
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
	"github.com/JoshFinlayAU/cgdns/internal/prefetch"
	"github.com/JoshFinlayAU/cgdns/internal/ratelimit"
	"github.com/JoshFinlayAU/cgdns/internal/resolver"
	"github.com/JoshFinlayAU/cgdns/internal/resolver/roothints"
	"github.com/JoshFinlayAU/cgdns/internal/servestale"
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
		MaxBytes:       int64(cfg.Cache.MaxSize),
		Shards:         cfg.Cache.Shards,
		MinTTL:         cfg.Cache.MinTTL,
		MaxTTL:         cfg.Cache.MaxTTL,
		MaxNegativeTTL: cfg.Cache.MaxNegativeTTL,
		MaxStale:       staleWindow(cfg),
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

	var prefetcher *prefetch.Cache
	prefetchMetrics := &prefetch.Metrics{}
	if cfg.Cache.Prefetch.Enabled {
		prefetcher = prefetch.New(resolverCache, prefetch.Options{
			Threshold:     cfg.Cache.Prefetch.Threshold,
			MinTTL:        cfg.Cache.Prefetch.MinTTL,
			MaxConcurrent: cfg.Cache.Prefetch.MaxConcurrent,
			Timeout:       cfg.Cache.Prefetch.Timeout,
			Log:           log,
			Metrics:       prefetchMetrics,
		})
		defer func() { _ = prefetcher.Close() }()
		resolverCache = prefetcher
	}

	resMetrics := &resolver.Metrics{}
	recMetrics := &resolver.RecursiveMetrics{}

	handler, err := buildHandler(cfg, resolverCache, infraCache, resMetrics, recMetrics, log)
	if err != nil {
		return fmt.Errorf("building resolver: %w", err)
	}

	if prefetcher != nil {
		// The refresh runs against the resolver alone, before policy and rate
		// limiting: it belongs to no subscriber, so there is no class to filter
		// it into and no client to limit.
		resolveOnly := handler
		probeClient := netip.MustParseAddrPort("127.0.0.1:0")
		prefetcher.SetRefresh(func(ctx context.Context, k cache.Key) {
			m := new(dns.Msg)
			m.SetQuestion(k.Name, k.Type)
			m.Question[0].Qclass = k.Class
			m.RecursionDesired = true
			// The answer is discarded: the cache fills as a side effect, which
			// is the whole point.
			_ = resolveOnly.ServeDNS(resolver.WithRefresh(ctx), &transport.Request{
				Msg:             m,
				Client:          probeClient,
				Local:           probeClient.Addr(),
				Proto:           transport.ProtoUDP,
				Received:        time.Now(),
				MaxResponseSize: dns.MaxMsgSize,
			})
		})
		log.Info("prefetch enabled",
			slog.Float64("threshold", cfg.Cache.Prefetch.Threshold),
			slog.Duration("min_ttl", cfg.Cache.Prefetch.MinTTL),
			slog.Int("max_concurrent", cfg.Cache.Prefetch.MaxConcurrent))
	}

	// Serve-stale sits directly around the resolver, inside policy: a name the
	// operator blocks stays blocked even when the answer came from expired
	// data.
	staleMetrics := &servestale.Metrics{}
	if cfg.Cache.ServeStale.Enabled {
		handler = servestale.New(servestale.Options{
			Next:      handler,
			Cache:     rrCache,
			AnswerTTL: cfg.Cache.ServeStale.AnswerTTL,
			Log:       log,
			Metrics:   staleMetrics,
		})
		log.Info("serve-stale enabled",
			slog.Duration("max_stale", cfg.Cache.ServeStale.MaxStale),
			slog.Duration("answer_ttl", cfg.Cache.ServeStale.AnswerTTL))
	}

	polMetrics := &policy.Metrics{}
	classifier, registry, err := buildPolicy(cfg, log)
	if err != nil {
		return err
	}

	// Feed content is fetched off the query path and written to files the
	// compiler reads, so a refresh never touches resolution directly.
	var (
		fetcher     *policy.Fetcher
		feedRefresh chan struct{}
	)
	fetchMetrics := &policy.FetchMetrics{}
	if cfg.Policy.Enabled && cfg.Policy.FeedRefreshInterval > 0 {
		dir := cfg.Policy.FeedDir
		if dir == "" {
			dir = filepath.Join(cfg.Node.StateDir, "feeds")
		}
		fetcher, err = policy.NewFetcher(policy.FetcherOptions{
			Dir:      dir,
			MaxBytes: cfg.Policy.FeedMaxBytes,
			Timeout:  cfg.Policy.FeedTimeout,
			Log:      log,
			Metrics:  fetchMetrics,
		})
		if err != nil {
			return err
		}
		feedRefresh = make(chan struct{}, 1)
		log.Info("feed fetching enabled",
			slog.String("dir", dir),
			slog.Duration("interval", cfg.Policy.FeedRefreshInterval))
	}

	var publisher *control.Publisher
	if classifier != nil {
		opts := control.PublisherOptions{
			Store: store, Classifier: classifier, Registry: registry, Log: log,
		}
		if fetcher != nil {
			opts.FeedPath = fetcher.Path
		}
		publisher = control.NewPublisher(opts)
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

	// Rate limiting wraps everything else, so it sees the response actually
	// bound for the client — including one policy rewrote. A device hammering a
	// blocked name is still a device hammering us.
	var limiter *ratelimit.Limiter
	rlMetrics := &ratelimit.Metrics{}
	if cfg.RateLimit.Enabled {
		limiter, err = ratelimit.New(ratelimit.Options{
			ResponsesPerSecond: cfg.RateLimit.ResponsesPerSecond,
			DenialsPerSecond:   cfg.RateLimit.DenialsPerSecond,
			ErrorsPerSecond:    cfg.RateLimit.ErrorsPerSecond,
			Window:             cfg.RateLimit.Window,
			SlipRatio:          cfg.RateLimit.SlipRatio,
			IPv4PrefixLen:      cfg.RateLimit.IPv4PrefixLen,
			IPv6PrefixLen:      cfg.RateLimit.IPv6PrefixLen,
			MaxBuckets:         cfg.RateLimit.MaxBuckets,
			Shards:             cfg.RateLimit.Shards,
			Metrics:            rlMetrics,
		})
		if err != nil {
			return fmt.Errorf("building the rate limiter: %w", err)
		}

		var exempt *netacl.ACL
		if len(cfg.RateLimit.ExemptClients) > 0 {
			exempt = netacl.New(cfg.RateLimitExempt(), false)
		}
		handler = ratelimit.NewHandler(ratelimit.HandlerOptions{
			Limiter: limiter,
			Next:    handler,
			Exempt:  exempt,
			Log:     log,
			Metrics: rlMetrics,
		})
		log.Info("response rate limiting enabled",
			slog.Float64("denials_per_second", cfg.RateLimit.DenialsPerSecond),
			slog.Float64("errors_per_second", cfg.RateLimit.ErrorsPerSecond),
			slog.Float64("responses_per_second", cfg.RateLimit.ResponsesPerSecond),
			slog.Int("slip_ratio", int(cfg.RateLimit.SlipRatio)))
	}

	queryACL := netacl.New(cfg.AllowQueryPrefixes(), false)

	txMetrics := &transport.Metrics{}

	udp, err := transport.NewUDP(transport.UDPOptions{
		Addrs:          cfg.UDPAddrs(),
		SocketsPerAddr: cfg.Listen.UDPSocketsPerAddr,
		Workers:        cfg.Listen.UDPWorkersPerSocket,
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
		doq *transport.DoQ
	)
	acmeMetrics := &acme.Metrics{}
	var certManager *acme.Manager
	if len(cfg.Listen.DoT) > 0 || len(cfg.Listen.DoH) > 0 || len(cfg.Listen.DoQ) > 0 {
		var tlsCfg *tls.Config
		if cfg.ACME.Enabled {
			certManager, err = buildACME(cfg, log, acmeMetrics)
			if err != nil {
				return err
			}
			// GetCertificate rather than a fixed certificate, so a renewal is
			// picked up by the next handshake without restarting a listener.
			tlsCfg = &tls.Config{
				GetCertificate: certManager.GetCertificate,
				MinVersion:     minTLSVersion(cfg.Listen.TLS.MinVersion),
				NextProtos:     []string{"h2", "http/1.1", "dot"},
			}
		} else {
			tlsCfg, err = loadTLS(cfg.Listen.TLS)
			if err != nil {
				return err
			}
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
		if len(cfg.Listen.DoQ) > 0 {
			doq, err = transport.NewDoQ(transport.DoQOptions{
				Addrs:             cfg.DoQAddrs(),
				TLS:               tlsCfg,
				MaxIdleTimeout:    cfg.Listen.DoQMaxIdleTimeout,
				MaxStreamsPerConn: int64(cfg.Listen.DoQMaxStreamsPerConn),
				ClientBudget:      cfg.Resolver.ClientBudget,
				AllowQuery:        queryACL,
				Handler:           handler,
				Log:               log,
				Metrics:           txMetrics,
			})
			if err != nil {
				return err
			}
			defer func() { _ = doq.Close() }()
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
	registerMetrics(reg, txMetrics, resMetrics, recMetrics, rrCache, acmeMetrics)
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
	if limiter != nil {
		registerRateLimitMetrics(reg, rlMetrics)
	}
	if cfg.Cache.ServeStale.Enabled {
		registerServeStaleMetrics(reg, staleMetrics)
	}
	if prefetcher != nil {
		registerPrefetchMetrics(reg, prefetchMetrics)
	}
	if cfg.Resolver.AggressiveNSEC && cfg.Resolver.DNSSEC {
		registerAggressiveMetrics(reg, nsecMetrics)
	}
	if fetcher != nil {
		registerFeedMetrics(reg, fetchMetrics)
	}

	var (
		mgmt     *management.Server
		sessions *management.SessionStore
	)
	if cfg.Management.Enabled {
		if store == nil {
			return errors.New("management is enabled but there is no control store to manage")
		}
		if err := management.Bootstrap(store, cfg.Management.BootstrapTokenFile, time.Now(), log); err != nil {
			return err
		}

		api, err := management.NewAPI(management.APIOptions{
			Store:      store,
			Log:        log,
			SessionTTL: cfg.Management.SessionTimeout,
			Issuer:     "cgdns " + cfg.Node.ID,
			UI:         cfg.Management.UI,
			Metrics:    reg.Snapshot,
			RefreshFeeds: func() {
				if feedRefresh != nil {
					select {
					case feedRefresh <- struct{}{}:
					default:
					}
				}
			},
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

		mgmtTLSCfg := cfg.Management.TLS
		if mgmtTLSCfg.CertFile == "" || mgmtTLSCfg.KeyFile == "" {
			// The WebUI's session cookie is Secure, so a browser will not store
			// it over plain HTTP. Generating a certificate keeps a fresh node
			// usable without the operator producing one by hand; real TLS is
			// expected to be terminated in front of this.
			hosts := make([]string, 0, len(cfg.Management.Listen))
			for _, a := range cfg.ManagementAddrs() {
				hosts = append(hosts, a.Addr().String())
			}
			certFile, keyFile, err := management.EnsureSelfSigned(
				filepath.Join(cfg.Node.StateDir, "tls"), cfg.Node.ID, hosts, log)
			if err != nil {
				return err
			}
			mgmtTLSCfg.CertFile, mgmtTLSCfg.KeyFile = certFile, keyFile
		}
		mgmtTLS, err := loadTLS(mgmtTLSCfg)
		if err != nil {
			return fmt.Errorf("loading management TLS: %w", err)
		}

		mgmt, err = management.NewServer(management.ServerOptions{
			Listen:      cfg.Management.Listen,
			TLS:         mgmtTLS,
			ACL:         netacl.New(cfg.ManagementAllowFrom(), true),
			LocalSocket: cfg.ManagementLocalSocket(),
			Handler:     api.Handler(),
			Log:         log,
		})
		if err != nil {
			return err
		}
		defer func() { _ = mgmt.Close() }()
		sessions = api.Sessions()
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
	if fetcher != nil && publisher != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runFeedRefresh(ctx, cfg, store, fetcher, publisher, feedRefresh, log)
		}()
	}
	if mgmt != nil {
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- mgmt.Serve(ctx) }()
	}
	if sessions != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					sessions.Sweep()
				}
			}
		}()
	}
	if cfg.Control.StoreFile != "" {
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- store.RunFlusher(ctx, time.Second) }()
	}
	if limiter != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Buckets are also evicted under pressure, but a flood leaves a
			// table full of sources that will never be seen again; sweeping
			// keeps it proportional to active clients.
			t := time.NewTicker(cfg.RateLimit.Window)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-t.C:
					limiter.Sweep(now)
				}
			}
		}()
	}

	if certManager != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Run never returns an error: a CA that cannot be reached is a
			// reason to retry, not a reason to stop resolving on the
			// certificate already held.
			_ = certManager.Run(ctx, cfg.ACME.CheckInterval)
		}()
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
	if doq != nil {
		wg.Add(1)
		go func() { defer wg.Done(); errCh <- doq.Serve(ctx) }()
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
// nsecMetrics is shared between the store and the metrics registry, which are
// built in different places.
var nsecMetrics = &aggressive.Metrics{}

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
		srcV4, srcV6 := cfg.OutboundSources()
		return resolver.NewForwarder(resolver.ForwardOptions{
			OutboundSource: resolver.OutboundSource{V4: srcV4, V6: srcV6},
			Upstreams:      cfg.UpstreamAddrs(),
			Cache:          rrCache,
			QueryTimeout:   cfg.Resolver.QueryTimeout,
			UDPSize:        cfg.Resolver.UDPBufferSize,
			Log:            log,
			Metrics:        fwdMetrics,
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

		srcV4, srcV6 := cfg.OutboundSources()
		var nsecStore *aggressive.Store
		if cfg.Resolver.AggressiveNSEC && cfg.Resolver.DNSSEC {
			nsecStore = aggressive.New(aggressive.Options{
				MaxZones:          cfg.Resolver.AggressiveNSECMaxZones,
				MaxRecordsPerZone: cfg.Resolver.AggressiveNSECMaxRecords,
				Metrics:           nsecMetrics,
			})
			log.Info("aggressive NSEC enabled",
				slog.Int("max_zones", cfg.Resolver.AggressiveNSECMaxZones),
				slog.Int("max_records_per_zone", cfg.Resolver.AggressiveNSECMaxRecords))
		}

		rec, err := resolver.NewRecursive(resolver.RecursiveOptions{
			NSEC:              nsecStore,
			OutboundSource:    resolver.OutboundSource{V4: srcV4, V6: srcV6},
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
// minTLSVersion maps the configured minimum. 1.3 unless an operator has a
// client old enough to need otherwise.
func minTLSVersion(v string) uint16 {
	if v == "1.2" {
		return tls.VersionTLS12
	}
	return tls.VersionTLS13
}

// buildACME assembles the certificate manager and picks the challenge type.
//
// dns-01 whenever a provider is configured, because it opens nothing. http-01
// otherwise, binding its port only for the duration of each challenge.
func buildACME(cfg config.Config, log *slog.Logger, m *acme.Metrics) (*acme.Manager, error) {
	var solver acme.Solver
	switch cfg.ACME.DNS01.Provider {
	case "cloudflare":
		raw, err := os.ReadFile(cfg.ACME.DNS01.APITokenFile)
		if err != nil {
			return nil, fmt.Errorf("reading the acme dns-01 token: %w", err)
		}
		solver = &acme.DNS01{
			Provider: &acme.Cloudflare{
				Token:  strings.TrimSpace(string(raw)),
				ZoneID: cfg.ACME.DNS01.ZoneID,
			},
			PropagationTimeout: cfg.ACME.DNS01.PropagationTimeout,
			Resolvers:          cfg.ACME.DNS01.Resolvers,
			Log:                log,
		}
	default:
		addrs := cfg.ACME.HTTP01.Listen
		if len(addrs) == 0 {
			addrs = defaultChallengeAddrs(cfg)
		}
		solver = &acme.HTTP01{Addrs: addrs, Timeout: cfg.ACME.HTTP01.Timeout, Log: log}
	}

	return acme.New(acme.Options{
		Domains:        cfg.ACME.Domains,
		Email:          cfg.ACME.Email,
		DirectoryURL:   cfg.ACME.DirectoryURL,
		CertFile:       cfg.Listen.TLS.CertFile,
		KeyFile:        cfg.Listen.TLS.KeyFile,
		AccountKeyFile: cfg.ACME.AccountKeyFile,
		RenewBefore:    cfg.ACME.RenewBefore,
		Solver:         solver,
		Log:            log,
		Metrics:        m,
	})
}

// defaultChallengeAddrs puts the http-01 responder on port 80 of every address
// already serving an encrypted transport, since those are the addresses the
// name resolves to and therefore the ones the CA will connect to.
func defaultChallengeAddrs(cfg config.Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range [][]string{cfg.Listen.DoT, cfg.Listen.DoH, cfg.Listen.DoQ} {
		for _, a := range group {
			host, _, err := net.SplitHostPort(a)
			if err != nil {
				continue
			}
			addr := net.JoinHostPort(host, "80")
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	return out
}

func loadTLS(t config.TLS) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS keypair: %w", err)
	}
	min := minTLSVersion(t.MinVersion)
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

func registerMetrics(reg *metrics.Registry, tx *transport.Metrics, res *resolver.Metrics, rec *resolver.RecursiveMetrics, c *cache.Cache, acmeMetrics *acme.Metrics) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	i64 := func(f func() int64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	reg.Register(
		metrics.Source{Name: "cgdns_queries_total", Help: "DNS queries received.", Kind: metrics.Counter, Read: u64(tx.Queries.Load)},
		// Whichever mode is running keeps this tally; the other stays zero. It
		// is registered here rather than beside the recursion counters so the
		// hit ratio exists in both modes — an operator asking "how much is the
		// cache doing" should not get silence because of how the node resolves.
		metrics.Source{Name: "cgdns_queries_from_cache_total", Help: "Client queries answered without a single outbound query. This is the hit ratio, against cgdns_queries_total.", Kind: metrics.Counter, Read: func() float64 {
			return float64(res.CacheHits.Load() + rec.AnsweredFromCache.Load())
		}},
		metrics.Source{Name: "cgdns_acme_renewals_total", Help: "Certificates successfully issued or renewed.", Kind: metrics.Counter, Read: u64(acmeMetrics.Renewals.Load)},
		metrics.Source{Name: "cgdns_acme_failures_total", Help: "Failed certificate orders. Sustained non-zero means the certificate will eventually expire.", Kind: metrics.Counter, Read: u64(acmeMetrics.Failures.Load)},
		metrics.Source{Name: "cgdns_acme_cert_not_after", Help: "Expiry of the certificate in use, as a Unix timestamp. Alert on this approaching, not on the renewal count.", Kind: metrics.Gauge, Read: i64(acmeMetrics.NotAfter.Load)},
		metrics.Source{Name: "cgdns_acme_challenge_seconds", Help: "How long the http-01 port was open during the last challenge. It is the exposure window.", Kind: metrics.Gauge, Read: i64(acmeMetrics.ChallengeSeconds.Load)},
		metrics.Source{Name: "cgdns_query_parse_errors_total", Help: "Queries dropped as malformed.", Kind: metrics.Counter, Read: u64(tx.ParseErrors.Load)},
		metrics.Source{Name: "cgdns_query_dropped_total", Help: "Queries dropped due to overload or an expired budget.", Kind: metrics.Counter, Read: u64(tx.Dropped.Load)},
		metrics.Source{Name: "cgdns_handler_panics_total", Help: "Panics recovered at the transport boundary.", Kind: metrics.Counter, Read: u64(tx.Panics.Load)},
		metrics.Source{Name: "cgdns_responses_truncated_total", Help: "Responses truncated with TC set.", Kind: metrics.Counter, Read: u64(tx.Truncated.Load)},
		metrics.Source{Name: "cgdns_response_write_errors_total", Help: "Failures writing a response.", Kind: metrics.Counter, Read: u64(tx.WriteErrors.Load)},
		metrics.Source{Name: "cgdns_tcp_accepted_total", Help: "TCP connections accepted.", Kind: metrics.Counter, Read: u64(tx.TCPAccepted.Load)},
		metrics.Source{Name: "cgdns_tcp_refused_total", Help: "TCP connections refused by ACL or connection limit.", Kind: metrics.Counter, Read: u64(tx.TCPRefused.Load)},

		// Read from the cache rather than the resolver: only the forwarder
		// increments the resolver's copy, so in recursive mode — which is what
		// a POP runs — both read zero for ever, and hit ratio is the first
		// number anyone asks a resolver for.
		// These count cache lookups, not client queries: one recursion makes
		// many — the delegation walk, every DNSKEY, every DS. Useful for cache
		// behaviour, misleading as a hit ratio. For that, use
		// cgdns_queries_from_cache_total.
		metrics.Source{Name: "cgdns_cache_lookup_hits_total", Help: "Cache lookups that found a live entry. Includes internal lookups made during recursion.", Kind: metrics.Counter, Read: func() float64 { return float64(c.Stats().Hits) }},
		metrics.Source{Name: "cgdns_cache_lookup_misses_total", Help: "Cache lookups that found nothing.", Kind: metrics.Counter, Read: func() float64 { return float64(c.Stats().Misses) }},
		metrics.Source{Name: "cgdns_upstream_queries_total", Help: "Outbound queries to upstream resolvers.", Kind: metrics.Counter, Read: u64(res.Upstream.Load)},
		metrics.Source{Name: "cgdns_upstream_failures_total", Help: "Outbound queries that failed.", Kind: metrics.Counter, Read: u64(res.UpstreamFail.Load)},
		metrics.Source{Name: "cgdns_tcp_fallback_total", Help: "Upstream exchanges retried over TCP after TC.", Kind: metrics.Counter, Read: u64(res.TCPFallback.Load)},
		metrics.Source{Name: "cgdns_servfail_total", Help: "Responses returned as SERVFAIL.", Kind: metrics.Counter, Read: u64(res.ServFail.Load)},
		metrics.Source{Name: "cgdns_timeouts_total", Help: "Queries that exhausted the client budget.", Kind: metrics.Counter, Read: u64(res.Timeouts.Load)},

		metrics.Source{Name: "cgdns_cache_bytes", Help: "Estimated memory held by cached entries. This is what cache.max_size bounds and what a node should be sized against.", Kind: metrics.Gauge, Read: func() float64 { return float64(c.Stats().Bytes) }},
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
		metrics.Source{Name: "cgdns_dnssec_unavailable_total", Help: "Answers withheld because the records needed to validate could not be fetched.", Kind: metrics.Counter, Read: u64(m.ValidationUnavailable.Load)},
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

func registerRateLimitMetrics(reg *metrics.Registry, m *ratelimit.Metrics) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	reg.Register(
		metrics.Source{Name: "cgdns_ratelimit_evaluated_total", Help: "Responses considered for rate limiting.", Kind: metrics.Counter, Read: u64(m.Evaluated.Load)},
		metrics.Source{Name: "cgdns_ratelimit_allowed_total", Help: "Responses that were within their bucket's allowance.", Kind: metrics.Counter, Read: u64(m.Allowed.Load)},
		// Rising means something is being limited: either an attack, or a rate
		// set below what a legitimate client needs.
		metrics.Source{Name: "cgdns_ratelimit_dropped_total", Help: "Responses dropped by rate limiting.", Kind: metrics.Counter, Read: u64(m.Dropped.Load)},
		metrics.Source{Name: "cgdns_ratelimit_slipped_total", Help: "Over-limit responses sent truncated so a real client retries over TCP.", Kind: metrics.Counter, Read: u64(m.Slipped.Load)},
		metrics.Source{Name: "cgdns_ratelimit_exempted_total", Help: "Responses skipped because the client is exempt.", Kind: metrics.Counter, Read: u64(m.Exempted.Load)},
		metrics.Source{Name: "cgdns_ratelimit_buckets", Help: "Rate-limit buckets currently held.", Kind: metrics.Gauge, Read: func() float64 { return float64(m.Buckets.Load()) }},
		// Sustained evictions mean max_buckets is too small for the client
		// population, so buckets are being forgotten while still in use.
		metrics.Source{Name: "cgdns_ratelimit_evictions_total", Help: "Buckets evicted to stay within max_buckets.", Kind: metrics.Counter, Read: u64(m.Evictions.Load)},
	)
}

// staleWindow is how long the cache keeps expired entries, which is zero unless
// serve-stale is on: without it, retaining them would only waste memory.
func staleWindow(cfg config.Config) time.Duration {
	if !cfg.Cache.ServeStale.Enabled {
		return 0
	}
	return cfg.Cache.ServeStale.MaxStale
}

func registerServeStaleMetrics(reg *metrics.Registry, m *servestale.Metrics) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	reg.Register(
		// Rising means authoritatives are failing and subscribers are being
		// kept online by expired data. It is a good outcome and a bad sign.
		metrics.Source{Name: "cgdns_serve_stale_served_total", Help: "Responses answered from expired cache data.", Kind: metrics.Counter, Read: u64(m.Served.Load)},
		metrics.Source{Name: "cgdns_serve_stale_eligible_total", Help: "Resolution failures where stale data was consulted.", Kind: metrics.Counter, Read: u64(m.Eligible.Load)},
		metrics.Source{Name: "cgdns_serve_stale_unavailable_total", Help: "Resolution failures with nothing stale to fall back to.", Kind: metrics.Counter, Read: u64(m.Unavailable.Load)},
	)
}

func registerPrefetchMetrics(reg *metrics.Registry, m *prefetch.Metrics) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	reg.Register(
		metrics.Source{Name: "cgdns_prefetch_triggered_total", Help: "Entries refreshed because a read found them close to expiry.", Kind: metrics.Counter, Read: u64(m.Triggered.Load)},
		metrics.Source{Name: "cgdns_prefetch_completed_total", Help: "Refreshes that ran to completion.", Kind: metrics.Counter, Read: u64(m.Completed.Load)},
		metrics.Source{Name: "cgdns_prefetch_suppressed_total", Help: "Refreshes skipped because one was already in flight for that name.", Kind: metrics.Counter, Read: u64(m.Suppressed.Load)},
		// Sustained drops mean max_concurrent is too small for the working set,
		// so popular names are expiring before their refresh gets a slot.
		metrics.Source{Name: "cgdns_prefetch_dropped_total", Help: "Refreshes skipped because the concurrency cap was full.", Kind: metrics.Counter, Read: u64(m.Dropped.Load)},
		metrics.Source{Name: "cgdns_prefetch_in_flight", Help: "Refreshes running now.", Kind: metrics.Gauge, Read: func() float64 { return float64(m.InFlight.Load()) }},
	)
}

func registerAggressiveMetrics(reg *metrics.Registry, m *aggressive.Metrics) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	reg.Register(
		// Rising fast means a flood of made-up names is being absorbed here
		// rather than reaching the zone it is aimed at.
		metrics.Source{Name: "cgdns_nsec_synthesised_total", Help: "NXDOMAINs answered from a cached NSEC proof instead of asking the authoritative.", Kind: metrics.Counter, Read: u64(m.Synthesised.Load)},
		metrics.Source{Name: "cgdns_nsec_stored_total", Help: "NSEC records kept from validated denials.", Kind: metrics.Counter, Read: u64(m.Stored.Load)},
		metrics.Source{Name: "cgdns_nsec_misses_total", Help: "Lookups with no cached NSEC proof covering the name.", Kind: metrics.Counter, Read: u64(m.Misses.Load)},
		metrics.Source{Name: "cgdns_nsec_zones", Help: "Zones with NSEC records cached.", Kind: metrics.Gauge, Read: func() float64 { return float64(m.Zones.Load()) }},
		metrics.Source{Name: "cgdns_nsec_records", Help: "NSEC records held.", Kind: metrics.Gauge, Read: func() float64 { return float64(m.Records.Load()) }},
	)
}

// runFeedRefresh keeps locally fetched feed content current.
//
// It runs once at startup so a node that has been down comes back with fresh
// lists rather than whatever it had when it stopped, then on the configured
// interval. A refresh that changes nothing does not republish: recompiling
// identical rules would swap the query path's tables for no reason.
func runFeedRefresh(
	ctx context.Context,
	cfg config.Config,
	store *control.Store,
	fetcher *policy.Fetcher,
	publisher *control.Publisher,
	now <-chan struct{},
	log *slog.Logger,
) {
	refresh := func() {
		state, _ := store.State()
		feeds := make([]policy.Feed, 0, len(state.Feeds()))
		for _, f := range state.Feeds() {
			if f.URL == "" {
				continue
			}
			feeds = append(feeds, policy.Feed{Name: f.Name, URL: f.URL, SHA256: f.SHA256})
		}
		if len(feeds) == 0 {
			return
		}

		changed := 0
		for _, r := range fetcher.Refresh(ctx, feeds) {
			if r.Updated {
				changed++
			}
		}
		if changed > 0 {
			log.Info("feed content changed, recompiling policy", slog.Int("feeds", changed))
			publisher.Republish()
		}
	}

	refresh()

	t := time.NewTicker(cfg.Policy.FeedRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		case <-now:
			// An operator asked for it, usually because they just added a feed
			// and would rather not wait an hour to see whether it works.
			refresh()
		}
	}
}

func registerFeedMetrics(reg *metrics.Registry, m *policy.FetchMetrics) {
	u64 := func(f func() uint64) func() float64 {
		return func() float64 { return float64(f()) }
	}
	reg.Register(
		metrics.Source{Name: "cgdns_feed_fetch_attempts_total", Help: "Feed fetches attempted.", Kind: metrics.Counter, Read: u64(m.Attempts.Load)},
		metrics.Source{Name: "cgdns_feed_fetch_updated_total", Help: "Feed fetches that changed the local content.", Kind: metrics.Counter, Read: u64(m.Updated.Load)},
		metrics.Source{Name: "cgdns_feed_fetch_unchanged_total", Help: "Feed fetches that found no change.", Kind: metrics.Counter, Read: u64(m.Unchanged.Load)},
		// Rising means filtering is going stale: the previous content is still
		// serving, which is the right failure, but nobody is refreshing it.
		metrics.Source{Name: "cgdns_feed_fetch_failures_total", Help: "Feed fetches that failed, leaving the previous content in place.", Kind: metrics.Counter, Read: u64(m.Failures.Load)},
		// Any of these is worth an alert: a feed was tampered with in transit,
		// or its publisher changed it without telling the control plane.
		metrics.Source{Name: "cgdns_feed_hash_mismatches_total", Help: "Feed content that did not match its pinned sha256.", Kind: metrics.Counter, Read: u64(m.HashMismatches.Load)},
		metrics.Source{Name: "cgdns_feed_last_success_timestamp", Help: "Unix time of the last successful feed fetch.", Kind: metrics.Gauge, Read: func() float64 { return float64(m.LastSuccess.Load()) }},
	)
}
