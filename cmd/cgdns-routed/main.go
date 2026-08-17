// Command cgdns-routed installs BGP-learned routes into the kernel.
//
// It is a separate daemon from cgdns on purpose. Installing routes needs
// CAP_NET_ADMIN, and the process answering internet queries should not also be
// able to reconfigure the network. It reads the same node configuration file,
// so a node still has one config to edit.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/JoshFinlayAU/cgdns/internal/config"
	"github.com/JoshFinlayAU/cgdns/internal/routeagent"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		configPath = flag.String("config", "/etc/cgdns/cgdns.yaml", "path to the node configuration file")
		logLevel   = flag.String("log-level", "", "override log.level from config")
		checkOnly  = flag.Bool("check", false, "validate the configuration and exit")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("cgdns-routed %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}

	if err := run(*configPath, *logLevel, *checkOnly); err != nil {
		fmt.Fprintf(os.Stderr, "cgdns-routed: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath, logLevelOverride string, checkOnly bool) error {
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
		fmt.Printf("cgdns-routed: %s is valid\n", configPath)
		return nil
	}

	log := newLogger(cfg.Log)
	slog.SetDefault(log)

	if !cfg.RouteAgent.Enabled {
		// Exiting cleanly rather than idling: a disabled agent that sits there
		// looking healthy is harder to notice than one that is plainly not
		// running.
		log.Info("route_agent.enabled is false; nothing to do")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srcV4, srcV6 := cfg.RouteAgentSources()
	agent, err := routeagent.New(ctx, routeagent.Options{
		Target:    cfg.RouteAgent.GoBGPTarget,
		SourceV4:  srcV4,
		SourceV6:  srcV6,
		Accept:    cfg.RouteAgentAccept(),
		MaxRoutes: cfg.RouteAgent.MaxRoutes,
		Table:     cfg.RouteAgent.Table,
		Metric:    cfg.RouteAgent.Metric,
		Interval:  cfg.RouteAgent.Interval,
		Log:       log,
	})
	if err != nil {
		return err
	}
	defer func() { _ = agent.Close() }()

	log.Info("starting cgdns-routed",
		slog.String("version", version),
		slog.String("node_id", cfg.Node.ID))

	if err := agent.Run(ctx); err != nil {
		return err
	}
	log.Info("shutting down; installed routes removed so any static fallback applies")
	return nil
}

// newLogger mirrors the resolver's logging so both daemons read alike.
func newLogger(c config.Log) *slog.Logger {
	level := slog.LevelInfo
	switch c.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if c.Format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}
