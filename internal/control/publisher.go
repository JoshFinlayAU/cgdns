package control

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"

	"github.com/JoshFinlayAU/cgdns/internal/policy"
	"github.com/JoshFinlayAU/cgdns/internal/subscriber"
)

// Publisher moves control-plane state into the structures the query path reads.
//
// It coalesces: a burst of writes, or a catch-up sync pulling hundreds of
// records from the peer, bumps the version many times and produces one rebuild
// rather than recompiling policy per record.
//
// A rebuild that fails leaves the previous published state in place. Feeds are
// curated elsewhere and will eventually ship something malformed; when that
// happens filtering must go stale, never resolution.
type Publisher struct {
	store      *Store
	classifier *subscriber.Classifier
	registry   *policy.Registry
	log        *slog.Logger

	published atomic.Uint64
	failures  atomic.Uint64
}

// PublisherOptions configures a Publisher.
type PublisherOptions struct {
	Store      *Store
	Classifier *subscriber.Classifier
	Registry   *policy.Registry
	Log        *slog.Logger
}

// NewPublisher builds a Publisher.
func NewPublisher(opts PublisherOptions) *Publisher {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Publisher{
		store:      opts.Store,
		classifier: opts.Classifier,
		registry:   opts.Registry,
		log:        opts.Log,
	}
}

// Run publishes on every state change until ctx is cancelled.
func (p *Publisher) Run(ctx context.Context) {
	stop := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stop)
	}()

	var known uint64
	// Publish once up front so a node that just loaded its store from disk
	// serves that policy without waiting for the next write.
	p.publish()

	for {
		version := p.store.WaitForChange(known, stop)
		if ctx.Err() != nil {
			return
		}
		if version == known {
			continue
		}
		known = version
		p.publish()
	}
}

// PublishedVersion reports the last state version successfully published.
func (p *Publisher) PublishedVersion() uint64 { return p.published.Load() }

// Failures reports how many rebuilds were abandoned.
func (p *Publisher) Failures() uint64 { return p.failures.Load() }

// publish rebuilds and swaps the query-path structures.
func (p *Publisher) publish() {
	state, version := p.store.State()

	entries, err := subscriberEntries(state)
	if err != nil {
		p.failures.Add(1)
		p.log.Error("keeping previous subscriber table; the new one did not compile",
			slog.Uint64("version", version), slog.String("err", err.Error()))
		return
	}

	policies, warnings, err := compilePolicies(state)
	if err != nil {
		p.failures.Add(1)
		p.log.Error("keeping previous policy; the new one did not compile",
			slog.Uint64("version", version), slog.String("err", err.Error()))
		return
	}
	for _, w := range warnings {
		p.log.Warn("policy feed skipped", slog.String("detail", w))
	}

	overrides := compileOverrides(state)

	if p.classifier != nil {
		p.classifier.Replace(entries)
	}
	if p.registry != nil {
		p.registry.Replace(policies)
		p.registry.ReplaceOverrides(overrides)
	}
	p.published.Store(version)

	p.log.Info("published control-plane state",
		slog.Uint64("version", version),
		slog.Int("prefixes", len(entries)),
		slog.Int("classes", len(policies)),
		slog.Int("subscribers_with_overrides", len(overrides)))
}

// subscriberEntries converts replicated records into classifier entries.
func subscriberEntries(state *State) ([]subscriber.Entry, error) {
	records := state.Subscribers()
	out := make([]subscriber.Entry, 0, len(records))
	for _, r := range records {
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			return nil, fmt.Errorf("subscriber prefix %q: %w", r.Prefix, err)
		}
		out = append(out, subscriber.Entry{
			Prefix:     p,
			Subscriber: subscriber.Subscriber{ID: r.ID, Class: r.Class},
		})
	}
	return out, nil
}

// compileOverrides turns replicated override records into policy rule sets.
func compileOverrides(state *State) map[string]*policy.Overrides {
	out := map[string]*policy.Overrides{}
	for _, r := range state.Overrides() {
		ov := &policy.Overrides{Allow: policy.NewSet(), Block: policy.NewSet()}
		for _, name := range r.Allow {
			rule := policy.Rule{Action: policy.ActionPassthru, Feed: "override:" + r.SubscriberID}
			ov.Allow.AddExact(name, rule)
			ov.Allow.AddWildcard(name, rule)
		}
		for _, name := range r.Block {
			rule := policy.Rule{Action: policy.ActionNXDOMAIN, Feed: "override:" + r.SubscriberID}
			ov.Block.AddExact(name, rule)
			ov.Block.AddWildcard(name, rule)
		}
		out[r.SubscriberID] = ov
	}
	return out
}

// compilePolicies builds per-class rule sets from feed metadata.
//
// A feed whose content this node does not hold is reported and skipped rather
// than failing the whole rebuild: one unfetched feed must not drop every other
// class's filtering.
func compilePolicies(state *State) (map[string]*policy.Policy, []string, error) {
	var (
		specs    []policy.FeedSpec
		warnings []string
		usable   = map[string]bool{}
	)
	for _, f := range state.Feeds() {
		if f.File == "" {
			warnings = append(warnings, fmt.Sprintf("feed %q has no local content on this node yet", f.Name))
			continue
		}
		if _, err := os.Stat(f.File); err != nil {
			warnings = append(warnings, fmt.Sprintf("feed %q content %q is not readable: %v", f.Name, f.File, err))
			continue
		}
		specs = append(specs, policy.FeedSpec{
			Name: f.Name, Format: f.Format, File: f.File, RPZZone: f.RPZZone,
		})
		usable[f.Name] = true
	}

	classes := make([]policy.ClassSpec, 0, len(state.Classes()))
	for _, c := range state.Classes() {
		action, err := policy.ParseAction(c.Action)
		if err != nil {
			return nil, warnings, fmt.Errorf("class %q: %w", c.Name, err)
		}
		addrs := make([]netip.Addr, 0, len(c.RedirectTo))
		for _, a := range c.RedirectTo {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				return nil, warnings, fmt.Errorf("class %q redirect_to %q: %w", c.Name, a, err)
			}
			addrs = append(addrs, addr)
		}

		feeds := make([]string, 0, len(c.Feeds))
		for _, f := range c.Feeds {
			if usable[f] {
				feeds = append(feeds, f)
			}
		}
		classes = append(classes, policy.ClassSpec{
			Name: c.Name, Feeds: feeds, Action: action, RedirectTo: addrs,
		})
	}

	policies, err := policy.Compile(specs, classes)
	return policies, warnings, err
}
