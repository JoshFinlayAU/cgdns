package control

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sort"
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
	// refresh carries a request to recompile without the store having moved.
	refresh chan struct{}
	// feedPath resolves a feed name to the file the fetcher wrote, for records
	// that name no file of their own.
	feedPath func(string) string

	store      *Store
	classifier *subscriber.Classifier
	registry   *policy.Registry
	log        *slog.Logger

	published atomic.Uint64
	failures  atomic.Uint64
}

// PublisherOptions configures a Publisher.
type PublisherOptions struct {
	Store *Store
	// FeedPath resolves a feed name to locally fetched content.
	FeedPath   func(string) string
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
		refresh:    make(chan struct{}, 1),
		feedPath:   opts.FeedPath,
	}
}

// Run publishes on every state change until ctx is cancelled.
func (p *Publisher) Run(ctx context.Context) {
	stop := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stop)
	}()

	// A store change and a feed refresh both mean "recompile", but only the
	// first moves the version. Watching the store in its own goroutine lets one
	// loop serve both without either having to poll.
	changes := make(chan uint64, 1)
	go func() {
		var known uint64
		for {
			version := p.store.WaitForChange(known, stop)
			if ctx.Err() != nil {
				return
			}
			if version == known {
				continue
			}
			known = version
			select {
			case changes <- version:
			default:
			}
		}
	}()

	// Publish once up front so a node that just loaded its store from disk
	// serves that policy without waiting for the next write.
	p.publish()

	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
			p.publish()
		case <-p.refresh:
			p.publish()
		}
	}
}

// Republish recompiles and swaps in the current state.
//
// It exists because feed content can change without the control store moving:
// the record naming a feed is unchanged, but the file behind it now holds
// different rules. It never blocks — a refresh already queued is enough.
func (p *Publisher) Republish() {
	select {
	case p.refresh <- struct{}{}:
	default:
	}
}

// PublishedVersion reports the last state version successfully published.
func (p *Publisher) PublishedVersion() uint64 { return p.published.Load() }

// Failures reports how many rebuilds were abandoned.
func (p *Publisher) Failures() uint64 { return p.failures.Load() }

// publish rebuilds and swaps the query-path structures.
func (p *Publisher) publish() {
	state, version := p.store.State()

	for _, r := range state.Rejected() {
		p.log.Error("control record rejected and not in force", slog.String("detail", r))
	}

	entries, err := subscriberEntries(state)
	if err != nil {
		p.failures.Add(1)
		p.log.Error("keeping previous subscriber table; the new one did not compile",
			slog.Uint64("version", version), slog.String("err", err.Error()))
		return
	}

	policies, mandatory, warnings, err := compilePolicies(state, p.feedPath)
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
		p.registry.ReplaceMandatory(mandatory)
	}
	p.published.Store(version)

	p.log.Info("published control-plane state",
		slog.Uint64("version", version),
		slog.Int("prefixes", len(entries)),
		slog.Int("classes", len(policies)),
		slog.Int("subscribers_with_overrides", len(overrides)),
		slog.Int("mandatory_rules", mandatoryLen(mandatory)))
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
func compilePolicies(state *State, feedPath func(string) string) (map[string]*policy.Policy, *policy.Policy, []string, error) {
	var (
		specs     []policy.FeedSpec
		warnings  []string
		usable    = map[string]bool{}
		mandatory []string
	)
	for _, f := range state.Feeds() {
		entries, err := managedEntries(f)
		if err != nil {
			return nil, nil, warnings, err
		}

		file := f.File
		if file == "" && feedPath != nil {
			// No explicit file, so use whatever the fetcher put on disk for it.
			file = feedPath(f.Name)
		}
		if file != "" {
			if _, err := os.Stat(file); err != nil {
				// A list kept here and never fetched has no file, and saying so
				// every rebuild would train an operator to ignore the warning
				// that matters: a feed that should have content and has none.
				if f.URL != "" || !f.Managed {
					warnings = append(warnings, fmt.Sprintf("feed %q content %q is not readable: %v", f.Name, file, err))
				}
				file = ""
			}
		}
		// A list maintained here has its entries even before anything has been
		// fetched for it, which is what makes a compliance list usable the
		// moment it is written rather than at the next refresh.
		if file == "" && len(entries) == 0 {
			if !f.Managed {
				warnings = append(warnings, fmt.Sprintf("feed %q has no local content on this node yet", f.Name))
			}
			continue
		}
		specs = append(specs, policy.FeedSpec{
			Name: f.Name, Format: f.Format, File: file, RPZZone: f.RPZZone, Entries: entries,
		})
		usable[f.Name] = true
		if f.Mandatory {
			mandatory = append(mandatory, f.Name)
		}
	}

	// The mandatory tier is compiled as a class of its own so it goes through
	// the same path as everything else, then held separately by the registry
	// because it is consulted before any subscriber's own lists.
	classes := make([]policy.ClassSpec, 0, len(state.Classes())+1)
	if len(mandatory) > 0 {
		sort.Strings(mandatory)
		classes = append(classes, policy.ClassSpec{
			Name: mandatoryClass, Feeds: mandatory, Action: policy.ActionNXDOMAIN,
		})
	}
	for _, c := range state.Classes() {
		action, err := policy.ParseAction(c.Action)
		if err != nil {
			return nil, nil, warnings, fmt.Errorf("class %q: %w", c.Name, err)
		}
		addrs := make([]netip.Addr, 0, len(c.RedirectTo))
		for _, a := range c.RedirectTo {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				return nil, nil, warnings, fmt.Errorf("class %q redirect_to %q: %w", c.Name, a, err)
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
	if err != nil {
		return nil, nil, warnings, err
	}
	forced := policies[mandatoryClass]
	delete(policies, mandatoryClass)
	return policies, forced, warnings, nil
}

// mandatoryClass names the internal class the mandatory tier is compiled as. It
// is not a class an operator can assign — the store lowercases class names and
// this one cannot be typed.
const mandatoryClass = "\x00mandatory"

func mandatoryLen(p *policy.Policy) int {
	if p == nil || p.Rules == nil {
		return 0
	}
	return p.Rules.Len()
}

// managedEntries converts a hand-maintained list's records into rules.
func managedEntries(f FeedRecord) ([]policy.Entry, error) {
	if len(f.Entries) == 0 {
		return nil, nil
	}
	out := make([]policy.Entry, 0, len(f.Entries))
	for _, e := range f.Entries {
		action, err := policy.ParseAction(e.Action)
		if err != nil {
			return nil, fmt.Errorf("feed %q entry %q: %w", f.Name, e.Name, err)
		}
		addrs := make([]netip.Addr, 0, len(e.To))
		for _, a := range e.To {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				return nil, fmt.Errorf("feed %q entry %q redirects to %q: %w", f.Name, e.Name, a, err)
			}
			addrs = append(addrs, addr)
		}
		out = append(out, policy.Entry{Name: e.Name, Action: action, To: addrs})
	}
	return out, nil
}
