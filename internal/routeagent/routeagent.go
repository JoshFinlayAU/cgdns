// Package routeagent installs a small, explicitly allowed set of BGP-learned
// routes into the kernel.
//
// gobgpd is a BGP speaker: it will hold a learned route in its RIB and never
// put it in the forwarding table. That is fine for advertising an anycast
// address, which is all the resolver needs, but it means a node cannot use a
// default route its upstream is offering — it keeps whatever static route it
// was configured with, including when that next hop is gone.
//
// This agent closes that gap without adopting a full routing suite. It is
// deliberately narrow:
//
//   - It installs only prefixes on an explicit allow list, matched exactly.
//     The upstream router filters what it sends and gobgp filters what it
//     accepts; this is the third filter, and the only one that is not
//     someone else's configuration to get wrong.
//   - It installs at most MaxRoutes, so a policy failure upstream cannot turn
//     into a full table in the kernel.
//   - It only ever deletes routes it installed, identified by their protocol.
//
// It runs as its own daemon because installing routes needs CAP_NET_ADMIN, and
// the process answering internet queries should not also be able to reconfigure
// the network.
package routeagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	apipb "github.com/osrg/gobgp/v4/api"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Metrics counts what the agent has done.
type Metrics struct {
	Installed atomic.Uint64
	Removed   atomic.Uint64
	// Rejected counts learned prefixes that were not on the allow list. A
	// non-zero value means an upstream filter is looser than it should be.
	Rejected atomic.Uint64
	// Errors counts reconciliations that failed.
	Errors atomic.Uint64
	// Current is how many routes the agent holds in the kernel now.
	Current atomic.Int64
}

// Options configures the agent.
type Options struct {
	// Target is the gobgpd gRPC endpoint.
	Target string

	// Accept lists the prefixes that may be installed, matched exactly. A
	// default route is the usual case; a sibling's loopback is the other.
	Accept []netip.Prefix

	// MaxRoutes bounds how many routes may be held at once.
	MaxRoutes int

	// Table is the kernel routing table to install into. Zero means main.
	Table int

	// SourceV4 and SourceV6 are the preferred source addresses stamped on
	// installed routes.
	//
	// They matter more than they look. A static default written by hand
	// usually carries one, and a learned route that wins without one silently
	// changes the address everything on the node egresses from — anything that
	// does not pin its own source moves from the loopback to whatever the
	// outgoing interface happens to hold.
	SourceV4 netip.Addr
	SourceV6 netip.Addr

	// Metric is the priority given to installed routes. It should be better
	// (lower) than any static fallback, so a learned route wins while it
	// exists and the static one takes over the moment it is withdrawn.
	Metric int

	// Interval is how often the RIB is reconciled against the kernel.
	//
	// This polls rather than streams. A default route changes rarely, and a
	// reconcile is idempotent: it repairs drift from anything that touched the
	// table behind us, which a stream of deltas would not.
	Interval time.Duration

	Log     *slog.Logger
	Metrics *Metrics
}

// Agent reconciles learned routes into the kernel.
type Agent struct {
	opts   Options
	conn   *grpc.ClientConn
	client apipb.GoBgpServiceClient

	// installed tracks what this agent put in the kernel, so it never removes
	// a route somebody else owns.
	installed map[netip.Prefix]netip.Addr
}

// protocol marks routes installed by this agent.
//
// RTPROT_BGP is the honest label — these are BGP routes — and it makes them
// identifiable in `ip route` and impossible to confuse with the kernel's own
// or with a static one from netplan.
const protocol = unix.RTPROT_BGP

// New builds an agent and connects to gobgpd.
func New(ctx context.Context, opts Options) (*Agent, error) {
	if opts.Target == "" {
		return nil, errors.New("routeagent: a gobgpd target is required")
	}
	if len(opts.Accept) == 0 {
		return nil, errors.New("routeagent: an accept list is required; this agent installs nothing without one")
	}
	if opts.MaxRoutes <= 0 {
		opts.MaxRoutes = 16
	}
	if opts.Metric <= 0 {
		opts.Metric = 5
	}
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}

	conn, err := grpc.NewClient(opts.Target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("routeagent: connecting to gobgpd at %s: %w", opts.Target, err)
	}

	a := &Agent{
		opts:      opts,
		conn:      conn,
		client:    apipb.NewGoBgpServiceClient(conn),
		installed: map[netip.Prefix]netip.Addr{},
	}

	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := a.client.GetBgp(probe, &apipb.GetBgpRequest{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("routeagent: gobgpd at %s is not answering: %w", opts.Target, err)
	}
	return a, nil
}

// Close releases the connection and removes the routes this agent installed.
//
// They go rather than linger: whatever static fallback the node was configured
// with should take over the moment this agent stops maintaining its view, not
// sit behind a route nobody is checking any more.
func (a *Agent) Close() error {
	for p := range a.installed {
		if err := a.remove(p); err != nil {
			a.opts.Log.Warn("removing route on shutdown failed",
				slog.String("prefix", p.String()), slog.String("err", err.Error()))
		}
	}
	return a.conn.Close()
}

// Run reconciles until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.opts.Log.Info("route agent started",
		slog.String("gobgp", a.opts.Target),
		slog.Any("accept", prefixStrings(a.opts.Accept)),
		slog.Int("max_routes", a.opts.MaxRoutes),
		slog.Int("metric", a.opts.Metric))

	t := time.NewTicker(a.opts.Interval)
	defer t.Stop()

	a.reconcileOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			a.reconcileOnce(ctx)
		}
	}
}

func (a *Agent) reconcileOnce(ctx context.Context) {
	desired, err := a.learned(ctx)
	if err != nil {
		a.opts.Metrics.Errors.Add(1)
		a.opts.Log.Warn("reading the gobgp RIB failed; leaving the kernel as it is",
			slog.String("err", err.Error()))
		return
	}
	if err := a.apply(desired); err != nil {
		a.opts.Metrics.Errors.Add(1)
		a.opts.Log.Warn("applying routes failed", slog.String("err", err.Error()))
	}
}

// learned returns the allowed prefixes gobgp currently holds, with next hops.
func (a *Agent) learned(ctx context.Context) (map[netip.Prefix]netip.Addr, error) {
	out := make(map[netip.Prefix]netip.Addr)

	for _, family := range []*apipb.Family{
		{Afi: apipb.Family_AFI_IP, Safi: apipb.Family_SAFI_UNICAST},
		{Afi: apipb.Family_AFI_IP6, Safi: apipb.Family_SAFI_UNICAST},
	} {
		stream, err := a.client.ListPath(ctx, &apipb.ListPathRequest{
			TableType: apipb.TableType_TABLE_TYPE_GLOBAL,
			Family:    family,
		})
		if err != nil {
			return nil, err
		}
		for {
			r, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			prefix, nexthop, ok := pathOf(r.GetDestination())
			if !ok {
				continue
			}
			if !a.allowed(prefix) {
				a.opts.Metrics.Rejected.Add(1)
				continue
			}
			out[prefix] = nexthop
		}
	}

	if len(out) > a.opts.MaxRoutes {
		// Refusing wholesale is the safe answer: something upstream is sending
		// far more than this agent was told to expect, and installing an
		// arbitrary subset would be worse than installing none.
		return nil, fmt.Errorf("routeagent: %d allowed routes exceeds max_routes %d", len(out), a.opts.MaxRoutes)
	}
	return out, nil
}

// allowed reports whether a prefix is on the allow list, matched exactly.
//
// Exact rather than containment: "accept a default route" must not silently
// also accept every more-specific route inside it.
func (a *Agent) allowed(p netip.Prefix) bool {
	for _, want := range a.opts.Accept {
		if want == p {
			return true
		}
	}
	return false
}

// pathOf extracts the prefix and next hop from a destination.
//
// A locally originated path is skipped: those are the node's own anycast and
// loopback advertisements, and installing a route to ourselves would be at
// best pointless.
func pathOf(dst *apipb.Destination) (netip.Prefix, netip.Addr, bool) {
	if dst == nil {
		return netip.Prefix{}, netip.Addr{}, false
	}
	prefix, err := netip.ParsePrefix(dst.GetPrefix())
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, false
	}

	for _, path := range dst.GetPaths() {
		if path.GetIsFromExternal() == false && path.GetSourceAsn() == 0 {
			// Locally originated.
			continue
		}
		for _, attr := range path.GetPattrs() {
			nh := attr.GetNextHop()
			if nh == nil {
				continue
			}
			addr, err := netip.ParseAddr(nh.GetNextHop())
			if err != nil || addr.IsUnspecified() {
				continue
			}
			return prefix, addr, true
		}
	}
	return netip.Prefix{}, netip.Addr{}, false
}

// apply makes the kernel match desired.
func (a *Agent) apply(desired map[netip.Prefix]netip.Addr) error {
	var firstErr error

	for p, nh := range desired {
		if have, ok := a.installed[p]; ok && have == nh {
			continue
		}
		if err := a.install(p, nh); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		a.installed[p] = nh
		a.opts.Metrics.Installed.Add(1)
		a.opts.Log.Info("installed a learned route",
			slog.String("prefix", p.String()), slog.String("via", nh.String()))
	}

	for p := range a.installed {
		if _, ok := desired[p]; ok {
			continue
		}
		if err := a.remove(p); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		delete(a.installed, p)
		a.opts.Metrics.Removed.Add(1)
		a.opts.Log.Info("removed a withdrawn route", slog.String("prefix", p.String()))
	}

	a.opts.Metrics.Current.Store(int64(len(a.installed)))
	return firstErr
}

func (a *Agent) install(p netip.Prefix, nh netip.Addr) error {
	if p.Addr().Is4() != nh.Is4() {
		return fmt.Errorf("routeagent: next hop %s does not match the family of %s", nh, p)
	}
	route := a.routeFor(p, nh)
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("routeagent: installing %s via %s: %w", p, nh, err)
	}
	return nil
}

func (a *Agent) remove(p netip.Prefix) error {
	nh, ok := a.installed[p]
	if !ok {
		return nil
	}
	if err := netlink.RouteDel(a.routeFor(p, nh)); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("routeagent: removing %s: %w", p, err)
	}
	return nil
}

func (a *Agent) routeFor(p netip.Prefix, nh netip.Addr) *netlink.Route {
	r := &netlink.Route{
		Dst:      prefixToIPNet(p),
		Gw:       net.IP(nh.AsSlice()),
		Protocol: protocol,
		Priority: a.opts.Metric,
		Table:    a.opts.Table,
	}
	if src := a.sourceFor(p); src.IsValid() {
		r.Src = net.IP(src.AsSlice())
	}
	return r
}

// sourceFor returns the preferred source for a route's family.
func (a *Agent) sourceFor(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		return a.opts.SourceV4
	}
	return a.opts.SourceV6
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	bits := 32
	if p.Addr().Is6() {
		bits = 128
	}
	return &net.IPNet{
		IP:   net.IP(p.Addr().AsSlice()),
		Mask: net.CIDRMask(p.Bits(), bits),
	}
}

func prefixStrings(in []netip.Prefix) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.String())
	}
	return out
}
