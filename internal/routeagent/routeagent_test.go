package routeagent

import (
	"net/netip"
	"testing"
)

func prefixes(t *testing.T, in ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// The allow list is the last filter before the kernel, and the only one that is
// not somebody else's configuration to get wrong.
func TestAllowed_MatchesExactlyAndNothingElse(t *testing.T) {
	a := &Agent{opts: Options{Accept: prefixes(t, "0.0.0.0/0", "::/0", "10.255.0.1/32")}}

	for _, p := range []string{"0.0.0.0/0", "::/0", "10.255.0.1/32"} {
		if !a.allowed(netip.MustParsePrefix(p)) {
			t.Fatalf("%s is on the allow list but was refused", p)
		}
	}

	// Accepting a default must not accept the routes inside it. A router that
	// leaked a full table would otherwise be installed one prefix at a time.
	for _, p := range []string{
		"10.0.0.0/8", "192.0.2.0/24", "0.0.0.0/1", "128.0.0.0/1",
		"10.255.0.1/31", "10.255.0.2/32", "2001:db8::/32",
	} {
		if a.allowed(netip.MustParsePrefix(p)) {
			t.Fatalf("%s is not on the allow list but was accepted", p)
		}
	}
}

func TestPrefixToIPNet(t *testing.T) {
	for _, tc := range []struct{ prefix, want string }{
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"10.255.0.1/32", "10.255.0.1/32"},
		{"::/0", "::/0"},
		{"fd51:13::1/128", "fd51:13::1/128"},
	} {
		got := prefixToIPNet(netip.MustParsePrefix(tc.prefix))
		if got.String() != tc.want {
			t.Fatalf("%s -> %s, want %s", tc.prefix, got, tc.want)
		}
	}
}

// A v6 next hop cannot carry a v4 route. Handing that to the kernel would be a
// confusing failure at best.
func TestInstall_RefusesAMismatchedNextHopFamily(t *testing.T) {
	a := &Agent{opts: Options{Accept: prefixes(t, "0.0.0.0/0"), Metric: 5}}
	err := a.install(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("fd51:13::3"))
	if err == nil {
		t.Fatal("a v6 next hop was accepted for a v4 route")
	}
}

// The agent must never remove a route it did not install, even if asked.
func TestRemove_IgnoresRoutesItDoesNotOwn(t *testing.T) {
	a := &Agent{
		opts:      Options{Accept: prefixes(t, "0.0.0.0/0")},
		installed: map[netip.Prefix]netip.Addr{},
	}
	// Nothing tracked, so this must be a no-op rather than a netlink call that
	// deletes somebody else's default route.
	if err := a.remove(netip.MustParsePrefix("0.0.0.0/0")); err != nil {
		t.Fatalf("removing an untracked route returned %v", err)
	}
}

func TestRouteFor_CarriesTheAgentsMarkings(t *testing.T) {
	a := &Agent{opts: Options{Metric: 5, Table: 100}}
	r := a.routeFor(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("10.255.255.3"))

	if r.Protocol != protocol {
		t.Fatalf("protocol is %v, want RTPROT_BGP so the route is identifiable", r.Protocol)
	}
	if r.Priority != 5 {
		t.Fatalf("metric is %d, want the configured 5", r.Priority)
	}
	if r.Table != 100 {
		t.Fatalf("table is %d, want the configured 100", r.Table)
	}
	if r.Gw.String() != "10.255.255.3" {
		t.Fatalf("gateway is %s", r.Gw)
	}
}

func TestNew_RequiresAnAcceptList(t *testing.T) {
	// Building without one must fail rather than default to accepting
	// everything or nothing silently.
	if _, err := New(t.Context(), Options{Target: "127.0.0.1:1"}); err == nil {
		t.Fatal("an agent was built with no accept list")
	}
	if _, err := New(t.Context(), Options{Accept: prefixes(t, "0.0.0.0/0")}); err == nil {
		t.Fatal("an agent was built with no gobgpd target")
	}
}

// A static default written by hand usually pins a source. A learned route that
// wins without one silently moves the node's egress address to whatever the
// outgoing interface holds, which is a change nobody asked for.
func TestRouteFor_StampsThePreferredSource(t *testing.T) {
	a := &Agent{opts: Options{
		Metric:   5,
		SourceV4: netip.MustParseAddr("10.255.0.2"),
		SourceV6: netip.MustParseAddr("fd51:13::2"),
	}}

	v4 := a.routeFor(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("10.255.255.3"))
	if v4.Src == nil || v4.Src.String() != "10.255.0.2" {
		t.Fatalf("v4 source is %v, want the configured loopback", v4.Src)
	}
	v6 := a.routeFor(netip.MustParsePrefix("::/0"), netip.MustParseAddr("fd51:13:1::3"))
	if v6.Src == nil || v6.Src.String() != "fd51:13::2" {
		t.Fatalf("v6 source is %v, want the configured loopback", v6.Src)
	}

	// Unset means unset: the kernel keeps its own choice rather than being
	// handed a zero address.
	none := &Agent{opts: Options{Metric: 5}}
	if r := none.routeFor(netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("10.255.255.3")); r.Src != nil {
		t.Fatalf("an unconfigured source produced %v", r.Src)
	}
}
