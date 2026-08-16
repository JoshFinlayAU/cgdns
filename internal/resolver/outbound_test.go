package resolver

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestClientSet_PicksTheMatchingFamily(t *testing.T) {
	src := OutboundSource{
		V4: netip.MustParseAddr("127.0.0.1"),
		V6: netip.MustParseAddr("::1"),
	}
	set := newClientSet("udp", time.Second, 1232, src)

	if set.v4 == nil || set.v6 == nil {
		t.Fatal("both families should have their own client when both sources are set")
	}
	if got := set.forAddr(netip.MustParseAddr("192.0.2.1")); got != set.v4 {
		t.Fatal("a v4 destination did not get the v4-sourced client")
	}
	if got := set.forAddr(netip.MustParseAddr("2001:db8::1")); got != set.v6 {
		t.Fatal("a v6 destination did not get the v6-sourced client")
	}
	// A v4-mapped v6 address is still IPv4 on the wire.
	if got := set.forAddr(netip.MustParseAddr("::ffff:192.0.2.1")); got != set.v4 {
		t.Fatal("a v4-mapped destination did not get the v4-sourced client")
	}
}

// A family with no source configured must fall back to letting the kernel
// choose, not to the other family's source, which would fail to bind.
func TestClientSet_UnsetFamilyFallsBack(t *testing.T) {
	set := newClientSet("udp", time.Second, 1232, OutboundSource{V4: netip.MustParseAddr("127.0.0.1")})

	if set.v6 != nil {
		t.Fatal("a v6 client was built with no v6 source")
	}
	if got := set.forAddr(netip.MustParseAddr("2001:db8::1")); got != set.any {
		t.Fatal("a v6 destination should use the unpinned client")
	}
	if got := set.forAddr(netip.MustParseAddr("192.0.2.1")); got != set.v4 {
		t.Fatal("a v4 destination should use the pinned client")
	}
}

func TestClientSet_NoSourceUsesOneClient(t *testing.T) {
	set := newClientSet("udp", time.Second, 1232, OutboundSource{})
	if set.v4 != nil || set.v6 != nil {
		t.Fatal("per-family clients were built with no source configured")
	}
	for _, dst := range []string{"192.0.2.1", "2001:db8::1"} {
		if got := set.forAddr(netip.MustParseAddr(dst)); got != set.any {
			t.Fatalf("%s did not use the unpinned client", dst)
		}
	}
}

// The source port must stay kernel-assigned. A fixed one would make off-path
// spoofing dramatically easier, since the attacker would only have to guess the
// query ID.
func TestLocalAddr_LeavesThePortToTheKernel(t *testing.T) {
	if a, ok := localAddr("udp", netip.MustParseAddr("127.0.0.1")).(*net.UDPAddr); !ok || a.Port != 0 {
		t.Fatalf("udp local addr = %v, want port 0", a)
	}
	if a, ok := localAddr("tcp", netip.MustParseAddr("127.0.0.1")).(*net.TCPAddr); !ok || a.Port != 0 {
		t.Fatalf("tcp local addr = %v, want port 0", a)
	}
}

// A source that cannot be bound must stop the daemon at startup rather than
// failing every query later, on a node anycast has already routed traffic to.
func TestOutboundSource_VerifyRejectsAnUnbindableAddress(t *testing.T) {
	src := OutboundSource{V4: netip.MustParseAddr("192.0.2.99")}
	err := src.Verify()
	if err == nil {
		t.Fatal("an address this node does not hold was accepted")
	}
	if !contains(err.Error(), "resolver.outbound_source_v4") {
		t.Fatalf("error does not name the field: %v", err)
	}
}

func TestOutboundSource_VerifyAcceptsLoopbackAndEmpty(t *testing.T) {
	if err := (OutboundSource{}).Verify(); err != nil {
		t.Fatalf("an unset source was rejected: %v", err)
	}
	src := OutboundSource{V4: netip.MustParseAddr("127.0.0.1"), V6: netip.MustParseAddr("::1")}
	if err := src.Verify(); err != nil {
		t.Fatalf("loopback sources were rejected: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
