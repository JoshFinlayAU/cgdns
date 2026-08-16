package resolver

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// OutboundSource pins the local address recursion and forwarding leave from.
//
// Anycast makes this matter. A node's service address is shared with its
// siblings, so an outbound query sourced from it invites the reply back to
// whichever node the return path happens to pick — which may not be the one
// waiting for it. Pinning egress to an address unique to this node keeps the
// reply coming home, and gives the operator one address to permit through
// upstream filters.
//
// Leaving a family unset keeps the kernel's own choice, which is correct on a
// node whose egress address is already unambiguous.
type OutboundSource struct {
	V4 netip.Addr
	V6 netip.Addr
}

// clientSet holds the per-family clients an outbound source requires.
//
// One client cannot serve both families: a dialer carries a single local
// address, and binding a v4 source for a v6 destination fails.
type clientSet struct {
	any *dns.Client
	v4  *dns.Client
	v6  *dns.Client
}

// forAddr picks the client whose source matches the destination family.
func (c clientSet) forAddr(server netip.Addr) *dns.Client {
	if server.Is4() || server.Is4In6() {
		if c.v4 != nil {
			return c.v4
		}
		return c.any
	}
	if c.v6 != nil {
		return c.v6
	}
	return c.any
}

// newClientSet builds the clients for one transport.
func newClientSet(network string, timeout time.Duration, udpSize uint16, src OutboundSource) clientSet {
	base := func() *dns.Client {
		c := &dns.Client{Net: network, Timeout: timeout}
		if network == "udp" {
			c.UDPSize = udpSize
		}
		return c
	}

	set := clientSet{any: base()}
	if src.V4.IsValid() {
		set.v4 = base()
		set.v4.Dialer = &net.Dialer{Timeout: timeout, LocalAddr: localAddr(network, src.V4)}
	}
	if src.V6.IsValid() {
		set.v6 = base()
		set.v6.Dialer = &net.Dialer{Timeout: timeout, LocalAddr: localAddr(network, src.V6)}
	}
	return set
}

// localAddr builds the dialer's local address for a transport. Port zero lets
// the kernel choose, which is what keeps source ports random — a fixed port
// would make off-path spoofing dramatically easier.
func localAddr(network string, addr netip.Addr) net.Addr {
	if network == "tcp" {
		return &net.TCPAddr{IP: addr.AsSlice()}
	}
	return &net.UDPAddr{IP: addr.AsSlice()}
}

// verifySource fails startup when a configured source cannot be bound.
//
// A typo here would otherwise surface as every outbound query failing once
// traffic arrives, on a node anycast has already routed subscribers to. Binding
// once at startup turns that into a refusal to start, which is the project's
// bargain everywhere else in the config.
func verifySource(field string, addr netip.Addr) error {
	if !addr.IsValid() {
		return nil
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: addr.AsSlice()})
	if err != nil {
		return fmt.Errorf("%s: cannot bind %s on this node: %w", field, addr, err)
	}
	return conn.Close()
}

// Verify checks both families.
func (s OutboundSource) Verify() error {
	if err := verifySource("resolver.outbound_source_v4", s.V4); err != nil {
		return err
	}
	return verifySource("resolver.outbound_source_v6", s.V6)
}
