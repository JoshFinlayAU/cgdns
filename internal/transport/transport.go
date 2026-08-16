// Package transport owns the client-facing listeners. It gets bytes off the
// wire, turns them into a well-formed question, hands that to a Handler and
// writes the answer back. Resolution policy lives behind Handler.
//
// Two rules shape it:
//
//   - Packet handling may never panic out. Everything on the wire is
//     attacker-controlled, so each packet runs under a recover: count, SERVFAIL,
//     keep serving.
//   - Sockets bind explicit addresses, never a wildcard. A wildcard PacketConn
//     does not know which local address a datagram arrived on, so replies can
//     leave with the wrong source IP — which breaks anycast only under load.
package transport

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Proto identifies which listener a query arrived on.
type Proto uint8

const (
	ProtoUDP Proto = iota
	ProtoTCP
	ProtoDoT
	ProtoDoH
)

// String implements fmt.Stringer.
func (p Proto) String() string {
	switch p {
	case ProtoUDP:
		return "udp"
	case ProtoTCP:
		return "tcp"
	case ProtoDoT:
		return "dot"
	case ProtoDoH:
		return "doh"
	default:
		return "unknown"
	}
}

// Request is one client query with the context a resolver needs to answer it.
type Request struct {
	// Msg is the parsed query. It may be pooled and must not be retained past
	// the ServeDNS call.
	Msg *dns.Msg
	// Client is the source address, used for subscriber classification.
	Client netip.AddrPort
	// Local is the address the query arrived on, and under anycast the address
	// the reply must be sourced from.
	Local netip.Addr
	// Proto is the listener that received it.
	Proto Proto
	// Received is when the packet came off the wire. The client budget runs
	// from here, not from when a worker picked it up.
	Received time.Time
	// MaxResponseSize is the largest response the client will accept, already
	// resolved from EDNS0 and the transport.
	MaxResponseSize int
}

// Handler answers queries. Returning nil drops the query silently, as opposed
// to answering with an error rcode.
type Handler interface {
	ServeDNS(ctx context.Context, req *Request) *dns.Msg
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, req *Request) *dns.Msg

// ServeDNS implements Handler.
func (f HandlerFunc) ServeDNS(ctx context.Context, req *Request) *dns.Msg { return f(ctx, req) }

// Metrics counts transport-level events.
type Metrics struct {
	Queries     atomic.Uint64
	ParseErrors atomic.Uint64
	Panics      atomic.Uint64
	Truncated   atomic.Uint64
	WriteErrors atomic.Uint64
	Dropped     atomic.Uint64
	TCPAccepted atomic.Uint64
	TCPRefused  atomic.Uint64
}

// minUDPSize is the largest response we may send to a client that offered no
// EDNS0 OPT record (RFC 1035 §4.2.1).
const minUDPSize = 512

// maxPacket is the read buffer size, larger than any datagram accepted so an
// oversized one is detected rather than silently cut.
const maxPacket = 4096

// responseSizeFor resolves how many bytes the client will accept, clamping its
// EDNS0 advertisement to the operator's ceiling to limit fragmentation and
// reflection amplification.
func responseSizeFor(msg *dns.Msg, proto Proto, limit uint16) int {
	if proto != ProtoUDP {
		return dns.MaxMsgSize
	}
	opt := msg.IsEdns0()
	if opt == nil {
		return minUDPSize
	}
	size := opt.UDPSize()
	if size < minUDPSize {
		size = minUDPSize
	}
	if size > limit {
		size = limit
	}
	return int(size)
}

// errorResponse builds a bare failure reply. Used on panic recovery, so it
// must not itself be able to fail.
func errorResponse(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	resp.AuthenticatedData = false
	return resp
}

// refusedResponse answers a query declined outright, e.g. from a client
// outside the ACL.
func refusedResponse(req *dns.Msg) *dns.Msg { return errorResponse(req, dns.RcodeRefused) }
