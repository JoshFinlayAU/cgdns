package ratelimit

import (
	"context"
	"log/slog"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/netacl"
	"github.com/JoshFinlayAU/cgdns/internal/privacy"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// Handler applies response rate limiting around a resolver.
type Handler struct {
	limiter *Limiter
	next    transport.Handler
	exempt  *netacl.ACL
	log     *slog.Logger
	metrics *Metrics
	now     func() time.Time
}

var _ transport.Handler = (*Handler)(nil)

// HandlerOptions configures the decorator.
type HandlerOptions struct {
	Limiter *Limiter
	Next    transport.Handler
	// Exempt lists clients that are never limited. It is a plain allow list,
	// so an empty ACL exempts nobody.
	Exempt  *netacl.ACL
	Log     *slog.Logger
	Metrics *Metrics
	Now     func() time.Time
}

// NewHandler wraps next with rate limiting.
func NewHandler(opts HandlerOptions) *Handler {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Handler{
		limiter: opts.Limiter,
		next:    opts.Next,
		exempt:  opts.Exempt,
		log:     opts.Log,
		metrics: opts.Metrics,
		now:     opts.Now,
	}
}

// ServeDNS implements transport.Handler.
//
// The decision is made on the response, after resolution, because the response
// is what carries the amplification and what identifies the zone a flood is
// aimed at. Limiting the query instead would mean guessing at both.
func (h *Handler) ServeDNS(ctx context.Context, req *transport.Request) *dns.Msg {
	resp := h.next.ServeDNS(ctx, req)
	if resp == nil {
		return nil
	}

	// Only UDP can be spoofed or reflected. Everything else completed a
	// handshake, so limiting it would punish a client that is provably real.
	if req.Proto != transport.ProtoUDP {
		return resp
	}
	if h.exempt != nil && h.exempt.Allows(req.Client.Addr()) {
		h.metrics.Exempted.Add(1)
		return resp
	}

	key := h.keyFor(req, resp)
	switch h.limiter.Allow(key, h.now()) {
	case ActionAllow:
		return resp
	case ActionSlip:
		return truncatedResponse(req.Msg)
	default:
		// Logged at debug: under a flood this fires per packet, and the whole
		// point is to spend less work per packet, not more.
		h.log.Debug("response rate limited",
			slog.String("client_prefix", key.Prefix.String()),
			slog.String("class", key.Class.String()),
			slog.String("name", privacy.Redact(key.Name)))
		return nil
	}
}

// keyFor classifies a response into the bucket it counts against.
func (h *Handler) keyFor(req *transport.Request, resp *dns.Msg) Key {
	key := Key{Prefix: h.limiter.Mask(req.Client.Addr())}

	switch {
	case resp.Rcode == dns.RcodeNameError, isNoData(resp):
		// Group by the zone that denied it, never by the QNAME. A
		// random-subdomain flood produces a fresh QNAME per query, so keying
		// on it would give every query a private bucket and limit nothing —
		// which is precisely the attack this exists to stop.
		key.Class = ClassDenial
		key.Name = denialZone(req, resp)

	case resp.Rcode != dns.RcodeSuccess:
		// Errors carry no zone worth trusting, so they collapse per client.
		key.Class = ClassError

	default:
		key.Class = ClassAnswer
		if len(req.Msg.Question) == 1 {
			key.Name = req.Msg.Question[0].Name
			key.Type = req.Msg.Question[0].Qtype
		}
	}
	return key
}

// isNoData reports a NOERROR response that carries no answer.
func isNoData(resp *dns.Msg) bool {
	return resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0
}

// denialZone finds the zone a denial came from.
//
// The SOA in the authority section names it directly, which is the whole reason
// a flood collapses into one bucket. Without one, fall back to the QNAME with
// its leftmost label removed: for random1.victim.com that is still victim.com,
// so the grouping survives a response that arrives without an SOA.
func denialZone(req *transport.Request, resp *dns.Msg) string {
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Hdr.Name
		}
	}
	if len(req.Msg.Question) != 1 {
		return "."
	}
	name := req.Msg.Question[0].Name
	if _, after, found := cutLabel(name); found {
		return after
	}
	return name
}

// cutLabel splits the leftmost label from a name.
func cutLabel(name string) (label, rest string, found bool) {
	if name == "" || name == "." {
		return "", ".", false
	}
	i := 0
	for i < len(name) {
		if name[i] == '\\' {
			i += 2
			continue
		}
		if name[i] == '.' {
			rest := name[i+1:]
			if rest == "" {
				// The name was a single label followed by the root dot, so
				// what remains is the root itself, not an empty name.
				rest = "."
			}
			return name[:i], rest, true
		}
		i++
	}
	return name, ".", false
}

// truncatedResponse builds the empty TC=1 reply a slip sends, so a legitimate
// client retries over TCP where it is not limited.
func truncatedResponse(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Truncated = true
	m.Answer = nil
	m.Ns = nil
	m.Extra = nil
	return m
}
