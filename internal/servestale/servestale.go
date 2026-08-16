// Package servestale answers from expired cache data when resolution fails
// (RFC 8767).
//
// The case it exists for is an authoritative that has gone away — DDoSed, badly
// delegated, or simply broken. Without it every subscriber for that zone gets
// SERVFAIL and the domain is down for them, even though we hold a perfectly
// usable answer that expired minutes ago. Answering slightly old data beats
// answering nothing.
//
// It never competes with a working authoritative. A live cache entry is served
// by the normal path, and a successful resolution is always preferred; stale
// data is consulted only once resolution has already failed.
package servestale

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// Metrics counts stale answers.
type Metrics struct {
	// Served counts responses answered from expired data.
	Served atomic.Uint64
	// Eligible counts failures where stale was consulted at all.
	Eligible atomic.Uint64
	// Unavailable counts failures with nothing stale to fall back to.
	Unavailable atomic.Uint64
}

// Cache is the subset of the RRset cache this needs. Defined here rather than
// in the cache package because this is the consumer.
type Cache interface {
	GetStale(k cache.Key) (cache.Entry, bool)
}

// Handler serves stale data when the next handler fails.
type Handler struct {
	next      transport.Handler
	cache     Cache
	answerTTL time.Duration
	log       *slog.Logger
	metrics   *Metrics
}

var _ transport.Handler = (*Handler)(nil)

// Options configures the decorator.
type Options struct {
	Next  transport.Handler
	Cache Cache
	// AnswerTTL is the TTL stamped on a stale answer. RFC 8767 recommends a
	// short one (30s): the client should come back soon, because by then the
	// authoritative may have recovered.
	AnswerTTL time.Duration
	Log       *slog.Logger
	Metrics   *Metrics
}

// New wraps next with serve-stale.
func New(opts Options) *Handler {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.AnswerTTL <= 0 {
		opts.AnswerTTL = 30 * time.Second
	}
	return &Handler{
		next:      opts.Next,
		cache:     opts.Cache,
		answerTTL: opts.AnswerTTL,
		log:       opts.Log,
		metrics:   opts.Metrics,
	}
}

// ServeDNS implements transport.Handler.
func (h *Handler) ServeDNS(ctx context.Context, req *transport.Request) *dns.Msg {
	resp := h.next.ServeDNS(ctx, req)
	if !h.failed(resp) || len(req.Msg.Question) != 1 {
		return resp
	}

	h.metrics.Eligible.Add(1)

	q := req.Msg.Question[0]
	entry, ok := h.cache.GetStale(cache.NewKey(q.Name, q.Qtype, q.Qclass))
	if !ok {
		h.metrics.Unavailable.Add(1)
		return resp
	}

	stale := h.answer(req.Msg, entry)
	h.metrics.Served.Add(1)
	return stale
}

// failed reports whether the resolver gave up.
//
// Only SERVFAIL counts. NXDOMAIN and NODATA are answers — the authoritative was
// reached and said no — and overriding them with stale data would resurrect
// names their owner has deliberately removed.
func (h *Handler) failed(resp *dns.Msg) bool {
	return resp == nil || resp.Rcode == dns.RcodeServerFailure
}

// answer builds the stale response.
func (h *Handler) answer(req *dns.Msg, e cache.Entry) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = e.Rcode

	switch e.Kind {
	case cache.KindAnswer:
		m.Answer = cache.StaleRRs(e, h.answerTTL)
	case cache.KindNegative:
		m.Ns = cache.StaleRRs(e, h.answerTTL)
	}

	// AD is never set on a stale answer, whatever the entry recorded. The
	// signatures are as old as the data and may well have expired, so claiming
	// the chain validated would be a claim we cannot stand behind.
	m.AuthenticatedData = false

	setEDE(m, dns.ExtendedErrorCodeStaleAnswer, "answering from expired cache: the authoritative could not be reached")
	return m
}

// setEDE attaches an RFC 8914 extended error, so a client can tell a stale
// answer from a fresh one rather than having to guess why the TTL is short.
func setEDE(m *dns.Msg, code uint16, text string) {
	opt := m.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(dns.DefaultMsgSize)
		m.Extra = append(m.Extra, opt)
	}
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{
		InfoCode:  code,
		ExtraText: text,
	})
}
