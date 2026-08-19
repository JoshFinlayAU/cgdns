package policy

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/privacy"
	"github.com/JoshFinlayAU/cgdns/internal/subscriber"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// Metrics counts policy decisions.
type Metrics struct {
	Evaluated       atomic.Uint64
	Blocked         atomic.Uint64
	Redirected      atomic.Uint64
	Rewritten       atomic.Uint64
	Dropped         atomic.Uint64
	Passthru        atomic.Uint64
	OverrideAllowed atomic.Uint64
	OverrideBlocked atomic.Uint64
	// MandatoryApplied counts answers decided by the compliance tier. It is
	// reported separately because it is the number a regulator asks about.
	MandatoryApplied atomic.Uint64
}

// Enforcer applies subscriber policy in front of a resolver.
//
// Evaluation order is fixed and is the whole contract:
//
//  1. the mandatory rules, which nothing overrides;
//  2. the subscriber's own allow list, which beats everything below it;
//  3. the subscriber's own block list;
//  4. the feeds their class subscribes to.
//
// A subscriber unblocking a name they need must not require editing a shared
// feed, so their allow list is consulted before any class rule is considered.
//
// Above it sits the compliance tier, and the ordering there is the point: where
// a jurisdiction requires a name to be blocked or redirected, "the subscriber
// asked us not to" is not a defence, so a subscriber allow cannot reach it.
// Everything else here is built to make unblocking fast; this part deliberately
// is not.
type Enforcer struct {
	classifier *subscriber.Classifier
	registry   *Registry
	next       transport.Handler
	log        *slog.Logger
	metrics    *Metrics
}

var _ transport.Handler = (*Enforcer)(nil)

// Options configures an Enforcer.
type Options struct {
	Classifier *subscriber.Classifier
	Registry   *Registry
	Next       transport.Handler
	Log        *slog.Logger
	Metrics    *Metrics
}

// NewEnforcer builds an Enforcer.
func NewEnforcer(opts Options) *Enforcer {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	return &Enforcer{
		classifier: opts.Classifier,
		registry:   opts.Registry,
		next:       opts.Next,
		log:        opts.Log,
		metrics:    opts.Metrics,
	}
}

// ServeDNS implements transport.Handler.
func (e *Enforcer) ServeDNS(ctx context.Context, req *transport.Request) *dns.Msg {
	if e.classifier == nil || e.registry == nil {
		return e.next.ServeDNS(ctx, req)
	}

	q := req.Msg.Question[0]
	sub := e.classifier.Classify(req.Client.Addr())
	e.metrics.Evaluated.Add(1)

	rule, matched := e.lookup(sub, q.Name)
	if !matched || rule.Action == ActionPassthru {
		if matched {
			e.metrics.Passthru.Add(1)
		}
		return e.next.ServeDNS(ctx, req)
	}

	e.log.Debug("policy applied",
		slog.String("action", rule.Action.String()),
		slog.String("feed", rule.Feed),
		slog.String("class", sub.Class),
		slog.String("qname", privacy.Redact(q.Name)))

	return e.apply(req, rule, sub)
}

// lookup resolves the rule for a subscriber, compliance first.
func (e *Enforcer) lookup(sub subscriber.Subscriber, qname string) (Rule, bool) {
	// Checked before anything a subscriber or an operator can set, and applied
	// even to a subscriber with no policy at all: a compliance obligation does
	// not depend on which product tier somebody bought.
	if m := e.registry.Mandatory(); m != nil {
		if r, ok := m.Rules.Match(qname); ok && r.Action != ActionPassthru {
			e.metrics.MandatoryApplied.Add(1)
			return r, true
		}
	}
	if ov := e.registry.OverridesFor(sub.ID); ov != nil {
		if r, ok := ov.Allow.Match(qname); ok {
			e.metrics.OverrideAllowed.Add(1)
			r.Action = ActionPassthru
			return r, true
		}
		if r, ok := ov.Block.Match(qname); ok {
			e.metrics.OverrideBlocked.Add(1)
			return r, true
		}
	}
	pol := e.registry.For(sub.Class)
	if pol == nil {
		return Rule{}, false
	}
	r, ok := pol.Rules.Match(qname)
	if !ok {
		return Rule{}, false
	}
	if r.Action == ActionRedirect && len(r.Addrs) == 0 {
		r.Addrs = pol.RedirectTo
	}
	return r, true
}

// apply synthesises the policy answer.
func (e *Enforcer) apply(req *transport.Request, rule Rule, sub subscriber.Subscriber) *dns.Msg {
	q := req.Msg.Question[0]
	ttl := rule.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}

	resp := new(dns.Msg)
	resp.SetReply(req.Msg)
	resp.RecursionAvailable = true
	// A synthesised answer was never validated, whatever the zone's real
	// status is.
	resp.AuthenticatedData = false

	switch rule.Action {
	case ActionDrop:
		e.metrics.Dropped.Add(1)
		return nil

	case ActionNXDOMAIN:
		e.metrics.Blocked.Add(1)
		resp.Rcode = dns.RcodeNameError
		addEDE(resp, dns.ExtendedErrorCodeBlocked, "blocked by subscriber policy")
		return resp

	case ActionNODATA:
		e.metrics.Blocked.Add(1)
		addEDE(resp, dns.ExtendedErrorCodeBlocked, "blocked by subscriber policy")
		return resp

	case ActionRedirect:
		e.metrics.Redirected.Add(1)
		for _, addr := range rule.Addrs {
			switch {
			case addr.Is4() && q.Qtype == dns.TypeA:
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   net.IP(addr.AsSlice()),
				})
			case addr.Is6() && q.Qtype == dns.TypeAAAA:
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
					AAAA: net.IP(addr.AsSlice()),
				})
			}
		}
		addEDE(resp, dns.ExtendedErrorCodeForgedAnswer, "redirected by subscriber policy")
		return resp

	case ActionRewrite:
		e.metrics.Rewritten.Add(1)
		resp.Answer = append(resp.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: rule.Target,
		})
		addEDE(resp, dns.ExtendedErrorCodeForgedAnswer, "rewritten by subscriber policy")
		return resp

	default:
		return resp
	}
}

// addEDE attaches an RFC 8914 extended error, so a client can tell a policy
// block apart from a genuine NXDOMAIN.
func addEDE(resp *dns.Msg, code uint16, text string) {
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code, ExtraText: text})
	resp.Extra = append(resp.Extra, opt)
}
