// Package resolver answers client queries, either by forwarding to configured
// upstreams or by walking the delegation chain from the root.
//
// Neither path verifies the DNSSEC chain, so neither may set AD. An upstream
// having validated is not an assertion AD is allowed to carry.
package resolver

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/privacy"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// Cache is the resolver's view of the cache.
//
// Declared here, in the consumer, so the pair link can decorate it with
// push-on-fill and pull-on-miss without this package knowing a peer exists.
type Cache interface {
	Get(k cache.Key) (cache.Entry, bool)
	PutRRset(k cache.Key, rrs []dns.RR, authenticated bool)
	PutNegative(k cache.Key, rcode int, soa []dns.RR, ttl time.Duration, authenticated bool)
}

// Metrics counts resolver-level events.
type Metrics struct {
	CacheHits    atomic.Uint64
	CacheMisses  atomic.Uint64
	Upstream     atomic.Uint64
	UpstreamFail atomic.Uint64
	TCPFallback  atomic.Uint64
	ServFail     atomic.Uint64
	Timeouts     atomic.Uint64
}

// ForwardOptions configures a Forwarder.
type ForwardOptions struct {
	// Upstreams must be non-empty.
	Upstreams []netip.AddrPort
	// OutboundSource pins the local address queries leave from, per family.
	OutboundSource OutboundSource
	// Cache is required.
	Cache Cache
	// QueryTimeout bounds a single outbound exchange.
	QueryTimeout time.Duration
	// UDPSize is the EDNS0 buffer we advertise upstream.
	UDPSize uint16

	Log     *slog.Logger
	Metrics *Metrics
}

// Forwarder implements transport.Handler by serving from cache and forwarding
// misses upstream.
type Forwarder struct {
	opts      ForwardOptions
	upstreams []*upstream
	udp       clientSet
	tcp       clientSet
	rr        atomic.Uint64
}

// upstream tracks one forwarder target and how well it is behaving.
type upstream struct {
	addr string
	// family is the upstream's address, used to pick the client whose outbound
	// source matches it.
	family netip.Addr

	mu sync.Mutex
	// srtt is an exponentially weighted moving average of round-trip time.
	srtt time.Duration
	// failures counts consecutive errors.
	failures int
	// downUntil suppresses an upstream that has failed repeatedly.
	downUntil time.Time
}

var _ transport.Handler = (*Forwarder)(nil)

// ErrNoUpstream is returned when every configured upstream is unusable.
var ErrNoUpstream = errors.New("resolver: no usable upstream")

// NewForwarder builds a Forwarder.
func NewForwarder(opts ForwardOptions) (*Forwarder, error) {
	if len(opts.Upstreams) == 0 {
		return nil, errors.New("resolver: at least one upstream is required")
	}
	if opts.Cache == nil {
		return nil, errors.New("resolver: cache is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.QueryTimeout <= 0 {
		opts.QueryTimeout = 2 * time.Second
	}
	if opts.UDPSize == 0 {
		opts.UDPSize = 1232
	}

	if err := opts.OutboundSource.Verify(); err != nil {
		return nil, err
	}

	f := &Forwarder{
		opts: opts,
		udp:  newClientSet("udp", opts.QueryTimeout, opts.UDPSize, opts.OutboundSource),
		tcp:  newClientSet("tcp", opts.QueryTimeout, 0, opts.OutboundSource),
	}
	for _, u := range opts.Upstreams {
		f.upstreams = append(f.upstreams, &upstream{
			addr:   u.String(),
			family: u.Addr(),
			srtt:   50 * time.Millisecond,
		})
	}
	return f, nil
}

// ServeDNS implements transport.Handler.
func (f *Forwarder) ServeDNS(ctx context.Context, req *transport.Request) *dns.Msg {
	q := req.Msg.Question[0]

	if q.Qclass != dns.ClassINET {
		return reply(req.Msg, dns.RcodeRefused)
	}
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR, dns.TypeOPT:
		return reply(req.Msg, dns.RcodeRefused)
	}

	key := cache.NewKey(q.Name, q.Qtype, q.Qclass)
	now := time.Now()

	if entry, ok := f.opts.Cache.Get(key); ok {
		f.opts.Metrics.CacheHits.Add(1)
		return f.fromCache(req.Msg, entry, now)
	}
	f.opts.Metrics.CacheMisses.Add(1)

	resp, err := f.exchange(ctx, req.Msg)
	if err != nil {
		f.opts.Metrics.ServFail.Add(1)
		if errors.Is(err, context.DeadlineExceeded) {
			f.opts.Metrics.Timeouts.Add(1)
		}
		f.opts.Log.Warn("upstream resolution failed",
			slog.String("qname", privacy.Redact(q.Name)),
			slog.String("qtype", dns.TypeToString[q.Qtype]),
			slog.String("err", err.Error()))
		return servfail(req.Msg, dns.ExtendedErrorCodeNetworkError, "no upstream answered")
	}

	f.store(key, resp)

	out := resp.Copy()
	out.Id = req.Msg.Id
	f.finalise(req.Msg, out)
	return out
}

// fromCache rebuilds a response from a cached entry, counting the TTL down.
func (f *Forwarder) fromCache(req *dns.Msg, e cache.Entry, now time.Time) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = e.Rcode
	resp.RecursionAvailable = true

	switch e.Kind {
	case cache.KindAnswer:
		resp.Answer = e.RRsAt(now)
	case cache.KindNegative:
		resp.Ns = e.RRsAt(now)
	}

	resp.AuthenticatedData = false
	f.finalise(req, resp)
	return resp
}

// store caches a response if it is cacheable.
func (f *Forwarder) store(key cache.Key, resp *dns.Msg) {
	switch resp.Rcode {
	case dns.RcodeSuccess:
		if len(resp.Answer) > 0 {
			var matching []dns.RR
			for _, rr := range resp.Answer {
				h := rr.Header()
				if h.Class == key.Class && cache.CanonicalName(h.Name) == key.Name &&
					(h.Rrtype == key.Type || h.Rrtype == dns.TypeCNAME) {
					matching = append(matching, rr)
				}
			}
			if len(matching) > 0 {
				f.opts.Cache.PutRRset(key, matching, false)
			}
			return
		}
		// NOERROR with no answer is NODATA: a denial, cached negatively.
		fallthrough
	case dns.RcodeNameError:
		soa, ttl := negativeTTL(resp)
		if ttl > 0 {
			f.opts.Cache.PutNegative(key, resp.Rcode, soa, ttl, false)
		}
	default:
		// SERVFAIL and REFUSED describe a server, not the namespace. Caching
		// them turns a transient upstream blip into a sustained outage.
	}
}

// negativeTTL extracts the RFC 2308 §5 negative caching TTL: the lesser of the
// SOA MINIMUM field and the SOA record's own TTL.
func negativeTTL(resp *dns.Msg) ([]dns.RR, time.Duration) {
	for _, rr := range resp.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		ttl := soa.Hdr.Ttl
		if soa.Minttl < ttl {
			ttl = soa.Minttl
		}
		return []dns.RR{rr}, time.Duration(ttl) * time.Second
	}
	return nil, 0
}

// exchange sends the query to the best available upstream, failing over on
// error within the client budget carried on ctx.
func (f *Forwarder) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Copy()
	q.Id = dns.Id()
	q.RecursionDesired = true
	if q.IsEdns0() == nil {
		q.SetEdns0(f.opts.UDPSize, false)
	}

	var lastErr error = ErrNoUpstream
	for _, u := range f.order() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		start := time.Now()
		resp, _, err := f.udp.forAddr(u.family).ExchangeContext(ctx, q, u.addr)
		if err == nil && resp != nil && resp.Truncated {
			f.opts.Metrics.TCPFallback.Add(1)
			resp, _, err = f.tcp.forAddr(u.family).ExchangeContext(ctx, q, u.addr)
		}

		f.opts.Metrics.Upstream.Add(1)
		if err != nil || resp == nil {
			f.opts.Metrics.UpstreamFail.Add(1)
			u.penalise()
			lastErr = err
			if lastErr == nil {
				lastErr = errors.New("resolver: nil response from upstream")
			}
			continue
		}
		u.succeed(time.Since(start))
		return resp, nil
	}
	return nil, lastErr
}

// order returns upstreams best-first: usable ones by smoothed RTT, then those
// backed off, so a total outage is still attempted rather than failed outright.
func (f *Forwarder) order() []*upstream {
	now := time.Now()
	live := make([]*upstream, 0, len(f.upstreams))
	backedOff := make([]*upstream, 0, len(f.upstreams))
	for _, u := range f.upstreams {
		u.mu.Lock()
		down := now.Before(u.downUntil)
		u.mu.Unlock()
		if down {
			backedOff = append(backedOff, u)
		} else {
			live = append(live, u)
		}
	}

	for i := 1; i < len(live); i++ {
		for j := i; j > 0 && live[j].smoothedRTT() < live[j-1].smoothedRTT(); j-- {
			live[j], live[j-1] = live[j-1], live[j]
		}
	}

	if len(live) > 1 && f.rr.Add(1)%16 == 0 {
		live = append(live[1:], live[0])
	}
	return append(live, backedOff...)
}

func (u *upstream) smoothedRTT() time.Duration {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.srtt
}

func (u *upstream) succeed(rtt time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.srtt = (u.srtt*7 + rtt) / 8
	u.failures = 0
	u.downUntil = time.Time{}
}

func (u *upstream) penalise() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.failures++
	u.srtt = min(u.srtt*2, 5*time.Second)
	if u.failures >= 3 {
		backoff := time.Duration(math.Min(
			float64(time.Second)*math.Pow(2, float64(u.failures-3)),
			float64(30*time.Second)))
		u.downUntil = time.Now().Add(backoff)
	}
}

// finalise applies the invariants every response must satisfy.
func (f *Forwarder) finalise(req, resp *dns.Msg) {
	resp.Id = req.Id
	resp.Response = true
	resp.Opcode = req.Opcode
	resp.RecursionDesired = req.RecursionDesired
	resp.RecursionAvailable = true
	resp.AuthenticatedData = false
	if len(resp.Question) == 0 {
		resp.Question = req.Question
	}
}

// reply builds a bare response with the given rcode.
func reply(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	m.RecursionAvailable = true
	m.AuthenticatedData = false
	return m
}

// servfail builds a SERVFAIL carrying an RFC 8914 Extended DNS Error.
func servfail(req *dns.Msg, code uint16, text string) *dns.Msg {
	m := reply(req, dns.RcodeServerFailure)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{
		InfoCode:  code,
		ExtraText: text,
	})
	m.Extra = append(m.Extra, opt)
	return m
}
