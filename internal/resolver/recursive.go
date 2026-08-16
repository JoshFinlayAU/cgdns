// The recursion engine walks the delegation chain: start at the deepest known
// delegation, ask one of that zone's authoritative servers, and either get an
// answer or get referred one step closer.
//
// Three budgets bound every client query: the wall-clock budget on the
// context, the delegation depth cap, and the outbound query cap that stops one
// client query becoming an amplification lever against third parties.
//
// What a response is trusted to assert is decided in bailiwick.go.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/dnssec"
	"github.com/JoshFinlayAU/cgdns/internal/privacy"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// Nameserver is an authoritative server name together with any addresses we
// currently know for it. Addrs is empty when the delegation carried no usable
// glue, in which case the name must be resolved before it can be queried.
type Nameserver struct {
	Name  string
	Addrs []netip.Addr
}

// RecursiveMetrics counts recursion-specific events.
type RecursiveMetrics struct {
	Referrals        atomic.Uint64
	BogusReferrals   atomic.Uint64
	OutboundQueries  atomic.Uint64
	OutboundFailures atomic.Uint64
	DepthExceeded    atomic.Uint64
	BudgetExceeded   atomic.Uint64
	CaseMismatch     atomic.Uint64
	GluelessLookups  atomic.Uint64
	EDNSDowngrades   atomic.Uint64
	TCPFallbacks     atomic.Uint64
	CNAMEChased      atomic.Uint64
	MinimiseFallback atomic.Uint64
	Secure           atomic.Uint64
	Insecure         atomic.Uint64
	Bogus            atomic.Uint64
}

// RecursiveOptions configures a Recursive resolver.
type RecursiveOptions struct {
	Cache *cache.Cache
	Infra *cache.Infra

	// RootHints bootstraps the walk. Required.
	RootHints []Nameserver

	// MaxDepth caps delegation depth per client query.
	MaxDepth int
	// MaxOutbound caps total outbound queries per client query. This is the
	// amplification limit.
	MaxOutbound int
	// MaxCNAME caps how far a CNAME chain is followed.
	MaxCNAME int

	// QueryTimeout bounds one outbound exchange.
	QueryTimeout time.Duration
	// UDPSize is the EDNS0 buffer advertised to authoritatives.
	UDPSize uint16

	// ServerPort is the port authoritatives are contacted on. Defaults to 53;
	// configurable so a test hierarchy can run unprivileged on loopback.
	ServerPort uint16

	// QNAMEMinimisation and CaseRandomisation default on; both have config
	// escape hatches for broken authoritatives.
	QNAMEMinimisation bool
	CaseRandomisation bool

	// Validator enables DNSSEC validation. When nil, answers are served with
	// AD clear and no chain is built.
	Validator *dnssec.Validator

	// UseIPv4 and UseIPv6 select the outbound families; both must not be
	// false. Disabling IPv6 makes v6-only authoritatives unreachable.
	UseIPv4 bool
	UseIPv6 bool

	Log     *slog.Logger
	Metrics *RecursiveMetrics
}

// Recursive resolves by walking the delegation chain itself.
type Recursive struct {
	opts RecursiveOptions
	udp  *dns.Client
	tcp  *dns.Client
}

// stateKey carries the per-query budget through the dnssec.Fetcher interface,
// so chain-building shares the client's outbound allowance instead of getting
// a fresh one.
type stateKey struct{}

func withState(ctx context.Context, st *queryState) context.Context {
	return context.WithValue(ctx, stateKey{}, st)
}

func stateFrom(ctx context.Context, fallback int) *queryState {
	if st, ok := ctx.Value(stateKey{}).(*queryState); ok && st != nil {
		return st
	}
	return &queryState{maxOutTrip: fallback}
}

var _ transport.Handler = (*Recursive)(nil)

// Sentinel errors, wrapped with context before surfacing.
var (
	ErrBudgetExhausted   = errors.New("resolver: query budget exhausted")
	ErrNoReachableServer = errors.New("resolver: no authoritative server answered")
	ErrBogusReferral     = errors.New("resolver: referral failed bailiwick check")
)

// NewRecursive builds a Recursive resolver.
func NewRecursive(opts RecursiveOptions) (*Recursive, error) {
	if opts.Cache == nil {
		return nil, errors.New("resolver: cache is required")
	}
	if opts.Infra == nil {
		return nil, errors.New("resolver: infra cache is required")
	}
	if len(opts.RootHints) == 0 {
		return nil, errors.New("resolver: root hints are required")
	}
	if !opts.UseIPv4 && !opts.UseIPv6 {
		return nil, errors.New("resolver: at least one of UseIPv4/UseIPv6 must be enabled")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &RecursiveMetrics{}
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 16
	}
	if opts.MaxOutbound <= 0 {
		opts.MaxOutbound = 32
	}
	if opts.MaxCNAME <= 0 {
		opts.MaxCNAME = 8
	}
	if opts.QueryTimeout <= 0 {
		opts.QueryTimeout = 2 * time.Second
	}
	if opts.UDPSize == 0 {
		opts.UDPSize = 1232
	}
	if opts.ServerPort == 0 {
		opts.ServerPort = 53
	}

	return &Recursive{
		opts: opts,
		udp:  &dns.Client{Net: "udp", Timeout: opts.QueryTimeout, UDPSize: opts.UDPSize},
		tcp:  &dns.Client{Net: "tcp", Timeout: opts.QueryTimeout},
	}, nil
}

// queryState carries the per-client-query budgets. One exists per inbound
// query and is threaded through every recursive step, including glueless
// nameserver resolution; a fresh budget there would void the caps.
type queryState struct {
	outbound   int
	cnames     int
	nsDepth    int
	maxOutTrip int
}

func (s *queryState) spend() error {
	s.outbound++
	if s.outbound > s.maxOutTrip {
		return ErrBudgetExhausted
	}
	return nil
}

// result is an internal resolution outcome, before it becomes a wire message.
type result struct {
	rcode     int
	answer    []dns.RR
	authority []dns.RR // SOA on a negative answer
	sigs      []*dns.RRSIG
	secure    dnssec.Status
}

// ServeDNS implements transport.Handler.
func (r *Recursive) ServeDNS(ctx context.Context, req *transport.Request) *dns.Msg {
	q := req.Msg.Question[0]

	if q.Qclass != dns.ClassINET {
		return reply(req.Msg, dns.RcodeRefused)
	}
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR, dns.TypeOPT:
		return reply(req.Msg, dns.RcodeRefused)
	}

	st := &queryState{maxOutTrip: r.opts.MaxOutbound}
	ctx = withState(ctx, st)

	res, err := r.resolve(ctx, dns.CanonicalName(q.Name), q.Qtype, st)
	if err != nil {
		return r.failure(req.Msg, q, err)
	}

	if r.opts.Validator != nil && res.secure == dnssec.StatusIndeterminate {
		status, verr := r.validate(ctx, res)
		switch status {
		case dnssec.StatusBogus:
			r.opts.Metrics.Bogus.Add(1)
			r.opts.Log.Warn("DNSSEC validation failed",
				slog.String("qname", privacy.Redact(q.Name)),
				slog.String("qtype", dns.TypeToString[q.Qtype]),
				slog.String("err", verr.Error()))
			return servfail(req.Msg, dnssec.ExtendedError(verr), verr.Error())
		case dnssec.StatusSecure:
			r.opts.Metrics.Secure.Add(1)
			r.opts.Cache.PutRRset(cache.NewKey(dns.CanonicalName(q.Name), q.Qtype, dns.ClassINET), res.answer, true)
		default:
			r.opts.Metrics.Insecure.Add(1)
		}
		res.secure = status
	}

	resp := new(dns.Msg)
	resp.SetReply(req.Msg)
	resp.Rcode = res.rcode
	resp.RecursionAvailable = true
	resp.Answer = res.answer
	resp.Ns = res.authority
	// AD is set only by a chain this resolver validated itself.
	resp.AuthenticatedData = res.secure == dnssec.StatusSecure
	return resp
}

// validate builds the chain for an answer and verifies it.
//
// An answer with no signatures is acceptable only where the zone is provably
// unsigned; otherwise it is a stripped-signature attack and must be Bogus.
func (r *Recursive) validate(ctx context.Context, res *result) (dnssec.Status, error) {
	if len(res.answer) == 0 {
		return dnssec.StatusInsecure, nil
	}

	zone := dns.CanonicalName(res.answer[0].Header().Name)
	if len(res.sigs) > 0 {
		zone = dns.CanonicalName(res.sigs[0].SignerName)
	}

	keys, status, err := r.opts.Validator.TrustedKeys(ctx, zone)
	if err != nil {
		return status, err
	}
	if status != dnssec.StatusSecure {
		return status, nil
	}
	if len(res.sigs) == 0 {
		return dnssec.StatusBogus, dnssec.ErrNoSignatures
	}
	if _, err := r.opts.Validator.VerifyRRset(res.answer, res.sigs, keys); err != nil {
		return dnssec.StatusBogus, err
	}
	return dnssec.StatusSecure, nil
}

// FetchSigned implements dnssec.Fetcher, letting the validator pull DNSKEY and
// DS records through the same delegation walk. It does not validate what it
// returns; that is the validator's job, and doing it here would recurse.
func (r *Recursive) FetchSigned(ctx context.Context, name string, qtype uint16) ([]dns.RR, []*dns.RRSIG, []dns.RR, error) {
	st := stateFrom(ctx, r.opts.MaxOutbound)
	name = dns.CanonicalName(name)

	startAt := ""
	if qtype == dns.TypeDS && name != "." {
		_, startAt = splitFirstLabel(name)
	}
	res, err := r.walkFrom(ctx, name, qtype, st, startAt)
	if err != nil {
		return nil, nil, nil, err
	}
	return res.answer, res.sigs, res.authority, nil
}

func (r *Recursive) failure(req *dns.Msg, q dns.Question, err error) *dns.Msg {
	code := dns.ExtendedErrorCodeNetworkError
	switch {
	case errors.Is(err, ErrBudgetExhausted):
		r.opts.Metrics.BudgetExceeded.Add(1)
		code = dns.ExtendedErrorCodeNoReachableAuthority
	case errors.Is(err, ErrBogusReferral):
		code = dns.ExtendedErrorCodeNoReachableAuthority
	case errors.Is(err, ErrNoReachableServer):
		code = dns.ExtendedErrorCodeNoReachableAuthority
	}
	r.opts.Log.Warn("recursion failed",
		slog.String("qname", privacy.Redact(q.Name)),
		slog.String("qtype", dns.TypeToString[q.Qtype]),
		slog.String("err", err.Error()))
	return servfail(req, code, err.Error())
}

// resolve answers one name/type, consulting cache first and walking the
// delegation chain when it misses.
func (r *Recursive) resolve(ctx context.Context, qname string, qtype uint16, st *queryState) (*result, error) {
	if entry, ok := r.opts.Cache.Get(cache.NewKey(qname, qtype, dns.ClassINET)); ok {
		now := time.Now()
		res := &result{rcode: entry.Rcode}
		if entry.Authenticated {
			// Validated once on insert; re-verifying on every hit would put
			// public-key cryptography on the hot path for no added assurance.
			res.secure = dnssec.StatusSecure
		}
		switch entry.Kind {
		case cache.KindAnswer:
			res.answer = entry.RRsAt(now)
		case cache.KindNegative:
			res.authority = entry.RRsAt(now)
		}
		return res, nil
	}
	return r.walk(ctx, qname, qtype, st)
}

// walk performs the delegation descent for one name/type.
func (r *Recursive) walk(ctx context.Context, qname string, qtype uint16, st *queryState) (*result, error) {
	return r.walkFrom(ctx, qname, qtype, st, "")
}

// walkFrom descends toward qname, optionally starting the search for
// authoritative servers at a name other than qname itself.
//
// A DS query must start at the parent: the delegation signer is published on
// the parent side of the cut, so asking the child returns nothing and looks
// exactly like an unsigned zone.
func (r *Recursive) walkFrom(ctx context.Context, qname string, qtype uint16, st *queryState, startAt string) (*result, error) {
	search := qname
	if startAt != "" {
		search = startAt
	}
	zone, servers := r.bestDelegation(search)

	sname := zone
	minimise := r.opts.QNAMEMinimisation
	steps := 0

	for depth := 0; depth < r.opts.MaxDepth; depth++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		probe, probeType := qname, qtype
		if minimise && steps < maxMinimiseSteps && shouldMinimise(qname, sname) {
			probe = minimisedName(qname, sname)
			probeType = minimiseQType(probe, qname, qtype)
			steps++
		}

		resp, err := r.ask(ctx, servers, zone, probe, probeType, st)
		if err != nil {
			return nil, err
		}

		switch classify(resp, probe, probeType) {
		case classReferral:
			newZone := referralZone(resp.Ns, zone, qname)
			if qtype == dns.TypeDS && probe == qname && newZone == qname {
				// The parent referred us to the child rather than answering.
				// A referral for a signed child carries the DS in its
				// authority section, so take it from there instead of
				// descending and asking the child about its own delegation.
				return r.finishDSReferral(qname, resp), nil
			}
			if newZone == "" {
				r.opts.Metrics.BogusReferrals.Add(1)
				return nil, fmt.Errorf("%w: %s referred to a zone outside its authority",
					ErrBogusReferral, privacy.Redact(zone))
			}
			r.opts.Metrics.Referrals.Add(1)
			ns := nameserversFrom(resp.Ns, resp.Extra, newZone)
			if len(ns) == 0 {
				return nil, fmt.Errorf("%w: referral to %s carried no usable nameservers",
					ErrBogusReferral, privacy.Redact(newZone))
			}
			r.cacheDelegation(newZone, resp)
			zone, servers, sname = newZone, ns, newZone
			continue

		case classAnswer:
			if probe != qname {
				sname = probe
				continue
			}
			return r.finishAnswer(ctx, qname, qtype, resp, st)

		case classNoData:
			if probe != qname {
				// Empty non-terminal: the label exists but holds no A record.
				sname = probe
				continue
			}
			return r.finishNegative(qname, qtype, resp), nil

		case classNXDomain:
			if probe != qname {
				// RFC 9156 §4: an intermediate NXDOMAIN is not authoritative
				// for the full name — some servers return it for an empty
				// non-terminal — so ask outright instead of trusting it.
				r.opts.Metrics.MinimiseFallback.Add(1)
				minimise = false
				continue
			}
			return r.finishNegative(qname, qtype, resp), nil

		default:
			return &result{rcode: resp.Rcode}, nil
		}
	}

	r.opts.Metrics.DepthExceeded.Add(1)
	return nil, fmt.Errorf("%w: delegation depth exceeded resolving %s",
		ErrBudgetExhausted, privacy.Redact(qname))
}

// finishAnswer caches an answer and follows a CNAME chain if it did not
// terminate in the requested type.
func (r *Recursive) finishAnswer(ctx context.Context, qname string, qtype uint16, resp *dns.Msg, st *queryState) (*result, error) {
	answer, final := answersFor(resp.Answer, qname, qtype)
	if len(answer) == 0 {
		return r.finishNegative(qname, qtype, resp), nil
	}

	terminal := false
	for _, rr := range answer {
		if rr.Header().Rrtype == qtype {
			terminal = true
			break
		}
	}
	if terminal || qtype == dns.TypeCNAME {
		r.cacheAdditional(qname, resp)
		r.opts.Cache.PutRRset(cache.NewKey(qname, qtype, dns.ClassINET), answer, false)
		return &result{rcode: dns.RcodeSuccess, answer: answer, sigs: sigsCovering(resp.Answer, answer)}, nil
	}

	st.cnames++
	if st.cnames > r.opts.MaxCNAME {
		return nil, fmt.Errorf("%w: CNAME chain too long for %s",
			ErrBudgetExhausted, privacy.Redact(qname))
	}
	r.opts.Metrics.CNAMEChased.Add(1)

	tail, err := r.resolve(ctx, final, qtype, st)
	if err != nil {
		return nil, err
	}
	combined := append(append([]dns.RR{}, answer...), tail.answer...)
	return &result{rcode: tail.rcode, answer: combined, authority: tail.authority}, nil
}

// sigsCovering returns the RRSIGs from section that cover the types present in
// answer, discarding signatures for anything we did not accept.
func sigsCovering(section []dns.RR, answer []dns.RR) []*dns.RRSIG {
	want := map[uint16]bool{}
	names := map[string]bool{}
	for _, rr := range answer {
		h := rr.Header()
		want[h.Rrtype] = true
		names[dns.CanonicalName(h.Name)] = true
	}
	var out []*dns.RRSIG
	for _, rr := range section {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if want[sig.TypeCovered] && names[dns.CanonicalName(sig.Hdr.Name)] {
			out = append(out, sig)
		}
	}
	return out
}

// finishDSReferral extracts a DS RRset, or its denial, from a referral's
// authority section.
func (r *Recursive) finishDSReferral(qname string, resp *dns.Msg) *result {
	var (
		ds   []dns.RR
		sigs []*dns.RRSIG
	)
	for _, rr := range resp.Ns {
		switch v := rr.(type) {
		case *dns.DS:
			if dns.CanonicalName(v.Hdr.Name) == qname {
				ds = append(ds, rr)
			}
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeDS && dns.CanonicalName(v.Hdr.Name) == qname {
				sigs = append(sigs, v)
			}
		}
	}
	if len(ds) > 0 {
		r.opts.Cache.PutRRset(cache.NewKey(qname, dns.TypeDS, dns.ClassINET), ds, false)
		return &result{rcode: dns.RcodeSuccess, answer: ds, sigs: sigs}
	}
	return &result{rcode: dns.RcodeSuccess, authority: denialRecords(resp)}
}

// finishNegative caches and returns a denial, deriving the negative TTL from
// the SOA per RFC 2308 §5.
func (r *Recursive) finishNegative(qname string, qtype uint16, resp *dns.Msg) *result {
	soa, ttl := negativeTTL(resp)
	rcode := resp.Rcode
	if ttl > 0 {
		r.opts.Cache.PutNegative(cache.NewKey(qname, qtype, dns.ClassINET), rcode, soa, ttl, false)
	}
	return &result{rcode: rcode, authority: denialRecords(resp)}
}

// denialRecords returns the authority section records a negative answer needs:
// the SOA plus any NSEC/NSEC3 proving the denial, with their signatures.
func denialRecords(resp *dns.Msg) []dns.RR {
	out := make([]dns.RR, 0, len(resp.Ns))
	for _, rr := range resp.Ns {
		switch rr.(type) {
		case *dns.SOA, *dns.NSEC, *dns.NSEC3, *dns.RRSIG:
			out = append(out, rr)
		}
	}
	return out
}

// cacheAdditional caches address records volunteered alongside an answer,
// bailiwick-checked against the answered zone.
//
// A priming query for the root NS is answered with the server names, and their
// addresses come in the additional section; without keeping them the delegation
// is cached in an unusable, address-less form.
func (r *Recursive) cacheAdditional(zone string, resp *dns.Msg) {
	byKey := map[cache.Key][]dns.RR{}
	for _, rr := range filterGlue(resp.Extra, zone) {
		h := rr.Header()
		k := cache.NewKey(h.Name, h.Rrtype, h.Class)
		byKey[k] = append(byKey[k], rr)
	}
	for k, rrs := range byKey {
		r.opts.Cache.PutRRset(k, rrs, false)
	}
}

// cacheDelegation stores a referral's NS RRset and its in-bailiwick glue.
func (r *Recursive) cacheDelegation(zone string, resp *dns.Msg) {
	var ns []dns.RR
	for _, rr := range resp.Ns {
		if rec, ok := rr.(*dns.NS); ok && dns.CanonicalName(rec.Hdr.Name) == dns.CanonicalName(zone) {
			ns = append(ns, rr)
		}
	}
	if len(ns) > 0 {
		r.opts.Cache.PutRRset(cache.NewKey(zone, dns.TypeNS, dns.ClassINET), ns, false)
	}

	byName := map[cache.Key][]dns.RR{}
	for _, rr := range filterGlue(resp.Extra, zone) {
		h := rr.Header()
		k := cache.NewKey(h.Name, h.Rrtype, h.Class)
		byName[k] = append(byName[k], rr)
	}
	for k, rrs := range byName {
		r.opts.Cache.PutRRset(k, rrs, false)
	}
}

// bestDelegation finds the deepest cached NS RRset covering qname, falling
// back to the root hints.
//
// A cached delegation is only usable if at least one of its nameservers has a
// known address. An address-less set is worse than nothing: the walk would try
// to resolve those nameserver names, which needs the very zone it is trying to
// reach. That is exactly what happens at the root, where caching a `. NS`
// answer stores the names but not the addresses — those arrive in the
// additional section — so an unguarded lookup recurses until the budget dies.
func (r *Recursive) bestDelegation(qname string) (string, []Nameserver) {
	name := dns.CanonicalName(qname)
	for {
		if entry, ok := r.opts.Cache.Get(cache.NewKey(name, dns.TypeNS, dns.ClassINET)); ok && entry.Kind == cache.KindAnswer {
			if ns := r.hydrate(entry.RRs, name); hasAddress(ns) {
				return name, ns
			}
		}
		if name == "." {
			break
		}
		_, rest := splitFirstLabel(name)
		name = rest
	}
	return ".", r.opts.RootHints
}

// hasAddress reports whether any nameserver in the set can actually be queried.
func hasAddress(ns []Nameserver) bool {
	for _, n := range ns {
		if len(n.Addrs) > 0 {
			return true
		}
	}
	return false
}

// hydrate turns cached NS records into Nameservers, attaching any addresses we
// already hold for their names.
func (r *Recursive) hydrate(rrs []dns.RR, zone string) []Nameserver {
	out := make([]Nameserver, 0, len(rrs))
	for _, rr := range rrs {
		rec, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		name := dns.CanonicalName(rec.Ns)
		ns := Nameserver{Name: name}
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			if e, ok := r.opts.Cache.Get(cache.NewKey(name, t, dns.ClassINET)); ok && e.Kind == cache.KindAnswer {
				for _, arr := range e.RRs {
					if a, ok := addrOfRR(arr); ok {
						ns.Addrs = append(ns.Addrs, a)
					}
				}
			}
		}
		out = append(out, ns)
	}
	return out
}

// candidate is one address worth trying, with the estimate used to order it.
type candidate struct {
	ns   string
	addr netip.Addr
	rtt  time.Duration
}

// ask sends probe to the best available server for zone, retrying across
// servers on failure.
func (r *Recursive) ask(ctx context.Context, servers []Nameserver, zone, probe string, ptype uint16, st *queryState) (*dns.Msg, error) {
	cands := r.candidates(servers)

	if len(cands) == 0 {
		if err := r.resolveNameserverAddrs(ctx, servers, st); err != nil {
			return nil, err
		}
		cands = r.candidates(servers)
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("%w: no addresses for any nameserver of %s",
			ErrNoReachableServer, privacy.Redact(zone))
	}

	var lastErr error = ErrNoReachableServer
	for _, c := range cands {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := st.spend(); err != nil {
			return nil, fmt.Errorf("%w resolving %s", err, privacy.Redact(probe))
		}

		resp, err := r.exchange(ctx, c.addr, probe, ptype)
		if err != nil {
			r.opts.Metrics.OutboundFailures.Add(1)
			r.opts.Infra.Failure(c.addr)
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("%w for %s: %v", ErrNoReachableServer, privacy.Redact(zone), lastErr)
}

// candidates flattens the nameserver set into individually-tryable addresses,
// filtered by enabled family and current health, ordered fastest first.
func (r *Recursive) candidates(servers []Nameserver) []candidate {
	var out []candidate
	for _, ns := range servers {
		for _, a := range ns.Addrs {
			if a.Is4() && !r.opts.UseIPv4 {
				continue
			}
			if a.Is6() && !r.opts.UseIPv6 {
				continue
			}
			if !r.opts.Infra.Usable(a) {
				continue
			}
			out = append(out, candidate{ns: ns.Name, addr: a, rtt: r.opts.Infra.RTT(a)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].rtt < out[j].rtt })
	return out
}

// resolveNameserverAddrs resolves nameserver names that arrived without glue.
// It stops at the first success; resolving the rest would only spend budget.
func (r *Recursive) resolveNameserverAddrs(ctx context.Context, servers []Nameserver, st *queryState) error {
	// Guards mutual recursion: a zone whose nameserver lives in the zone its
	// own nameserver needs resolved.
	if st.nsDepth >= 4 {
		return fmt.Errorf("%w: nameserver address resolution nested too deeply", ErrBudgetExhausted)
	}
	st.nsDepth++
	defer func() { st.nsDepth-- }()

	r.opts.Metrics.GluelessLookups.Add(1)

	types := make([]uint16, 0, 2)
	if r.opts.UseIPv6 {
		types = append(types, dns.TypeAAAA)
	}
	if r.opts.UseIPv4 {
		types = append(types, dns.TypeA)
	}

	var lastErr error = ErrNoReachableServer
	for i := range servers {
		if len(servers[i].Addrs) > 0 {
			continue
		}
		for _, t := range types {
			res, err := r.resolve(ctx, servers[i].Name, t, st)
			if err != nil {
				lastErr = err
				continue
			}
			for _, rr := range res.answer {
				if a, ok := addrOfRR(rr); ok {
					servers[i].Addrs = append(servers[i].Addrs, a)
				}
			}
		}
		if len(servers[i].Addrs) > 0 {
			return nil
		}
	}
	return lastErr
}

// exchange sends one query to one server, handling 0x20 verification, EDNS
// downgrade and TCP fallback.
func (r *Recursive) exchange(ctx context.Context, server netip.Addr, qname string, qtype uint16) (*dns.Msg, error) {
	sent := dns.Fqdn(qname)
	if r.opts.CaseRandomisation {
		sent = randomiseCase(sent)
	}

	m := new(dns.Msg)
	m.SetQuestion(sent, qtype)
	m.Id = dns.Id()
	// Asking an authoritative to recurse would be asking it to act as an open
	// resolver on our behalf.
	m.RecursionDesired = false
	if !r.opts.Infra.EDNSBroken(server) {
		// DO is set whenever validation is on, otherwise authoritatives omit
		// the RRSIGs the chain needs.
		m.SetEdns0(r.opts.UDPSize, r.opts.Validator != nil)
	}

	addr := netip.AddrPortFrom(server, r.opts.ServerPort).String()
	start := time.Now()
	r.opts.Metrics.OutboundQueries.Add(1)

	resp, _, err := r.udp.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, fmt.Errorf("querying %s: %w", server, err)
	}

	if (resp.Rcode == dns.RcodeFormatError || resp.Rcode == dns.RcodeNotImplemented) && m.IsEdns0() != nil {
		r.opts.Metrics.EDNSDowngrades.Add(1)
		r.opts.Infra.MarkEDNSBroken(server)
		plain := new(dns.Msg)
		plain.SetQuestion(sent, qtype)
		plain.Id = dns.Id()
		plain.RecursionDesired = false
		resp, _, err = r.udp.ExchangeContext(ctx, plain, addr)
		if err != nil {
			return nil, fmt.Errorf("querying %s without EDNS: %w", server, err)
		}
		m = plain
	}

	if resp.Truncated {
		r.opts.Metrics.TCPFallbacks.Add(1)
		resp, _, err = r.tcp.ExchangeContext(ctx, m, addr)
		if err != nil {
			return nil, fmt.Errorf("querying %s over tcp: %w", server, err)
		}
	}

	if r.opts.CaseRandomisation && len(resp.Question) == 1 {
		if !caseMatches(sent, resp.Question[0].Name) {
			r.opts.Metrics.CaseMismatch.Add(1)
			r.opts.Log.Warn("discarding response with mismatched 0x20 encoding (possible spoofing attempt)",
				slog.String("server", server.String()),
				slog.String("qname", privacy.Redact(qname)))
			return nil, fmt.Errorf("querying %s: response failed 0x20 verification", server)
		}
	}

	if r.opts.CaseRandomisation {
		normaliseCase(resp)
	}

	r.opts.Infra.Success(server, time.Since(start))
	return resp, nil
}

// responseClass is how a response is interpreted during the walk.
type responseClass int

const (
	classAnswer responseClass = iota
	classReferral
	classNoData
	classNXDomain
	classOther
)

// classify decides what a response means for the descent.
func classify(resp *dns.Msg, probe string, ptype uint16) responseClass {
	if resp.Rcode == dns.RcodeNameError {
		return classNXDomain
	}
	if resp.Rcode != dns.RcodeSuccess {
		return classOther
	}

	for _, rr := range resp.Answer {
		h := rr.Header()
		if dns.CanonicalName(h.Name) == dns.CanonicalName(probe) &&
			(h.Rrtype == ptype || h.Rrtype == dns.TypeCNAME) {
			return classAnswer
		}
	}

	hasNS, hasSOA := false, false
	for _, rr := range resp.Ns {
		switch rr.(type) {
		case *dns.NS:
			hasNS = true
		case *dns.SOA:
			hasSOA = true
		}
	}
	switch {
	case hasNS && !hasSOA:
		return classReferral
	default:
		return classNoData
	}
}

// splitFirstLabel removes the leftmost label: "www.example.com." becomes
// ("www", "example.com.").
func splitFirstLabel(name string) (string, string) {
	if name == "." || name == "" {
		return "", "."
	}
	i, end := dns.NextLabel(name, 0)
	if end {
		return strings.TrimSuffix(name, "."), "."
	}
	return name[:i-1], name[i:]
}
