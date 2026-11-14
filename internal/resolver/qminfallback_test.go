package resolver

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// rdns.athenanetworks.com.au is delegated our /48 under ip6.arpa but hosts
// only zones further down, and refuses every name in between. A minimised
// probe for one of those names must not become the client's answer.
func TestRecursive_MinimisedProbeErrorFallsBackToFullName(t *testing.T) {
	t.Parallel()

	const qname = "host.sub.example.com."
	tests := []struct {
		name  string
		rcode int
	}{
		{"refused", dns.RcodeRefused},
		{"servfail", dns.RcodeServerFailure},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := 40 + i*10
			ip := func(n int) string { return "127.0.0." + strconv.Itoa(base+n) }

			root := newFakeAuth(".", ip(0)).
				delegate("com.", map[string][]string{"ns.com.": {ip(1)}})
			com := newFakeAuth("com.", ip(1)).
				delegate("example.com.", map[string][]string{"ns.example.com.": {ip(2)}})
			example := newFakeAuth("example.com.", ip(2)).
				addA("ns.example.com.", ip(2), 3600).
				addA(qname, "192.0.2.90", 300)
			example.setMangle(func(req, resp *dns.Msg) *dns.Msg {
				if dns.CanonicalName(req.Question[0].Name) != qname {
					resp.Rcode = tc.rcode
					resp.Answer, resp.Ns, resp.Extra = nil, nil, nil
				}
				return resp
			})

			h := startHierarchy(t, root, com, example)
			r := newTestRecursive(t, h)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			st := &queryState{maxOutTrip: 64}
			res, err := r.resolve(withState(ctx, st), qname, dns.TypeA, st)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if res.rcode != dns.RcodeSuccess || len(res.answer) == 0 {
				t.Fatalf("got rcode %s with %d answers, want the full name's answer",
					dns.RcodeToString[res.rcode], len(res.answer))
			}
			if got := r.opts.Metrics.MinimiseFallback.Load(); got == 0 {
				t.Error("the fallback was not counted")
			}
		})
	}
}
