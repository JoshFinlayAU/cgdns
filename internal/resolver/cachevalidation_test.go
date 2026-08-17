package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/cache"
	"github.com/JoshFinlayAU/cgdns/internal/dnssec"
	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

// The delegation walk caches records on its way past — delegation NS sets, glue,
// the root's own NS — and those entries keep no signatures. A client query for
// one of those same names must not be answered from such an entry while
// validation is on: there is nothing left to validate it with, so the name would
// SERVFAIL for as long as the entry lived.
func TestUnvalidatedCacheEntryIsNotServed(t *testing.T) {
	t.Parallel()

	h := standardHierarchy(t)
	c := testCache(t)

	anchors := []dnssec.Anchor{{
		Zone:       ".",
		KeyTag:     20326,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
	}}
	validator, err := dnssec.New(dnssec.Options{Anchors: anchors, MaxDepth: 16})
	if err != nil {
		t.Fatalf("building validator: %v", err)
	}

	r := newTestRecursive(t, h, func(o *RecursiveOptions) {
		o.Cache = c
		o.Validator = validator
	})

	poison := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("203.0.113.66"),
	}
	c.PutRRset(cache.NewKey("www.example.com.", dns.TypeA, dns.ClassINET), []dns.RR{poison}, false)

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)

	before := h.zone("example.com.").queries.Load()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp := r.ServeDNS(ctx, &transport.Request{Msg: req, Received: time.Now(), MaxResponseSize: 4096})
	if resp == nil {
		t.Fatal("no response")
	}

	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == "203.0.113.66" {
			t.Fatal("served the unvalidated cache entry; it carries no signatures, so it cannot be validated and must be resolved again")
		}
	}
	if got := h.zone("example.com.").queries.Load(); got == before {
		t.Fatal("answered without consulting the authoritative; the unvalidated cache entry was used instead of being passed over")
	}
}

// An answer that validated as insecure is marked validated, so an unsigned zone
// is not walked again on every single query.
func TestValidatedInsecureAnswerStaysCached(t *testing.T) {
	t.Parallel()

	c := testCache(t)
	k := cache.NewKey("www.example.com.", dns.TypeA, dns.ClassINET)
	rrs := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.80"),
	}}

	c.PutRRset(k, rrs, false)
	entry, ok := c.Get(k)
	if !ok {
		t.Fatal("entry missing after PutRRset")
	}
	if entry.Validated {
		t.Error("PutRRset marked the entry validated; only a decided DNSSEC status may do that")
	}

	c.PutValidated(k, rrs, false)
	entry, ok = c.Get(k)
	if !ok {
		t.Fatal("entry missing after PutValidated")
	}
	if !entry.Validated {
		t.Error("PutValidated left the entry unvalidated, so an unsigned zone would be re-walked on every hit")
	}
	if entry.Authenticated {
		t.Error("an insecure answer must never be marked authenticated")
	}
}
