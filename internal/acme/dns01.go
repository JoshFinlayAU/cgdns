package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNS01 answers dns-01 challenges by publishing a TXT record.
//
// It is preferred wherever a provider is configured, because it needs nothing
// listening: no port opens, so no port can be reached. It is also the only
// option for a name whose addresses are not reachable on 80 — behind a firewall,
// or on an anycast address the CA would validate against whichever POP happens
// to be nearest it rather than the one being issued for.
type DNS01 struct {
	// Provider publishes and withdraws the record.
	Provider DNSProvider
	// PropagationTimeout bounds the wait for the record to become visible.
	// Publishing is not the same as being answerable, and accepting the
	// challenge before the record is live wastes an order and a rate limit.
	PropagationTimeout time.Duration
	// Resolvers are consulted to confirm propagation. The zone's own
	// authoritative servers are the right answer; a recursive resolver may
	// serve a cached negative for the whole TTL.
	Resolvers []string

	Log *slog.Logger
}

// DNSProvider publishes challenge records.
type DNSProvider interface {
	// Present publishes a TXT record at name with the given value.
	Present(ctx context.Context, name, value string) error
	// Cleanup withdraws it.
	Cleanup(ctx context.Context, name, value string) error
}

// Kind implements Solver.
func (d *DNS01) Kind() string { return "dns-01" }

// Present publishes the record and waits for it to be answerable.
func (d *DNS01) Present(ctx context.Context, domain, token, keyAuth string) (func(), error) {
	if d.Provider == nil {
		return nil, errors.New("acme: dns-01 needs a provider")
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	timeout := d.PropagationTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}

	name := "_acme-challenge." + dns.Fqdn(domain)
	if err := d.Provider.Present(ctx, name, keyAuth); err != nil {
		return nil, fmt.Errorf("publishing %s: %w", name, err)
	}

	cleanup := func() {
		// A fresh context: the order's may already be cancelled, and a
		// challenge record left behind is a small standing disclosure and a
		// stale answer for the next order to trip over.
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := d.Provider.Cleanup(cctx, name, keyAuth); err != nil {
			log.Warn("could not withdraw the dns-01 record",
				slog.String("name", name), slog.String("err", err.Error()))
		}
	}

	if err := d.waitForPropagation(ctx, name, keyAuth, timeout); err != nil {
		cleanup()
		return nil, err
	}
	log.Info("dns-01 record is live", slog.String("name", name))
	return cleanup, nil
}

// waitForPropagation polls until every configured resolver returns the value.
func (d *DNS01) waitForPropagation(ctx context.Context, name, value string, timeout time.Duration) error {
	resolvers := d.Resolvers
	if len(resolvers) == 0 {
		// Nothing to check against: the provider's word has to do.
		return nil
	}

	deadline := time.Now().Add(timeout)
	c := &dns.Client{Timeout: 5 * time.Second}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		seen := 0
		for _, r := range resolvers {
			m := new(dns.Msg)
			m.SetQuestion(name, dns.TypeTXT)
			resp, _, err := c.ExchangeContext(ctx, m, r)
			if err != nil {
				continue
			}
			for _, rr := range resp.Answer {
				txt, ok := rr.(*dns.TXT)
				if !ok {
					continue
				}
				if strings.Join(txt.Txt, "") == value {
					seen++
					break
				}
			}
		}
		if seen == len(resolvers) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("acme: %s did not propagate to all %d resolvers within %s",
				name, len(resolvers), timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// Cloudflare publishes challenge records through the Cloudflare API.
type Cloudflare struct {
	// Token is a scoped API token. It needs Zone:Read and DNS:Edit on the zone
	// holding the challenge name and nothing else — this credential can publish
	// records, so its blast radius is worth keeping small.
	Token string
	// ZoneID may be set to skip the zone lookup. When empty the zone is found
	// by walking up from the record name.
	ZoneID string

	Client *http.Client
	// BaseURL exists so tests can point at a stub.
	BaseURL string
}

const cloudflareAPI = "https://api.cloudflare.com/client/v4"

func (c *Cloudflare) base() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return cloudflareAPI
}

func (c *Cloudflare) httpClient() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *Cloudflare) call(ctx context.Context, method, path string, body any, out any) error {
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var parsed cfResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return fmt.Errorf("cloudflare: HTTP %d, and the body did not parse: %w", resp.StatusCode, err)
	}
	if !parsed.Success {
		if len(parsed.Errors) > 0 {
			// The token is never logged, only what the API said about it.
			return fmt.Errorf("cloudflare: %s (code %d)", parsed.Errors[0].Message, parsed.Errors[0].Code)
		}
		return fmt.Errorf("cloudflare: request failed with HTTP %d", resp.StatusCode)
	}
	if out != nil && len(parsed.Result) > 0 {
		return json.Unmarshal(parsed.Result, out)
	}
	return nil
}

// zoneFor finds the zone holding name by trying progressively shorter suffixes,
// which is what makes this work for a record several labels below the apex.
func (c *Cloudflare) zoneFor(ctx context.Context, name string) (string, error) {
	if c.ZoneID != "" {
		return c.ZoneID, nil
	}
	labels := dns.SplitDomainName(dns.Fqdn(name))
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := c.call(ctx, http.MethodGet, "/zones?name="+candidate, nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare: no zone found for %s", name)
}

// Present implements DNSProvider.
func (c *Cloudflare) Present(ctx context.Context, name, value string) error {
	zone, err := c.zoneFor(ctx, name)
	if err != nil {
		return err
	}
	body := map[string]any{
		"type":    "TXT",
		"name":    strings.TrimSuffix(name, "."),
		"content": value,
		// Short, because the record exists for one validation and a long TTL
		// only delays the next order.
		"ttl":     60,
		"comment": "cgdns acme challenge",
	}
	return c.call(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", body, nil)
}

// Cleanup implements DNSProvider.
func (c *Cloudflare) Cleanup(ctx context.Context, name, value string) error {
	zone, err := c.zoneFor(ctx, name)
	if err != nil {
		return err
	}
	var records []struct {
		ID      string `json:"id"`
		Content string `json:"content"`
	}
	path := "/zones/" + zone + "/dns_records?type=TXT&name=" + strings.TrimSuffix(name, ".")
	if err := c.call(ctx, http.MethodGet, path, nil, &records); err != nil {
		return err
	}
	var errs []error
	for _, r := range records {
		// Only this order's record: a parallel issuance for another name in the
		// same zone has its own, and deleting it would break that order.
		if r.Content != value {
			continue
		}
		if err := c.call(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+r.ID, nil, nil); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
