package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/netacl"
)

// testTLS builds a self-signed certificate valid for loopback.
func testTLS(t *testing.T) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "resolver.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"resolver.test", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1", "dot"},
	}
}

func startDoT(t *testing.T, opts TCPOptions) netip.AddrPort {
	t.Helper()
	if opts.Log == nil {
		opts.Log = quietLogger()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	srv, err := NewTCP(opts)
	if err != nil {
		t.Fatalf("NewTCP(DoT): %v", err)
	}
	addrs := srv.LocalAddrs()
	if len(addrs) == 0 {
		t.Fatal("no bound DoT addresses")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("DoT listener did not shut down")
		}
	})
	return addrs[0]
}

func startDoH(t *testing.T, opts DoHOptions) netip.AddrPort {
	t.Helper()
	if opts.Log == nil {
		opts.Log = quietLogger()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	srv, err := NewDoH(opts)
	if err != nil {
		t.Fatalf("NewDoH: %v", err)
	}
	addrs := srv.LocalAddrs()
	if len(addrs) == 0 {
		t.Fatal("no bound DoH addresses")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("DoH listener did not shut down")
		}
	})
	return addrs[0]
}

func TestDoT_AnswersOverTLS(t *testing.T) {
	addr := startDoT(t, TCPOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		AllowQuery: allowLoopback(t),
		TLS:        testTLS(t),
		Handler:    echoHandler(),
	})

	c := &dns.Client{
		Net:       "tcp-tls",
		Timeout:   5 * time.Second,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)

	resp, _, err := c.Exchange(m, addr.String())
	if err != nil {
		t.Fatalf("DoT exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("rcode=%s answers=%d, want NOERROR with 1 answer", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
}

// The handler must be told the query arrived over DoT, since policy and logging
// distinguish encrypted transports.
func TestDoT_ReportsProto(t *testing.T) {
	got := make(chan Proto, 1)
	addr := startDoT(t, TCPOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		AllowQuery: allowLoopback(t),
		TLS:        testTLS(t),
		Handler: HandlerFunc(func(ctx context.Context, req *Request) *dns.Msg {
			got <- req.Proto
			m := new(dns.Msg)
			m.SetReply(req.Msg)
			return m
		}),
	})

	c := &dns.Client{Net: "tcp-tls", Timeout: 5 * time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	if _, _, err := c.Exchange(m, addr.String()); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	select {
	case p := <-got:
		if p != ProtoDoT {
			t.Errorf("proto = %s, want dot", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler was never called")
	}
}

func TestDoT_RefusesClientOutsideACL(t *testing.T) {
	addr := startDoT(t, TCPOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		AllowQuery: netacl.New([]netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")}, false),
		TLS:        testTLS(t),
		Handler:    echoHandler(),
	})

	c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	if _, _, err := c.Exchange(m, addr.String()); err == nil {
		t.Error("expected a disallowed client to be dropped")
	}
}

// dohClient returns an HTTPS client that trusts the test certificate.
func dohClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}
}

func dohQuery(t *testing.T, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("packing query: %v", err)
	}
	return packed
}

func TestDoH_POST(t *testing.T) {
	addr := startDoH(t, DoHOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		TLS:        testTLS(t),
		AllowQuery: allowLoopback(t),
		Handler:    echoHandler(),
	})

	url := "https://" + addr.String() + "/dns-query"
	resp, err := dohClient().Post(url, "application/dns-message", bytes.NewReader(dohQuery(t, "example.com")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		t.Errorf("content-type = %q, want application/dns-message", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc == "" {
		t.Error("expected Cache-Control derived from the answer TTL")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	var answer dns.Msg
	if err := answer.Unpack(body); err != nil {
		t.Fatalf("unpacking response: %v", err)
	}
	if len(answer.Answer) != 1 {
		t.Errorf("answers = %d, want 1", len(answer.Answer))
	}
}

func TestDoH_GET(t *testing.T) {
	addr := startDoH(t, DoHOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		TLS:        testTLS(t),
		AllowQuery: allowLoopback(t),
		Handler:    echoHandler(),
	})

	// RFC 8484 §4.1: base64url, no padding.
	q := base64.RawURLEncoding.EncodeToString(dohQuery(t, "example.com"))
	url := "https://" + addr.String() + "/dns-query?dns=" + q

	resp, err := dohClient().Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var answer dns.Msg
	if err := answer.Unpack(body); err != nil {
		t.Fatalf("unpacking response: %v", err)
	}
	if len(answer.Answer) != 1 {
		t.Errorf("answers = %d, want 1", len(answer.Answer))
	}
}

func TestDoH_Rejects(t *testing.T) {
	addr := startDoH(t, DoHOptions{
		Addrs:      []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
		TLS:        testTLS(t),
		AllowQuery: allowLoopback(t),
		Handler:    echoHandler(),
	})
	base := "https://" + addr.String() + "/dns-query"
	client := dohClient()

	t.Run("wrong content type", func(t *testing.T) {
		resp, err := client.Post(base, "application/json", bytes.NewReader(dohQuery(t, "example.com")))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("garbage body", func(t *testing.T) {
		resp, err := client.Post(base, "application/dns-message", bytes.NewReader([]byte{0xde, 0xad}))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("missing dns parameter", func(t *testing.T) {
		resp, err := client.Get(base)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("oversized body", func(t *testing.T) {
		resp, err := client.Post(base, "application/dns-message", bytes.NewReader(make([]byte, maxDoHBody+10)))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})
}

// Subscriber policy keys on the client address, so a forwarding header from an
// untrusted peer must never be believed — otherwise any DoH client could claim
// another subscriber's identity and inherit their filtering.
func TestDoH_ClientAddressResolution(t *testing.T) {
	tests := []struct {
		name     string
		trusted  []netip.Prefix
		header   string
		wantAddr string
	}{
		{
			name:     "no trusted proxies means the header is ignored",
			trusted:  nil,
			header:   "198.51.100.42",
			wantAddr: "127.0.0.1",
		},
		{
			name:     "a trusted peer's header is believed",
			trusted:  []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
			header:   "198.51.100.42",
			wantAddr: "198.51.100.42",
		},
		{
			name:     "trusted peer with no header falls back to the peer",
			trusted:  []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
			header:   "",
			wantAddr: "127.0.0.1",
		},
		{
			name:     "an untrusted range does not grant the header",
			trusted:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			header:   "198.51.100.42",
			wantAddr: "127.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(chan netip.Addr, 1)
			addr := startDoH(t, DoHOptions{
				Addrs:          []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:0")},
				TLS:            testTLS(t),
				TrustedProxies: tt.trusted,
				Handler: HandlerFunc(func(ctx context.Context, req *Request) *dns.Msg {
					seen <- req.Client.Addr()
					m := new(dns.Msg)
					m.SetReply(req.Msg)
					return m
				}),
			})

			req, err := http.NewRequest(http.MethodPost,
				"https://"+addr.String()+"/dns-query",
				bytes.NewReader(dohQuery(t, "example.com")))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/dns-message")
			if tt.header != "" {
				req.Header.Set("X-Forwarded-For", tt.header)
			}

			resp, err := dohClient().Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			_ = resp.Body.Close()

			select {
			case got := <-seen:
				if got.String() != tt.wantAddr {
					t.Errorf("client address = %s, want %s", got, tt.wantAddr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("handler was never called")
			}
		})
	}
}

func TestMinTTL(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	if got := minTTL(m); got != 0 {
		t.Errorf("empty response TTL = %d, want 0", got)
	}

	m.Answer = append(m.Answer,
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Ttl: 300}},
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Ttl: 60}},
	)
	m.SetEdns0(1232, false)
	if got := minTTL(m); got != 60 {
		t.Errorf("TTL = %d, want the smallest (60), ignoring OPT", got)
	}
}
