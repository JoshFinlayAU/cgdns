package netacl

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("bad test prefix %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

func TestAllows(t *testing.T) {
	tests := []struct {
		name          string
		allow         []string
		allowLoopback bool
		addr          string
		want          bool
	}{
		{"allowed v4", []string{"10.20.0.0/24"}, false, "10.20.0.5", true},
		{"denied v4", []string{"10.20.0.0/24"}, false, "10.20.1.5", false},
		{"allowed v6", []string{"2001:db8::/32"}, false, "2001:db8::1", true},
		{"denied v6", []string{"2001:db8::/32"}, false, "2001:db9::1", false},
		{"loopback implicitly allowed", nil, true, "127.0.0.1", true},
		{"v6 loopback implicitly allowed", nil, true, "::1", true},
		{"loopback denied when not implicit", nil, false, "127.0.0.1", false},
		{"v4-mapped matches v4 rule", []string{"10.20.0.0/24"}, false, "::ffff:10.20.0.5", true},
		// The whole design: an empty allow list denies, it does not permit.
		{"empty allow list denies", nil, false, "10.20.0.5", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			acl := New(prefixes(t, tt.allow...), tt.allowLoopback)
			addr, err := netip.ParseAddr(tt.addr)
			if err != nil {
				t.Fatalf("bad test address: %v", err)
			}
			if got := acl.Allows(addr); got != tt.want {
				t.Errorf("Allows(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// A nil ACL must fail closed. If a listener is ever wired up without one, the
// failure mode has to be "nobody gets in", not "everybody does".
func TestNilACL_DeniesEverything(t *testing.T) {
	var acl *ACL
	if acl.Allows(netip.MustParseAddr("127.0.0.1")) {
		t.Error("a nil ACL must deny")
	}
	if acl.Len() != 0 {
		t.Error("a nil ACL should report zero prefixes")
	}
}

func TestListener_DropsDisallowedPeers(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()

	// Deny loopback so our own dial is rejected.
	acl := New(prefixes(t, "10.99.0.0/24"), false)
	ln := Listener(inner, acl, nil)

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	// The connection is accepted by the kernel then immediately closed by the
	// ACL wrapper, so the read returns EOF rather than data.
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Error("expected the disallowed connection to be closed")
	}

	select {
	case <-accepted:
		t.Error("Accept must not surface a connection from a disallowed source")
	case <-time.After(200 * time.Millisecond):
		// Correct: nothing reached the server.
	}
}

func TestListener_PassesAllowedPeers(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = inner.Close() }()

	acl := New(nil, true) // loopback implicitly allowed
	ln := Listener(inner, acl, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("ok"))
		_ = c.Close()
	}()

	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("expected the allowed connection to be served: %v", err)
	}
	if string(buf) != "ok" {
		t.Errorf("got %q, want %q", buf, "ok")
	}
	<-done
}

func TestMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		allow      []string
		remoteAddr string
		wantStatus int
	}{
		{"allowed", []string{"10.20.0.0/24"}, "10.20.0.5:12345", http.StatusOK},
		{"denied", []string{"10.20.0.0/24"}, "203.0.113.9:12345", http.StatusForbidden},
		{"unparseable remote denied", []string{"10.20.0.0/24"}, "garbage", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			acl := New(prefixes(t, tt.allow...), false)
			h := Middleware(acl, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

// Proxy headers must never influence the management ACL: a spoofable client
// address on the admin plane is a straight ACL bypass.
func TestMiddleware_IgnoresForwardedHeaders(t *testing.T) {
	acl := New(prefixes(t, "10.20.0.0/24"), false)
	h := Middleware(acl, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	req.Header.Set("X-Forwarded-For", "10.20.0.5")
	req.Header.Set("X-Real-IP", "10.20.0.5")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — a spoofed X-Forwarded-For must not grant access", rec.Code)
	}
}

func BenchmarkAllows(b *testing.B) {
	ps := make([]netip.Prefix, 0, 256)
	for i := 0; i < 256; i++ {
		ps = append(ps, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16))
	}
	acl := New(ps, true)
	addr := netip.AddrFrom4([4]byte{10, 128, 1, 1})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acl.Allows(addr)
	}
}
