// Package netacl enforces source-address access control on the management and
// metrics planes.
//
// The policy is default-deny with no allow-all form: config validation rejects
// an empty allow list on a non-loopback listener. Enforcement happens at
// Accept, before the TLS handshake, so a disallowed peer costs no handshake and
// learns nothing about the box.
package netacl

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"

	"github.com/JoshFinlayAU/cgdns/internal/prefixmap"
)

// ACL is an immutable source-address allow list. It is safe for concurrent use.
type ACL struct {
	allow         *prefixmap.Map[struct{}]
	allowLoopback bool
}

// New builds an ACL from allow prefixes. allowLoopback implicitly permits
// 127.0.0.0/8 and ::1, making a loopback-only listener usable with no ACL.
func New(allow []netip.Prefix, allowLoopback bool) *ACL {
	m := prefixmap.New[struct{}]()
	for _, p := range allow {
		m.Insert(p, struct{}{})
	}
	return &ACL{allow: m, allowLoopback: allowLoopback}
}

// Allows reports whether addr may reach the protected plane.
func (a *ACL) Allows(addr netip.Addr) bool {
	if a == nil {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if a.allowLoopback && addr.IsLoopback() {
		return true
	}
	return a.allow.Contains(addr)
}

// Len reports the number of allow prefixes.
func (a *ACL) Len() int {
	if a == nil {
		return 0
	}
	return a.allow.Len()
}

// Listener wraps inner so Accept drops connections from disallowed sources.
// A rejection is never surfaced as an error: a blocked peer is routine, not a
// listener failure.
func Listener(inner net.Listener, acl *ACL, log *slog.Logger) net.Listener {
	return &aclListener{Listener: inner, acl: acl, log: log}
}

type aclListener struct {
	net.Listener
	acl *ACL
	log *slog.Logger
}

func (l *aclListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		addr, ok := addrOf(c.RemoteAddr())
		if ok && l.acl.Allows(addr) {
			return c, nil
		}
		if l.log != nil {
			l.log.Warn("management connection refused by source ACL",
				slog.String("remote", c.RemoteAddr().String()),
				slog.String("local", c.LocalAddr().String()))
		}
		_ = c.Close()
	}
}

// Middleware is defence in depth behind Listener, for a listener wired up
// without the ACL wrapper.
//
// It reads only the real transport peer address. Proxy headers are not
// consulted: a spoofable client address on the admin plane is an ACL bypass.
func Middleware(acl *ACL, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, ok := addrOf2(r.RemoteAddr)
		if !ok || !acl.Allows(addr) {
			if log != nil {
				log.Warn("management request refused by source ACL",
					slog.String("remote", r.RemoteAddr),
					slog.String("path", r.URL.Path))
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func addrOf(a net.Addr) (netip.Addr, bool) {
	switch v := a.(type) {
	case *net.TCPAddr:
		ap, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.Addr{}, false
		}
		return ap.Unmap(), true
	case *net.UDPAddr:
		ap, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.Addr{}, false
		}
		return ap.Unmap(), true
	default:
		return addrOf2(a.String())
	}
}

func addrOf2(hostport string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(hostport); err == nil {
		return ap.Addr().Unmap(), true
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}
