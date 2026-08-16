// Package privacy keeps subscriber-identifying detail out of logs and metrics.
//
// The rule it enforces: never log or metric-label a full QNAME above debug
// level. A resolver sees every site every subscriber visits, and its logs are
// among the most sensitive data a carrier holds. Logs get the registrable
// domain; metric labels get that at most, and usually nothing.
package privacy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Redact reduces a QNAME to its registrable domain (eTLD+1) — "example.com"
// for "very.secret.host.example.com". This is the default for log lines: it
// keeps the zone an operator needs to debug and drops what the subscriber was
// doing.
func Redact(qname string) string {
	name := strings.TrimSuffix(strings.ToLower(qname), ".")
	if name == "" {
		return "."
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return name + "."
	}
	return reg + "."
}

// Hash returns a short stable hash of the full name, for correlating log lines
// without the name appearing.
//
// It is unkeyed, so it defends against casual disclosure only, not against an
// attacker who can hash candidate names. A threat model needing that requires
// an HMAC with a rotated per-node key.
func Hash(qname string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(qname)))
	return hex.EncodeToString(sum[:6])
}

// RedactAddr reduces a client address to its network, so a log line can say
// which subscriber range misbehaved without pinning it to one household.
// v4 keeps the /24, v6 the /48 — the usual assignment boundary.
func RedactAddr(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 && strings.Count(addr, ":") == 1 {
		addr = addr[:i]
	}
	if strings.Contains(addr, ".") {
		parts := strings.Split(addr, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
		}
		return addr
	}
	parts := strings.Split(addr, ":")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ":") + "::/48"
	}
	return addr
}
