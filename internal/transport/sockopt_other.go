//go:build !linux

package transport

import "syscall"

// reusePortControl is a no-op on platforms without SO_REUSEPORT semantics we
// rely on. The daemon still runs — one socket per address instead of several —
// which is fine for development on a laptop. Production is Linux.
func reusePortControl(network, address string, c syscall.RawConn) error { return nil }

// reusePortSupported reports whether multiple sockets per address are usable.
const reusePortSupported = false
