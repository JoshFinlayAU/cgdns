//go:build linux

package transport

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePortControl sets SO_REUSEPORT so several sockets can bind the same
// address and the kernel load-balances datagrams across them.
//
// This is how a single address scales past one socket's receive queue: one
// socket per CPU, each with its own reader goroutine, so a busy resolver is
// not bottlenecked on a single kernel queue and the wakeups spread across
// cores instead of thundering onto one.
//
// SO_REUSEADDR is deliberately NOT set alongside it. On Linux the two together
// would let an unrelated process silently join the group and steal a share of
// production queries.
func reusePortControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return opErr
}

// reusePortSupported reports whether multiple sockets per address are usable.
const reusePortSupported = true
