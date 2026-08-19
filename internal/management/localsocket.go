package management

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// The local socket is how an operator on the box manages the daemon.
//
// It carries no token. The file's mode is the credential: it is created
// root-owned and 0600, so opening it already requires the privilege that would
// let you read the config, replace the binary, or stop the service. Demanding a
// bearer token on top of that protects nothing — it just leaves a long-lived
// admin secret sitting in a file or a shell history for an attacker who is by
// then past caring.
//
// It is a unix socket rather than loopback TCP precisely so that reasoning
// holds: a TCP port is reachable by any local user and, given a routing
// mistake, from off the box. A socket is reachable by whoever the filesystem
// says, and by nobody else.
const localSocketMode = 0o600

type localConnKey struct{}

// withLocal marks a request as having arrived on the local socket.
func withLocal(ctx context.Context) context.Context {
	return context.WithValue(ctx, localConnKey{}, true)
}

// isLocal reports whether a request arrived on the local socket.
func isLocal(ctx context.Context) bool {
	v, _ := ctx.Value(localConnKey{}).(bool)
	return v
}

// bindLocal creates the management socket, replacing a stale one left behind by
// a crash — a socket file outlives the process that made it, and refusing to
// start because of one would turn an unclean shutdown into an outage.
func (s *Server) bindLocal(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("management: creating the socket directory: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("management: clearing the stale socket %s: %w", path, err)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("management: binding %s: %w", path, err)
	}
	// Set the mode explicitly rather than trusting the umask: the mode is the
	// only thing standing between this socket and every user on the box.
	if err := os.Chmod(path, localSocketMode); err != nil {
		_ = ln.Close()
		return fmt.Errorf("management: securing %s: %w", path, err)
	}

	s.localLn = ln
	s.localPath = path
	s.opts.Log.Info("management local socket listening",
		slog.String("path", path),
		slog.String("mode", fmt.Sprintf("%#o", localSocketMode)))
	return nil
}

// peerIsPrivileged reports whether the far end of a unix connection may
// administer this node without a token.
//
// Root qualifies, and so does the uid the daemon itself runs as: the socket is
// mode 0600 and owned by that uid, so those two are already the only peers the
// kernel will let connect, and that uid can read the node's keys and state
// directly in any case. Refusing it would only mean the account that owns the
// daemon cannot operate it.
func peerIsPrivileged(c net.Conn) (bool, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false, err
	}
	var (
		cred    *syscall.Ucred
		credErr error
	)
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return false, err
	}
	if credErr != nil {
		return false, credErr
	}
	return cred.Uid == 0 || cred.Uid == uint32(os.Getuid()), nil
}
