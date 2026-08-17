package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// challengePrefix is the only path an HTTP-01 responder ever serves (RFC 8555
// §8.3).
const challengePrefix = "/.well-known/acme-challenge/"

// HTTP01 answers http-01 challenges by binding a port for as long as the
// challenge takes and not one moment longer.
//
// The port stays shut the rest of the time. A resolver's addresses are reachable
// by every subscriber and, because the covering prefix is announced, by the
// internet at large; leaving a web server on one of them all year to serve a
// file for ten seconds a quarter is attack surface bought for nothing. Opening
// on demand also means a misconfiguration fails closed — there is no listener to
// find if the certificate is never renewed.
type HTTP01 struct {
	// Addrs are bound while a challenge is outstanding, conventionally :80.
	// The CA chooses which address to validate against, so every address the
	// name resolves to has to answer.
	Addrs []string
	// Timeout bounds how long the port may stay open, whatever the CA does.
	// A validation that never completes must not leave a listener behind.
	Timeout time.Duration

	Log *slog.Logger

	mu sync.Mutex
}

// Kind implements Solver.
func (h *HTTP01) Kind() string { return "http-01" }

// Present binds the listeners and returns a cleanup that closes them.
func (h *HTTP01) Present(ctx context.Context, domain, token, keyAuth string) (func(), error) {
	if len(h.Addrs) == 0 {
		return nil, errors.New("acme: http-01 needs at least one listen address")
	}
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}

	// One challenge at a time: two orders would otherwise race for the port and
	// the loser would fail for a reason that looks nothing like the cause.
	h.mu.Lock()

	mux := http.NewServeMux()
	mux.HandleFunc(challengePrefix, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		if strings.TrimPrefix(r.URL.Path, challengePrefix) != token {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(keyAuth))
	})
	// Anything else gets nothing. This server exists to serve exactly one file.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       5 * time.Second,
	}

	var (
		listeners []net.Listener
		wg        sync.WaitGroup
	)
	closeAll := func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		for _, l := range listeners {
			_ = l.Close()
		}
		wg.Wait()
	}

	for _, addr := range h.Addrs {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			closeAll()
			h.mu.Unlock()
			return nil, fmt.Errorf("binding %s for the http-01 challenge: %w", addr, err)
		}
		listeners = append(listeners, l)
		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			_ = srv.Serve(l)
		}(l)
	}

	opened := time.Now()
	log.Info("http-01 challenge port open",
		slog.Any("addrs", h.Addrs), slog.String("domain", domain))

	// A hard deadline, independent of the caller: if the order stalls, the port
	// still closes.
	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() {
			close(done)
			closeAll()
			h.mu.Unlock()
			log.Info("http-01 challenge port closed",
				slog.Any("addrs", h.Addrs),
				slog.Duration("open_for", time.Since(opened)))
		})
	}
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			stop()
		case <-time.After(timeout):
			log.Warn("http-01 challenge timed out, closing the port anyway",
				slog.Duration("timeout", timeout))
			stop()
		}
	}()

	return stop, nil
}
