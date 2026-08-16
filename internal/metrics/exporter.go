// Package metrics exposes counters in Prometheus text exposition format.
//
// Nothing here is labelled by QNAME or client address. Metric labels are
// retained, high-cardinality and widely readable, so a browsing history
// reconstructed from a series is the same privacy failure as one reconstructed
// from logs.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind is the Prometheus metric type.
type Kind string

const (
	Counter Kind = "counter"
	Gauge   Kind = "gauge"
)

// Source reads a single metric value at scrape time, keeping the hot path to
// an atomic increment.
type Source struct {
	Name string
	Help string
	Kind Kind
	Read func() float64
}

// Registry holds the metric sources.
type Registry struct {
	mu      sync.RWMutex
	sources []Source
	started time.Time
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{started: time.Now()}
}

// Register adds sources. It is safe to call before serving; not intended to be
// called concurrently with a scrape.
func (r *Registry) Register(s ...Source) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources = append(r.sources, s...)
}

// Export emits the exposition format.
func (r *Registry) Export(w io.Writer) error {
	r.mu.RLock()
	srcs := make([]Source, len(r.sources))
	copy(srcs, r.sources)
	r.mu.RUnlock()

	sort.Slice(srcs, func(i, j int) bool { return srcs[i].Name < srcs[j].Name })

	var b strings.Builder
	for _, s := range srcs {
		if s.Help != "" {
			fmt.Fprintf(&b, "# HELP %s %s\n", s.Name, s.Help)
		}
		fmt.Fprintf(&b, "# TYPE %s %s\n", s.Name, s.Kind)
		fmt.Fprintf(&b, "%s %g\n", s.Name, s.Read())
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(&b, "# TYPE cgdns_uptime_seconds counter\ncgdns_uptime_seconds %g\n", time.Since(r.started).Seconds())
	fmt.Fprintf(&b, "# TYPE cgdns_goroutines gauge\ncgdns_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(&b, "# TYPE cgdns_memory_heap_bytes gauge\ncgdns_memory_heap_bytes %d\n", ms.HeapAlloc)
	fmt.Fprintf(&b, "# TYPE cgdns_gc_pause_total_seconds counter\ncgdns_gc_pause_total_seconds %g\n", float64(ms.PauseTotalNs)/1e9)

	_, err := io.WriteString(w, b.String())
	return err
}

// Handler serves the registry over HTTP.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := r.Export(w); err != nil {
			return
		}
	})
}
