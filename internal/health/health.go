// Package health owns the single decision "should this node be in the anycast
// set", and drives the routing daemon accordingly.
//
// The decision is deliberately concentrated here. Anything else that withdrew
// or advertised the prefix independently would make the node's routing state a
// function of several opinions, and the failure mode of that is a prefix that
// flaps between two components disagreeing.
//
// Withdrawal is fast and re-advertisement is slow. A dead node costs the
// traffic that was heading to it; a flapping prefix costs every node in the
// anycast set, because each withdrawal reconverges the whole network and
// in-flight queries are lost each time.
package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// State is the node's health.
type State uint8

const (
	// StateStarting is the state before the first check completes. The node
	// does not advertise: coming up and immediately attracting traffic before
	// knowing whether resolution works would blackhole it.
	StateStarting State = iota
	// StateHealthy means the node is fit to serve and should be advertised.
	StateHealthy
	// StateUnhealthy means the node must be withdrawn.
	StateUnhealthy
)

// String implements fmt.Stringer.
func (s State) String() string {
	switch s {
	case StateHealthy:
		return "healthy"
	case StateUnhealthy:
		return "unhealthy"
	default:
		return "starting"
	}
}

// Checker is one health probe.
//
// A check must exercise the real serving path. A probe that tests a private
// code path proves only that the probe works.
type Checker interface {
	Name() string
	Check(ctx context.Context) error
}

// Advertiser is the routing side of the decision.
//
// Declared here, in the consumer, so this package never depends on a particular
// routing daemon. The gobgp implementation lives alongside it.
type Advertiser interface {
	Advertise(ctx context.Context) error
	Withdraw(ctx context.Context) error
}

// Metrics counts health transitions.
type Metrics struct {
	Checks         atomic.Uint64
	CheckFailures  atomic.Uint64
	Advertisements atomic.Uint64
	Withdrawals    atomic.Uint64
	AdvertiseErrs  atomic.Uint64
	Flaps          atomic.Uint64
}

// Options configures a Monitor.
type Options struct {
	Checks     []Checker
	Advertiser Advertiser

	// Interval is how often checks run.
	Interval time.Duration
	// Timeout bounds a single check.
	Timeout time.Duration

	// FailureThreshold is how many consecutive failures withdraw the node.
	// Small on purpose: withdrawing a healthy node is cheap, since anycast
	// sends its traffic to a sibling.
	FailureThreshold int
	// SuccessThreshold is how many consecutive successes are needed to come
	// back. Larger than FailureThreshold, so recovery is harder than failure.
	SuccessThreshold int

	// MinHold is the shortest time a node stays withdrawn before it may
	// re-advertise, regardless of how healthy it looks.
	MinHold time.Duration
	// MaxHold caps the dampening backoff.
	MaxHold time.Duration
	// StableAfter is how long a node must serve without failing before a
	// subsequent failure is treated as a one-off rather than a flap. Without
	// it, dampening never escalates: a node that recovers cleanly each time
	// resets its own penalty and can oscillate indefinitely.
	StableAfter time.Duration

	Log     *slog.Logger
	Metrics *Metrics
	Now     func() time.Time
}

// Monitor runs the checks and drives the Advertiser.
type Monitor struct {
	opts Options

	mu           sync.Mutex
	state        State
	consecFail   int
	consecOK     int
	withdrawnAt  time.Time
	healthySince time.Time
	hold         time.Duration
	lastFailures []string
}

// New builds a Monitor.
func New(opts Options) (*Monitor, error) {
	if len(opts.Checks) == 0 {
		return nil, errors.New("health: at least one check is required")
	}
	if opts.Advertiser == nil {
		return nil, errors.New("health: an advertiser is required")
	}
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Second
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.FailureThreshold <= 0 {
		opts.FailureThreshold = 2
	}
	if opts.SuccessThreshold <= 0 {
		opts.SuccessThreshold = 3
	}
	if opts.MinHold <= 0 {
		opts.MinHold = 30 * time.Second
	}
	if opts.MaxHold <= 0 {
		opts.MaxHold = 5 * time.Minute
	}
	if opts.StableAfter <= 0 {
		opts.StableAfter = 10 * opts.MinHold
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Monitor{opts: opts, state: StateStarting, hold: opts.MinHold}, nil
}

// State reports the current health.
func (m *Monitor) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// LastFailures reports the check failures behind the current state, for the
// operator API.
func (m *Monitor) LastFailures() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.lastFailures...)
}

// Run evaluates health until ctx is cancelled, then withdraws.
//
// The withdrawal on shutdown is what makes a planned restart graceful: the
// prefix leaves before the listeners do, so traffic has already moved on by the
// time the node stops answering.
func (m *Monitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(m.opts.Interval)
	defer ticker.Stop()

	m.evaluate(ctx)
	for {
		select {
		case <-ctx.Done():
			m.shutdownWithdraw()
			return nil
		case <-ticker.C:
			m.evaluate(ctx)
		}
	}
}

// shutdownWithdraw pulls the prefix on the way out, with its own short timeout
// because the parent context is already cancelled.
func (m *Monitor) shutdownWithdraw() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	m.mu.Lock()
	advertising := m.state == StateHealthy
	m.state = StateUnhealthy
	m.mu.Unlock()

	if !advertising {
		return
	}
	m.opts.Log.Info("withdrawing anycast prefix for shutdown")
	if err := m.opts.Advertiser.Withdraw(ctx); err != nil {
		m.opts.Metrics.AdvertiseErrs.Add(1)
		m.opts.Log.Error("withdrawing on shutdown failed", slog.String("err", err.Error()))
		return
	}
	m.opts.Metrics.Withdrawals.Add(1)
}

// evaluate runs every check once and applies the result.
func (m *Monitor) evaluate(ctx context.Context) {
	failures := m.runChecks(ctx)
	m.opts.Metrics.Checks.Add(1)
	if len(failures) > 0 {
		m.opts.Metrics.CheckFailures.Add(1)
	}

	m.mu.Lock()
	m.lastFailures = failures
	if len(failures) == 0 {
		m.consecOK++
		m.consecFail = 0
	} else {
		m.consecFail++
		m.consecOK = 0
	}

	want := m.state
	switch {
	case m.consecFail >= m.opts.FailureThreshold && m.state != StateUnhealthy:
		want = StateUnhealthy
	case m.consecOK >= m.opts.SuccessThreshold && m.state != StateHealthy:
		if m.readyToReadvertiseLocked() {
			want = StateHealthy
		}
	}
	transition := want != m.state
	from := m.state
	if transition {
		m.state = want
		if want == StateUnhealthy {
			m.withdrawnAt = m.opts.Now()
		}
	}
	m.mu.Unlock()

	if !transition {
		return
	}
	m.apply(ctx, from, want, failures)
}

// readyToReadvertiseLocked implements the dampening: a node that has just been
// withdrawn must stay down for the hold period, and repeated flapping doubles
// that period.
func (m *Monitor) readyToReadvertiseLocked() bool {
	if m.withdrawnAt.IsZero() {
		return true
	}
	return m.opts.Now().Sub(m.withdrawnAt) >= m.hold
}

func (m *Monitor) apply(ctx context.Context, from, to State, failures []string) {
	switch to {
	case StateUnhealthy:
		m.opts.Log.Warn("node is unhealthy, withdrawing from the anycast set",
			slog.String("from", from.String()),
			slog.Any("failed_checks", failures))
		if err := m.opts.Advertiser.Withdraw(ctx); err != nil {
			m.opts.Metrics.AdvertiseErrs.Add(1)
			m.opts.Log.Error("withdraw failed", slog.String("err", err.Error()))
			return
		}
		m.opts.Metrics.Withdrawals.Add(1)

		m.mu.Lock()
		if from == StateHealthy {
			m.opts.Metrics.Flaps.Add(1)
			stable := !m.healthySince.IsZero() && m.opts.Now().Sub(m.healthySince) >= m.opts.StableAfter
			if stable {
				// Served cleanly for a long time before failing: a one-off,
				// not a flap, so it is not punished for previous history.
				m.hold = m.opts.MinHold
			} else {
				m.hold *= 2
				if m.hold > m.opts.MaxHold {
					m.hold = m.opts.MaxHold
				}
			}
		}
		m.mu.Unlock()

	case StateHealthy:
		m.opts.Log.Info("node is healthy, advertising to the anycast set",
			slog.String("from", from.String()))
		if err := m.opts.Advertiser.Advertise(ctx); err != nil {
			m.opts.Metrics.AdvertiseErrs.Add(1)
			m.opts.Log.Error("advertise failed", slog.String("err", err.Error()))
			m.mu.Lock()
			m.state = from
			m.mu.Unlock()
			return
		}
		m.opts.Metrics.Advertisements.Add(1)

		m.mu.Lock()
		m.healthySince = m.opts.Now()
		m.mu.Unlock()
	}
}

func (m *Monitor) runChecks(ctx context.Context) []string {
	var failures []string
	for _, c := range m.opts.Checks {
		cctx, cancel := context.WithTimeout(ctx, m.opts.Timeout)
		err := c.Check(cctx)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", c.Name(), err))
		}
	}
	return failures
}
