package health

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/JoshFinlayAU/cgdns/internal/transport"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// fakeAdvertiser records what the monitor asked the routing daemon to do.
type fakeAdvertiser struct {
	mu         sync.Mutex
	advertised bool
	calls      []string
	failNext   error
}

func (f *fakeAdvertiser) Advertise(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		f.calls = append(f.calls, "advertise-failed")
		return err
	}
	f.advertised = true
	f.calls = append(f.calls, "advertise")
	return nil
}

func (f *fakeAdvertiser) Withdraw(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.advertised = false
	f.calls = append(f.calls, "withdraw")
	return nil
}

func (f *fakeAdvertiser) history() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeAdvertiser) isAdvertised() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.advertised
}

// toggleCheck fails or passes on demand.
type toggleCheck struct {
	mu   sync.Mutex
	fail bool
}

func (t *toggleCheck) Name() string { return "toggle" }
func (t *toggleCheck) Check(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fail {
		return errors.New("simulated failure")
	}
	return nil
}
func (t *toggleCheck) set(fail bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fail = fail
}

// clock is a controllable time source, so dampening is tested without sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)} }
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newMonitor(t *testing.T, chk Checker, adv Advertiser, clk *clock, tune ...func(*Options)) *Monitor {
	t.Helper()
	opts := Options{
		Checks:           []Checker{chk},
		Advertiser:       adv,
		Interval:         time.Hour, // tests drive evaluate directly
		FailureThreshold: 2,
		SuccessThreshold: 3,
		MinHold:          30 * time.Second,
		MaxHold:          5 * time.Minute,
		Log:              quietLogger(),
		Now:              clk.Now,
	}
	for _, f := range tune {
		f(&opts)
	}
	m, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// A node must not advertise before it knows it can resolve. Coming up and
// attracting traffic first would blackhole it.
func TestMonitor_DoesNotAdvertiseBeforeFirstSuccess(t *testing.T) {
	adv := &fakeAdvertiser{}
	chk := &toggleCheck{fail: true}
	m := newMonitor(t, chk, adv, newClock())

	if m.State() != StateStarting {
		t.Errorf("initial state = %s, want starting", m.State())
	}
	if adv.isAdvertised() {
		t.Error("must not advertise before any check has passed")
	}
}

func TestMonitor_AdvertisesAfterSuccessThreshold(t *testing.T) {
	adv := &fakeAdvertiser{}
	chk := &toggleCheck{}
	m := newMonitor(t, chk, adv, newClock())
	ctx := context.Background()

	m.evaluate(ctx)
	m.evaluate(ctx)
	if adv.isAdvertised() {
		t.Error("advertised before reaching the success threshold")
	}
	m.evaluate(ctx)
	if !adv.isAdvertised() {
		t.Error("should be advertising after 3 consecutive successes")
	}
	if m.State() != StateHealthy {
		t.Errorf("state = %s, want healthy", m.State())
	}
}

// Withdrawal is fast: a couple of failures and the node takes itself out.
func TestMonitor_WithdrawsQuickly(t *testing.T) {
	adv := &fakeAdvertiser{}
	chk := &toggleCheck{}
	clk := newClock()
	m := newMonitor(t, chk, adv, clk)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		m.evaluate(ctx)
	}
	if !adv.isAdvertised() {
		t.Fatal("expected the node to be advertising")
	}

	chk.set(true)
	m.evaluate(ctx)
	if !adv.isAdvertised() {
		t.Error("one failure should not withdraw; the threshold is 2")
	}
	m.evaluate(ctx)
	if adv.isAdvertised() {
		t.Error("two consecutive failures should have withdrawn the node")
	}
	if m.State() != StateUnhealthy {
		t.Errorf("state = %s, want unhealthy", m.State())
	}
	if len(m.LastFailures()) == 0 {
		t.Error("the failing check should be reported for the operator")
	}
}

// Re-advertisement is dampened: a node that recovers immediately must still
// wait out the hold, because a flapping prefix reconverges the whole anycast
// set every time.
func TestMonitor_ReadvertisementIsDampened(t *testing.T) {
	adv := &fakeAdvertiser{}
	chk := &toggleCheck{}
	clk := newClock()
	m := newMonitor(t, chk, adv, clk)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		m.evaluate(ctx)
	}
	chk.set(true)
	m.evaluate(ctx)
	m.evaluate(ctx)
	if adv.isAdvertised() {
		t.Fatal("expected withdrawal")
	}

	// Recovers instantly, but the hold has not elapsed.
	chk.set(false)
	for i := 0; i < 5; i++ {
		m.evaluate(ctx)
	}
	if adv.isAdvertised() {
		t.Error("re-advertised before the hold elapsed; dampening is not working")
	}

	// Past the hold (doubled to 60s after the first flap), it comes back.
	clk.advance(90 * time.Second)
	for i := 0; i < 3; i++ {
		m.evaluate(ctx)
	}
	if !adv.isAdvertised() {
		t.Error("should have re-advertised once the hold elapsed")
	}
}

// Repeated flapping must take the node out for progressively longer.
func TestMonitor_HoldBacksOffOnRepeatedFlaps(t *testing.T) {
	adv := &fakeAdvertiser{}
	chk := &toggleCheck{}
	clk := newClock()
	m := newMonitor(t, chk, adv, clk)
	ctx := context.Background()

	flap := func() {
		chk.set(false)
		for i := 0; i < 3; i++ {
			m.evaluate(ctx)
		}
		chk.set(true)
		m.evaluate(ctx)
		m.evaluate(ctx)
	}

	flap()
	m.mu.Lock()
	first := m.hold
	m.mu.Unlock()

	clk.advance(10 * time.Minute)
	flap()
	m.mu.Lock()
	second := m.hold
	m.mu.Unlock()

	if second <= first {
		t.Errorf("hold did not grow across flaps: %s then %s", first, second)
	}
	if second > 5*time.Minute {
		t.Errorf("hold %s exceeded MaxHold", second)
	}
}

// A failed advertise must not leave the monitor believing it is advertising.
func TestMonitor_FailedAdvertiseDoesNotClaimHealthy(t *testing.T) {
	adv := &fakeAdvertiser{failNext: errors.New("gobgpd is down")}
	chk := &toggleCheck{}
	m := newMonitor(t, chk, adv, newClock())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		m.evaluate(ctx)
	}
	if m.State() == StateHealthy {
		t.Error("state must not be healthy when the advertise call failed")
	}
	if adv.isAdvertised() {
		t.Error("nothing was actually advertised")
	}
}

// Shutdown withdraws before the listeners stop, so a planned restart moves
// traffic away rather than blackholing it.
func TestMonitor_WithdrawsOnShutdown(t *testing.T) {
	adv := &fakeAdvertiser{}
	chk := &toggleCheck{}
	m := newMonitor(t, chk, adv, newClock(), func(o *Options) { o.Interval = 10 * time.Millisecond })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = m.Run(ctx); close(done) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !adv.isAdvertised() {
		time.Sleep(5 * time.Millisecond)
	}
	if !adv.isAdvertised() {
		t.Fatal("expected the node to start advertising")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if adv.isAdvertised() {
		t.Error("shutdown must withdraw the prefix")
	}
	hist := adv.history()
	if hist[len(hist)-1] != "withdraw" {
		t.Errorf("last routing action = %q, want withdraw", hist[len(hist)-1])
	}
}

func TestNew_Rejects(t *testing.T) {
	adv := &fakeAdvertiser{}
	if _, err := New(Options{Advertiser: adv}); err == nil {
		t.Error("a monitor with no checks must be refused")
	}
	if _, err := New(Options{Checks: []Checker{&toggleCheck{}}}); err == nil {
		t.Error("a monitor with no advertiser must be refused")
	}
}

// The resolve check must exercise the real handler, and must fail when the
// resolver fails.
func TestResolveCheck(t *testing.T) {
	client := netip.MustParseAddrPort("127.0.0.1:0")

	tests := []struct {
		name    string
		handler transport.Handler
		require bool
		wantErr bool
	}{
		{
			name: "answer returned",
			handler: transport.HandlerFunc(func(ctx context.Context, req *transport.Request) *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(req.Msg)
				m.Ns = append(m.Ns, &dns.NS{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
					Ns:  "a.root-servers.net.",
				})
				m.Answer = append(m.Answer, &dns.NS{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
					Ns:  "a.root-servers.net.",
				})
				return m
			}),
			require: true,
		},
		{
			name: "servfail",
			handler: transport.HandlerFunc(func(ctx context.Context, req *transport.Request) *dns.Msg {
				m := new(dns.Msg)
				m.SetRcode(req.Msg, dns.RcodeServerFailure)
				return m
			}),
			wantErr: true,
		},
		{
			name: "no response at all",
			handler: transport.HandlerFunc(func(ctx context.Context, req *transport.Request) *dns.Msg {
				return nil
			}),
			wantErr: true,
		},
		{
			name: "noerror but empty when an answer is required",
			handler: transport.HandlerFunc(func(ctx context.Context, req *transport.Request) *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(req.Msg)
				return m
			}),
			require: true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &ResolveCheck{
				Handler:       tt.handler,
				QName:         ".",
				QType:         dns.TypeNS,
				RequireAnswer: tt.require,
				Client:        client,
			}
			err := c.Check(context.Background())
			if tt.wantErr && err == nil {
				t.Error("expected the check to fail")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected the check to pass, got %v", err)
			}
		})
	}
}

func TestRootCheck_Name(t *testing.T) {
	c := RootCheck(transport.HandlerFunc(func(context.Context, *transport.Request) *dns.Msg { return nil }),
		netip.MustParseAddrPort("127.0.0.1:0"))
	if c.Name() != "root-ns" {
		t.Errorf("name = %q", c.Name())
	}
	if c.QName != "." || c.QType != dns.TypeNS {
		t.Errorf("root check should probe the root NS, got %s %s", c.QName, dns.TypeToString[c.QType])
	}
}

func TestStateString(t *testing.T) {
	for s, want := range map[State]string{
		StateStarting:  "starting",
		StateHealthy:   "healthy",
		StateUnhealthy: "unhealthy",
	} {
		if got := s.String(); got != want {
			t.Errorf("State(%d) = %q, want %q", s, got, want)
		}
	}
}

func TestPathFor(t *testing.T) {
	tests := []struct {
		prefix  string
		wantErr bool
	}{
		{"10.255.0.53/32", false},
		{"fd51:13:53::53/128", false},
		{"10.255.0.0/24", false},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			t.Parallel()
			p := netip.MustParsePrefix(tt.prefix)
			path, err := pathFor(p)
			if tt.wantErr {
				if err == nil {
					t.Error("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("pathFor: %v", err)
			}
			if path.GetNlri().GetPrefix().GetPrefix() != p.Addr().String() {
				t.Errorf("nlri prefix = %q, want %q", path.GetNlri().GetPrefix().GetPrefix(), p.Addr())
			}
			if got := path.GetNlri().GetPrefix().GetPrefixLen(); got != uint32(p.Bits()) {
				t.Errorf("prefix len = %d, want %d", got, p.Bits())
			}
			if len(path.GetPattrs()) != 2 {
				t.Errorf("expected origin and next-hop attributes, got %d", len(path.GetPattrs()))
			}
		})
	}
}
