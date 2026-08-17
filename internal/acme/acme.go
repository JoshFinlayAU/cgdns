// Package acme obtains and renews the certificate the encrypted transports
// present to subscribers.
//
// A resolver serving DoT, DoH and DoQ needs a certificate a subscriber's device
// will trust, which means a public CA and a renewal every few months. Doing that
// by hand is a scheduled outage waiting to happen: the failure is silent until
// the day it expires, and then every encrypted client stops resolving at once.
//
// Two challenge types are supported and the choice is not a preference. DNS-01
// is used when a provider is configured, because it needs nothing listening.
// Otherwise HTTP-01 is used, and the port it needs is opened only for the
// seconds the challenge takes and closed again immediately — a permanently open
// port 80 on an anycast address that subscribers reach is attack surface bought
// for nothing.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// Metrics counts certificate lifecycle events.
type Metrics struct {
	Renewals   atomic.Uint64
	Failures   atomic.Uint64
	NotAfter   atomic.Int64
	LastAttempt atomic.Int64
	// ChallengeSeconds records how long the last HTTP-01 listener was open.
	// It is the exposure window, so it is worth being able to alert on.
	ChallengeSeconds atomic.Int64
}

// Solver answers one ACME challenge.
type Solver interface {
	// Kind is the ACME challenge type this solver answers.
	Kind() string
	// Present makes the challenge answerable and returns a cleanup function.
	// The cleanup runs whether validation succeeded or not.
	Present(ctx context.Context, domain, token, keyAuth string) (func(), error)
}

// Options configures a Manager.
type Options struct {
	// Domains are the names the certificate must cover. The first is the
	// common name.
	Domains []string
	// Email is the ACME account contact. A CA uses it to warn about expiry,
	// which is the backstop for this package failing quietly.
	Email string
	// DirectoryURL is the ACME endpoint.
	DirectoryURL string

	CertFile       string
	KeyFile        string
	AccountKeyFile string

	// RenewBefore is how long before expiry to renew. Renewing early is free;
	// renewing late is an outage.
	RenewBefore time.Duration
	// Solver answers the challenge.
	Solver Solver
	// Roots is the trust store a held certificate is checked against. Nil means
	// the system store, which is what a subscriber's device uses. Tests supply
	// their own.
	Roots *x509.CertPool

	Log     *slog.Logger
	Metrics *Metrics
	// now exists so tests can control renewal decisions.
	now func() time.Time
}

// Manager keeps a certificate current.
type Manager struct {
	opts Options
	mu   sync.RWMutex
	cert *tls.Certificate
}

// ErrNoSolver means no challenge type was configured.
var ErrNoSolver = errors.New("acme: no challenge solver configured")

// New builds a Manager and loads any certificate already on disk, so a restart
// does not require the CA to be reachable.
func New(opts Options) (*Manager, error) {
	if len(opts.Domains) == 0 {
		return nil, errors.New("acme: at least one domain is required")
	}
	if opts.CertFile == "" || opts.KeyFile == "" {
		return nil, errors.New("acme: cert_file and key_file are required")
	}
	if opts.AccountKeyFile == "" {
		return nil, errors.New("acme: account_key_file is required")
	}
	if opts.Solver == nil {
		return nil, ErrNoSolver
	}
	if opts.DirectoryURL == "" {
		opts.DirectoryURL = xacme.LetsEncryptURL
	}
	if opts.RenewBefore <= 0 {
		opts.RenewBefore = 30 * 24 * time.Hour
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = &Metrics{}
	}
	if opts.now == nil {
		opts.now = time.Now
	}

	// Check now that the certificate can actually be written. Discovering it
	// after a successful order wastes an issuance against the CA's rate limit,
	// which is counted per registered domain and takes a week to recover.
	for _, f := range []string{opts.CertFile, opts.KeyFile, opts.AccountKeyFile} {
		if err := checkWritable(filepath.Dir(f)); err != nil {
			return nil, fmt.Errorf("acme cannot write %s: %w", f, err)
		}
	}

	m := &Manager{opts: opts}
	if cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			cert.Leaf = leaf
			m.mu.Lock()
			m.cert = &cert
			m.mu.Unlock()
			opts.Metrics.NotAfter.Store(leaf.NotAfter.Unix())
		}
	}
	return m, nil
}

// GetCertificate serves tls.Config.GetCertificate, so a renewal is picked up by
// the next handshake without restarting a listener or dropping a connection.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, errors.New("acme: no certificate available yet")
	}
	return m.cert, nil
}

// Current returns the certificate in use, or nil.
func (m *Manager) Current() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert
}

// NeedsRenewal reports whether the held certificate is missing, expiring, or no
// longer covers the configured names.
func (m *Manager) NeedsRenewal() bool {
	m.mu.RLock()
	cert := m.cert
	m.mu.RUnlock()

	if cert == nil || cert.Leaf == nil {
		return true
	}
	if m.opts.now().Add(m.opts.RenewBefore).After(cert.Leaf.NotAfter) {
		return true
	}
	// A certificate no public CA vouches for is a placeholder — the interim one
	// a node is given so its listeners can start before it has ever reached a
	// CA. It can be valid for years and name the right hosts, so expiry and
	// hostname checks both pass and nothing would ever replace it, leaving
	// subscribers with a certificate their devices reject and no signal that
	// anything is wrong. The check is the one the subscriber's device makes.
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(c)
		}
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:         m.opts.Roots,
		Intermediates: intermediates,
		DNSName:       m.opts.Domains[0],
	}); err != nil {
		return true
	}
	// A name added to the config is as good a reason to reissue as expiry.
	for _, d := range m.opts.Domains {
		if err := cert.Leaf.VerifyHostname(d); err != nil {
			return true
		}
	}
	return false
}

// Run obtains a certificate when one is needed and keeps it current until ctx
// is cancelled.
//
// A failure is logged and retried rather than returned: the daemon must keep
// serving on the certificate it already has, and an expiring certificate is a
// problem for tomorrow while a resolver that will not start is a problem now.
func (m *Manager) Run(ctx context.Context, check time.Duration) error {
	if check <= 0 {
		check = 12 * time.Hour
	}
	if m.NeedsRenewal() {
		if err := m.Obtain(ctx); err != nil {
			m.opts.Log.Error("could not obtain a certificate, continuing with what is on disk",
				slog.String("err", err.Error()))
		}
	}

	t := time.NewTicker(check)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if !m.NeedsRenewal() {
				continue
			}
			if err := m.Obtain(ctx); err != nil {
				m.opts.Log.Error("certificate renewal failed, will retry",
					slog.String("err", err.Error()))
			}
		}
	}
}

// Obtain runs one full ACME order.
func (m *Manager) Obtain(ctx context.Context) error {
	m.opts.Metrics.LastAttempt.Store(m.opts.now().Unix())

	accountKey, err := m.accountKey()
	if err != nil {
		m.opts.Metrics.Failures.Add(1)
		return fmt.Errorf("acme account key: %w", err)
	}

	client := &xacme.Client{Key: accountKey, DirectoryURL: m.opts.DirectoryURL}
	acct := &xacme.Account{}
	if m.opts.Email != "" {
		acct.Contact = []string{"mailto:" + m.opts.Email}
	}
	if _, err := client.Register(ctx, acct, xacme.AcceptTOS); err != nil && !errors.Is(err, xacme.ErrAccountAlreadyExists) {
		m.opts.Metrics.Failures.Add(1)
		return fmt.Errorf("registering acme account: %w", err)
	}

	ids := make([]xacme.AuthzID, 0, len(m.opts.Domains))
	for _, d := range m.opts.Domains {
		ids = append(ids, xacme.AuthzID{Type: "dns", Value: d})
	}
	order, err := client.AuthorizeOrder(ctx, ids)
	if err != nil {
		m.opts.Metrics.Failures.Add(1)
		return fmt.Errorf("creating acme order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := m.authorize(ctx, client, authzURL); err != nil {
			m.opts.Metrics.Failures.Add(1)
			return err
		}
	}

	if _, err := client.WaitOrder(ctx, order.URI); err != nil {
		m.opts.Metrics.Failures.Add(1)
		return fmt.Errorf("waiting for the order to be ready: %w", err)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		m.opts.Metrics.Failures.Add(1)
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: m.opts.Domains[0]},
		DNSNames: m.opts.Domains,
	}, certKey)
	if err != nil {
		m.opts.Metrics.Failures.Add(1)
		return err
	}

	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		m.opts.Metrics.Failures.Add(1)
		return fmt.Errorf("finalising the order: %w", err)
	}

	if err := m.install(chain, certKey); err != nil {
		m.opts.Metrics.Failures.Add(1)
		return err
	}

	m.opts.Metrics.Renewals.Add(1)
	leaf := m.Current().Leaf
	m.opts.Metrics.NotAfter.Store(leaf.NotAfter.Unix())
	m.opts.Log.Info("certificate issued",
		slog.Any("domains", m.opts.Domains),
		slog.String("challenge", m.opts.Solver.Kind()),
		slog.Time("not_after", leaf.NotAfter))
	return nil
}

// authorize satisfies one authorization, cleaning up the challenge whatever the
// outcome — a stale TXT record or a listener left running is worse than a
// failed order.
func (m *Manager) authorize(ctx context.Context, client *xacme.Client, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("fetching authorization: %w", err)
	}
	if authz.Status == xacme.StatusValid {
		return nil
	}

	want := m.opts.Solver.Kind()
	var chal *xacme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == want {
			chal = c
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("acme: the CA offered no %s challenge for %s", want, authz.Identifier.Value)
	}

	keyAuth, err := challengeResponse(client, chal, want)
	if err != nil {
		return err
	}

	started := m.opts.now()
	cleanup, err := m.opts.Solver.Present(ctx, authz.Identifier.Value, chal.Token, keyAuth)
	if err != nil {
		return fmt.Errorf("presenting the %s challenge: %w", want, err)
	}
	defer func() {
		cleanup()
		if want == "http-01" {
			m.opts.Metrics.ChallengeSeconds.Store(int64(m.opts.now().Sub(started).Seconds()))
		}
	}()

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accepting the challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("waiting for validation of %s: %w", authz.Identifier.Value, err)
	}
	return nil
}

// challengeResponse computes what the solver has to publish.
func challengeResponse(client *xacme.Client, chal *xacme.Challenge, kind string) (string, error) {
	switch kind {
	case "dns-01":
		return client.DNS01ChallengeRecord(chal.Token)
	case "http-01":
		return client.HTTP01ChallengeResponse(chal.Token)
	default:
		return "", fmt.Errorf("acme: unsupported challenge type %q", kind)
	}
}

// install writes the chain and key, then swaps them in.
//
// Both files are written next to their destination and renamed, so a reader
// racing a renewal sees the old pair or the new one and never a half-written
// key that would stop every handshake.
func (m *Manager) install(chain [][]byte, key crypto.Signer) error {
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	der, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	if err := writeAtomic(m.opts.CertFile, certPEM, 0o644); err != nil {
		return err
	}
	if err := writeAtomic(m.opts.KeyFile, keyPEM, 0o600); err != nil {
		return err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	cert.Leaf = leaf

	m.mu.Lock()
	m.cert = &cert
	m.mu.Unlock()
	return nil
}

// accountKey loads the ACME account key, creating it on first use. The account
// is the identity the CA rate-limits and warns, so it must survive restarts.
func (m *Manager) accountKey() (crypto.Signer, error) {
	raw, err := os.ReadFile(m.opts.AccountKeyFile)
	if err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("acme: %s is not PEM", m.opts.AccountKeyFile)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(m.opts.AccountKeyFile), 0o750); err != nil {
		return nil, err
	}
	if err := writeAtomic(m.opts.AccountKeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// checkWritable confirms the daemon can create a file in dir, creating dir if
// it does not exist.
func checkWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".acme-probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".acme-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// selfSigned is used only by tests that need a leaf without a CA.
func selfSigned(domain string, notAfter time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// caIssued is used only by tests that need a leaf whose issuer differs from its
// subject, which is what distinguishes a real certificate from a placeholder.
func caIssued(domain string, notAfter time.Time) (tls.Certificate, *x509.CertPool, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test issuing CA"},
		NotBefore:             notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:              notAfter.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key, Leaf: leaf}, pool, nil
}
