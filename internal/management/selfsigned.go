package management

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// selfSignedValidity is deliberately long.
//
// This certificate is not what anyone trusts. The WebUI is bound to localhost
// and fronted by a tunnel that terminates the real TLS, so this exists only to
// satisfy the browser's requirement that a Secure cookie arrives over HTTPS.
// Expiring it would break the UI for no security gain.
const selfSignedValidity = 10 * 365 * 24 * time.Hour

// EnsureSelfSigned returns a certificate and key path, generating a self-signed
// pair if none exists yet.
//
// A fresh node must be usable without the operator first producing certificates
// by hand. The generated pair covers localhost only, which is where the UI
// listens by default.
func EnsureSelfSigned(dir, nodeID string, hosts []string, log *slog.Logger) (certFile, keyFile string, err error) {
	certFile = filepath.Join(dir, "mgmt-selfsigned.pem")
	keyFile = filepath.Join(dir, "mgmt-selfsigned.key")

	if fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", fmt.Errorf("management: creating %s: %w", dir, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("management: generating key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("management: generating serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "cgdns " + nodeID + " management"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	if len(tmpl.IPAddresses) == 0 && len(tmpl.DNSNames) == 0 {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		tmpl.DNSNames = []string{"localhost"}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("management: creating certificate: %w", err)
	}

	if err := writePEM(certFile, "CERTIFICATE", der, 0o644); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("management: encoding key: %w", err)
	}
	if err := writePEM(keyFile, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return "", "", err
	}

	log.Warn("generated a self-signed certificate for the management plane",
		slog.String("cert", certFile),
		slog.Any("hosts", hosts),
		slog.String("note", "it exists so the browser accepts the session cookie; terminate real TLS in front of it"))
	return certFile, keyFile, nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("management: writing %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("management: encoding %s: %w", path, err)
	}
	return f.Close()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
