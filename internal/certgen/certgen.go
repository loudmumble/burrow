// Package certgen provides self-signed TLS certificate generation and
// fingerprint verification for Burrow tunnel authentication.
//
// All cryptographic operations use Go stdlib only — no external dependencies.
package certgen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
	// ErrNoCertificate is returned when the TLS certificate has no leaf.
	ErrNoCertificate = errors.New("tls certificate contains no leaf certificate")
	// ErrFingerprintMismatch is returned when peer fingerprint doesn't match expected.
	ErrFingerprintMismatch = errors.New("peer certificate fingerprint mismatch")
)

// GenerateSelfSigned creates a self-signed X.509 certificate with an Ed25519
// key pair. The certificate is valid for the given duration from now and
// includes localhost SANs. Returns a tls.Certificate ready for tls.Config.
func GenerateSelfSigned(org string, validity time.Duration) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate ed25519 key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create tls keypair: %w", err)
	}

	// Parse leaf so it's available without re-parsing later.
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse leaf certificate: %w", err)
	}
	tlsCert.Leaf = leaf

	return tlsCert, nil
}

// GenerateSelfSignedECDSA creates a self-signed X.509 certificate with an
// ECDSA P-256 key pair. Browser-compatible (unlike Ed25519). Used for the
// WebUI HTTPS server.
func GenerateSelfSignedECDSA(org string, validity time.Duration) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate ecdsa key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create tls keypair: %w", err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse leaf certificate: %w", err)
	}
	tlsCert.Leaf = leaf

	return tlsCert, nil
}

// Fingerprint computes the SHA-256 fingerprint of a DER-encoded X.509
// certificate and returns it as uppercase hex colon-separated octets
// (e.g. "AB:CD:EF:01:...").
func Fingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	hexStr := hex.EncodeToString(hash[:])
	upper := strings.ToUpper(hexStr)

	parts := make([]string, sha256.Size)
	for i := 0; i < sha256.Size; i++ {
		parts[i] = upper[i*2 : i*2+2]
	}
	return strings.Join(parts, ":")
}

// FingerprintFromTLSCert extracts the leaf certificate from a tls.Certificate
// and returns its SHA-256 fingerprint.
func FingerprintFromTLSCert(tlsCert tls.Certificate) (string, error) {
	if tlsCert.Leaf != nil {
		return Fingerprint(tlsCert.Leaf), nil
	}
	if len(tlsCert.Certificate) == 0 {
		return "", ErrNoCertificate
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("parse leaf certificate: %w", err)
	}
	return Fingerprint(leaf), nil
}

// EncodePEM returns PEM-encoded certificate and private key from a tls.Certificate.
func EncodePEM(tlsCert tls.Certificate) (certPEM, keyPEM []byte, err error) {
	if len(tlsCert.Certificate) == 0 {
		return nil, nil, ErrNoCertificate
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Certificate[0]})

	privDER, err := x509.MarshalPKCS8PrivateKey(tlsCert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	return certPEM, keyPEM, nil
}

// SavePEM writes PEM-encoded certificate and key data to disk with
// restrictive permissions (0644 for cert, 0600 for key).
func SavePEM(certPEM, keyPEM []byte, certPath, keyPath string) error {
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

// LoadPEM reads PEM-encoded certificate and key files from disk and returns
// a tls.Certificate with the leaf pre-parsed.
func LoadPEM(certPath, keyPath string) (tls.Certificate, error) {
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load keypair: %w", err)
	}
	if len(tlsCert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse leaf: %w", err)
		}
		tlsCert.Leaf = leaf
	}
	return tlsCert, nil
}

// TLSConfig creates a *tls.Config using the provided certificate. If
// verifyFingerprint is non-empty, the config enables InsecureSkipVerify
// and installs a custom VerifyPeerCertificate callback that checks the
// peer's SHA-256 fingerprint against the expected value.
func TLSConfig(cert tls.Certificate, verifyFingerprint string) *tls.Config {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if verifyFingerprint != "" {
		expected := strings.ToUpper(strings.TrimSpace(verifyFingerprint))
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificates presented")
			}
			peerCert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse peer certificate: %w", err)
			}
			actual := Fingerprint(peerCert)
			if actual != expected {
				return fmt.Errorf("%w: expected %s, got %s", ErrFingerprintMismatch, expected, actual)
			}
			return nil
		}
	}

	return cfg
}
