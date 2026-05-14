package certgen

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateSelfSigned(t *testing.T) {
	cert, err := GenerateSelfSigned("BurrowTest", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	if cert.Leaf == nil {
		t.Fatal("expected leaf certificate to be pre-parsed")
	}

	leaf := cert.Leaf
	if leaf.Subject.Organization[0] != "BurrowTest" {
		t.Errorf("org = %q, want %q", leaf.Subject.Organization[0], "BurrowTest")
	}
	if leaf.NotAfter.Before(time.Now().Add(23 * time.Hour)) {
		t.Error("certificate validity too short")
	}
	if !leaf.NotBefore.Before(time.Now().Add(time.Minute)) {
		t.Error("certificate NotBefore in the future")
	}

	// Check SANs
	hasLocalhost := false
	for _, dns := range leaf.DNSNames {
		if dns == "localhost" {
			hasLocalhost = true
		}
	}
	if !hasLocalhost {
		t.Error("expected localhost in DNS SANs")
	}

	hasLoopback := false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback) {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		t.Error("expected loopback in IP SANs")
	}

	// Ed25519 key type
	if leaf.PublicKeyAlgorithm != x509.Ed25519 {
		t.Errorf("key algorithm = %v, want Ed25519", leaf.PublicKeyAlgorithm)
	}
}

func TestFingerprint(t *testing.T) {
	cert, err := GenerateSelfSigned("FPTest", time.Hour)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	fp := Fingerprint(cert.Leaf)

	// Format: 32 hex pairs separated by colons = 32*2 + 31 = 95 chars
	if len(fp) != 95 {
		t.Errorf("fingerprint length = %d, want 95", len(fp))
	}

	parts := strings.Split(fp, ":")
	if len(parts) != 32 {
		t.Errorf("fingerprint parts = %d, want 32", len(parts))
	}

	// Must be uppercase hex
	for i, part := range parts {
		if len(part) != 2 {
			t.Errorf("part[%d] length = %d, want 2", i, len(part))
		}
		if strings.ToUpper(part) != part {
			t.Errorf("part[%d] = %q, not uppercase", i, part)
		}
	}

	// Deterministic: same cert yields same fingerprint
	fp2 := Fingerprint(cert.Leaf)
	if fp != fp2 {
		t.Error("fingerprint not deterministic")
	}
}

func TestFingerprintFromTLSCert(t *testing.T) {
	cert, err := GenerateSelfSigned("FPTLSTest", time.Hour)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	// With leaf pre-parsed
	fp1, err := FingerprintFromTLSCert(cert)
	if err != nil {
		t.Fatalf("FingerprintFromTLSCert: %v", err)
	}

	expected := Fingerprint(cert.Leaf)
	if fp1 != expected {
		t.Errorf("fingerprint mismatch: got %s, want %s", fp1, expected)
	}

	// Without leaf — force re-parse
	certNoLeaf := cert
	certNoLeaf.Leaf = nil
	fp2, err := FingerprintFromTLSCert(certNoLeaf)
	if err != nil {
		t.Fatalf("FingerprintFromTLSCert (no leaf): %v", err)
	}
	if fp2 != expected {
		t.Errorf("fingerprint without leaf mismatch: got %s, want %s", fp2, expected)
	}

	// Empty cert
	_, err = FingerprintFromTLSCert(tls.Certificate{})
	if err != ErrNoCertificate {
		t.Errorf("expected ErrNoCertificate, got %v", err)
	}
}

func TestPEMRoundTrip(t *testing.T) {
	cert, err := GenerateSelfSigned("PEMTest", time.Hour)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// Encode and save
	certPEM, keyPEM, err := EncodePEM(cert)
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}

	if err := SavePEM(certPEM, keyPEM, certPath, keyPath); err != nil {
		t.Fatalf("SavePEM: %v", err)
	}

	// Check key file permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key permissions = %o, want 0600", perm)
	}

	// Load back
	loaded, err := LoadPEM(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadPEM: %v", err)
	}

	if loaded.Leaf == nil {
		t.Fatal("loaded cert has no leaf")
	}

	// Fingerprints must match
	origFP := Fingerprint(cert.Leaf)
	loadedFP := Fingerprint(loaded.Leaf)
	if origFP != loadedFP {
		t.Errorf("fingerprint mismatch after round-trip: %s != %s", origFP, loadedFP)
	}
}

func TestTLSConfigBasic(t *testing.T) {
	cert, err := GenerateSelfSigned("ConfigTest", time.Hour)
	if err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}

	cfg := TLSConfig(cert, "")
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false without fingerprint")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Error("expected MinVersion TLS 1.2")
	}
}

func TestTLSConfigFingerprintVerification(t *testing.T) {
	// Generate server and client certs
	serverCert, err := GenerateSelfSigned("Server", time.Hour)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	clientCert, err := GenerateSelfSigned("Client", time.Hour)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}

	serverFP := Fingerprint(serverCert.Leaf)

	// Client config with correct fingerprint
	clientCfg := TLSConfig(clientCert, serverFP)
	if !clientCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true with fingerprint")
	}
	if clientCfg.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate should be set")
	}

	// Correct fingerprint should pass
	err = clientCfg.VerifyPeerCertificate(
		[][]byte{serverCert.Leaf.Raw},
		nil,
	)
	if err != nil {
		t.Errorf("correct fingerprint failed: %v", err)
	}

	// Wrong fingerprint should fail
	err = clientCfg.VerifyPeerCertificate(
		[][]byte{clientCert.Leaf.Raw},
		nil,
	)
	if err == nil {
		t.Error("wrong fingerprint should have failed")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected mismatch error, got: %v", err)
	}

	// No certs should fail
	err = clientCfg.VerifyPeerCertificate(nil, nil)
	if err == nil {
		t.Error("no certs should have failed")
	}
}

func TestTLSHandshakeWithFingerprint(t *testing.T) {
	serverCert, err := GenerateSelfSigned("Server", time.Hour)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	clientCert, err := GenerateSelfSigned("Client", time.Hour)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}

	serverFP := Fingerprint(serverCert.Leaf)

	serverCfg := TLSConfig(serverCert, "")
	serverCfg.ClientAuth = tls.NoClientCert

	clientCfg := TLSConfig(clientCert, serverFP)

	// Start TLS server
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 5)
		n, err := conn.Read(buf)
		if err != nil {
			done <- err
			return
		}
		_, err = conn.Write(buf[:n])
		done <- err
	}()

	// Client connects and verifies fingerprint
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("echo = %q, want %q", string(buf[:n]), "hello")
	}

	if err := <-done; err != nil {
		t.Errorf("server error: %v", err)
	}
}
