package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if kp.Public == [KeySize]byte{} {
		t.Fatal("public key is zero")
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 2: %v", err)
	}
	if kp.Public == kp2.Public {
		t.Fatal("two keypairs have same public key")
	}
}

func TestDeriveSharedKey(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	sharedA, err := DeriveSharedKey(alice.Private, bob.Public)
	if err != nil {
		t.Fatalf("DeriveSharedKey alice: %v", err)
	}

	sharedB, err := DeriveSharedKey(bob.Private, alice.Public)
	if err != nil {
		t.Fatalf("DeriveSharedKey bob: %v", err)
	}

	if sharedA != sharedB {
		t.Fatal("shared keys don't match")
	}
}

func TestEncryptDecryptChaCha20(t *testing.T) {
	key := [KeySize]byte{}
	copy(key[:], bytes.Repeat([]byte{0xAB}, KeySize))

	plaintext := []byte("hello burrow tunnel")
	frame, err := EncryptFrame(key, plaintext, 42, ChaCha20Poly1305, nil)
	if err != nil {
		t.Fatalf("EncryptFrame: %v", err)
	}

	counter, decrypted, err := DecryptFrame(key, frame, ChaCha20Poly1305, nil)
	if err != nil {
		t.Fatalf("DecryptFrame: %v", err)
	}

	if counter != 42 {
		t.Fatalf("counter = %d, want 42", counter)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptAES256GCM(t *testing.T) {
	key := [KeySize]byte{}
	copy(key[:], bytes.Repeat([]byte{0xCD}, KeySize))

	plaintext := []byte("AES-256-GCM test data")
	frame, err := EncryptFrame(key, plaintext, 7, AES256GCM, nil)
	if err != nil {
		t.Fatalf("EncryptFrame: %v", err)
	}

	counter, decrypted, err := DecryptFrame(key, frame, AES256GCM, nil)
	if err != nil {
		t.Fatalf("DecryptFrame: %v", err)
	}

	if counter != 7 {
		t.Fatalf("counter = %d, want 7", counter)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptWithAAD(t *testing.T) {
	key := [KeySize]byte{}
	copy(key[:], bytes.Repeat([]byte{0xEF}, KeySize))

	plaintext := []byte("aad test")
	aad := []byte("burrow-session-001")

	frame, err := EncryptFrame(key, plaintext, 0, ChaCha20Poly1305, aad)
	if err != nil {
		t.Fatalf("EncryptFrame: %v", err)
	}

	_, _, err = DecryptFrame(key, frame, ChaCha20Poly1305, []byte("wrong-aad"))
	if err == nil {
		t.Fatal("decryption should fail with wrong AAD")
	}

	_, decrypted, err := DecryptFrame(key, frame, ChaCha20Poly1305, aad)
	if err != nil {
		t.Fatalf("DecryptFrame with correct AAD: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptTamperedFrame(t *testing.T) {
	key := [KeySize]byte{}
	copy(key[:], bytes.Repeat([]byte{0x11}, KeySize))

	frame, _ := EncryptFrame(key, []byte("secret"), 0, ChaCha20Poly1305, nil)

	// Tamper with ciphertext
	frame[len(frame)-1] ^= 0xFF

	_, _, err := DecryptFrame(key, frame, ChaCha20Poly1305, nil)
	if err == nil {
		t.Fatal("decryption should fail on tampered frame")
	}
}

func TestFrameTooShort(t *testing.T) {
	key := [KeySize]byte{}
	_, _, err := DecryptFrame(key, []byte{0x01, 0x02}, ChaCha20Poly1305, nil)
	if err != ErrFrameTooShort {
		t.Fatalf("expected ErrFrameTooShort, got %v", err)
	}
}

func TestSessionEncryptDecrypt(t *testing.T) {
	alice, err := NewSession(ChaCha20Poly1305)
	if err != nil {
		t.Fatalf("NewSession alice: %v", err)
	}

	bob, err := NewSession(ChaCha20Poly1305)
	if err != nil {
		t.Fatalf("NewSession bob: %v", err)
	}

	alice.SetPeerPublicKey(bob.LocalPublicKey())
	bob.SetPeerPublicKey(alice.LocalPublicKey())

	plaintext := []byte("session encrypted message")
	frame, err := alice.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("alice.Encrypt: %v", err)
	}

	decrypted, err := bob.Decrypt(frame, nil)
	if err != nil {
		t.Fatalf("bob.Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}

	if alice.SendCounter() != 1 {
		t.Fatalf("alice.SendCounter = %d, want 1", alice.SendCounter())
	}
}

func TestSessionNoPeerKey(t *testing.T) {
	s, _ := NewSession(ChaCha20Poly1305)
	_, err := s.Encrypt([]byte("data"), nil)
	if err != ErrPeerKeyNotSet {
		t.Fatalf("expected ErrPeerKeyNotSet, got %v", err)
	}
}

func TestSessionRotateKey(t *testing.T) {
	s, _ := NewSession(ChaCha20Poly1305)
	oldPub := s.LocalPublicKey()

	newPub, err := s.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	if oldPub == newPub {
		t.Fatal("rotated key should differ from original")
	}

	if s.SendCounter() != 0 {
		t.Fatal("counters should reset after rotation")
	}
}
