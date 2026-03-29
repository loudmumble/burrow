// Package crypto provides WireGuard-style encryption for tunnel traffic.
//
// Implements X25519 key exchange and ChaCha20-Poly1305/AES-256-GCM frame encryption
// for securing data in transit through Burrow tunnels.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"crypto/sha256"
)

// CipherSuite identifies the AEAD cipher used for frame encryption.
type CipherSuite int

const (
	// ChaCha20Poly1305 is the default cipher suite (WireGuard-style).
	ChaCha20Poly1305 CipherSuite = iota
	// AES256GCM uses AES-256 in GCM mode.
	AES256GCM
)

const (
	// KeySize is the size of X25519 keys and derived symmetric keys (32 bytes).
	KeySize = 32
	// NonceSize is 12 bytes for both ChaCha20-Poly1305 and AES-256-GCM.
	NonceSize = 12
	// CounterSize is 4 bytes for the frame counter prefix.
	CounterSize = 4
	// FrameHeaderSize is CounterSize + NonceSize.
	FrameHeaderSize = CounterSize + NonceSize
	// MaxFrameSize limits individual encrypted frames to 64KB.
	MaxFrameSize = 65536
	// DefaultRotationInterval is the key rotation interval (1 hour).
	DefaultRotationInterval = time.Hour
)

var (
	// ErrPeerKeyNotSet is returned when attempting crypto operations without a peer key.
	ErrPeerKeyNotSet = errors.New("peer public key not set")
	// ErrFrameTooShort is returned when an encrypted frame is smaller than the header.
	ErrFrameTooShort = errors.New("frame too short")
	// ErrDecryptFailed is returned when AEAD decryption fails (tampered data).
	ErrDecryptFailed = errors.New("decryption failed: invalid ciphertext or tag")
	// ErrReplayDetected is returned when a decrypted frame has an already-seen counter.
	ErrReplayDetected = errors.New("replay detected: counter not advancing")
	// ErrCounterExhausted is returned when the send counter exceeds uint32 max.
	ErrCounterExhausted = errors.New("counter exhausted: rotate key before sending more data")
)

// KeyPair holds an X25519 private/public key pair.
type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

// GenerateKeyPair creates a new X25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	// Clamp private key per X25519 spec
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("compute public key: %w", err)
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// DeriveSharedKey performs X25519 ECDH and derives a 256-bit key via HKDF-SHA256.
func DeriveSharedKey(privateKey, peerPublicKey [KeySize]byte) ([KeySize]byte, error) {
	var derived [KeySize]byte

	shared, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return derived, fmt.Errorf("ECDH exchange: %w", err)
	}

	hkdfReader := hkdf.New(sha256.New, shared, nil, []byte("burrow-tunnel-v1"))
	if _, err := io.ReadFull(hkdfReader, derived[:]); err != nil {
		return derived, fmt.Errorf("HKDF derive: %w", err)
	}
	return derived, nil
}

// newAEAD creates an AEAD cipher from the given key and suite.
func newAEAD(key [KeySize]byte, suite CipherSuite) (cipher.AEAD, error) {
	switch suite {
	case ChaCha20Poly1305:
		return chacha20poly1305.New(key[:])
	case AES256GCM:
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %d", suite)
	}
}

// buildNonce creates a 12-byte nonce: 4 zero bytes + 4-byte BE counter + 4 random bytes.
func buildNonce(counter uint32) ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	// First 4 bytes: zero padding
	// Next 4 bytes: big-endian counter
	binary.BigEndian.PutUint32(nonce[4:8], counter)
	// Last 4 bytes: random
	if _, err := rand.Read(nonce[8:]); err != nil {
		return nonce, err
	}
	return nonce, nil
}

// EncryptFrame encrypts plaintext into a framed message:
// counter(4) || nonce(12) || ciphertext+tag
func EncryptFrame(key [KeySize]byte, plaintext []byte, counter uint32, suite CipherSuite, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key, suite)
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	nonce, err := buildNonce(counter)
	if err != nil {
		return nil, fmt.Errorf("build nonce: %w", err)
	}

	frame := make([]byte, FrameHeaderSize+len(plaintext)+aead.Overhead())
	binary.BigEndian.PutUint32(frame[:CounterSize], counter)
	copy(frame[CounterSize:FrameHeaderSize], nonce[:])

	ciphertext := aead.Seal(frame[FrameHeaderSize:FrameHeaderSize], nonce[:], plaintext, aad)
	return frame[:FrameHeaderSize+len(ciphertext)], nil
}

// DecryptFrame decrypts a framed message, returning the counter and plaintext.
func DecryptFrame(key [KeySize]byte, frame []byte, suite CipherSuite, aad []byte) (uint32, []byte, error) {
	if len(frame) < FrameHeaderSize {
		return 0, nil, ErrFrameTooShort
	}

	aead, err := newAEAD(key, suite)
	if err != nil {
		return 0, nil, fmt.Errorf("create AEAD: %w", err)
	}

	counter := binary.BigEndian.Uint32(frame[:CounterSize])
	var nonce [NonceSize]byte
	copy(nonce[:], frame[CounterSize:FrameHeaderSize])
	ciphertext := frame[FrameHeaderSize:]

	plaintext, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return 0, nil, ErrDecryptFailed
	}
	return counter, plaintext, nil
}

// Session manages an encrypted tunnel session with counter tracking and key rotation.
type Session struct {
	localKey    *KeyPair
	peerPublic  [KeySize]byte
	sharedKey   [KeySize]byte
	suite       CipherSuite
	hasPeer     bool
	hasShared   bool
	sendCounter atomic.Uint64
	recvCounter atomic.Uint64
	keyCreated  time.Time
	rotationInt time.Duration
	mu          sync.RWMutex
}

// NewSession creates a new crypto session with a fresh key pair.
func NewSession(suite CipherSuite) (*Session, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &Session{
		localKey:    kp,
		suite:       suite,
		keyCreated:  time.Now(),
		rotationInt: DefaultRotationInterval,
	}, nil
}

// LocalPublicKey returns this session's public key for sharing with the peer.
func (s *Session) LocalPublicKey() [KeySize]byte {
	return s.localKey.Public
}

// SetPeerPublicKey sets the peer's public key and derives the shared secret.
func (s *Session) SetPeerPublicKey(peerPub [KeySize]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.peerPublic = peerPub
	s.hasPeer = true

	shared, err := DeriveSharedKey(s.localKey.Private, peerPub)
	if err != nil {
		return err
	}
	s.sharedKey = shared
	s.hasShared = true
	s.keyCreated = time.Now()
	s.sendCounter.Store(0)
	s.recvCounter.Store(0)
	return nil
}

// Encrypt encrypts plaintext with the session's shared key, auto-incrementing the counter.
func (s *Session) Encrypt(plaintext []byte, aad []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.hasShared {
		return nil, ErrPeerKeyNotSet
	}

	cnt := s.sendCounter.Add(1) - 1
	if cnt > math.MaxUint32 {
		return nil, ErrCounterExhausted
	}
	counter := uint32(cnt)
	return EncryptFrame(s.sharedKey, plaintext, counter, s.suite, aad)
}

// Decrypt decrypts a frame with the session's shared key.
func (s *Session) Decrypt(frame []byte, aad []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.hasShared {
		return nil, ErrPeerKeyNotSet
	}

	counter, plaintext, err := DecryptFrame(s.sharedKey, frame, s.suite, aad)
	if err != nil {
		return nil, err
	}

	// Enforce strictly advancing counters for anti-replay.
	next := uint64(counter) + 1
	for {
		current := s.recvCounter.Load()
		if next <= current {
			return nil, ErrReplayDetected
		}
		if s.recvCounter.CompareAndSwap(current, next) {
			break
		}
	}
	return plaintext, nil
}

// NeedsRotation returns true if the session key should be rotated.
func (s *Session) NeedsRotation() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.keyCreated) > s.rotationInt
}

// RotateKey generates a new key pair and resets counters. Returns new public key.
func (s *Session) RotateKey() ([KeySize]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	kp, err := GenerateKeyPair()
	if err != nil {
		return [KeySize]byte{}, err
	}
	s.localKey = kp
	s.hasShared = false
	s.sendCounter.Store(0)
	s.recvCounter.Store(0)
	return kp.Public, nil
}

// SendCounter returns the current send counter value.
func (s *Session) SendCounter() uint64 {
	return s.sendCounter.Load()
}

// RecvCounter returns the current recv counter value.
func (s *Session) RecvCounter() uint64 {
	return s.recvCounter.Load()
}
