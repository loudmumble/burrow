// Package httptunnel implements a reGeorg-style HTTP tunnel for TCP relay.
//
// The server runs on the target machine and accepts inbound HTTP requests
// from the attacker, relaying TCP connections to internal hosts. The client
// runs on the attacker's machine and provides a local SOCKS5 interface,
// encoding all traffic as HTTP request/response pairs.
//
// This solves the "egress blocked" scenario: the target has no outbound
// connectivity, but the attacker can reach the target's HTTP port.
package httptunnel

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Tunnel command constants sent as query parameters.
const (
	CmdConnect    = "connect"    // Open TCP connection to target host:port
	CmdSend       = "send"       // Send data to an established TCP connection
	CmdRecv       = "recv"       // Receive data from an established TCP connection
	CmdDisconnect = "disconnect" // Close TCP connection and remove session
	CmdPing       = "ping"       // Keepalive heartbeat
)

// Encrypt XOR-encrypts data with a repeating key.
// XOR is symmetric so Encrypt and Decrypt are the same operation.
func Encrypt(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

// Decrypt XOR-decrypts data with a repeating key. Same as Encrypt (XOR is symmetric).
func Decrypt(data []byte, key []byte) []byte {
	return Encrypt(data, key)
}

// EncodePayload encrypts data with the key then base64-encodes it for HTTP transport.
func EncodePayload(data []byte, key []byte) string {
	encrypted := Encrypt(data, key)
	return base64.StdEncoding.EncodeToString(encrypted)
}

// DecodePayload base64-decodes then decrypts the payload.
func DecodePayload(encoded string, key []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return Decrypt(raw, key), nil
}

// GenerateSessionID returns a random 8-byte hex string (16 chars) for session identification.
func GenerateSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback: should never happen with crypto/rand
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}

// AuthToken computes SHA256(key) as a hex string for X-Token header authentication.
func AuthToken(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:])
}
