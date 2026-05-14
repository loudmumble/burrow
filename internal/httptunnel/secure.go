package httptunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Secure tunnel protocol — pivotnacci-style evasion.
//
// Differences from basic mode:
//   - AES-256-GCM encryption (not XOR)
//   - Commands encoded in cookies (not query params)
//   - Responses wrapped in HTML (always 200 OK)
//   - No signaturable ?cmd=, ?sid=, ?target= query strings

const (
	// SecureNonceSize is the GCM nonce size (12 bytes).
	SecureNonceSize = 12

	// SecureKeySize is AES-256 key size (32 bytes).
	SecureKeySize = 32

	// Default cookie name — looks like a Cloudflare cookie.
	DefaultCookieName = "__cf_bm"

	// Status bytes prepended to decrypted response data.
	StatusOK    byte = 0x00
	StatusError byte = 0x01
	StatusEmpty byte = 0x02
)

// Secure action codes (sent inside encrypted command).
const (
	ActionPing       = 0
	ActionConnect    = 1
	ActionSend       = 2
	ActionRecv       = 3
	ActionDisconnect = 4
)

// SecureCommand is the JSON structure encrypted inside the cookie.
type SecureCommand struct {
	Action int    `json:"a"`
	Target string `json:"t,omitempty"`
	SID    string `json:"s,omitempty"`
}

// SecureKeys holds the derived key material for the secure tunnel.
type SecureKeys struct {
	EncKey     []byte // 32 bytes, AES-256-GCM
	CookieName string // derived cookie name
}

// DeriveSecureKeys derives AES-256-GCM key material from a pre-shared key using HKDF-SHA256.
func DeriveSecureKeys(psk []byte) (*SecureKeys, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("secure mode requires a key")
	}

	salt := []byte("burrow-secure-tunnel-v1")

	// Derive encryption key
	encReader := hkdf.New(sha256.New, psk, salt, []byte("encryption"))
	encKey := make([]byte, SecureKeySize)
	if _, err := io.ReadFull(encReader, encKey); err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}

	// Derive cookie name from key material — pick from a set of common names
	nameReader := hkdf.New(sha256.New, psk, salt, []byte("cookie-name"))
	nameByte := make([]byte, 1)
	if _, err := io.ReadFull(nameReader, nameByte); err != nil {
		return nil, fmt.Errorf("derive cookie name: %w", err)
	}

	cookieNames := []string{
		"__cf_bm", "_ga", "XSRF-TOKEN", "__session", "_gid",
		"__cfduid", "csrftoken", "__stripe_mid",
	}
	cookieName := cookieNames[int(nameByte[0])%len(cookieNames)]

	return &SecureKeys{
		EncKey:     encKey,
		CookieName: cookieName,
	}, nil
}

// SecureEncrypt encrypts plaintext with AES-256-GCM.
// Returns: nonce(12) || ciphertext || tag(16)
func SecureEncrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// SecureDecrypt decrypts AES-256-GCM ciphertext.
// Expects: nonce(12) || ciphertext || tag(16)
func SecureDecrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

// EncodeSecureCommand encrypts a command and returns a base64 cookie value.
func EncodeSecureCommand(cmd SecureCommand, key []byte) (string, error) {
	jsonData, err := json.Marshal(cmd)
	if err != nil {
		return "", err
	}
	encrypted, err := SecureEncrypt(jsonData, key)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

// DecodeSecureCommand decrypts a base64 cookie value into a command.
func DecodeSecureCommand(cookieValue string, key []byte) (SecureCommand, error) {
	var cmd SecureCommand
	data, err := base64.RawURLEncoding.DecodeString(cookieValue)
	if err != nil {
		return cmd, fmt.Errorf("base64 decode: %w", err)
	}
	jsonData, err := SecureDecrypt(data, key)
	if err != nil {
		return cmd, fmt.Errorf("decrypt: %w", err)
	}
	if err := json.Unmarshal(jsonData, &cmd); err != nil {
		return cmd, fmt.Errorf("json unmarshal: %w", err)
	}
	return cmd, nil
}

// EncodeSecurePayload encrypts data and returns base64-encoded ciphertext.
func EncodeSecurePayload(data, key []byte) (string, error) {
	encrypted, err := SecureEncrypt(data, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecodeSecurePayload decodes and decrypts a base64-encoded payload.
func DecodeSecurePayload(encoded string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return SecureDecrypt(data, key)
}

// HTML response templates that look like a modern SPA.
var secureHTMLPages = []string{
	`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard</title>
<link rel="icon" href="/favicon.ico">
</head>
<body>
<div id="root"%s></div>
<script src="/assets/main.js" defer></script>
</body>
</html>`,
	`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Portal</title>
<link rel="stylesheet" href="/css/app.css">
</head>
<body>
<div id="app"%s></div>
<script src="/js/vendor.js"></script>
<script src="/js/app.js"></script>
</body>
</html>`,
	`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Application</title>
</head>
<body>
<main id="content"%s></main>
<script type="module" src="/src/index.js"></script>
</body>
</html>`,
}

// WrapSecureResponse encrypts response data and embeds it in an HTML page.
// The encrypted data is placed in a data-cfg attribute on the main div element.
func WrapSecureResponse(data []byte, status byte, key []byte) (string, error) {
	payload := append([]byte{status}, data...)
	encrypted, err := SecureEncrypt(payload, key)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	// Pick template deterministically from data length (avoids randomness per-request
	// while still varying the template across different response sizes)
	tmpl := secureHTMLPages[len(encoded)%len(secureHTMLPages)]
	attr := fmt.Sprintf(` data-cfg="%s"`, encoded)
	return fmt.Sprintf(tmpl, attr), nil
}

// WrapSecureEmpty returns an HTML page with no data (empty recv / cover).
func WrapSecureEmpty() string {
	return fmt.Sprintf(secureHTMLPages[0], "")
}

// UnwrapSecureResponse parses the HTML, extracts the data-cfg attribute,
// and decrypts the payload. Returns status byte and data.
func UnwrapSecureResponse(html string, key []byte) (byte, []byte, error) {
	// Extract data-cfg="..." from the HTML
	marker := `data-cfg="`
	idx := strings.Index(html, marker)
	if idx < 0 {
		// No data attribute — empty response
		return StatusEmpty, nil, nil
	}

	start := idx + len(marker)
	end := strings.Index(html[start:], `"`)
	if end < 0 {
		return 0, nil, fmt.Errorf("malformed data-cfg attribute")
	}

	encoded := html[start : start+end]
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return 0, nil, fmt.Errorf("base64 decode: %w", err)
	}

	plaintext, err := SecureDecrypt(data, key)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypt: %w", err)
	}

	if len(plaintext) == 0 {
		return 0, nil, fmt.Errorf("empty decrypted payload")
	}

	return plaintext[0], plaintext[1:], nil
}
