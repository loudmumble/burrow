package tun

import (
	"encoding/binary"
	"net"
	"testing"
)

// =============================================================================
// Non-privileged tests — run with: go test ./internal/tun/
// =============================================================================

func TestDefaultMagicIP(t *testing.T) {
	ip, mask := DefaultMagicIP()

	expectedIP := net.IPv4(240, 0, 0, 1).To4()
	if !ip.Equal(expectedIP) {
		t.Errorf("DefaultMagicIP() IP = %v, want %v", ip, expectedIP)
	}

	expectedMask := net.CIDRMask(32, 32)
	if !maskEqual(mask, expectedMask) {
		t.Errorf("DefaultMagicIP() mask = %v, want %v", mask, expectedMask)
	}

	prefix, bits := mask.Size()
	if prefix != 32 || bits != 32 {
		t.Errorf("DefaultMagicIP() mask size = /%d (of %d), want /32 (of 32)", prefix, bits)
	}
}

func TestNextMagicIP(t *testing.T) {
	tests := []struct {
		sessionIndex int
		wantIP       net.IP
	}{
		{0, net.IPv4(240, 0, 0, 1).To4()},
		{1, net.IPv4(240, 0, 0, 2).To4()},
		{2, net.IPv4(240, 0, 0, 3).To4()},
		{9, net.IPv4(240, 0, 0, 10).To4()},
		{254, net.IPv4(240, 0, 0, 255).To4()},
	}

	for _, tt := range tests {
		ip, mask := NextMagicIP(tt.sessionIndex)
		if !ip.To4().Equal(tt.wantIP) {
			t.Errorf("NextMagicIP(%d) IP = %v, want %v", tt.sessionIndex, ip, tt.wantIP)
		}

		prefix, _ := mask.Size()
		if prefix != 32 {
			t.Errorf("NextMagicIP(%d) mask = /%d, want /32", tt.sessionIndex, prefix)
		}
	}
}

func TestNextMagicIPIsolation(t *testing.T) {
	// Verify each session gets a distinct IP.
	seen := make(map[string]int)
	for i := 0; i < 100; i++ {
		ip, _ := NextMagicIP(i)
		key := ip.String()
		if prev, ok := seen[key]; ok {
			t.Fatalf("NextMagicIP(%d) collides with session %d: both = %s", i, prev, key)
		}
		seen[key] = i
	}
}

// =============================================================================
// Packet parsing tests
// =============================================================================

// craftIPv4Packet builds a minimal 20-byte IPv4 header with the given fields.
func craftIPv4Packet(srcIP, dstIP net.IP, proto uint8, payloadLen int) []byte {
	ihl := 5 // 20 bytes, no options
	totalLen := ihl*4 + payloadLen

	pkt := make([]byte, totalLen)
	pkt[0] = (4 << 4) | byte(ihl) // version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[9] = proto
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())

	return pkt
}

func TestParseIPHeader(t *testing.T) {
	srcIP := net.IPv4(10, 0, 0, 1).To4()
	dstIP := net.IPv4(192, 168, 1, 100).To4()

	pkt := craftIPv4Packet(srcIP, dstIP, ProtoTCP, 40)

	parsed, err := ParseIPHeader(pkt)
	if err != nil {
		t.Fatalf("ParseIPHeader() error = %v", err)
	}

	if parsed.Version != 4 {
		t.Errorf("Version = %d, want 4", parsed.Version)
	}
	if !parsed.SrcIP.Equal(srcIP) {
		t.Errorf("SrcIP = %v, want %v", parsed.SrcIP, srcIP)
	}
	if !parsed.DstIP.Equal(dstIP) {
		t.Errorf("DstIP = %v, want %v", parsed.DstIP, dstIP)
	}
	if parsed.Protocol != ProtoTCP {
		t.Errorf("Protocol = %d, want %d", parsed.Protocol, ProtoTCP)
	}
	if parsed.PayloadLen != 40 {
		t.Errorf("PayloadLen = %d, want 40", parsed.PayloadLen)
	}
}

func TestParseIPHeaderProtocols(t *testing.T) {
	tests := []struct {
		name  string
		proto uint8
	}{
		{"ICMP", ProtoICMP},
		{"TCP", ProtoTCP},
		{"UDP", ProtoUDP},
	}

	src := net.IPv4(10, 0, 0, 1).To4()
	dst := net.IPv4(10, 0, 0, 2).To4()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := craftIPv4Packet(src, dst, tt.proto, 100)
			parsed, err := ParseIPHeader(pkt)
			if err != nil {
				t.Fatalf("ParseIPHeader() error = %v", err)
			}
			if parsed.Protocol != tt.proto {
				t.Errorf("Protocol = %d, want %d", parsed.Protocol, tt.proto)
			}
		})
	}
}

func TestParseIPHeaderTooShort(t *testing.T) {
	// Less than 20 bytes should fail.
	short := make([]byte, 10)
	short[0] = 0x45 // valid version/IHL but too short

	_, err := ParseIPHeader(short)
	if err == nil {
		t.Fatal("ParseIPHeader() expected error for short packet, got nil")
	}
}

func TestParseIPHeaderNotIPv4(t *testing.T) {
	// IPv6 version nibble (6).
	pkt := make([]byte, 20)
	pkt[0] = 0x60 // version=6

	_, err := ParseIPHeader(pkt)
	if err == nil {
		t.Fatal("ParseIPHeader() expected error for IPv6 packet, got nil")
	}
}

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want bool
	}{
		{"valid IPv4", []byte{0x45, 0x00}, true},
		{"IPv6", []byte{0x60, 0x00}, false},
		{"empty", []byte{}, false},
		{"nil", nil, false},
		{"version 0", []byte{0x00}, false},
		{"version 15", []byte{0xF0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIPv4(tt.raw)
			if got != tt.want {
				t.Errorf("IsIPv4(%v) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestParseIPHeaderZeroPayload(t *testing.T) {
	src := net.IPv4(172, 16, 0, 1).To4()
	dst := net.IPv4(240, 0, 0, 1).To4()

	// Header-only packet (e.g., some ICMP types).
	pkt := craftIPv4Packet(src, dst, ProtoICMP, 0)

	parsed, err := ParseIPHeader(pkt)
	if err != nil {
		t.Fatalf("ParseIPHeader() error = %v", err)
	}
	if parsed.PayloadLen != 0 {
		t.Errorf("PayloadLen = %d, want 0", parsed.PayloadLen)
	}
	// Verify magic IP destination is correctly parsed.
	if !parsed.DstIP.Equal(dst) {
		t.Errorf("DstIP = %v, want %v (magic IP)", parsed.DstIP, dst)
	}
}

// maskEqual compares two net.IPMask values.
func maskEqual(a, b net.IPMask) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
