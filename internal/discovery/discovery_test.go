package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestParseCIDR24(t *testing.T) {
	ips, err := ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	if len(ips) != 254 {
		t.Fatalf("len(ips) = %d, want 254", len(ips))
	}
	if ips[0] != "10.0.0.1" {
		t.Fatalf("first IP = %s, want 10.0.0.1", ips[0])
	}
	if ips[253] != "10.0.0.254" {
		t.Fatalf("last IP = %s, want 10.0.0.254", ips[253])
	}
}

func TestParseCIDR32(t *testing.T) {
	ips, err := ParseCIDR("10.0.0.5/32")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("len(ips) = %d, want 1", len(ips))
	}
}

func TestParseCIDRPrefix(t *testing.T) {
	ips, err := ParseCIDR("192.168.1")
	if err != nil {
		t.Fatalf("ParseCIDR prefix: %v", err)
	}
	if len(ips) != 254 {
		t.Fatalf("len(ips) = %d, want 254", len(ips))
	}
}

func TestParseCIDRInvalid(t *testing.T) {
	_, err := ParseCIDR("invalid")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"22,80,443", 3},
		{"1-5", 5},
		{"22,80,100-102", 5},
		{"", 0},
	}

	for _, tc := range tests {
		ports := ParsePortRange(tc.input)
		if len(ports) != tc.expected {
			t.Errorf("ParsePortRange(%q) = %d ports, want %d", tc.input, len(ports), tc.expected)
		}
	}
}

func TestGenerateIPRange(t *testing.T) {
	ips := GenerateIPRange("10.0.0")
	if len(ips) != 254 {
		t.Fatalf("len(ips) = %d, want 254", len(ips))
	}
	if ips[0] != "10.0.0.1" {
		t.Fatalf("first = %s", ips[0])
	}
	if ips[253] != "10.0.0.254" {
		t.Fatalf("last = %s", ips[253])
	}
}

func TestScanHostFindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	scanner := NewScanner([]int{port}, 2*time.Second, 10)
	targets, err := scanner.ScanHosts(context.Background(), []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("ScanHosts: %v", err)
	}

	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}

	found := false
	for _, p := range targets[0].OpenPorts {
		if p == port {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("port %d not found in open ports: %v", port, targets[0].OpenPorts)
	}
}

func TestScanHostNoOpenPorts(t *testing.T) {
	scanner := NewScanner([]int{1}, 200*time.Millisecond, 10)
	targets, err := scanner.ScanHosts(context.Background(), []string{"192.0.2.1"})
	if err != nil {
		t.Fatalf("ScanHosts: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(targets))
	}
}

func TestScanSubnet(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	scanner := NewScanner([]int{port}, 500*time.Millisecond, 10)
	targets, err := scanner.ScanSubnet(context.Background(), "127.0.0.1/32")
	if err != nil {
		t.Fatalf("ScanSubnet: %v", err)
	}

	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
}

func TestScanContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanner := NewScanner([]int{22, 80}, 2*time.Second, 10)
	targets, err := scanner.ScanHosts(ctx, []string{"192.0.2.1", "192.0.2.2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("should find 0 targets with cancelled context, got %d", len(targets))
	}
}

func TestIdentifyServices(t *testing.T) {
	services := identifyServices([]int{22, 80, 99999})
	if len(services) != 3 {
		t.Fatalf("expected 3 services, got %d", len(services))
	}
	if services[0] != "SSH" {
		t.Fatalf("port 22 = %s, want SSH", services[0])
	}
	if services[1] != "HTTP" {
		t.Fatalf("port 80 = %s, want HTTP", services[1])
	}
}

func TestIsPivotable(t *testing.T) {
	if !isPivotable([]int{22, 80}) {
		t.Fatal("port 22 should be pivotable")
	}
	if isPivotable([]int{3306, 5432}) {
		t.Fatal("MySQL/Postgres ports should not be pivotable")
	}
}
