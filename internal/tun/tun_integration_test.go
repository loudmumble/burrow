//go:build integration

// Integration tests for the tun package.
//
// These tests require root or CAP_NET_ADMIN capability because they create
// real TUN interfaces via the kernel. They are excluded from normal test runs.
//
// Run with: go test -tags integration -v ./internal/tun/
//
// You must run as root (or with sudo) for these to pass.
package tun

import (
	"net"
	"testing"
)

func TestNewInterface(t *testing.T) {
	ifce, err := New("burrowtest0")
	if err != nil {
		t.Fatalf("New() error = %v (are you running as root?)", err)
	}
	defer ifce.Close()

	if ifce.Name == "" {
		t.Error("interface name is empty")
	}
	if ifce.MTU != DefaultMTU {
		t.Errorf("MTU = %d, want %d", ifce.MTU, DefaultMTU)
	}
}

func TestNewInterfaceDefaultName(t *testing.T) {
	ifce, err := New("")
	if err != nil {
		t.Fatalf("New(\"\") error = %v (are you running as root?)", err)
	}
	defer ifce.Close()

	if ifce.Name != DefaultName {
		t.Errorf("Name = %q, want %q", ifce.Name, DefaultName)
	}
}

func TestConfigureInterface(t *testing.T) {
	ifce, err := New("burrowtest1")
	if err != nil {
		t.Fatalf("New() error = %v (are you running as root?)", err)
	}
	defer ifce.Close()

	ip, mask := DefaultMagicIP()
	if err := ifce.Configure(ip, mask); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
}

func TestAddRemoveRoute(t *testing.T) {
	ifce, err := New("burrowtest2")
	if err != nil {
		t.Fatalf("New() error = %v (are you running as root?)", err)
	}
	defer ifce.Close()

	ip := net.IPv4(240, 0, 0, 99)
	mask := net.CIDRMask(32, 32)
	if err := ifce.Configure(ip, mask); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}

	cidr := "198.51.100.0/24"
	if err := ifce.AddRoute(cidr); err != nil {
		t.Fatalf("AddRoute(%q) error = %v", cidr, err)
	}

	if err := ifce.RemoveRoute(cidr); err != nil {
		t.Fatalf("RemoveRoute(%q) error = %v", cidr, err)
	}
}
