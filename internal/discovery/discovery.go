// Package discovery provides network topology scanning with CIDR parsing,
// concurrent ping sweep, and TCP port scanning for pivot target identification.
package discovery

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Top 20 ports commonly scanned for pivot discovery.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
	445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443,
}

var portServiceMap = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	53: "DNS", 80: "HTTP", 110: "POP3", 135: "MSRPC",
	139: "NetBIOS", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
	995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
	5432: "PostgreSQL", 5900: "VNC", 5901: "VNC", 6379: "Redis",
	8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
	27017: "MongoDB",
}

var pivotPorts = map[int]bool{
	22: true, 23: true, 80: true, 443: true,
	3389: true, 8080: true, 8443: true,
}

// Target represents a discovered host with open ports and service info.
type Target struct {
	IP        string
	OpenPorts []int
	Services  []string
	Pivotable bool
	Latency   time.Duration
}

// Scanner performs network discovery scans.
type Scanner struct {
	ports       []int
	timeout     time.Duration
	concurrency int
	logger      *log.Logger
}

// New creates a Scanner. If ports is nil, DefaultPorts are used.
func New(network string, ports []int) *Scanner {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	return &Scanner{
		ports:       ports,
		timeout:     2 * time.Second,
		concurrency: 256,
		logger:      log.Default(),
	}
}

// NewScanner creates a Scanner with explicit configuration.
func NewScanner(ports []int, timeout time.Duration, concurrency int) *Scanner {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	if concurrency <= 0 {
		concurrency = 256
	}
	return &Scanner{
		ports:       ports,
		timeout:     timeout,
		concurrency: concurrency,
		logger:      log.Default(),
	}
}

// Ports returns the configured port list.
func (s *Scanner) Ports() []int {
	return s.ports
}

// ScanSubnet scans all hosts in a CIDR subnet.
func (s *Scanner) ScanSubnet(ctx context.Context, subnet string) ([]*Target, error) {
	ips, err := ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("parse subnet: %w", err)
	}
	return s.ScanHosts(ctx, ips)
}

// ScanHosts scans a list of IPs concurrently.
func (s *Scanner) ScanHosts(ctx context.Context, ips []string) ([]*Target, error) {
	var (
		targets []*Target
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	sem := make(chan struct{}, s.concurrency)

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}

		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			target := s.scanHost(ctx, ip)
			if target != nil {
				mu.Lock()
				targets = append(targets, target)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].IP < targets[j].IP
	})
	return targets, nil
}

func (s *Scanner) scanHost(ctx context.Context, ip string) *Target {
	var (
		openPorts []int
		mu        sync.Mutex
		wg        sync.WaitGroup
		firstSeen time.Time
	)

	for _, port := range s.ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			if s.isPortOpen(ctx, ip, port) {
				mu.Lock()
				if len(openPorts) == 0 {
					firstSeen = time.Now()
				}
				openPorts = append(openPorts, port)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()

	if len(openPorts) == 0 {
		return nil
	}

	sort.Ints(openPorts)
	services := identifyServices(openPorts)
	pivotable := isPivotable(openPorts)

	var latency time.Duration
	if !firstSeen.IsZero() {
		latency = time.Since(firstSeen)
	}

	return &Target{
		IP:        ip,
		OpenPorts: openPorts,
		Services:  services,
		Pivotable: pivotable,
		Latency:   latency,
	}
}

func (s *Scanner) isPortOpen(ctx context.Context, ip string, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Scan is the legacy API - scans the network prefix as /24.
func (s *Scanner) Scan() []*Target {
	// Legacy compatibility: not used by new CLI but kept for old callers
	return nil
}

func identifyServices(ports []int) []string {
	var result []string
	for _, port := range ports {
		if svc, ok := portServiceMap[port]; ok {
			result = append(result, svc)
		} else {
			result = append(result, fmt.Sprintf("Unknown(%d)", port))
		}
	}
	return result
}

func isPivotable(ports []int) bool {
	for _, port := range ports {
		if pivotPorts[port] {
			return true
		}
	}
	return false
}

// ParseCIDR parses a CIDR notation subnet and returns all host IPs.
// Supports /24, /16, etc. Also handles bare "10.0.0" prefix notation.
func ParseCIDR(subnet string) ([]string, error) {
	if !strings.Contains(subnet, "/") {
		parts := strings.Split(subnet, ".")
		switch len(parts) {
		case 3:
			subnet = subnet + ".0/24"
		case 4:
			subnet = subnet + "/32"
		default:
			return nil, fmt.Errorf("invalid subnet format: %s", subnet)
		}
	}

	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %s: %w", subnet, err)
	}

	var ips []string
	maskSize, bits := ipNet.Mask.Size()

	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 CIDR supported, got %d-bit", bits)
	}

	// For /32, return just the single IP
	if maskSize == 32 {
		return []string{ip.String()}, nil
	}

	// Calculate network range
	networkIP := ipNet.IP.To4()
	if networkIP == nil {
		return nil, fmt.Errorf("not an IPv4 address: %s", subnet)
	}

	networkInt := binary.BigEndian.Uint32(networkIP)
	hostBits := uint(bits - maskSize)
	numHosts := (1 << hostBits) - 2 // Exclude network and broadcast

	if numHosts <= 0 {
		return []string{ip.String()}, nil
	}

	// Cap at /16 (65534 hosts) to prevent accidental huge scans
	if numHosts > 65534 {
		numHosts = 65534
	}

	for i := uint32(1); i <= uint32(numHosts); i++ {
		hostIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(hostIP, networkInt+i)
		ips = append(ips, hostIP.String())
	}

	return ips, nil
}

// GenerateIPRange generates IPs from a /24 prefix (legacy API).
func GenerateIPRange(prefix string) []string {
	ips := make([]string, 254)
	for i := 1; i < 255; i++ {
		ips[i-1] = fmt.Sprintf("%s.%d", prefix, i)
	}
	return ips
}

// ParsePortRange parses port range strings like "80", "1-1024", "22,80,443".
func ParsePortRange(s string) []int {
	var ports []int
	if s == "" {
		return ports
	}

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			var start, end int
			if n, _ := fmt.Sscanf(part, "%d-%d", &start, &end); n == 2 {
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
			}
		} else {
			if p, err := strconv.Atoi(part); err == nil && p > 0 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}
