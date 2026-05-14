// Package discovery provides network topology scanning with CIDR parsing,
// concurrent ping sweep, TCP port scanning, and service detection for
// pivot target identification.
package discovery

import (
	"bufio"
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

// ServiceInfo holds detailed information about a discovered service.
type ServiceInfo struct {
	Port    int
	Name    string
	Version string
	Banner  string
}

// Top 20 ports commonly scanned for pivot discovery.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
	445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443,
}

var portServiceMap = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3",
	111: "RPCBind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
	389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kpasswd",
	593: "HTTP-RPC", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
	1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3268: "LDAP-GC",
	3269: "LDAPS-GC", 3306: "MySQL", 3389: "RDP",
	4444: "Meterpreter", 5432: "PostgreSQL", 5900: "VNC",
	5901: "VNC", 5985: "WinRM", 5986: "WinRM-S",
	6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
	8888: "HTTP-Alt", 9200: "Elasticsearch", 9389: "ADWS",
	11211: "Memcached", 27017: "MongoDB",
}

var pivotPorts = map[int]bool{
	22: true, 23: true, 80: true, 443: true,
	3389: true, 5985: true, 5986: true,
	8080: true, 8443: true,
}

// Target represents a discovered host with open ports and service info.
type Target struct {
	IP             string
	OpenPorts      []int
	Services       []string
	ServiceDetails []ServiceInfo
	Pivotable      bool
	Latency        time.Duration
}

// DialFunc is a function that dials a TCP connection. When nil, the scanner
// uses net.Dialer directly (local scanning). Set this to route scans through
// a yamux session for remote scanning through an agent.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Scanner performs network discovery scans.
type Scanner struct {
	ports       []int
	timeout     time.Duration
	concurrency int
	verbosity   int // 0=quick, 1=standard, 2=detailed, 3=intensive
	logger      *log.Logger
	dial        DialFunc
	// OnHostFound is called each time a host with open ports is discovered.
	// Useful for streaming results to a TUI during long scans.
	OnHostFound func(target *Target)
}

// SetVerbosity sets the scan verbosity level (0-3).
// 0 = quick (port scan + service name only)
// 1 = standard (banner grabbing enabled)
// 2 = detailed (additional protocol probes)
// 3 = intensive (full banners with raw output)
func (s *Scanner) SetVerbosity(level int) {
	s.verbosity = level
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

// SetDialer sets a custom dial function for remote scanning through sessions.
func (s *Scanner) SetDialer(dial DialFunc) {
	s.dial = dial
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

	// Global semaphore for total concurrent probes across all hosts and ports.
	sem := make(chan struct{}, s.concurrency)

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			target := s.scanHost(ctx, sem, ip)
			if target != nil {
				mu.Lock()
				targets = append(targets, target)
				mu.Unlock()
				if s.OnHostFound != nil {
					s.OnHostFound(target)
				}
			}
		}(ip)
	}

	wg.Wait()

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].IP < targets[j].IP
	})
	return targets, nil
}

func (s *Scanner) scanHost(ctx context.Context, sem chan struct{}, ip string) *Target {
	var (
		openPorts      []int
		serviceDetails []ServiceInfo
		mu             sync.Mutex
		wg             sync.WaitGroup
		firstSeen      time.Time
	)

	for _, port := range s.ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			// Wait for slot in probe pool
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			if s.isPortOpen(ctx, ip, port) {
				// Record open port under lock, but capture port for service detection
				// outside the lock to avoid serializing banner-grabbing I/O.
				mu.Lock()
				if len(openPorts) == 0 {
					firstSeen = time.Now()
				}
				openPorts = append(openPorts, port)
				mu.Unlock()

				// Service detection runs concurrently — no lock held during I/O.
				svc := s.detectService(ctx, ip, port)

				mu.Lock()
				serviceDetails = append(serviceDetails, svc)
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

	// Sort service details by port
	sort.Slice(serviceDetails, func(i, j int) bool {
		return serviceDetails[i].Port < serviceDetails[j].Port
	})

	return &Target{
		IP:             ip,
		OpenPorts:      openPorts,
		Services:       services,
		ServiceDetails: serviceDetails,
		Pivotable:      pivotable,
		Latency:        latency,
	}
}

func (s *Scanner) isPortOpen(ctx context.Context, ip string, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	var conn net.Conn
	var err error
	network := "tcp"
	if !strings.Contains(addr, "[") {
		network = "tcp4"
	}
	if s.dial != nil {
		conn, err = s.dial(ctx, network, addr)
	} else {
		d := net.Dialer{Timeout: s.timeout}
		network := "tcp"
		if !strings.Contains(addr, "[") {
			network = "tcp4"
		}
		conn, err = d.DialContext(ctx, network, addr)
	}
	if err != nil {
		return false
	}
	conn.Close()
	return true
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
				if start < 1 || end > 65535 || start > end {
					continue
				}
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
			}
		} else {
			if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}
// FormatTargetsAsTree returns an ASCII tree representation of discovered targets.
func FormatTargetsAsTree(targets []*Target, subnet string) string {
	var b strings.Builder
	b.WriteString("[Infrastructure]\n")
	b.WriteString("└── Local Scanner\n")

	if len(targets) == 0 {
		b.WriteString("    └── (no hosts discovered in " + subnet + ")\n")
		return b.String()
	}

	// Group by /24 subnet (common for internal discovery)
	subnets := make(map[string][]*Target)
	for _, t := range targets {
		parts := strings.Split(t.IP, ".")
		if len(parts) == 4 {
			prefix := parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
			subnets[prefix] = append(subnets[prefix], t)
		} else {
			subnets["Other"] = append(subnets["Other"], t)
		}
	}

	// Sort subnets for consistent output
	var sortedSubnets []string
	for s := range subnets {
		sortedSubnets = append(sortedSubnets, s)
	}
	sort.Strings(sortedSubnets)

	for i, s := range sortedSubnets {
		isLastSubnet := i == len(sortedSubnets)-1
		prefix := "    ├── "
		linePrefix := "    │   "
		if isLastSubnet {
			prefix = "    └── "
			linePrefix = "        "
		}

		hosts := subnets[s]
		b.WriteString(fmt.Sprintf("%ssubnet [%s] (%d hosts)\n", prefix, s, len(hosts)))

		for j, h := range hosts {
			hostPrefix := "├── "
			if j == len(hosts)-1 {
				hostPrefix = "└── "
			}
			svcs := strings.Join(h.Services, ",")
			if len(svcs) > 40 {
				svcs = svcs[:37] + "..."
			}
			pivotMark := ""
			if h.Pivotable {
				pivotMark = " [PIVOT]"
			}
			b.WriteString(fmt.Sprintf("%s%shost %s [%s]%s\n", linePrefix, hostPrefix, h.IP, svcs, pivotMark))
			
			// Show detailed service info if available
			for _, svc := range h.ServiceDetails {
				detail := svc.Name
				if svc.Version != "" {
					detail += " " + svc.Version
				}
				b.WriteString(fmt.Sprintf("%s    └─ %d/%s\n", linePrefix, svc.Port, detail))
			}
		}
	}

	return b.String()
}

// grabBanner attempts to grab a service banner from an open port.
func grabBanner(ctx context.Context, ip string, port int, timeout time.Duration) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	// Protocol-specific probes
	switch port {
	case 21: // FTP
		return readBanner(conn, timeout)
	case 22: // SSH
		return readBanner(conn, timeout)
	case 25, 110, 143, 587, 993, 995: // SMTP/POP/IMAP
		return readBanner(conn, timeout)
	case 80, 8080, 8443, 8888: // HTTP
		return grabHTTPBanner(ctx, conn, ip, port, timeout)
	case 443: // HTTPS - skip banner (would need TLS)
		return ""
	case 445, 139: // SMB
		return grabSMBBanner(ctx, conn, timeout)
	case 3389: // RDP
		return grabRDPBanner(ctx, conn, timeout)
	default:
		return readBanner(conn, timeout)
	}
}

// readBanner reads the initial data sent by a server.
func readBanner(conn net.Conn, timeout time.Duration) string {
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return sanitizeBanner(string(buf[:n]))
}

// grabHTTPBanner sends an HTTP HEAD request and returns the Server header.
func grabHTTPBanner(ctx context.Context, conn net.Conn, ip string, port int, timeout time.Duration) string {
	req := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}

	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		}
	}
	return ""
}

// grabSMBBanner attempts to identify SMB version via negotiation.
func grabSMBBanner(ctx context.Context, conn net.Conn, timeout time.Duration) string {
	// SMB1 Negotiate Protocol request
	smb1Negotiate := []byte{
		0x00, 0x00, 0x00, 0x45, // NetBIOS session header
		0xFF, 'S', 'M', 'B', // SMB header
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(smb1Negotiate); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return ""
	}

	// Check for SMB2 response (starts with 0xFE 'SMB')
	if n >= 4 && buf[0] == 0xFE && buf[1] == 'S' && buf[2] == 'M' && buf[3] == 'B' {
		return "SMB2/3"
	}
	// Check for SMB1 response (starts with 0xFF 'SMB')
	if n >= 4 && buf[0] == 0xFF && buf[1] == 'S' && buf[2] == 'M' && buf[3] == 'B' {
		return "SMB1"
	}

	return "SMB"
}

// grabRDPBanner sends an X.224 Connection Request and reads the response.
func grabRDPBanner(ctx context.Context, conn net.Conn, timeout time.Duration) string {
	// X.224 Connection Request PDU
	x224Request := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT header
		0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(x224Request); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	if err != nil || n < 19 {
		return "RDP"
	}

	// Parse RDP version from X.224 response
	if n >= 19 && buf[0] == 0x03 && buf[1] == 0x00 {
		// Look for RDP version in the negotiation response
		return "RDP"
	}

	return "RDP"
}

// sanitizeBanner cleans up banner text for display.
func sanitizeBanner(banner string) string {
	// Remove control characters and excessive whitespace
	banner = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, banner)
	return strings.TrimSpace(banner)
}

// detectService performs banner grabbing and service identification.
// Verbosity level controls detection depth:
// 0 = quick: service name from port number only
// 1 = standard: banner grabbing for version detection
// 2+ = detailed: always grab banners
func (s *Scanner) detectService(ctx context.Context, ip string, port int) ServiceInfo {
	svc := ServiceInfo{
		Port: port,
		Name: portServiceMap[port],
	}

	if svc.Name == "" {
		svc.Name = "unknown"
	}

	// Skip banner grabbing in quick mode (verbosity 0)
	if s.verbosity < 1 {
		return svc
	}

	// Grab banner for service identification
	timeout := s.timeout
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}

	banner := grabBanner(ctx, ip, port, timeout)
	if banner != "" {
		svc.Banner = banner
		svc.Version = parseVersionFromBanner(port, banner)
	}

	return svc
}

// parseVersionFromBanner extracts version info from common service banners.
func parseVersionFromBanner(port int, banner string) string {
	if banner == "" {
		return ""
	}

	banner = strings.ToLower(banner)

	switch port {
	case 22: // SSH
		if strings.Contains(banner, "openssh") {
			if idx := strings.Index(banner, "openssh_"); idx != -1 {
				end := idx + 8
				for end < len(banner) && (banner[end] == '.' || (banner[end] >= '0' && banner[end] <= '9')) {
					end++
				}
				return "OpenSSH " + banner[idx+8:end]
			}
		}
		if strings.Contains(banner, "libssh") {
			return "libssh"
		}
		return "SSH"

	case 21: // FTP
		if strings.Contains(banner, "vsftpd") {
			return "vsftpd"
		}
		if strings.Contains(banner, "proftpd") {
			return "ProFTPD"
		}
		if strings.Contains(banner, "microsoft ftp") {
			return "Microsoft FTP"
		}
		return "FTP"

	case 25, 587: // SMTP
		if strings.Contains(banner, "postfix") {
			return "Postfix"
		}
		if strings.Contains(banner, "sendmail") {
			return "Sendmail"
		}
		if strings.Contains(banner, "microsoft esmtp") {
			return "Microsoft ESMTP"
		}
		return "SMTP"

	case 80, 8080, 8443, 8888: // HTTP
		if strings.Contains(banner, "apache") {
			return "Apache"
		}
		if strings.Contains(banner, "nginx") {
			return "nginx"
		}
		if strings.Contains(banner, "iis") {
			return "IIS"
		}
		if strings.Contains(banner, "lighttpd") {
			return "lighttpd"
		}
		return ""

	default:
		return ""
	}
}
