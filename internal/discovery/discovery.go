package discovery

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

type Target struct {
	IP        string
	OpenPorts []int
	Services  []string
	Pivotable bool
}

type Discovery struct {
	network string
	ports   []int
	timeout time.Duration
}

func New(network string, ports []int) *Discovery {
	return &Discovery{
		network: network,
		ports:   ports,
		timeout: 1 * time.Second,
	}
}

func (d *Discovery) Scan() []*Target {
	var targets []*Target
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 1; i < 255; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			ip := fmt.Sprintf("%s.%d", d.network, i)
			openPorts := d.scanHost(ip)

			if len(openPorts) > 0 {
				services := d.identifyServices(openPorts)
				pivotable := d.isPivotable(openPorts)

				mu.Lock()
				targets = append(targets, &Target{
					IP:        ip,
					OpenPorts: openPorts,
					Services:  services,
					Pivotable: pivotable,
				})
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()
	return targets
}

func (d *Discovery) scanHost(ip string) []int {
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range d.ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			addr := fmt.Sprintf("%s:%d", ip, port)
			conn, err := net.DialTimeout("tcp", addr, d.timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, port)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return open
}

func (d *Discovery) identifyServices(ports []int) []string {
	services := make(map[int]string)
	services[22] = "SSH"
	services[23] = "Telnet"
	services[80] = "HTTP"
	services[443] = "HTTPS"
	services[445] = "SMB"
	services[139] = "NetBIOS"
	services[3389] = "RDP"
	services[5900] = "VNC"
	services[5901] = "VNC"
	services[8080] = "HTTP-Proxy"
	services[8443] = "HTTPS-Alt"
	services[3306] = "MySQL"
	services[5432] = "PostgreSQL"
	services[1433] = "MSSQL"
	services[27017] = "MongoDB"
	services[6379] = "Redis"
	services[9200] = "Elasticsearch"

	var result []string
	for _, port := range ports {
		if svc, ok := services[port]; ok {
			result = append(result, svc)
		} else {
			result = append(result, "Unknown")
		}
	}
	return result
}

func (d *Discovery) isPivotable(ports []int) bool {
	pivotPorts := map[int]bool{
		22:   true,
		23:   true,
		443:  true,
		8080: true,
		8443: true,
	}

	for _, port := range ports {
		if pivotPorts[port] {
			return true
		}
	}
	return false
}

func GenerateIPRange(prefix string) []string {
	ips := make([]string, 254)
	for i := 1; i < 255; i++ {
		ips[i-1] = fmt.Sprintf("%s.%d", prefix, i)
	}
	return ips
}

func ParsePortRange(s string) []int {
	var ports []int

	if s == "" {
		return ports
	}

	start, end := 0, 0
	if n, _ := fmt.Sscanf(s, "%d-%d", &start, &end); n == 2 {
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	} else {
		p, _ := strconv.Atoi(s)
		ports = append(ports, p)
	}

	return ports
}
