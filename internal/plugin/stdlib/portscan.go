package stdlib

import (
	"context"
	"fmt"
	"strings"

	"github.com/loudmumble/burrow/internal/plugin"
)

// PortscanModule implements a basic portscan using OS-native tools via the exec framework.
type PortscanModule struct{}

func init() {
	plugin.Register(&PortscanModule{})
}

func (m *PortscanModule) Name() string {
	return "portscan"
}

func (m *PortscanModule) Description() string {
	return "Scan ports on the target agent's local network using built-in OS tools."
}

func (m *PortscanModule) Author() string {
	return "Burrow Team"
}

func (m *PortscanModule) Options() []plugin.Option {
	return []plugin.Option{
		{Name: "target", Description: "Target IP or hostname", Required: true},
		{Name: "ports", Description: "Comma-separated list of ports (e.g. 22,80,443)", Required: true},
		{Name: "os", Description: "Target OS (linux, windows)", Default: "linux"},
	}
}

func (m *PortscanModule) Run(ctx context.Context, env *plugin.Environment) (string, error) {
	target := env.Params["target"]
	ports := strings.Split(env.Params["ports"], ",")
	osType := env.Params["os"]

	var cmd string
	if osType == "linux" {
		var checks []string
		for _, p := range ports {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			checks = append(checks, fmt.Sprintf("(timeout 1 bash -c '</dev/tcp/%s/%s' 2>/dev/null && echo '[+] %s open' || echo '[-] %s closed')", target, p, p, p))
		}
		cmd = strings.Join(checks, " ; ")
	} else if osType == "windows" {
		var checks []string
		for _, p := range ports {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			checks = append(checks, fmt.Sprintf("if (Test-NetConnection -ComputerName %s -Port %s -InformationLevel Quiet) { Write-Output '[+] %s open' } else { Write-Output '[-] %s closed' }", target, p, p, p))
		}
		cmd = "powershell -NoProfile -Command \"" + strings.Join(checks, "; ") + "\""
	} else {
		return "", fmt.Errorf("unsupported OS: %s", osType)
	}

	return env.ExecFunc(env.SessionID, cmd)
}
