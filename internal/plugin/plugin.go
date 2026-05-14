// Package plugin provides a module system for extending Burrow with custom
// post-exploitation capabilities. Modules register via init() and are
// available to operators through the TUI, API, and automation SDKs.
//
// Modules implement the Module interface and register themselves:
//
//	func init() {
//	    plugin.Register(&MyModule{})
//	}
//
// The server dispatches module commands to agents via the existing exec
// framework or custom protocol messages.
package plugin

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Module is the interface that all Burrow plugins must implement.
type Module interface {
	// Name returns the unique module identifier (e.g., "mimikatz", "portscan").
	Name() string
	// Description returns a brief description of the module.
	Description() string
	// Author returns the module author.
	Author() string
	// Options returns the configurable parameters for this module.
	Options() []Option
	// Run executes the module against a target session.
	// The context carries the session ID and operator identity.
	// Returns output text and any error.
	Run(ctx context.Context, env *Environment) (string, error)
}

// Option describes a configurable parameter for a module.
type Option struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

// Environment provides the module with access to session management
// and operator context without importing internal packages directly.
type Environment struct {
	SessionID  string
	Operator   string
	Params     map[string]string
	ExecFunc   func(sessionID, command string) (string, error)
	UploadFunc func(sessionID, remotePath string, data []byte) error
}

// registry holds all registered modules.
var (
	registry = make(map[string]Module)
	mu       sync.RWMutex
)

// Register adds a module to the global registry.
// Typically called from init() in the module's package.
func Register(m Module) {
	mu.Lock()
	defer mu.Unlock()
	registry[m.Name()] = m
}

// Get returns a registered module by name.
func Get(name string) (Module, bool) {
	mu.RLock()
	defer mu.RUnlock()
	m, ok := registry[name]
	return m, ok
}

// List returns all registered module names sorted alphabetically.
func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListModules returns all registered modules sorted by name.
func ListModules() []Module {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	mods := make([]Module, 0, len(names))
	for _, name := range names {
		mods = append(mods, registry[name])
	}
	return mods
}

// Run executes a module by name with the given environment.
func Run(ctx context.Context, name string, env *Environment) (string, error) {
	m, ok := Get(name)
	if !ok {
		return "", fmt.Errorf("module %q not found", name)
	}

	// Apply defaults and validate required options.
	for _, opt := range m.Options() {
		v, exists := env.Params[opt.Name]
		if !exists || v == "" {
			if opt.Default != "" {
				env.Params[opt.Name] = opt.Default
			} else if opt.Required {
				return "", fmt.Errorf("required option %q not set", opt.Name)
			}
		}
	}

	return m.Run(ctx, env)
}
