// Package operator provides multi-operator management for team engagements.
// Operators authenticate via tokens and have role-based access control.
package operator

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Role defines the access level for an operator.
type Role string

const (
	RoleAdmin    Role = "admin"    // full access
	RoleOperator Role = "operator" // can modify sessions, tunnels, routes
	RoleObserver Role = "observer" // read-only
)

// Operator represents a connected team member.
type Operator struct {
	Name    string    `json:"name"`
	Token   string    `json:"token"`
	Role    Role      `json:"role"`
	Created time.Time `json:"created"`
}

// AuditEntry records a single operator action.
type AuditEntry struct {
	Time     time.Time `json:"time"`
	Operator string    `json:"operator"`
	Action   string    `json:"action"`
	Target   string    `json:"target,omitempty"` // session ID, tunnel ID, etc.
	Detail   string    `json:"detail,omitempty"`
}

// LootEntry is a shared finding (credential, hash, etc.).
type LootEntry struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"`     // "credential", "hash", "finding"
	Host     string    `json:"host"`
	Data     string    `json:"data"`
	AddedBy  string    `json:"added_by"`
	AddedAt  time.Time `json:"added_at"`
}

// Registry manages operators, audit log, and shared loot.
type Registry struct {
	operators map[string]*Operator // token -> operator
	locked    map[string]string    // session ID -> operator name (who has lock)
	audit     []AuditEntry
	loot      []LootEntry
	mu        sync.RWMutex
}

// NewRegistry creates an empty operator registry.
func NewRegistry() *Registry {
	return &Registry{
		operators: make(map[string]*Operator),
		locked:    make(map[string]string),
	}
}

// AddOperator creates a new operator with a generated token.
func (r *Registry) AddOperator(name string, role Role) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate name.
	for _, op := range r.operators {
		if op.Name == name {
			return "", fmt.Errorf("operator %q already exists", name)
		}
	}

	token := generateToken()
	r.operators[token] = &Operator{
		Name:    name,
		Token:   token,
		Role:    role,
		Created: time.Now(),
	}
	return token, nil
}

// RemoveOperator removes an operator by name.
func (r *Registry) RemoveOperator(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for token, op := range r.operators {
		if op.Name == name {
			delete(r.operators, token)
			break
		}
	}
	// Release any locks held by this operator.
	for sid, holder := range r.locked {
		if holder == name {
			delete(r.locked, sid)
		}
	}
}

// Authenticate returns the operator for a given token, or nil if invalid.
func (r *Registry) Authenticate(token string) *Operator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.operators[token]
}

// ListOperators returns all registered operators.
func (r *Registry) ListOperators() []*Operator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var ops []*Operator
	for _, op := range r.operators {
		ops = append(ops, op)
	}
	return ops
}

// CanWrite returns true if the role allows write operations.
func (r Role) CanWrite() bool {
	return r == RoleAdmin || r == RoleOperator
}

// IsAdmin returns true if the role is admin.
func (r Role) IsAdmin() bool {
	return r == RoleAdmin
}

// --- Session locking ---

// LockSession claims exclusive control of a session for an operator.
func (r *Registry) LockSession(sessionID, operatorName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if holder, locked := r.locked[sessionID]; locked {
		if holder == operatorName {
			return nil // already locked by this operator
		}
		return fmt.Errorf("session %s locked by %s", sessionID, holder)
	}
	r.locked[sessionID] = operatorName
	return nil
}

// UnlockSession releases exclusive control.
func (r *Registry) UnlockSession(sessionID, operatorName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if holder, locked := r.locked[sessionID]; locked {
		if holder != operatorName {
			return fmt.Errorf("session %s locked by %s, not %s", sessionID, holder, operatorName)
		}
		delete(r.locked, sessionID)
	}
	return nil
}

// SessionLockedBy returns who holds the lock, or empty string.
func (r *Registry) SessionLockedBy(sessionID string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.locked[sessionID]
}

// --- Audit log ---

// Log records an operator action.
func (r *Registry) Log(operatorName, action, target, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.audit = append(r.audit, AuditEntry{
		Time:     time.Now(),
		Operator: operatorName,
		Action:   action,
		Target:   target,
		Detail:   detail,
	})
	// Cap at 10000 entries.
	if len(r.audit) > 10000 {
		r.audit = r.audit[len(r.audit)-10000:]
	}
}

// AuditLog returns the full audit log.
func (r *Registry) AuditLog() []AuditEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cp := make([]AuditEntry, len(r.audit))
	copy(cp, r.audit)
	return cp
}

// --- Shared loot ---

// AddLoot stores a credential or finding.
func (r *Registry) AddLoot(lootType, host, data, operatorName string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := generateToken()[:8]
	r.loot = append(r.loot, LootEntry{
		ID:      id,
		Type:    lootType,
		Host:    host,
		Data:    data,
		AddedBy: operatorName,
		AddedAt: time.Now(),
	})
	return id
}

// ListLoot returns all loot entries.
func (r *Registry) ListLoot() []LootEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cp := make([]LootEntry, len(r.loot))
	copy(cp, r.loot)
	return cp
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
