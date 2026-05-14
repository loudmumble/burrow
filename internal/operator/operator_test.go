package operator

import (
	"testing"
)

func TestAddAuthenticateOperator(t *testing.T) {
	r := NewRegistry()
	token, err := r.AddOperator("alice", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("token should not be empty")
	}

	op := r.Authenticate(token)
	if op == nil {
		t.Fatal("should authenticate valid token")
	}
	if op.Name != "alice" {
		t.Errorf("name = %q, want %q", op.Name, "alice")
	}
	if op.Role != RoleAdmin {
		t.Errorf("role = %q, want %q", op.Role, RoleAdmin)
	}
}

func TestDuplicateOperator(t *testing.T) {
	r := NewRegistry()
	r.AddOperator("bob", RoleOperator)
	_, err := r.AddOperator("bob", RoleOperator)
	if err == nil {
		t.Error("should reject duplicate name")
	}
}

func TestInvalidToken(t *testing.T) {
	r := NewRegistry()
	if r.Authenticate("bogus") != nil {
		t.Error("should return nil for invalid token")
	}
}

func TestRemoveOperator(t *testing.T) {
	r := NewRegistry()
	token, _ := r.AddOperator("charlie", RoleObserver)
	r.RemoveOperator("charlie")
	if r.Authenticate(token) != nil {
		t.Error("should not authenticate removed operator")
	}
}

func TestSessionLocking(t *testing.T) {
	r := NewRegistry()

	if err := r.LockSession("s1", "alice"); err != nil {
		t.Fatal(err)
	}
	if r.SessionLockedBy("s1") != "alice" {
		t.Error("session should be locked by alice")
	}

	if err := r.LockSession("s1", "bob"); err == nil {
		t.Error("bob should not be able to lock alice's session")
	}

	if err := r.UnlockSession("s1", "alice"); err != nil {
		t.Fatal(err)
	}
	if r.SessionLockedBy("s1") != "" {
		t.Error("session should be unlocked")
	}
}

func TestAuditLog(t *testing.T) {
	r := NewRegistry()
	r.Log("alice", "tunnel.add", "s1", "local 8080->10.0.0.1:80")
	r.Log("bob", "route.add", "s1", "10.0.0.0/24")

	log := r.AuditLog()
	if len(log) != 2 {
		t.Fatalf("audit log len = %d, want 2", len(log))
	}
	if log[0].Operator != "alice" {
		t.Errorf("log[0].Operator = %q, want %q", log[0].Operator, "alice")
	}
}

func TestRolePermissions(t *testing.T) {
	if !RoleAdmin.CanWrite() {
		t.Error("admin should be able to write")
	}
	if !RoleOperator.CanWrite() {
		t.Error("operator should be able to write")
	}
	if RoleObserver.CanWrite() {
		t.Error("observer should not be able to write")
	}
	if !RoleAdmin.IsAdmin() {
		t.Error("admin should be admin")
	}
	if RoleOperator.IsAdmin() {
		t.Error("operator should not be admin")
	}
}

func TestSharedLoot(t *testing.T) {
	r := NewRegistry()
	id := r.AddLoot("credential", "10.0.0.1", "admin:Password123!", "alice")
	if id == "" {
		t.Error("loot ID should not be empty")
	}

	loot := r.ListLoot()
	if len(loot) != 1 {
		t.Fatalf("loot len = %d, want 1", len(loot))
	}
	if loot[0].Data != "admin:Password123!" {
		t.Errorf("loot data = %q, want %q", loot[0].Data, "admin:Password123!")
	}
}
