package plugin

import (
	"context"
	"testing"
)

type testModule struct{}

func (m *testModule) Name() string        { return "test-mod" }
func (m *testModule) Description() string  { return "A test module" }
func (m *testModule) Author() string       { return "test" }
func (m *testModule) Options() []Option {
	return []Option{
		{Name: "target", Description: "target IP", Required: true},
		{Name: "port", Description: "port", Required: false, Default: "445"},
	}
}
func (m *testModule) Run(_ context.Context, env *Environment) (string, error) {
	return "ok: " + env.Params["target"] + ":" + env.Params["port"], nil
}

func TestRegisterAndGet(t *testing.T) {
	Register(&testModule{})
	m, ok := Get("test-mod")
	if !ok {
		t.Fatal("module not found")
	}
	if m.Name() != "test-mod" {
		t.Errorf("name = %q, want %q", m.Name(), "test-mod")
	}
}

func TestList(t *testing.T) {
	Register(&testModule{})
	names := List()
	found := false
	for _, n := range names {
		if n == "test-mod" {
			found = true
		}
	}
	if !found {
		t.Error("test-mod not in List()")
	}
}

func TestRunModule(t *testing.T) {
	Register(&testModule{})
	env := &Environment{
		SessionID: "s1",
		Operator:  "alice",
		Params:    map[string]string{"target": "10.0.0.1"},
	}
	out, err := Run(context.Background(), "test-mod", env)
	if err != nil {
		t.Fatal(err)
	}
	if out != "ok: 10.0.0.1:445" {
		t.Errorf("output = %q, want %q", out, "ok: 10.0.0.1:445")
	}
}

func TestRunMissingRequired(t *testing.T) {
	Register(&testModule{})
	env := &Environment{
		Params: map[string]string{},
	}
	_, err := Run(context.Background(), "test-mod", env)
	if err == nil {
		t.Error("should fail with missing required option")
	}
}

func TestRunNotFound(t *testing.T) {
	_, err := Run(context.Background(), "nonexistent", &Environment{Params: map[string]string{}})
	if err == nil {
		t.Error("should fail for unknown module")
	}
}
