package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnvStore(t *testing.T) {
	t.Setenv("MESHMCP_SECRET_api", "v1")
	s := EnvStore{Prefix: "MESHMCP_SECRET_"}
	if v, ok := s.Get("api"); !ok || v != "v1" {
		t.Fatalf("env secret wrong: %q %v", v, ok)
	}
	if _, ok := s.Get("nope"); ok {
		t.Fatal("missing env secret should not resolve")
	}
}

func TestFileStore(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secrets.json")
	os.WriteFile(p, []byte(`{"a":"1","b":"2"}`), 0o600)
	s, err := NewFileStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := s.Get("a"); !ok || v != "1" {
		t.Fatalf("file secret wrong: %q %v", v, ok)
	}
	if len(s.Names()) != 2 {
		t.Fatalf("expected 2 names, got %v", s.Names())
	}
}

func TestChainFallsThrough(t *testing.T) {
	c := Chain{MapStore{"a": "1"}, MapStore{"b": "2"}}
	if v, _ := c.Get("b"); v != "2" {
		t.Fatalf("chain should fall through to the second store, got %q", v)
	}
	if _, ok := c.Get("z"); ok {
		t.Fatal("chain should miss for an unknown name")
	}
}
