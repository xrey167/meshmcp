package registry

import "testing"

func TestFileRegistry(t *testing.T) {
	r, err := NewFileRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(r.Register("svc", "a:1"))
	must(r.Register("svc", "b:2"))
	must(r.Register("svc", "b:2")) // idempotent
	must(r.Register("other", "c:3"))

	m, err := r.Lookup()
	must(err)
	if len(m["svc"]) != 2 {
		t.Fatalf("svc = %v, want 2 addrs", m["svc"])
	}
	if len(m["other"]) != 1 || m["other"][0] != "c:3" {
		t.Fatalf("other = %v", m["other"])
	}

	must(r.Deregister("svc", "a:1"))
	m, err = r.Lookup()
	must(err)
	if len(m["svc"]) != 1 || m["svc"][0] != "b:2" {
		t.Fatalf("after deregister svc = %v, want [b:2]", m["svc"])
	}
}
