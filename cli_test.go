package main

import "testing"

func TestArgFlagsCoercion(t *testing.T) {
	a := argFlags{}
	for _, kv := range []string{"n=3", "text=hello", "flag=true", "path=go.mod", `list=[1,2]`} {
		if err := a.Set(kv); err != nil {
			t.Fatalf("Set(%q): %v", kv, err)
		}
	}
	if a["n"] != float64(3) {
		t.Fatalf("n = %#v, want float64(3)", a["n"])
	}
	if a["text"] != "hello" {
		t.Fatalf("text = %#v, want bare string hello", a["text"])
	}
	if a["flag"] != true {
		t.Fatalf("flag = %#v, want bool true", a["flag"])
	}
	if a["path"] != "go.mod" {
		t.Fatalf("path = %#v, want string go.mod", a["path"])
	}
	if _, ok := a["list"].([]any); !ok {
		t.Fatalf("list = %#v, want []any", a["list"])
	}
}

func TestArgFlagsRejectsMissingEquals(t *testing.T) {
	a := argFlags{}
	if err := a.Set("noequals"); err == nil {
		t.Fatalf("expected error for missing '='")
	}
}
