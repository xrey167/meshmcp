package main

import "testing"

func TestBuiltinCommandsReserveRequestReplyVerbs(t *testing.T) {
	for _, name := range []string{"request", "respond"} {
		if !isBuiltinCommand(name) {
			t.Fatalf("isBuiltinCommand(%q) = false; a plugin could shadow a built-in pub/sub verb", name)
		}
	}
}
