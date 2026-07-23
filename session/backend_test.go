package session

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is re-invoked by the tests below as both the egress
// wrapper and the backend it wraps. It is a normal no-op test unless
// GO_WANT_HELPER_PROCESS=1 is set in its environment (the standard os/exec
// helper-process pattern). Each mode os.Exit()s so the test framework never
// prints its own summary onto the MCP stdout stream.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	// Arguments after the first "--" are ours.
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "helper: no mode")
		os.Exit(2)
	}
	switch args[0] {
	case "wrapper":
		// A cross-platform pass-through "jailer": record the argv it was
		// spawned with (so the test can prove prepend order), then run its
		// tail arguments as a child with the SAME stdio, exactly as a real
		// `firejail --net=none <cmd>` would exec its tail. It applies no
		// containment — this exercises WIRING only, never OS enforcement.
		argvFile := args[1]
		tail := args[2:]
		_ = os.WriteFile(argvFile, []byte(strings.Join(os.Args, "\n")), 0o600)
		if len(tail) == 0 {
			os.Exit(0)
		}
		child := exec.Command(tail[0], tail[1:]...)
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		child.Env = os.Environ()
		if err := child.Run(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "backend":
		// Minimal MCP backend over stdio: answer initialize.
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var m struct {
				ID     *int   `json:"id"`
				Method string `json:"method"`
			}
			_ = json.Unmarshal(sc.Bytes(), &m)
			if m.ID == nil {
				continue
			}
			if m.Method == "initialize" {
				fmt.Fprintf(os.Stdout, `{"jsonrpc":"2.0","id":%d,"result":{"ok":true}}`+"\n", *m.ID)
			}
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "helper: unknown mode %q\n", args[0])
		os.Exit(2)
	}
}

func helperEnv() []string { return append(os.Environ(), "GO_WANT_HELPER_PROCESS=1") }

func readLineFrom(t *testing.T, r io.Reader) string {
	t.Helper()
	br := bufio.NewReader(r)
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		line, err := br.ReadString('\n')
		ch <- res{line, err}
	}()
	select {
	case got := <-ch:
		if got.line == "" && got.err != nil {
			t.Fatalf("read backend response: %v", got.err)
		}
		return got.line
	case <-time.After(10 * time.Second):
		t.Fatal("timed out reading backend response")
		return ""
	}
}

func initHandshake(t *testing.T, be Backend) string {
	t.Helper()
	if _, err := be.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")); err != nil {
		t.Fatalf("write initialize: %v", err)
	}
	return readLineFrom(t, be)
}

// TestExecBackendFactoryWrapperPrepend proves the wrapper is prepended in the
// correct order (wrapper[0] execs, wrapper[1:]+name+args become its argv) and
// that stdio survives the extra hop: a full MCP initialize handshake completes
// through wrapper -> backend. It asserts WIRING only; the pass-through wrapper
// applies no network containment (the real firejail/bwrap/netns enforcement
// path is Linux-only and is not exercised here).
func TestExecBackendFactoryWrapperPrepend(t *testing.T) {
	self := os.Args[0]
	argvFile := filepath.Join(t.TempDir(), "argv.txt")

	wrapper := []string{self, "-test.run=TestHelperProcess", "--", "wrapper", argvFile}
	name := self
	args := []string{"-test.run=TestHelperProcess", "--", "backend"}

	factory := ExecBackendFactoryWithWrapper(wrapper, name, args, helperEnv())
	be, err := factory(Meta{SessionID: "s1"})
	if err != nil {
		t.Fatalf("spawn wrapped backend: %v", err)
	}
	defer be.Close()

	if resp := initHandshake(t, be); !strings.Contains(resp, `"ok":true`) {
		t.Fatalf("handshake through wrapper = %q, want ok:true", resp)
	}

	// The handshake completing proves the wrapper already wrote argvFile
	// (it does so before running the child that produced the response).
	raw, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read recorded argv: %v", err)
	}
	got := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// Expected process argv = wrapper[0] then wrapper[1:]+name+args. Compare
	// from index 1 to sidestep any os.Args[0] path normalization; the order
	// after wrapper[0] is what proves the prepend contract.
	want := append(append(append([]string{}, wrapper...), name), args...)
	if len(got) != len(want) {
		t.Fatalf("wrapper saw %d argv elements, want %d\n got=%v\nwant=%v", len(got), len(want), got, want)
	}
	for i := 1; i < len(want); i++ {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q\n got=%v\nwant=%v", i, got[i], want[i], got, want)
		}
	}
}

// TestExecBackendFactoryEmptyWrapperUnchanged verifies a nil/empty wrapper is
// behaviorally identical to the no-wrapper path: the backend handshakes
// directly. Covers both ExecBackendFactoryWithWrapper(nil,...) and the
// original ExecBackendFactory signature (which delegates with a nil wrapper).
func TestExecBackendFactoryEmptyWrapperUnchanged(t *testing.T) {
	self := os.Args[0]
	name := self
	args := []string{"-test.run=TestHelperProcess", "--", "backend"}

	factories := map[string]BackendFactory{
		"nil wrapper":        ExecBackendFactoryWithWrapper(nil, name, args, helperEnv()),
		"empty wrapper":      ExecBackendFactoryWithWrapper([]string{}, name, args, helperEnv()),
		"original signature": ExecBackendFactory(name, args, helperEnv()),
	}
	for label, factory := range factories {
		t.Run(label, func(t *testing.T) {
			be, err := factory(Meta{SessionID: "s"})
			if err != nil {
				t.Fatalf("spawn: %v", err)
			}
			defer be.Close()
			if resp := initHandshake(t, be); !strings.Contains(resp, `"ok":true`) {
				t.Fatalf("handshake = %q, want ok:true", resp)
			}
		})
	}
}

// TestExecBackendFactoryWrapperFailClosed verifies the runtime backstop: a
// wrapper that cannot start does not fall through to an unwrapped spawn — the
// factory returns an error, so the backend never runs with full egress.
func TestExecBackendFactoryWrapperFailClosed(t *testing.T) {
	name := os.Args[0]
	args := []string{"-test.run=TestHelperProcess", "--", "backend"}

	t.Run("empty wrapper[0]", func(t *testing.T) {
		factory := ExecBackendFactoryWithWrapper([]string{""}, name, args, helperEnv())
		if be, err := factory(Meta{}); err == nil {
			_ = be.Close()
			t.Fatal("empty wrapper[0] must fail closed, got nil error")
		}
	})
	t.Run("unresolvable wrapper", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "no-such-jailer")
		factory := ExecBackendFactoryWithWrapper([]string{bad}, name, args, helperEnv())
		if be, err := factory(Meta{}); err == nil {
			_ = be.Close()
			t.Fatal("unresolvable wrapper must fail to start, got nil error")
		}
	})
}
