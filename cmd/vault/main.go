// vault is a mesh secrets-vault MCP server (F26): a zero-exposure, identity-gated
// secrets manager on the mesh. It STORES and ROTATES secrets into the same JSON
// store the credential broker injects from — so agents keep referencing secrets
// by name ({{secret:NAME}}) and never hold the value. The vault deliberately has
// NO get tool: values leave only via the gateway's broker injection into an
// authorized backend call, never back to the agent that manages them. The
// firewall in front governs who may set / rotate / delete, and audits each.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/xrey167/meshmcp/mcp"
)

// vaultStore is a JSON secrets file ({"name":"value",...}) at mode 0600, written
// atomically. It is the same format secrets.FileStore reads, so pointing a
// gateway's secrets broker at this file injects vault-managed secrets by name.
type vaultStore struct {
	mu   sync.Mutex
	path string
	m    map[string]string
}

func openVault(path string) (*vaultStore, error) {
	v := &vaultStore{path: path, m: map[string]string{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return v, nil
		}
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &v.m); err != nil {
			return nil, fmt.Errorf("parse vault %s: %w", path, err)
		}
	}
	return v, nil
}

func (v *vaultStore) saveLocked() error {
	if v.path == "" {
		return nil
	}
	b, _ := json.MarshalIndent(v.m, "", "  ")
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path)
}

func (v *vaultStore) set(name, value string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.m[name] = value
	return v.saveLocked()
}

// rotate replaces an existing secret with a fresh random value generated
// SERVER-SIDE — the caller never learns it (only backends do, via injection).
func (v *vaultStore) rotate(name string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.m[name]; !ok {
		return false, nil
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false, err
	}
	v.m[name] = hex.EncodeToString(b[:])
	return true, v.saveLocked()
}

func (v *vaultStore) del(name string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.m[name]; !ok {
		return false, nil
	}
	delete(v.m, name)
	return true, v.saveLocked()
}

// names returns the secret names (never values), sorted.
func (v *vaultStore) names() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]string, 0, len(v.m))
	for n := range v.m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func main() {
	path := "vault.json"
	for i, a := range os.Args {
		if a == "--store" && i+1 < len(os.Args) {
			path = os.Args[i+1]
		}
	}
	v, err := openVault(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vault:", err)
		os.Exit(1)
	}
	peer := os.Getenv("MESHMCP_PEER_KEY")
	if peer == "" {
		peer = os.Getenv("MESHMCP_PEER")
	}
	fmt.Fprintf(os.Stderr, "vault: started for peer %q, store %s (%d secrets)\n", peer, path, len(v.names()))

	s := mcp.New("meshmcp-vault", "0.1.0")
	registerVault(s, v)
	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "vault:", err)
		os.Exit(1)
	}
}

func registerVault(s *mcp.Server, v *vaultStore) {
	s.AddTool(mcp.Tool{
		Name:        "set_secret",
		Description: "Store or update a secret by name. Backends reference it as {{secret:NAME}}; the value is never returned by this vault.",
		InputSchema: objSchema(map[string]any{
			"name":  strProp("secret name ([A-Za-z0-9_.-])"),
			"value": strProp("the secret value to store"),
		}, "name", "value"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ Name, Value string }
			if err := json.Unmarshal(args, &a); err != nil || a.Name == "" || a.Value == "" {
				return errResult("name and value are required"), nil
			}
			if err := v.set(a.Name, a.Value); err != nil {
				return errResult("%v", err), nil
			}
			return jsonRes(map[string]any{"stored": a.Name}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "rotate_secret",
		Description: "Rotate a secret to a fresh random value generated server-side. The new value is NOT returned — backends receive it by injection.",
		InputSchema: objSchema(map[string]any{"name": strProp("secret name to rotate")}, "name"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ Name string }
			if err := json.Unmarshal(args, &a); err != nil || a.Name == "" {
				return errResult("name is required"), nil
			}
			ok, err := v.rotate(a.Name)
			if err != nil {
				return errResult("%v", err), nil
			}
			if !ok {
				return errResult("no such secret %q", a.Name), nil
			}
			return jsonRes(map[string]any{"rotated": a.Name}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "delete_secret",
		Description: "Delete a secret by name.",
		InputSchema: objSchema(map[string]any{"name": strProp("secret name to delete")}, "name"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ Name string }
			if err := json.Unmarshal(args, &a); err != nil || a.Name == "" {
				return errResult("name is required"), nil
			}
			ok, err := v.del(a.Name)
			if err != nil {
				return errResult("%v", err), nil
			}
			return jsonRes(map[string]any{"deleted": ok}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "list_secrets",
		Description: "List secret NAMES (never values) held in the vault.",
		InputSchema: objSchema(nil),
		Handler: func(_ context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
			names := v.names()
			return jsonRes(map[string]any{"count": len(names), "names": names}), nil
		},
	})
}

func jsonRes(v any) mcp.ToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(string(b))}}
}

func errResult(format string, a ...any) mcp.ToolResult {
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(fmt.Sprintf(format, a...))}, IsError: true}
}

func objSchema(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
