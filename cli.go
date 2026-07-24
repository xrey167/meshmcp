package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"meshmcp/mcpclient"
)

// argFlags collects repeatable --arg key=value pairs. Values are coerced to
// JSON (numbers, booleans, quoted strings) when possible, else kept as a
// bare string, so "--arg n=3" is a number and "--arg path=go.mod" a string.
type argFlags map[string]any

func (a argFlags) String() string { return "" }

func (a argFlags) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok {
		return fmt.Errorf("expected key=value, got %q", s)
	}
	var parsed any
	if err := json.Unmarshal([]byte(v), &parsed); err == nil {
		a[k] = parsed
	} else {
		a[k] = v
	}
	return nil
}

// dialMCP joins the mesh, dials the target backend, and completes the MCP
// handshake. The caller must call the returned cleanup.
func dialMCP(o *meshOptions, target string) (*mcpclient.Client, func(), error) {
	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return nil, nil, err
	}
	conn, err := client.Dial(context.Background(), "tcp", target)
	if err != nil {
		stopMesh(client)
		return nil, nil, fmt.Errorf("dial %s over mesh: %w", target, err)
	}
	// Print server-initiated notifications (progress, tasks/status, ...) to
	// stderr so forwarded/streamed events are visible.
	mc := mcpclient.New(conn, func(method string, params json.RawMessage) {
		fmt.Fprintf(os.Stderr, "notify: %s %s\n", method, string(params))
	})
	if _, err := mc.Initialize(context.Background(), "meshmcp-cli"); err != nil {
		mc.Close()
		stopMesh(client)
		return nil, nil, fmt.Errorf("initialize: %w", err)
	}
	cleanup := func() { mc.Close(); stopMesh(client) }
	return mc, cleanup, nil
}

// cmdLs lists a backend's tools, resources, and prompts.
func cmdLs(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	o := meshFlags(fs)
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON instead of a text listing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp ls [flags] <peer-ip:port>")
	}
	mc, cleanup, err := dialMCP(o, fs.Arg(0))
	if err != nil {
		return err
	}
	defer cleanup()
	ctx := context.Background()

	tools, err := mc.ListTools(ctx)
	if err != nil {
		return err
	}
	res, _ := mc.ListResources(ctx)
	pr, _ := mc.ListPrompts(ctx)

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"tools": tools, "resources": res, "prompts": pr,
		})
	}

	fmt.Println("TOOLS:")
	for _, t := range tools {
		fmt.Printf("  %-20s %s\n", t.Name, t.Description)
	}
	if len(res) > 0 {
		fmt.Println("RESOURCES:")
		for _, r := range res {
			fmt.Printf("  %-28s %s\n", r.URI, r.Description)
		}
	}
	if len(pr) > 0 {
		fmt.Println("PROMPTS:")
		for _, p := range pr {
			fmt.Printf("  %-20s %s\n", p.Name, p.Description)
		}
	}
	return nil
}

// cmdCall invokes a tool: meshmcp call [mesh-flags] <peer> <tool> [--arg k=v ...] [--json '{...}'] [--task]
func cmdCall(args []string) error {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	o := meshFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 2 {
		return errors.New("usage: meshmcp call [mesh-flags] <peer-ip:port> <tool> [--arg k=v ...] [--json '{...}'] [--task]")
	}
	target, tool := rest[0], rest[1]

	// Tool-argument flags come after the positionals.
	fs2 := flag.NewFlagSet("call-args", flag.ExitOnError)
	argv := argFlags{}
	fs2.Var(argv, "arg", "tool argument key=value (repeatable)")
	raw := fs2.String("json", "", "tool arguments as a raw JSON object (overrides --arg)")
	task := fs2.Bool("task", false, "run the tool asynchronously as a task")
	wait := fs2.Bool("wait", false, "with --task, wait for the task to finish and print its result")
	capTok := fs2.String("capability", "", "present a signed capability grant; @file reads the token from a file")
	if err := fs2.Parse(rest[2:]); err != nil {
		return err
	}

	capToken, err := readCapabilityToken(*capTok)
	if err != nil {
		return err
	}

	var arguments any = map[string]any(argv)
	if *raw != "" {
		var m any
		if err := json.Unmarshal([]byte(*raw), &m); err != nil {
			return fmt.Errorf("--json: %w", err)
		}
		arguments = m
	}

	mc, cleanup, err := dialMCP(o, target)
	if err != nil {
		return err
	}
	defer cleanup()
	if capToken != "" {
		// Presented in params._meta under the gateway's capability key; the
		// gateway verifies and strips it before the backend ever sees it.
		mc.RequestMeta = map[string]any{"com.meshmcp/capability": capToken}
	}
	ctx := context.Background()

	if *task && *wait {
		st, err := mc.StartTool(ctx, tool, arguments)
		if err != nil {
			return err
		}
		res, err := mc.WaitTask(ctx, st.TaskID, mcpclient.WaitTaskOptions{})
		if len(res.Raw) > 0 {
			printJSON(res.Raw)
		}
		return err // non-nil (incl. *ToolExecutionError) → non-zero exit
	}

	res, err := mc.CallTool(ctx, tool, arguments, *task)
	if err != nil {
		return err
	}
	printJSON(res)
	return nil
}

// readCapabilityToken resolves a --capability flag value: "" stays empty, a
// leading '@' reads the token from a file (the recommended path — keeps the
// token out of shell history), otherwise the value is the token literally.
func readCapabilityToken(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if strings.HasPrefix(v, "@") {
		data, err := os.ReadFile(v[1:])
		if err != nil {
			return "", fmt.Errorf("--capability: %w", err)
		}
		tok := strings.TrimSpace(string(data))
		if tok == "" {
			return "", fmt.Errorf("--capability: file %q is empty", v[1:])
		}
		return tok, nil
	}
	return strings.TrimSpace(v), nil
}

// cmdFunctions lists a backend's tools as provider-neutral function definitions.
func cmdFunctions(args []string) error {
	fs := flag.NewFlagSet("functions", flag.ExitOnError)
	o := meshFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp functions [flags] <peer-ip:port>")
	}
	mc, cleanup, err := dialMCP(o, fs.Arg(0))
	if err != nil {
		return err
	}
	defer cleanup()
	fns, err := mc.ListFunctions(context.Background())
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(fns, "", "  ")
	fmt.Println(string(b))
	return nil
}

// cmdFunctionCall invokes a tool as a model function call: the argument is one
// JSON object {"name","arguments"} where arguments is itself a JSON string.
func cmdFunctionCall(args []string) error {
	fs := flag.NewFlagSet("function-call", flag.ExitOnError)
	o := meshFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		return errors.New("usage: meshmcp function-call [flags] <peer-ip:port> --json '{\"name\":...,\"arguments\":\"{...}\"}'")
	}
	fs2 := flag.NewFlagSet("fc", flag.ExitOnError)
	raw := fs2.String("json", "", "the function call as {\"name\":...,\"arguments\":\"<json>\"}")
	if err := fs2.Parse(rest[1:]); err != nil {
		return err
	}
	if *raw == "" {
		return errors.New("function-call: --json is required")
	}
	var call mcpclient.ModelFunctionCall
	if err := json.Unmarshal([]byte(*raw), &call); err != nil {
		return fmt.Errorf("--json: %w", err)
	}
	mc, cleanup, err := dialMCP(o, rest[0])
	if err != nil {
		return err
	}
	defer cleanup()
	res, err := mc.InvokeFunction(context.Background(), call)
	if len(res.Raw) > 0 {
		printJSON(res.Raw)
	}
	return err
}

// cmdRead reads a resource: meshmcp read <peer> <uri>
func cmdRead(args []string) error {
	fs := flag.NewFlagSet("read", flag.ExitOnError)
	o := meshFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: meshmcp read [flags] <peer-ip:port> <uri>")
	}
	mc, cleanup, err := dialMCP(o, fs.Arg(0))
	if err != nil {
		return err
	}
	defer cleanup()
	res, err := mc.ReadResource(context.Background(), fs.Arg(1))
	if err != nil {
		return err
	}
	printJSON(res)
	return nil
}

// cmdPrompt renders a prompt: meshmcp prompt [mesh-flags] <peer> <name> [--arg k=v ...]
func cmdPrompt(args []string) error {
	fs := flag.NewFlagSet("prompt", flag.ExitOnError)
	o := meshFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 2 {
		return errors.New("usage: meshmcp prompt [mesh-flags] <peer-ip:port> <name> [--arg k=v ...]")
	}
	fs2 := flag.NewFlagSet("prompt-args", flag.ExitOnError)
	argv := argFlags{}
	fs2.Var(argv, "arg", "prompt argument key=value (repeatable)")
	if err := fs2.Parse(rest[2:]); err != nil {
		return err
	}
	mc, cleanup, err := dialMCP(o, rest[0])
	if err != nil {
		return err
	}
	defer cleanup()
	res, err := mc.GetPrompt(context.Background(), rest[1], map[string]any(argv))
	if err != nil {
		return err
	}
	printJSON(res)
	return nil
}

func printJSON(raw json.RawMessage) {
	var pretty any
	if err := json.Unmarshal(raw, &pretty); err == nil {
		b, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Println(string(raw))
}
