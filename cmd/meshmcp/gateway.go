package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/xrey167/meshmcp/gateway"
	"github.com/xrey167/meshmcp/gateway/channels"
)

// cmdGateway is the `meshmcp gateway ...` verb: openclaw-style multi-channel
// ingress folded in as a front door to the same governed harness. Each inbound
// message opens a governed harness run under a per-channel-user identity.
func cmdGateway(args []string) error {
	if len(args) == 0 {
		gatewayUsage()
		return fmt.Errorf("gateway: a subcommand is required")
	}
	switch args[0] {
	case "serve":
		return gatewayServe(args[1:])
	case "channels":
		return gatewayChannels(args[1:])
	case "-h", "--help", "help":
		gatewayUsage()
		return nil
	default:
		gatewayUsage()
		return fmt.Errorf("gateway: unknown subcommand %q", args[0])
	}
}

func gatewayUsage() {
	fmt.Fprint(os.Stderr, `usage: meshmcp gateway <subcommand> [flags]

  serve          start channel ingress; the built-in webchat reads lines from stdin
  channels ls    list the known transport kinds

flags (serve): --audit <file>  --dm-pairing  (require pairing before serving)
`)
}

func gatewayChannels(args []string) error {
	fs := flag.NewFlagSet("gateway channels", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 && fs.Arg(0) != "ls" {
		return fmt.Errorf("gateway channels: only `ls` is supported")
	}
	kinds := append([]string(nil), channels.KnownChannels...)
	sort.Strings(kinds)
	fmt.Printf("known transports (%d):\n", len(kinds))
	for _, k := range kinds {
		note := "token channel (broker-provisioned; live wiring pending)"
		if k == "webchat" {
			note = "in-process (no token)"
		}
		fmt.Printf("  %-16s %s\n", k, note)
	}
	return nil
}

func gatewayServe(args []string) error {
	fs := flag.NewFlagSet("gateway serve", flag.ExitOnError)
	var d harnessDeps
	d.bind(fs)
	pairing := fs.Bool("dm-pairing", false, "require DM pairing before serving a channel session")
	if err := fs.Parse(args); err != nil {
		return err
	}
	eng, closer, err := d.engine()
	if err != nil {
		return err
	}
	defer closer()

	gw := gateway.New(eng, gateway.DMPairing{Required: *pairing, DefaultSandbox: "docker"})
	wc := channels.NewWebChat()
	gw.Register(wc)

	fmt.Fprintln(os.Stderr, "gateway: webchat ready — type a message (or /help). Ctrl-D to exit.")
	if *pairing {
		fmt.Fprintln(os.Stderr, "gateway: DM pairing required — send /pair first.")
	}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		r, err := gw.Handle(context.Background(), channels.Inbound{Channel: "webchat", User: "stdin", Text: line})
		if err != nil {
			fmt.Printf("! %v\n", err)
		}
		fmt.Printf("< %s\n", r.Text)
	}
	return sc.Err()
}
