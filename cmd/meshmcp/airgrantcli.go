package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

// air grant — the operator side of grant-on-request: the "Allow once / Always /
// Deny" that WRITES the grant. When a RECOGNIZED peer is denied a scope, that
// denial becomes a pending opportunity; the operator resolves it here without
// hand-editing a --grant flag or YAML.
//
//	air grant list   <control-ip:port>                        who is waiting, what is granted
//	air grant allow  [--once|--always] <control-ip:port> <peer-key> <scope>
//	air grant deny   <control-ip:port> <peer-key> <scope>     drop the pending ask
//	air grant revoke <control-ip:port> <peer-key> <scope>     remove an active grant
//
// Every action is gated by the endpoint on the operator's mesh identity (the
// --operator ACL, fail-closed) — an un-allowed caller is refused. The address is
// the verb's serve listener (e.g. an `air kg serve --grant-store …` endpoint),
// which hosts the grant admin surface alongside its served ops.

func cmdAirGrant(args []string) error {
	if len(args) == 0 {
		return airGrantUsage()
	}
	switch args[0] {
	case "list", "ls":
		return cmdAirGrantList(args[1:])
	case "allow":
		return cmdAirGrantAction("allow", args[1:])
	case "deny":
		return cmdAirGrantAction("deny", args[1:])
	case "revoke":
		return cmdAirGrantAction("revoke", args[1:])
	case "-h", "--help", "help":
		return airGrantUsage()
	default:
		return fmt.Errorf("air grant: unknown subcommand %q (want list | allow | deny | revoke)", args[0])
	}
}

func airGrantUsage() error {
	fmt.Fprintln(os.Stderr, bold("meshmcp air grant")+dim(" — resolve grant requests (Allow once / Always / Deny)"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  "+bold("air grant list")+"   <control-ip:port>                        "+dim("pending opportunities + active grants"))
	fmt.Fprintln(os.Stderr, "  "+bold("air grant allow")+"  [--once|--always] <control-ip:port> <peer-key> <scope>")
	fmt.Fprintln(os.Stderr, "                   "+dim("WRITE a grant so the peer's retry succeeds (--always persistent [default], --once single-use)"))
	fmt.Fprintln(os.Stderr, "  "+bold("air grant deny")+"   <control-ip:port> <peer-key> <scope>     "+dim("drop the pending ask (grants nothing)"))
	fmt.Fprintln(os.Stderr, "  "+bold("air grant revoke")+" <control-ip:port> <peer-key> <scope>     "+dim("remove an active grant"))
	return nil
}

// cmdAirGrantList shows the endpoint's pending grant opportunities and the grants
// currently in force.
func cmdAirGrantList(args []string) error {
	fs := flag.NewFlagSet("air grant list", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "emit the pending/grants lists as JSON")
	control, err := parseAirControlFlags(fs, args)
	if err != nil {
		return fmt.Errorf("air grant list: %w", err)
	}
	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	req, err := http.NewRequest(http.MethodGet, "http://air-control/v1/grant/pending", nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("air grant list: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air grant list: %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(body)))
		return nil
	}
	var out grantListResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("air grant list: bad response: %w", err)
	}
	renderGrantLists(out)
	return nil
}

func renderGrantLists(out grantListResponse) {
	if len(out.Pending) == 0 {
		fmt.Fprintln(os.Stderr, dim("no pending grant requests"))
	} else {
		fmt.Fprintln(os.Stdout, bold("Waiting for a grant"))
		var rows [][]cell
		for _, p := range out.Pending {
			rows = append(rows, []cell{
				styled(p.Scope, bold),
				styled(shortKey(p.Identity), dim),
				plain(fmt.Sprintf("%d", p.Count)),
				styled(p.LastSeen, dim),
			})
		}
		renderTable(os.Stdout, []string{"scope", "peer", "denied", "last seen"}, rows)
	}
	if len(out.Grants) > 0 {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, bold("Active grants"))
		var rows [][]cell
		for _, g := range out.Grants {
			rows = append(rows, []cell{
				styled(g.Scope, bold),
				styled(shortKey(g.Identity), dim),
				grantKindCell(g.Once),
				styled(g.GrantedBy, dim),
			})
		}
		renderTable(os.Stdout, []string{"scope", "peer", "kind", "granted by"}, rows)
	}
}

func grantKindCell(once bool) cell {
	if once {
		return styled("once", amber)
	}
	return styled("always", green)
}

// cmdAirGrantAction runs allow/deny/revoke against a (peer-key, scope). Flags
// precede the positionals (standard flag ordering, as with `air pair`).
func cmdAirGrantAction(op string, args []string) error {
	fs := flag.NewFlagSet("air grant "+op, flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "emit the raw JSON result")
	var once, always *bool
	if op == "allow" {
		once = fs.Bool("once", false, "single-use grant (consumed the first time it authorizes a call)")
		always = fs.Bool("always", false, "persistent grant (the default)")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return fmt.Errorf("usage: meshmcp air grant %s [flags] <control-ip:port> <peer-key> <scope>", op)
	}
	if op == "allow" && *once && *always {
		return fmt.Errorf("air grant allow: choose at most one of --once / --always")
	}
	control, peerKey, scope := fs.Arg(0), fs.Arg(1), fs.Arg(2)

	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	payload := map[string]any{"pubkey": peerKey, "scope": scope}
	if op == "allow" {
		payload["once"] = *once // default (neither flag) is persistent ("always")
	}
	reqBody, _ := json.Marshal(payload)
	resp, err := hc.Post("http://air-control/v1/grant/"+op, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("air grant %s: %w", op, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air grant %s: %s: %s", op, resp.Status, bytes.TrimSpace(body))
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(body)))
		return nil
	}
	switch op {
	case "allow":
		kind := "always"
		if *once {
			kind = "once"
		}
		fmt.Println(okLine("granted %s to %s", scope, shortKey(peerKey)) + dim(" · "+kind))
	case "deny":
		fmt.Println(okLine("denied %s for %s", scope, shortKey(peerKey)) + dim(" · nothing granted"))
	case "revoke":
		fmt.Println(okLine("revoked %s from %s", scope, shortKey(peerKey)) + dim(" · no longer authorized"))
	}
	return nil
}
