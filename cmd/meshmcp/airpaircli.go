package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/xrey167/meshmcp/air"
)

// air join / air pair — the two sides of the "Accept?" moment.
//
//   air join <pair-addr> [--label name]     the peer asking for access
//   air pair list|approve|deny|revoke ...   the operator granting it
//
// join sends a pair request over the mesh, then waits, reporting the calm
// arc: requesting access… waiting for approval… ✓ approved. It confers nothing
// on its own — an operator must approve. pair is the operator side and is
// identity-gated by the gateway: only an already-allowed operator may approve.

// cmdAirJoin implements `air join`: request pairing with a gateway and wait for
// an operator to approve. It only ever asks — recognition is granted by the
// operator, never by this command.
func cmdAirJoin(args []string) error {
	fs := flag.NewFlagSet("air join", flag.ExitOnError)
	o := meshFlags(fs)
	label := fs.String("label", "", "friendly label the operator sees when approving you")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long to wait for approval before giving up")
	interval := fs.Duration("interval", 2*time.Second, "how often to check whether you've been approved")
	asJSON := fs.Bool("json", false, "emit the final status as JSON instead of a rendered line")
	control, err := parseAirControlFlags(fs, args)
	if err != nil {
		return fmt.Errorf("air join: %w (usage: air join <pair-addr> [--label name])", err)
	}
	if *interval <= 0 {
		return errors.New("air join: --interval must be positive")
	}
	if *timeout <= 0 {
		return errors.New("air join: --timeout must be positive")
	}

	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals...)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	status, you, err := postPairRequest(ctx, hc, *label)
	if err != nil {
		return fmt.Errorf("air join: %w", err)
	}
	if !*asJSON {
		fmt.Fprintln(os.Stderr, okLine("requesting access as %s", bold(sanitizeCell(you)))+dim(" · "+control))
	}
	if air.PairStatus(status) == air.StatusApproved {
		return reportJoinApproved(you, *asJSON)
	}
	if !*asJSON {
		fmt.Fprintln(os.Stderr, dim("waiting for approval… (Ctrl-C to stop)"))
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	sawPending := air.PairStatus(status) == air.StatusPending
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return errors.New("air join: still waiting for approval when the timeout elapsed — ask the operator to run `air pair approve`, then try again")
			}
			return nil // interrupted
		case <-ticker.C:
		}
		st, _, err := getPairStatus(ctx, hc)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("air join: %w", err)
		}
		switch air.PairStatus(st) {
		case air.StatusApproved:
			return reportJoinApproved(you, *asJSON)
		case air.StatusPending:
			sawPending = true
		case air.StatusNone:
			// A request we watched go pending has vanished — the operator
			// declined it (or it aged out). Report it plainly rather than
			// silently spinning.
			if sawPending {
				if *asJSON {
					return printJSONValue(map[string]string{"status": "declined", "you": you})
				}
				fmt.Fprintln(os.Stderr, amber("✗ your request was declined."))
				return errors.New("air join: request declined")
			}
		}
	}
}

func reportJoinApproved(you string, asJSON bool) error {
	if asJSON {
		return printJSONValue(map[string]string{"status": "approved", "you": you})
	}
	fmt.Println(okLine("approved — you're recognized on the mesh as %s", bold(sanitizeCell(you))))
	// State the boundary so the peer does not mistake recognition for access:
	// being recognized is an identity, not a capability.
	fmt.Fprintln(os.Stderr, dim("recognition is not access — ask the operator to grant the specific tools you need."))
	return nil
}

// pairStatusResponse is the shared shape of /v1/pair/request and /status.
type pairStatusResponse struct {
	Status string `json:"status"`
	You    string `json:"you"`
}

func postPairRequest(ctx context.Context, hc *http.Client, label string) (status, you string, err error) {
	var body io.Reader
	if label != "" {
		b, _ := json.Marshal(map[string]string{"label": label})
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://air-control/v1/pair/request", body)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	return doPairStatus(hc, req)
}

func getPairStatus(ctx context.Context, hc *http.Client) (status, you string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://air-control/v1/pair/status", nil)
	if err != nil {
		return "", "", err
	}
	return doPairStatus(hc, req)
}

func doPairStatus(hc *http.Client, req *http.Request) (status, you string, err error) {
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(b))
	}
	var out pairStatusResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return "", "", fmt.Errorf("bad response: %w", err)
	}
	return out.Status, out.You, nil
}

// cmdAirPair is the operator side: list who is waiting/recognized, and
// approve, deny, or revoke a peer. Every action is gated by the gateway on the
// operator's mesh identity — an un-allowed caller is refused.
func cmdAirPair(args []string) error {
	if len(args) == 0 {
		return airPairUsage()
	}
	switch args[0] {
	case "list", "ls":
		return cmdAirPairList(args[1:])
	case "approve":
		return cmdAirPairAction("approve", args[1:])
	case "deny":
		return cmdAirPairAction("deny", args[1:])
	case "revoke":
		return cmdAirPairAction("revoke", args[1:])
	case "-h", "--help", "help":
		return airPairUsage()
	default:
		return fmt.Errorf("air pair: unknown subcommand %q (want list | approve | deny | revoke)", args[0])
	}
}

func airPairUsage() error {
	fmt.Fprintln(os.Stderr, bold("meshmcp air pair")+dim(" — approve peers onto the mesh (operator side)"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  "+bold("air pair list")+"    <control-ip:port>              "+dim("who is waiting, and who is recognized"))
	fmt.Fprintln(os.Stderr, "  "+bold("air pair approve")+" <control-ip:port> <peer-key>   "+dim("recognize a pending peer (identity only — not tool access)"))
	fmt.Fprintln(os.Stderr, "  "+bold("air pair deny")+"    <control-ip:port> <peer-key>   "+dim("drop a pending request"))
	fmt.Fprintln(os.Stderr, "  "+bold("air pair revoke")+"  <control-ip:port> <peer-key>   "+dim("un-recognize a paired peer"))
	return nil
}

// cmdAirPairList shows the gateway's pending requests and recognized peers.
func cmdAirPairList(args []string) error {
	fs := flag.NewFlagSet("air pair list", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "emit the pending/paired lists as JSON")
	control, err := parseAirControlFlags(fs, args)
	if err != nil {
		return fmt.Errorf("air pair list: %w", err)
	}
	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	req, err := http.NewRequest(http.MethodGet, "http://air-control/v1/pair/pending", nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("air pair list: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air pair list: %s: %s", resp.Status, bytes.TrimSpace(body))
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(body)))
		return nil
	}
	var out pairListResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("air pair list: bad response: %w", err)
	}
	renderPairLists(out)
	return nil
}

func renderPairLists(out pairListResponse) {
	if len(out.Pending) == 0 {
		fmt.Fprintln(os.Stderr, dim("no pending requests"))
	} else {
		fmt.Fprintln(os.Stdout, bold("Waiting for approval"))
		var rows [][]cell
		for _, p := range out.Pending {
			rows = append(rows, []cell{
				styled(pairLabelOr(p.Label), bold),
				plain(pairIdentity(p.FQDN, p.PublicKey)),
				styled(p.PublicKey, dim),
				styled(p.RequestedAt, dim),
			})
		}
		renderTable(os.Stdout, []string{"label", "identity", "key", "requested"}, rows)
	}
	if len(out.Paired) > 0 {
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, bold("Recognized peers")+dim(" (identity only — not tool access)"))
		var rows [][]cell
		for _, p := range out.Paired {
			rows = append(rows, []cell{
				styled(pairLabelOr(p.Label), bold),
				plain(pairIdentity(p.FQDN, p.PublicKey)),
				styled(p.PublicKey, dim),
				styled(p.Approver, dim),
			})
		}
		renderTable(os.Stdout, []string{"label", "identity", "key", "approved by"}, rows)
	}
}

// cmdAirPairAction runs approve/deny/revoke against a peer key.
func cmdAirPairAction(op string, args []string) error {
	fs := flag.NewFlagSet("air pair "+op, flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "emit the raw JSON result")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: meshmcp air pair %s [flags] <control-ip:port> <peer-key>", op)
	}
	control, peerKey := fs.Arg(0), fs.Arg(1)

	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	reqBody, _ := json.Marshal(map[string]string{"pubkey": peerKey})
	resp, err := hc.Post("http://air-control/v1/pair/"+op, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("air pair %s: %w", op, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air pair %s: %s: %s", op, resp.Status, bytes.TrimSpace(body))
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(body)))
		return nil
	}
	switch op {
	case "approve":
		fmt.Println(okLine("recognized %s", shortKey(peerKey)) + dim(" · identity only — grant tools separately"))
	case "deny":
		fmt.Println(okLine("denied %s", shortKey(peerKey)))
	case "revoke":
		fmt.Println(okLine("revoked %s", shortKey(peerKey)) + dim(" · no longer recognized"))
	}
	return nil
}

func pairLabelOr(label string) string {
	if label == "" {
		return "—"
	}
	return label
}

func pairIdentity(fqdn, pubKey string) string {
	if fqdn != "" {
		return fqdn
	}
	return shortKey(pubKey)
}
