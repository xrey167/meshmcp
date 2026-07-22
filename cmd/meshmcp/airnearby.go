package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/air"
)

const maxPresenceListBytes = 64 << 20

// presenceResponse is the gateway's identity-filtered Nearby projection.
type presenceResponse struct {
	Presence []air.Presence `json:"presence"`
	You      string         `json:"you"`
}

// cmdAirNearby is the human and scriptable directory of identity-stamped Air
// nodes. It deliberately resolves names only after fetching the verified cards
// from the control endpoint; advertised services are hints, while the service's
// own ACL remains the authority for every actual action.
func cmdAirNearby(args []string) error {
	fs := flag.NewFlagSet("air nearby", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "emit the verified Presence response as JSON")
	watch := fs.Bool("watch", false, "redraw when a Presence or Activity card changes")
	interval := fs.Duration("interval", 3*time.Second, "poll cadence for --watch")
	selector := fs.String("resolve", "", "resolve an exact node name, FQDN, or full public key")
	service := fs.String("service", "", "service kind to resolve with --resolve (for example steer, ring, or home)")
	control, err := parseAirControlFlags(fs, args)
	if err != nil {
		return err
	}
	if *selector != "" && *service == "" {
		return errors.New("air nearby: --resolve requires --service")
	}
	if *selector != "" && *watch {
		return errors.New("air nearby: --resolve and --watch cannot be combined")
	}
	if *selector == "" && *service != "" {
		return errors.New("air nearby: --service is only valid with --resolve")
	}
	if *interval <= 0 {
		return errors.New("air nearby: --interval must be positive")
	}

	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	load := func(ctx context.Context) (presenceResponse, error) {
		return fetchPresence(ctx, hc)
	}
	if *selector != "" {
		out, err := load(context.Background())
		if err != nil {
			return fmt.Errorf("air nearby: %w", err)
		}
		resolved, err := air.ResolvePresence(out.Presence, *selector, air.ServiceKind(*service))
		if err != nil {
			return fmt.Errorf("air nearby: %w", err)
		}
		if *asJSON {
			return writePrettyJSON(os.Stdout, resolved)
		}
		fmt.Fprintln(os.Stdout, sanitizeCell(resolved.Service.Address))
		fmt.Fprintln(os.Stderr, dim("resolved ")+bold(resolved.Node.Name)+dim(" · "+string(resolved.Service.Kind)))
		return nil
	}

	render := func(out presenceResponse) error {
		if *asJSON {
			return writePrettyJSON(os.Stdout, out)
		}
		renderNearby(os.Stdout, out)
		return nil
	}
	if !*watch {
		out, err := load(context.Background())
		if err != nil {
			return fmt.Errorf("air nearby: %w", err)
		}
		return render(out)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	previous := ""
	for {
		out, err := load(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("air nearby: %w", err)
		}
		if sig := (air.Home{Nearby: out.Presence}).Signature(); sig != previous {
			previous = sig
			if colorOn && !*asJSON {
				_, _ = io.WriteString(os.Stdout, "\x1b[H\x1b[2J")
			}
			if err := render(out); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// cmdAirAnnounce publishes one short-lived card. Long-running processes should
// use air node so expiry is refreshed and a graceful leave is sent on shutdown.
func cmdAirAnnounce(args []string) error {
	fs := flag.NewFlagSet("air announce", flag.ExitOnError)
	o := meshFlags(fs)
	flags := bindPresenceFlags(fs)
	asJSON := fs.Bool("json", false, "emit the gateway-stamped Presence card as JSON")
	control, err := parseAirControlFlags(fs, args)
	if err != nil {
		return err
	}
	announcement, err := flags.announcement()
	if err != nil {
		return fmt.Errorf("air announce: %w", err)
	}
	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()
	result, err := postPresence(context.Background(), hc, announcement)
	if err != nil {
		return fmt.Errorf("air announce: %w", err)
	}
	if *asJSON {
		return writePrettyJSON(os.Stdout, result)
	}
	fmt.Fprintln(os.Stdout, okLine("present as %s", result.Presence.Name)+dim(" · expires "+result.Presence.ExpiresAt))
	return nil
}

// cmdAirNode is the tiny lifecycle host for any agent/device that does not yet
// integrate the Presence client directly: heartbeat, crash-safe TTL, and a
// best-effort authenticated DELETE when it shuts down cleanly.
func cmdAirNode(args []string) error {
	fs := flag.NewFlagSet("air node", flag.ExitOnError)
	o := meshFlags(fs)
	flags := bindPresenceFlags(fs)
	interval := fs.Duration("interval", 30*time.Second, "heartbeat cadence (must be shorter than --ttl)")
	quiet := fs.Bool("quiet", false, "suppress heartbeat status; errors still print")
	control, err := parseAirControlFlags(fs, args)
	if err != nil {
		return err
	}
	announcement, err := flags.announcement()
	if err != nil {
		return fmt.Errorf("air node: %w", err)
	}
	if *interval <= 0 || *interval >= time.Duration(announcement.TTLSeconds)*time.Second {
		return errors.New("air node: --interval must be positive and shorter than the effective --ttl")
	}
	hc, cleanup, err := airControlHTTP(o, control)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	first, err := postPresence(ctx, hc, announcement)
	if err != nil {
		return fmt.Errorf("air node: initial announce: %w", err)
	}
	if !*quiet {
		fmt.Fprintln(os.Stderr, okLine("%s is nearby", first.Presence.Name)+dim(" · Ctrl-C to leave"))
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			leaveCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := deletePresence(leaveCtx, hc)
			cancel()
			if err != nil {
				fmt.Fprintln(os.Stderr, amber("presence leave failed; TTL will expire the card: ")+err.Error())
			} else if !*quiet {
				fmt.Fprintln(os.Stderr, dim("left Nearby"))
			}
			return nil
		case <-ticker.C:
			if _, err := postPresence(ctx, hc, announcement); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, amber("presence heartbeat failed: ")+err.Error())
			}
		}
	}
}

// parseAirControlFlags accepts the natural command shape used throughout the
// Air help — `<control> --flag value` — as well as conventional
// `--flag value <control>`. Go's flag package otherwise stops at the first
// positional argument, silently turning every trailing option into an extra
// positional. Moving only a leading control address to the end preserves flag
// value pairing and repeatable options without inventing a second parser.
func parseAirControlFlags(fs *flag.FlagSet, args []string) (string, error) {
	parseArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		parseArgs = append(append([]string(nil), args[1:]...), args[0])
	}
	if err := fs.Parse(parseArgs); err != nil {
		return "", err
	}
	if fs.NArg() != 1 {
		return "", errors.New("exactly one control-ip:port is required")
	}
	return fs.Arg(0), nil
}

type presenceFlags struct {
	name            *string
	kind            *string
	status          *string
	ttl             *time.Duration
	labels          multiFlag
	services        multiFlag
	activityID      *string
	activityKind    *string
	activityTitle   *string
	activitySummary *string
	activityState   *string
	progress        *int
	activityTarget  *string
	contextRef      *string
	handoff         *bool
	revision        *uint64
}

func bindPresenceFlags(fs *flag.FlagSet) *presenceFlags {
	p := &presenceFlags{}
	p.name = fs.String("name", "", "friendly node name (required)")
	p.kind = fs.String("kind", string(air.NodeAgent), "node kind: agent, device, gateway, or service")
	p.status = fs.String("status", string(air.StatusAvailable), "availability: available, busy, focus, or away")
	p.ttl = fs.Duration("ttl", time.Duration(air.DefaultPresenceTTLSeconds)*time.Second, "requested card lifetime (server clamps it to 15s..5m)")
	fs.Var(&p.labels, "label", "discovery label (repeatable)")
	fs.Var(&p.services, "service", "service kind=port[/protocol][,capability...] (repeatable)")
	p.activityID = fs.String("activity-id", "", "stable Activity id; enables the Activity card")
	p.activityKind = fs.String("activity-kind", string(air.ActivityTask), "Activity kind: session, task, workflow, approval, or knowledge")
	p.activityTitle = fs.String("activity-title", "", "short human Activity title (required with --activity-id)")
	p.activitySummary = fs.String("activity-summary", "", "privacy-safe Activity summary")
	p.activityState = fs.String("activity-state", string(air.ActivityRunning), "Activity state")
	p.progress = fs.Int("progress", -1, "Activity progress from 0 to 100; omit for unknown")
	p.activityTarget = fs.String("activity-target", "", "canonical governed target, for example task:9f2a")
	p.contextRef = fs.String("context-ref", "", "content-addressed context reference (sha256:, blake3:, or kh_)")
	p.handoff = fs.Bool("handoff-ready", false, "mark the Activity as context-ready for a future governed handoff")
	p.revision = fs.Uint64("revision", 0, "monotonic Activity revision")
	return p
}

func (p *presenceFlags) announcement() (air.Announcement, error) {
	if strings.TrimSpace(*p.name) == "" {
		return air.Announcement{}, errors.New("--name is required")
	}
	if *p.ttl <= 0 {
		return air.Announcement{}, errors.New("--ttl must be positive")
	}
	if *p.progress < -1 || *p.progress > 100 {
		return air.Announcement{}, errors.New("--progress must be between 0 and 100, or omitted")
	}
	ttlSeconds := int(math.Ceil(p.ttl.Seconds()))
	services := make([]air.Service, 0, len(p.services))
	for _, value := range p.services {
		svc, err := parsePresenceService(value)
		if err != nil {
			return air.Announcement{}, err
		}
		services = append(services, svc)
	}
	a := air.Announcement{
		Version: air.PresenceSchema, Name: strings.TrimSpace(*p.name), Kind: air.NodeKind(*p.kind),
		Status: air.PresenceStatus(*p.status), Labels: append([]string(nil), p.labels...),
		TTLSeconds: ttlSeconds, Services: services,
	}
	activityRequested := *p.activityID != "" || *p.activityTitle != "" || *p.activitySummary != "" ||
		*p.activityTarget != "" || *p.contextRef != "" || *p.progress >= 0 || *p.handoff || *p.revision > 0
	if activityRequested {
		if *p.activityID == "" || *p.activityTitle == "" {
			return air.Announcement{}, errors.New("--activity-id and --activity-title are both required for an Activity card")
		}
		activity := &air.Activity{
			Schema: air.ActivitySchema, ID: *p.activityID, Kind: air.ActivityKind(*p.activityKind),
			Title: *p.activityTitle, Summary: *p.activitySummary, State: air.ActivityState(*p.activityState),
			Target: *p.activityTarget, ContextRef: *p.contextRef, Handoff: *p.handoff, Revision: *p.revision,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if *p.progress >= 0 {
			progress := *p.progress
			activity.Progress = &progress
		}
		a.Activity = activity
	}
	a = a.Normalized()
	if err := a.Validate(); err != nil {
		return air.Announcement{}, err
	}
	return a, nil
}

func parsePresenceService(value string) (air.Service, error) {
	kind, spec, ok := strings.Cut(value, "=")
	if !ok || kind == "" || spec == "" {
		return air.Service{}, fmt.Errorf("bad --service %q (want kind=port[/protocol][,capability...])", value)
	}
	parts := strings.Split(spec, ",")
	portText, protocol, _ := strings.Cut(parts[0], "/")
	port, err := strconv.Atoi(portText)
	if err != nil {
		return air.Service{}, fmt.Errorf("bad --service %q: port must be a number", value)
	}
	if protocol == "" {
		protocol = "tcp"
	}
	return air.Service{
		Kind: air.ServiceKind(kind), Port: port, Protocol: protocol,
		Capabilities: append([]string(nil), parts[1:]...),
	}, nil
}

type announceResponse struct {
	Status   string       `json:"status"`
	Changed  bool         `json:"changed"`
	Presence air.Presence `json:"presence"`
}

func fetchPresence(ctx context.Context, hc *http.Client) (presenceResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://air-control/v1/presence", nil)
	if err != nil {
		return presenceResponse{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return presenceResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPresenceListBytes+1))
	if err != nil {
		return presenceResponse{}, err
	}
	if len(body) > maxPresenceListBytes {
		return presenceResponse{}, fmt.Errorf("presence response exceeds %d bytes", maxPresenceListBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return presenceResponse{}, fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(body))
	}
	var out presenceResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return presenceResponse{}, fmt.Errorf("bad response: %w", err)
	}
	if out.Presence == nil {
		out.Presence = []air.Presence{}
	}
	return out, nil
}

func postPresence(ctx context.Context, hc *http.Client, announcement air.Announcement) (announceResponse, error) {
	body, err := json.Marshal(announcement)
	if err != nil {
		return announceResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://air-control/v1/presence", bytes.NewReader(body))
	if err != nil {
		return announceResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return announceResponse{}, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return announceResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return announceResponse{}, fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(responseBody))
	}
	var out announceResponse
	if err := json.Unmarshal(responseBody, &out); err != nil {
		return announceResponse{}, fmt.Errorf("bad response: %w", err)
	}
	return out, nil
}

func deletePresence(ctx context.Context, hc *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://air-control/v1/presence", nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(body))
	}
	return nil
}

func renderNearby(w io.Writer, out presenceResponse) {
	if out.You != "" {
		fmt.Fprintln(w, dim("you  ")+bold(sanitizeCell(out.You)))
	}
	if len(out.Presence) == 0 {
		fmt.Fprintln(w, dim("no Air nodes nearby"))
		return
	}
	var rows [][]cell
	for _, p := range out.Presence {
		identity := p.FQDN
		if identity == "" {
			identity = shortKey(p.PublicKey)
		}
		services := make([]string, 0, len(p.Services))
		for _, svc := range p.Services {
			services = append(services, string(svc.Kind))
		}
		sort.Strings(services)
		activity := "—"
		if p.Activity != nil {
			activity = string(p.Activity.State) + " · " + p.Activity.Title
		}
		statusStyle := dim
		switch p.Status {
		case air.StatusAvailable:
			statusStyle = green
		case air.StatusBusy, air.StatusFocus:
			statusStyle = amber
		}
		rows = append(rows, []cell{
			styled("● "+string(p.Status), statusStyle), styled(p.Name, bold), plain(string(p.Kind)),
			styled(identity, dim), plain(strings.Join(services, " · ")), plain(activity),
		})
	}
	renderTable(w, []string{"status", "node", "kind", "identity", "services", "activity"}, rows)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d nearby node(s)", len(rows))))
}

func writePrettyJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(value)
}
