package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/session"
)

const (
	defaultAirSendMaxBytes = air.MaxActionPayloadBytes
	maxAirSendPayloads     = air.MaxActionPayloads
	maxAirSendTotalBytes   = air.MaxActionTotalBytes
)

type airDeliveryBounds struct {
	perItemBytes int64
	totalBytes   int64
	payloads     int
}

var defaultAirDeliveryBounds = airDeliveryBounds{
	perItemBytes: defaultAirSendMaxBytes,
	totalBytes:   maxAirSendTotalBytes,
	payloads:     maxAirSendPayloads,
}

type airSendOptions struct {
	mesh     *meshOptions
	control  string
	to       string
	text     string
	name     string
	files    []string
	maxBytes int64
}

// parseAirSendArgs accepts both `air send <control> --to ...` (the documented
// human-first shape) and conventional flags-first ordering.
func parseAirSendArgs(args []string) (airSendOptions, error) {
	fs := flag.NewFlagSet("air send", flag.ContinueOnError)
	var help bytes.Buffer
	fs.SetOutput(&help)
	fs.Usage = func() { writeAirSendUsage(&help) }
	o := meshFlags(fs)
	to := fs.String("to", "", "nearby node name, FQDN, or full public key")
	text := fs.String("text", "", "text to include in the delivery")
	name := fs.String("name", "", "name for the text payload (default: clip-<unix>.txt)")
	maxBytes := fs.Int64("max-bytes", defaultAirSendMaxBytes, "maximum text or stdin payload bytes (cap: 8 MiB)")
	var files multiFlag
	fs.Var(&files, "file", "file or directory to include (repeatable)")
	control, err := parseAirControlFlags(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(os.Stderr, &help)
			return airSendOptions{}, flag.ErrHelp
		}
		return airSendOptions{}, fmt.Errorf("air send: %w", err)
	}
	selector := *to
	if err := air.ValidatePresenceSelector(selector); err != nil {
		return airSendOptions{}, fmt.Errorf("air send: invalid --to selector: %w", err)
	}
	if *maxBytes <= 0 {
		return airSendOptions{}, errors.New("air send: --max-bytes must be positive")
	}
	if *maxBytes > defaultAirSendMaxBytes {
		return airSendOptions{}, fmt.Errorf("air send: --max-bytes cannot exceed %d bytes (8 MiB per-item limit)", defaultAirSendMaxBytes)
	}
	for _, path := range files {
		if path == "" {
			return airSendOptions{}, errors.New("air send: --file cannot be empty")
		}
	}
	return airSendOptions{
		mesh: o, control: control, to: selector, text: *text, name: *name,
		files: append([]string(nil), files...), maxBytes: *maxBytes,
	}, nil
}

func writeAirSendUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: meshmcp air send <control-ip:port> --to <node> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Resolve a verified nearby Inbox and send one receiver-confirmed delivery.")
	fmt.Fprintln(w, "  --to node       exact name, FQDN, or full public key (required)")
	fmt.Fprintln(w, "  --text text     include a text payload; stdin is used when piped")
	fmt.Fprintln(w, "  --name name     text payload name (default clip-<unix>.txt)")
	fmt.Fprintln(w, "  --file path     include a file or directory; repeatable")
	fmt.Fprintln(w, "  --max-bytes n   text/stdin cap, at most 8 MiB")
	fmt.Fprintln(w, "Limits: 256 payloads, 8 MiB each, 64 MiB total.")
}

type airDelivery struct {
	text     []byte
	textName string
	files    []string
}

// airPayloadMeta describes the exact immutable frame that will be handed to
// sendData/sendFiles. Source paths never enter this model-facing metadata.
type airPayloadMeta struct {
	action air.ActionKind
	name   string
	size   int64
}

// airDeliverySnapshot owns private staged copies of file payloads. Both the
// receipt plan and sendFiles consume this snapshot, so a source tree changing
// mid-send cannot make the returned receipt disagree with delivered frames.
type airDeliverySnapshot struct {
	delivery airDelivery
	payloads []airPayloadMeta
	root     string
}

func (s airDeliverySnapshot) close() error {
	if s.root != "" {
		return os.RemoveAll(s.root)
	}
	return nil
}

func (d airDelivery) validate(maxTextBytes int64) error {
	if len(d.text) == 0 && len(d.files) == 0 {
		return errors.New("nothing to send")
	}
	if int64(len(d.text)) > maxTextBytes {
		return fmt.Errorf("text payload exceeds %d bytes (per-item limit)", maxTextBytes)
	}
	if len(d.text) > 0 && d.textName == "" {
		return errors.New("text payload name is required")
	}
	for _, path := range d.files {
		if path == "" {
			return errors.New("file path cannot be empty")
		}
		info, err := os.Lstat(path)
		if err != nil {
			return privateAirPathError("inspect selected path", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("selected path must not be a symbolic link")
		}
	}
	return nil
}

// privateAirPathError keeps assistant/CLI failures useful without echoing a
// potentially sensitive local source path into logs or model transcripts.
func privateAirPathError(action string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s: selected path does not exist", action)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s: permission denied", action)
	default:
		return fmt.Errorf("%s failed", action)
	}
}

func prepareAirDelivery(opts airSendOptions, stdin io.Reader, now time.Time) (airDelivery, error) {
	if opts.maxBytes <= 0 || opts.maxBytes > defaultAirSendMaxBytes {
		return airDelivery{}, fmt.Errorf("air send: payload bound must be between 1 and %d bytes (8 MiB)", defaultAirSendMaxBytes)
	}
	text := []byte(opts.text)
	if len(text) == 0 && len(opts.files) == 0 {
		var err error
		text, err = io.ReadAll(io.LimitReader(stdin, opts.maxBytes+1))
		if err != nil {
			return airDelivery{}, fmt.Errorf("read stdin: %w", err)
		}
		if int64(len(text)) > opts.maxBytes {
			return airDelivery{}, fmt.Errorf("stdin payload exceeds %d bytes", opts.maxBytes)
		}
		if len(text) == 0 {
			return airDelivery{}, errors.New("air send: provide --text, at least one --file, or stdin")
		}
	}
	name := opts.name
	if len(text) > 0 && name == "" {
		name = fmt.Sprintf("clip-%d.txt", now.Unix())
	}
	delivery := airDelivery{
		text: append([]byte(nil), text...), textName: name,
		files: append([]string(nil), opts.files...),
	}
	if err := delivery.validate(opts.maxBytes); err != nil {
		return airDelivery{}, fmt.Errorf("air send: %w", err)
	}
	return delivery, nil
}

// snapshotAirDelivery bounds and copies every regular file into a private
// staging tree. Existing sendFiles still owns the wire format; it now reads
// only these stable paths. The staged layout preserves sendFiles' relative
// names for both individual files and directory trees.
func snapshotAirDelivery(delivery airDelivery, bounds airDeliveryBounds) (airDeliverySnapshot, error) {
	if bounds.perItemBytes <= 0 || bounds.perItemBytes > defaultAirSendMaxBytes {
		return airDeliverySnapshot{}, fmt.Errorf("per-item bound must be between 1 and %d bytes (8 MiB)", defaultAirSendMaxBytes)
	}
	if bounds.totalBytes <= 0 || bounds.totalBytes > maxAirSendTotalBytes {
		return airDeliverySnapshot{}, fmt.Errorf("aggregate bound must be between 1 and %d bytes (64 MiB)", maxAirSendTotalBytes)
	}
	if bounds.payloads <= 0 || bounds.payloads > maxAirSendPayloads {
		return airDeliverySnapshot{}, fmt.Errorf("payload count bound must be between 1 and %d", maxAirSendPayloads)
	}
	if len(delivery.files) > bounds.payloads {
		return airDeliverySnapshot{}, fmt.Errorf("delivery selects more than %d paths", bounds.payloads)
	}
	if int64(len(delivery.text)) > bounds.perItemBytes {
		return airDeliverySnapshot{}, fmt.Errorf("text payload exceeds %d bytes (per-item limit)", bounds.perItemBytes)
	}
	if int64(len(delivery.text)) > bounds.totalBytes {
		return airDeliverySnapshot{}, fmt.Errorf("delivery exceeds %d bytes (aggregate limit)", bounds.totalBytes)
	}
	totalBytes := int64(len(delivery.text))
	seenNames := &dropNameTrie{}
	reserveName := func(action air.ActionKind, name string) error {
		if err := validateAirPayloadName(action, name); err != nil {
			return err
		}
		key := airPayloadDestinationKey(name)
		if !seenNames.reserve(key) {
			return errors.New("delivery contains conflicting destination payload names")
		}
		return nil
	}
	snapshot := airDeliverySnapshot{
		delivery: airDelivery{
			text:     append([]byte(nil), delivery.text...),
			textName: delivery.textName,
		},
		payloads: []airPayloadMeta{},
	}
	if len(delivery.text) > 0 {
		if err := reserveName(air.ActionPush, delivery.textName); err != nil {
			return airDeliverySnapshot{}, err
		}
		snapshot.payloads = append(snapshot.payloads, airPayloadMeta{
			action: air.ActionPush, name: delivery.textName, size: int64(len(delivery.text)),
		})
	}
	if len(delivery.files) == 0 {
		if len(snapshot.payloads) == 0 {
			return airDeliverySnapshot{}, errors.New("delivery contains no text or regular files")
		}
		return snapshot, nil
	}

	root, err := os.MkdirTemp("", "meshmcp-air-send-*")
	if err != nil {
		return airDeliverySnapshot{}, fmt.Errorf("create private send snapshot: %w", err)
	}
	snapshot.root = root
	fail := func(err error) (airDeliverySnapshot, error) {
		if cleanupErr := snapshot.close(); cleanupErr != nil {
			return airDeliverySnapshot{}, fmt.Errorf("%v; remove private send snapshot: %w", err, cleanupErr)
		}
		return airDeliverySnapshot{}, err
	}
	type plannedFile struct {
		source, staged, wireName string
		expected                 fs.FileInfo
	}
	type stagedSelection struct {
		root           string
		expandChildren bool
	}
	var planned []plannedFile
	var selections []stagedSelection
	planFile := func(source, staged, wireName string, expected fs.FileInfo) error {
		if len(snapshot.payloads)+len(planned) >= bounds.payloads {
			return fmt.Errorf("delivery exceeds the %d-payload resolved-send limit", bounds.payloads)
		}
		if err := reserveName(air.ActionDrop, wireName); err != nil {
			return err
		}
		planned = append(planned, plannedFile{
			source: source, staged: staged, wireName: wireName, expected: expected,
		})
		return nil
	}

	for index, source := range delivery.files {
		clean := filepath.Clean(source)
		info, err := os.Lstat(clean)
		if err != nil {
			return fail(privateAirPathError("inspect selected path", err))
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fail(errors.New("selected path must not be a symbolic link"))
		}
		container := filepath.Join(root, fmt.Sprintf("payload-%03d", index))
		if err := os.Mkdir(container, 0o700); err != nil {
			return fail(fmt.Errorf("stage selected path: %w", err))
		}
		if !info.IsDir() {
			if !info.Mode().IsRegular() {
				return fail(errors.New("selected path is not a regular file"))
			}
			name := filepath.Base(clean)
			staged := filepath.Join(container, name)
			if err := planFile(clean, staged, name, info); err != nil {
				return fail(fmt.Errorf("stage selected file: %w", err))
			}
			selections = append(selections, stagedSelection{root: staged})
			continue
		}

		base := filepath.Base(clean)
		if base == ".." {
			return fail(errors.New("selected directory would escape the receiver"))
		}
		withoutPrefix := base == "." || base == string(os.PathSeparator)
		stagedRoot := container
		if !withoutPrefix {
			stagedRoot = filepath.Join(container, base)
		}
		if err := os.MkdirAll(stagedRoot, 0o700); err != nil {
			return fail(fmt.Errorf("stage selected directory: %w", err))
		}
		sourceRoot := filepath.Dir(clean)
		err = filepath.WalkDir(clean, func(current string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return privateAirPathError("walk selected directory", walkErr)
			}
			if entry.IsDir() || !entry.Type().IsRegular() {
				return nil
			}
			wireName, err := filepath.Rel(sourceRoot, current)
			if err != nil {
				return errors.New("derive selected payload name failed")
			}
			wireName = filepath.ToSlash(wireName)
			relativeToSelection, err := filepath.Rel(clean, current)
			if err != nil {
				return errors.New("derive private snapshot path failed")
			}
			entryInfo, err := entry.Info()
			if err != nil {
				return privateAirPathError("inspect selected file", err)
			}
			return planFile(current, filepath.Join(stagedRoot, relativeToSelection), wireName, entryInfo)
		})
		if err != nil {
			return fail(fmt.Errorf("stage selected directory: %w", err))
		}
		selections = append(selections, stagedSelection{root: stagedRoot, expandChildren: withoutPrefix})
	}

	// Only after every destination name is known unique do payload bytes enter
	// the private staging tree.
	for _, file := range planned {
		remaining := bounds.totalBytes - totalBytes
		copyLimit := bounds.perItemBytes
		limitKind := "per-item"
		if remaining < copyLimit {
			copyLimit = remaining
			limitKind = "aggregate"
		}
		size, err := copyAirSnapshotFile(file.source, file.staged, file.expected, copyLimit, limitKind)
		if err != nil {
			return fail(fmt.Errorf("stage selected file: %w", err))
		}
		totalBytes += size
		snapshot.payloads = append(snapshot.payloads, airPayloadMeta{
			action: air.ActionDrop, name: file.wireName, size: size,
		})
	}
	for _, selection := range selections {
		if !selection.expandChildren {
			snapshot.delivery.files = append(snapshot.delivery.files, selection.root)
			continue
		}
		children, err := os.ReadDir(selection.root)
		if err != nil {
			return fail(fmt.Errorf("read staged directory: %w", err))
		}
		for _, child := range children {
			snapshot.delivery.files = append(snapshot.delivery.files, filepath.Join(selection.root, child.Name()))
		}
	}
	if len(snapshot.payloads) == 0 {
		return fail(errors.New("delivery contains no text or regular files"))
	}
	return snapshot, nil
}

func validateAirPayloadName(action air.ActionKind, name string) error {
	if !validDropWireNameEncoding(name) {
		return errors.New("payload name must be valid UTF-8")
	}
	portableName := strings.ReplaceAll(name, "\\", "/")
	portableClean := path.Clean(portableName)
	if portableClean == ".." || strings.HasPrefix(portableClean, "../") || strings.HasPrefix(portableClean, "/") {
		return errors.New("payload name must remain inside the receiver inbox")
	}
	localName := filepath.FromSlash(portableName)
	if filepath.Clean(localName) == "." {
		return errors.New("payload name must identify a file")
	}
	if _, err := sanitizeDest("air-send", localName); err != nil {
		return fmt.Errorf("payload name is not deliverable: %w", err)
	}
	_, err := air.NewActionReceipt(action, air.ActionRecipient{
		Service: air.ServiceInbox, Address: "127.0.0.1:1",
	}, name, 0, time.Unix(1, 0))
	return err
}

func airPayloadDestinationKey(name string) string {
	return normalizedDropWireName(name)
}

func copyAirSnapshotFile(source, destination string, expected fs.FileInfo, maxBytes int64, limitKind string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return 0, err
	}
	in, err := os.Open(source)
	if err != nil {
		return 0, privateAirPathError("open selected file", err)
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil {
		return 0, errors.New("inspect opened selected file failed")
	}
	if !opened.Mode().IsRegular() {
		return 0, errors.New("selected file is no longer regular")
	}
	if expected == nil || !os.SameFile(expected, opened) {
		return 0, errors.New("selected file changed while creating the send snapshot")
	}
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(out, io.LimitReader(in, maxBytes))
	if copyErr != nil {
		_ = out.Close()
		_ = os.Remove(destination)
		return 0, errors.New("copy selected file into private snapshot failed")
	}
	var probe [1]byte
	probeN, probeErr := in.Read(probe[:])
	if probeN > 0 {
		copyErr = fmt.Errorf("selected file exceeds %d bytes (%s limit)", maxBytes, limitKind)
	} else if probeErr != nil && !errors.Is(probeErr, io.EOF) {
		copyErr = errors.New("verify selected file size failed")
	}
	if copyErr == nil {
		copyErr = out.Chmod(opened.Mode().Perm())
	}
	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(destination)
		return 0, copyErr
	}
	return n, nil
}

// resolveAirInbox converts presentation metadata into a concrete service
// address. The destination still authorizes the subsequent session normally;
// Presence never acts as a grant.
func resolveAirInbox(ctx context.Context, hc *http.Client, selector string) (air.ResolvedService, error) {
	if err := air.ValidatePresenceSelector(selector); err != nil {
		return air.ResolvedService{}, err
	}
	out, err := fetchPresence(ctx, hc)
	if err != nil {
		return air.ResolvedService{}, err
	}
	resolved, err := air.ResolvePresence(out.Presence, selector, air.ServiceInbox)
	if err != nil {
		return air.ResolvedService{}, err
	}
	if !airServiceHasCapability(resolved.Service, air.InboxCompletionCapabilityV1) {
		return air.ResolvedService{}, fmt.Errorf("selected nearby node does not advertise the receiver-confirmed Inbox protocol %q", air.InboxCompletionCapabilityV1)
	}
	return resolved, nil
}

func airServiceHasCapability(service air.Service, capability string) bool {
	for _, advertised := range service.Capabilities {
		if advertised == capability {
			return true
		}
	}
	return false
}

// verifiedAirDialer binds every initial or resumed transport connection to the
// Presence-selected WireGuard key. Presence supplies routing metadata; the
// embedded client's live peer table is the transport-derived identity check.
func verifiedAirDialer(client *embed.Client, target, expectedKey string) session.Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		if err := verifyAirPeerAtTarget(client, target, expectedKey); err != nil {
			return nil, err
		}
		conn, err := client.Dial(ctx, "tcp", target)
		if err != nil {
			return nil, err
		}
		if err := verifyAirPeerAtTarget(client, target, expectedKey); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

func verifyAirPeerAtTarget(client *embed.Client, target, expectedKey string) error {
	host, _, err := net.SplitHostPort(target)
	if err != nil || net.ParseIP(host) == nil {
		return errors.New("resolved Inbox target is not a mesh IP address")
	}
	status, err := client.Status()
	if err != nil {
		return fmt.Errorf("verify resolved Inbox transport identity: %w", err)
	}
	found := false
	for _, peer := range status.Peers {
		peerIP := strings.SplitN(peer.IP, "/", 2)[0]
		if peerIP != host {
			continue
		}
		if found || peer.PubKey != expectedKey {
			return errors.New("resolved Inbox address no longer belongs to the selected mesh identity")
		}
		found = true
	}
	if !found {
		return errors.New("selected mesh identity is no longer reachable at its resolved Inbox address")
	}
	return nil
}

func actionRecipientFromResolved(resolved air.ResolvedService) air.ActionRecipient {
	return air.ActionRecipient{
		Name: resolved.Node.Name, FQDN: resolved.Node.FQDN, PublicKey: resolved.Node.PublicKey,
		Service: air.ServiceInbox, Address: resolved.Service.Address,
	}
}

// buildAirSendResult validates the immutable snapshot manifest through the
// shared action-receipt contract before delivery begins.
func buildAirSendResult(payloads []airPayloadMeta, recipient air.ActionRecipient, now time.Time) (air.ActionResult, error) {
	if len(payloads) > maxAirSendPayloads {
		return air.ActionResult{}, fmt.Errorf("delivery exceeds the %d-payload resolved-send limit", maxAirSendPayloads)
	}
	receipts := make([]air.ActionReceipt, 0, len(payloads))
	for _, payload := range payloads {
		receipt, err := air.NewActionReceipt(payload.action, recipient, payload.name, payload.size, now)
		if err != nil {
			return air.ActionResult{}, err
		}
		receipts = append(receipts, receipt)
	}
	return air.NewActionResult(recipient, receipts)
}

// writeAirDelivery frames optional text followed by every selected path on one
// drop stream, so a mixed delivery is one governed/resumable session.
func writeAirDelivery(w io.Writer, delivery airDelivery) error {
	if len(delivery.text) == 0 && len(delivery.files) == 0 {
		return errors.New("nothing to send")
	}
	if len(delivery.text) > 0 {
		if err := sendData(w, delivery.textName, delivery.text); err != nil {
			return err
		}
	}
	if len(delivery.files) > 0 {
		return sendFiles(w, delivery.files)
	}
	return nil
}

func runAirDelivery(
	ctx context.Context,
	dial session.Dialer,
	delivery airDelivery,
	expectedPayloads int,
	expectedBytes int64,
	logf func(string, ...any),
) error {
	return runDropWithCompletion(ctx, dial, func(w io.Writer) error {
		return writeAirDelivery(w, delivery)
	}, expectedPayloads, expectedBytes, logf)
}

func cmdAirSend(args []string) error {
	opts, err := parseAirSendArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	delivery, err := prepareAirDelivery(opts, os.Stdin, time.Now())
	if err != nil {
		return err
	}

	opts.mesh.BlockInbound = true
	client, err := startMesh(opts.mesh, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals...)
	defer stop()
	snapshot, err := snapshotAirDelivery(delivery, defaultAirDeliveryBounds)
	if err != nil {
		return fmt.Errorf("air send: %w", err)
	}
	defer func() {
		if err := snapshot.close(); err != nil {
			log.Printf("remove private send snapshot: %v", err)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	resolved, err := resolveAirInbox(ctx, meshDialHTTP(client, opts.control), opts.to)
	if err != nil {
		return fmt.Errorf("air send: resolve recipient: %w", err)
	}
	recipient := actionRecipientFromResolved(resolved)
	plannedResult, err := buildAirSendResult(snapshot.payloads, recipient, time.Unix(1, 0))
	if err != nil {
		return fmt.Errorf("air send: %w", err)
	}
	target := resolved.Service.Address
	dial := verifiedAirDialer(client, target, recipient.PublicKey)
	if err := runAirDelivery(ctx, dial, snapshot.delivery, plannedResult.Payloads, plannedResult.Bytes, log.Printf); err != nil {
		return fmt.Errorf("air send to %s: %w", resolved.Node.Name, err)
	}
	result, err := buildAirSendResult(snapshot.payloads, recipient, time.Now())
	if err != nil {
		return fmt.Errorf("air send: build confirmed result: %w", err)
	}
	log.Printf("sent payloads=%d bytes=%d to %s (%s)", result.Payloads, result.Bytes, resolved.Node.Name, target)
	return writePrettyJSON(os.Stdout, result)
}

// appInboxTarget preserves raw target compatibility while letting assistant
// tools choose a verified nearby node with `to`. Exactly one form is accepted.
func validateAppInboxChoice(target, to string) error {
	target = strings.TrimSpace(target)
	toProvided := to != ""
	if target == "" && !toProvided {
		return errors.New("either target or to is required")
	}
	if target != "" && toProvided {
		return errors.New("give either target or to, not both")
	}
	return nil
}

func (a *meshApp) appInboxRecipient(ctx context.Context, target, to string) (air.ActionRecipient, error) {
	if err := validateAppInboxChoice(target, to); err != nil {
		return air.ActionRecipient{}, err
	}
	target = strings.TrimSpace(target)
	if target != "" {
		if !validMeshTarget(target) {
			return air.ActionRecipient{}, errors.New("target must be a mesh host:port with port 1..65535")
		}
		recipient := air.ActionRecipient{Service: air.ServiceInbox, Address: target}
		if err := recipient.Validate(); err != nil {
			return air.ActionRecipient{}, err
		}
		return recipient, nil
	}
	if err := air.ValidatePresenceSelector(to); err != nil {
		return air.ActionRecipient{}, err
	}
	hc, err := a.controlClient()
	if err != nil {
		return air.ActionRecipient{}, err
	}
	resolved, err := resolveAirInbox(ctx, hc, to)
	if err != nil {
		return air.ActionRecipient{}, fmt.Errorf("resolve recipient: %w", err)
	}
	recipient := actionRecipientFromResolved(resolved)
	if err := recipient.Validate(); err != nil {
		return air.ActionRecipient{}, fmt.Errorf("resolve recipient: %w", err)
	}
	return recipient, nil
}

func (a *meshApp) appInboxTarget(ctx context.Context, target, to string) (string, string, error) {
	recipient, err := a.appInboxRecipient(ctx, target, to)
	if err != nil {
		return "", "", err
	}
	label := recipient.Name
	if label == "" {
		label = recipient.Address
	}
	return recipient.Address, label, nil
}

// sendResolvedAirDelivery is the assistant-facing counterpart to cmdAirSend.
// It snapshots before resolving, then uses the app's one mesh client for both
// Presence lookup and the single resumable delivery session.
func (a *meshApp) sendResolvedAirDelivery(ctx context.Context, to string, delivery airDelivery) (air.ActionResult, error) {
	if err := air.ValidatePresenceSelector(to); err != nil {
		return air.ActionResult{}, err
	}
	if err := delivery.validate(defaultAirSendMaxBytes); err != nil {
		return air.ActionResult{}, err
	}
	if a.mesh == nil {
		return air.ActionResult{}, errors.New("not joined to the mesh (set NB_SETUP_KEY)")
	}
	snapshot, err := snapshotAirDelivery(delivery, defaultAirDeliveryBounds)
	if err != nil {
		return air.ActionResult{}, err
	}
	defer func() {
		if err := snapshot.close(); err != nil {
			log.Printf("remove private send snapshot: %v", err)
		}
	}()
	recipient, err := a.appInboxRecipient(ctx, "", to)
	if err != nil {
		return air.ActionResult{}, err
	}
	plannedResult, err := buildAirSendResult(snapshot.payloads, recipient, time.Unix(1, 0))
	if err != nil {
		return air.ActionResult{}, err
	}
	dial := verifiedAirDialer(a.mesh, recipient.Address, recipient.PublicKey)
	if err := runAirDelivery(ctx, dial, snapshot.delivery, plannedResult.Payloads, plannedResult.Bytes, nil); err != nil {
		return air.ActionResult{}, fmt.Errorf("send to %s: %w", recipient.Name, err)
	}
	result, err := buildAirSendResult(snapshot.payloads, recipient, time.Now())
	if err != nil {
		return air.ActionResult{}, fmt.Errorf("build confirmed result: %w", err)
	}
	return result, nil
}
