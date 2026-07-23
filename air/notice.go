package air

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Notice is one attention request delivered between mesh identities — the wire
// shared by `air ring` (send) and `air listen` (receive). A ring is AirDrop's
// ping / a doorbell: a governed, identity-attributed nudge for a HUMAN, not an
// agent instruction (that is a SteerEnvelope). It rides the same resumable, ACL'd
// mesh channel as a drop, framed as one newline-delimited JSON object.
type Notice struct {
	Kind     string `json:"kind,omitempty"`     // "ring" (default) — reserved for future notice kinds
	From     string `json:"from,omitempty"`     // sender's chosen label; the real identity is transport-verified, not this
	Message  string `json:"message"`            // the human-readable body (required)
	Priority string `json:"priority,omitempty"` // "normal" (default) | "urgent"
	Approval string `json:"approval,omitempty"` // optional approvals host:port — a ring-for-approval link-out
	ID       string `json:"id,omitempty"`       // caller correlation id (audited)
}

// Notice kinds and priorities.
const (
	NoticeRing     = "ring"
	PriorityNormal = "normal"
	PriorityUrgent = "urgent"
)

// maxNoticeMessage bounds a notice body so a ring cannot flood a terminal or a
// page banner. Attention is a scarce resource; keep the message short.
const maxNoticeMessage = 500

// Ring builds a normal-priority ring notice with the given message.
func Ring(message string) Notice {
	return Notice{Kind: NoticeRing, Message: message, Priority: PriorityNormal}
}

// Validate reports whether the notice is well-formed: a non-empty message within
// the length cap, free of control characters (which could inject terminal
// escapes on a listener or break a page banner), and a known priority. An empty
// Kind defaults to ring; an empty Priority defaults to normal.
func (n Notice) Validate() error {
	msg := strings.TrimSpace(n.Message)
	if msg == "" {
		return fmt.Errorf("notice requires a message")
	}
	if len(msg) > maxNoticeMessage {
		return fmt.Errorf("notice message is %d chars, over the %d limit", len(msg), maxNoticeMessage)
	}
	if hasControl(n.Message) || hasControl(n.From) {
		return fmt.Errorf("notice message and from must not contain control characters")
	}
	switch n.Priority {
	case "", PriorityNormal, PriorityUrgent:
	default:
		return fmt.Errorf("unknown priority %q (want %s or %s)", n.Priority, PriorityNormal, PriorityUrgent)
	}
	if n.Kind != "" && n.Kind != NoticeRing {
		return fmt.Errorf("unknown notice kind %q", n.Kind)
	}
	return nil
}

// Normalized returns a copy with defaults applied (kind=ring, priority=normal),
// so a listener can rely on the fields being set.
func (n Notice) Normalized() Notice {
	if n.Kind == "" {
		n.Kind = NoticeRing
	}
	if n.Priority == "" {
		n.Priority = PriorityNormal
	}
	return n
}

// Urgent reports whether the notice is urgent priority.
func (n Notice) Urgent() bool { return n.Priority == PriorityUrgent }

// hasControl reports whether s contains a C0, DEL, or C1 control character —
// including the single-code-point CSI form that can carry terminal escapes.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return true
		}
	}
	return false
}

// WriteNotice frames one notice as a newline-delimited JSON record — the wire
// form a listener reads (see ParseNotices).
func WriteNotice(w io.Writer, n Notice) error {
	line, err := json.Marshal(n)
	if err != nil {
		return err
	}
	_, err = w.Write(append(line, '\n'))
	return err
}

// ParseNotices decodes newline-delimited JSON notices from r and calls onNotice
// for each. A malformed line ends the stream with an error; blank lines are
// skipped. The per-line buffer is bounded (maxEnvelopeLine), so a sender cannot
// force an unbounded buffer.
func ParseNotices(r io.Reader, onNotice func(Notice)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), maxEnvelopeLine)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var n Notice
		if err := json.Unmarshal(line, &n); err != nil {
			return fmt.Errorf("bad notice: %w", err)
		}
		onNotice(n)
	}
	return sc.Err()
}
