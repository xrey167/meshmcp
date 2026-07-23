package session

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// maxPeerErrorBytes bounds every peer-controlled error string that can cross
// the session trust boundary or be emitted onto the wire.
const maxPeerErrorBytes = 4096

// sanitizeErrorText turns untrusted wire/error bytes into terminal- and
// log-safe UTF-8. Invalid bytes become '?'; C0, C1, and DEL controls are
// removed; and truncation never splits a UTF-8 encoding.
func sanitizeErrorText(raw []byte, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}

	var clean strings.Builder
	if len(raw) < maxBytes {
		clean.Grow(len(raw))
	} else {
		clean.Grow(maxBytes)
	}
	truncated := false
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		if r == utf8.RuneError && size == 1 {
			r = '?'
		}
		raw = raw[size:]
		if r <= 0x1f || (r >= 0x7f && r <= 0x9f) {
			continue
		}
		encoded := utf8.RuneLen(r)
		if encoded < 0 {
			r = '?'
			encoded = 1
		}
		if clean.Len()+encoded > maxBytes {
			truncated = true
			break
		}
		clean.WriteRune(r)
	}
	if !truncated {
		return clean.String()
	}

	const marker = "..."
	if maxBytes < len(marker) {
		return marker[:maxBytes]
	}
	text := clean.String()
	limit := maxBytes - len(marker)
	for len(text) > limit {
		_, size := utf8.DecodeLastRuneInString(text)
		text = text[:len(text)-size]
	}
	return text + marker
}

func boundedPeerError(prefix string, payload []byte) error {
	if len(prefix) >= maxPeerErrorBytes {
		return errors.New(sanitizeErrorText([]byte(prefix), maxPeerErrorBytes))
	}
	return errors.New(prefix + sanitizeErrorText(payload, maxPeerErrorBytes-len(prefix)))
}
