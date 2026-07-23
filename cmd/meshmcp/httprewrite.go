package main

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/xrey167/meshmcp/policy"
)

// Response-side secret redaction for Streamable-HTTP backends (parity with the
// stdio filter's pumpInner): once a secret has been injected for a peer, that
// peer's responses are scrubbed so a backend cannot trivially echo the
// credential back to the agent. Best-effort like stdio (an encoding/splitting
// backend stays within the secret's exposure boundary — see the threat model);
// what it must NEVER do is forward bytes it could not scan, so a compressed or
// oversized response with an active redactor is refused (502), not passed.

// redactResponse rewrites resp in place for the given redactor. A nil or
// inactive redactor leaves the response untouched. It returns an error to make
// the proxy fail the exchange (502) rather than forward unscannable bytes.
func redactResponse(resp *http.Response, red *policy.Redactor) error {
	if !red.Active() {
		return nil
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		// Fail closed: we cannot scan what we cannot decode. (The proxy asks
		// for identity; a backend that compresses anyway is refused.)
		return fmt.Errorf("response Content-Encoding %q cannot be scanned for injected secrets (refusing to forward)", enc)
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if ct == "text/event-stream" {
		// SSE: line-preserving streaming rewrite. The redactor only substitutes
		// secret byte-values (which cannot contain '\n' inside a data line — the
		// broker supplies the JSON-escaped form for values that had one), so
		// event:/data:/id: prefixes and blank-line delimiters stay byte-identical
		// and per-line emission preserves stream liveness (FlushInterval -1).
		resp.Body = &sseRedactReader{src: resp.Body, red: red}
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		return nil
	}
	// Everything else (application/json and unknown): one bounded document.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody+1))
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("read backend response for secret redaction: %w", err)
	}
	if len(body) > maxHTTPBody {
		// Fail closed: an unscannable oversized body is refused (the bound is
		// symmetric with the request-side cap).
		return fmt.Errorf("backend response exceeds %d bytes and cannot be scanned for injected secrets (refusing to forward)", maxHTTPBody)
	}
	body = red.Redact(body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return nil
}

// sseRedactReader wraps an SSE body, redacting each complete line before it is
// emitted. It holds at most one partial line (capped at maxHTTPBody; exceeding
// the cap errors the stream — fail closed, matching the stdio filter's
// maxLineBytes teardown) and never blocks while redacted output is pending, so
// each backend flush that completes a line reaches the client immediately.
type sseRedactReader struct {
	src io.ReadCloser
	red *policy.Redactor
	buf []byte // pending incomplete line (no '\n' yet)
	out []byte // redacted bytes ready for the caller
	err error  // sticky terminal condition from src
}

func (r *sseRedactReader) Read(p []byte) (int, error) {
	for {
		if len(r.out) > 0 {
			n := copy(p, r.out)
			r.out = r.out[n:]
			return n, nil
		}
		if r.err != nil {
			return 0, r.err
		}
		chunk := make([]byte, 32*1024)
		n, err := r.src.Read(chunk)
		if n > 0 {
			r.buf = append(r.buf, chunk[:n]...)
			for {
				i := bytes.IndexByte(r.buf, '\n')
				if i < 0 {
					break
				}
				line := r.red.Redact(r.buf[:i+1])
				r.out = append(r.out, line...)
				r.buf = append(r.buf[:0], r.buf[i+1:]...)
			}
			if len(r.buf) > maxHTTPBody {
				// A backend streaming an endless unterminated line could
				// otherwise grow the buffer without bound — tear the stream.
				r.buf = nil
				r.err = fmt.Errorf("SSE line exceeds %d bytes and cannot be scanned for injected secrets", maxHTTPBody)
				return 0, r.err
			}
		}
		if err != nil {
			// Flush any unterminated tail, redacted, then surface the error
			// (EOF included) on the next call.
			if len(r.buf) > 0 {
				r.out = append(r.out, r.red.Redact(r.buf)...)
				r.buf = nil
			}
			r.err = err
		}
	}
}

func (r *sseRedactReader) Close() error { return r.src.Close() }
