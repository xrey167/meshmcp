package main

import (
	"net/http"
	"time"
)

// newLocalHTTPServer builds an http.Server for the loopback control surfaces
// (dash, room, approvals) with timeouts set, so a slow or half-open client
// cannot tie up the listener (Slowloris). ReadHeaderTimeout in particular
// bounds how long a connection may dribble request headers.
func newLocalHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// newAirHTTPServer gives the Air action surface enough bounded time for an
// 8 MiB upload over a relayed mesh and for a receiver-confirmed, resumable
// delivery. The generic control-surface timeouts are intentionally shorter
// than this user-visible transfer workflow.
func newAirHTTPServer(addr string, h http.Handler) *http.Server {
	srv := newLocalHTTPServer(addr, h)
	srv.ReadTimeout = 5 * time.Minute
	srv.WriteTimeout = srv.ReadTimeout + maxDropAttemptDuration + time.Minute
	return srv
}
