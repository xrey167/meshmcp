//go:build !windows

package main

// enableVT is a no-op off Windows: Unix terminals process ANSI escape
// sequences natively.
func enableVT() {}
