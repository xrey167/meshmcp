//go:build !windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func tryHandoffFileLock(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	return false, err
}

func unlockHandoffFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
