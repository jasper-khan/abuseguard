//go:build !linux

package main

import (
	"errors"
	"time"
)

// policy-apply is unsupported outside Linux; this exists only so the engine
// still builds and reports a clear failure instead of a fake success.
func acquirePolicyLock(string, time.Duration) (*fileLock, error) {
	return nil, errors.New("policy-apply is not supported on this platform")
}
