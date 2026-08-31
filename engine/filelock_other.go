//go:build !linux

package main

import "sync"

var localFileLocks sync.Map

type fileLock struct {
	mu *sync.Mutex
}

func acquireFileLock(path string) (*fileLock, error) {
	v, _ := localFileLocks.LoadOrStore(path, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return &fileLock{mu: mu}, nil
}

func (l *fileLock) Close() error {
	l.mu.Unlock()
	return nil
}
