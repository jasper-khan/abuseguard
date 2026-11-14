//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// acquirePolicyLock serializes root policy applies with a bounded wait. It
// reuses fileLock.Close but polls non-blocking so a stuck peer cannot hang the
// boot service past the deadline.
func acquirePolicyLock(path string, timeout time.Duration) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return nil, fmt.Errorf("无法创建策略锁 %s：%w", path, err)
	}
	deadline := time.Now().Add(timeout)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &fileLock{f: f}, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			f.Close()
			return nil, fmt.Errorf("无法锁定策略锁 %s：%w", path, err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("另一个策略操作仍在运行（等待锁超时）。")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
