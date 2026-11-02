//go:build unix

package posture

// The regular-file gate must classify the descriptor it opened, not a path it
// stat'ed earlier: a writer in a scanned repository can replace a file with a
// FIFO between the two. These tests prove the read path cannot be made to
// block on one.

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadFileLimitedRejectsFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readFileLimited(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("readFileLimited accepted a FIFO")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readFileLimited blocked on a FIFO")
	}
}

func TestProbeReadableRejectsFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan *bool, 1)
	go func() {
		done <- probeReadable(fifo)
	}()
	select {
	case ok := <-done:
		if ok != nil && *ok {
			t.Error("probeReadable reported a FIFO readable")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probeReadable blocked on a FIFO")
	}
}
