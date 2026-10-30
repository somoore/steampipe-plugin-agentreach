//go:build unix

package posture

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO blocks on open until a writer appears, so a repository that ships one
// could hang a scan forever. The probe must reject it without opening it.
func TestProbeReadableSkipsFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan *bool, 1)
	go func() { done <- probeReadable(p) }()
	select {
	case got := <-done:
		if got == nil || *got {
			t.Errorf("probeReadable(fifo) = %v, want false", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("probeReadable blocked on a FIFO")
	}
	if _, err := readFileLimited(p); err == nil {
		t.Error("readFileLimited accepted a FIFO")
	}
}
