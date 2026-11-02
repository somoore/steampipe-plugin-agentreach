//go:build unix

package posture

import (
	"os"
	"syscall"
)

// openNonblock opens p for reading without waiting for a writer. A FIFO
// (named pipe) and a device are not the files the posture model describes,
// and a repository can ship one to make a scan hang forever. Opening
// non-blocking makes it safe to open first and gate on the descriptor's own
// stat, which is what closes the stat→open race: a writer cannot swap a
// regular file for a FIFO between the check and the open if the open happens
// first. O_NONBLOCK has no effect on a regular file.
func openNonblock(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
