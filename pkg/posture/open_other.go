//go:build !unix

package posture

import "os"

// openNonblock is the portable fallback: Windows has no O_NONBLOCK and named
// pipes are not filesystem paths, so a plain open cannot block on a FIFO.
func openNonblock(p string) (*os.File, error) {
	return os.Open(p)
}
