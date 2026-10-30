//go:build unix

package posture

import (
	"fmt"
	"os"
	"syscall"
)

// devIno returns "device:inode" for path, as stat -c %d:%i (Linux) and
// stat -f %d:%i (macOS) print them, or "" when it cannot be read. The raw
// typed values are printed without conversion, so every unix platform's
// stat_t fields format correctly.
func devIno(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}
