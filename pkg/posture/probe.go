package posture

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// probeReadable opens p for reading and reads at most one byte. Directories
// are listed instead. Anything that is not a regular file is reported not
// readable: opening a FIFO (a named pipe) blocks until a writer appears, so a
// repository that ships one could otherwise hang the scan forever, and a
// device or socket is not the file read the posture model describes.
func probeReadable(p string) *bool {
	var ok bool
	fi, err := os.Stat(p)
	switch {
	case err != nil:
	case fi.IsDir():
		_, err := os.ReadDir(p)
		ok = err == nil
	case fi.Mode().IsRegular():
		f, err := os.Open(p)
		if err == nil {
			var one [1]byte
			_, rerr := f.Read(one[:])
			_ = f.Close()
			ok = rerr == nil || rerr.Error() == "EOF"
		}
	}
	return &ok
}

// probeTCP dials host:port with a short timeout and closes immediately.
func probeTCP(addr string, timeout time.Duration) *bool {
	c, err := net.DialTimeout("tcp", addr, timeout)
	ok := err == nil
	if ok {
		_ = c.Close()
	}
	return &ok
}

// probeUnix reports whether a unix socket exists and accepts a connection.
func probeUnix(p string, timeout time.Duration) *bool {
	fi, err := os.Stat(p)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		f := false
		return &f
	}
	c, err := net.DialTimeout("unix", p, timeout)
	ok := err == nil
	if ok {
		_ = c.Close()
	}
	return &ok
}

// listeningPort is a discovered TCP listener on this host.
type listeningPort struct {
	Addr    string // host:port as listed
	Port    int
	Process string
}

// discoverListeners enumerates TCP listeners without privileges: lsof on
// macOS, /proc/net/tcp on Linux. Best effort; errors yield an empty list.
func discoverListeners() []listeningPort {
	switch runtime.GOOS {
	case "darwin":
		return lsofListeners()
	case "linux":
		return procListeners()
	}
	return nil
}

func lsofListeners() []listeningPort {
	out, err := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:LISTEN").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var res []listeningPort
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 9 || f[0] == "COMMAND" {
			continue
		}
		addr := f[8]
		i := strings.LastIndex(addr, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(addr[i+1:])
		if err != nil || seen[addr] {
			continue
		}
		seen[addr] = true
		res = append(res, listeningPort{Addr: addr, Port: port, Process: f[0]})
	}
	return res
}

func procListeners() []listeningPort {
	var res []listeningPort
	seen := map[string]bool{}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := readFileLimited(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(b), "\n")
		for _, l := range lines[1:] {
			f := strings.Fields(l)
			if len(f) < 4 || f[3] != "0A" { // 0A = LISTEN
				continue
			}
			hp := strings.Split(f[1], ":")
			if len(hp) != 2 {
				continue
			}
			port64, err := strconv.ParseUint(hp[1], 16, 32)
			if err != nil {
				continue
			}
			host := "127.0.0.1"
			if hp[0] == "00000000" || len(hp[0]) == 32 && strings.Trim(hp[0], "0") == "" {
				host = "*"
			}
			addr := fmt.Sprintf("%s:%d", host, port64)
			if seen[addr] {
				continue
			}
			seen[addr] = true
			res = append(res, listeningPort{Addr: addr, Port: int(port64)})
		}
	}
	return res
}

// serviceForPort guesses a service name from the catalog.
func serviceForPort(port int) string {
	for _, s := range localServiceCatalog {
		if s.Port == port {
			return s.Service
		}
	}
	return ""
}
