package posture

import (
	"strconv"
	"strings"
	"time"
)

// localServices probes this machine's local listeners and sockets once per
// collection and returns agent-neutral rows (Target, Kind, Service,
// ProcessName, Reachable, ProbeMethod, Loopback, ReachableEvidence). Each
// agent copies them and adds its own sandbox and approval columns, so there
// is one probe loop however many agents are collected.
func localServices(opts Options, home string, snap *Snapshot) []ReachHost {
	if snap.servicesDone {
		return snap.services
	}
	snap.servicesDone = true
	timeout := opts.ProbeTimeout
	if timeout == 0 {
		timeout = 300 * time.Millisecond
	}
	// A fixture run never looks at this machine's ports or sockets: the
	// result would depend on whatever happens to be running.
	fixture := opts.Home != ""
	var listeners []listeningPort
	if !fixture {
		listeners = discoverListeners()
	}
	// Options.Listeners stands in for the listener table in tests: the
	// addresses are dialled like discovered listeners.
	for _, a := range opts.Listeners {
		if i := strings.LastIndex(a, ":"); i > 0 {
			if port, err := strconv.Atoi(a[i+1:]); err == nil {
				listeners = append(listeners, listeningPort{Addr: a, Port: port, Process: "test"})
			}
		}
	}
	probeMethod := "listener_table"
	if len(listeners) == 0 && !fixture {
		probeMethod = "catalog_dial"
		for _, s := range localServiceCatalog {
			listeners = append(listeners, listeningPort{Addr: "127.0.0.1:" + itoaStd(s.Port), Port: s.Port})
		}
	}
	fixed := map[string]bool{}
	for _, s := range opts.Services {
		if s.Kind == "tcp" {
			if i := strings.LastIndex(s.Target, ":"); i > 0 {
				if port, err := strconv.Atoi(s.Target[i+1:]); err == nil {
					listeners = append(listeners, listeningPort{Addr: s.Target, Port: port, Process: s.Process})
					fixed[s.Target] = s.Reachable
				}
			}
		}
	}
	var out []ReachHost
	for _, l := range listeners {
		host := l.Addr[:strings.LastIndex(l.Addr, ":")]
		dialHost := host
		if host == "*" || host == "0.0.0.0" || host == "[::]" || host == "::" {
			dialHost = "127.0.0.1"
		}
		dialHost = strings.Trim(dialHost, "[]")
		r := ReachHost{
			Target: l.Addr, Kind: "tcp", ProcessName: l.Process,
			Service: serviceForPort(l.Port), ProbeMethod: probeMethod,
			Loopback: dialHost == "127.0.0.1" || dialHost == "::1" || dialHost == "localhost",
		}
		if v, ok := fixed[l.Addr]; ok {
			r.Reachable = &v
		} else {
			r.Reachable = probeTCP(net_join(dialHost, l.Port), timeout)
		}
		r.ReachableEvidence = EvidenceObserved
		if probeMethod == "catalog_dial" && !*r.Reachable {
			continue
		}
		out = append(out, r)
	}
	for _, s := range unixSocketCatalog {
		if (opts.goos() == "darwin" && !s.Darwin) || (opts.goos() == "linux" && !s.Linux) {
			continue
		}
		if fixture && !strings.HasPrefix(s.Path, "~/") {
			continue
		}
		p := expandHome(s.Path, home)
		fixedSock, isFixed := false, false
		for _, f := range opts.Services {
			if f.Kind == "unix_socket" && expandHome(f.Target, home) == p {
				fixedSock, isFixed = f.Reachable, true
			}
		}
		if !isFixed && !fileExists(p) {
			continue
		}
		r := ReachHost{Target: p, Kind: "unix_socket", Loopback: true, Service: s.Service, ProbeMethod: "dial"}
		if isFixed {
			r.Reachable = &fixedSock
		} else {
			r.Reachable = probeUnix(p, timeout)
		}
		r.ReachableEvidence = EvidenceObserved
		out = append(out, r)
	}
	snap.services = out
	return out
}
