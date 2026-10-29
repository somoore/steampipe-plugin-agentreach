package posture

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Controls outside the agent's configuration. A detected control is an
// observed fact (a proxy variable is set, a container marker exists, an
// endpoint agent process is running); agentreach does not verify that it blocks
// anything. A declared control is the operator's assertion, recorded as
// configured evidence. Both change how exits are labelled, never whether a
// leg exists.

// edrProcesses maps process names to products. Matching is exact on the
// command's base name.
var edrProcesses = map[string]string{
	"falcond": "CrowdStrike Falcon", "com.crowdstrike.falcon.Agent": "CrowdStrike Falcon",
	"SentinelAgent": "SentinelOne", "sentinelone-agent": "SentinelOne",
	"JamfProtect": "Jamf Protect", "wdavdaemon": "Microsoft Defender", "mdatp": "Microsoft Defender",
	"elastic-endpoint": "Elastic Defend", "cbagentd": "Carbon Black", "CbOsxSensorService": "Carbon Black",
	"osqueryd": "osquery", "orbit": "Fleet (osquery)", "santad": "Santa", "esets_daemon": "ESET",
}

// KnownDeclaredControls are the names the path logic understands.
var KnownDeclaredControls = []string{"egress_allowlist", "devcontainer", "vm", "edr", "secrets_broker"}

func proxyHost(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "unparseable"
	}
	return u.Host // userinfo is dropped
}

func collectEnvironment(ctx context.Context, opts Options, snap *Snapshot) {
	rows := map[string]*EnvControl{}
	put := func(e EnvControl) {
		if r, ok := rows[e.Name]; ok {
			r.Detected = r.Detected || e.Detected
			r.Declared = r.Declared || e.Declared
			if e.Detail != "" {
				r.Detail = strings.Trim(r.Detail+"; "+e.Detail, "; ")
			}
			if r.Detected {
				r.Evidence = EvidenceObserved
			}
			return
		}
		e.Agent = "*"
		rows[e.Name] = &e
	}
	if opts.Home == "" { // fixture runs never look at the real machine
		for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
			if h := proxyHost(os.Getenv(k)); h != "" {
				put(EnvControl{Name: "egress_proxy", Kind: "network", Detected: true, Evidence: EvidenceObserved, Detail: k + " -> " + h})
				break
			}
		}
		if runtime.GOOS == "darwin" {
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			out, err := exec.CommandContext(cctx, "scutil", "--proxy").Output()
			cancel()
			if err == nil {
				s := string(out)
				if strings.Contains(s, "HTTPSEnable : 1") || strings.Contains(s, "HTTPEnable : 1") || strings.Contains(s, "ProxyAutoConfigEnable : 1") {
					put(EnvControl{Name: "system_proxy", Kind: "network", Detected: true, Evidence: EvidenceObserved, Detail: "macOS network proxy settings enabled"})
				}
			}
		}
		for _, m := range []string{"/.dockerenv", "/run/.containerenv"} {
			if fileExists(m) {
				put(EnvControl{Name: "container", Kind: "isolation", Detected: true, Evidence: EvidenceObserved, Detail: m})
			}
		}
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
			put(EnvControl{Name: "container", Kind: "isolation", Detected: true, Evidence: EvidenceObserved, Detail: "KUBERNETES_SERVICE_HOST set"})
		}
		for _, k := range []string{"REMOTE_CONTAINERS", "CODESPACES", "DEVCONTAINER"} {
			if os.Getenv(k) != "" {
				put(EnvControl{Name: "devcontainer", Kind: "isolation", Detected: true, Evidence: EvidenceObserved, Detail: k + " set"})
				break
			}
		}
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		out, err := exec.CommandContext(cctx, "ps", "-axo", "comm=").Output()
		cancel()
		if err == nil {
			found := map[string]bool{}
			for _, l := range strings.Split(string(out), "\n") {
				base := l[strings.LastIndex(l, "/")+1:]
				if prod, ok := edrProcesses[strings.TrimSpace(base)]; ok {
					found[prod] = true
				}
			}
			if len(found) > 0 {
				names := make([]string, 0, len(found))
				for n := range found {
					names = append(names, n)
				}
				sort.Strings(names)
				put(EnvControl{Name: "edr", Kind: "endpoint", Detected: true, Evidence: EvidenceObserved, Detail: strings.Join(names, ", ")})
			}
		}
	}
	for _, d := range opts.DeclaredControls {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		kind := "declared"
		switch d {
		case "egress_allowlist":
			kind = "network"
		case "devcontainer", "vm":
			kind = "isolation"
		case "edr":
			kind = "endpoint"
		}
		put(EnvControl{Name: d, Kind: kind, Declared: true, Evidence: EvidenceConfigured, Detail: "declared by the operator; not verified by agentreach"})
	}
	names := make([]string, 0, len(rows))
	for n := range rows {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		snap.Environment = append(snap.Environment, *rows[n])
	}
}
