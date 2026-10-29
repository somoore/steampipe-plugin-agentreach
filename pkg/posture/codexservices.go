package posture

// Local services for Codex: the same probed listeners and sockets as
// Claude Code (localServices), gated by the Codex sandbox. Facts from the
// codex-cli 0.155.1 source (the docs do not cover loopback or sockets
// outside the network proxy section):
//
//   - macOS (sandboxing/src/seatbelt.rs, seatbelt_base_policy.sbpl): the
//     profile starts "(deny default)". With network off and no proxy the
//     dynamic network policy is empty, so loopback TCP is refused. With
//     network on it adds an unfiltered "(allow network-outbound)". Unix
//     sockets need "(allow system-socket (socket-domain AF_UNIX))", which is
//     added only for configured allow_unix_sockets entries, so a socket
//     such as docker.sock stays refused even with network on.
//   - Linux (linux-sandbox/src/bwrap.rs, landlock.rs): network off is
//     "--unshare-net" (no host loopback) plus a seccomp filter that still
//     allows socket(AF_UNIX); whether a host socket is reachable through the
//     read-only root bind is not established, so agentreach reports unknown.
//     Network on keeps the host namespace.
//   - danger-full-access runs commands with no sandbox.
//
// A refused connection can still run outside the sandbox through an
// escalation you approve (on-request, untrusted, granular with
// sandbox_approval) or a network-capable exec-policy allow rule; never
// returns the denial to the model. That is codexGate.Network for TCP.
func (x *codexScan) services() {
	if !x.opts.Probe {
		return
	}
	for _, s := range localServices(x.opts, x.home, x.snap) {
		r := s
		reach := *s.Reachable
		r.Agent, r.Reachable, r.SandboxEnabled = AgentCodex, &reach, x.a.SandboxEnabled
		r.Approval, r.AllowedBySandbox, r.SandboxRule = codexServiceGate(x.g, r.Kind, x.opts.goos())
		if !reach {
			r.Approval = ApprovalDenied
		}
		x.snap.ReachHosts = append(x.snap.ReachHosts, r)
	}
}

// codexServiceGate returns the approval for a shell command connecting to a
// local service, whether the sandbox lets it through (nil when there is no
// sandbox or agentreach cannot tell), and the setting that decides.
func codexServiceGate(g codexGate, kind, goos string) (string, *bool, string) {
	t, f := true, false
	netOn := g.Sandbox == "workspace-write" && g.NetworkAccess
	blocked := g.escape()
	if len(g.AllowRules) > 0 && blocked != ApprovalUnknown {
		blocked = ApprovalNone
	}
	switch {
	case g.Unknown != "":
		return ApprovalUnknown, nil, ""
	case g.Sandbox == "danger-full-access":
		return g.Network, nil, ""
	case g.Proxy:
		return ApprovalUnknown, nil, "network_proxy"
	case kind == "tcp" && netOn:
		return g.Network, &t, "network_access"
	case kind == "tcp":
		return g.Network, &f, ""
	case goos == "linux" && netOn:
		return g.Network, &t, "network_access"
	case goos == "linux":
		return ApprovalUnknown, nil, ""
	}
	return blocked, &f, ""
}
