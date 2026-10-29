package posture

import (
	"cmp"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Candidate exposure paths. This file is the one implementation of the
// three legs (untrusted input, private data, exit) and of the integrity
// pairing (untrusted input, write target). The Powerpipe mod reads the
// resulting agentreach_path rows and never re-derives a leg.
//
// A path is a candidate: each leg is established on its own, from
// configuration and probes, and agentreach has not shown that one session can
// chain them. Legs that only load in one project (a project's CLAUDE.md,
// its .mcp.json, its .env) must agree on that project; home-directory legs
// pair with any project.

// Leg is one node of a path.
type Leg struct {
	// gate names the session gate the approval came from, so a session in a
	// project with its own mode or sandbox can recompute it: network,
	// shell, webfetch, read, mcp; "" when fixed by configuration.
	gate string

	ID         string
	Kind       string
	Title      string
	Detail     string
	ProjectDir string
	Evidence   string
	Rank       int
	// target-only
	Path      string
	Category  string
	Tier      int
	Via       string
	BlockedBy string
	// Approval is the gate on this step for exits and write targets.
	Approval string
}

var homePrefix = regexp.MustCompile(`^/Users/[^/]+|^/home/[^/]+`)

// Tilde shortens a home-directory path for display.
func Tilde(p string) string { return homePrefix.ReplaceAllString(p, "~") }

// UntrustedLegs returns the untrusted-input leg for agent.
func UntrustedLegs(s *Snapshot, agent string) []Leg {
	var out []Leg
	// A plugin's files share one publisher and one switch (enabledPlugins),
	// so they are one source, like its hooks: a plugin with 55 skills is one
	// way in, not 55.
	type pk struct{ name, dir string }
	pfiles := map[pk][]InstructionFile{}
	var porder []pk
	for _, f := range s.InstructionFiles {
		if f.Agent != agent || !f.Untrusted {
			continue
		}
		if f.PluginName != "" {
			k := pk{f.PluginName, f.ProjectDir}
			if _, ok := pfiles[k]; !ok {
				porder = append(porder, k)
			}
			pfiles[k] = append(pfiles[k], f)
			continue
		}
		out = append(out, Leg{ID: "src:file:" + f.Path, Kind: "instruction_file", Title: Tilde(f.Path), Detail: f.UntrustedReason,
			ProjectDir: f.ProjectDir, Evidence: EvidenceConfigured, Rank: 0})
	}
	for _, k := range porder {
		fs := pfiles[k]
		kinds := map[string]int{}
		var reasons []string
		for _, f := range fs {
			kinds[f.Kind]++
			reasons = append(reasons, f.UntrustedReason)
		}
		var parts []string
		for _, kd := range slices.Sorted(maps.Keys(kinds)) {
			parts = append(parts, fmt.Sprintf("%d %s", kinds[kd], kd))
		}
		id := "src:plugin:" + k.name
		if k.dir != "" {
			id += "@" + k.dir
		}
		out = append(out, Leg{ID: id, Kind: "plugin_file", Title: k.name,
			Detail:     fmt.Sprintf("%d file(s) the plugin loads (%s); %s", len(fs), strings.Join(parts, ", "), strings.Join(uniqSorted(reasons), "; ")),
			ProjectDir: k.dir, Evidence: EvidenceConfigured, Rank: 1})
	}
	type key struct{ name, dir string }
	mcp := map[key]int{}
	var keys []key
	for _, m := range s.MCPServers {
		if m.Agent != agent {
			continue
		}
		pending := m.Scope == "project" && m.Enabled == nil
		plugin := m.Scope == "plugin" && (m.Enabled == nil || *m.Enabled)
		if !pending && !plugin || m.CommandExists != nil && !*m.CommandExists {
			continue
		}
		k := key{m.Name, m.ProjectDir}
		if plugin {
			k = key{m.PluginName + ":" + m.Name, m.ProjectDir} // "" unless installed for one project
		}
		if _, ok := mcp[k]; !ok {
			keys = append(keys, k)
		}
		mcp[k]++
	}
	for _, k := range keys {
		detail := "declared in this project's .mcp.json, no approval decision; loads if approved at the prompt"
		switch {
		case strings.Contains(k.name, ":") && k.dir == "":
			detail = "bundled by an enabled plugin; starts with every session"
		case strings.Contains(k.name, ":"):
			detail = "bundled by a plugin installed for " + Tilde(k.dir) + "; starts in sessions there"
		}
		// A project server with no decision loads only after you approve it
		// at the prompt Claude Code shows when the project opens (mcp,
		// "Project scope"): the source itself waits for a person.
		gate := ApprovalPrompt
		if strings.Contains(k.name, ":") {
			gate = ApprovalNone // a plugin's servers start with the plugin
		}
		out = append(out, Leg{ID: "src:mcp:" + k.name + "@" + k.dir, Kind: "mcp", Title: k.name, Detail: detail,
			ProjectDir: k.dir, Evidence: EvidenceConfigured, Rank: 2, Approval: gate})
	}
	type hk struct{ plugin, dir string }
	hooks := map[hk][]string{}
	var plugins []hk
	for _, h := range s.Hooks {
		if h.Agent != agent || h.Scope != "plugin" || (h.Runs != nil && !*h.Runs) || (h.PluginEnabled != nil && !*h.PluginEnabled) {
			continue
		}
		k := hk{h.PluginName, h.ProjectDir}
		if _, ok := hooks[k]; !ok {
			plugins = append(plugins, k)
		}
		hooks[k] = append(hooks[k], h.Event)
	}
	for _, p := range plugins {
		ev := uniqSorted(hooks[p])
		id := "src:hook:" + p.plugin
		if p.dir != "" {
			id += "@" + p.dir
		}
		out = append(out, Leg{ID: id, Kind: "plugin_hook", Title: p.plugin, ProjectDir: p.dir,
			Detail: fmt.Sprintf("%d hook(s) on %s", len(hooks[p]), strings.Join(ev, ", ")), Evidence: EvidenceConfigured, Rank: 3})
	}
	for _, a := range s.Agents {
		if a.Agent != agent || a.WebFetchApproval == ApprovalDenied {
			continue
		}
		if agent == AgentClaudeCode && a.WebSourceApproval == ApprovalDenied {
			continue
		}
		if agent == AgentCodex {
			out = append(out, Leg{ID: "src:web", Kind: "web_tool", Title: "web search results",
				Detail: "web_search results enter the conversation; set web_search = \"disabled\" to remove", Evidence: EvidenceInferred, Rank: 4})
			continue
		}
		// A fetched page arrives through a WebFetch. Its gate is the
		// weakest way a page can arrive (webSourceApproval): ungated unless
		// a rule covers every domain. The session's, in a project.
		out = append(out, Leg{ID: "src:web", Kind: "web_tool", Title: "web pages the agent fetches",
			Detail: "WebFetch and WebSearch results enter the conversation; deny WebFetch to remove", Evidence: EvidenceInferred, Rank: 4,
			Approval: a.WebSourceApproval, gate: "websource"})
	}
	return out
}

// PrivateLegs returns the private-data leg: sensitive files the agent can
// open by shell or by its file tool.
func PrivateLegs(s *Snapshot, agent string) []Leg {
	var out []Leg
	for _, f := range s.ReachFiles {
		if f.Agent != agent || !f.Exists {
			continue
		}
		bash := f.ReachableViaBash != nil && *f.ReachableViaBash
		tool := f.ReachableViaReadTool != nil && *f.ReachableViaReadTool
		retry := f.ReachableViaRetry != nil && *f.ReachableViaRetry
		if !bash && !tool && !retry {
			continue
		}
		via := "read_tool"
		switch {
		case bash:
			via = "shell"
		case retry && !(tool && f.ProjectDir != ""):
			via = "shell_retry"
		}
		approval := f.ReadApproval
		if approval == "" {
			approval = ApprovalUnknown
		}
		gate := "read"
		if agent == AgentClaudeCode && (bash || (tool && f.ProjectDir != "")) {
			gate = "" // a read-only command, or the Read tool in the working directory
		}
		ev := f.ReachEvidence
		if bash && f.ObservedViaSandbox != nil && *f.ObservedViaSandbox {
			ev = EvidenceObserved
		}
		out = append(out, Leg{ID: "file:" + f.Path, Kind: "private_file", Title: Tilde(f.Path), Detail: f.Description,
			ProjectDir: f.ProjectDir, Evidence: ev, Path: f.Path, Category: f.Category, Tier: f.Tier, Via: via, Approval: approval, gate: gate})
	}
	// A machine-wide leg already pairs with every project, so a project
	// copy of the same file with the same gate (Codex's project .env when
	// the project is the home folder) would count every path twice.
	machine := map[string]Leg{}
	for _, l := range out {
		if l.ProjectDir == "" {
			machine[l.Path] = l
		}
	}
	kept := out[:0]
	for _, l := range out {
		if m, ok := machine[l.Path]; ok && l.ProjectDir != "" && m.Approval == l.Approval && m.Via == l.Via && m.gate == l.gate {
			continue
		}
		kept = append(kept, l)
	}
	return kept
}

// exitServices are local services that can carry data off the machine
// themselves (they start containers or reach a cluster). A database or a
// model server on loopback is not counted: data sent there stays local
// unless something else moves it.
var exitServices = map[string]bool{"docker": true, "docker-desktop": true, "docker-tcp": true, "colima": true, "podman": true, "kube-apiserver": true, "orbstack": true}

// ExitLegs returns the exit leg for agent.
func ExitLegs(s *Snapshot, agent string) []Leg {
	var out []Leg
	var proxy, declared string
	for _, e := range s.Environment {
		if (e.Name == "egress_proxy" || e.Name == "system_proxy") && e.Detected {
			proxy = e.Detail
		}
		if e.Name == "egress_allowlist" && e.Declared {
			declared = "declared egress_allowlist (not verified)"
		}
	}
	inetEv := EvidenceInferred
	inetDetail := "assumed, not probed: agentreach sends nothing"
	if proxy != "" {
		inetEv = EvidenceUnknown
		inetDetail = "an egress proxy is configured (" + proxy + "); agentreach cannot tell what it allows"
	}
	var ag *Agent
	for i := range s.Agents {
		if s.Agents[i].Agent == agent {
			ag = &s.Agents[i]
		}
	}
	if ag == nil {
		return nil
	}
	// The internet, by shell command. With the sandbox on, a host outside
	// allowedDomains is decided by the permission mode unless strictAllowlist
	// refuses it (approval.go), so the exit exists whenever that gate is not
	// "denied".
	if ag.NetworkApproval != ApprovalDenied {
		title := "internet by shell command (sandbox off)"
		switch {
		case agent == AgentCodex:
			title = "internet by shell command (" + ag.EffectivePermissionMode + ": " + ag.NetworkApproval + ")"
		case ag.SandboxEnabled:
			title = "internet by shell command (hosts outside allowedDomains: " + ag.NetworkApproval + ")"
		}
		out = append(out, Leg{ID: "exit:internet", Kind: "internet", Title: title, Detail: inetDetail + "; " + ag.NetworkApprovalReason,
			Evidence: inetEv, Rank: 0, BlockedBy: declared, Approval: ag.NetworkApproval, gate: "network"})
	}
	// A saved Bash allow rule for a network-capable command removes the
	// prompt in the project that saved it: directly with the sandbox off, or
	// through the unsandboxed retry, which "an allow rule that matches a
	// command also approves" (sandboxing, auto-allow mode).
	if (!ag.SandboxEnabled || ag.SandboxAllowUnsandboxed) && ag.NetworkApproval != ApprovalNone {
		byDir := map[string][]string{}
		var dirs []string
		for _, r := range s.SandboxRules {
			if r.Agent != agent || !r.ApprovesNetwork || r.ProjectDir == "" || (r.Scope != "project" && r.Scope != "local") {
				continue
			}
			if _, ok := byDir[r.ProjectDir]; !ok {
				dirs = append(dirs, r.ProjectDir)
			}
			byDir[r.ProjectDir] = append(byDir[r.ProjectDir], r.Pattern)
		}
		sort.Strings(dirs)
		for _, d := range dirs {
			rules := uniqSorted(byDir[d])
			show := rules
			if len(show) > 2 {
				show = append(append([]string{}, show[:2]...), fmt.Sprintf("+%d more", len(rules)-2))
			}
			out = append(out, Leg{ID: "exit:internet@" + d, Kind: "internet", Title: "internet by allowed command: " + strings.Join(show, ", "),
				Detail: "saved allow rules in " + Tilde(d) + " run these commands without a prompt", ProjectDir: d,
				Evidence: EvidenceConfigured, Rank: 0, BlockedBy: declared, Approval: ApprovalNone})
		}
	}
	// Codex: a project whose own gate lets shell commands reach any host
	// more easily than the machine-wide session (a trusted project's
	// sandbox_mode, network_access or exec-policy rules) is its own exit.
	if agent == AgentCodex {
		for _, p := range s.Projects {
			if p.Agent != agent || !p.Exists || approvalRank[p.NetworkApproval] >= approvalRank[ag.NetworkApproval] {
				continue
			}
			out = append(out, Leg{ID: "exit:internet@" + p.ProjectDir, Kind: "internet", Title: "internet by shell command (" + p.EffectivePermissionMode + ": " + p.NetworkApproval + ")",
				Detail: "sessions in " + Tilde(p.ProjectDir) + ": " + p.NetworkApprovalReason, ProjectDir: p.ProjectDir,
				Evidence: EvidenceConfigured, Rank: 0, BlockedBy: declared, Approval: p.NetworkApproval})
		}
	}
	var domains []string
	for _, h := range s.ReachHosts {
		if h.Agent != agent {
			continue
		}
		switch {
		case h.Kind == "allowed_domain":
			domains = append(domains, h.Target)
		case (h.Kind == "tcp" || h.Kind == "unix_socket") && exitServices[h.Service] && h.Reachable != nil && *h.Reachable && h.Approval != ApprovalDenied:
			g := "shell"
			if h.AllowedBySandbox != nil && !*h.AllowedBySandbox {
				g = "network"
			}
			// Codex: TCP follows the session's network gate; a socket row is
			// decided for the machine-wide session only (the macOS sandbox
			// refuses sockets even where a project turns network on).
			if agent == AgentCodex {
				g = ""
				if h.Kind == "tcp" {
					g = "network"
				}
			}
			approval := h.Approval
			if approval == "" {
				approval = ag.ShellApproval
			}
			out = append(out, Leg{ID: "exit:" + h.Target, Kind: "local_service", Title: h.Service + " " + Tilde(h.Target),
				Detail: "can start a container or reach a cluster with its own network", Evidence: h.ReachableEvidence, Rank: 2, Approval: approval, gate: g})
		}
	}
	// Codex: a project whose own gate reaches a local service the
	// machine-wide session cannot (or only with a prompt, for a socket) is
	// its own exit, as for the internet above. Sockets open only under full
	// access.
	if agent == AgentCodex {
		for _, h := range s.ReachHosts {
			if h.Agent != agent || (h.Kind != "tcp" && h.Kind != "unix_socket") || !exitServices[h.Service] || h.Reachable == nil || !*h.Reachable {
				continue
			}
			for _, p := range s.Projects {
				if p.Agent != agent || !p.Exists {
					continue
				}
				gate := p.NetworkApproval
				if h.Kind == "unix_socket" && !strings.HasPrefix(p.EffectivePermissionMode, "danger-full-access/") {
					continue
				}
				// A TCP leg the machine-wide session keeps already takes the
				// project's network gate (sessionGate); only a dropped one
				// needs its own leg here.
				if gate == ApprovalDenied || approvalRank[gate] >= approvalRank[h.Approval] || (h.Kind == "tcp" && h.Approval != ApprovalDenied) {
					continue
				}
				out = append(out, Leg{ID: "exit:" + h.Target + "@" + p.ProjectDir, Kind: "local_service", Title: h.Service + " " + Tilde(h.Target),
					Detail:     "sessions in " + Tilde(p.ProjectDir) + " (" + p.EffectivePermissionMode + ") can start a container or reach a cluster with its own network",
					ProjectDir: p.ProjectDir, Evidence: h.ReachableEvidence, Rank: 2, Approval: gate})
			}
		}
	}
	if len(domains) > 0 && ag.SandboxEnabled {
		sort.Strings(domains)
		show := domains
		if len(show) > 4 {
			show = append(append([]string{}, show[:4]...), fmt.Sprintf("+%d more", len(domains)-4))
		}
		out = append(out, Leg{ID: "exit:allowed_domains", Kind: "allowed_domains", Title: "allowed domains: " + strings.Join(show, ", "),
			Detail: "the sandbox lets shell commands reach these hosts; any of them can receive data", Evidence: EvidenceInferred, Rank: 1, Approval: ag.ShellApproval, gate: "shell"})
	}
	// A project's own allowedDomains and WebFetch(domain:...) allow rules
	// widen the allowlist in sessions started there.
	for _, p := range s.Projects {
		if p.Agent != agent || len(p.SandboxAllowedDomains) == 0 || p.ShellApproval == "" {
			continue
		}
		show := p.SandboxAllowedDomains
		if len(show) > 4 {
			show = append(append([]string{}, show[:4]...), fmt.Sprintf("+%d more", len(p.SandboxAllowedDomains)-4))
		}
		out = append(out, Leg{ID: "exit:allowed_domains@" + p.ProjectDir, Kind: "allowed_domains", Title: "allowed domains: " + strings.Join(show, ", "),
			Detail: "settings in " + Tilde(p.ProjectDir) + " add these hosts to the sandbox allowlist", ProjectDir: p.ProjectDir,
			Evidence: EvidenceConfigured, Rank: 1, Approval: p.ShellApproval, gate: "shell"})
	}
	// Codex web search queries go to the model provider with the rest of
	// the conversation; agentreach does not count them as a new exit.
	if agent == AgentClaudeCode && ag.WebFetchApproval != ApprovalDenied {
		out = append(out, Leg{ID: "exit:web_tool", Kind: "web_tool", Title: "WebFetch requests",
			Detail:   "the WebFetch tool runs outside the sandbox and follows permission rules (" + ag.EffectivePermissionMode + " mode)",
			Evidence: EvidenceInferred, Rank: 1, BlockedBy: declared, Approval: ag.WebFetchApproval, gate: "webfetch"})
	}
	// MCP servers are grouped per project ("" for servers that load
	// everywhere) and per gate, so a group's gate is every member's gate: one
	// allow-listed server does not make the others look open. Remote servers
	// receive every tool call made to them; local ones run with your network
	// access.
	type mk struct {
		remote    bool
		dir, gate string
	}
	groups := map[mk][]string{}
	var keys []mk
	for _, m := range s.MCPServers {
		if m.Agent != agent || !mcpLoads(m) {
			continue
		}
		gate := m.ToolApproval
		if gate == "" {
			gate = ApprovalUnknown
		}
		k := mk{m.Transport == "http" || m.Transport == "sse" || m.Transport == "url", m.ProjectDir, gate}
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], m.Name)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.remote != b.remote {
			return a.remote
		}
		if a.dir != b.dir {
			return a.dir < b.dir
		}
		return approvalRank[a.gate] < approvalRank[b.gate]
	})
	perDir := map[mk]int{}
	for _, k := range keys {
		perDir[mk{k.remote, k.dir, ""}]++
	}
	for _, k := range keys {
		names := uniqSorted(groups[k])
		show := names
		if len(show) > 3 {
			show = append(append([]string{}, show[:3]...), fmt.Sprintf("+%d more", len(names)-3))
		}
		where := "load in every session"
		if k.dir != "" {
			where = "load in " + Tilde(k.dir)
		}
		// The id names the gate only when one place has servers under
		// different gates, so ids stay stable on the common case.
		kind, id := "mcp_process", "exit:mcp_process"
		title := "local MCP servers: " + strings.Join(show, ", ")
		detail := fmt.Sprintf("%d local server(s) that %s run with your network access", len(names), where)
		if k.remote {
			kind, id = "mcp_remote", "exit:mcp_remote"
			title = "remote MCP servers: " + strings.Join(show, ", ")
			detail = fmt.Sprintf("%d remote server(s) that %s receive every tool call sent to them", len(names), where)
		}
		if perDir[mk{k.remote, k.dir, ""}] > 1 {
			id += "/" + k.gate
		}
		if k.dir != "" || k.remote {
			id += "@" + k.dir
		}
		ev, rank, blocked := EvidenceInferred, 3, declared
		if k.remote {
			ev, rank, blocked = EvidenceConfigured, 2, ""
		}
		out = append(out, Leg{ID: id, Kind: kind, Title: title, Detail: detail, ProjectDir: k.dir, Evidence: ev, Rank: rank,
			BlockedBy: blocked, Approval: k.gate, gate: mcpGateKind(agent, k.gate, ag.EffectivePermissionMode)})
	}
	// Plugin hooks receive tool calls and their output on stdin (PostToolUse
	// carries tool_response; Stop carries the transcript path) and run with
	// your network access. The agent does not choose where a hook sends
	// anything: this exit is third-party code that sees the data, so its
	// evidence is inferred.
	nh := map[string]int{}
	hp := map[string][]string{}
	var hdirs []string
	for _, h := range s.Hooks {
		if h.Agent == agent && h.Scope == "plugin" && (h.Runs == nil || *h.Runs) && (h.PluginEnabled == nil || *h.PluginEnabled) {
			if nh[h.ProjectDir] == 0 {
				hdirs = append(hdirs, h.ProjectDir)
			}
			nh[h.ProjectDir]++
			hp[h.ProjectDir] = append(hp[h.ProjectDir], h.PluginName)
		}
	}
	sort.Strings(hdirs)
	for _, d := range hdirs {
		id, where := "exit:hooks", ""
		if d != "" {
			id, where = id+"@"+d, " in "+Tilde(d)
		}
		out = append(out, Leg{ID: id, Kind: "plugin_hooks", Title: "plugin hooks: " + strings.Join(uniqSorted(hp[d]), ", "),
			Detail:     fmt.Sprintf("%d hook command(s)%s receive tool calls and their output and run with your full access, with no prompt; whether data leaves depends on the hook's code", nh[d], where),
			ProjectDir: d, Evidence: EvidenceInferred, Rank: 3, Approval: ApprovalNone})
	}
	return out
}

// mcpGateKind: an MCP gate of none outside bypassPermissions comes from an
// allow rule and stays fixed; otherwise it follows the session's mode.
// Codex MCP approvals come from the server's own approval_mode, not the
// session, so they stay fixed.
func mcpGateKind(agent, gate, mode string) string {
	if agent == AgentCodex {
		return ""
	}
	if gate == ApprovalNone && mode != "bypassPermissions" {
		return ""
	}
	return "mcp"
}

// sessionGate is a leg's approval in a session started in project p.
func sessionGate(l Leg, p *Project) string {
	if p == nil || l.gate == "" || p.EffectivePermissionMode == "" {
		return l.Approval
	}
	switch l.gate {
	case "network":
		return p.NetworkApproval
	case "shell":
		return p.ShellApproval
	case "webfetch":
		return p.WebFetchApproval
	case "websource":
		if p.WebSourceApproval != "" {
			return p.WebSourceApproval
		}
	case "read", "mcp":
		return p.ReadApproval // the mode's gate for a call that needs approval
	}
	return l.Approval
}

// mcpLoads reports whether a server starts in sessions where it is declared.
func mcpLoads(m MCPServer) bool {
	if m.CommandExists != nil && !*m.CommandExists {
		return false // the launcher is gone: the server cannot start
	}
	switch m.Scope {
	case "project":
		return m.Enabled != nil && *m.Enabled
	default:
		return m.Enabled == nil || *m.Enabled
	}
}

// WriteLegs returns integrity targets the agent can change, through a shell
// write the sandbox allows or a file-tool edit, with the weaker of the two
// gates. A target both layers refuse is not a leg.
func WriteLegs(s *Snapshot, agent string) []Leg {
	shell := ApprovalUnknown
	for _, a := range s.Agents {
		if a.Agent == agent && a.ShellApproval != "" {
			shell = a.ShellApproval
		}
	}
	var out []Leg
	for _, w := range s.WriteTargets {
		if w.Agent != agent {
			continue
		}
		session, id := w.SessionDir, "write:"+w.Path
		if session == "" {
			session = w.ProjectDir
		}
		if w.ProjectDir == "" && session != "" {
			id += "@" + session // a home file under one project's gates
		}
		bashGate := ApprovalDenied
		if w.WritableViaBash != nil && *w.WritableViaBash {
			bashGate = shell
			for _, p := range s.Projects {
				if session != "" && p.Agent == agent && p.ProjectDir == session && p.ShellApproval != "" {
					bashGate = p.ShellApproval
				}
			}
		}
		editGate := editApprovalGate(w.EditToolApproval)
		if w.EditToolApproval == "" {
			editGate = ApprovalDenied
		}
		gate := weakestApproval(bashGate, editGate)
		if gate == ApprovalDenied {
			continue
		}
		via := "edit_tool"
		if approvalRank[bashGate] <= approvalRank[editGate] {
			via = "shell"
		}
		out = append(out, Leg{ID: id, Kind: "write_target", Title: Tilde(w.Path), Detail: w.Category,
			ProjectDir: session, Evidence: w.WriteEvidence, Path: w.Path, Category: w.Category, Via: via, Approval: gate})
	}
	return out
}

// sessionDir returns the project a session must start in for all legs to
// load, and false when two legs need different projects.
func sessionDir(dirs ...string) (string, bool) {
	d := ""
	for _, x := range dirs {
		if x == "" {
			continue
		}
		if d != "" && d != x {
			return "", false
		}
		d = x
	}
	return d, true
}

// ComputePaths fills s.Paths for every agent in the snapshot.
func ComputePaths(s *Snapshot) {
	s.Paths = nil
	s.Legs = nil
	for _, a := range s.Agents {
		if a.Agent != AgentClaudeCode && a.Agent != AgentCodex {
			continue // only agents whose gates are modelled get legs and paths
		}
		src := UntrustedLegs(s, a.Agent)
		priv := PrivateLegs(s, a.Agent)
		exits := ExitLegs(s, a.Agent)
		writes := WriteLegs(s, a.Agent)
		homeOverride := map[string]bool{}
		for _, w := range writes {
			if w.ProjectDir != "" && w.ID == "write:"+w.Path+"@"+w.ProjectDir {
				homeOverride[w.Path+"|"+w.ProjectDir] = true
			}
		}
		for role, legs := range map[string][]Leg{"untrusted": src, "private": priv, "exit": exits, "write": writes} {
			for _, l := range legs {
				s.Legs = append(s.Legs, LegRow{Agent: a.Agent, Role: role, LegID: l.ID, Kind: l.Kind, Title: l.Title, Detail: l.Detail,
					ProjectDir: l.ProjectDir, Evidence: l.Evidence, Rank: l.Rank, Path: l.Path, Category: l.Category, Tier: l.Tier,
					Via: l.Via, BlockedBy: l.BlockedBy, Approval: l.Approval})
			}
		}
		projects := map[string]*Project{}
		for i := range s.Projects {
			if s.Projects[i].Agent == a.Agent {
				projects[s.Projects[i].ProjectDir] = &s.Projects[i]
			}
		}
		for _, u := range src {
			for _, t := range priv {
				for _, e := range exits {
					dir, ok := sessionDir(u.ProjectDir, t.ProjectDir, e.ProjectDir)
					if !ok {
						continue
					}
					// In a project session, legs that follow the session's
					// mode or sandbox take that project's gates.
					var proj *Project
					if dir != "" {
						proj = projects[dir]
					}
					srcGate, readGate, exitGate := sessionGate(u, proj), sessionGate(t, proj), sessionGate(e, proj)
					if srcGate == ApprovalDenied || readGate == ApprovalDenied || exitGate == ApprovalDenied {
						continue
					}
					p := newPath(a.Agent, "confidentiality", dir, u, t)
					p.PathID = u.ID + "|" + t.Path + "|" + e.ID + sessionSuffix(dir)
					p.ExitID, p.ExitKind, p.ExitTitle, p.ExitDetail, p.ExitEvidence, p.ExitRank = e.ID, e.Kind, e.Title, e.Detail, e.Evidence, e.Rank
					p.SourceApproval = cmp.Or(srcGate, ApprovalNone)
					p.AfterSourceApproval = strongestApproval(readGate, exitGate)
					p.Approval = strongestApproval(srcGate, readGate, exitGate)
					if e.BlockedBy != "" {
						// The operator says a control closes this exit; agentreach
						// has not verified it, so the path stays a finding.
						p.Status, p.MitigatedBy = "attested", e.BlockedBy
					}
					s.Paths = append(s.Paths, p)
				}
			}
			for _, w := range writes {
				dir, ok := sessionDir(u.ProjectDir, w.ProjectDir)
				if !ok {
					continue
				}
				// A project with its own home-file gates replaces the
				// machine-wide row in its sessions.
				if w.ProjectDir == "" && dir != "" && homeOverride[w.Path+"|"+dir] {
					continue
				}
				srcGate := sessionGate(u, nil)
				if dir != "" {
					srcGate = sessionGate(u, projects[dir])
				}
				if srcGate == ApprovalDenied {
					continue
				}
				p := newPath(a.Agent, "integrity", dir, u, w)
				p.PathID = u.ID + "|" + w.ID + sessionSuffix(dir)
				p.SourceApproval = cmp.Or(srcGate, ApprovalNone)
				p.AfterSourceApproval = strongestApproval(w.Approval)
				p.Approval = strongestApproval(srcGate, w.Approval)
				s.Paths = append(s.Paths, p)
			}
		}
	}
	sortLegs(s.Legs)
}

func sortLegs(ls []LegRow) {
	order := map[string]int{"untrusted": 0, "private": 1, "exit": 2, "write": 3}
	sort.SliceStable(ls, func(i, j int) bool {
		a, b := ls[i], ls[j]
		if a.Agent != b.Agent {
			return a.Agent < b.Agent
		}
		if order[a.Role] != order[b.Role] {
			return order[a.Role] < order[b.Role]
		}
		return a.LegID < b.LegID
	})
}

func newPath(agent, kind, dir string, u, t Leg) Path {
	return Path{
		Agent: agent, Kind: kind, ProjectDir: dir, Status: "candidate",
		SourceID: u.ID, SourceKind: u.Kind, SourceTitle: u.Title, SourceDetail: u.Detail, SourceEvidence: u.Evidence, SourceRank: u.Rank,
		TargetPath: t.Path, TargetTitle: t.Title, TargetCategory: t.Category, TargetTier: t.Tier, Via: t.Via, TargetEvidence: t.Evidence, TargetBlockedBy: t.BlockedBy,
	}
}

func uniqSorted(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range in {
		if !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// sessionSuffix keeps path ids unique when the same legs pair in more than
// one session: machine-wide paths carry none, project paths "#<dir>".
func sessionSuffix(dir string) string {
	if dir == "" {
		return ""
	}
	return "#" + dir
}

// launcherExists stats an absolute launcher path (a stat is a probe that
// reads nothing). A bare name resolves on the launching process's PATH,
// which agentreach cannot see, and a path with a variable is expanded at launch:
// both give nil.
func launcherExists(cmd string) *bool {
	if cmd == "" || !filepath.IsAbs(cmd) || strings.Contains(cmd, "${") {
		return nil
	}
	ok := fileExists(cmd)
	return &ok
}
