package posture

// Agent Client Protocol (ACP) harness discovery. ACP (agentclientprotocol.com,
// by Zed; co-developed with JetBrains) is how editors drive coding agents: an
// adapter - claude-code-acp, @zed-industries/codex-acp, or an agent's own
// acp subcommand - starts the agent with the adapter's options. agentreach
// does not integrate with ACP: posture is read from configuration, and the
// protocol has no dry-run permission check (a live ACP session would put an
// LLM in the verdict path and would not be inert). It records the harness
// instead, because a session started through ACP is a start surface whose
// options agentreach cannot see - the same blind spot as the Agent SDK and
// VS Code surfaces in surface.go.
//
// Zed, the protocol's author, writes its agent servers to
// ~/.config/zed/settings.json under "agent_servers" (Zed docs, "External
// Agents"). Other ACP clients keep their own configuration and are not read
// yet; an ACP audit proxy that logs runtime permission requests is parked as
// a separate idea (see the GitHub issue).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// acpHarness is one configured ACP agent server.
type acpHarness struct {
	client  string   // editor that runs the adapter, e.g. Zed
	server  string   // configured server name
	command string   // redacted
	args    []string // redacted
	source  string   // settings file it came from
}

// discoverACP returns the ACP agent servers configured in editor settings.
func discoverACP(opts Options, home string) []acpHarness {
	var dirs []string
	if opts.Home != "" {
		// Fixture runs read only the fixture home.
		dirs = append(dirs, filepath.Join(home, ".config", "zed"))
	} else if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		dirs = append(dirs, filepath.Join(x, "zed"))
	} else {
		dirs = append(dirs, filepath.Join(home, ".config", "zed"))
	}
	var out []acpHarness
	for _, d := range dirs {
		p := filepath.Join(d, "settings.json")
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cfg map[string]any
		if json.Unmarshal(b, &cfg) != nil {
			continue
		}
		servers := getMap(cfg, "agent_servers")
		for _, name := range sortedKeys(servers) {
			m, ok := servers[name].(map[string]any)
			if !ok {
				continue
			}
			h := acpHarness{
				client: "Zed", server: name, source: p,
				command: scrubbedDefault(getString(m, "command")),
			}
			for _, a := range toStringSlice(m["args"]) {
				s, _ := scrubText(a)
				h.args = append(h.args, s)
			}
			out = append(out, h)
		}
	}
	return out
}

// agentID maps a harness to the agent it can start, "" when it cannot be
// established from the server's name, command or arguments.
func (h acpHarness) agentID() string {
	text := h.server + " " + h.command + " " + strings.Join(h.args, " ")
	text = strings.ToLower(text)
	switch {
	case strings.Contains(text, "claude"):
		return AgentClaudeCode
	case strings.Contains(text, "codex"):
		return AgentCodex
	case strings.Contains(text, "opencode"):
		return AgentOpenCode
	case strings.Contains(text, "cline"):
		return AgentCline
	case strings.Contains(text, "grok"):
		return AgentGrok
	}
	return ""
}

// describe says which editor agent servers can start the agent, for the
// agent row's acp_harness column.
func describeACP(hs []acpHarness) string {
	var parts []string
	for _, h := range hs {
		cmd := h.command
		if len(h.args) > 0 {
			cmd += " " + strings.Join(h.args, " ")
		}
		parts = append(parts, h.client+" \""+h.server+"\" ("+strings.TrimSpace(cmd)+")")
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// applyACP fills the acp_harness field on every agent row a discovered
// harness can start.
func applyACP(opts Options, home string, snap *Snapshot) {
	hs := discoverACP(opts, home)
	if len(hs) == 0 || len(snap.Agents) == 0 {
		return
	}
	byAgent := map[string][]acpHarness{}
	for _, h := range hs {
		if id := h.agentID(); id != "" {
			byAgent[id] = append(byAgent[id], h)
		}
	}
	for i := range snap.Agents {
		if hs := byAgent[snap.Agents[i].Agent]; len(hs) > 0 {
			snap.Agents[i].ACPHarness = describeACP(hs)
		}
	}
}

// scrubbedDefault redacts credential-shaped spans in a command, keeping the
// text visible for identification.
func scrubbedDefault(s string) string {
	out, _ := scrubText(s)
	return out
}
