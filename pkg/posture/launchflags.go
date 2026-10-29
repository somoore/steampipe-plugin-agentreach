package posture

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Launch flags change what a session may do, and no settings file shows
// them. They live in two places agentreach can read without running the agent:
// shell aliases and functions in startup files (configured: every session
// typed as that command gets them) and the command lines of running
// sessions (observed). Only recognised flag names are kept, and a value only
// when it comes from a fixed set (permission modes, sandbox modes, approval
// policies); prompts, paths and rule text never reach the table.

// LaunchFlag is one recognised flag on a way of starting an agent.
type LaunchFlag struct {
	Agent    string `json:"agent"`
	Source   string `json:"source"` // alias | function | running_session
	File     string `json:"file"`   // startup file, empty for a running session
	Line     int    `json:"line"`
	Name     string `json:"name"` // alias or function name; "pid <n>" for a running session
	Default  bool   `json:"default"`
	Flag     string `json:"flag"`
	Value    string `json:"value"`
	Effect   string `json:"effect"`
	Evidence string `json:"evidence"` // configured | observed

	rules        []string // --allowedTools / --disallowedTools rules, never stored
	ruleType     string   // allow | deny
	settingsPath string   // --settings file, read like a settings file
}

// launchStartupFiles are read for aliases and functions, relative to home.
var launchStartupFiles = []string{
	".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zsh_aliases",
	".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_aliases",
	".config/fish/config.fish", ".config/fish/functions/claude.fish", ".config/fish/functions/codex.fish",
}

var (
	reAlias     = regexp.MustCompile(`^\s*alias\s+(?:-[a-zA-Z]+\s+)*([A-Za-z0-9_.:+-]+)(?:=|\s+)(.*)$`)
	reFuncStart = regexp.MustCompile(`^\s*(?:function\s+([A-Za-z0-9_.:+-]+)\s*(?:\(\s*\))?|([A-Za-z0-9_.:+-]+)\s*\(\s*\))\s*(\{)?\s*(.*)$`)
)

var claudePermModes = map[string]string{"default": "default", "manual": "default", "acceptEdits": "acceptEdits", "plan": "plan", "auto": "auto", "dontAsk": "dontAsk", "bypassPermissions": "bypassPermissions"}
var codexSandboxModes = map[string]bool{"read-only": true, "workspace-write": true, "danger-full-access": true}
var codexApprovals = map[string]bool{"untrusted": true, "on-request": true, "on-failure": true, "never": true}

// launchFlagsFromStartupFiles parses aliases and functions that start claude
// or codex.
func launchFlagsFromStartupFiles(home string) []LaunchFlag {
	var out []LaunchFlag
	for _, rel := range launchStartupFiles {
		p := filepath.Join(home, rel)
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		var fn string // inside a function body
		var fnLine, depth int
		fish := strings.HasSuffix(p, ".fish")
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		n := 0
		for sc.Scan() {
			n++
			line := sc.Text()
			if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if fn != "" {
				out = append(out, flagsInCommand(line, "function", p, fnLine, fn)...)
				if fish {
					if strings.TrimSpace(line) == "end" {
						fn = ""
					}
					continue
				}
				depth += strings.Count(line, "{") - strings.Count(line, "}")
				if depth <= 0 {
					fn = ""
				}
				continue
			}
			if m := reAlias.FindStringSubmatch(line); m != nil {
				out = append(out, flagsInCommand(unquote(strings.TrimSpace(m[2])), "alias", p, n, m[1])...)
				continue
			}
			if m := reFuncStart.FindStringSubmatch(line); m != nil {
				name := m[1] + m[2]
				body := m[4]
				if fish || m[3] != "" || strings.HasPrefix(strings.TrimSpace(body), "{") {
					out = append(out, flagsInCommand(body, "function", p, n, name)...)
					depth = strings.Count(line, "{") - strings.Count(line, "}")
					if fish || depth > 0 {
						fn, fnLine = name, n
					}
				}
			}
		}
		f.Close()
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// flagsInCommand finds every claude or codex invocation in a shell command
// and returns its recognised flags.
func flagsInCommand(cmd, source, file string, line int, name string) []LaunchFlag {
	var out []LaunchFlag
	words := shellWords(cmd)
	for i := 0; i < len(words); i++ {
		agent := agentFor(words[i])
		if agent == "" {
			continue
		}
		j := i + 1
		for ; j < len(words) && !isSeparator(words[j]); j++ {
		}
		ev := "configured"
		if source == "running_session" {
			ev = "observed"
		}
		for _, f := range recogniseFlags(agent, words[i+1:j]) {
			f.Source, f.File, f.Line, f.Name, f.Evidence = source, file, line, name, ev
			f.Default = source != "running_session" && agentFor(name) == agent
			out = append(out, f)
		}
		i = j
	}
	return out
}

func agentFor(word string) string {
	switch filepath.Base(word) {
	case "claude":
		return AgentClaudeCode
	case "codex":
		return AgentCodex
	}
	return ""
}

func isSeparator(w string) bool {
	switch w {
	case ";", "&&", "||", "|", "&", "\n":
		return true
	}
	return false
}

// shellWords splits a command the way a shell would for these purposes:
// quotes group, separators stand alone, $VAR and "$@" stay as words.
func shellWords(s string) []string {
	var out []string
	var cur strings.Builder
	in := byte(0)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case in != 0:
			if ch == in {
				in = 0
			} else {
				cur.WriteByte(ch)
			}
		case ch == '\'' || ch == '"':
			in = ch
		case ch == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case ch == ' ' || ch == '\t':
			flush()
		case ch == ';' || ch == '|' || ch == '&' || ch == '\n' || ch == '{' || ch == '}' || ch == '(' || ch == ')':
			flush()
			if ch == '|' || ch == '&' {
				if i+1 < len(s) && s[i+1] == ch {
					out = append(out, string([]byte{ch, ch}))
					i++
					continue
				}
			}
			if ch != '{' && ch != '}' && ch != '(' && ch != ')' {
				out = append(out, string(ch))
			} else {
				out = append(out, ";")
			}
		default:
			cur.WriteByte(ch)
		}
	}
	flush()
	return out
}

// recogniseFlags maps argv to known flags. Values are kept only from fixed
// sets; rule lists and settings paths stay on unexported fields.
func recogniseFlags(agent string, args []string) []LaunchFlag {
	var out []LaunchFlag
	add := func(flag, value, effect string) {
		out = append(out, LaunchFlag{Agent: agent, Flag: flag, Value: value, Effect: effect})
	}
	val := func(i int, a string) (string, int) {
		if k := strings.IndexByte(a, '='); k > 0 {
			return a[k+1:], i
		}
		if i+1 < len(args) {
			return args[i+1], i + 1
		}
		return "", i
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		name := a
		if k := strings.IndexByte(a, '='); k > 0 && strings.HasPrefix(a, "--") {
			name = a[:k]
		}
		if agent == AgentClaudeCode {
			switch name {
			case "--dangerously-skip-permissions":
				add(name, "", "starts in bypassPermissions mode")
			case "--allow-dangerously-skip-permissions":
				add(name, "", "puts bypassPermissions in the mode cycle")
			case "--permission-mode":
				v, ni := val(i, a)
				i = ni
				if m, ok := claudePermModes[v]; ok {
					add(name, m, "starts in "+m+" mode")
				} else {
					add(name, "", "starts in a mode agentreach cannot read")
				}
			case "--allowedTools", "--allowed-tools", "--disallowedTools", "--disallowed-tools":
				rt := "allow"
				if strings.Contains(name, "isallowed") {
					rt = "deny"
				}
				var rules []string
				for k := i + 1; k < len(args) && !strings.HasPrefix(args[k], "-"); k++ {
					for _, r := range splitRules(args[k]) {
						rules = append(rules, r)
					}
					i = k
				}
				if v, _ := val(i, a); strings.Contains(a, "=") {
					rules = append(rules, splitRules(v)...)
				}
				out = append(out, LaunchFlag{Agent: agent, Flag: name, Effect: strconv.Itoa(len(rules)) + " " + rt + " rule(s) on top of settings", rules: rules, ruleType: rt})
			case "--settings":
				v, ni := val(i, a)
				i = ni
				out = append(out, LaunchFlag{Agent: agent, Flag: name, Effect: "loads extra settings", settingsPath: v})
			case "--mcp-config":
				_, i = val(i, a)
				add(name, "", "adds MCP servers agentreach does not read")
			case "--strict-mcp-config":
				add(name, "", "uses only the MCP servers from --mcp-config")
			case "--add-dir":
				_, i = val(i, a)
				add(name, "", "adds a working directory")
			case "--plugin-dir":
				_, i = val(i, a)
				add(name, "", "loads a plugin agentreach does not read")
			// The Agent SDK starts the CLI with these (Python SDK
			// subprocess_cli.py; SDK docs: permissions, settingSources).
			case "--setting-sources":
				// An empty value given as its own argument does not
				// survive ps; never take the next flag as the value.
				v, ni := "", i
				if strings.Contains(a, "=") || i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					v, ni = val(i, a)
				}
				i = ni
				var keep []string
				for _, s := range strings.Split(v, ",") {
					if s = strings.TrimSpace(s); (s == "user" || s == "project" || s == "local") && !slices.Contains(keep, s) {
						keep = append(keep, s)
					}
				}
				sort.Strings(keep)
				if len(keep) == 0 {
					add(name, "none", "reads no user, project or local settings")
				} else {
					add(name, strings.Join(keep, ","), "reads only "+strings.Join(keep, ", ")+" settings")
				}
			case "--permission-prompt-tool":
				v, ni := val(i, a)
				i = ni
				if v == "stdio" {
					add(name, v, "sends approvals to the program that started it (an Agent SDK canUseTool callback)")
				} else {
					add(name, "", "sends approvals to an MCP tool")
				}
			case "--input-format":
				v, ni := val(i, a)
				i = ni
				if v == "stream-json" {
					add(name, v, "takes its prompts from a program: the Agent SDK, an IDE or another launcher")
				}
			}
			continue
		}
		switch name {
		case "--dangerously-bypass-approvals-and-sandbox", "--yolo":
			add(name, "", "runs with no sandbox and no approvals")
		case "--approve-for-me", "--not-so-yolo":
			add(name, "", "workspace-write sandbox, approvals sent to automatic review")
		case "--full-auto":
			add(name, "", "removed in Codex 0.155; older releases ran workspace-write with automatic approvals")
		case "-s", "--sandbox":
			v, ni := val(i, a)
			i = ni
			if codexSandboxModes[v] {
				add(name, v, "sandbox "+v)
			} else {
				add(name, "", "a sandbox mode agentreach cannot read")
			}
		case "-a", "--ask-for-approval":
			v, ni := val(i, a)
			i = ni
			if codexApprovals[v] {
				add(name, v, "approval policy "+v)
			} else {
				add(name, "", "an approval policy agentreach cannot read")
			}
		case "-c", "--config":
			v, ni := val(i, a)
			i = ni
			key, value, _ := strings.Cut(v, "=")
			key, value = strings.TrimSpace(key), strings.Trim(strings.TrimSpace(value), `"'`)
			switch {
			case key == "sandbox_mode" && codexSandboxModes[value], key == "approval_policy" && codexApprovals[value],
				key == "sandbox_workspace_write.network_access" && (value == "true" || value == "false"):
				add(name, key+"="+value, "overrides "+key)
			case key != "" && regexp.MustCompile(`^[A-Za-z0-9_.]+$`).MatchString(key):
				add(name, key, "overrides "+key+" (value not kept)")
			}
		case "-p", "--profile":
			v, ni := val(i, a)
			i = ni
			if regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`).MatchString(v) {
				add(name, v, "uses profile "+v)
			}
		}
	}
	return out
}

func splitRules(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',', ' ':
			if depth == 0 {
				if r := strings.TrimSpace(s[start:i]); r != "" {
					out = append(out, r)
				}
				start = i + 1
			}
		}
	}
	if r := strings.TrimSpace(s[start:]); r != "" {
		out = append(out, r)
	}
	return out
}

// launchFlagsFromProcesses reads the command lines of running claude and
// codex sessions. lines pins the ps output (tests); nil runs ps when live.
func launchFlagsFromProcesses(ctx context.Context, lines []string, live bool) []LaunchFlag {
	if lines == nil && live {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(cctx, "ps", "-axww", "-o", "pid=,args=").Output()
		if err != nil {
			return nil
		}
		lines = strings.Split(string(out), "\n")
	}
	self := os.Getpid()
	var flags []LaunchFlag
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil || pid == self {
			continue
		}
		args := f[1:]
		// node .../claude-code/cli.js and node .../@openai/codex/bin/codex.js
		if b := filepath.Base(args[0]); (b == "node" || b == "bun") && len(args) > 1 {
			switch {
			case strings.Contains(args[1], "claude-code"), strings.Contains(args[1], "claude-agent-sdk"):
				args = append([]string{"claude"}, args[2:]...)
			case strings.Contains(args[1], "codex"):
				args = append([]string{"codex"}, args[2:]...)
			}
		}
		agent := agentFor(args[0])
		if agent == "" {
			continue
		}
		for _, fl := range recogniseFlags(agent, args[1:]) {
			fl.Source, fl.Name, fl.Evidence = "running_session", "pid "+f[0], "observed"
			flags = append(flags, fl)
		}
	}
	return flags
}

// machineScope reports whether a rule applies in every session: managed and
// user settings, and flags on the default claude alias or function.
func machineScope(s string) bool { return s == "managed" || s == "user" || s == "launch_flag" }

// ingestLaunchFlags reads startup files and, live, running sessions. Flags
// on the default command (an alias or function named claude) apply to every
// session typed as claude: their rules join the machine-wide rules and their
// mode outranks defaultMode (permission-modes, "Which mode a session starts
// in": the flag comes first). Flags on other names, and running sessions,
// are listed but change nothing.
func (c *ccCollector) ingestLaunchFlags() {
	for i := range c.snap.LaunchFlags {
		f := &c.snap.LaunchFlags[i]
		if f.Agent == AgentClaudeCode && f.Default {
			for _, r := range f.rules {
				tool, spec := r, ""
				if mm := permRulePattern.FindStringSubmatch(r); mm != nil {
					tool, spec = mm[1], mm[2]
				}
				resolved := ""
				if (tool == "Read" || tool == "Edit" || tool == "Write" || tool == "Glob") && spec != "" {
					resolved = resolvePermissionRule(spec, f.ruleType, c.home, c.home)
				}
				pat, red := scrubText(r)
				c.snap.SandboxRules = append(c.snap.SandboxRules, SandboxRule{
					Agent: AgentClaudeCode, Scope: "launch_flag", SourcePath: f.File,
					Category: "permission", RuleType: f.ruleType, Tool: tool, Pattern: pat, ResolvedPath: resolved, Redacted: red,
				})
			}
			if f.settingsPath != "" {
				p := f.settingsPath
				if strings.HasPrefix(p, "~/") {
					p = filepath.Join(c.home, p[2:])
				}
				if filepath.IsAbs(p) {
					if m := c.doc(p); m != nil {
						c.ingestSettings("launch_flag", p, "", m, filepath.Dir(p))
						if mode := getString(m, "permissions", "defaultMode"); mode != "" && c.flagMode == "" {
							c.flagMode, c.flagModeWhy = mode, "permissions.defaultMode in --settings "+p
						}
					}
				}
			}
			switch {
			case f.Flag == "--dangerously-skip-permissions":
				c.flagMode, c.flagModeWhy = "bypassPermissions", f.Flag+" on the "+f.Name+" "+f.Source+" ("+f.File+":"+strconv.Itoa(f.Line)+")"
				c.flagBypass = c.flagModeWhy
			case f.Flag == "--permission-mode" && f.Value != "":
				c.flagMode, c.flagModeWhy = f.Value, f.Flag+" "+f.Value+" on the "+f.Name+" "+f.Source+" ("+f.File+":"+strconv.Itoa(f.Line)+")"
			case f.Flag == "--allow-dangerously-skip-permissions":
				c.flagBypass = f.Flag + " on the " + f.Name + " " + f.Source + " (" + f.File + ":" + strconv.Itoa(f.Line) + ")"
			}
		}
		if f.Source == "running_session" && f.Agent == AgentClaudeCode &&
			(f.Flag == "--dangerously-skip-permissions" || f.Flag == "--allow-dangerously-skip-permissions" || f.Value == "bypassPermissions") {
			c.runningBypass++
		}
	}
}

// collectLaunchFlags reads startup files and, live, running sessions once
// per collection, for the agents being collected.
func collectLaunchFlags(ctx context.Context, opts Options, snap *Snapshot) {
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	flags := launchFlagsFromStartupFiles(home)
	// Reading other processes' command lines is a probe: it runs only on a
	// live collection with probes on.
	flags = append(flags, launchFlagsFromProcesses(ctx, opts.Processes, opts.Probe && opts.Home == "")...)
	snap.LaunchFlags = []LaunchFlag{}
	for _, f := range flags {
		if wantAgent(opts, f.Agent) {
			snap.LaunchFlags = append(snap.LaunchFlags, f)
		}
	}
}

// codexFlagLayer turns flags on the default codex alias or function into a
// config layer. Codex applies CLI flags and -c overrides above every config
// file except managed config (config-reference: "CLI flags and -c
// overrides" come first). Values outside the fixed sets are never stored, so
// a -c override of another key is listed but not modelled.
func codexFlagLayer(flags []LaunchFlag) (map[string]any, string) {
	var layer map[string]any
	var why []string
	set := func(f LaunchFlag, kv ...any) {
		if layer == nil {
			layer = map[string]any{}
		}
		for i := 0; i+1 < len(kv); i += 2 {
			switch k := kv[i].(string); k {
			case "network_access":
				layer["sandbox_workspace_write"] = map[string]any{"network_access": kv[i+1]}
			default:
				layer[k] = kv[i+1]
			}
		}
		why = append(why, f.Flag+" on the "+f.Name+" "+f.Source+" ("+f.File+":"+strconv.Itoa(f.Line)+")")
	}
	for _, f := range flags {
		if f.Agent != AgentCodex || !f.Default {
			continue
		}
		switch {
		case f.Flag == "--yolo" || f.Flag == "--dangerously-bypass-approvals-and-sandbox":
			set(f, "sandbox_mode", "danger-full-access", "approval_policy", "never")
		case f.Flag == "--approve-for-me" || f.Flag == "--not-so-yolo":
			// cli/src/main.rs (0.155.1): workspace-write plus auto review.
			set(f, "sandbox_mode", "workspace-write", "approvals_reviewer", "auto_review")
		case (f.Flag == "-s" || f.Flag == "--sandbox") && f.Value != "":
			set(f, "sandbox_mode", f.Value)
		case (f.Flag == "-a" || f.Flag == "--ask-for-approval") && f.Value != "":
			set(f, "approval_policy", f.Value)
		case (f.Flag == "-c" || f.Flag == "--config") && strings.Contains(f.Value, "="):
			k, v, _ := strings.Cut(f.Value, "=")
			switch k {
			case "sandbox_mode", "approval_policy":
				set(f, k, v)
			case "sandbox_workspace_write.network_access":
				set(f, "network_access", v == "true")
			}
		}
	}
	return layer, strings.Join(why, "; ")
}

// bypassDisabled reports whether settings turn bypassPermissions off, which
// also stops the flags (permission-modes: disableBypassPermissionsMode).
func (c *ccCollector) bypassDisabled() bool {
	for _, m := range []map[string]any{c.managed, c.user} {
		if getString(getMap(m, "permissions"), "disableBypassPermissionsMode") == "disable" {
			return true
		}
	}
	return false
}
