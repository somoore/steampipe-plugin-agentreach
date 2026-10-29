package posture

// Helpers shared by the OpenCode, Cline and Grok collectors. They mirror
// the Claude Code and Codex implementations so every agent gets the same
// redaction, provenance and MCP classification.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// lookPath finds an agent binary on PATH (live runs only).
func lookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// runVersion asks a binary for its version and returns the output's fields;
// collectors take the last field. Nothing else from the binary is kept.
func runVersion(ctx context.Context, bin string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, "--version").Output()
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// readAgentTOML reads a TOML config for a non-Codex agent. It returns the
// parsed file, and the path when it exists but does not parse (recorded as
// a collect error on the agent row).
func readAgentTOML(path string, a *Agent, snap *Snapshot, agent string) (map[string]any, string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, ""
	}
	var cfg map[string]any
	if err := toml.Unmarshal(b, &cfg); err != nil {
		e := agent + ": " + path + ": " + err.Error()
		snap.Errors = append(snap.Errors, e)
		a.CollectErrors = append(a.CollectErrors, e)
		return nil, path
	}
	return cfg, ""
}

// mcpFromMap builds an MCP server row from any agent's config map, with
// the same redaction and launcher classification as Claude Code and Codex.
func mcpFromMap(agent, scope, src, projectDir, name string, sm map[string]any, toolApproval string) MCPServer {
	s := MCPServer{Agent: agent, Scope: scope, SourcePath: src, ProjectDir: projectDir, Name: name, ToolApproval: toolApproval}
	s.Command, _ = sm["command"].(string)
	s.Args = toStringSlice(sm["args"])
	s.URL, _ = sm["url"].(string)
	s.Transport = "stdio"
	if s.URL != "" {
		s.Transport = "http"
	}
	if t, _ := sm["type"].(string); t == "remote" && s.URL != "" {
		s.Transport = "http"
	}
	lt := launcherType(s.Command, s.Args, s.URL)
	pin := pinned(lt, s.Args)
	var r1, r2, r3 bool
	s.Args, r1 = scrubArgs(s.Args)
	s.URL, r2 = scrubURL(s.URL)
	s.Command, r3 = scrubText(s.Command)
	s.Redacted = r1 || r2 || r3
	s.HasInlineSecret = s.Redacted
	for _, key := range []string{"env", "environment", "headers", "http_headers"} {
		for k, v := range getMap(sm, key) {
			if key == "env" || key == "environment" {
				s.EnvKeys = append(s.EnvKeys, k)
			}
			if vs, ok := v.(string); ok && looksLikeSecret(k, vs) {
				s.HasInlineSecret = true
			}
		}
	}
	sort.Strings(s.EnvKeys)
	if e := getBool(sm, "enabled"); e != nil {
		s.Enabled = e
	}
	s.LauncherType = lt
	s.Pinned = pin
	s.CommandExists = launcherExists(s.Command)
	return s
}

// addAgentInstruction adds an instruction file with git provenance and the
// review ledger, for any agent.
func addAgentInstruction(snap *Snapshot, agent, scope, projectDir, path, kind string, git *ccCollector, reviews *ReviewLedger) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	f := InstructionFile{
		Agent: agent, Scope: scope, ProjectDir: projectDir, Path: path, Kind: kind,
		SizeBytes: fi.Size(), SHA256: sha256File(path), WritableBy: writableBy(path),
		TrackedInGit: gitTracked(path), HiddenUnicode: hiddenUnicodeCount(b),
		HTMLComments:     len(htmlCommentPattern.FindAll(b, -1)),
		ExternalIncludes: len(includePattern.FindAll(b, -1)),
		ExternalURLs:     len(urlPattern.FindAll(b, -1)),
	}
	if f.TrackedInGit {
		f.GitLastAuthor = git.lastAuthor(path)
		f.GitUncommitted = git.uncommitted(path)
	}
	f.ThirdParty = f.GitLastAuthor != "" && !git.repoIdentities(path)[strings.ToLower(f.GitLastAuthor)]
	markTrust(&f, reviews)
	snap.InstructionFiles = append(snap.InstructionFiles, f)
}

// ruleCarriesNetwork reports whether a command pattern's first word can
// reach the network or run arbitrary code, using the Claude Code command
// classification.
func ruleCarriesNetwork(pattern string) bool {
	w := strings.Fields(pattern)
	if len(w) == 0 {
		return false
	}
	return networkCommands[strings.TrimSuffix(w[0], "*")]
}

// slicesOfMaps extracts a []map[string]any from a parsed TOML/JSON value.
func slicesOfMaps(v any) []map[string]any {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, e := range list {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// sameJSON compares two values by their JSON encoding.
func sameJSON(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}
