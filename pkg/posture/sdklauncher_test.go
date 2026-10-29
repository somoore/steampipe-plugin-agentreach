package posture

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestSDKLauncherTypeScript(t *testing.T) {
	l, ok := parseSDKLauncher([]byte(`import { query } from "@anthropic-ai/claude-agent-sdk";

for await (const m of query({
  prompt,
  options: {
    permissionMode: "bypassPermissions",
    allowDangerouslySkipPermissions: true,
    settingSources: ["project"],
    sandbox: { enabled: true, autoAllowBashIfSandboxed: true },
  },
})) {}
const other = { permissionMode: mode };
`), "typescript")
	if !ok || l.ImportLine != 1 || !slices.Equal(l.PermissionModes, []string{"bypassPermissions"}) || !l.DynamicPermissionMode ||
		!l.SkipPermissionsAllowed || !slices.Equal(l.SettingSources, []string{"project"}) || !l.SandboxEnabled || l.CanUseTool {
		t.Errorf("%+v", l)
	}
}

func TestSDKLauncherPython(t *testing.T) {
	l, ok := parseSDKLauncher([]byte(`import asyncio
from claude_agent_sdk import ClaudeAgentOptions, query

opts = ClaudeAgentOptions(
    permission_mode="dontAsk",
    setting_sources=[],
    can_use_tool=approve,
)
`), "python")
	if !ok || l.ImportLine != 2 || !slices.Equal(l.PermissionModes, []string{"dontAsk"}) || l.DynamicPermissionMode ||
		l.SettingSources == nil || len(l.SettingSources) != 0 || !l.CanUseTool || l.SandboxEnabled {
		t.Errorf("%+v", l)
	}
	// No settingSources: null, so the SDK reads every filesystem source.
	l, _ = parseSDKLauncher([]byte("from claude_agent_sdk import query\n"), "python")
	if l.SettingSources != nil {
		t.Errorf("omitted setting_sources = %v", l.SettingSources)
	}
	if _, ok := parseSDKLauncher([]byte("# mentions claude_agent_sdk in a comment\nimport os\n"), "python"); ok {
		t.Error("a file that does not import the SDK is not a launcher")
	}
}

// Only directories whose manifest names the SDK are read; node_modules,
// hidden directories and the home directory are not.
func TestSDKLaunchersCollected(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "proj")
	src := "import { query } from '@anthropic-ai/claude-agent-sdk'\nquery({ options: { permissionMode: 'acceptEdits' } })\n"
	f.write(filepath.Join(proj, "package.json"), `{"name":"x"}`)
	f.write(filepath.Join(proj, "agent", "package.json"), `{"dependencies":{"@anthropic-ai/claude-agent-sdk":"0.2.0"}}`)
	f.write(filepath.Join(proj, "agent", "src", "run.ts"), src)
	f.write(filepath.Join(proj, "agent", "node_modules", "dep", "index.js"), src)
	f.write(filepath.Join(proj, "agent", ".cache", "x.ts"), src)
	f.write(filepath.Join(proj, "web", "app.ts"), src) // no manifest names the SDK here
	// The home directory as a project is never walked.
	f.write(filepath.Join(f.home, "package.json"), `{"dependencies":{"@anthropic-ai/claude-agent-sdk":"0.2.0"}}`)
	f.write(filepath.Join(f.home, "stray.ts"), src)
	f.write(filepath.Join(f.home, ".claude.json"), `{"projects":{"`+proj+`":{},"`+f.home+`":{}}}`)
	s := f.collectWith(Options{Probe: true})
	if len(s.SDKLaunchers) != 1 || s.SDKLaunchers[0].Path != filepath.Join(proj, "agent", "src", "run.ts") ||
		!slices.Equal(s.SDKLaunchers[0].PermissionModes, []string{"acceptEdits"}) || s.SDKLaunchers[0].ProjectDir != proj {
		t.Fatalf("%+v", s.SDKLaunchers)
	}
}

// The flags the SDK starts the CLI with are recognised on a running
// session, including the TypeScript SDK's bundled cli.js.
func TestSDKSessionFlags(t *testing.T) {
	got := launchFlagsFromProcesses(nil, []string{
		"42 node /app/node_modules/@anthropic-ai/claude-agent-sdk/cli.js --output-format stream-json --verbose --permission-mode dontAsk --setting-sources=project,bogus --permission-prompt-tool stdio --input-format stream-json",
	}, false)
	want := map[string]string{"--permission-mode": "dontAsk", "--setting-sources": "project", "--permission-prompt-tool": "stdio", "--input-format": "stream-json"}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for _, f := range got {
		if want[f.Flag] != f.Value || f.Source != "running_session" || f.Agent != AgentClaudeCode {
			t.Errorf("%+v", f)
		}
	}
	// settingSources: [] reaches ps as --setting-sources= (Python SDK) or
	// as a lost empty argument; neither may swallow the next flag.
	for _, line := range []string{
		"7 claude --setting-sources= --permission-mode dontAsk",
		"7 claude --setting-sources --permission-mode dontAsk",
	} {
		got := map[string]string{}
		for _, f := range launchFlagsFromProcesses(nil, []string{line}, false) {
			got[f.Flag] = f.Value
		}
		if got["--setting-sources"] != "none" || got["--permission-mode"] != "dontAsk" {
			t.Errorf("%q: %v", line, got)
		}
	}
}
