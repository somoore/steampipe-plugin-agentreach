package posture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//// SECRET DETECTION

// TestLooksLikeSecret pins the one promise the plugin makes about secrets:
// it classifies, never stores. These cases are the boundary of "real".
func TestLooksLikeSecret(t *testing.T) {
	cases := []struct {
		key, value string
		want       bool
	}{
		{"OPENAI_API_KEY", fake("s"+"k-", 10), true},
		{"ANTHROPIC_API_KEY", fake("s"+"k-ant-", 9), true},
		{"GITHUB_TOKEN", fake("gh"+"p_", 13), true},
		{"AWS_ACCESS_KEY_ID", "AK" + "IA" + strings.Repeat("Q7X", 6)[:16], true},
		{"Authorization", "Bearer " + fake("s"+"k-", 10), true},
		{"MY_SECRET", "abcdefghijklmnopqrstuvwxyz", true}, // key says secret, value is long and opaque
		{"API_KEY", "${OPENAI_API_KEY}", false},           // env reference, not a value
		{"API_KEY", "$OPENAI_API_KEY", false},
		{"API_KEY", "<your-key-here>", false},
		{"API_KEY", "changeme", false},
		{"API_KEY", "", false},
		{"PATH", "/usr/local/bin:/usr/bin", false}, // slashes mean path, not token
		{"MCP_TRANSPORT", "stdio", false},          // benign key, short value
		{"TOKEN", "short", false},                  // secret-ish key but too short to be a credential
		// Identifiers whose name says auth are not credentials.
		{"TAILSCALE_OAUTH_CLIENT_ID", strings.Repeat("q7X", 6), false},
		{"oauthClientId", strings.Repeat("q7X", 6), false},
		{"AUTH_USERNAME", "someone.long.name", false},
		{"TAILSCALE_OAUTH_CLIENT_SECRET", strings.Repeat("q7X", 6), true},
		{"AUTH_TOKEN", strings.Repeat("q7X", 6), true},
	}
	for _, c := range cases {
		if got := looksLikeSecret(c.key, c.value); got != c.want {
			t.Errorf("looksLikeSecret(%q, %q) = %v, want %v", c.key, c.value, got, c.want)
		}
	}
}

//// INSTRUCTION FILE SIGNALS

func TestHiddenUnicodeCount(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"plain ascii\nwith newlines\tand tabs", 0},
		{"zero\u200bwidth", 1},
		{"\ufeffbom at start", 0},
		{"mid \ufeffbom", 1},
		{"a\ufe00\ufe01b", 2},
		{"heart \u2764\ufe0f ok", 0},
		{"x\U000E0100", 1},
		{"hangul\u3164filler", 1},
		{"bidi \u202eoverride\u202c", 2},
		{"tag chars \U000E0001\U000E007F", 2},
		{"soft\u00adhyphen", 1},
		{"émoji 🙂 and accents are fine", 0},
	}
	for _, c := range cases {
		if got := hiddenUnicodeCount([]byte(c.in)); got != c.want {
			t.Errorf("hiddenUnicodeCount(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestIncludePattern(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"@~/.claude/shared.md\n@/etc/x.md\n@./local.md\n@docs/rules.md\n@README.md", 5},
		{"ping @alice about this", 0},
		{"email me@example.com", 0},
		{"  @docs/indented.md", 1},
		{"see @docs/rules.md for more", 1},
	}
	for _, c := range cases {
		if got := len(includePattern.FindAllString(c.in, -1)); got != c.want {
			t.Errorf("includePattern on %q matched %d, want %d", c.in, got, c.want)
		}
	}
}

//// MCP LAUNCHERS

func TestLauncherType(t *testing.T) {
	cases := []struct {
		command string
		url     string
		want    string
	}{
		{"npx", "", "npx"},
		{"/opt/homebrew/bin/bunx", "", "npx"},
		{"uvx", "", "uvx"},
		{"docker", "", "docker"},
		{"node", "", "node"},
		{"python3", "", "python"},
		{"bash", "", "shell"},
		{"/usr/local/bin/cmesh", "", "binary"},
		{"", "https://mcp.example.com/sse", "remote"},
	}
	for _, c := range cases {
		if got := launcherType(c.command, nil, c.url); got != c.want {
			t.Errorf("launcherType(%q, nil, %q) = %q, want %q", c.command, c.url, got, c.want)
		}
	}
}

func TestLauncherTypeUV(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"run", "server.py"}, "python"},        // local script
		{[]string{"run", "./tools/local.py"}, "python"}, // local path
		{[]string{"run", "--with", "mcp", "server.py"}, "python"},
		{[]string{"run", "mcp-server-fetch"}, "uvx"}, // console script from a registry package
		{[]string{"tool", "run", "mcp-server-git"}, "uvx"},
	}
	for _, c := range cases {
		if got := launcherType("uv", c.args, ""); got != c.want {
			t.Errorf("launcherType(uv, %v) = %q, want %q", c.args, got, c.want)
		}
	}
}

func TestPinned(t *testing.T) {
	b := func(v bool) *bool { return &v }
	cases := []struct {
		lt   string
		args []string
		want *bool
	}{
		{"npx", []string{"-y", "@modelcontextprotocol/server-github@1.2.3"}, b(true)},
		{"npx", []string{"-y", "@modelcontextprotocol/server-github"}, b(false)},
		{"npx", []string{"-y", "@scope/pkg@latest"}, b(false)}, // a dist-tag floats; it is not a pin
		{"npx", []string{"-y", "@scope/pkg@v2.1.0"}, b(true)},
		{"npx", []string{"-y"}, b(false)},
		{"uvx", []string{"mcp-server-fetch==0.6.2"}, b(true)},
		{"uvx", []string{"mcp-server-fetch"}, b(false)},
		{"uvx", []string{"run", "bridge.py"}, b(false)},
		{"binary", []string{"serve"}, nil},
		{"remote", nil, nil},
	}
	for _, c := range cases {
		got := pinned(c.lt, c.args)
		switch {
		case got == nil && c.want == nil:
		case got == nil || c.want == nil || *got != *c.want:
			t.Errorf("pinned(%q, %v) = %v, want %v", c.lt, c.args, fmtBool(got), fmtBool(c.want))
		}
	}
}

func fmtBool(p *bool) string {
	if p == nil {
		return "nil"
	}
	if *p {
		return "true"
	}
	return "false"
}

//// SETTINGS FLATTENING

func TestFlatten(t *testing.T) {
	in := map[string]any{
		"permissions": map[string]any{
			"defaultMode": "auto",
			"allow":       []any{"Bash(ls:*)", "Read(~/**)"},
			"deny":        []any{},
		},
		"env":   map[string]any{},
		"model": "opus",
	}
	out := map[string]any{}
	flatten("", in, out)

	if out["permissions.defaultMode"] != "auto" {
		t.Errorf("defaultMode = %v", out["permissions.defaultMode"])
	}
	if out["model"] != "opus" {
		t.Errorf("model = %v", out["model"])
	}
	if arr, ok := out["permissions.allow"].([]any); !ok || len(arr) != 2 {
		t.Errorf("permissions.allow should be kept whole as a 2-element array, got %#v", out["permissions.allow"])
	}
	if _, ok := out["permissions.deny"]; !ok {
		t.Error("empty array leaf dropped")
	}
	if _, ok := out["env"]; !ok {
		t.Error("empty object leaf dropped; it should surface as a key so 'env is set but empty' is queryable")
	}
	if len(out) != 5 {
		t.Errorf("expected 5 leaves, got %d: %v", len(out), out)
	}
}

//// PERMISSION RULES

func TestPermRulePattern(t *testing.T) {
	cases := []struct {
		rule       string
		tool, spec string
		ok         bool
	}{
		{"Bash(git status:*)", "Bash", "git status:*", true},
		{"Read(~/.ssh/**)", "Read", "~/.ssh/**", true},
		{"mcp__pencil", "mcp__pencil", "", true},
		{"WebFetch", "WebFetch", "", true},
		{"*", "*", "", true},
		{"Bash(echo ) extra", "", "", false},
	}
	for _, c := range cases {
		m := permRulePattern.FindStringSubmatch(c.rule)
		if (m != nil) != c.ok {
			t.Errorf("permRulePattern(%q) matched=%v, want %v", c.rule, m != nil, c.ok)
			continue
		}
		if m != nil && (m[1] != c.tool || m[2] != c.spec) {
			t.Errorf("permRulePattern(%q) = (%q, %q), want (%q, %q)", c.rule, m[1], m[2], c.tool, c.spec)
		}
	}
}

//// PATH RESOLUTION AND COVERAGE

func TestResolvePermissionPath(t *testing.T) {
	home, anchor := "/home/u", "/home/u/proj/.claude"
	cases := []struct{ spec, want string }{
		{"//etc/passwd", "/etc/passwd"},
		{"~/.ssh/**", "/home/u/.ssh/**"},
		{"~", "/home/u"},
		{"/src/**", "/home/u/proj/.claude/src/**"}, // single slash anchors at the settings dir
		{"./build", "<cwd>/build"},
		{"build/*.go", "<cwd>/build/*.go"},
	}
	for _, c := range cases {
		if got := resolvePermissionPath(c.spec, home, anchor); got != c.want {
			t.Errorf("resolvePermissionPath(%q) = %q, want %q", c.spec, got, c.want)
		}
	}
}

func TestResolveSandboxPath(t *testing.T) {
	home, anchor := "/home/u", "/home/u/proj"
	cases := []struct{ pat, want string }{
		{"~/.aws", "/home/u/.aws"},
		{"/etc/hosts", "/etc/hosts"},
		{".env", "/home/u/proj/.env"},
		{"../secrets", "/home/u/secrets"},
	}
	for _, c := range cases {
		if got := resolveSandboxPath(c.pat, home, anchor); got != c.want {
			t.Errorf("resolveSandboxPath(%q) = %q, want %q", c.pat, got, c.want)
		}
	}
}

func TestCovers(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/home/u/.ssh", "/home/u/.ssh", true},
		{"/home/u/.ssh", "/home/u/.ssh/id_ed25519", true}, // directory rule is a prefix
		{"/home/u/.ssh", "/home/u/.sshx", false},          // but not a string prefix
		{"/home/u/.ssh/*", "/home/u/.ssh/id_ed25519", true},
		{"/home/u/.ssh/*", "/home/u/.ssh/sub/key", true}, // pattern exhausted on a prefix still covers
		{"/home/u/**/.env", "/home/u/a/b/.env", true},
		{"/home/u/**/.env", "/home/u/.env", true},
		{"/home/u/**", "/home/u/anything/at/all", true},
		{"/home/u/*.json", "/home/u/.claude.json", true},
		{"/home/u/*.json", "/home/u/x/.claude.json", false},
		{"<cwd>/.env", "/home/u/proj/.env", false}, // unresolvable cwd-relative never covers
		{"", "/home/u/.ssh", false},
	}
	for _, c := range cases {
		if got := covers(c.pattern, c.path); got != c.want {
			t.Errorf("covers(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestExpandHome(t *testing.T) {
	cases := []struct{ in, want string }{
		{"~", "/home/u"},
		{"~/x", "/home/u/x"},
		{"/abs", "/abs"},
		{"~user/x", "~user/x"},
	}
	for _, c := range cases {
		if got := expandHome(c.in, "/home/u"); got != c.want {
			t.Errorf("expandHome(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

//// CATALOG INTEGRITY

// TestCatalogShape keeps the sensitive-path catalog honest: every entry has a
// category and a description that reads as a sentence, and no path repeats.
func TestCatalogShape(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range sensitiveCatalog {
		if e.Path == "" || e.Category == "" {
			t.Errorf("catalog entry %+v missing path or category", e)
		}
		if seen[e.Path] {
			t.Errorf("catalog path %q listed twice", e.Path)
		}
		seen[e.Path] = true
		if len(e.Description) < 8 || e.Description[len(e.Description)-1] != '.' {
			t.Errorf("catalog %q description must be a sentence ending in a period: %q", e.Path, e.Description)
		}
		if !e.Darwin && !e.Linux {
			t.Errorf("catalog %q applies to no platform", e.Path)
		}
	}
}

//// PLUGINS AND MARKETPLACES

func TestPluginPinned(t *testing.T) {
	b := func(v bool) *bool { return &v }
	cases := []struct {
		version, sha string
		want         *bool
	}{
		{"2.0.17", "41f619d61b999adec1a1c8deb97d1a5b6ac35bb6", b(true)},
		{"41f619d61b99", "41f619d61b999adec1a1c8deb97d1a5b6ac35bb6", b(false)},
		{"41f619d61b99", "", b(false)},
		{"v1.0", "", b(true)},
		{"", "41f619d61b99", nil},
	}
	for _, c := range cases {
		got := pluginPinned(c.version, c.sha)
		switch {
		case got == nil && c.want == nil:
		case got == nil || c.want == nil || *got != *c.want:
			t.Errorf("pluginPinned(%q, %q) = %v, want %v", c.version, c.sha, fmtBool(got), fmtBool(c.want))
		}
	}
}

func TestPluginEnabled(t *testing.T) {
	user := map[string]any{"a@m": true, "b@m": false}
	proj := map[string]any{"b@m": true}
	decision := func(m map[string]any, full string) *bool {
		if v, ok := m[full].(bool); ok {
			return &v
		}
		return nil
	}
	if got := decision(user, "a@m"); got == nil || !*got {
		t.Errorf("a@m: want true")
	}
	if got := decision(user, "b@m"); got == nil || *got {
		t.Errorf("b@m: want false")
	}
	if got := decision(user, "c@m"); got != nil {
		t.Errorf("c@m: want nil, got %v", *got)
	}
	if got := decision(mergeEnabled(user, proj), "b@m"); got == nil || !*got {
		t.Errorf("project override of b@m: want true")
	}
	if n, m := splitPluginName("code-review@claude-plugins-official"); n != "code-review" || m != "claude-plugins-official" {
		t.Errorf("splitPluginName = %q, %q", n, m)
	}
}

func TestMarketplaceAllowed(t *testing.T) {
	list := []any{
		map[string]any{"source": "github", "repo": "acme-corp/approved-plugins"},
		map[string]any{"source": "github", "repo": "trusted-org/*"},
		map[string]any{"source": "url", "url": "https://plugins.example.com/marketplace.json"},
		map[string]any{"source": "directory", "path": "/opt/acme/marketplaces"},
		map[string]any{"source": "hostPattern", "hostPattern": `^gitlab\.example\.com$`},
		map[string]any{"source": "pathPattern", "pathPattern": `^/opt/approved/`},
	}
	cases := []struct {
		name, src, repo string
		want            bool
	}{
		{"approved", "github", "acme-corp/approved-plugins", true},
		{"approved-case", "github", "Acme-Corp/Approved-Plugins", true},
		{"wild", "github", "trusted-org/anything", true},
		{"other", "github", "someone/else", false},
		{"url", "url", "https://plugins.example.com/marketplace.json", true},
		{"dir", "directory", "/opt/acme/marketplaces", true},
		{"host", "git", "https://gitlab.example.com/tools/plugins.git", true},
		{"host-ssh", "git", "git@gitlab.example.com:tools/plugins.git", true},
		{"host-other", "git", "https://github.com/x/y.git", false},
		{"pathpat", "directory", "/opt/approved/x", true},
		{"pathpat-no", "directory", "/tmp/x", false},
	}
	for _, c := range cases {
		if got := marketplaceAllowed(c.name, c.src, c.repo, list); got != c.want {
			t.Errorf("%s: marketplaceAllowed = %v, want %v", c.name, got, c.want)
		}
	}
	if !marketplaceAllowed(officialMarketplace, "github", officialMarketplaceRepo, []any{map[string]any{"source": "github", "repo": "anthropics/claude-plugins-official"}}) {
		t.Errorf("official marketplace should be admitted by its repo")
	}
	if marketplaceAllowed(officialMarketplace, "github", officialMarketplaceRepo, []any{}) {
		t.Errorf("empty allowlist must admit nothing")
	}
	if !marketplaceOfficial("claude-plugins-official", "") || !marketplaceOfficial("x", "Anthropics/claude-plugins-official") || marketplaceOfficial("x", "y/z") {
		t.Errorf("marketplaceOfficial misclassifies")
	}
}

func TestCollectPluginsFixture(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".claude")
	root := filepath.Join(cfg, "plugins", "cache", "m", "p", "1.2.3")
	for _, d := range []string{filepath.Join(root, "hooks"), filepath.Join(root, "skills", "s1"), filepath.Join(root, "skills", "s2"), filepath.Join(root, "agents"), filepath.Join(root, ".claude-plugin"), filepath.Join(cfg, "plugins", "marketplaces", "m")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "hooks", "hooks.json"), `{"hooks":{}}`)
	write(filepath.Join(root, "skills", "s1", "SKILL.md"), "# s1\n")
	write(filepath.Join(root, "skills", "s2", "SKILL.md"), "# s2\n")
	write(filepath.Join(root, "agents", "a.md"), "# a\n")
	write(filepath.Join(root, ".claude-plugin", "plugin.json"), `{"name":"p","mcpServers":{"x":{"command":"true"}}}`)
	write(filepath.Join(cfg, "plugins", "installed_plugins.json"), `{"version":2,"plugins":{
	  "p@m":[{"scope":"user","installPath":"`+root+`","version":"1.2.3","installedAt":"2026-01-07T18:42:02.292Z","lastUpdated":"2026-10-27T14:43:18.370Z","gitCommitSha":"41f619d61b999adec1a1c8deb97d1a5b6ac35bb6"}],
	  "q@m":[{"scope":"user","installPath":"`+filepath.Join(cfg, "plugins", "cache", "m", "q", "deadbeef1234")+`","version":"deadbeef1234","gitCommitSha":"deadbeef1234deadbeef1234deadbeef12345678"}]}}`)
	write(filepath.Join(cfg, "plugins", "known_marketplaces.json"), `{
	  "m":{"source":{"source":"github","repo":"org/m"},"installLocation":"`+filepath.Join(cfg, "plugins", "marketplaces", "m")+`","lastUpdated":"2026-10-27T14:56:52.355Z","autoUpdate":true},
	  "claude-plugins-official":{"source":{"source":"github","repo":"anthropics/claude-plugins-official"},"installLocation":"/nonexistent"}}`)
	// strictKnownMarketplaces is managed-only: a user-settings copy is
	// ignored (P6), the managed copy decides.
	managed := filepath.Join(home, "managed")
	if err := os.MkdirAll(managed, 0o755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(cfg, "settings.json"), `{"enabledPlugins":{"p@m":false},"strictKnownMarketplaces":[{"source":"github","repo":"org/m"}]}`)
	write(filepath.Join(home, ".claude.json"), `{}`)
	userOnly := Collect(context.Background(), Options{Home: home, Probe: false, ManagedDir: managed, PlistPath: "-"})
	for _, mk := range userOnly.Marketplaces {
		if mk.InStrictAllowlist != nil {
			t.Errorf("user-scope strictKnownMarketplaces honoured for %s", mk.Name)
		}
	}
	write(filepath.Join(managed, "managed-settings.json"), `{"strictKnownMarketplaces":[{"source":"github","repo":"anthropics/claude-plugins-official"}]}`)

	snap := Collect(context.Background(), Options{Home: home, Probe: false, ManagedDir: managed, PlistPath: "-"})
	if len(snap.Plugins) != 2 {
		t.Fatalf("plugins: got %d rows, want 2", len(snap.Plugins))
	}
	p := snap.Plugins[0]
	if p.FullName != "p@m" || p.Name != "p" || p.Marketplace != "m" || p.Scope != "user" {
		t.Errorf("identity: %+v", p)
	}
	if p.Pinned == nil || !*p.Pinned || p.Enabled == nil || *p.Enabled {
		t.Errorf("p@m pinned/enabled: pinned=%s enabled=%s", fmtBool(p.Pinned), fmtBool(p.Enabled))
	}
	if !p.HasHooks || !p.HasMCP || p.SkillCount != 2 || p.AgentCount != 1 || p.CommandCount != 0 || p.HasInstructionFile {
		t.Errorf("contents: %+v", p)
	}
	if p.InstalledAt == nil || p.InstalledAt.Year() != 2026 || p.WritableBy != "owner" {
		t.Errorf("installed_at/writable: %+v", p)
	}
	q := snap.Plugins[1]
	if q.Pinned == nil || *q.Pinned || q.Enabled != nil || q.InstallPathExists {
		t.Errorf("q@m: pinned=%s enabled=%s exists=%v", fmtBool(q.Pinned), fmtBool(q.Enabled), q.InstallPathExists)
	}
	if len(snap.Marketplaces) != 2 {
		t.Fatalf("marketplaces: got %d rows, want 2", len(snap.Marketplaces))
	}
	off, m := snap.Marketplaces[0], snap.Marketplaces[1]
	if !off.Official || off.InStrictAllowlist == nil || !*off.InStrictAllowlist || off.InstallLocationExists {
		t.Errorf("official: %+v", off)
	}
	if m.Official || m.InStrictAllowlist == nil || *m.InStrictAllowlist || !m.InstallLocationExists || m.AutoUpdate == nil || !*m.AutoUpdate || m.SourceRepo != "org/m" {
		t.Errorf("m: %+v", m)
	}
}

//// SERVER-MANAGED SETTINGS

func TestRemoteSettingsFixture(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".claude")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	remote := filepath.Join(cfg, "remote-settings.json")
	if err := os.WriteFile(remote, []byte(`{"sandbox":{"enabled":true,"filesystem":{"denyRead":["~/.aws"]}},"permissions":{"deny":["Read(~/.ssh/**)"],"defaultMode":"plan"},"allowManagedHooksOnly":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	snap := Collect(context.Background(), Options{Home: home, Probe: false, ManagedDir: filepath.Join(home, "no-managed"), PlistPath: "-"})
	if len(snap.Agents) != 1 {
		t.Fatalf("agents: %d", len(snap.Agents))
	}
	a := snap.Agents[0]
	if !a.RemoteSettingsPresent || a.RemoteSettingsPath != remote || !a.ManagedSettingsPresent {
		t.Errorf("agent remote/managed flags: %+v", a)
	}
	if !a.SandboxEnabled || a.EffectivePermissionMode != "plan" {
		t.Errorf("remote settings must count as managed: sandbox=%v mode=%q", a.SandboxEnabled, a.EffectivePermissionMode)
	}
	var sawSetting, sawSandbox, sawPerm bool
	for _, s := range snap.Settings {
		if s.Scope == "managed" && s.SourcePath == remote && s.Key == "allowManagedHooksOnly" {
			sawSetting = true
		}
	}
	for _, r := range snap.SandboxRules {
		if r.Scope == "managed" && r.SourcePath == remote && r.Category == "filesystem" && r.RuleType == "denyRead" {
			sawSandbox = true
		}
		if r.Scope == "managed" && r.SourcePath == remote && r.Category == "permission" && r.Tool == "Read" {
			sawPerm = true
		}
	}
	if !sawSetting || !sawSandbox || !sawPerm {
		t.Errorf("remote rows: setting=%v sandbox=%v perm=%v", sawSetting, sawSandbox, sawPerm)
	}
}

//// SECRET CLASSIFIER: SHAPES THE FIRST VERSION MISSED

func TestLooksLikeSecretShapes(t *testing.T) {
	cases := []struct {
		key, value string
		want       bool
	}{
		{"AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", true},  // base64 with "/" is still a token
		{"DATABASE_URL", "postgres://app:s3cretpassw0rd@db.internal:5432/app", true}, // userinfo password
		{"DATABASE_URL", "postgres://db.internal:5432/app", false},                   // no credential in it
		{"HOME_TOKEN_DIR", "/Users/alice/.tokens/", false},                           // path
		{"API_KEY", "~/.config/key", false},
		{"SECRET_FILE", "./secrets/x.json", false},
	}
	for _, c := range cases {
		if got := looksLikeSecret(c.key, c.value); got != c.want {
			t.Errorf("looksLikeSecret(%q, %q) = %v, want %v", c.key, c.value, got, c.want)
		}
	}
}

func TestPermRulePatternMultiline(t *testing.T) {
	m := permRulePattern.FindStringSubmatch("Bash(cat <<'EOF' > x\nline\nEOF)")
	if m == nil || m[1] != "Bash" {
		t.Fatalf("multi-line Bash rule must parse: %v", m)
	}
}

func TestResolvePermissionRuleDepth(t *testing.T) {
	cases := []struct {
		spec, rt, want string
	}{
		{".env", "deny", "<cwd>/**/.env"}, // bare filename: any depth
		{"./.env", "deny", "<cwd>/**/.env"},
		{"secrets/**", "deny", "<cwd>/**/secrets/**"}, // single dir segment: any depth for deny
		{"secrets/**", "allow", "<cwd>/secrets/**"},   // allow stays anchored
		{"src/components/**", "deny", "<cwd>/src/components/**"},
		{"**/.env", "deny", "<cwd>/**/.env"},
		{"/secrets/**", "deny", "/proj/secrets/**"}, // anchored at the settings source
		{"~/.ssh/**", "deny", "/home/u/.ssh/**"},
		{"//etc/passwd", "deny", "/etc/passwd"},
	}
	for _, c := range cases {
		if got := resolvePermissionRule(c.spec, c.rt, "/home/u", "/proj"); got != c.want {
			t.Errorf("resolvePermissionRule(%q, %q) = %q, want %q", c.spec, c.rt, got, c.want)
		}
	}
	if withCwd("<cwd>/**/.env", "") != "" || withCwd("<cwd>/**/.env", "/p") != "/p/**/.env" || withCwd("/abs", "/p") != "/abs" {
		t.Errorf("withCwd")
	}
	if !covers("/p/**/.env", "/p/.env") || !covers("/p/**/.env", "/p/a/b/.env") || covers("/p/**/.env", "/q/.env") {
		t.Errorf("covers with **")
	}
}

//// FIXTURES: MANAGED TIER, SCOPES, APPROVALS, REDACTION

type fixture struct {
	t       *testing.T
	home    string
	cfg     string
	managed string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	home := t.TempDir()
	f := fixture{t: t, home: home, cfg: filepath.Join(home, ".claude"), managed: filepath.Join(home, "managed")}
	for _, d := range []string{f.cfg, f.managed} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.write(filepath.Join(home, ".claude.json"), `{}`)
	return f
}

func (f fixture) write(p, s string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f fixture) collect(extra ...string) *Snapshot {
	return Collect(context.Background(), Options{Home: f.home, Probe: true, ManagedDir: f.managed, PlistPath: "-", ProjectDirs: extra})
}

func (f fixture) agent(snap *Snapshot) Agent {
	if len(snap.Agents) != 1 {
		f.t.Fatalf("agents: %d", len(snap.Agents))
	}
	return snap.Agents[0]
}

func settingValue(snap *Snapshot, scope, key string) (Setting, bool) {
	for _, s := range snap.Settings {
		if s.Scope == scope && s.Key == key {
			return s, true
		}
	}
	return Setting{}, false
}

// Docs: "first-wins, the default: Claude Code uses the highest-ranked source
// that delivers at least one policy key and ignores the rest".
func TestManagedFirstWins(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "remote-settings.json"), `{"sandbox":{"enabled":false},"permissions":{"defaultMode":"plan"}}`)
	f.write(filepath.Join(f.managed, "managed-settings.json"), `{"sandbox":{"enabled":true},"disableAllHooks":true,"permissions":{"deny":["Read(~/.ssh/**)"]}}`)
	snap := f.collect()
	a := f.agent(snap)
	if a.ManagedSource != "remote" || a.ManagedSourcesBehavior != "first-wins" {
		t.Fatalf("source=%q behavior=%q", a.ManagedSource, a.ManagedSourcesBehavior)
	}
	if a.SandboxEnabled || a.HooksDisabled || a.EffectivePermissionMode != "plan" {
		t.Errorf("remote must win outright: sandbox=%v hooks=%v mode=%q", a.SandboxEnabled, a.HooksDisabled, a.EffectivePermissionMode)
	}
	if !a.ManagedSettingsPresent || !a.RemoteSettingsPresent || len(a.CollectErrors) != 0 {
		t.Errorf("flags: %+v", a)
	}
	// The skipped file is still listed, marked as not applying, and
	// contributes no rules.
	s, ok := settingValue(snap, "managed", "disableAllHooks")
	if !ok || s.Applies {
		t.Errorf("skipped managed file row: found=%v applies=%v", ok, s.Applies)
	}
	for _, r := range snap.SandboxRules {
		if r.Scope == "managed" && r.Tool == "Read" {
			t.Errorf("rule from a skipped source must not apply: %+v", r)
		}
	}
}

// Docs: "An empty managed settings file counts as {}"; a document with no
// policy key is skipped and the next source is used.
func TestManagedEmptyRemoteFallsThrough(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "remote-settings.json"), `{}`)
	f.write(filepath.Join(f.managed, "managed-settings.json"), `{"sandbox":{"enabled":true}}`)
	a := f.agent(f.collect())
	if a.ManagedSource != "file" || !a.SandboxEnabled || !a.RemoteSettingsPresent {
		t.Errorf("source=%q sandbox=%v remote=%v", a.ManagedSource, a.SandboxEnabled, a.RemoteSettingsPresent)
	}
}

// Docs: drop-ins merge after managed-settings.json in alphabetical order;
// scalars replace, lists union, nested blocks merge key by key.
func TestManagedDropIns(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.managed, "managed-settings.json"), `{"model":"opus","permissions":{"deny":["Read(~/.ssh/**)"]},"sandbox":{"enabled":true}}`)
	f.write(filepath.Join(f.managed, "managed-settings.d", "20-b.json"), `{"model":"sonnet","permissions":{"deny":["Read(~/.aws/**)"]}}`)
	f.write(filepath.Join(f.managed, "managed-settings.d", "10-a.json"), `{"model":"haiku","sandbox":{"filesystem":{"denyRead":["~/.gnupg"]}}}`)
	f.write(filepath.Join(f.managed, "managed-settings.d", ".hidden.json"), `{"model":"hidden"}`)
	f.write(filepath.Join(f.managed, "managed-settings.d", "notes.txt"), `{"model":"txt"}`)
	snap := f.collect()
	a := f.agent(snap)
	if a.ManagedSource != "file + drop-ins" || !a.SandboxEnabled {
		t.Fatalf("source=%q sandbox=%v", a.ManagedSource, a.SandboxEnabled)
	}
	if s, _ := settingValue(snap, "managed", "model"); s.Value != "sonnet" {
		t.Errorf("later drop-in must replace scalar: %v", s.Value)
	}
	var deny, denyRead int
	for _, r := range snap.SandboxRules {
		if r.Scope == "managed" && r.Tool == "Read" && r.RuleType == "deny" {
			deny++
		}
		if r.Scope == "managed" && r.RuleType == "denyRead" {
			denyRead++
		}
	}
	if deny != 2 || denyRead != 1 {
		t.Errorf("lists must union: permission deny=%d sandbox denyRead=%d", deny, denyRead)
	}
}

// Docs: "merge: ... on most keys the higher-ranked source's value applies,
// lists union". Cross-source locks are read from every admin source.
func TestManagedMergeAndLocks(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "remote-settings.json"), `{"managedSourcesBehavior":"merge","model":"opus"}`)
	f.write(filepath.Join(f.managed, "managed-settings.json"), `{"model":"sonnet","sandbox":{"enabled":true}}`)
	snap := f.collect()
	a := f.agent(snap)
	if a.ManagedSource != "remote + file, merged" || a.ManagedSourcesBehavior != "merge" || !a.SandboxEnabled {
		t.Errorf("merge: source=%q behavior=%q sandbox=%v", a.ManagedSource, a.ManagedSourcesBehavior, a.SandboxEnabled)
	}
	// first-wins with a lock only in the unselected source
	f2 := newFixture(t)
	f2.write(filepath.Join(f2.cfg, "remote-settings.json"), `{"model":"opus"}`)
	f2.write(filepath.Join(f2.managed, "managed-settings.json"), `{"sandbox":{"filesystem":{"allowManagedReadPathsOnly":true}}}`)
	snap2 := f2.collect()
	if a2 := f2.agent(snap2); a2.ManagedSource != "remote" {
		t.Fatalf("source=%q", a2.ManagedSource)
	}
	// the lock is visible on the effective document through computeEffective's
	// inputs: check via a fresh collector read of the merged doc
	c := &ccCollector{snap: &Snapshot{}, remotePath: filepath.Join(f2.cfg, "remote-settings.json"), managedDir: f2.managed}
	c.loadManaged(context.Background())
	if b := getBool(c.managed, "sandbox", "filesystem", "allowManagedReadPathsOnly"); b == nil || !*b {
		t.Errorf("cross-source lock must be read from the unselected source")
	}
	if c.managed["model"] != "opus" {
		t.Errorf("selected source must still win scalars: %v", c.managed["model"])
	}
}

// Docs: "For a managed settings document that isn't valid JSON ... every
// session exits at startup". The posture is unknown, not "no managed settings".
func TestManagedMalformedSurfacesError(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.managed, "managed-settings.json"), `{"sandbox": {"enabled": true,}`)
	a := f.agent(f.collect())
	if !a.ManagedSettingsPresent || a.ManagedSource != "" || len(a.CollectErrors) != 1 || !strings.Contains(a.CollectErrors[0], "managed-settings.json") {
		t.Errorf("present=%v source=%q errors=%v", a.ManagedSettingsPresent, a.ManagedSource, a.CollectErrors)
	}
}

// Docs (permissions): deny rules from any scope apply; project settings
// anchor "/path" at the project and bare names match at any depth. A project
// rule must not make a home-directory file look protected machine-wide.
func TestProjectScopeDenyRules(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "work", "app")
	f.write(filepath.Join(proj, ".env"), "X=1\n")
	f.write(filepath.Join(proj, "nested", "deep", ".env"), "Y=1\n")
	f.write(filepath.Join(proj, ".claude", "settings.json"), `{"permissions":{"deny":["Read(.env)","Read(~/.ssh/**)"]},"sandbox":{"enabled":true,"filesystem":{"denyRead":["~/.aws"]}}}`)
	f.write(filepath.Join(f.home, ".ssh", "id_ed25519"), "key\n") // catalog row is the ~/.ssh directory
	f.write(filepath.Join(f.home, ".aws", "credentials"), "[default]\n")
	f.write(filepath.Join(f.home, ".claude.json"), `{"projects":{"`+proj+`":{"hasTrustDialogAccepted":true}}}`)
	snap := f.collect()
	byPath := map[string]ReachFile{}
	for _, r := range snap.ReachFiles {
		byPath[r.Path] = r
	}
	env := byPath[filepath.Join(proj, ".env")]
	if env.PermissionDenyReadRule != "Read(.env)" || env.ReachableViaReadTool == nil || *env.ReachableViaReadTool {
		t.Errorf("project deny must cover the project's .env: %+v", env)
	}
	// Project sandbox.enabled applies in that project, so the sandbox rule
	// blocks shell reads there; ~/.aws is a home file and stays reachable
	// machine-wide because user and managed settings do not enable the sandbox.
	if env.ReachableViaBash == nil || !*env.ReachableViaBash {
		t.Errorf(".env has no sandbox denyRead rule, so bash reach stays true: %+v", env)
	}
	ssh := byPath[filepath.Join(f.home, ".ssh")]
	if ssh.PermissionDenyReadRule != "" || ssh.ReachableViaReadTool == nil || !*ssh.ReachableViaReadTool {
		t.Errorf("a project-scope rule must not protect a home file machine-wide: %+v", ssh)
	}
	aws := byPath[filepath.Join(f.home, ".aws", "credentials")]
	if aws.SandboxDenyReadRule != "" || aws.ReachableViaBash == nil || !*aws.ReachableViaBash {
		t.Errorf("project sandbox rule must not count machine-wide: %+v", aws)
	}
	a := f.agent(snap)
	if a.SandboxEnabled {
		t.Errorf("project-only sandbox.enabled is not machine-wide")
	}
}

// Docs (mcp): approvals in user and managed settings apply everywhere; in
// project and local files only once the folder is trusted;
// disabledMcpjsonServers in any file rejects; ~/.claude.json records
// interactive choices.
func TestMCPApprovalSources(t *testing.T) {
	f := newFixture(t)
	trusted := filepath.Join(f.home, "t")
	untrusted := filepath.Join(f.home, "u")
	mcp := `{"mcpServers":{"a":{"command":"x"},"b":{"command":"x"},"c":{"command":"x"},"d":{"command":"x"},"e":{"command":"x"}}}`
	for _, d := range []string{trusted, untrusted} {
		f.write(filepath.Join(d, ".mcp.json"), mcp)
		f.write(filepath.Join(d, ".claude", "settings.json"), `{"enabledMcpjsonServers":["a"]}`)
		f.write(filepath.Join(d, ".claude", "settings.local.json"), `{"enabledMcpjsonServers":["b"],"disabledMcpjsonServers":["c"]}`)
	}
	f.write(filepath.Join(f.cfg, "settings.json"), `{"enabledMcpjsonServers":["d"]}`)
	f.write(filepath.Join(f.home, ".claude.json"), `{"projects":{"`+trusted+`":{"hasTrustDialogAccepted":true,"enabledMcpjsonServers":["e"]},"`+untrusted+`":{"hasTrustDialogAccepted":false}}}`)
	snap := f.collect()
	got := map[string]string{}
	for _, s := range snap.MCPServers {
		if s.Scope == "project" {
			got[filepath.Base(s.ProjectDir)+"/"+s.Name] = fmtBool(s.Enabled)
		}
	}
	want := map[string]string{
		"t/a": "true", "t/b": "true", "t/c": "false", "t/d": "true", "t/e": "true",
		"u/a": "nil", "u/b": "nil", "u/c": "false", "u/d": "true", "u/e": "nil",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: enabled=%s, want %s", k, got[k], v)
		}
	}
}

// The plugin classifies, never stores: env values leave the table as a
// boolean, switches stay readable, helpers are redacted.
func TestSettingRedaction(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "settings.json"), `{"env":{"OPENAI_API_KEY":"`+fake("s"+"k-", 10)+`","DISABLE_TELEMETRY":"1","CLAUDE_CODE_FLAG":"true","EDITOR":"vim"},"apiKeyHelper":"/usr/local/bin/get-key","model":"opus"}`)
	snap := f.collect()
	check := func(key string, wantRedacted bool, wantSecret string, wantValue any) {
		s, ok := settingValue(snap, "user", key)
		if !ok {
			t.Errorf("%s: missing", key)
			return
		}
		if s.Redacted != wantRedacted || fmtBool(s.LooksLikeSecret) != wantSecret || s.Value != wantValue || !s.Applies {
			t.Errorf("%s: redacted=%v looks=%s value=%v applies=%v", key, s.Redacted, fmtBool(s.LooksLikeSecret), s.Value, s.Applies)
		}
	}
	check("env.OPENAI_API_KEY", true, "true", nil)
	check("env.DISABLE_TELEMETRY", false, "nil", "1")
	check("env.CLAUDE_CODE_FLAG", false, "nil", "true")
	check("env.EDITOR", true, "false", nil)
	check("apiKeyHelper", true, "false", nil)
	check("model", false, "nil", "opus")
	for _, s := range snap.Settings {
		if v, ok := s.Value.(string); ok && strings.Contains(v, "sk-abc") {
			t.Fatalf("secret value stored in %s", s.Key)
		}
	}
}

// Managed CLAUDE.md and managed-mcp.json live in the system directory.
func TestManagedMCPAndInstructions(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.managed, "managed-mcp.json"), `{"mcpServers":{"corp":{"type":"http","url":"https://mcp.corp.example/sse"}}}`)
	f.write(filepath.Join(f.managed, "CLAUDE.md"), "# org rules\n")
	snap := f.collect()
	var mcp, inst bool
	for _, s := range snap.MCPServers {
		if s.Scope == "managed" && s.Name == "corp" && s.Transport == "http" {
			mcp = true
		}
	}
	for _, i := range snap.InstructionFiles {
		if i.Scope == "managed" && i.Kind == "CLAUDE.md" {
			inst = true
		}
	}
	if !mcp || !inst {
		t.Errorf("managed mcp=%v instruction=%v", mcp, inst)
	}
}

func TestInstructionTreesRecursive(t *testing.T) {
	f := newFixture(t)
	f.write(filepath.Join(f.cfg, "rules", "team", "go", "style.md"), "# nested rule\n")
	f.write(filepath.Join(f.cfg, "commands", "ops", "deploy.md"), "# nested command\n")
	f.write(filepath.Join(f.cfg, "agents", "review", "sec.md"), "# nested agent\n")
	f.write(filepath.Join(f.cfg, "rules", ".hidden", "skip.md"), "# hidden dir\n")
	snap := f.collect()
	got := map[string]bool{}
	for _, i := range snap.InstructionFiles {
		got[i.Kind+":"+filepath.Base(i.Path)] = true
	}
	for _, want := range []string{"rules:style.md", "command:deploy.md", "subagent:sec.md"} {
		if !got[want] {
			t.Errorf("nested instruction file %s not found; got %v", want, got)
		}
	}
	if got["rules:skip.md"] {
		t.Error("file under a hidden directory was collected")
	}
}
