package posture

// Regression tests for the fixes from the security review: credentialed URLs
// in published provenance fields, multi-line PEM redaction, and symlinked
// instruction files that resolve outside the project they were found in.
// Credentials are built at run time (see fake) so this file adds no
// secret-shaped literal to the tree.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitRemoteRedacted(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "work", "app")
	tok := fake("gh"+"p_", 10)
	f.write(filepath.Join(proj, ".git", "config"),
		"[remote \"origin\"]\n\turl = https://user:"+tok+"@github.com/org/repo\n")
	snap := f.collect(proj)

	var seen bool
	for _, p := range snap.Projects {
		if p.ProjectDir != proj {
			continue
		}
		seen = true
		if strings.Contains(p.GitRemote, tok) {
			t.Errorf("token kept in git_remote: %q", p.GitRemote)
		}
		if !strings.Contains(p.GitRemote, redactedMark+"@github.com/org/repo") {
			t.Errorf("git_remote lost its host/path or the marker: %q", p.GitRemote)
		}
	}
	if !seen {
		t.Fatalf("no project row for %s", proj)
	}
}

func TestMarketplaceSourceRepoRedacted(t *testing.T) {
	f := newFixture(t)
	tok := fake("gh"+"p_", 10)
	f.write(filepath.Join(f.cfg, "plugins", "known_marketplaces.json"),
		`{"m":{"source":{"source":"git","url":"https://user:`+tok+`@github.com/org/m"}}}`)
	snap := f.collect()

	var seen bool
	for _, mk := range snap.Marketplaces {
		if mk.Name != "m" {
			continue
		}
		seen = true
		if strings.Contains(mk.SourceRepo, tok) {
			t.Errorf("token kept in source_repo: %q", mk.SourceRepo)
		}
		if !strings.Contains(mk.SourceRepo, redactedMark) {
			t.Errorf("source_repo not marked: %q", mk.SourceRepo)
		}
	}
	if !seen {
		t.Fatal("no marketplace row")
	}
}

// testPEM builds a PEM private key block at run time: the header is split so
// no secret-shaped literal (gitleaks' private-key rule) sits in the tree.
func testPEM(label, body string) string {
	const begin, end = "-----BEGIN ", "-----END "
	const key = "PRIVATE" + " KEY-----"
	return begin + label + key + "\n" + body + "\n" + end + label + key
}

func TestPEMBlockRedacted(t *testing.T) {
	body := strings.Repeat("MIIEowIBAAKCAQEA", 4)
	rsa := testPEM("RSA ", body)
	openssh := testPEM("OPENSSH ", body)

	for name, in := range map[string]string{
		"bare":       rsa,
		"after flag": "run --key " + rsa,
		"inside sh":  "sh -c 'echo " + rsa + "'",
		"openssh":    "PRIVATE_KEY=" + openssh,
	} {
		got, changed := scrubText(in)
		if !changed {
			t.Errorf("%s: scrubText reported no change: %q", name, got)
		}
		if strings.Contains(got, "BEGIN RSA ") || strings.Contains(got, body[:16]) {
			t.Errorf("%s: PEM survived scrubText: %q", name, got)
		}
		if !strings.Contains(got, redactedMark) {
			t.Errorf("%s: no redaction marker: %q", name, got)
		}
	}
	// The context around the block is kept, so a reviewer still sees what runs.
	if got, _ := scrubText("run --key " + rsa + " --verbose"); !strings.Contains(got, "--verbose") || !strings.Contains(got, "run") {
		t.Errorf("surrounding text lost: %q", got)
	}

	for name, args := range map[string][]string{
		"bare":     {rsa},
		"--key":    {"--key", rsa},
		"prefixed": {"echo " + rsa},
		"kv":       {"--payload=" + rsa},
	} {
		got, _ := scrubArgs(args)
		joined := strings.Join(got, " ")
		if strings.Contains(joined, body[:16]) || strings.Contains(joined, "BEGIN RSA ") {
			t.Errorf("%s: PEM survived scrubArgs: %q", name, joined)
		}
	}

	// A certificate is public and must survive: the pattern is PRIVATE KEY only.
	cert := "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----"
	if got, changed := scrubText("cert " + cert); changed || got != "cert "+cert {
		t.Errorf("certificate was altered: %q", got)
	}
}

// A repository can ship CLAUDE.md as a symlink to a file outside the
// repository. Its size and digest must not be published, and the skip must be
// recorded as a collect error (missing evidence is never a pass).
func TestInstructionSymlinkOutsideProjectNotRead(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "work", "app")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(outside, []byte("SECRET_INSTRUCTION\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(proj, "CLAUDE.md")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	f.write(filepath.Join(proj, ".claude", "settings.json"), `{}`)
	snap := f.collect(proj)

	want := filepath.Join(proj, "CLAUDE.md")
	for _, r := range snap.InstructionFiles {
		if r.Path != want {
			continue
		}
		t.Errorf("out-of-tree symlink was read: size=%d sha=%s", r.SizeBytes, r.SHA256)
	}
	recorded := false
	for _, e := range snap.Errors {
		if strings.Contains(e, want) && strings.Contains(e, "resolves outside") {
			recorded = true
		}
	}
	if !recorded {
		t.Errorf("no collect error for the skipped file; errors: %v", snap.Errors)
	}
}

// A link that stays inside the project is normal and is still read.
func TestInstructionSymlinkInsideProjectRead(t *testing.T) {
	f := newFixture(t)
	proj := filepath.Join(f.home, "work", "app")
	target := filepath.Join(proj, "docs", "rules.md")
	f.write(target, "# project rules\n")
	if err := os.Symlink(target, filepath.Join(proj, "CLAUDE.md")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	snap := f.collect(proj)

	want := filepath.Join(proj, "CLAUDE.md")
	for _, r := range snap.InstructionFiles {
		if r.Path == want {
			if r.SHA256 == "" || r.SizeBytes == 0 {
				t.Errorf("inside link was not read: %+v", r)
			}
			return
		}
	}
	t.Errorf("no row for %s", want)
}

// Home-scope dotfile users symlink ~/.claude/CLAUDE.md on purpose; those reads
// are operator-owned and must keep working.
func TestHomeInstructionSymlinkStillRead(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.home, "dotfiles", "CLAUDE.md")
	f.write(target, "# home rules\n")
	link := filepath.Join(f.cfg, "CLAUDE.md")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	snap := f.collect()

	for _, r := range snap.InstructionFiles {
		if r.Path == link {
			if r.SHA256 == "" {
				t.Errorf("home-scope symlink was not read: %+v", r)
			}
			return
		}
	}
	t.Errorf("no row for %s", link)
}

// A plugin manifest's mcpServers can be a path. A "../.." value must not make
// the collector ingest a config file outside the plugin.
func TestPluginManifestPathEscapeNotRead(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "plugins", "cache", "m", "p", "deadbeef")
	outside := filepath.Join(f.home, "plugins", "cache", "outside.json")
	f.write(outside, `{"mcpServers":{"escaped":{"command":"evil-cmd"}}}`)
	f.write(filepath.Join(root, ".claude-plugin", "plugin.json"),
		`{"name":"p","mcpServers":"../../../outside.json"}`)
	f.write(filepath.Join(root, "hooks", "hooks.json"), `{"hooks":{}}`)
	f.write(filepath.Join(f.cfg, "plugins", "installed_plugins.json"),
		`{"version":2,"plugins":{"p@m":[{"scope":"user","installPath":"`+root+`","version":"1"}]}}`)

	snap := f.collect()
	for _, m := range snap.MCPServers {
		if m.Name == "escaped" {
			t.Errorf("plugin manifest escaped its root: %+v", m)
		}
	}
	recorded := false
	for _, e := range snap.Errors {
		if strings.Contains(e, "points outside") {
			recorded = true
		}
	}
	if !recorded {
		t.Errorf("no collect error for the escaped manifest; errors: %v", snap.Errors)
	}
}

// `agentreach scan .` passes a relative project directory. A file inside it
// must not be reported as escaping, whether its path is relative or absolute,
// and a link out of it must still be caught.
func TestInstructionEscapesRelativeRoot(t *testing.T) {
	proj := t.TempDir()
	if err := os.WriteFile(filepath.Join(proj, "CLAUDE.md"), []byte("# rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(outside, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(proj, "AGENTS.md")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	t.Chdir(proj)

	for _, p := range []string{"CLAUDE.md", filepath.Join(proj, "CLAUDE.md")} {
		if target, escaped := instructionEscapes(p, "."); escaped {
			t.Errorf("%s reported as escaping to %s", p, target)
		}
	}
	if _, escaped := instructionEscapes("AGENTS.md", "."); !escaped {
		t.Error("out-of-tree link under a relative root was not caught")
	}
}
