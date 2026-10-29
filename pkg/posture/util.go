package posture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// expandHome replaces a leading ~ with home.
func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// fileExists reports whether p exists (file or dir).
func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// readJSON parses a JSON file into a generic map. Missing files return nil, nil.
func readJSON(p string) (map[string]any, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// flatten walks a JSON object and emits dotted leaf keys. Arrays are kept
// whole as values so list-valued settings (permissions.allow) stay queryable
// as JSON rather than exploding into index keys.
func flatten(prefix string, v any, out map[string]any) {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 0 && prefix != "" {
			out[prefix] = t
			return
		}
		for k, child := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flatten(key, child, out)
		}
	default:
		out[prefix] = v
	}
}

// writableBy summarises the broadest class that can write the file.
func writableBy(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return ""
	}
	m := fi.Mode().Perm()
	switch {
	case m&0o002 != 0:
		return "others"
	case m&0o020 != 0:
		return "group"
	default:
		return "owner"
	}
}

// gitCmd builds a read-only git invocation. agentreach runs git inside
// repositories it did not create, so repository config must not make git run
// a program or write: no optional locks (no index refresh), no fsmonitor
// daemon, no signature checks that would run gpg.program, no pager, and no
// credential or terminal prompts. Callers use only plumbing-like commands
// that apply no clean/smudge filters (log, ls-files, ls-tree, rev-parse,
// config, remote get-url).
func gitCmd(args ...string) *exec.Cmd {
	base := []string{"--no-optional-locks",
		"-c", "core.fsmonitor=false",
		"-c", "log.showSignature=false",
		"-c", "core.pager=cat",
		"-c", "credential.helper=",
	}
	cmd := exec.Command("git", append(base, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat", "GIT_OPTIONAL_LOCKS=0")
	return cmd
}

// gitRoot returns the repository root containing dir, or "".
func gitRoot(dir string) string {
	out, err := gitCmd("-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// gitTracked reports whether path is tracked by the repository that contains it.
func gitTracked(path string) bool {
	dir := filepath.Dir(path)
	err := gitCmd("-C", dir, "ls-files", "--error-unmatch", "--", path).Run()
	return err == nil
}

// sha256File hashes a file's contents.
func sha256File(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var (
	// secretValuePattern matches well-known credential prefixes. Only the
	// boolean result is ever stored; values are never retained.
	secretValuePattern = regexp.MustCompile(`(?i)^(sk-[A-Za-z0-9_-]{10,}|sk-ant-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abp]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,}|tpuf_[A-Za-z0-9]{10,}|msy_[A-Za-z0-9]{10,}|glpat-[A-Za-z0-9_-]{15,}|npm_[A-Za-z0-9]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)`)
	secretKeyPattern   = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd|credential|auth)`)
	// identifierKeyPattern names a value that says who, not a credential:
	// an OAuth client ID or a user name is not secret on its own, even
	// when the name also says auth (TAILSCALE_OAUTH_CLIENT_ID). A known
	// credential shape (AWS_ACCESS_KEY_ID's AKIA...) is still caught by
	// secretValuePattern first.
	identifierKeyPattern = regexp.MustCompile(`(?i)(?:^|[_.-])(?:id|client[_-]?id|user(?:name)?|e?mail|account)$|[a-z](?:Id|ID)$`)
	authSchemePattern    = regexp.MustCompile(`(?i)^(?:bearer|basic|token|apikey)\s+(.+)$`)
	// urlUserinfoPattern matches scheme://user:password@host.
	urlUserinfoPattern = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@`)
	placeholderPattern = regexp.MustCompile(`(?i)^(\$\{?[A-Z_]+\}?|<.*>|your[_-]|xxx|changeme|example|todo|redacted|\*+)`)
)

// looksLikeSecret reports whether an env value appears to be a real credential.
func looksLikeSecret(key, value string) bool {
	v := strings.TrimSpace(value)
	// HTTP auth headers carry a scheme prefix; judge the credential part.
	if m := authSchemePattern.FindStringSubmatch(v); m != nil {
		v = strings.TrimSpace(m[1])
	}
	if v == "" || placeholderPattern.MatchString(v) {
		return false
	}
	if secretValuePattern.MatchString(v) || urlUserinfoPattern.MatchString(strings.ToLower(v)) {
		return true
	}
	// Paths and URLs are not credentials, but an opaque token may contain
	// "/" and "+" (AWS secret access keys do), so only shape excludes them.
	pathLike := strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "~") ||
		strings.Contains(v, "://") || strings.ContainsAny(v, " \\")
	return secretKeyPattern.MatchString(key) && !identifierKeyPattern.MatchString(key) && len(v) >= 16 && !pathLike
}

// hiddenUnicodeCount counts zero-width, bidi-override and tag characters that
// can hide instructions from a human reviewer.
func hiddenUnicodeCount(b []byte) int {
	n := 0
	prev := rune(0)
	for i, r := range string(b) {
		cur := r
		switch {
		case r == 0xFEFF && i == 0: // a leading byte-order mark is an encoding marker, not hidden text
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF: // zero-width
			n++
		case r >= 0xE0100 && r <= 0xE01EF: // supplementary variation selectors (can encode bytes)
			n++
		case r >= 0xFE00 && r <= 0xFE0F:
			// A selector after an emoji or symbol is normal presentation;
			// after a letter or another selector it is hiding something.
			if (prev >= 'A' && prev <= 'Z') || (prev >= 'a' && prev <= 'z') || (prev >= 0xFE00 && prev <= 0xFE0F) {
				n++
			}
		case r == 0x115F || r == 0x1160 || r == 0x3164 || r == 0xFFA0: // Hangul fillers render as blank
			n++
		case r >= 0x202A && r <= 0x202E: // bidi embeddings/overrides
			n++
		case r >= 0x2066 && r <= 0x2069: // bidi isolates
			n++
		case r >= 0xE0000 && r <= 0xE007F: // tag characters
			n++
		case r == 0x00AD || r == 0x034F || r == 0x180E: // soft hyphen, CGJ, mongolian vowel separator
			n++
		case unicode.Is(unicode.Cf, r) && r != '\n' && r != '\r' && r != '\t':
			n++
		}
		prev = cur
	}
	return n
}

var (
	htmlCommentPattern = regexp.MustCompile(`(?s)<!--.*?-->`)
	// includePattern matches CLAUDE.md @path imports at the start of a line:
	// @~/x, @/x, @./x, @docs/x, @README.md. Bare handles like @alice are not
	// imports and are ignored.
	// Imports also work mid-line ("see @docs/rules.md"), so a preceding
	// space counts; an address like me@example.com does not.
	includePattern = regexp.MustCompile(`(?m)(?:^|\s)@(?:[~/.]|[A-Za-z0-9_.-]+/|[A-Za-z0-9_-]+\.(?:md|txt|json|yaml|yml|toml|mdc))`)
	urlPattern     = regexp.MustCompile(`https?://[^\s)>\]"']+`)
)

// launcherType classifies how an MCP server is started.
func launcherType(command string, args []string, url string) string {
	if url != "" {
		return "remote"
	}
	base := filepath.Base(command)
	switch base {
	case "npx", "bunx", "pnpx":
		return "npx"
	case "uv":
		// "uv run <script.py>" runs a local file; "uv tool run" and "uvx"
		// fetch from a registry.
		if len(args) > 0 && args[0] == "run" {
			skip := false
			for _, a := range args[1:] {
				if skip {
					skip = false
					continue
				}
				if strings.HasPrefix(a, "-") {
					switch a {
					case "--with", "--from", "--python", "-p", "--directory", "--project", "--env-file", "--with-requirements":
						skip = true // flag takes a value
					}
					continue
				}
				if strings.Contains(a, "/") || strings.HasSuffix(a, ".py") {
					return "python"
				}
				break
			}
		}
		return "uvx"
	case "uvx", "pipx":
		return "uvx"
	case "docker", "podman":
		return "docker"
	case "node", "bun", "deno":
		return "node"
	case "python", "python3":
		return "python"
	case "sh", "bash", "zsh", "cmd", "powershell", "pwsh":
		return "shell"
	}
	return "binary"
}

// pinned reports whether an npx/uvx launcher names an exact package version.
// Returns nil when the launcher type has no notion of pinning.
func pinned(lt string, args []string) *bool {
	switch lt {
	case "npx", "uvx":
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			// first positional is the package spec
			at := strings.LastIndex(a, "@")
			v := at > 0 && at < len(a)-1 && a[at+1] != '/'
			if v {
				// A dist-tag such as @latest or @next is not a pin.
				tag := a[at+1:]
				v = tag[0] >= '0' && tag[0] <= '9' || (tag[0] == 'v' && len(tag) > 1 && tag[1] >= '0' && tag[1] <= '9')
			}
			if lt == "uvx" {
				v = v || strings.Contains(a, "==")
			}
			return &v
		}
		f := false
		return &f
	}
	return nil
}

// toStringSlice converts a JSON array to []string, dropping non-strings.
func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// getMap safely digs a nested object.
func getMap(m map[string]any, keys ...string) map[string]any {
	cur := m
	for _, k := range keys {
		if cur == nil {
			return nil
		}
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

// getString safely digs a nested string.
func getString(m map[string]any, keys ...string) string {
	if len(keys) == 0 {
		return ""
	}
	parent := getMap(m, keys[:len(keys)-1]...)
	if parent == nil {
		return ""
	}
	s, _ := parent[keys[len(keys)-1]].(string)
	return s
}

// getBool safely digs a nested bool; nil when absent.
func getBool(m map[string]any, keys ...string) *bool {
	parent := getMap(m, keys[:len(keys)-1]...)
	if parent == nil {
		return nil
	}
	b, ok := parent[keys[len(keys)-1]].(bool)
	if !ok {
		return nil
	}
	return &b
}
