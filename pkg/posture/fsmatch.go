package posture

import (
	"path/filepath"
	"strings"
)

// resolveSandboxPath resolves a sandbox.filesystem pattern the way Claude
// Code does: ~ is home, absolute stays absolute, relative is anchored at the
// settings file's directory (project root for project files, ~/.claude for
// user settings).
func resolveSandboxPath(pattern, home, anchor string) string {
	p := expandHome(pattern, home)
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(anchor, p))
}

// resolvePermissionPath resolves a Read/Edit rule specifier: //abs, ~/home,
// /anchored-at-settings-source, or plain cwd-relative (left as <cwd>/...).
func resolvePermissionPath(spec, home, anchor string) string {
	switch {
	case strings.HasPrefix(spec, "//"):
		return filepath.Clean(spec[1:])
	case strings.HasPrefix(spec, "~/") || spec == "~":
		return filepath.Clean(expandHome(spec, home))
	case strings.HasPrefix(spec, "/"):
		return filepath.Clean(filepath.Join(anchor, spec))
	case strings.HasPrefix(spec, "./"):
		return "<cwd>/" + filepath.Clean(spec[2:])
	default:
		return "<cwd>/" + spec
	}
}

// resolvePermissionRule resolves a Read/Edit rule for its rule type. Deny
// and ask rules written as a bare filename or a single directory segment
// match at any depth under the current directory, allow rules do not.
//
// Source: https://code.claude.com/docs/en/permissions, "How deep a pattern
// matches": "Bare filenames follow gitignore semantics and match at any
// depth, so Read(.env) and Read(**/.env) are equivalent" and "Deny and ask
// rules: Read(secrets/**) matches a directory named secrets at any depth
// under the current directory". Allow rules: "Edit(src/**) matches only
// <cwd>/src and the files under it."
func resolvePermissionRule(spec, ruleType, home, anchor string) string {
	r := resolvePermissionPath(spec, home, anchor)
	if !strings.HasPrefix(r, "<cwd>/") || (ruleType != "deny" && ruleType != "ask") {
		return r
	}
	rel := strings.TrimPrefix(r, "<cwd>/")
	if strings.HasPrefix(rel, "**/") {
		return r
	}
	segs := strings.Split(rel, "/")
	switch {
	case len(segs) == 1:
		return "<cwd>/**/" + rel
	case len(segs) == 2 && segs[1] == "**":
		return "<cwd>/**/" + rel
	}
	return r
}

// withCwd substitutes the session working directory into a <cwd> pattern.
// Returns "" when the pattern needs a cwd and none is known.
func withCwd(pattern, cwd string) string {
	if !strings.HasPrefix(pattern, "<cwd>") {
		return pattern
	}
	if cwd == "" {
		return ""
	}
	return cwd + strings.TrimPrefix(pattern, "<cwd>")
}

// covers reports whether a resolved rule pattern covers path. A pattern
// without wildcards covers itself and everything beneath it (Claude treats a
// directory rule as a prefix). Wildcards: * within a segment, ** across
// segments.
func covers(pattern, path string) bool {
	if pattern == "" || strings.HasPrefix(pattern, "<cwd>") {
		return false
	}
	pattern = filepath.Clean(pattern)
	path = filepath.Clean(path)
	if !strings.ContainsAny(pattern, "*?[") {
		return path == pattern || strings.HasPrefix(path, pattern+string(filepath.Separator))
	}
	return globMatch(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func globMatch(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(segs); i++ {
				if globMatch(pat[1:], segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		ok, err := filepath.Match(pat[0], segs[0])
		if err != nil || !ok {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	// Pattern exhausted. A match on a prefix of the path still counts: a
	// rule for a directory (deny ~/.ssh/*) also covers deeper files.
	return true
}
