package posture

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Managed-tier resolution.
//
// Source: https://code.claude.com/docs/en/managed-settings, "How Claude Code
// combines managed sources":
//
//   "Claude Code checks the sources in this order, highest priority first:
//    1. Remote settings ... 2. MDM or OS-level policies: the macOS plist or
//    the HKLM registry key 3. Managed settings files, managed-settings.d/*.json
//    and managed-settings.json merged together 4. The HKCU registry"
//
//   "first-wins, the default: Claude Code uses the highest-ranked source that
//    delivers at least one policy key and ignores the rest rather than merging
//    them, apart from the keys in Keys read from every admin source."
//
//   "merge: Claude Code applies every admin source that delivers a policy key
//    and combines them by kind of key: on most keys the higher-ranked source's
//    value applies, lists union, and locks take the strictest value."
//
//   "Policy key: any settings key other than the two control keys,
//    wslInheritsWindowsSettings and managedSourcesBehavior."
//
// "Split a file-based policy across teams": "Claude Code merges
// managed-settings.json first, then every *.json file in the directory in
// alphabetical order ... Single values: the later file's value replaces the
// earlier one. Lists: the two lists combine, with duplicates removed. Nested
// blocks: the two blocks merge key by key." Hidden files and files not ending
// in .json are ignored.
//
// The HKCU registry (Windows only, user-writable) is not read: this collector
// runs on macOS and Linux.

// managedSource is one admin document in rank order.
type managedSource struct {
	Name string // remote | plist | file | drop-ins | file + drop-ins
	Path string // file or directory the document came from
	Doc  map[string]any
	Err  error // read or parse failure; Doc is nil
}

// managedControlKeys are not policy keys.
var managedControlKeys = map[string]bool{"wslInheritsWindowsSettings": true, "managedSourcesBehavior": true}

// managedCrossSourceLocks are read from every admin source: a true in any
// source turns the lock on ("Keys read from every admin source").
var managedCrossSourceLocks = [][]string{
	{"sandbox", "network", "allowManagedDomainsOnly"},
	{"sandbox", "filesystem", "allowManagedReadPathsOnly"},
	{"allowAllClaudeAiMcps"},
	{"allowManagedMcpServersOnly"},
}

func managedSystemDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	case "windows":
		return `C:\Program Files\ClaudeCode`
	default:
		return "/etc/claude-code"
	}
}

func managedPlistPath() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	return "/Library/Managed Preferences/com.anthropic.claudecode.plist"
}

// hasPolicyKey reports whether a document "delivers at least one policy key":
// any key other than the control keys whose value is not null.
func hasPolicyKey(doc map[string]any) bool {
	for k, v := range doc {
		if managedControlKeys[k] || v == nil {
			continue
		}
		return true
	}
	return false
}

// mergeUnion merges over onto base with the drop-in rules: scalars from over
// replace, lists union with duplicates removed, nested objects merge key by key.
func mergeUnion(base, over map[string]any) map[string]any {
	if base == nil && over == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		switch ov := v.(type) {
		case map[string]any:
			if bm, ok := out[k].(map[string]any); ok {
				out[k] = mergeUnion(bm, ov)
				continue
			}
		case []any:
			if bl, ok := out[k].([]any); ok {
				out[k] = unionList(bl, ov)
				continue
			}
		}
		out[k] = v
	}
	return out
}

func unionList(a, b []any) []any {
	seen := map[string]bool{}
	out := make([]any, 0, len(a)+len(b))
	for _, l := range [][]any{a, b} {
		for _, e := range l {
			key, _ := json.Marshal(e)
			if seen[string(key)] {
				continue
			}
			seen[string(key)] = true
			out = append(out, e)
		}
	}
	return out
}

// readPlistJSON converts a macOS plist to JSON with plutil (read-only) and
// decodes it. Returns nil, nil when the file is absent.
func readPlistJSON(ctx context.Context, path string) (map[string]any, error) {
	if path == "" || !fileExists(path) {
		return nil, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// #nosec G204 -- plutil with fixed arguments; the path comes from
	// Options.PlistPath (the managed-preferences location), never from
	// repository content.
	out, err := exec.CommandContext(cctx, "plutil", "-convert", "json", "-o", "-", path).Output()
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// readManagedFiles merges managed-settings.json and managed-settings.d/*.json
// in the documented order. The returned name tells which parts existed.
func readManagedFiles(dir string) (name, path string, doc map[string]any, err error) {
	main := filepath.Join(dir, "managed-settings.json")
	dropDir := filepath.Join(dir, "managed-settings.d")
	var parts []string
	if fileExists(main) {
		m, e := readJSON(main)
		if e != nil {
			return "file", main, nil, e
		}
		if m == nil {
			m = map[string]any{} // "An empty managed settings file counts as {}."
		}
		doc = m
		parts = append(parts, "file")
	}
	if entries, e := os.ReadDir(dropDir); e == nil {
		names := []string{}
		for _, en := range entries {
			n := en.Name()
			if en.IsDir() || strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") {
				continue
			}
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			p := filepath.Join(dropDir, n)
			m, e := readJSON(p)
			if e != nil {
				return "drop-ins", p, nil, e
			}
			if doc == nil {
				doc = map[string]any{}
			}
			doc = mergeUnion(doc, m)
		}
		if len(names) > 0 {
			parts = append(parts, "drop-ins")
		}
	}
	if doc == nil {
		return "", "", nil, nil
	}
	return strings.Join(parts, " + "), main, doc, nil
}

// loadManaged ranks the admin sources, selects or merges them per
// managedSourcesBehavior, applies the cross-source locks, and records which
// source won. It fills c.managed, c.managedSources, c.managedSourceName and
// c.managedBehavior, and appends read failures to snap.Errors.
func (c *ccCollector) loadManaged(ctx context.Context) {
	var sources []managedSource

	remote, err := readJSON(c.remotePath)
	if err != nil {
		sources = append(sources, managedSource{Name: "remote", Path: c.remotePath, Err: err})
	} else if remote != nil {
		sources = append(sources, managedSource{Name: "remote", Path: c.remotePath, Doc: remote})
	}

	if pp := c.plistPath; pp != "" {
		if m, err := readPlistJSON(ctx, pp); err != nil {
			sources = append(sources, managedSource{Name: "plist", Path: pp, Err: err})
		} else if m != nil {
			sources = append(sources, managedSource{Name: "plist", Path: pp, Doc: m})
		}
	}

	if name, path, doc, err := readManagedFiles(c.managedDir); err != nil {
		sources = append(sources, managedSource{Name: name, Path: path, Err: err})
	} else if doc != nil {
		sources = append(sources, managedSource{Name: name, Path: path, Doc: doc})
	}

	c.managedSources = sources

	// A document that exists but cannot be read still counts as present and,
	// for a malformed managed file, Claude Code refuses to start.
	for _, s := range sources {
		if s.Err != nil {
			c.snap.Errors = append(c.snap.Errors, "managed settings ("+s.Name+"): "+s.Path+": "+s.Err.Error()+
				"; Claude Code exits at startup when a managed settings document cannot be parsed")
		}
	}

	// managedSourcesBehavior is a delivery control; read it from the
	// highest-ranked source that sets it.
	c.managedBehavior = "first-wins"
	for _, s := range sources {
		if b := getString(s.Doc, "managedSourcesBehavior"); b != "" {
			c.managedBehavior = b
			break
		}
	}

	var selected []string
	defer func() { c.managedSelected = selected }()
	switch c.managedBehavior {
	case "merge":
		// Higher-ranked source wins on scalars, lists union: merge from the
		// lowest rank upward so the highest is applied last.
		var doc map[string]any
		for i := len(sources) - 1; i >= 0; i-- {
			s := sources[i]
			if s.Doc == nil || !hasPolicyKey(s.Doc) {
				continue
			}
			doc = mergeUnion(doc, s.Doc)
			selected = append([]string{s.Name}, selected...)
		}
		c.managed = doc
	default:
		for _, s := range sources {
			if s.Doc == nil || !hasPolicyKey(s.Doc) {
				continue
			}
			c.managed = mergeUnion(nil, s.Doc)
			selected = []string{s.Name}
			break
		}
	}

	// Cross-source locks: a true in any admin source turns the lock on, even
	// when that source was not selected.
	for _, s := range sources {
		if s.Doc == nil {
			continue
		}
		for _, keyPath := range managedCrossSourceLocks {
			if b := getBool(s.Doc, keyPath...); b != nil && *b {
				if c.managed == nil {
					c.managed = map[string]any{}
				}
				setPath(c.managed, keyPath, true)
			}
		}
	}

	switch {
	case len(selected) == 0:
		c.managedSourceName = ""
	case c.managedBehavior == "merge" && len(selected) > 1:
		c.managedSourceName = strings.Join(selected, " + ") + ", merged"
	default:
		c.managedSourceName = selected[0]
	}
}

// managedApplies reports whether a given source contributes to the effective
// managed document.
func (c *ccCollector) managedApplies(name string) bool {
	for _, s := range c.managedSelected {
		if s == name {
			return true
		}
	}
	return false
}

// setPath sets a nested key, creating intermediate maps.
func setPath(m map[string]any, keys []string, v any) {
	for i, k := range keys {
		if i == len(keys)-1 {
			m[k] = v
			return
		}
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
}
