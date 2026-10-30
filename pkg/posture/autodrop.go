package posture

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Auto mode drops broad allow rules on entry (permission-modes: "Blanket
// Bash(*) ... Wildcarded interpreters like Bash(python*) ... Package-manager
// run commands"). The docs give examples, not the list, so agentreach reads the
// list from the Claude Code that is installed, every collection, and falls
// back to the list read from 2.1.312 when it cannot. The source used is on
// agentreach_agent (auto_mode_drop_source, auto_mode_drop_reason).

// builtinAutoDropVersion and builtinAutoDrop are the fallback, read from
// Claude Code 2.1.312 (isDangerousBashPermission). The weekly
// claude-code-drift workflow fails when the latest release differs.
const builtinAutoDropVersion = "2.1.312"

var builtinAutoDrop = []string{
	"python", "python3", "python2", "node", "deno", "tsx", "ruby", "perl", "php", "lua",
	"npx", "bunx", "npm run", "yarn run", "pnpm run", "bun run", "bash", "sh", "ssh",
	"zsh", "fish", "eval", "exec", "env", "xargs", "sudo",
}

// autoDropList is the command list in use and where it came from.
type autoDropList struct {
	Commands []string
	Source   string // binary | built_in | pinned
	Reason   string
}

// The anchor is a run of entries every known release has kept together;
// the array literal around it is the list. Minified identifiers change per
// build, so the code is found by shape, never by name.
var (
	autoDropAnchor = []byte(`"npm run","yarn run"`)
	// The matcher compares a rule with `${c}:*` and `${c} *`; if that shape
	// is gone the matching may have changed too.
	autoDropMatcher = regexp.MustCompile("===`\\$\\{(\\w+)\\}:\\*`\\|\\|\\w+===`\\$\\{(\\w+)\\} \\*`")
	jsIdent         = regexp.MustCompile(`[A-Za-z_$][\w$]*$`)
	commandWord     = regexp.MustCompile(`^[a-z0-9][a-z0-9 ._+-]*$`)
)

var autoDropCache struct {
	sync.Mutex
	m map[string]autoDropList
}

// loadAutoDrop reads the list from the Claude Code program at path (the
// launcher, a native binary or cli.js). It reads bytes only; nothing runs.
// Results are cached in memory per path, size and modification time.
func loadAutoDrop(path, version string) autoDropList {
	fallback := func(why string) autoDropList {
		return autoDropList{Commands: builtinAutoDrop, Source: "built_in",
			Reason: why + "; using the list read from Claude Code " + builtinAutoDropVersion}
	}
	if path == "" {
		return fallback("no claude binary found")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fallback("could not resolve " + path)
	}
	fi, err := os.Stat(real)
	if err != nil || !fi.Mode().IsRegular() {
		return fallback("could not read " + real)
	}
	key := fmt.Sprintf("%s|%d|%d", real, fi.Size(), fi.ModTime().UnixNano())
	autoDropCache.Lock()
	defer autoDropCache.Unlock()
	if l, ok := autoDropCache.m[key]; ok {
		return l
	}
	l := fallback("")
	cmds, matcher, err := extractAutoDropFile(real)
	switch {
	case err != nil:
		l = fallback("could not read the list from Claude Code " + version + " (" + err.Error() + ")")
	case !matcher:
		l = fallback("read a list from Claude Code " + version + " but not the matcher agentreach models, so the matching may have changed")
	default:
		l = autoDropList{Commands: cmds, Source: "binary",
			Reason: "read from Claude Code " + version + " at " + real}
	}
	if autoDropCache.m == nil {
		autoDropCache.m = map[string]autoDropList{}
	}
	autoDropCache.m[key] = l
	return l
}

// extractAutoDropFile streams the file and parses the list around the
// first anchor that yields a valid list.
func extractAutoDropFile(path string) ([]string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	const chunk, overlap, window = 8 << 20, 64 << 10, 16 << 10
	buf := make([]byte, chunk+overlap)
	var keep int
	var off int64
	var cmds []string
	matcher := false
	for {
		n, rerr := io.ReadFull(f, buf[keep:])
		data := buf[:keep+n]
		if !matcher && autoDropMatcher.Match(data) {
			matcher = true
		}
		if cmds == nil {
			for i := 0; ; {
				j := bytes.Index(data[i:], autoDropAnchor)
				if j < 0 {
					break
				}
				at := i + j
				lo, hi := max(0, at-window), min(len(data), at+window)
				if got, ok := parseAutoDrop(data[lo:hi], at-lo); ok {
					cmds = got
					break
				}
				i = at + len(autoDropAnchor)
			}
		}
		if cmds != nil && matcher {
			return cmds, true, nil
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return nil, false, rerr
		}
		keep = min(overlap, len(data))
		copy(buf, data[len(data)-keep:])
		off += int64(len(data) - keep)
	}
	if cmds == nil {
		return nil, false, errors.New("list not found")
	}
	return cmds, matcher, nil
}

// parseAutoDrop parses the array literal around data[at], then the arrays
// defined soon after that spread it ("X=[...Base,"zsh",...]"), and returns
// the union: the list the matcher is called with.
func parseAutoDrop(data []byte, at int) ([]string, bool) {
	open := bytes.LastIndexByte(data[:at], '[')
	if open < 0 {
		return nil, false
	}
	elems, end, ok := parseJSArray(data, open)
	if !ok {
		return nil, false
	}
	set := map[string]bool{}
	for _, e := range elems {
		if strings.HasPrefix(e, `"`) {
			set[strings.Trim(e, `"`)] = true
		}
	}
	// Follow arrays that spread this one, up to three levels.
	name := ""
	// #nosec G602 -- open is a bytes.Index result into data, so
	// 0 <= open < len(data) and both slices below are in bounds.
	if open > 0 && data[open-1] == '=' {
		name = jsIdent.FindString(string(data[max(0, open-64) : open-1]))
	}
	for depth := 0; depth < 3 && name != ""; depth++ {
		next := ""
		rest := data[end:min(len(data), end+4096)]
		k := bytes.Index(rest, []byte("=[..."+name+","))
		if k < 0 {
			k = bytes.Index(rest, []byte("=[..."+name+"]"))
		}
		if k < 0 {
			break
		}
		start := end + k + 1
		more, e2, ok := parseJSArray(data, start)
		if !ok {
			break
		}
		for _, e := range more {
			if strings.HasPrefix(e, `"`) {
				set[strings.Trim(e, `"`)] = true
			}
		}
		next = jsIdent.FindString(string(data[max(0, end+k-64) : end+k]))
		end = e2
		name = next
	}
	var out []string
	for s := range set {
		if !commandWord.MatchString(s) {
			return nil, false
		}
		out = append(out, s)
	}
	sort.Strings(out)
	// Sanity: the documented examples must be on it.
	has := map[string]bool{}
	for _, s := range out {
		has[s] = true
	}
	if len(out) < 8 || len(out) > 300 || !has["npm run"] || !has["python"] || !has["bash"] {
		return nil, false
	}
	return out, true
}

// parseJSArray reads a minified array literal of string literals and
// spreads starting at data[open] == '['. It returns the elements and the
// index after the closing bracket; anything else in it fails the parse.
func parseJSArray(data []byte, open int) ([]string, int, bool) {
	var elems []string
	i := open + 1
	for i < len(data) {
		switch {
		case data[i] == ']':
			return elems, i + 1, true
		case data[i] == ',':
			i++
		case data[i] == '"':
			j := bytes.IndexByte(data[i+1:], '"')
			if j < 0 || bytes.IndexByte(data[i+1:i+1+j], '\\') >= 0 {
				return nil, 0, false
			}
			elems = append(elems, string(data[i:i+j+2]))
			i += j + 2
		case bytes.HasPrefix(data[i:], []byte("...")):
			j := i + 3
			if j < len(data) && data[j] == '[' {
				_, e, ok := parseJSArray(data, j)
				if !ok {
					return nil, 0, false
				}
				i = e
				continue
			}
			for j < len(data) && (data[j] == '_' || data[j] == '$' || data[j] >= '0' && data[j] <= '9' || data[j]|0x20 >= 'a' && data[j]|0x20 <= 'z') {
				j++
			}
			elems = append(elems, "..."+string(data[i+3:j]))
			i = j
		default:
			return nil, 0, false
		}
	}
	return nil, 0, false
}
