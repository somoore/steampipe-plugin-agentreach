package posture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Starting surface. The permission mode a Claude Code session starts in
// depends on how it is started (permission-modes, "Which mode a session
// starts in"): a terminal session takes the flag, then defaultMode, then the
// built-in default (auto from 2.1.283); `claude -p` and the Agent SDK
// start in default, and from 2.1.302 deny calls that need approval unless a
// rule allows them; the VS Code extension takes
// claudeCode.initialPermissionMode, then the mode last picked, then
// defaultMode from managed or user settings, then the built-in default, and
// never reads project settings for it. agentreach's gates model the terminal;
// surface_modes records the others.

const (
	SurfaceTerminal = "terminal"
	SurfacePrintSDK = "print_or_sdk"
	SurfaceVSCode   = "vscode"
	SurfaceDesktop  = "desktop"
)

// surfaceFromEntrypoint maps CLAUDE_CODE_ENTRYPOINT, which Claude Code sets
// in the processes it starts, to a surface.
func surfaceFromEntrypoint(e string) string {
	switch {
	case e == "":
		return ""
	case e == "cli":
		return SurfaceTerminal
	case strings.HasPrefix(e, "sdk"):
		return SurfacePrintSDK
	case strings.Contains(e, "vscode"):
		return SurfaceVSCode
	case strings.Contains(e, "desktop"):
		return SurfaceDesktop
	}
	return e
}

// vscodeSettingsPath is the VS Code user settings file for home.
func vscodeSettingsPath(home, goos string) string {
	if goos == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "settings.json")
	}
	return filepath.Join(home, ".config", "Code", "User", "settings.json")
}

// readJSONC reads a JSON-with-comments file such as VS Code's settings.
func readJSONC(p string) (map[string]any, error) {
	b, err := readFileLimited(p)
	if err != nil {
		return nil, err
	}
	return parseJSONBytes(stripJSONC(b))
}

// stripJSONC removes // and /* */ comments outside strings and commas
// before a closing bracket.
func stripJSONC(b []byte) []byte {
	var out []byte
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		ch := b[i]
		if inStr {
			out = append(out, ch)
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		switch {
		case ch == '"':
			inStr = true
			out = append(out, ch)
		case ch == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case ch == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		case ch == ']' || ch == '}':
			j := len(out) - 1
			for j >= 0 && (out[j] == ' ' || out[j] == '\t' || out[j] == '\n' || out[j] == '\r') {
				j--
			}
			if j >= 0 && out[j] == ',' {
				out = append(out[:j], out[j+1:]...)
			}
			out = append(out, ch)
		default:
			out = append(out, ch)
		}
	}
	return out
}

// computeSurfaces fills the agent's surface fields. It runs after the
// terminal mode is known.
func (c *ccCollector) computeSurfaces(a *Agent) {
	a.StartSurface, a.StartSurfaceSource = SurfaceTerminal, "assumed"
	entry := c.opts.Entrypoint
	if entry == "" && c.opts.Home == "" {
		entry = os.Getenv("CLAUDE_CODE_ENTRYPOINT")
	}
	if s := surfaceFromEntrypoint(entry); s != "" {
		a.StartSurface, a.StartSurfaceSource = s, "CLAUDE_CODE_ENTRYPOINT="+entry
	}

	modes := map[string]string{SurfaceTerminal: c.effMode}

	// claude -p and the Agent SDK: the flag (for claude -p) and defaultMode
	// apply as in a terminal; the built-in default is default, which
	// denies calls that need approval.
	switch c.effModeSource {
	case "built_in", "unknown", "":
		modes[SurfacePrintSDK] = "default (calls that need approval are denied unless a rule allows them)"
	default:
		modes[SurfacePrintSDK] = c.effMode + " (from " + c.effModeSource + "; an SDK launcher can pass its own mode and settings)"
	}

	// VS Code: initialPermissionMode, else the mode last picked (not
	// recorded where agentreach can read it), else managed or user defaultMode,
	// else the built-in default.
	vs := vscodeSettingsPath(c.home, c.opts.goos())
	if m, err := readJSONC(vs); err == nil {
		a.VscodeInitialPermissionMode, _ = m["claudeCode.initialPermissionMode"].(string)
		if w, _ := m["claudeCode.claudeProcessWrapper"].(string); w != "" {
			a.VscodeProcessWrapper = true
		}
	}
	fallback := c.effMode
	if c.effModeSource == "launch_flag" {
		fallback, _ = c.effectiveMode(c.version) // a shell alias's flag does not reach the extension
	}
	switch {
	case a.VscodeInitialPermissionMode != "":
		v := a.VscodeInitialPermissionMode
		if v == "manual" {
			v = "default"
		}
		modes[SurfaceVSCode] = v
	case a.VscodeProcessWrapper:
		modes[SurfaceVSCode] = "the mode last picked in VS Code, else default (claudeProcessWrapper is set)"
	default:
		modes[SurfaceVSCode] = "the mode last picked in VS Code, else " + fallback
	}
	a.SurfaceModes = modes
}

func parseJSONBytes(b []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
