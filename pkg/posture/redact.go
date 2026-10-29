package posture

import (
	"net/url"
	"regexp"
	"strings"
)

// Redaction. Every free-text field that can carry a credential (MCP args and
// URLs, hook commands and URLs, permission rule text, settings strings) goes
// through scrubText or scrubURL before it reaches a Snapshot, so JSON
// exports, SQL tables and dashboards all see the same redacted value.
// Secret-shaped spans are replaced with redactedMark; the rest of the text is
// kept so a reviewer can still see what runs.

const redactedMark = "<redacted>"

var (
	// tokenSplit keeps separators so the text can be rebuilt exactly.
	tokenSplit = regexp.MustCompile(`[^\s"'=,;]+`)
	// authHeaderPattern catches "Authorization: Bearer x", "Bearer x",
	// "token x" and "-u user:pass" forms inside a command line.
	authHeaderPattern = regexp.MustCompile(`(?i)\b(bearer|basic|token|apikey)(\s+)([A-Za-z0-9._~+/=:-]{8,})`)
	// secretFlagPattern is a flag whose next argument is a credential.
	secretFlagPattern = regexp.MustCompile(`(?i)^-{1,2}([a-z0-9_-]*(api[_-]?key|token|secret|password|passwd|auth|credential|bearer)[a-z0-9_-]*)$`)
	// assignPattern is KEY=value or --key=value.
	assignPattern = regexp.MustCompile(`^(-{0,2}[A-Za-z_][A-Za-z0-9_.-]*)=(.+)$`)
	// secretQueryKey is a URL query parameter that usually carries a credential.
	secretQueryKey = regexp.MustCompile(`(?i)(key|token|secret|sig|signature|auth|password|passwd|code|credential|session)`)
)

// scrubText redacts credential-shaped spans in free text such as a shell
// command or a permission rule. It reports whether anything was replaced.
func scrubText(s string) (string, bool) {
	if s == "" {
		return s, false
	}
	changed := false
	out := authHeaderPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := authHeaderPattern.FindStringSubmatch(m)
		if placeholderPattern.MatchString(sub[3]) {
			return m
		}
		changed = true
		return sub[1] + sub[2] + redactedMark
	})
	// URLs with userinfo or secret query values.
	out = urlInText.ReplaceAllStringFunc(out, func(m string) string {
		r, ch := scrubURL(m)
		if ch {
			changed = true
		}
		return r
	})
	// Token by token: well-known prefixes anywhere, KEY=value with a
	// secret-looking key, and the argument after a secret flag.
	fields := tokenSplit.FindAllStringIndex(out, -1)
	var b strings.Builder
	last := 0
	prevSecretFlag := false
	for _, f := range fields {
		tok := out[f[0]:f[1]]
		repl := tok
		switch {
		case tok == redactedMark || strings.Contains(tok, redactedMark):
		case prevSecretFlag && !strings.HasPrefix(tok, "-") && !placeholderPattern.MatchString(tok) && len(tok) >= 6:
			repl = redactedMark
		case secretValuePattern.MatchString(tok):
			repl = redactedMark
		}
		if m := assignPattern.FindStringSubmatch(tok); m != nil && repl == tok {
			if looksLikeSecret(m[1], m[2]) || secretValuePattern.MatchString(m[2]) {
				repl = m[1] + "=" + redactedMark
			}
		}
		prevSecretFlag = secretFlagPattern.MatchString(tok)
		// "--token=..." split at '=' by tokenSplit: the value token follows
		// immediately after an '=' separator.
		if !prevSecretFlag && f[0] > 0 && out[f[0]-1] == '=' && repl == tok {
			start := strings.LastIndexAny(out[:f[0]-1], " \t\"'") + 1
			key := out[start : f[0]-1]
			if looksLikeSecret(key, tok) || (secretFlagPattern.MatchString(key) && len(tok) >= 6 && !placeholderPattern.MatchString(tok)) {
				repl = redactedMark
			}
		}
		if repl != tok {
			changed = true
		}
		b.WriteString(out[last:f[0]])
		b.WriteString(repl)
		last = f[1]
	}
	b.WriteString(out[last:])
	return b.String(), changed
}

var urlInText = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)

// scrubURL removes userinfo and secret-looking query values from a URL.
func scrubURL(raw string) (string, bool) {
	if raw == "" {
		return raw, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Not parseable: fall back to the userinfo pattern alone.
		if urlUserinfoPattern.MatchString(strings.ToLower(raw)) {
			i := strings.Index(raw, "://") + 3
			j := strings.Index(raw[i:], "@")
			return raw[:i] + redactedMark + raw[i+j:], true
		}
		return raw, false
	}
	changed := false
	if u.User != nil {
		changed = true
		u.User = url.User(redactedMark)
	}
	if u.RawQuery != "" {
		q := u.Query()
		for k, vs := range q {
			for i, v := range vs {
				if v == "" || placeholderPattern.MatchString(v) {
					continue
				}
				if secretQueryKey.MatchString(k) || secretValuePattern.MatchString(v) {
					vs[i] = redactedMark
					changed = true
				}
			}
			q[k] = vs
		}
		if changed {
			u.RawQuery = strings.ReplaceAll(q.Encode(), url.QueryEscape(redactedMark), redactedMark)
		}
	}
	if !changed {
		return raw, false
	}
	s := u.String()
	s = strings.Replace(s, url.PathEscape(redactedMark)+"@", redactedMark+"@", 1)
	s = strings.Replace(s, "%3Credacted%3E@", redactedMark+"@", 1)
	return s, true
}

// scrubArgs redacts an argv. A secret flag (--api-key) redacts the next
// argument; KEY=value and --key=value forms redact the value; known token
// prefixes and URLs with credentials are redacted wherever they appear.
func scrubArgs(args []string) ([]string, bool) {
	if len(args) == 0 {
		return args, false
	}
	out := make([]string, len(args))
	changed := false
	for i, a := range args {
		r := a
		switch {
		case i > 0 && secretFlagPattern.MatchString(args[i-1]) && !strings.HasPrefix(a, "-") && !placeholderPattern.MatchString(a):
			r = redactedMark
		case secretValuePattern.MatchString(a):
			r = redactedMark
		default:
			if m := assignPattern.FindStringSubmatch(a); m != nil {
				key := strings.TrimLeft(m[1], "-")
				if (looksLikeSecret(key, m[2]) || secretValuePattern.MatchString(m[2]) ||
					(secretFlagPattern.MatchString("--"+key) && len(m[2]) >= 6 && !placeholderPattern.MatchString(m[2]))) && !strings.Contains(m[2], "://") {
					r = m[1] + "=" + redactedMark
				}
			}
			if r == a {
				if s, ch := scrubText(a); ch {
					r = s
				}
			}
		}
		if r != a {
			changed = true
		}
		out[i] = r
	}
	return out, changed
}
