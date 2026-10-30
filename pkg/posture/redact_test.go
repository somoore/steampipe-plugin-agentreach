package posture

import (
	"strings"
	"testing"
)

// fake builds credential-shaped strings at run time so no secret-shaped
// literal sits in the repository (gitleaks and ci/checks.sh scan it).
func fake(prefix string, n int) string { return prefix + strings.Repeat("Q7x", n) }

func TestScrubText(t *testing.T) {
	gh := fake("gh"+"p_", 10)
	sk := fake("s"+"k-", 6)
	cases := []struct {
		in       string
		mustLose string
		mustKeep string
	}{
		{`curl -H "Authorization: Bearer ` + fake("abc", 5) + `" https://api.example.com`, "abcQ7x", "https://api.example.com"},
		{"npx tool --api-key " + sk + " --verbose", sk, "--verbose"},
		{"npx tool --token=" + fake("tok", 6), "tokQ7x", "npx tool"},
		{"OPENAI_API_KEY=" + sk + " node server.js", sk, "node server.js"},
		{"git clone https://user:" + fake("pw", 4) + "@github.com/a/b", "pwQ7x", "github.com/a/b"},
		{"echo " + gh, gh, "echo"},
		{"huggingface " + fake("hf_", 12), "hf_Q7x", "huggingface"},
		{"stripe " + fake("sk_live_", 4), "sk_live_Q7x", "stripe"},
		{"sendgrid SG." + strings.Repeat("a", 24), "SG.aaa", "sendgrid"},
		{"python hook.py --event Stop", "", "python hook.py --event Stop"},
	}
	for _, c := range cases {
		got, _ := scrubText(c.in)
		if c.mustLose != "" && strings.Contains(got, c.mustLose) {
			t.Errorf("scrubText(%q) kept secret: %q", c.in, got)
		}
		if !strings.Contains(got, c.mustKeep) {
			t.Errorf("scrubText(%q) lost context %q: %q", c.in, c.mustKeep, got)
		}
	}
	if got, ch := scrubText("bash ~/.claude/hooks/format.sh"); ch || got != "bash ~/.claude/hooks/format.sh" {
		t.Errorf("benign command changed: %q", got)
	}
}

func TestScrubURLAndArgs(t *testing.T) {
	tok := fake("t", 8)
	u, ch := scrubURL("https://mcp.example.com/sse?api_key=" + tok + "&region=eu")
	if !ch || strings.Contains(u, tok) || !strings.Contains(u, "region=eu") {
		t.Errorf("scrubURL query: %q", u)
	}
	u, ch = scrubURL("https://bob:" + tok + "@mcp.example.com/x")
	if !ch || strings.Contains(u, tok) || !strings.Contains(u, "mcp.example.com/x") {
		t.Errorf("scrubURL userinfo: %q", u)
	}
	if u, ch := scrubURL("https://mcp.example.com/sse"); ch || u != "https://mcp.example.com/sse" {
		t.Errorf("benign url changed: %q", u)
	}
	sk := fake("s"+"k-", 6)
	args, ch := scrubArgs([]string{"-y", "@acme/mcp@1.2.3", "--api-key", sk, "--project=demo", "TOKEN=" + fake("z", 7)})
	joined := strings.Join(args, " ")
	if !ch || strings.Contains(joined, sk) || strings.Contains(joined, "zQ7x") || !strings.Contains(joined, "@acme/mcp@1.2.3") || !strings.Contains(joined, "--project=demo") {
		t.Errorf("scrubArgs: %q", joined)
	}
}
