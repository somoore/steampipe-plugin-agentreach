package posture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// CIWorkflow is one step in a GitHub Actions workflow that runs a coding
// agent: the Claude Code GitHub Action, its base action, the Codex action,
// or a run step that calls claude -p or codex exec. A workflow is another
// way a session starts, with its own trigger, token and permission mode,
// none of which the terminal model covers. Only enums, booleans, counts and
// names GitHub restricts (job ids, secret names, event names) are kept:
// prompts, run scripts and input values never leave the file.
//
// Docs: Claude Code GitHub Actions (code.claude.com/docs/en/github-actions),
// the claude-code-action security guide (docs/security.md in
// anthropics/claude-code-action), the Codex action README (openai/codex-action)
// and Codex non-interactive mode (developers.openai.com/codex/noninteractive).
type CIWorkflow struct {
	Agent      string `json:"agent"`
	ProjectDir string `json:"project_dir"` // repository root the workflow belongs to
	Path       string `json:"path"`
	Job        string `json:"job"` // job id; empty when it is not one GitHub accepts
	Line       int    `json:"line"`
	// Launcher is claude_code_action, claude_code_base_action,
	// codex_action, or run (a shell step that calls the CLI).
	Launcher  string `json:"launcher"`
	ActionRef string `json:"action_ref"` // the ref after @ for an action
	Pinned    bool   `json:"pinned"`     // the ref is a full commit SHA
	Mode      string `json:"mode"`       // interactive (answers @claude mentions) or automation (runs a fixed prompt)

	Triggers []string `json:"triggers"`
	// UntrustedTrigger: an issue, comment, review, discussion, pull
	// request or workflow_run event, where text someone else wrote can
	// reach the agent.
	UntrustedTrigger bool `json:"untrusted_trigger"`
	// OutsiderTrigger: someone without write access can cause a run that
	// has the repository's secrets: issues, issue_comment, discussion,
	// discussion_comment, pull_request_target or workflow_run. Fork pull
	// request and review events run with no secrets (GitHub docs, Events
	// that trigger workflows).
	OutsiderTrigger bool `json:"outsider_trigger"`
	// BaseSecretsTrigger: pull_request_target or workflow_run, which run
	// with the base repository's secrets on pull request content.
	BaseSecretsTrigger bool `json:"base_secrets_trigger"`
	// ChecksOutHead: an earlier step in the job checks out the pull
	// request head into the workspace root, so the agent runs in that tree
	// and reads its settings, hooks and instructions.
	ChecksOutHead bool `json:"checks_out_head"`
	// ActorCheck is write_access (the action refuses users without write
	// access), relaxed (allowed_non_write_users or allow-users widens it)
	// or none (the base action and run steps check nobody).
	ActorCheck    string `json:"actor_check"`
	AllowedBots   string `json:"allowed_bots"`   // none, listed or all; empty when the launcher has no bot check
	CommentFilter bool   `json:"comment_filter"` // include_comments_by_actor limits whose comments reach Claude

	PermissionMode       string `json:"permission_mode"`        // Claude Code mode, or the Codex permission profile
	PermissionModeSource string `json:"permission_mode_source"` // flag, settings_input, project_settings, action_input or built_in
	SkipPermissions      bool   `json:"skip_permissions"`       // bypassPermissions, or Codex with no sandbox and no approvals
	UnrestrictedShell    bool   `json:"unrestricted_shell"`     // any shell command runs with no approval and no sandbox
	AllowRules           int    `json:"allow_rules"`            // allow rules from flags, the settings input and project settings
	Sandbox              string `json:"sandbox"`                // Claude Code: enabled or off; Codex: the sandbox mode
	SafetyStrategy       string `json:"safety_strategy"`        // Codex action safety-strategy

	PermissionsDeclared bool     `json:"permissions_declared"` // the job or workflow sets permissions:
	WriteScopes         []string `json:"write_scopes"`         // token scopes with write, or write-all
	GitHubToken         string   `json:"github_token"`         // app, workflow, secret or inline (Claude Code action only)
	Secrets             []string `json:"secrets"`              // secret names the step, its job or the workflow passes
	HasInlineSecret     bool     `json:"has_inline_secret"`    // an input or env value is a literal credential
}

// Launchers.
const (
	ciClaudeAction = "claude_code_action"
	ciClaudeBase   = "claude_code_base_action"
	ciCodexAction  = "codex_action"
	ciRun          = "run"
)

var (
	ciUntrusted = map[string]bool{
		"issues": true, "issue_comment": true, "pull_request": true, "pull_request_target": true,
		"pull_request_review": true, "pull_request_review_comment": true,
		"discussion": true, "discussion_comment": true, "workflow_run": true,
	}
	ciOutsider        = map[string]bool{"issues": true, "issue_comment": true, "discussion": true, "discussion_comment": true, "pull_request_target": true, "workflow_run": true}
	ciBaseSecrets     = map[string]bool{"pull_request_target": true, "workflow_run": true}
	reCIWorkflowToken = regexp.MustCompile(`^\$\{\{\s*(secrets\.GITHUB_TOKEN|github\.token)\s*\}\}$`)
	reCIEvent         = regexp.MustCompile(`^[a-z_]{1,40}$`)
	reCIJob           = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,99}$`)
	reCISecret        = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]{0,99})`)
	reCIExpr          = regexp.MustCompile(`\$\{\{[^}]*\}\}`)
	reCIRef           = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,64}$`)
	reCISHA           = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reCIProfile       = regexp.MustCompile(`^:?[A-Za-z0-9_-]{1,40}$`)
	reCIHeadRef       = regexp.MustCompile(`pull_request\.head\.(sha|ref)|github\.head_ref|workflow_run\.head_(sha|branch)|refs/pull/`)
	ciSafety          = map[string]bool{"drop-sudo": true, "unprivileged-user": true, "read-only": true, "unsafe": true}
	ciTokenScopes     = map[string]bool{"actions": true, "attestations": true, "checks": true, "contents": true, "deployments": true, "discussions": true, "id-token": true, "issues": true, "models": true, "packages": true, "pages": true, "pull-requests": true, "repository-projects": true, "security-events": true, "statuses": true}
	ciMaxFiles        = 200
	ciMaxFileBytes    = int64(1 << 20)
)

// collectCIWorkflows reads .github/workflows in the repository of every
// project agentreach already knows. It never walks the home directory.
func collectCIWorkflows(opts Options, snap *Snapshot) {
	for _, root := range projectRoots(opts, snap) {
		var files []string
		for _, pat := range []string{"*.yml", "*.yaml"} {
			m, _ := filepath.Glob(filepath.Join(root, ".github", "workflows", pat))
			files = append(files, m...)
		}
		sort.Strings(files)
		if len(files) > ciMaxFiles {
			files = files[:ciMaxFiles]
		}
		for _, f := range files {
			for _, r := range parseWorkflow(root, f) {
				if wantAgent(opts, r.Agent) {
					snap.CIWorkflows = append(snap.CIWorkflows, r)
				}
			}
		}
	}
}

// parseWorkflow returns one row per agent step. A file that does not parse
// returns nothing: GitHub rejects it, so it never runs.
func parseWorkflow(root, path string) []CIWorkflow {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > ciMaxFileBytes {
		return nil
	}
	b, err := readFileLimited(path)
	if err != nil {
		return nil
	}
	var doc yaml.Node
	if yaml.Unmarshal(b, &doc) != nil || len(doc.Content) == 0 {
		return nil
	}
	top := doc.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil
	}
	triggers := ciTriggers(ynode(top, "on"))
	untrusted, outsider, baseSecrets := false, false, false
	for _, t := range triggers {
		untrusted = untrusted || ciUntrusted[t]
		outsider = outsider || ciOutsider[t]
		baseSecrets = baseSecrets || ciBaseSecrets[t]
	}
	wfPerms := ynode(top, "permissions")
	wfEnv := ynode(top, "env")
	projectSettings, _ := readJSON(filepath.Join(root, ".claude", "settings.json"))

	var out []CIWorkflow
	jobs := ynode(top, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobID, job := jobs.Content[i].Value, jobs.Content[i+1]
		if job.Kind != yaml.MappingNode || ynode(job, "uses") != nil {
			continue // a reusable workflow call has no steps here
		}
		if !reCIJob.MatchString(jobID) {
			jobID = ""
		}
		perms := ynode(job, "permissions")
		if perms == nil {
			perms = wfPerms
		}
		declared, scopes := ciPermissions(perms)
		jobEnv := ynode(job, "env")
		steps := ynode(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		headCheckout := false
		for _, step := range steps.Content {
			if step.Kind != yaml.MappingNode {
				continue
			}
			uses := strings.TrimSpace(yscalar(ynode(step, "uses")))
			with := ynode(step, "with")
			run := yscalar(ynode(step, "run"))
			base := CIWorkflow{
				ProjectDir: root, Path: path, Job: jobID, Line: step.Line,
				Triggers: triggers, UntrustedTrigger: untrusted, OutsiderTrigger: outsider, BaseSecretsTrigger: baseSecrets,
				ChecksOutHead: headCheckout, PermissionsDeclared: declared, WriteScopes: scopes,
			}
			base.Secrets, base.HasInlineSecret = ciSecrets(wfEnv, jobEnv, ynode(step, "env"), with, run)
			action, ref := ciAction(uses)
			base.ActionRef, base.Pinned = ref, reCISHA.MatchString(ref)
			switch action {
			case ciClaudeAction, ciClaudeBase:
				r := base
				r.Agent, r.Launcher = AgentClaudeCode, action
				ciClaudeRow(&r, root, with, projectSettings)
				out = append(out, r)
			case ciCodexAction:
				r := base
				r.Agent, r.Launcher = AgentCodex, action
				ciCodexActionRow(&r, with)
				out = append(out, r)
			case "":
				if run != "" {
					out = append(out, ciRunRows(base, run, root, projectSettings)...)
				}
			}
			// Later steps run in whatever this step checked out.
			if strings.HasPrefix(strings.ToLower(uses), "actions/checkout@") && reCIHeadRef.MatchString(yscalar(ynode(with, "ref"))) &&
				strings.Trim(yscalar(ynode(with, "path")), " ./") == "" {
				headCheckout = true
			}
			if strings.Contains(run, "gh pr checkout") {
				headCheckout = true
			}
		}
	}
	return out
}

func ciAction(uses string) (action, ref string) {
	name, ref, ok := strings.Cut(uses, "@")
	if !ok {
		return "", ""
	}
	if !reCIRef.MatchString(ref) {
		ref = ""
	}
	switch strings.ToLower(name) {
	case "anthropics/claude-code-action":
		return ciClaudeAction, ref
	case "anthropics/claude-code-action/base-action", "anthropics/claude-code-base-action":
		return ciClaudeBase, ref
	case "openai/codex-action":
		return ciCodexAction, ref
	}
	return "", ""
}

// ciClaudeRow reads the action's inputs. The action runs Claude Code
// through the Agent SDK, which starts in default mode unless a flag or
// settings set one (SDK docs: permissions); with no person at the prompt,
// a call that needs approval is denied.
func ciClaudeRow(r *CIWorkflow, root string, with *yaml.Node, project map[string]any) {
	r.Mode = "automation"
	if r.Launcher == ciClaudeAction {
		if yscalar(ynode(with, "prompt")) == "" && yscalar(ynode(with, "direct_prompt")) == "" && yscalar(ynode(with, "override_prompt")) == "" {
			r.Mode = "interactive"
		}
		r.ActorCheck = "write_access"
		if yscalar(ynode(with, "allowed_non_write_users")) != "" {
			r.ActorCheck = "relaxed"
		}
		switch b := strings.TrimSpace(yscalar(ynode(with, "allowed_bots"))); {
		case b == "":
			r.AllowedBots = "none"
		case b == "*":
			r.AllowedBots = "all"
		default:
			r.AllowedBots = "listed"
		}
		r.CommentFilter = strings.TrimSpace(yscalar(ynode(with, "include_comments_by_actor"))) != ""
		switch t := strings.TrimSpace(yscalar(ynode(with, "github_token"))); {
		case t == "":
			r.GitHubToken = "app"
		case reCIWorkflowToken.MatchString(t):
			r.GitHubToken = "workflow"
		case strings.Contains(t, "${{"):
			r.GitHubToken = "secret"
		default:
			r.GitHubToken = "inline"
		}
	} else {
		r.ActorCheck = "none"
	}
	flags := recogniseFlags(AgentClaudeCode, shellWords(ciCommandText(yscalar(ynode(with, "claude_args")))))
	settings := ciSettings(root, yscalar(ynode(with, "settings")))
	extra := splitRules(yscalar(ynode(with, "allowed_tools")))
	ciClaudeGates(r, root, flags, settings, project, extra)
}

// ciSettings reads a settings value given as inline JSON or as a path
// inside the repository; anything else (an expression, a path outside the
// checkout) is not read.
func ciSettings(root, s string) map[string]any {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(s), &m) == nil {
			return m
		}
		return nil
	}
	if s == "" || strings.Contains(s, "${{") || strings.Contains(s, "EXPR") {
		return nil
	}
	if p := filepath.Join(root, s); strings.HasPrefix(p, root+string(filepath.Separator)) {
		m, _ := readJSON(p)
		return m
	}
	return nil
}

// ciClaudeGates resolves the mode (flag, then the settings input, then the
// repository's .claude/settings.json, then the built-in default) and the
// allow rules. bypassPermissions or a blanket Bash allow rule lets any
// command run.
func ciClaudeGates(r *CIWorkflow, root string, flags []LaunchFlag, settings, project map[string]any, extra []string) {
	for _, f := range flags {
		if f.Flag == "--settings" && settings == nil {
			settings = ciSettings(root, f.settingsPath)
		}
	}
	r.PermissionMode, r.PermissionModeSource = "default", "built_in"
	if m := getString(project, "permissions", "defaultMode"); claudePermModes[m] != "" {
		r.PermissionMode, r.PermissionModeSource = claudePermModes[m], "project_settings"
	}
	if m := getString(settings, "permissions", "defaultMode"); claudePermModes[m] != "" {
		r.PermissionMode, r.PermissionModeSource = claudePermModes[m], "settings_input"
	}
	rules := append([]string{}, extra...)
	rules = append(rules, toStringSlice(getMap(project, "permissions")["allow"])...)
	rules = append(rules, toStringSlice(getMap(settings, "permissions")["allow"])...)
	for _, f := range flags {
		switch {
		case f.Flag == "--dangerously-skip-permissions":
			r.PermissionMode, r.PermissionModeSource = "bypassPermissions", "flag"
		case f.Flag == "--permission-mode" && f.Value != "":
			r.PermissionMode, r.PermissionModeSource = f.Value, "flag"
		case f.ruleType == "allow":
			rules = append(rules, f.rules...)
		}
	}
	r.AllowRules = len(rules)
	r.SkipPermissions = r.PermissionMode == "bypassPermissions"
	r.UnrestrictedShell = r.SkipPermissions
	for _, rule := range rules {
		if _, blanket, _, ok := bashRule(rule); ok && blanket {
			r.UnrestrictedShell = true
		}
	}
	r.Sandbox = "off"
	for _, m := range []map[string]any{project, settings} {
		if b := getBool(m, "sandbox", "enabled"); b != nil {
			if *b {
				r.Sandbox = "enabled"
			} else {
				r.Sandbox = "off"
			}
		}
	}
}

// ciCodexActionRow reads openai/codex-action inputs. With neither sandbox
// nor permission-profile the action runs the legacy workspace-write
// sandbox; safety-strategy defaults to drop-sudo (codex-action README).
func ciCodexActionRow(r *CIWorkflow, with *yaml.Node) {
	r.Mode = "automation"
	r.ActorCheck = "write_access"
	if yscalar(ynode(with, "allow-users")) != "" {
		r.ActorCheck = "relaxed"
	}
	r.AllowedBots = "none"
	if b := strings.TrimSpace(yscalar(ynode(with, "allow-bots"))); b == "true" {
		r.AllowedBots = "listed" // github-actions[bot] only
	}
	r.SafetyStrategy = "drop-sudo"
	if s := strings.TrimSpace(yscalar(ynode(with, "safety-strategy"))); s != "" {
		r.SafetyStrategy = "unknown"
		if ciSafety[s] {
			r.SafetyStrategy = s
		}
	}
	r.Sandbox, r.PermissionModeSource = "workspace-write", "built_in"
	if s := strings.TrimSpace(yscalar(ynode(with, "sandbox"))); s != "" {
		r.Sandbox, r.PermissionModeSource = "unknown", "action_input"
		if codexSandboxModes[s] {
			r.Sandbox = s
		}
	}
	if p := strings.TrimSpace(yscalar(ynode(with, "permission-profile"))); p != "" {
		r.Sandbox, r.PermissionModeSource = "profile", "action_input"
		if reCIProfile.MatchString(p) {
			r.PermissionMode = p
		}
	}
	if r.SafetyStrategy == "read-only" {
		r.Sandbox = "read-only"
	}
	args := strings.TrimSpace(yscalar(ynode(with, "codex-args")))
	var words []string
	if !strings.HasPrefix(args, "[") || json.Unmarshal([]byte(args), &words) != nil {
		words = shellWords(ciCommandText(args))
	}
	ciCodexFlags(r, recogniseFlags(AgentCodex, words))
}

func ciCodexFlags(r *CIWorkflow, flags []LaunchFlag) {
	for _, f := range flags {
		switch f.Flag {
		case "--dangerously-bypass-approvals-and-sandbox", "--yolo":
			r.Sandbox, r.SkipPermissions, r.PermissionModeSource = "danger-full-access", true, "flag"
		case "-s", "--sandbox":
			if f.Value != "" {
				r.Sandbox, r.PermissionModeSource = f.Value, "flag"
			}
		case "-c", "--config":
			if v, ok := strings.CutPrefix(f.Value, "sandbox_mode="); ok {
				r.Sandbox, r.PermissionModeSource = v, "flag"
			}
		}
	}
	r.UnrestrictedShell = r.Sandbox == "danger-full-access"
}

// ciRunRows finds claude -p and codex exec in a run step, including npx
// and bunx package forms. A run step checks no actor.
func ciRunRows(base CIWorkflow, run, root string, project map[string]any) []CIWorkflow {
	var out []CIWorkflow
	words := shellWords(ciCommandText(run))
	for i := 0; i < len(words); i++ {
		agent := ciAgentWord(words[i])
		if agent == "" {
			continue
		}
		j := i + 1
		for ; j < len(words) && !isSeparator(words[j]); j++ {
		}
		args := words[i+1 : j]
		i = j
		r := base
		r.Agent, r.Launcher, r.Mode, r.ActorCheck = agent, ciRun, "automation", "none"
		if agent == AgentClaudeCode {
			if !slices.Contains(args, "-p") && !slices.Contains(args, "--print") {
				continue // claude mcp, claude --version and the like
			}
			ciClaudeGates(&r, root, recogniseFlags(agent, args), nil, project, nil)
		} else {
			if len(args) == 0 || (args[0] != "exec" && args[0] != "e") {
				continue
			}
			r.Sandbox, r.PermissionModeSource = "read-only", "built_in" // codex exec's default
			ciCodexFlags(&r, recogniseFlags(agent, args[1:]))
		}
		out = append(out, r)
	}
	return out
}

func ciAgentWord(w string) string {
	if a := agentFor(w); a != "" {
		return a
	}
	pkg := w
	if k := strings.LastIndex(pkg, "@"); k > 0 {
		pkg = pkg[:k]
	}
	switch pkg {
	case "@anthropic-ai/claude-code":
		return AgentClaudeCode
	case "@openai/codex":
		return AgentCodex
	}
	return ""
}

// ciCommandText joins continued lines and replaces ${{ }} expressions so
// the shell splitter does not read their braces as separators.
func ciCommandText(s string) string {
	s = strings.ReplaceAll(s, "\\\r\n", " ")
	s = strings.ReplaceAll(s, "\\\n", " ")
	return reCIExpr.ReplaceAllString(s, "EXPR")
}

func ciTriggers(n *yaml.Node) []string {
	var raw []string
	switch {
	case n == nil:
	case n.Kind == yaml.ScalarNode:
		raw = []string{n.Value}
	case n.Kind == yaml.SequenceNode:
		for _, c := range n.Content {
			raw = append(raw, c.Value)
		}
	case n.Kind == yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			raw = append(raw, n.Content[i].Value)
		}
	}
	out := []string{}
	for _, t := range raw {
		if reCIEvent.MatchString(t) && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// ciPermissions returns whether permissions: is set and which scopes it
// grants write. Without it the token gets the repository's default, which
// agentreach cannot see.
func ciPermissions(n *yaml.Node) (bool, []string) {
	scopes := []string{}
	if n == nil {
		return false, scopes
	}
	if n.Kind == yaml.ScalarNode {
		if n.Value == "write-all" {
			scopes = append(scopes, "write-all")
		}
		return true, scopes
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k := n.Content[i].Value; ciTokenScopes[k] && n.Content[i+1].Value == "write" {
				scopes = append(scopes, k)
			}
		}
	}
	sort.Strings(scopes)
	return true, scopes
}

// ciSecrets returns the secret names an agent step can see through its
// inputs and environment, and whether any value is a literal credential.
func ciSecrets(wfEnv, jobEnv, stepEnv, with *yaml.Node, run string) ([]string, bool) {
	names := []string{}
	inline := false
	note := func(s string) {
		for _, m := range reCISecret.FindAllStringSubmatch(s, -1) {
			if !slices.Contains(names, m[1]) {
				names = append(names, m[1])
			}
		}
	}
	for _, n := range []*yaml.Node{wfEnv, jobEnv, stepEnv, with} {
		if n == nil || n.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i].Value, yscalar(n.Content[i+1])
			note(v)
			if !strings.Contains(v, "${{") && looksLikeSecret(k, v) {
				inline = true
			}
		}
	}
	note(run)
	sort.Strings(names)
	return names, inline
}

func ynode(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			v := n.Content[i+1]
			if v.Kind == yaml.AliasNode && v.Alias != nil {
				v = v.Alias
			}
			return v
		}
	}
	return nil
}

func yscalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}
