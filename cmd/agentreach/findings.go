package main

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/somoore/steampipe-plugin-agentreach/pkg/posture"
)

// Rule ids. Every finding comes from a value the collector already computed;
// the CLI re-implements no posture rule.
const (
	rulePathConf      = "AgentReach-PATH-CONF"
	rulePathIntegrity = "AgentReach-PATH-INTEGRITY"
	ruleInlineSecret  = "AgentReach-MCP-INLINE-SECRET" // #nosec G101 -- a rule identifier for the report, not a credential
	ruleNotAssessed   = "AgentReach-NOT-ASSESSED"      // #nosec G101 -- a rule identifier for the report, not a credential
	ruleCIAgent       = "AgentReach-CI-AGENT"
	ruleSDKBypass     = "AgentReach-SDK-BYPASS" // #nosec G101 -- a rule identifier for the report, not a credential
)

const docsBase = "https://github.com/somoore/steampipe-mod-agentreach-compliance/blob/main/"

type ruleInfo struct {
	ID, Name, Short, Help, HelpURI string
}

var rules = []ruleInfo{
	{rulePathConf, "ConfidentialityPath", "Untrusted content can make the agent read a private file and send it out",
		"Cut one leg: deny the read (sandbox.filesystem.denyRead or permissions.deny Read), refuse the exit (sandbox network allowlist with strictAllowlist, deny WebFetch, disable the MCP server), or remove the untrusted source.",
		docsBase + "README.md#the-legs"},
	{rulePathIntegrity, "IntegrityPath", "Untrusted content can make the agent change guardrails, CI, dependencies or startup files",
		"Deny the write (permissions.deny Edit or sandbox.filesystem.denyWrite) or keep a prompt on it (leave the permission mode at default and avoid broad allow rules).",
		docsBase + "README.md#the-legs"},
	{ruleInlineSecret, "MCPInlineSecret", "An MCP server configuration holds a credential inline",
		"Move the value to the environment and reference it as ${VAR}; rotate the credential, since it sat in a file.",
		docsBase + "spec/controls.yaml"},
	{ruleCIAgent, "CIAgentWorkflow", "A CI workflow runs a coding agent where someone else's input meets the repository's secrets or an unrestricted shell",
		"Check out the base ref at the workspace root (the pull request head into a subdirectory passed with --add-dir), keep the Claude Code action's write-access check (drop allowed_non_write_users, list bots by name), and remove bypassPermissions, blanket Bash rules or Codex danger-full-access.",
		"https://github.com/somoore/steampipe-plugin-agentreach/blob/main/docs/tables/agentreach_ci_workflow.md"},
	{ruleSDKBypass, "SDKBypassPermissions", "An Agent SDK application starts sessions in bypassPermissions",
		"Pass permissionMode dontAsk with the allowedTools the application needs, or default with a canUseTool callback; enable the sandbox option; pass settingSources [] so the machine's settings do not apply. agentreach reads these options from source text, so check what the application passes at run time.",
		"https://github.com/somoore/steampipe-plugin-agentreach/blob/main/docs/tables/agentreach_sdk_launcher.md"},
	{ruleNotAssessed, "NotAssessed", "Part of the posture could not be assessed",
		"Fix the unreadable configuration source, run with probes on, or make the agent binary findable so its permission mode is known. Missing evidence is never a pass.",
		docsBase + "spec/controls.yaml"},
}

// approvalRank orders gates from weakest to strongest. unknown ranks below
// prompt so a gate agentreach cannot establish never counts as a person.
var approvalRank = map[string]int{"none": 0, "classifier": 1, "unknown": 2, "prompt": 3, "denied": 4}

// Finding is one reportable result.
type Finding struct {
	RuleID     string `json:"rule_id"`
	Level      string `json:"level"` // error | warning | note
	Failing    bool   `json:"failing"`
	Agent      string `json:"agent"`
	Approval   string `json:"approval,omitempty"`
	PathID     string `json:"path_id,omitempty"`
	ProjectDir string `json:"project_dir,omitempty"`
	Location   string `json:"location,omitempty"` // a file the finding is about, when there is one
	Line       int    `json:"line,omitempty"`     // line in Location, when known
	Status     string `json:"status,omitempty"`   // for paths: candidate, attested, or accepted (attested and --accept-attested)
	Message    string `json:"message"`

	// For grouping in the text report; not part of the JSON contract.
	kind, target, targetTitle, source, sourceTitle, exit, exitTitle string
	tier                                                            int
}

// Summary counts the snapshot's results.
type Summary struct {
	Findings      int            `json:"findings"`
	Failing       int            `json:"failing"`
	PathsByGate   map[string]int `json:"candidate_paths_by_approval"`
	Assessed      bool           `json:"fully_assessed"`
	NotAssessedBy []string       `json:"not_assessed_reasons"`
	Assumptions   []string       `json:"assumptions"`
	Attested      int            `json:"attested_paths"` // paths an operator says a declared control closes; agentreach did not verify
	Accepted      int            `json:"accepted_paths"` // attested paths reported as accepted (--accept-attested), not failing
	FailOn        string         `json:"fail_on"`
	// Agents is the discovered inventory: every coding agent and harness
	// found on the machine, with its version when known. Discovery is
	// automatic and every report carries it.
	Agents []AgentInventory `json:"agents"`
}

// AgentInventory is one discovered agent or harness.
type AgentInventory struct {
	Agent   string `json:"agent"`
	Version string `json:"version"`
}

var homeRE = regexp.MustCompile(`(/Users|/home)/[^/\s"']+`)

// tilde collapses home directories and scrubs credential-shaped text.
func tilde(s string) string {
	return posture.ScrubText(homeRE.ReplaceAllString(s, "~"))
}

func levelFor(approval string) string {
	switch approval {
	case "none":
		return "error"
	case "classifier":
		return "warning"
	default:
		return "note"
	}
}

// failsAt reports whether a gate is at or below the fail-on threshold. The
// default, auto, fails ungated paths everywhere and classifier-only paths
// when the agent's sandbox is not enforced: auto mode's classifier "does not
// guarantee safety" and is not an operating-system control (Claude Code
// permission-modes), so with no enforced sandbox it is the only thing in
// the way.
func failsAt(approval, failOn string, sandboxEnforced bool) bool {
	if failOn == "never" {
		return false
	}
	if failOn == "auto" {
		failOn = "none"
		if !sandboxEnforced {
			failOn = "classifier"
		}
	}
	r, ok := approvalRank[approval]
	if !ok || approval == "unknown" {
		return false // unknown is reported as not assessed, not as a failure
	}
	return r <= approvalRank[failOn]
}

func gateText(approval string) string {
	switch approval {
	case "none":
		return "and no step asks you first"
	case "classifier":
		return "and only auto mode's classifier stands in the way"
	case "prompt":
		return "but a prompt asks you first"
	default:
		return "and agentreach could not tell what approval it needs"
	}
}

// sourceOnlyGate reports a path whose only gate is the source loading: a
// project MCP server waiting for your approval, after which no later step
// asks.
func sourceOnlyGate(p posture.Path) bool {
	r := map[string]int{"unknown": 0, "none": 1, "classifier": 2, "prompt": 3}
	return p.AfterSourceApproval != "" && r[p.SourceApproval] > r[p.AfterSourceApproval] && p.Approval == p.SourceApproval
}

func pathMessage(p posture.Path) string {
	where := ""
	if p.ProjectDir != "" {
		where = " in a session started in " + p.ProjectDir
	}
	gate := gateText(p.Approval)
	if sourceOnlyGate(p) {
		load := "once it loads (a prompt asks you to approve it first)"
		if p.SourceApproval == "classifier" {
			load = "once it loads (only auto mode's classifier stands in the way of that)"
		}
		gate = load + ", " + strings.TrimPrefix(strings.TrimPrefix(gateText(p.AfterSourceApproval), "and "), "but ")
		gate = strings.Replace(gate, "no step asks you first", "no later step asks you", 1)
	}
	if p.Kind == "integrity" {
		return fmt.Sprintf("%s (%s) can make the agent change %s by %s%s, %s.",
			p.SourceTitle, p.SourceKind, p.TargetTitle, p.Via, where, gate)
	}
	return fmt.Sprintf("%s (%s) can make the agent read %s by %s and send it out through %s%s, %s.",
		p.SourceTitle, p.SourceKind, p.TargetTitle, p.Via, p.ExitTitle, where, gate)
}

// buildFindings derives findings from a snapshot.
func buildFindings(s *posture.Snapshot, failOn string, acceptAttested bool) ([]Finding, Summary) {
	sum := Summary{PathsByGate: map[string]int{}, FailOn: failOn, Assessed: true}
	var out []Finding

	// The discovered inventory is part of every report.
	for _, a := range s.Agents {
		sum.Agents = append(sum.Agents, AgentInventory{Agent: a.Agent, Version: a.Version})
	}
	if len(s.Agents) == 0 {
		// A machine with no coding agent or harness installed has nothing
		// to assess: that is a clean result, not a not-assessed one.
		sum.Assumptions = append(sum.Assumptions, "no coding agent or harness is installed on this machine")
	}
	enforced := map[string]bool{}
	for _, a := range s.Agents {
		enforced[a.Agent] = a.SandboxEnforced
		var reasons []string
		if len(a.CollectErrors) > 0 {
			reasons = append(reasons, fmt.Sprintf("%d configuration source(s) could not be read", len(a.CollectErrors)))
		}
		switch {
		case !a.Probed && a.ProbeSkippedReason != "":
			reasons = append(reasons, a.ProbeSkippedReason)
		case !a.Probed:
			reasons = append(reasons, "reachability probes were off")
		}
		switch {
		case a.StartSurfaceSource != "" && a.StartSurfaceSource != "assumed" && a.StartSurface != posture.SurfaceTerminal:
			reasons = append(reasons, fmt.Sprintf("agentreach ran inside a %s session (%s); its permission mode, settings and hooks can come from whatever started it, which agentreach cannot see, and the gates below model a terminal session", a.StartSurface, a.StartSurfaceSource))
		case a.StartSurface == posture.SurfaceTerminal:
			note := agentName(a.Agent) + ": gates model terminal sessions (" + a.StartSurfaceSource + ")"
			if m := a.SurfaceModes[posture.SurfacePrintSDK]; m != "" {
				note += "; claude -p and the Agent SDK start in " + m
			}
			if m := a.SurfaceModes[posture.SurfaceVSCode]; m != "" {
				note += "; VS Code starts in " + m
			}
			sum.Assumptions = append(sum.Assumptions, note)
		}
		if a.EffectivePermissionMode == "" || a.EffectivePermissionMode == "unknown" {
			reasons = append(reasons, "the permission mode is unknown")
		}
		for _, r := range reasons {
			sum.Assessed = false
			sum.NotAssessedBy = append(sum.NotAssessedBy, a.Agent+": "+r)
			out = append(out, Finding{RuleID: ruleNotAssessed, Level: "warning", Agent: a.Agent,
				Message: "Not assessed: " + r + ". Results below may be wrong either way."})
		}
	}

	for _, m := range s.MCPServers {
		if !m.HasInlineSecret {
			continue
		}
		out = append(out, Finding{RuleID: ruleInlineSecret, Level: "error", Failing: failOn != "never",
			Agent: m.Agent, ProjectDir: tilde(m.ProjectDir), Location: m.SourcePath,
			Message: tilde(fmt.Sprintf("MCP server %q in %s (%s scope) holds a credential inline. Reference it as ${VAR} instead and rotate it.", m.Name, m.SourcePath, m.Scope))})
	}

	for _, w := range s.CIWorkflows {
		why := ciRisks(w)
		if len(why) == 0 {
			continue
		}
		out = append(out, Finding{RuleID: ruleCIAgent, Level: "error", Failing: failOn != "never",
			Agent: w.Agent, ProjectDir: tilde(w.ProjectDir), Location: w.Path, Line: w.Line,
			Message: tilde(fmt.Sprintf("%s at %s:%d: %s.", ciStepName(w), w.Path, w.Line, strings.Join(why, "; ")))})
	}
	for _, l := range s.SDKLaunchers {
		if !slices.Contains(l.PermissionModes, "bypassPermissions") {
			continue
		}
		sandbox := "and no sandbox option, so every tool call runs without approval"
		if l.SandboxEnabled {
			sandbox = "with the sandbox option on: shell commands stay in the sandbox, other tools run without approval"
		}
		// A heuristic read of source text: reported, never failing.
		out = append(out, Finding{RuleID: ruleSDKBypass, Level: "warning", Agent: l.Agent,
			ProjectDir: tilde(l.ProjectDir), Location: l.Path, Line: l.ImportLine,
			Message: tilde(fmt.Sprintf("%s starts Agent SDK sessions in bypassPermissions %s (read from the source; agentreach cannot see run-time values).", l.Path, sandbox))})
	}
	if n := len(s.SDKLaunchers); n > 0 {
		sum.Assumptions = append(sum.Assumptions, fmt.Sprintf("SDK: %d file(s) start Claude Code through the Agent SDK; agentreach reads their options from source text, a heuristic", n))
	}
	if n := len(s.CIWorkflows); n > 0 {
		sum.Assumptions = append(sum.Assumptions, fmt.Sprintf("CI: %d workflow step(s) run an agent; agentreach reads the workflow files, not their runs", n))
	}

	paths := append([]posture.Path(nil), s.Paths...)
	sort.SliceStable(paths, func(i, j int) bool {
		ri, rj := approvalRank[paths[i].Approval], approvalRank[paths[j].Approval]
		if ri != rj {
			return ri < rj
		}
		if paths[i].Kind != paths[j].Kind {
			return paths[i].Kind == "confidentiality"
		}
		if paths[i].TargetTier != paths[j].TargetTier {
			return paths[i].TargetTier < paths[j].TargetTier
		}
		return paths[i].PathID < paths[j].PathID
	})
	for _, p := range paths {
		if p.Approval == "denied" || p.Status != "candidate" && p.Status != "attested" {
			continue
		}
		sum.PathsByGate[p.Approval]++
		rule := rulePathConf
		if p.Kind == "integrity" {
			rule = rulePathIntegrity
		}
		f := Finding{RuleID: rule, Level: levelFor(p.Approval), Failing: failsAt(p.Approval, failOn, enforced[p.Agent]),
			Agent: p.Agent, Approval: p.Approval, PathID: tilde(p.PathID), ProjectDir: tilde(p.ProjectDir),
			Location: p.TargetPath, Status: p.Status, Message: tilde(pathMessage(p)),
			kind: p.Kind, target: p.TargetPath, targetTitle: tilde(p.TargetTitle), tier: p.TargetTier,
			source: p.SourceID, sourceTitle: tilde(p.SourceTitle), exit: p.ExitID, exitTitle: tilde(p.ExitTitle)}
		if p.Status == "attested" {
			// An operator's declaration is recorded, not trusted: the path
			// stays a finding unless the operator accepts it explicitly.
			sum.Attested++
			f.Message += tilde(" You declared " + p.MitigatedBy + "; agentreach did not verify that it closes this exit.")
			if acceptAttested {
				f.Status, f.Failing, f.Level = "accepted", false, "note"
				sum.Accepted++
			}
		}
		out = append(out, f)
	}
	if sum.PathsByGate["unknown"] > 0 {
		sum.Assessed = false
		byAgent := map[string]int{}
		for _, f := range out {
			if f.Approval == "unknown" {
				byAgent[f.Agent]++
			}
		}
		var parts []string
		for _, a := range sortedKeys(byAgent) {
			parts = append(parts, fmt.Sprintf("%s %d", agentName(a), byAgent[a]))
		}
		sum.NotAssessedBy = append(sum.NotAssessedBy, fmt.Sprintf("%d path(s) need an approval agentreach could not determine (%s)", sum.PathsByGate["unknown"], strings.Join(parts, ", ")))
	}

	for _, f := range out {
		if f.Failing {
			sum.Failing++
		}
	}
	sum.Findings = len(out)
	return out, sum
}

// ciRisks names what makes a CI agent step dangerous, worst first: the
// same conditions the mod's CI-01, CI-02 and CI-03 alarm on.
func ciRisks(w posture.CIWorkflow) []string {
	var why []string
	if w.BaseSecretsTrigger && w.ChecksOutHead {
		why = append(why, "it runs a pull request's tree with the base repository's secrets (pull_request_target or workflow_run after checking out the head at the workspace root)")
	}
	if w.OutsiderTrigger {
		switch {
		case w.ActorCheck == "none":
			why = append(why, "someone without write access can start it (an issue, comment or pull_request_target event) and it checks nobody")
		case w.ActorCheck == "relaxed":
			why = append(why, "it lets users without write access start it")
		case w.AllowedBots == "all":
			why = append(why, "allowed_bots: '*' lets any bot or GitHub App start it")
		}
	}
	if w.UntrustedTrigger && w.UnrestrictedShell {
		how := "a blanket Bash allow rule"
		switch {
		case w.Agent == posture.AgentCodex:
			how = "Codex " + w.Sandbox
		case w.SkipPermissions:
			how = "bypassPermissions"
		}
		why = append(why, "any shell command runs with no approval ("+how+") on text someone else wrote")
	}
	return why
}

func ciStepName(w posture.CIWorkflow) string {
	switch w.Launcher {
	case "claude_code_action":
		return "The Claude Code action"
	case "claude_code_base_action":
		return "The Claude Code base action"
	case "codex_action":
		return "The Codex action"
	}
	if w.Agent == posture.AgentCodex {
		return "A run step that calls codex exec"
	}
	return "A run step that calls claude -p"
}

// exitCode: 0 nothing failing, 1 failing findings, 2 not fully assessed.
func exitCode(sum Summary) int {
	switch {
	case sum.Failing > 0:
		return 1
	case !sum.Assessed:
		return 2
	}
	return 0
}

func sortedKeys(m map[string]int) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// agentName is the product name for an agent id.
func agentName(a string) string {
	switch a {
	case "claude_code":
		return "Claude Code"
	case "codex":
		return "Codex"
	}
	return a
}
