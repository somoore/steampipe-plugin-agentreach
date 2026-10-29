// Package agentreach is a read-only Steampipe plugin that exposes the local
// security posture of AI coding agents (Claude Code first) as SQL tables:
// what the agent is configured to do, what it is told to obey, and what it
// can actually reach on this machine. All collection lives in pkg/posture.
package agentreach

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin/transform"
)

// Plugin returns the agentreach plugin definition.
func Plugin(ctx context.Context) *plugin.Plugin {
	p := &plugin.Plugin{
		Name: "steampipe-plugin-agentreach",
		ConnectionConfigSchema: &plugin.ConnectionConfigSchema{
			NewInstance: ConfigInstance,
		},
		DefaultTransform: transform.From(fromItemCamel), // FromCamel on the wrapped item; not FromGo: zero values (0, false) must stay queryable
		TableMap: map[string]*plugin.Table{
			"agentreach_agent":            tableAgentreachAgent(ctx),
			"agentreach_project":          tableAgentreachProject(ctx),
			"agentreach_setting":          tableAgentreachSetting(ctx),
			"agentreach_hook":             tableAgentreachHook(ctx),
			"agentreach_mcp_server":       tableAgentreachMCPServer(ctx),
			"agentreach_instruction_file": tableAgentreachInstructionFile(ctx),
			"agentreach_sandbox_rule":     tableAgentreachSandboxRule(ctx),
			"agentreach_reach_file":       tableAgentreachReachFile(ctx),
			"agentreach_reach_host":       tableAgentreachReachHost(ctx),
			"agentreach_plugin":           tableAgentreachPlugin(ctx),
			"agentreach_marketplace":      tableAgentreachMarketplace(ctx),
			"agentreach_leg":              tableAgentreachLeg(ctx),
			"agentreach_path":             tableAgentreachPath(ctx),
			"agentreach_write_target":     tableAgentreachWriteTarget(ctx),
			"agentreach_environment":      tableAgentreachEnvironment(ctx),
			"agentreach_launch_flag":      tableAgentreachLaunchFlag(ctx),
			"agentreach_ci_workflow":      tableAgentreachCIWorkflow(ctx),
			"agentreach_sdk_launcher":     tableAgentreachSDKLauncher(ctx),
		},
	}
	return p
}
