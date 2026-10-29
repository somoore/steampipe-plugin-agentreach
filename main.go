package main

import (
	"github.com/somoore/steampipe-plugin-agentreach/agentreach"
	"github.com/turbot/steampipe-plugin-sdk/v6/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: agentreach.Plugin})
}
