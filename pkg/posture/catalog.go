package posture

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// sensitivePath is a catalog entry for something an agent should usually not
// be able to read. Paths use ~ for home and are expanded at collection time.
type sensitivePath struct {
	Path        string
	Category    string
	Description string
	Darwin      bool // include on macOS
	Linux       bool // include on Linux
}

// sensitiveCatalog is the v0 list. It is deliberately data, not code, so it
// can move to an external file and grow by PR.
var sensitiveCatalog = []sensitivePath{
	{"~/.ssh", "ssh", "SSH private keys, config and known_hosts.", true, true},
	{"~/.aws/credentials", "cloud_credential", "AWS long-lived access keys.", true, true},
	{"~/.aws/config", "cloud_credential", "AWS profiles, SSO and role settings; keys belong in credentials, but config can hold them too.", true, true},
	{"~/.aws/sso/cache", "cloud_credential", "AWS IAM Identity Center (SSO) access tokens.", true, true},
	{"~/.aws/cli/cache", "cloud_credential", "AWS CLI cached temporary role credentials.", true, true},
	{"~/.config/gcloud/application_default_credentials.json", "cloud_credential", "Google Cloud application default credentials.", true, true},
	{"~/.config/gcloud/credentials.db", "cloud_credential", "gcloud user credential store.", true, true},
	{"~/.azure", "cloud_credential", "Azure CLI tokens and profiles.", true, true},
	{"~/.config/doctl/config.yaml", "cloud_credential", "DigitalOcean API token.", true, true},
	{"~/.kube/config", "kube", "Kubernetes cluster credentials.", true, true},
	{"~/.config/gh/hosts.yml", "vcs_credential", "GitHub CLI OAuth token.", true, true},
	{"~/.netrc", "vcs_credential", "Plaintext machine/login/password entries.", true, true},
	{"~/.git-credentials", "vcs_credential", "Git credential store (plaintext).", true, true},
	{"~/.gitconfig", "vcs_credential", "Global git config: names the credential helper, hooksPath and signing key; holds a token only in a URL.", true, true},
	{"~/.npmrc", "package_registry", "npm auth tokens.", true, true},
	{"~/.pypirc", "package_registry", "PyPI upload credentials.", true, true},
	{"~/.cargo/credentials.toml", "package_registry", "crates.io token.", true, true},
	{"~/.docker/config.json", "package_registry", "Docker registry auth.", true, true},
	{"~/.terraform.d/credentials.tfrc.json", "package_registry", "Terraform Cloud token.", true, true},
	{"~/.terraformrc", "package_registry", "Terraform CLI config and credentials.", true, true},
	{"~/.claude/.credentials.json", "agent_credential", "Claude Code OAuth tokens (Linux/fallback store).", true, true},
	{"~/.claude.json", "agent_credential", "Claude Code global config: account, MCP servers, project trust.", true, true},
	{"~/.codex/auth.json", "agent_credential", "OpenAI Codex CLI credentials.", true, true},
	{"~/.codex/config.toml", "agent_credential", "Codex CLI config including MCP servers.", true, true},
	{"~/.cursor", "agent_credential", "Cursor state, MCP config and tokens.", true, true},
	{"~/.gemini", "agent_credential", "Gemini CLI settings and OAuth state.", true, true},
	{"~/.config/opencode", "agent_credential", "OpenCode config and auth.", true, true},
	{"~/.config/op", "secrets_manager", "1Password CLI session state.", true, true},
	{"~/.password-store", "secrets_manager", "pass (GPG) password store.", true, true},
	{"~/.gnupg", "secrets_manager", "GPG private keyring.", true, true},
	{"~/Library/Keychains/login.keychain-db", "secrets_manager", "macOS login keychain database (where Claude Code stores its OAuth token on macOS); the file is encrypted with your login password, so a copy is an offline-cracking target, not a token.", true, false},
	{"~/Library/Application Support/Google/Chrome/Default/Cookies", "browser", "Chrome session cookies.", true, false},
	{"~/Library/Application Support/Google/Chrome/Default/Login Data", "browser", "Chrome saved passwords database.", true, false},
	{"~/.config/google-chrome/Default/Cookies", "browser", "Chrome session cookies.", false, true},
	{"~/.mozilla/firefox", "browser", "Firefox profiles including cookies and logins.", false, true},
	{"~/Library/Application Support/Firefox/Profiles", "browser", "Firefox profiles including cookies and logins.", true, false},
	{"~/.zsh_history", "shell_history", "Shell history (often contains pasted secrets).", true, true},
	{"~/.bash_history", "shell_history", "Shell history (often contains pasted secrets).", true, true},
	{"~/.env", "env_file", "Home-directory dotenv file.", true, true},
}

// projectSensitiveNames are files looked for inside each known project.
var projectSensitiveNames = []struct {
	Name        string
	Category    string
	Description string
}{
	{".env", "env_file", "Project dotenv secrets."},
	{".env.local", "env_file", "Project dotenv secrets."},
	{".env.production", "env_file", "Project dotenv secrets."},
	{".envrc", "env_file", "direnv file, often exports secrets."},
	{"terraform.tfvars", "env_file", "Terraform variables, often secrets."},
	{".terraform/terraform.tfstate", "env_file", "Terraform state, contains secrets in plaintext."},
	{"terraform.tfstate", "env_file", "Terraform state, contains secrets in plaintext."},
}

// localService is a well-known localhost service to probe.
type localService struct {
	Port    int
	Service string
}

var localServiceCatalog = []localService{
	{5432, "postgres"}, {3306, "mysql"}, {6379, "redis"}, {27017, "mongodb"},
	{9200, "elasticsearch"}, {5984, "couchdb"}, {8086, "influxdb"}, {9092, "kafka"},
	{2375, "docker-tcp"}, {2376, "docker-tls"}, {10250, "kubelet"}, {6443, "kube-apiserver"},
	{8200, "vault"}, {8500, "consul"}, {11434, "ollama"}, {1234, "lm-studio"},
	{3000, "dev-server"}, {5000, "dev-server"}, {8000, "dev-server"}, {8080, "dev-server"},
	{9090, "prometheus"}, {9093, "alertmanager"}, {4000, "dev-server"}, {5173, "vite"},
	{7777, "local-service"}, {8888, "jupyter"}, {15672, "rabbitmq-mgmt"}, {5672, "rabbitmq"},
	{4566, "localstack"}, {9000, "minio"}, {3900, "garage"}, {8332, "bitcoind"},
}

// unixSocketCatalog lists privileged local sockets.
var unixSocketCatalog = []struct {
	Path    string
	Service string
	Darwin  bool
	Linux   bool
}{
	{"/var/run/docker.sock", "docker", true, true},
	{"~/.docker/run/docker.sock", "docker-desktop", true, false},
	{"~/.colima/default/docker.sock", "colima", true, false},
	{"~/.orbstack/run/docker.sock", "orbstack", true, false},
	{"/run/podman/podman.sock", "podman", false, true},
	{"/var/run/com.apple.securityd", "securityd", true, false},
	{"/tmp/.s.PGSQL.5432", "postgres", true, true},
	{"~/.1password/agent.sock", "1password-ssh-agent", true, true},
	{"~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock", "1password-ssh-agent", true, false},
	{"/var/run/tailscaled.socket", "tailscaled", true, true},
}

// categoryTier ranks sensitive categories by blast radius: 1 grants access to
// other systems outright, 2 is tokens and agent state, 3 is files that often
// leak secrets but are not credentials by design.
var categoryTier = map[string]int{
	"ssh": 1, "cloud_credential": 1, "secrets_manager": 1, "kube": 1,
	"vcs_credential": 2, "agent_credential": 2, "package_registry": 2,
	"env_file": 3, "shell_history": 3, "browser": 3,
}

// pathTier lowers the tier of catalog files whose category overstates what
// reading them gives: the file points at a credential or holds it encrypted.
// Keys are home-relative suffixes of the expanded path.
var pathTier = map[string]int{
	"/.aws/config":                         2, // profiles and roles; keys normally live in credentials
	"/.gitconfig":                          3, // names a helper; the token lives in the helper's store
	"/Library/Keychains/login.keychain-db": 2, // encrypted at rest with the login password
}

func tierFor(category, path string) int {
	for suffix, t := range pathTier {
		if strings.HasSuffix(path, suffix) {
			return t
		}
	}
	if t, ok := categoryTier[category]; ok {
		return t
	}
	return 3
}

// shortLivedCaches are catalog directories that hold credentials with a
// fixed maximum lifetime. AWS role sessions last at most 12 hours
// (DurationSeconds up to 43200), and the CLI writes a new entry when it
// refreshes one.
var shortLivedCaches = map[string]time.Duration{
	"/.aws/cli/cache": 12 * time.Hour,
}

// cacheNote says when every entry in a short-lived credential cache is
// older than the credentials can live. It reads modification times only.
// The location keeps its tier: the next CLI call writes fresh credentials.
func cacheNote(path string, now time.Time) string {
	var life time.Duration
	for suffix, d := range shortLivedCaches {
		if strings.HasSuffix(path, suffix) {
			life = d
		}
	}
	if life == 0 {
		return ""
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return ""
	}
	var newest time.Time
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	if newest.IsZero() {
		return " Empty now; the next AWS CLI call that assumes a role fills it."
	}
	if age := now.Sub(newest); age > life {
		return fmt.Sprintf(" Newest entry written %d day(s) ago and these credentials last at most %d hours, so they have likely expired; the next AWS CLI call that assumes a role writes fresh ones.", int(age.Hours()/24), int(life.Hours()))
	}
	return ""
}
