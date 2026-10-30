# Run agentreach in CI

agentreach is a composite action. It downloads a release binary, verifies its
checksum, scans the runner, uploads the SARIF report to GitHub code scanning,
and then fails the step with agentreach's own exit code.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@<pinned-sha>

  - uses: somoore/steampipe-plugin-agentreach@v0.2.0
    with:
      fail-on: auto
```

A copy of this workflow is in [examples/github-actions.yml](../examples/github-actions.yml).

## What gets scanned

The runner's own home directory, exactly like `agentreach scan` on a laptop.
A GitHub-hosted runner has no coding agent installed, so it finds nothing and
exits 0. The action is useful on:

- a self-hosted runner where developers actually run agents
- a job that installs the agent first
- a job that passes a project directory in `args`, for example
  `args: "$GITHUB_WORKSPACE"`

## Inputs

| Input | Default | Meaning |
|-------|---------|---------|
| `version` | `v0.2.0` | Release tag to download. |
| `fail-on` | `auto` | Fail on paths at or below this gate: `auto`, `classifier`, `prompt` or `never`. |
| `args` | empty | Extra arguments for `agentreach scan`, such as a project directory. |

## Outputs

| Output | Meaning |
|--------|---------|
| `sarif` | Path to the SARIF file that was uploaded. |
| `exit-code` | agentreach's exit code: 0 clean, 1 failing findings, 2 not fully assessed. |

## Exit codes

The action fails the step when agentreach exits non-zero. `2` means the scan
could not assess everything it needed, which is different from a finding: the
SARIF report says which control came back not assessed.

To keep the scan non-blocking while still uploading results, set
`continue-on-error: true` on the step.

## Without GitHub Actions

Any CI can run the binary and keep the SARIF file:

```bash
curl -fsSLo agentreach.tgz \
  "https://github.com/somoore/steampipe-plugin-agentreach/releases/download/v0.2.0/agentreach_0.2.0_linux_amd64.tar.gz"
curl -fsSLo checksums.txt \
  "https://github.com/somoore/steampipe-plugin-agentreach/releases/download/v0.2.0/checksums.txt"
grep " agentreach_0.2.0_linux_amd64.tar.gz\$" checksums.txt | sha256sum -c -
tar -xzf agentreach.tgz
./agentreach scan --format sarif --out agentreach.sarif --fail-on auto
```

The release also carries GitHub build provenance. Verify it with the GitHub
CLI, which checks that this repository's release workflow built the file:

```bash
gh attestation verify agentreach_0.2.0_linux_amd64.tar.gz \
  --repo somoore/steampipe-plugin-agentreach
```
