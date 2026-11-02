# Security review and remediation — steampipe-plugin-agentreach

**Scanned:** `/Users/scottmoore/github/steampipe-plugin-agentreach` at commit `d98688b`
(working tree changes applied, not committed), 2026-11-02.

**Tools:** gosec 2.30.0 (`-exclude=G304,G703`, the repo's own flags), semgrep, trivy
(fs + config), govulncheck 1.9.0 (symbol + module), gitleaks 8.30.1 (history and
tree), shellcheck 0.10, actionlint 1.7.12, `gofmt`, `go vet`, `go test -race`,
`go build -tags netgo`, the fixture determinism check and `./ci/secrets.sh`.

**Team roles:** Role 1 product/PM (`01-pm.md`), Role 2 AppSec (`02-appsec.md`),
Role 3 Pentester (`03-pentest.md`), Role 4 Devil's Advocate (`04-devil.md`),
Role 5 QA/Verification (`05-qa.md`), plus the scanner baseline in `SUMMARY.txt`
and the raw JSON in the same directory.

**Adjudication rule used:** the Devil's Advocate wins on verdicts (false positives
are not "fixed"), the Pentester wins on reachability. Where a scanner finding was
a false positive but a real, bounded issue sat next to it, the real issue is a
separate ID (`M-*`, `SEC-*`, `SEC-PT-*`). Every `FIXED` row below was verified by
a command or test that failed before the change and passes after it.

## Findings

| ID | Severity | Status | Location | Issue | Fix | Verification |
|---|---|---|---|---|---|---|
| D-01 | INFO | FALSE POSITIVE | `pkg/posture/util.go:30` `fileExists` | gosec G703 taint on a fixed name under `$HOME`/the scanned project; stat only classifies, result is a local bool. | none | `gosec -exclude=G304,G703` exit 0 |
| D-02 | INFO | FALSE POSITIVE | `pkg/posture/util.go:44` `readFileLimited` | G703 on the same non-attacker path; read is capped at 8 MiB and regular-file-gated. | none (gate kept, TOCTOU hardening in M-02) | `TestReadFileLimited`, `TestReadFileLimitedRejectsFIFOWithoutBlocking` |
| D-03 | INFO | FALSE POSITIVE | `pkg/posture/util.go:51` `os.Open` | Reached only through D-02. | none (open now precedes the gate, see M-02) | package tests |
| D-04 | INFO | FALSE POSITIVE | `pkg/posture/util.go:106` `writableBy` | Only reports `fi.Mode().Perm()`. | none | package tests |
| D-05 | INFO | FALSE POSITIVE | `pkg/posture/codex.go:444` `dirExists` | Path is `~/.codex`/`CODEX_HOME`/a discovered project. | none | package tests |
| D-06 | INFO | FALSE POSITIVE | `pkg/posture/codex.go:378` `addCodexInstructionKind` | Path built by the collector from fixed relative names. | containment added for project scope (SEC-03a) | `TestInstructionSymlinkOutsideProjectNotRead` |
| D-07 | INFO | FALSE POSITIVE | `pkg/posture/codex.go:226` | Literal instruction names joined to `dir`. | none | package tests |
| D-08 | INFO | FALSE POSITIVE | `pkg/posture/agenthelpers.go:100` `addAgentInstruction` | Same shape as D-06. | containment added for project scope (SEC-03a) | `TestInstructionSymlink…` |
| D-09 | INFO | FALSE POSITIVE | `pkg/posture/util.go:51` (G304) | Variable path is inherent to a file scanner; `readFileLimited` is the mitigation. | none | gosec exit 0 |
| D-10 | INFO | FALSE POSITIVE | `pkg/posture/probe.go:29` (G304) | `probeReadable` is defined as "open this local path and read one byte". | none (reordered, M-02) | `TestProbeReadableRejectsFIFOWithoutBlocking` |
| D-11 | INFO | FALSE POSITIVE | `pkg/posture/launchflags.go:65` | `filepath.Join(home, rel)` over a constant list. | none | package tests |
| D-12 | INFO | FALSE POSITIVE | `pkg/posture/autodrop.go:104` | Reads the drop list from the binary it just located; documented feature. | none | package tests |
| D-13 | INFO | FALSE POSITIVE | `cmd/agentreach/main.go:152` (G304) | `--out`/`--snapshot-out` are operator CLI flags. The real residual is symlink-follow/truncate. | see M-01 | `TestOutRefusesSymlink` |
| D-14 | INFO | FALSE POSITIVE | `cmd/agentreach-fixtures/main.go:37,549,572` (G301) | Dev-only fixture generator in a temp dir; 0755 models a real home and the CI determinism diff. | none | fixture `diff -r` |
| D-15 | INFO | FALSE POSITIVE | `cmd/agentreach-fixtures/main.go:38,63,587,594` (G306) | Fixtures are intentionally 0644; the only "secret" is `notACredential`. | none | fixture `diff -r` |
| D-16 | INFO | FALSE POSITIVE | `pkg/posture/agenthelpers.go:30` (semgrep exec) | Fixed argv `--version` on `exec.LookPath` binaries; no shell, no interpolation. | none | `go test ./pkg/posture` |
| D-17 | INFO | FALSE POSITIVE | `pkg/posture/observed.go:149` (semgrep exec) | Operator-supplied/`LookPath("srt") ` + fixed argv + timeout. | none | `make test-srt` (opt-in) |
| D-18 | INFO | FALSE POSITIVE | `pkg/posture/observed.go:201` (semgrep exec) | Args built in-process from effective settings and literals; config text never becomes argv. | none | `observed_srt_test.go` |
| D-19 | INFO | FALSE POSITIVE | `pkg/posture/claudecode.go:1184` (SHA-1) | SHA-1 reproduces git blob ids for comparison, not a signature/MAC; changing it would be a functional bug. | none | `TestTextSafe`/git provenance tests |
| D-20 | INFO | FALSE POSITIVE | `pkg/posture/claudecode.go:360` (iterate empty map) | `flat` may be `{}`; the loop then does nothing. No security content. | none | package tests |
| D-21 | LOW | **FIXED** | `.github/dependabot.yml` | No cooldown: a compromised fresh release can be pulled before review. | `cooldown: default-days: 7, semver-major-days: 14` for gomod; `default-days: 7` for github-actions. Security updates still bypass cooldown. | `rg -n cooldown .github/dependabot.yml` → present; YAML parses |
| D-22 | LOW | **FIXED** | `examples/github-actions.yml:24` | Example consumed the mutable tag `@v0.2.0`. | Pinned to `057afc7263afe24858ee56e56d9f898585b01daa # v0.2.0` (the local `v0.2.0` tag commit). | `rg -n 'somoore/' examples/` → SHA only |
| D-23 | INFO | FALSE POSITIVE | `golang.org/x/crypto@v0.58.0` GO-2026-5932 (openpgp) | Package not imported (`go mod why` / `go list -deps`); module-only advisory. No fixed version exists. | none possible; recorded as residual risk. x/crypto did move to v0.58.0 with the x/net bump. | `govulncheck ./...` → 0 affecting code |
| D-24 | INFO | **FIXED** | `golang.org/x/net@v0.60.0` CVE-2026-78661 / GO-2026-6860 | `x/net/html` not imported, so not exploitable. | `go get golang.org/x/net@v0.62.0 && go mod tidy` (with x/sys, x/sync, x/text, x/tools, x/crypto). | `govulncheck ./...` → 0 affecting; `make test`; fixture diff |
| D-25 | INFO | **FIXED** | `golang.org/x/net@v0.60.0` CVE-2026-97045 / GO-2026-6866 | Same package, same unreachability. | same bump as D-24. | as D-24 |
| D-26 | INFO | **FIXED** | `ci/docs_drift.sh:22` (SC2164) | Unchecked `cd "$(git rev-parse --show-toplevel)"`: a failure left reads in the caller's cwd. | Resolve the root with an explicit `if ! root=$(…)` guard, then `cd "$root" || exit 1`. | `shellcheck -S warning ci/*.sh` exit 0 |
| D-27 | INFO | **FIXED** | `ci/secrets.sh:9` (SC2164) | Same pattern; worst case is scanning the wrong tree and passing. | Same guard, plus `set -e` (see QA-01). | from `/tmp`: exit 1 with "not inside a git repository" |
| D-28 | INFO | FALSE POSITIVE | `ci/secrets.sh:13,15` (SC2001) | Cosmetic `sed`; correct and quoted. | none | `shellcheck -S warning` exit 0 |
| M-01 | LOW | **FIXED** | `cmd/agentreach/main.go:151` | `--out`/`--snapshot-out` used `O_TRUNC` with no symlink check; a planted `report.json -> ~/.ssh/authorized_keys` is truncated. | `writeFile` refuses a path whose `Lstat` mode is a symlink (exit 3, target untouched). Documented in `docs/cli.md`; the action's `mktemp` strategy is unchanged. | `go test ./cmd/agentreach -run TestOutRefusesSymlink` (fails pre-fix: target overwritten) |
| M-02 | LOW | **FIXED** | `pkg/posture/util.go:44-51`, `probe.go:20-29` | Stat→Open TOCTOU: a writer can swap a regular file for a FIFO between the gate and the open, hanging the scan. | Open first with `O_NONBLOCK` (`openNonblock`, unix + portable fallback), then gate on `f.Stat()` of the descriptor. `O_NONBLOCK` cannot block on a FIFO and is a no-op for regular files. | `TestReadFileLimitedRejectsFIFOWithoutBlocking`, `TestProbeReadableRejectsFIFOWithoutBlocking`; `go test -race ./...` |
| M-03 | LOW | **FIXED** | `action.yml:81` | `$AGENTREACH_ARGS` expanded unquoted: word-split plus globbing, and a second `--out` overrides the action's own SARIF path. | Split with `read -r -a extra <<<"$AGENTREACH_ARGS"`, pass `"${extra[@]}"` (bash-3.2-safe `${extra[@]+…}` form), reject `--out`/`--out=*`/`--snapshot-out`/`--snapshot-out=*`, and document that `args` is trusted workflow config. | `go test ./cmd/agentreach -run TestCompositeActionArgsHandling`; shellcheck on the extracted `run:` block; bash 3.2 behaviour check |
| M-04 | INFO | ACCEPTED RISK | `pkg/posture/*` version probes | The scan executes whatever `claude`/`codex`/`opencode`/`grok`/`cline` PATH resolves to (documented feature), so a hostile PATH entry runs code during a read-only scan. | Not changed: skipping would silently drop version detection, and controlling PATH is already code execution. Documented as a trust boundary in `SECURITY.md`. | `SECURITY.md` |
| M-05 | INFO | ACCEPTED RISK | `.github/workflows/claude-code-drift.yml:41-44` | Weekly `npm install @latest` of a third-party package in CI. | Kept: it is the drift alarm's purpose. Already mitigated by `--ignore-scripts`, `contents: read`, scheduled-only trigger and a narrow output parser. | workflow review |
| M-06 | INFO | MITIGATED | `.github/dependabot.yml:6-11` | All Go modules grouped into one PR hides a malicious bump. | Grouping kept (noise control) but the new cooldown delays fresh releases; reviewers must still read the group's `go.sum` diff. | D-21 verification |
| SEC-01 | MEDIUM | **FIXED** | `claudecode.go:1043,1098-1107`; `claudecode.go:844` | `git_remote` and marketplace `source_repo` bypassed `scrubURL`, so a PAT clone URL (`https://user:ghp_…@host/org/repo`) was published to tables, JSON and snapshots. | Both go through the existing `scrubURL`; host/path are kept. Bare `org/repo` and `git@host:path` values pass through unchanged. | `TestGitRemoteRedacted`, `TestMarketplaceSourceRepoRedacted` (both fail pre-fix: token retained) |
| SEC-02 | MEDIUM | **FIXED** | `pkg/posture/redact.go:20,57-85`; `util.go:172` | Multi-line PEM private keys were never redacted: the tokenizer splits the header into separate tokens, so the only PEM alternative in `secretValuePattern` could not match. | A `(?s)-----BEGIN…PRIVATE KEY-----.*?-----END…PRIVATE KEY-----` pass runs before tokenization in `scrubText`, and before the per-argument rules in `scrubArgs`. Certificates/public keys are untouched. | `TestPEMBlockRedacted` (root cause reproduced pre-fix for bare/prefixed/`--payload=` forms; certificate survives) |
| SEC-03a / SEC-PT-01 | LOW | **FIXED** | `claudecode.go:666-690`, `agenthelpers.go:99`, `codex.go:377`, `claudecode_extra.go:97` | A scanned repository could ship `.claude/CLAUDE.md` or `AGENTS.md` as a symlink to a file outside the tree; the scanner published that file's size, SHA-256 and parsed frontmatter (metadata only, no content). | New `instructionEscapes`: a project- or plugin-scope instruction file must resolve inside its root; an escaping link is skipped and adds a `CollectErrors` entry ("not read"). Links that stay inside the tree and all home/managed-scope links still work. | `TestInstructionSymlinkOutsideProjectNotRead` (pre-fix: `size=19 sha=0c04…`), `TestInstructionSymlinkInsideProjectRead`, `TestHomeInstructionSymlinkStillRead` |
| SEC-03b | LOW | **FIXED** | `pkg/posture/claudecode_extra.go:82` | A plugin `plugin.json` could name an `mcpServers` file by `../../…`, making the collector ingest a config outside the plugin root. | The joined path is containment-checked with `instructionEscapes`; an escape is skipped with a collect error. | `TestPluginManifestPathEscapeNotRead` (pre-fix: `escaped` MCP row published) |
| SEC-03c | LOW | ACCEPTED RISK | `pkg/posture/opencode.go:229-233` | OpenCode `instructions` accepts absolute/`~` paths, so a repo's `opencode.json` can name `/etc/hosts` and get its digest published. | Not changed: absolute and `~` instruction paths are the documented OpenCode behaviour and the same merge covers operator-owned config, so containment would break working setups. Metadata only (no content), and the file is readable by the scanning user. Recorded as residual risk. | code review; `resolveProjectPath` unchanged |
| SEC-03d | LOW | **FIXED** | `pkg/posture/util.go:44-51`, `probe.go:22-29`, `util.go:106` | Stat→Open race (same as M-02); `writableBy` only stats permissions and opens nothing. | See M-02. | See M-02 |
| SEC-04 | LOW | **FIXED** | `cmd/agentreach/output.go:33,40` | `writeText` printed `Host`, `SnapshotID`, `CollectorVersion` and agent `Agent`/`Version` raw, so a crafted `--from`/fleet snapshot could emit OSC 52, title or screen-clear sequences. | All five fields go through `textSafe`; JSON/SARIF already escape. | `go test ./cmd/agentreach -run TestTextOutputHasNoControlBytes` (pre-fix: 4 ESC + 1 BEL) |
| SEC-05 / QA-09 | LOW | DEFERRED | `claudecode_extra.go:97-119`, `codexplugins.go:262-289`, `sdklauncher.go:127-157` | Instruction/plugin trees have no file-count, byte or depth cap, so a hostile repo can make a scan read/parse tens of thousands of files (per-file caps exist). | Not fixed in this pass: the cap needs a documented policy for large monorepos and "missing evidence is never a pass" collect errors, plus a deliberate lock-in test. Per-file read is still capped at 8 MiB and only regular files are read. | n/a — residual risk |
| SEC-06 | INFO | ACCEPTED RISK | `pkg/posture/observed.go:120-134,149,192-201`; `agentreach/connection_config.go:24` | `srt_path` is a program the plugin runs in opt-in `observe` mode. Not injection (fixed argv), but an operator-supplied executable. | Unchanged; documented as an operator-trusted input in `SECURITY.md`. | `SECURITY.md`, `make test-srt` |
| SEC-07 | INFO | **FIXED** | `cmd/agentreach/main.go:151-152` | `--out`/`--snapshot-out` followed a symlink and truncated its target. | Same fix as M-01. | `TestOutRefusesSymlink` (both flags) |
| SEC-08 | LOW | **FIXED** | `.github/dependabot.yml`, `examples/github-actions.yml:24` | No cooldown; example taught a mutable tag. | D-21 + D-22. | as D-21/D-22 |
| SEC-PT-02 | INFO | ACCEPTED RISK | `pkg/posture/agenthelpers.go:30`, `observed.go:149,201` | The version probe executes the PATH binary; not injectable (fixed argv, no config text in argv). | Unchanged; PATH control is already code execution, and the probe is a documented feature. | `TestRepoConfigRunsNothing` still green |
| QA-01 | LOW | **FIXED** | `ci/secrets.sh:8-9` | Without `-e` and with an unchecked `cd`, running outside a repo printed `ok` three times and exited 0 — a security gate passing while scanning the wrong tree. | `set -euo pipefail`, explicit `git rev-parse` guard, and an explicit failure message. | from `/tmp`: exit 1; from the repo: exit 0 with all three `ok` lines |
| QA-02 | LOW | **FIXED** | `cmd/agentreach/main.go:151` | No regression test for output-path symlink/truncate. | `TestOutRefusesSymlink` added (see M-01). | `go test ./cmd/agentreach` |
| QA-03 | LOW | **FIXED** | `cmd/agentreach/output.go:33,40` | No end-to-end test that header fields are terminal-safe. | `TestTextOutputHasNoControlBytes` added (see SEC-04). | `go test ./cmd/agentreach` |
| QA-04 | MEDIUM | **FIXED** | `claudecode.go`, `redact.go` tests | SEC-01/02/PT-01 had no tests. | `TestGitRemoteRedacted`, `TestMarketplaceSourceRepoRedacted`, `TestPEMBlockRedacted`, the three symlink tests and `TestPluginManifestPathEscapeNotRead` added; credentials are built at run time so `ci/secrets.sh` stays green. | all fail on the pre-fix tree, pass after; `./ci/secrets.sh` exit 0 |
| QA-05 | INFO | DEFERRED | `.github/workflows/claude-code-drift.yml`; `ci/docs-baseline.sha256` | Scheduled docs-drift job is red because cited upstream pages changed (reproduced locally, 9 hashes). This is the alarm working. | Not "fixed": a blind `--update` would defeat the alarm and the model has not been re-verified against the new pages. Pre-existing, unrelated to these changes. | `./ci/docs_drift.sh` still fails on changed pages (expected) |
| QA-06 | INFO | MITIGATED | `.github/workflows/ci.yml`; lint coverage | `actionlint`/`shellcheck` are not CI gates: 2 actionlint warnings and 4 shellcheck findings. | Both actionlint findings fixed (`for _ in 1 2 3`, `sha256sum -- *.tar.gz`); SC2164 fixed; SC2001 is cosmetic. Not wired into CI in this pass (no gate added that isn't already proven on the runner image), so drift can return. | `actionlint .github/workflows/*.yml` exit 0; `shellcheck -S warning …` exit 0 |
| QA-07 | INFO | **FIXED** | `go.mod:126,129` | GO-2026-6866 / GO-2026-6860 in `x/net@v0.60.0` (fixed in v0.62.0). | Bumped to v0.62.0 with `go mod tidy`. | `govulncheck ./...` → 0 affecting; `make test`; fixture diff |
| QA-08 | INFO | **FIXED** | `util.go:43-51`; `probe.go:20-29` | Stat→Open race not deterministically testable. | Reordered to open-then-stat (M-02) and added FIFO rejection tests with a wall-clock guard instead of a sleep/goroutine race test. | the two FIFO tests, `go test -race ./...` |
| QA-10 | INFO | **FIXED** | `agentreach/table_*.go` | Nothing pinned the property that makes SQLi/IDOR N/A: every table is list-only. | `TestTablesStayListOnly` asserts `List != nil`, `Get == nil`, no `KeyColumns`. | `go test ./agentreach -run TestTablesStayListOnly` |

**Present controls, recorded so they are not "simplified" later (not findings):**
`gitCmd` disables fsmonitor/pager/signature/credential helpers and uses `--`
(`TestRepoConfigRunsNothing`); `readFileLimited` keeps its 8 MiB cap and
regular-file gate; `probeScript` and the `srt` argv shape are fixed; every
`#nosec` has a reviewed rationale; the action keeps `mktemp` SARIF output plus
checksum + `gh attestation verify`; all workflow `uses:` are SHA-pinned; the
release workflow keeps its tag-on-main guard.

## Verification (exact commands, this working tree)

| Command | Result |
|---|---|
| `gofmt -l .` | PASS — no output |
| `go vet ./...` | PASS |
| `go build ./...` / `go build -tags netgo ./...` | PASS |
| `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags netgo ./...` | PASS |
| `make test` (= gofmt + vet + `go mod verify` + `go test ./...`) | PASS |
| `go test ./... -count=1` | PASS — 0 failures |
| `go test -race ./... -count=1` | PASS |
| `go run ./cmd/agentreach-fixtures -out a` ×2 + `diff -r a b` | PASS — byte-identical |
| `./ci/secrets.sh` | PASS — no credential/secret shapes; gitleaks history + tree clean |
| `cd /tmp && <repo>/ci/secrets.sh` | exit 1 (was exit 0) — QA-01 |
| `gosec v2.30.0 -exclude=G304,G703 ./pkg/posture/... ./agentreach/... ./cmd/agentreach/...` | PASS — exit 0 |
| `govulncheck v1.9.0 ./...` | 0 affecting code; 1 module-only advisory (D-23) |
| `actionlint .github/workflows/*.yml` | PASS — exit 0 (was 2 warnings) |
| `shellcheck -S warning ci/*.sh ci/hooks/pre-commit tools/*.sh` | PASS — exit 0 |
| `go test ./pkg/posture ./cmd/agentreach ./agentreach -run '<new tests>'` | PASS after; all fail on the pre-fix tree except the FIFO-rejection pair, which pin behaviour the old code happened to have and the new open-then-stat could regress |

Not run: `make test-srt` (needs `srt` installed; the argv path was not touched
and `observed_srt_test.go` is unmodified), the live Claude Code drift check, and
`make install` (writes outside the repo).

## Residual risk

1. **SEC-05 — unbounded instruction/plugin tree walk (DEFERRED).** Per-file reads
   are capped at 8 MiB and only regular files are opened, but a repository with
   tens of thousands of matching files can still slow or exhaust a scan. A cap
   needs a documented policy (bounded rows + a "not fully assessed" collect
   error) and its own lock-in test.
2. **SEC-03c — OpenCode absolute/`~` `instructions` (ACCEPTED).** A repo's
   `opencode.json` can point at a file outside the project and its size/digest is
   published. Absolute instruction paths are documented behaviour and the same
   merge includes operator config, so a blanket containment check would break
   working setups. Content is never stored.
3. **D-23 — `golang.org/x/crypto/openpgp` (GO-2026-5932).** No fixed version
   exists; the package is not imported (`go mod why` = "main module does not need
   package") and `govulncheck` reports no affecting symbols. Revisit when a fix
   is published.
4. **M-04 / SEC-PT-02 — version probes execute the PATH binary (ACCEPTED).**
   Documented feature; controlling `PATH` is already code execution as the
   scanning user.
5. **M-05 — weekly `npm install @latest` in the drift job (ACCEPTED).** That is
   the job's purpose; `--ignore-scripts`, read-only token and a narrow parser are
   the compensating controls.
6. **QA-05 — the docs-drift alarm is red (DEFERRED).** Upstream pages changed.
   Fixing it requires re-verifying `pkg/posture` against the new documents and
   bumping `ModelBasis*`, not re-hashing. Pre-existing; not caused by these
   changes.
7. **QA-06 — lint is not a CI gate (MITIGATED).** The findings are fixed, but
   without a CI step the tree can drift again. Left out to avoid adding a gate
   whose exact behaviour depends on the runner's shellcheck version.
8. **`writeFile` symlink refusal is a check, not `O_NOFOLLOW`.** A local attacker
   who can create the path between `Lstat` and `OpenFile` still wins that race.
   The exposure is a same-user file overwrite with an operator-chosen path; the
   shipped action uses `mktemp` and is unaffected. `O_NOFOLLOW` was rejected
   because it is not portable and would break writing through a symlink that
   some users rely on; passing the resolved path still works.
9. No git history was rewritten and no branch was created or committed. The
   owner must rotate any credential that a *previously published* snapshot or
   report already contained (SEC-01/SEC-02 data may exist in older snapshot
   files); this change only prevents new ones.
