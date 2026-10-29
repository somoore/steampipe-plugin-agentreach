# Contributing

agentreach is a read-only posture scanner: it never writes, never sends
anything, never runs an agent, and never stores a secret value. If your
change breaks any of those, it will not merge.

## The short version

1. Fork, branch, PR. `main` requires the CI checks to pass; the repository
   owner reviews everything (CODEOWNERS).
2. `make test` must pass locally before you push (gofmt, vet, `go mod
   verify`, standards + unit tests). The standards tests check table and
   column naming, docs and struct/column agreement - read their failures,
   they are precise.
3. A security issue is never a public issue or PR: use
   **Security → Report a vulnerability** (see SECURITY.md).

## Adding agent behaviour

Every fact the collector reports carries its evidence type (configured /
observed / inferred / unknown) and cites the vendor document it follows.
A new behaviour needs: the doc citation in a comment, the logic in the
matching collector, a fixture scenario in `cmd/agentreach-fixtures` that
reaches it, and a test. The conventions are enforced by the standards
tests: read their failures, they are precise.

## Adding a control (the mod lives in
[steampipe-mod-agentreach-compliance](https://github.com/somoore/steampipe-mod-agentreach-compliance))

Controls are atomic, deterministic and never fix anything. The mod's
repository has its own CONTRIBUTING with the fixture workflow.
