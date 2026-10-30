STEAMPIPE_INSTALL_DIR ?= ~/.steampipe
BUILD_TAGS = netgo

.PHONY: install build test test-srt fmt vet hooks snapshot cli secrets check-claude-code docs-drift docs-baseline security live-check live-check-install live-check-uninstall

install:
	go build -o $(STEAMPIPE_INSTALL_DIR)/plugins/local/agentreach/agentreach.plugin -tags "$(BUILD_TAGS)" *.go

build: install

# Fail if any file is not gofmt-clean, listing the offenders.
fmt:
	@files=$$(gofmt -l .); \
	if [ -n "$$files" ]; then echo "gofmt needed:"; echo "$$files"; exit 1; fi

vet:
	go vet ./...

# `make test` runs everything: format check, vet, module verification,
# standards + unit tests. `go mod verify` checks the module cache against
# go.sum, the pinned dependency hashes.
test: fmt vet
	go mod verify
	go test ./...

# Build the standalone CLI into ./bin/agentreach.
cli:
	go build -o bin/agentreach ./cmd/agentreach

# Behavioural tests: the inert probes inside a real srt
# (@anthropic-ai/sandbox-runtime), against fixture homes only.
# make test-srt SRT=/path/to/srt
SRT ?= $(shell command -v srt)
test-srt:
	@if [ -z "$(SRT)" ]; then echo "srt not found: npm install @anthropic-ai/sandbox-runtime, then make test-srt SRT=<path>"; exit 1; fi
	AGENTREACH_SRT="$(SRT)" go test ./pkg/posture/ -run 'TestSRT' -count=1 -v

# Secret scan: credential-shaped files, secret-shaped strings, gitleaks over
# history and tree. Prints file names only.
secrets:
	./ci/secrets.sh

# Dump the raw posture snapshot as JSON without Steampipe (library smoke test).
snapshot:
	go run ./cmd/agentreach-snapshot

# Point git at the versioned hooks dir so pre-commit runs `make test`.
hooks:
	@git config core.hooksPath ci/hooks
	@chmod +x ci/hooks/*
	@echo "git core.hooksPath -> ci/hooks (pre-commit active)"

# Read auto mode's rule-drop list from a Claude Code binary, cli.js or npm
# package directory and fail if it differs from the built-in fallback.
#   make check-claude-code CLAUDE=$$(readlink -f $$(which claude))
check-claude-code:
	AGENTREACH_CLAUDE_BIN=$(CLAUDE) go test ./pkg/posture/ -run TestAutoDropDrift -v -count=1

# Drift alarm: fail when any Claude Code document the behaviour model cites
# changed content (weekly CI runs this; see ci/docs_drift.sh).
docs-drift:
	./ci/docs_drift.sh

# Refresh the cited-document hashes after re-verifying the model against
# changed docs.
docs-baseline:
	./ci/docs_drift.sh --update

# Security scan: dependency vulnerabilities (govulncheck) and the gosec
# linter over the collector, CLI and plugin layer. Versions are pinned.
#
# gosec exclusions, deliberate and reviewed:
#   G304/G703 (file inclusion / path traversal via a variable): reading
#   agent configuration at discovered paths is the product. The collector
#   is read-only: it never writes to a discovered path, never dials a host
#   that came from configuration (network probes target the local listener
#   table only, wildcard binds normalized to 127.0.0.1), and never stores
#   file contents: names, sizes, booleans and redacted text only.
# Site-level exceptions carry a #nosec comment where they apply.
GOSEC_VERSION ?= v2.30.0
GOVULN_VERSION ?= v1.9.0
security:
	go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -quiet -tests=false \
	  -exclude=G304,G703 ./pkg/posture/... ./agentreach/... ./cmd/agentreach/...
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULN_VERSION) ./...

# Live check: scan this machine with the installed release, keep a dated
# report and print what changed since the previous run. Fixtures prove the
# model; this catches a new agent release that changed behaviour.
live-check:
	./tools/live-check.sh

# Schedule it monthly with launchd (first of the month, 09:17).
live-check-install:
	./tools/install-live-check.sh

live-check-uninstall:
	./tools/install-live-check.sh --uninstall
