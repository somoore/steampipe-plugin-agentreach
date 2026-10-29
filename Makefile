STEAMPIPE_INSTALL_DIR ?= ~/.steampipe
BUILD_TAGS = netgo

.PHONY: install build test test-srt fmt vet hooks snapshot cli secrets check-claude-code docs-drift docs-baseline

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
# changed docs and bumping ModelBasis* in pkg/posture/modelbasis.go.
docs-baseline:
	./ci/docs_drift.sh --update
