# =============================================================================
# AegisOps AI — developer entrypoint
#
# `make` with no target prints the catalogue.
#
# NOTE ON PATHS: every path here is relative to the repository root. This
# project directory contains spaces and an em-dash, and GNU Make cannot quote
# $(CURDIR) safely in prerequisites or `include`. Relative paths sidestep the
# problem entirely — do not "improve" these into absolute ones.
# =============================================================================

MODULE      := github.com/bishal05das/aegisops-ai
BIN_DIR     := bin
COMPOSE_FILE := deployments/compose/docker-compose.yml

# Prefer a real .env; fall back to the committed example so a fresh clone works.
ENV_FILE := $(shell [ -f .env ] && echo .env || echo .env.example)

# Sourcing rather than `include`: .env carries inline comments that Make would
# swallow into the value, whereas the shell terminates the word at ` #`.
LOAD_ENV := set -a; . ./$(ENV_FILE); set +a;

COMPOSE := docker compose -f $(COMPOSE_FILE) --env-file $(ENV_FILE)

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X '$(MODULE)/internal/version.Version=$(VERSION)' \
	-X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
	-X '$(MODULE)/internal/version.BuildDate=$(BUILD_DATE)'

GO       ?= go
GOFLAGS  ?=
SVC      ?=

.DEFAULT_GOAL := help
.PHONY: help env gen-secret tidy fmt fmt-check vet lint test test-race cover \
        build clean run run-check preflight preflight-json preflight-wait \
        dev-up dev-up-ollama dev-down dev-restart dev-ps dev-logs dev-clean dev-reset \
        psql redis-cli rabbit-ui ci verify

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------

## help: show this catalogue
help:
	@echo "AegisOps AI — $(VERSION)"
	@echo ""
	@echo "Environment"
	@grep -E '^## (env|gen-secret|dev-|preflight|psql|redis-cli|rabbit-ui)' $(MAKEFILE_LIST) \
		| sed 's/^## /  /' | sort
	@echo ""
	@echo "Code"
	@grep -E '^## (tidy|fmt|vet|lint|test|cover|build|clean|run|ci|verify)' $(MAKEFILE_LIST) \
		| sed 's/^## /  /' | sort
	@echo ""
	@echo "Active env file: $(ENV_FILE)"

## env: create .env from .env.example (never overwrites an existing one)
env:
	@if [ -f .env ]; then \
		echo ".env already exists — leaving it alone"; \
	else \
		cp .env.example .env && echo "created .env from .env.example"; \
		echo "next: make gen-secret"; \
	fi

## gen-secret: print a cryptographically random JWT secret (384 bits)
gen-secret:
	@head -c 48 /dev/urandom | base64 | tr -d '\n'; echo
	@echo "# paste into .env as AEGIS_JWT_SECRET" >&2

# -----------------------------------------------------------------------------
# Code quality
# -----------------------------------------------------------------------------

## tidy: sync go.mod/go.sum
tidy:
	$(GO) mod tidy

## fmt: rewrite sources with gofmt
fmt:
	gofmt -w -s .

## fmt-check: fail if any file is unformatted (used by CI)
fmt-check:
	@unformatted=$$(gofmt -l -s .); \
	if [ -n "$$unformatted" ]; then \
		echo "these files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi; \
	echo "gofmt: clean"

## vet: run go vet across all packages
vet:
	$(GO) vet ./...

## lint: run golangci-lint if installed, otherwise fall back to vet
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed — falling back to go vet"; \
		echo "install: https://golangci-lint.run/welcome/install/"; \
		$(GO) vet ./...; \
	fi

## test: run unit tests
test:
	$(GO) test $(GOFLAGS) ./...

## test-race: run unit tests under the race detector
test-race:
	$(GO) test -race -count=1 ./...

## cover: produce coverage.out and a browsable coverage.html
cover:
	$(GO) test -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@$(GO) tool cover -func=coverage.out | tail -1
	@echo "report: coverage.html"

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------

## build: compile every binary in cmd/ into bin/
build:
	@mkdir -p $(BIN_DIR)
	@for pkg in $$(ls cmd); do \
		if ls cmd/$$pkg/*.go >/dev/null 2>&1; then \
			echo "building $$pkg"; \
			$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$$pkg ./cmd/$$pkg || exit 1; \
		fi; \
	done
	@ls -1 $(BIN_DIR)

## run: start aegisopsd against the local dev stack
run:
	@$(LOAD_ENV) $(GO) run -ldflags "$(LDFLAGS)" ./cmd/aegisopsd

## run-check: validate the configuration and exit without serving
run-check:
	@$(LOAD_ENV) $(GO) run ./cmd/aegisopsd -check

## clean: remove build and coverage output
clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------

## preflight: verify every dependency is reachable and speaking its protocol
preflight:
	@$(LOAD_ENV) $(GO) run ./cmd/preflight

## preflight-wait: same, but retry for up to 60s while the stack boots
preflight-wait:
	@$(LOAD_ENV) $(GO) run ./cmd/preflight -wait 60s

## preflight-json: machine-readable preflight report
preflight-json:
	@$(LOAD_ENV) $(GO) run ./cmd/preflight -json

# -----------------------------------------------------------------------------
# Development stack
# -----------------------------------------------------------------------------

## dev-up: start the stack and block until preflight is green
dev-up:
	$(COMPOSE) up -d --wait
	@echo ""
	@$(MAKE) --no-print-directory preflight-wait

## dev-up-ollama: also start a containerised Ollama on port 11435
dev-up-ollama:
	$(COMPOSE) --profile ollama up -d --wait

## dev-down: stop the stack, keeping data volumes
dev-down:
	$(COMPOSE) down

## dev-restart: restart one service — make dev-restart SVC=postgres
dev-restart:
	@test -n "$(SVC)" || { echo "usage: make dev-restart SVC=<service>"; exit 2; }
	$(COMPOSE) restart $(SVC)

## dev-ps: show container status
dev-ps:
	$(COMPOSE) ps

## dev-logs: tail logs — make dev-logs SVC=rabbitmq
dev-logs:
	$(COMPOSE) logs -f --tail=100 $(SVC)

## dev-clean: stop the stack AND delete all data volumes (destructive)
dev-clean:
	@printf 'This deletes every AegisOps data volume. Type "yes" to continue: '; \
	read ans; [ "$$ans" = "yes" ] || { echo "aborted"; exit 1; }
	$(COMPOSE) down -v --remove-orphans

## dev-reset: dev-clean followed by a fresh dev-up
dev-reset: dev-clean dev-up

## psql: open a psql shell inside the postgres container
psql:
	@$(LOAD_ENV) $(COMPOSE) exec postgres psql -U "$$AEGIS_PG_USER" -d "$$AEGIS_PG_DATABASE"

## redis-cli: open a redis-cli shell inside the redis container
redis-cli:
	$(COMPOSE) exec redis redis-cli

## rabbit-ui: print the RabbitMQ management URL and credentials
rabbit-ui:
	@$(LOAD_ENV) echo "http://localhost:15672  user=$$AEGIS_AMQP_USER pass=$$AEGIS_AMQP_PASSWORD"

# -----------------------------------------------------------------------------
# Aggregates
# -----------------------------------------------------------------------------

## ci: everything the pipeline runs, in pipeline order
ci: fmt-check vet lint test-race build

## verify: full local gate — code checks plus a live environment probe
verify: ci preflight
	@echo ""
	@echo "AegisOps: code and environment both verified"
