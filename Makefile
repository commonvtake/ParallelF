# ParallelF developer tasks. Run `make help` for the list.

SHELL := /bin/sh
.DEFAULT_GOAL := help

# Local settings and generated secrets (created by `make init`).
-include .env
export

COMPOSE := docker compose --env-file .env -f deploy/compose/compose.yaml
DASHBOARD := web/dashboard
MIGRATE_IMAGE := migrate/migrate:v4.18.3

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# --- Local stack -------------------------------------------------------------

.PHONY: init
init: ## Create .env with generated secrets (keeps an existing .env)
	@scripts/dev/init-env.sh

.PHONY: up
up: init ## Build and start the whole stack, then wait until it is ready
	$(COMPOSE) up --build --detach
	@scripts/dev/wait-for-stack.sh

.PHONY: down
down: ## Stop the stack (data is kept)
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and delete its data volumes
	$(COMPOSE) down --volumes --remove-orphans

.PHONY: ps
ps: ## Show the state of every container
	$(COMPOSE) ps --all

.PHONY: logs
logs: ## Follow the logs of every service
	$(COMPOSE) logs --follow --tail 100

.PHONY: verify
verify: ## Smoke-test the running stack (needs only curl)
	@scripts/dev/verify.sh

.PHONY: verify-cloud
verify-cloud: ## One host, one VM: create, run, ping, stop, start and delete a CirrOS VM
	@python3 scripts/dev/verify_cloud.py

.PHONY: token
token: ## Print an access token for a development user (AS=owner|viewer)
	@scripts/dev/token.sh $(or $(AS),owner)

.PHONY: psql
psql: ## Open psql in the database container as the superuser
	$(COMPOSE) exec postgres psql -U postgres -d parallelf

.PHONY: migrate
migrate: ## Apply pending migrations to the running database
	$(COMPOSE) run --rm db-init
	$(COMPOSE) run --rm migrate-core
	$(COMPOSE) run --rm migrate-cloud

# --- Compute host (ParallelF Cloud) -----------------------------------------

AGENT_BIN := bin/pf-node-agent

.PHONY: cloud-host-setup
cloud-host-setup: ## Install KVM, libvirt, QEMU and genisoimage on this host (sudo)
	sudo scripts/dev/cloud-host-setup.sh

.PHONY: agent-build
agent-build: ## Build the node agent into bin/
	CGO_ENABLED=0 go build -trimpath -o $(AGENT_BIN) ./services/node-agent/cmd/pf-node-agent

.PHONY: agent-check
agent-check: agent-build ## Show which runtimes the agent can use on this host
	sudo env PF_AGENT_CLOUD_URL=http://localhost:9102 $(AGENT_BIN) -check

.PHONY: agent
agent: agent-build ## Run the node agent in the foreground (Ctrl-C stops it; workloads keep running)
	sudo env PF_AGENT_CLOUD_URL=http://localhost:9102 PF_AGENT_JOIN_TOKEN=$(PF_CLOUD_JOIN_TOKEN) \
		PF_LOG_LEVEL=$(PF_LOG_LEVEL) $(AGENT_BIN)

.PHONY: agent-install
agent-install: agent-build ## Install and start the node agent as a systemd service
	sudo env PF_CLOUD_JOIN_TOKEN=$(PF_CLOUD_JOIN_TOKEN) scripts/dev/agent-install.sh $(AGENT_BIN)

.PHONY: agent-uninstall
agent-uninstall: ## Stop and remove the agent service (workloads keep running)
	-sudo systemctl disable --now pf-node-agent
	sudo rm -f /etc/systemd/system/pf-node-agent.service /usr/local/bin/pf-node-agent
	sudo systemctl daemon-reload

# --- Code generation ---------------------------------------------------------

.PHONY: gen
gen: gen-proto gen-api ## Regenerate all generated code

.PHONY: gen-proto
gen-proto: ## Generate Go code from the Protobuf event schemas (needs buf)
	buf generate

.PHONY: gen-api
gen-api: ## Generate TypeScript types from the OpenAPI contract
	cd $(DASHBOARD) && pnpm run gen:api

# --- Checks ------------------------------------------------------------------

.PHONY: lint
lint: lint-go lint-python lint-web lint-contracts ## Run every linter

.PHONY: lint-go
lint-go: ## Lint Go (needs golangci-lint v2)
	go vet ./...
	golangci-lint run

.PHONY: lint-python
lint-python: ## Lint, format-check and type-check Python
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

.PHONY: lint-web
lint-web: ## Lint, format-check and type-check the dashboard
	cd $(DASHBOARD) && pnpm run lint && pnpm run format:check && pnpm run typecheck

.PHONY: lint-contracts
lint-contracts: ## Lint the Protobuf and OpenAPI contracts (needs buf and npx)
	buf lint
	buf format --diff --exit-code
	npx --yes @redocly/cli@2 lint api/openapi/parallelf.v1.yaml

.PHONY: test
test: test-go test-python test-web ## Run every unit test suite

.PHONY: test-go
test-go: ## Go unit tests (store tests need PF_TEST_DATABASE_URL, else they skip)
	go test -race -count=1 ./...

.PHONY: test-go-db
test-go-db: ## Go tests including the PostgreSQL store tests, against the running stack
	PF_TEST_DATABASE_URL="postgres://pf_core:$(PF_CORE_DB_PASSWORD)@localhost:$(PF_POSTGRES_HOST_PORT)/parallelf?sslmode=disable" \
	PF_TEST_CLOUD_DATABASE_URL="postgres://pf_cloud:$(PF_CLOUD_DB_PASSWORD)@localhost:$(PF_POSTGRES_HOST_PORT)/parallelf?sslmode=disable" \
	PF_TEST_ADMIN_DATABASE_URL="postgres://postgres:$(POSTGRES_PASSWORD)@localhost:$(PF_POSTGRES_HOST_PORT)/parallelf?sslmode=disable" \
		go test -race -count=1 ./...

.PHONY: test-python
test-python: ## Python unit tests
	uv run pytest

.PHONY: test-web
test-web: ## Dashboard unit tests
	cd $(DASHBOARD) && pnpm run test

.PHONY: test-integration
test-integration: ## API integration tests against the running stack
	uv run pytest tests/integration

.PHONY: test-e2e
test-e2e: ## Browser end-to-end tests against the running stack
	cd $(DASHBOARD) && pnpm exec playwright test

.PHONY: setup
setup: ## Install Python and dashboard dependencies for local development
	uv sync --all-packages
	cd $(DASHBOARD) && pnpm install --frozen-lockfile
