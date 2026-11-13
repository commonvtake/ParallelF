# 04 — Monorepo Directory Structure

> **Phase 1 differs in three places** ([ADR-0012](../adr/0012-single-go-module-and-make.md)): one Go module at the root instead of `go.work`, a `Makefile` instead of `Taskfile.yml`, and a single OpenAPI file `api/openapi/parallelf.v1.yaml`. The layout below remains the target as the repository grows.

## 1. Layout

```text
parallelf/
├── README.md                     # pitch, architecture diagram, quickstart (core profile < 15 min)
├── LICENSE                       # Apache-2.0 (assumed)
├── SECURITY.md                   # how to report issues, scope statement
├── CONTRIBUTING.md               # branch/commit conventions, local checks
├── Taskfile.yml                  # task runner (go-task): up/down per profile, lint, test, gen
├── go.work                       # Go workspace tying all Go modules together
├── .editorconfig  .gitattributes # LFS rules for lab/unity/**
├── .pre-commit-config.yaml       # gitleaks, gofumpt, ruff, prettier, buf format
├── .github/
│   ├── workflows/
│   │   ├── ci-go.yml             # golangci-lint, go test -race, govulncheck
│   │   ├── ci-python.yml         # ruff, mypy --strict, pytest, pip-audit
│   │   ├── ci-web.yml            # eslint, tsc, vitest, playwright (core profile in CI)
│   │   ├── ci-contracts.yml      # buf lint + buf breaking, redocly lint, oasdiff breaking
│   │   ├── ci-images.yml         # docker build, trivy scan, syft SBOM, (cosign sign on main)
│   │   ├── ci-e2e.yml            # compose up core+cloud(container driver)+vpn → Go e2e suite
│   │   ├── ci-lab-targets.yml    # sanitizer builds + exploit-check in --network none container
│   │   └── codeql.yml
│   ├── dependabot.yml
│   ├── CODEOWNERS
│   └── pull_request_template.md
│
├── api/                          # ── CONTRACTS (source of truth) ──
│   ├── openapi/
│   │   ├── core.yaml  cloud.yaml  vpn.yaml  netguard.yaml  lab.yaml  ai.yaml
│   │   ├── components/           # shared schemas: Problem, Page, Operation, Ids
│   │   └── bundle/parallelf.yaml # generated bundle served by gateway at /api/v1/openapi.yaml
│   ├── proto/parallelf/
│   │   ├── common/v1/envelope.proto, ids.proto
│   │   ├── cloud/v1/events.proto, agent.proto      # DesiredNodeState, WorkloadStatusReport
│   │   ├── vpn/v1/events.proto, agent.proto
│   │   ├── netguard/v1/telemetry.proto, alerts.proto, scope.proto
│   │   ├── lab/v1/integrity.proto
│   │   ├── ai/v1/events.proto
│   │   └── audit/v1/audit.proto
│   ├── asyncapi/parallelf.yaml   # human-readable event catalogue (generated + curated)
│   ├── permissions.yaml          # roles → permissions; generates Go/Py/TS constants
│   ├── buf.yaml  buf.gen.yaml
│
├── pkg/                          # ── SHARED GO LIBRARIES (module: github.com/commonvtake/parallelf/pkg) ──
│   ├── authn/  authz/  events/  natsx/  obs/  httpx/  pgx/  config/  errors/  testutil/
│
├── python/pf_common/             # ── SHARED PYTHON LIBRARY (uv workspace member) ──
│   └── pf_common/{auth,authz,events,nats,obs,db,http}/
│
├── services/                     # ── DEPLOYABLE UNITS ──
│   ├── gateway/                  # Go
│   │   ├── cmd/pf-gateway/main.go
│   │   ├── internal/{proxy,routes,ratelimit,sse,console}/
│   │   ├── go.mod  Dockerfile  README.md
│   ├── core/                     # Go: identity, mfa, tokens, projects, rbac, audit
│   │   ├── cmd/pf-core/
│   │   ├── internal/{identity,mfa,tokens,projects,rbac,serviceaccounts,apitokens,audit,bootstrap}/
│   │   ├── migrations/           # golang-migrate SQL, schema core + audit
│   │   ├── queries/              # sqlc input
│   │   └── sqlc.yaml
│   ├── cloud/                    # Go: pf-cloudd
│   │   ├── cmd/pf-cloudd/
│   │   ├── internal/{api,scheduler,reconciler,ipam,images,operations,store}/
│   │   ├── migrations/  queries/
│   ├── node-agent/               # Go: pf-node-agent (host, systemd)
│   │   ├── cmd/pf-node-agent/
│   │   ├── internal/drivers/{libvirt,docker}/
│   │   ├── internal/net/{bridge,cni,nft,vxlan}/
│   │   ├── internal/{reconcile,imagecache,labrelay,heartbeat}/
│   │   └── packaging/{pf-node-agent.service, apparmor/}
│   ├── vpn/                      # Go: pf-vpnd
│   │   ├── cmd/pf-vpnd/  internal/{api,policy,enroll,ipam,stats,store}/  migrations/  queries/
│   ├── wg-agent/                 # Go: pf-wg-agent (host, systemd)
│   │   ├── cmd/pf-wg-agent/  internal/{wg,nft,conntrack,stats,reconcile}/
│   ├── netguard/                 # Go: pf-netguardd
│   │   ├── cmd/pf-netguardd/
│   │   ├── internal/{ingest,inventory,topology,attribution,alerts,incidents,evidence,scopes,retention,api,store}/
│   │   ├── migrations/  queries/
│   ├── ng-shipper/               # Go
│   ├── ng-discovery/             # Go
│   ├── ng-probe/                 # C++20, CMake, optional
│   │   ├── CMakeLists.txt  src/  tests/ (GoogleTest)  fuzz/ (libFuzzer)
│   ├── ng-detect/                # Python
│   │   ├── pyproject.toml  src/ng_detect/{detectors,runtime,state}/  tests/  replays/
│   ├── lab/                      # Python FastAPI: pf-labd
│   │   ├── pyproject.toml  src/pf_labd/{api,envs,targets,experiments,integrity,clients}/  migrations/  tests/
│   └── ai/                       # Python FastAPI: pf-aid
│       ├── pyproject.toml  src/pf_aid/{api,orchestrator,tools,validator,redact,prompts,budget}/
│       ├── migrations/  tests/  evals/{scenarios,recordings,injection_corpus}/
│
├── web/dashboard/                # ── Next.js ──
│   ├── app/(auth)/  app/(platform)/{overview,cloud,vpn,netguard,lab,ai,admin}/
│   ├── app/bff/                  # route handlers (session, proxy, SSE)
│   ├── components/  lib/api/ (generated client)  lib/session/  styles/
│   ├── e2e/                      # Playwright
│   ├── package.json  pnpm-lock.yaml  next.config.ts  tsconfig.json
│
├── cli/pfctl/                    # Go CLI (cobra): login, cloud, vpn, ng, lab, ai, audit verify, nats apply
│
├── lab/                          # ── SECURITY LAB CONTENT ──
│   ├── unity/ParallelFArena/     # Unity 6 project (Git LFS); or a git submodule if LFS quota bites
│   ├── targets/vt-01-stack/ … vt-06-deser/   # README, vuln/, fixed/, exploit-check/, CMakeLists.txt
│   ├── images/                   # cloud-init templates + build scripts for lab VM images
│   └── scenarios/                # NetGuard/AI replay scenarios (traffic generators, expected alerts)
│
├── deploy/
│   ├── compose/
│   │   ├── compose.yaml          # services with profiles: core, cloud, vpn, ng, ng-full, lab, ai, obs
│   │   ├── compose.override.example.yaml
│   │   └── .env.example
│   ├── nats/{nats-server.conf, jetstream.yaml, accounts/}  # streams/consumers/KV as code
│   ├── postgres/{init/00-roles.sql, 01-schemas.sql, postgresql.conf}
│   ├── sensors/{zeek/local.zeek, suricata/suricata.yaml, suricata/rules/enabled.list}
│   ├── observability/{prometheus/prometheus.yml, prometheus/rules/, grafana/provisioning/, grafana/dashboards/}
│   ├── helm/parallelf/           # umbrella chart + subcharts per service, NetworkPolicies
│   ├── k3s/                      # bootstrap script, registries.yaml, k3s config
│   ├── systemd/                  # agent units (also packaged per service)
│   ├── secrets/                  # SOPS-encrypted *.enc.yaml (age); .sops.yaml at repo root
│   └── terraform/
│       ├── modules/{network,node,backup-bucket,budget}/
│       └── envs/aws-demo/{main.tf,variables.tf,outputs.tf,backend.tf}
│
├── scripts/
│   ├── dev/{wsl-bootstrap.sh, check-nested-virt.sh, mem-report.sh}
│   ├── pki/{init-ca.sh, issue-service-cert.sh}
│   └── nats/{gen-nkeys.sh}
│
├── test/
│   ├── e2e/                      # Go e2e suite (build tag e2e) against a running profile
│   ├── load/                     # k6 scripts (API), nats bench configs (telemetry)
│   ├── chaos/                    # scripts: kill NATS/Postgres/agent mid-operation
│   └── fixtures/pcaps/           # self-generated lab captures only
│
└── docs/
    ├── architecture/             # this document set
    ├── adr/                      # architecture decision records
    ├── security/                 # rules-of-engagement.md, threat-model updates
    ├── runbooks/                 # restore-from-backup, rotate-keys, revoke-device, incident-response
    ├── dev-setup.md
    └── lab-writeups/             # one per experiment/finding (portfolio material)
```

## 2. Module and package boundaries

| Rule | Enforcement |
|---|---|
| Each Go service is its own module (`services/<name>/go.mod`), tied together by `go.work` | `go work sync` in CI |
| Services may import `pkg/*` and generated contract code, **never another service's `internal/`** | Go's `internal/` visibility + a `depguard` rule in golangci-lint |
| Python services depend on `pf_common` through a `uv` workspace | `uv` lockfile, import-linter contract |
| Generated code goes to `gen/` folders that are **committed** (so reviewers see API changes) and checked for drift in CI (`task gen && git diff --exit-code`) | CI |
| Contracts change first: a PR touching `api/` must pass `buf breaking` and `oasdiff breaking` against `main`, or bump the version | CI |

## 3. Tooling choices

| Area | Tool |
|---|---|
| Task runner | `go-task` (`Taskfile.yml`): readable YAML, cross-platform |
| Go | Go 1.23+, `golangci-lint`, `gofumpt`, `sqlc`, `oapi-codegen`, `buf`, `govulncheck` |
| Python | Python 3.12, `uv` (env + lock), `ruff`, `mypy --strict`, `pytest`, `pip-audit` |
| TypeScript | Node 22 LTS, `pnpm`, `eslint`, `prettier`, `vitest`, `playwright` |
| C++ | C++20, CMake + Ninja, `clang-tidy`, `clang-format`, GoogleTest, libFuzzer, ASan/UBSan presets |
| Migrations | `golang-migrate` SQL files for **all** services (Python services too), one migration directory per service/schema |
| Commits | Conventional Commits; squash merge; `main` protected (CI required) |
| Versioning | One platform version (SemVer), git tags `v0.x.y`; images tagged by version + git SHA |
