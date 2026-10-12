# Architecture

## Goals

Unify authorized white-box (Shannon), black-box (Briar), and complementary scanners behind one scope policy, one finding schema, and Docker-friendly isolation — without vendoring AGPL engines.

## Diagram

```mermaid
flowchart TB
  subgraph clients [AI clients and humans]
    CURSOR[Cursor / AGENTS.md]
    CLAUDE[Claude / CLAUDE.md]
    GEMINI[Gemini / GEMINI.md]
    HUMAN[Human operator]
  end

  subgraph platform [pen-testing orchestrator Apache-2.0]
    CLI[core.cli]
    CFG[core.config]
    SCOPE[ScopeEngine]
    RUN[CommandRunner]
    NORM[Finding normalizer]
    REP[Report exporters]
    DAILY[Daily research report]
  end

  subgraph adapters [integrations]
    SH[ShannonAdapter]
    BR[BriarAdapter]
    HD[HeadersAdapter]
    GL[GitleaksAdapter]
    TR[TrivyAdapter]
  end

  subgraph isolated [Isolated runtimes]
    NPX["npx @keygraph/shannon@3.4.0 + Docker worker"]
    VENV["venv/container briar-pentest==0.4.62"]
    SCAN["optional gitleaks/trivy containers"]
  end

  REG[(scopes/registry.yaml)]
  OUT[(reports/out workspaces)]

  clients --> CLI
  CLI --> CFG
  CLI --> SCOPE
  SCOPE --> REG
  CLI --> adapters
  adapters --> RUN
  SH --> NPX
  BR --> VENV
  GL --> SCAN
  TR --> SCAN
  adapters --> NORM
  NORM --> REP
  REP --> OUT
  CLI --> DAILY
  DAILY --> OUT
```

## Package layout

| Path | Role |
|---|---|
| `core/` | Config, execution, scope, findings, reporting, diagnostics, CLI |
| `integrations/` | Tool adapters implementing `SecurityAdapter` |
| `providers/` | AI provider env detection (no secret values logged) |
| `scopes/` | Authorization registry and examples |
| `reports/` | Templates and generated output (generated gitignored) |
| `scripts/` | Setup/doctor/smoke for bash and PowerShell |
| `docker/` | Worker Dockerfiles |
| `tests/` | Unit/integration tests and local fixtures |
| `docs/` | Architecture, audits, installation, AI setup |

## Adapter interface

All tools implement `integrations.base.SecurityAdapter`:

1. `healthcheck()` — dependency/capability probe, no active scanning
2. `preflight(request)` — mandatory scope enforcement for active categories
3. `run(request)` — execute or dry-run; return `ExecutionResult` with normalized findings

## Finding lifecycle

`candidate → evidence_collected → reproduced → human_reviewed → report_drafted → submitted → resolved`

AI agreement alone must not promote a finding to human-confirmed.

## Isolation strategy

| Tool | Isolation |
|---|---|
| Orchestrator | Own venv / orchestrator container; non-root |
| Shannon | Upstream ephemeral worker via Docker; repo mount read-only (upstream behavior) |
| Briar | Dedicated `.venv-briar` or `docker/briar` image |
| Gitleaks/Trivy | Host binary or official container with read-only source mounts |

Docker socket is **not** mounted into Briar/active-testing workers.

## Adding a scanner

1. Create `integrations/<name>/adapter.py` subclassing `SecurityAdapter`
2. Pin version in config / compose
3. Map outputs into `normalize_generic_finding`
4. Add healthcheck + unit tests with mocks/fixtures
5. Update `docs/TOOL_MATRIX.md` and `THIRD_PARTY_NOTICES.md`
