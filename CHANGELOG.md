# Changelog

## 0.2.0a9 — 2026-10-13

### Security

- Briar default execution is Compose (`PEN_BRIAR_EXEC=compose`) on `pen-scanner-live` / `pen-scanner-isolated`
- Host Briar (`PEN_BRIAR_EXEC=host`) requires `PEN_ALLOW_BRIAR_HOST_NET=1` in addition to `PEN_ALLOW_BRIAR_LIVE=1`
- Docker runtime verifies the **actual** Briar worker container network membership and egress/fixture reachability
- Fixture-headers attached to `pen-scanner-live` for authorized compose-path probes
- Shannon residual clarified: workers remain on upstream `shannon-net` (not platform-attachable without upstream)

### Documentation

- Document enforced vs launch-time controls; Briar compose path vs Shannon uncontained workers

## 0.2.0a8 — 2026-10-12

### Security

- `skip_scope_check` no longer bypasses launch-time DNS/egress policy for Shannon/Briar
- Disabling `PEN_REQUIRE_EGRESS_POLICY` requires `PEN_ALLOW_EGRESS_DISABLE=1` (dual gate)
- MCP `demo=true` waives `confirm_authorized` only for Briar demo (not Shannon/headers)

### Documentation

- Document gate independence and residual in-engine isolation gaps after PR #10 merge (`93c228b`)

## 0.2.0a7 — 2026-10-12

### Security

- Live Briar requires explicit `PEN_ALLOW_BRIAR_LIVE=1` (host CLI is not on platform Compose isolation networks)
- CI concurrency no longer cancels in-flight runs on `main` (preserves post-merge Docker isolation verification)
- Docker runtime verify echoes control-network fixture probe output and fails closed if the fixture never becomes ready

### Documentation

- Reconcile isolation/security docs with `main` after PR #6–#9; document Briar live gate parity with Shannon

## 0.2.0a6 — 2026-10-12

### Security

- Live Shannon requires explicit `PEN_ALLOW_SHANNON_LIVE=1` (workers are not on platform networks)
- Docker runtime verify adds **runtime** probes: isolated network cannot reach `1.1.1.1:443`; control network reaches local fixture

### Documentation

- Reconcile isolation docs after PR #5 merge; distinguish static vs runtime evidence

## 0.2.0a5 — 2026-10-12

### Security

- Launch-time egress policy for live Shannon/Briar/Headers (`core/isolation/`)
- Dual-gate for disabling scope: `PEN_REQUIRE_SCOPE=false` requires `PEN_ALLOW_SCOPE_DISABLE=1`
- Compose: `pen-scanner-isolated` (`internal: true`) for default Briar workers; `briar-live` profile for explicit egress
- Docker runtime verify asserts isolation networks, no `docker.sock`, and runs isolation unit tests
- Headers redirects re-checked with resolve-time non-public policy

### Documentation

- `docs/SCANNER_ISOLATION.md` maps which controls apply to which engines

### Notes

- Does **not** claim in-engine Shannon/Briar DNS/redirect containment after subprocess start

## 0.2.0a4 — 2026-10-12

### Security

- Report exporters refuse final-path symlinks (`safe_write_text` / `O_NOFOLLOW`)

### Documentation

- Reconcile readiness/security docs with PR #3 merge on `main` (`c0bfe27`)

## 0.2.0a3 — 2026-10-12

### Security

- HeadersAdapter fails closed without a scope engine; http(s)-only fetches; resolve-time block for named-host→non-public DNS
- `--skip-scope-check` requires `PEN_ALLOW_SKIP_SCOPE=1`; loopback skip uses parsed hostname (not substring)
- Scheme-less `host/path` scope assets no longer authorize the whole host
- Redact URL userinfo in findings and free-text fields
- Confine Gitleaks/Trivy scan paths under work/reports/cwd; Trivy docker uses `--network none`
- Briar Compose worker: `read_only` + tmpfs

### Added

- `core/net/ssrf.py` and `core/paths.py` helpers
- Post-merge hardening regression suite (`tests/unit/test_post_merge_hardening.py`)

### Notes

- Assessment: READY FOR CONTROLLED TESTING (not production-ready for unconstrained active scanning)
- Shannon/Briar egress containment remains an upstream/operator responsibility

## 0.2.0a2 — 2026-10-12

### Security

- MCP `export_report` outdir confined to `reports_dir` / `work_dir`
- Assessment IDs required to be UUIDs (blocks path-like IDs)
- Scope validation requires absolute http(s) URLs with hostnames (non-path tools)
- Assessment `timeout_seconds` bounded to 1..86400
- Logger forced to stderr with `propagate=False` for stdio MCP safety

### Added

- MCP readiness audit, tool test matrix, and security validation docs
- MCP tool-call regression suite (`tests/unit/test_mcp_tool_calls.py`)
- GitHub Actions `docker-runtime` job + `scripts/docker_runtime_verify.sh` (Engine/Compose build, orchestrator doctor, host smoke)

### Notes

- Local Cursor agent VMs may lack Docker; runtime verification is performed on `ubuntu-latest` GitHub-hosted runners
- AI client E2E UI connections remain environment-dependent

## 0.2.0a1 — 2026-10-12

### Added

- Official MCP Python SDK (`mcp` 2.x) server with constrained tools
- Installers (`installers/install.sh`, `install.ps1`) and unified `scripts/setup_all.sh`
- Client configuration helpers for Cursor, Claude Desktop, and Gemini CLI
- Reproducible requirement sets under `requirements/`
- Client compatibility matrix and release process docs
- GitHub release workflow (tag-driven)

### Security

- MCP assessments default to `dry_run=true` and require `confirm_authorized` for live runs
- Headers redirect no-follow / cross-origin refusal retained from v0.1 readiness work

### Notes

- Alpha: Docker runtime verification may be incomplete in some environments
- ChatGPT remote MCP is documented only; not auto-deployed

## 0.1.0 — 2026-10-12

Initial orchestration platform: Shannon/Briar adapters, scope engine, reporting, Docker Compose, CI.
