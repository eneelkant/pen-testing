# MCP Readiness Audit

## Post-merge status (current)

Verification date: **2026-10-12**  
Starting `main` SHA for this review: **`b4e4fab6329abce2e1f686e9d6b1704bd1166fd1`** (merge of PR #2)  
Follow-up hardening branch: `cursor/post-merge-security-audit-39f7`

| Check | Result on `b4e4fab` / hardening branch |
|---|---|
| GitHub Actions CI on merge commit `b4e4fab` | **PASS** — Lint/unit, Docker build and runtime, gitleaks, dependency metadata ([run 38245405070](https://github.com/eneelkant/pen-testing/actions/runs/38245405070)) |
| Prior Docker proof on PR head `bb06250` | **PASS** ([run 38244472440](https://github.com/eneelkant/pen-testing/actions/runs/38244472440)) — historical evidence for the same Docker job |
| Local unit tests (agent) | **PASS** — 78 passed after post-merge hardening |
| `scripts/smoke.sh` (agent) | **PASS** (requires `PEN_ALLOW_SKIP_SCOPE=1` for fixture dry-runs) |
| MCP tool discovery | **PASS** — 9 tools |
| Local Docker Engine (Cursor agent VM) | **BLOCKED** — `docker: command not found` |
| Cursor / Claude / Gemini UI E2E | **BLOCKED** — clients not installed here |
| ChatGPT remote HTTPS connector | **BLOCKED** — not deployed |

### Assessment

**READY FOR CONTROLLED TESTING** — not production-ready for unconstrained active scanning. Platform-owned headers path is hardened against fail-open scope, `file://`, skip-scope substring tricks, and DNS→non-public pivots. Shannon/Briar egress, DNS rebinding inside upstream engines, and Briar Alpha status remain residual risks.

### Post-merge defects fixed (hardening PR)

| Defect | Severity | Fix |
|---|---|---|
| HeadersAdapter failed open when registry missing | Critical | Shared `preflight()` fail-closed |
| `file://` local file read via HeadersAdapter | Critical | http(s)-only scheme gate |
| `--skip-scope-check` substring loopback bypass | High | Hostname parse + `PEN_ALLOW_SKIP_SCOPE=1` CLI gate |
| Scheme-less `host/path` assets authorized whole host | High | Path-prefix match only |
| Named host → non-public DNS for headers | High | Resolve-time policy in `core/net/ssrf.py` |
| URL userinfo leaked in findings/logs | Medium | Redact userinfo in `redact_text` / normalize |
| Gitleaks/Trivy arbitrary path scan | Medium | Confine under work/reports/cwd |
| Trivy docker without `--network none` | Medium | Match Gitleaks isolation + `--skip-db-update` |

### Outstanding risks (not claimed fixed for upstream engines)

1. Shannon/Briar browser and worker egress are **not** governed by platform DNS/IP policy.
2. Orchestrator image intentionally has **no Docker socket** — Shannon workers are not launched from inside that container.
3. Briar remains upstream **Alpha**.
4. `PEN_REQUIRE_SCOPE=false` remains a powerful config override — treat as operator-controlled.
5. License/redistribution of AGPL Shannon/Briar via process isolation still needs human legal review (see `THIRD_PARTY_NOTICES.md`).

---

## Historical pre-merge audit (PR #2 era)

> The following section is **historical**. PR #2 was subsequently merged to `main` as `b4e4fab`. Do not treat draft/unmerged language below as current repository policy.

Audit date: **2026-10-12**  
Baseline `main` commit at audit start: `25fec5093db6b96dea30e4b55e1ff406f0509626` (PR #1 merge)  
Audit branch: `cursor/mcp-audit-hardening-39f7`  
Historical PR: https://github.com/eneelkant/pen-testing/pull/2 (**merged**)

### Historical summary

MCP was implemented and usable for local stdio diagnostics and dry-run orchestration via the official Python SDK (`mcp` 2.3.0). Nine tools were registered and call-tested. Agent-local Docker was blocked; GitHub Actions Docker runtime later passed.

### Historical defects fixed in PR #2

| Defect | Severity | Fix |
|---|---|---|
| `export_report(outdir=...)` could write outside project dirs | High | Confine outdir to `reports_dir` / `work_dir` |
| Assessment IDs accepted path-like values | High | Require UUID assessment IDs |
| `validate_target_scope("not-a-url")` fell through to scope match | Medium | Require absolute http(s) URL with hostname |
| Logging handler not explicitly bound to stderr | Medium | Force `StreamHandler(sys.stderr)` + `propagate=False` |
