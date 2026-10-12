# MCP Readiness Audit

## Current repository status (reconciled)

Verification date: **2026-10-12**  
Current `main` SHA: **`dad086dc328f83250a43e5b8d7b66527cb36d6b5`** (PR #5 merge)  
PR #5 head: `989aeb55daf6f5b599d2d90a8a90fd23acef75ec` — launch-time egress isolation (`0.2.0a5`)  
PR #4 merge: `9bd2663fe74216fbd16b034be70a154a8dc49a3c`  
PR #3 merge: `c0bfe276d4af06960627d8a181676edf75f34458`  
PR #2 merge: `b4e4fab6329abce2e1f686e9d6b1704bd1166fd1` (historical)

| Check | Result |
|---|---|
| GitHub Actions CI on current `main` (`c0bfe27`) | **PASS** — Lint/unit, Docker build and runtime, gitleaks, dependency metadata ([run 38247150006](https://github.com/eneelkant/pen-testing/actions/runs/38247150006)); log includes `Docker runtime verification passed.` |
| Local unit tests on `c0bfe27` (agent) | **PASS** — 78 passed |
| `scripts/smoke.sh` on `c0bfe27` (agent) | **PASS** |
| MCP tool discovery | **PASS** — 9 tools |
| Local Docker Engine (Cursor agent VM) | **BLOCKED** — `docker: command not found` (runtime proof via GitHub Actions) |
| Cursor / Claude / Gemini UI E2E | **BLOCKED** — clients not installed here |
| ChatGPT remote HTTPS connector | **BLOCKED** — not deployed |

### Assessment

**READY FOR CONTROLLED TESTING** — not production-ready for unconstrained active scanning. PR #3 security hardening is present on `main`. Platform-owned headers path fails closed on missing scope, rejects non-http(s), gates skip-scope, and blocks named-host→non-public DNS pivots. Shannon/Briar egress, DNS rebinding inside upstream engines, Briar Alpha status, and AGPL redistribution review remain residual risks.

### Security fixes present on `main` (from PR #3)

| Defect | Severity | Fix present |
|---|---|---|
| HeadersAdapter failed open when registry missing | Critical | Yes — `preflight()` fail-closed |
| `file://` local file read via HeadersAdapter | Critical | Yes — http(s)-only |
| `--skip-scope-check` substring loopback bypass | High | Yes — hostname parse + `PEN_ALLOW_SKIP_SCOPE=1` |
| Scheme-less `host/path` assets authorized whole host | High | Yes — path-prefix match |
| Named host → non-public DNS for headers | High | Yes — `core/net/ssrf.py` |
| URL userinfo leaked in findings/logs | Medium | Yes — redaction |
| Gitleaks/Trivy arbitrary path scan | Medium | Yes — `confine_path` |
| Trivy docker without `--network none` | Medium | Yes |

### Outstanding risks (not claimed fixed for upstream engines)

1. Shannon/Briar browser and worker egress are **not** governed by platform DNS/IP policy.
2. Orchestrator image intentionally has **no Docker socket** — Shannon workers are not launched from inside that container.
3. Briar remains upstream **Alpha**.
4. `PEN_REQUIRE_SCOPE=false` and `PEN_ALLOW_SKIP_SCOPE=1` are powerful operator overrides.
5. License/redistribution of AGPL Shannon/Briar via process isolation still needs human legal review (see `THIRD_PARTY_NOTICES.md`).
6. Report export refuses final-path symlinks (hardened); operators must still protect `reports_dir` / `work_dir` permissions.

---

## Historical: pre-PR #3 hardening review

> Historical note: the post-merge hardening work was authored against `main` `@ b4e4fab` (after PR #2) and landed via PR #3 as `c0bfe27`. Do not treat that review’s “draft / unmerged” language as current policy.

---

## Historical pre-merge audit (PR #2 era)

> The following section is **historical**. PR #2 was merged to `main` as `b4e4fab`.

Audit date: **2026-10-12**  
Baseline `main` commit at audit start: `25fec5093db6b96dea30e4b55e1ff406f0509626` (PR #1 merge)  
Audit branch: `cursor/mcp-audit-hardening-39f7`  
Historical PR: https://github.com/eneelkant/pen-testing/pull/2 (**merged**)

### Historical defects fixed in PR #2

| Defect | Severity | Fix |
|---|---|---|
| `export_report(outdir=...)` could write outside project dirs | High | Confine outdir to `reports_dir` / `work_dir` |
| Assessment IDs accepted path-like values | High | Require UUID assessment IDs |
| `validate_target_scope("not-a-url")` fell through to scope match | Medium | Require absolute http(s) URL with hostname |
| Logging handler not explicitly bound to stderr | Medium | Force `StreamHandler(sys.stderr)` + `propagate=False` |
