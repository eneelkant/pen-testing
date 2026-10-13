# MCP Readiness Audit

## Current repository status (reconciled)

Verification date: **2026-10-13**  
Current `main` SHA: **`89f6f127b346a0e2de0dfcea69c4396431c6ccea`** (PR #11 + Dependabot #12–#15)  
PR #11 merge: `022669c4887f351733d29c894bfc223211fb01e1` — scope-skip/egress decoupling (`0.2.0a8`) — [run 38396965513](https://github.com/eneelkant/pen-testing/actions/runs/38396965513)  
Latest main CI: [run 38397140220](https://github.com/eneelkant/pen-testing/actions/runs/38397140220) on `89f6f12`

| Check | Result |
|---|---|
| GitHub Actions CI on current `main` (`89f6f12`) | **PASS** |
| Local unit tests (agent, pre-0.2.0a9) | **PASS** — 106+ on PR #11 line; 116 after worker-path work |
| MCP tool discovery | **PASS** — 9 tools |
| Local Docker Engine (Cursor agent VM) | **BLOCKED** — runtime proof via GitHub Actions |
| Cursor / Claude / Gemini UI E2E | **BLOCKED** |
| ChatGPT remote HTTPS connector | **BLOCKED** |

### Assessment

**READY FOR CONTROLLED TESTING** — not production-ready for unconstrained active scanning. Briar Compose worker-network path is the enforceable platform boundary; Shannon workers remain on upstream `shannon-net`. In-engine DNS/redirect containment, Briar Alpha, and AGPL review remain residual.

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
