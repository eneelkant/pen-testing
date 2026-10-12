# v0.1 Readiness Review — PR #1

Review date: **2026-10-12**  
Reviewed commit (pre-fix): `9d666b31a5863d135084f53d41ea17b9555262d0`  
Branch: `cursor/ai-security-platform-39f7`

## Verdict

**Conditionally ready for human review; not merge-ready without Docker verification on a machine with Docker Engine/Desktop.**

Reasons:

1. Unit/smoke/security tests pass locally.
2. GitHub Actions CI was green on the reviewed head (re-verify after any new push).
3. **Docker Engine is unavailable in the review environment**, so image builds, compose up, container privilege verification at runtime, and Shannon worker execution are **blocked**.
4. Upstream Shannon/Briar browser/network containment is **not** fully enforceable by this orchestrator.

Merge requires explicit human authorization after Docker verification and any required approvals/branch protection.

## Check matrix

| Check | Result | Notes |
|---|---|---|
| Branch / clean tree | **Passed** | On feature branch; no unrelated dirty files |
| PR head == expected SHA | **Passed** (at review start) | `9d666b3…` |
| Unit tests | **Passed** | See post-fix count after redirect hardening |
| Integration marker (Docker) | **Skipped** | Docker absent |
| Smoke script | **Passed** | No external attacks |
| Scope accept local fixture | **Passed** | |
| Out-of-scope rejection | **Passed** | `https://example.com` denied |
| Expired authorization | **Passed** | |
| Production active block | **Passed** (added test) | |
| Redirect same-origin policy (headers adapter) | **Passed** (added) | No-follow + cross-origin block |
| Shannon/Briar redirect/browser containment | **Failed / not claimed** | Upstream engines can navigate beyond wrapper policy |
| Secret redaction | **Passed** | |
| Shannon missing Docker handling | **Passed** | Live run blocked |
| Briar missing install handling | **Passed** | Health fails closed |
| Report schema validation | **Passed** | |
| Missing API keys not logged | **Passed** | Provider status booleans only |
| Credentials in diff | **Passed** | None found |
| Shannon/Briar attribution | **Passed** | `THIRD_PARTY_NOTICES.md`, AGPL noted |
| Vendored upstream source | **Passed** | Not present; adapters only |
| Docker compose config validate | **Blocked** | No `docker` binary |
| Image build / run / cleanup | **Blocked** | No Docker |
| Compose static security review | **Passed** (static) | Non-root UIDs, `cap_drop: ALL`, `no-new-privileges`, no docker.sock; orchestrator `read_only` |
| CI recheck | Re-run after push | |

## Docker blocker — install instructions

Do **not** install silently from this agent. On the operator machine:

**Linux (official convenience script — review before use):**  
https://docs.docker.com/engine/install/

**macOS / Windows:** Docker Desktop — https://docs.docker.com/get-docker/

Then:

```bash
docker compose version
bash scripts/docker_runtime_verify.sh
# CI equivalent: GitHub Actions job "Docker build and runtime" on ubuntu-latest
```

## Network containment gaps (explicit)

- Shannon and Briar may perform browser automation and outbound HTTP beyond the initially authorized URL.
- This platform enforces preflight scope on the **requested target string**; it does **not** provide DNS pinning, egress firewalling, or per-request allowlists inside upstream engines.
- Headers adapter (platform-owned) now refuses to follow redirects and blocks cross-origin `Location` values.

## Licensing

| Component | License | Integration |
|---|---|---|
| This repo | Apache-2.0 | — |
| Shannon `@keygraph/shannon@3.4.0` | AGPL-3.0-only | `npx` / Docker worker, not vendored |
| Briar `briar-pentest==0.4.62` | AGPL-3.0 | isolated venv/container, not vendored |

## Remaining actions before merge

1. Install Docker and complete compose build/run/cleanup on a verified host.
2. Optionally install Briar in `.venv-briar` and run `briar demo` / health.
3. Re-run CI on the latest commit; confirm required checks and any branch protection reviews.
4. Human explicitly authorizes merge (this review does **not** merge).
