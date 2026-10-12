# Scanner Execution Isolation

Status: **partial platform enforcement** — READY FOR CONTROLLED TESTING, not full in-engine containment.

## What each layer protects

| Component | Scope preflight | Resolve-time egress policy | Docker network | In-engine DNS/redirects |
|---|---|---|---|---|
| Orchestrator CLI/MCP | Yes | Launch gate for remote tools | N/A (host process) | N/A |
| HeadersAdapter | Yes (fail closed) | Yes + redirect re-check | N/A | Platform-owned (no-follow) |
| Shannon adapter | Yes | Yes **before** `npx` launch | Shannon spawns its own workers | **Not controlled** by this platform |
| Briar adapter | Yes | Yes **before** CLI launch | Compose `briar` vs `briar-live` | **Not controlled** by this platform |
| Gitleaks/Trivy | N/A (local paths) | N/A | `--network none` when via Docker | N/A |

**Do not assume** that a successful URL preflight means Shannon or Briar cannot later resolve DNS differently or follow redirects to other hosts. Those engines perform independent network I/O after launch.

## Enforceable controls in this repository

1. **Authorization registry** (`scopes/registry.yaml`) via `ScopeEngine` — fail closed when missing for active tools.
2. **Dual-gate scope disable** — `PEN_REQUIRE_SCOPE=false` also requires `PEN_ALLOW_SCOPE_DISABLE=1`.
3. **Skip-scope gate** — CLI `--skip-scope-check` requires `PEN_ALLOW_SKIP_SCOPE=1`; MCP only sets skip for Briar `demo`.
4. **Launch-time egress policy** (`core/isolation/`) — for live Shannon/Briar/Headers:
   - http(s) only
   - optional `PEN_EGRESS_ALLOW_HOSTS`
   - block named hosts resolving to non-public/link-local/metadata addresses
   - IP literals allowed only when `PEN_ALLOW_NON_PUBLIC_LITERALS=true` (default) *and* scope authorized them
5. **Compose networks**
   - `pen-scanner-isolated` (`internal: true`) for default `briar` worker profile
   - `pen-scanner-live` for explicit `live-workers` profile (`briar-live`)
   - **No Docker socket** on orchestrator or Briar services
6. **Report path safety** — `confine_path` + `safe_write_text` / `O_NOFOLLOW`

## Operator environment

| Variable | Default | Meaning |
|---|---|---|
| `PEN_REQUIRE_SCOPE` | `true` | Require authorization registry |
| `PEN_ALLOW_SCOPE_DISABLE` | `false` | Second gate to honor `PEN_REQUIRE_SCOPE=false` |
| `PEN_ALLOW_SKIP_SCOPE` | unset/false | Required for CLI `--skip-scope-check` |
| `PEN_REQUIRE_EGRESS_POLICY` | `true` | Launch-time destination evaluation for live remote tools |
| `PEN_BLOCK_NON_PUBLIC_RESOLVED` | `true` | Deny DNS→non-public for named hosts |
| `PEN_ALLOW_NON_PUBLIC_LITERALS` | `true` | Allow scoped `127.0.0.1` / RFC1918 literals |
| `PEN_EGRESS_ALLOW_HOSTS` | empty | Optional extra host allowlist |

## Remaining limitations

1. Shannon Temporal/Docker workers are not attached to `pen-scanner-*` networks by this platform.
2. Briar browser automation after CLI start is not connection-intercepted.
3. DNS rebinding **after** launch inside upstream engines remains an upstream/operator firewall problem.
4. Compose `internal: true` proves isolation for the default Briar worker profile; it does **not** prove Shannon worker isolation.
5. Briar remains upstream Alpha; AGPL redistribution needs human legal review.

## Failure behavior

- Missing scope engine + active tool → **blocked**
- Live destination fails egress policy → **blocked** (subprocess not started)
- Shannon without Docker daemon → **blocked**
- Isolation unit tests missing in Docker verify script → **fail**
