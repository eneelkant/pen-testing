# Security Validation

Verification date: **2026-10-12**  
Current `main` baseline for this work: **`83f9e02d45689705a46b0e296f8f4b8098b0db6b`** (PR #6 + Dependabot #7–#9).  
See also `docs/SCANNER_ISOLATION.md`.

## Authorization / scope engine

| Case | Result | Evidence |
|---|---|---|
| Authorized in-scope asset (`http://127.0.0.1:18080/`) | PASS | unit / MCP tests |
| Unknown / public URL (`https://example.com`) | PASS | denied |
| Out-of-scope hostname | PASS | denied |
| Excluded asset | PASS | unit test |
| Expired authorization | PASS | unit test |
| Missing registry / empty target | PASS | fail closed (CLI + Headers + Shannon/Briar) |
| Disallowed testing category | PASS | unit test |
| Production target blocked | PASS | unit test |
| Invalid URL (`not-a-url`) | PASS | MCP service URL validation |
| Scheme-less `host/path` does not authorize whole host | PASS | `test_schemeless_path_asset_does_not_authorize_whole_host` |
| Redirect cross-origin (headers adapter) | PASS | no-follow + block |
| Redirect same-origin | PASS | allowed |
| Subdomain auto-expansion | PASS (not expanded) | unit test |
| Private IP auto-authorization (`10.0.0.1`) | PASS (not authorized) | scope deny |
| Headers `file://` | PASS (blocked) | http(s)-only |
| Headers skip-scope substring bypass | PASS (blocked) | hostname parse |
| Headers named-host → non-public DNS | PASS (blocked) | `validate_resolved_target` / isolation egress |
| Shannon/Briar launch-time DNS→non-public | PASS (blocked before subprocess) | `tests/unit/test_scanner_isolation.py` |
| `PEN_REQUIRE_SCOPE=false` without dual gate | PASS (blocked) | `PEN_ALLOW_SCOPE_DISABLE` required |
| Compose Briar default network `internal: true` | PASS (static + **runtime** probe) | `pen-scanner-isolated` cannot reach 1.1.1.1:443 |
| Live Shannon without `PEN_ALLOW_SHANNON_LIVE` | PASS (blocked) | unit tests |
| Live Briar without `PEN_ALLOW_BRIAR_LIVE` | PASS (blocked) | unit tests |
| Briar demo without `PEN_ALLOW_BRIAR_LIVE` | PASS (allowed) | unit tests |
| Control network → local fixture | PASS (runtime) | docker verify |
| In-engine Shannon/Briar connection interception | NOT IMPLEMENTED | documented limitation |
| DNS rebinding inside Shannon/Briar | NOT IMPLEMENTED | residual — upstream engines |
| Upstream browser navigation containment | FAIL / not claimed | documented limitation |
| Secret / URL userinfo redaction | PASS | `redact_text` + normalize |
| Assessment ID path traversal | PASS | UUID-only IDs |
| Report outdir escape | PASS | confined to reports/work dirs |
| Report write via final-path symlink | PASS | `safe_write_text` refuses symlinks / uses `O_NOFOLLOW` |
| Local scanner path escape | PASS | confined under work/reports/cwd |
| Symlink dir escape via `confine_path` | PASS | resolve() leaves allowed roots → blocked |
| CLI `--skip-scope-check` without env gate | PASS (rejected) | `PEN_ALLOW_SKIP_SCOPE=1` required |
| Rate limit enforcement (network) | NOT IMPLEMENTED | registry field recorded only |

## MCP surface

| Control | Result |
|---|---|
| No arbitrary shell tool | PASS |
| Live assessment requires `confirm_authorized` | PASS |
| Dry-run default | PASS |
| No scan on server start | PASS |
| Local path tools reject http(s) targets | PASS |

## Docker / isolation

| Control | Result |
|---|---|
| Non-root UIDs in compose | PASS (static) |
| `cap_drop: ALL`, `no-new-privileges` | PASS (static) |
| No docker.sock on workers/orchestrator | PASS (static + by design) |
| Briar `read_only` + tmpfs | PASS (static) |
| Runtime build/run (agent VM) | BLOCKED (no Docker Engine) |
| Runtime build/run (GitHub Actions on `c0bfe27`) | PASS — [run 38247150006](https://github.com/eneelkant/pen-testing/actions/runs/38247150006) |

## Residual risks

1. Shannon and Briar may issue requests beyond the initially authorized URL; platform DNS/IP policy does **not** wrap their connections.
2. Operator overrides (`PEN_REQUIRE_SCOPE=false`, `PEN_ALLOW_SKIP_SCOPE=1`) are powerful — restrict in production-like deployments.
3. Network egress firewalling remains operator-owned.
4. AGPL Shannon/Briar redistribution obligations need human legal review.
