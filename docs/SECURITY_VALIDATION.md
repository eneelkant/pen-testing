# Security Validation

Verification date: **2026-10-12**

## Authorization / scope engine

| Case | Result | Evidence |
|---|---|---|
| Authorized in-scope asset (`http://127.0.0.1:18080/`) | PASS | `validate_target_scope` / unit tests |
| Unknown / public URL (`https://example.com`) | PASS | denied |
| Out-of-scope hostname | PASS | denied |
| Excluded asset | PASS | unit test category/exclusion coverage |
| Expired authorization | PASS | `expired.example.invalid` |
| Missing registry / empty target | PASS | fail closed |
| Disallowed testing category | PASS | unit test |
| Production target blocked | PASS | unit test |
| Invalid URL (`not-a-url`) | PASS | MCP service URL validation |
| Redirect cross-origin (headers adapter) | PASS | no-follow + block |
| Redirect same-origin | PASS | allowed |
| Subdomain auto-expansion | PASS (not expanded) | unit test |
| Private IP auto-authorization (`10.0.0.1`) | PASS (not authorized) | scope deny |
| DNS rebinding / post-resolve IP pinning | NOT IMPLEMENTED | residual risk for upstream engines |
| Upstream browser navigation containment | FAIL / not claimed | documented limitation |
| Secret redaction in findings/export | PASS | unit tests |
| Assessment ID path traversal | PASS | UUID-only IDs |
| Report outdir escape | PASS | confined to reports/work dirs |
| Rate limit enforcement (network) | NOT IMPLEMENTED | registry field recorded only |
| Excessive duration hard kill of Shannon worker | PARTIAL | subprocess timeout on adapters; Temporal stop is upstream |

## MCP surface

| Control | Result |
|---|---|
| No arbitrary shell tool | PASS |
| Live assessment requires `confirm_authorized` | PASS |
| Dry-run default | PASS |
| No scan on server start | PASS |

## Docker / isolation (static)

| Control | Result |
|---|---|
| Non-root UIDs in compose | PASS (static) |
| `cap_drop: ALL`, `no-new-privileges` | PASS (static) |
| No docker.sock on workers | PASS (static) |
| Runtime build/run (agent VM) | BLOCKED (no Docker Engine) |
| Runtime build/run (GitHub Actions) | PASS — `Docker build and runtime` on `bb06250` |

## Residual risks

1. Shannon and Briar may issue requests beyond the initially authorized URL.
2. DNS rebinding and response-redirect chains inside upstream engines are not fully mediated.
3. Network egress firewalling is operator-owned.
