# Security Validation

Verification date: **2026-10-13**  
Current `main` baseline for this work: verify at branch time (PR #11 merge `022669c` + Dependabot).  
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
| `--skip-scope-check` + DNS→non-public still blocks launch | PASS (blocked) | unit tests (0.2.0a8) |
| `PEN_REQUIRE_EGRESS_POLICY=false` without dual gate | PASS (blocked) | unit tests (0.2.0a8) |
| MCP `demo=true` on Shannon without confirm | PASS (blocked) | unit tests (0.2.0a8) |
| Shannon live gate does not enable Briar | PASS (blocked) | unit tests (0.2.0a8) |
| Briar default exec mode is compose | PASS | unit tests (0.2.0a9) |
| Host Briar without `PEN_ALLOW_BRIAR_HOST_NET` | PASS (blocked) | unit tests (0.2.0a9) |
| Compose Briar dry-run plans `docker compose … briar-live` | PASS | unit + docker verify |
| Actual Briar worker on `pen-scanner-isolated` blocks egress | PASS (runtime) | `BRIAR_WORKER_ISOLATED_BLOCKED` |
| Actual Briar-live worker reaches local fixture | PASS (runtime) | `BRIAR_LIVE_REACHES_FIXTURE` |
| Briar-live direct internet blocked (internal net) | PASS (runtime) | `BRIAR_LIVE_DIRECT_EGRESS_BLOCKED` |
| Egress gateway denies unlisted CONNECT host | PASS (runtime) | `PROXY_DENIES_UNLISTED_HOST` |
| Shannon controlled net stand-in isolated | PASS (runtime) | `SHANNON_NET_ISOLATED_BLOCKED` |
| Shannon controlled net reaches gateway | PASS (runtime) | `SHANNON_NET_REACHES_GATEWAY` |
| Shannon stand-in direct blocked with proxy unset | PASS (runtime) | `SHANNON_NET_NOPROXY_DIRECT_BLOCKED` |
| Real Shannon worker image direct blocked | PASS (runtime, when image pullable) | `SHANNON_REAL_WORKER_DIRECT_BLOCKED` |
| Real Shannon worker restart retains isolation | PASS (runtime, when image pullable) | `SHANNON_REAL_WORKER_RESTART_BLOCKED` |
| Compose JSON requires internal scanner nets | PASS | `COMPOSE_NETWORKS_INTERNAL_ASSERTED` |
| Runtime Docker Internal=true on scanner nets | PASS (runtime) | `PEN_SCANNER_*_INTERNAL` |
| Briar-live direct blocked with proxy unset | PASS (runtime) | `BRIAR_LIVE_NOPROXY_DIRECT_BLOCKED` |
| Briar-live restart retains isolation | PASS (runtime) | `BRIAR_LIVE_RESTART_DIRECT_BLOCKED` |
| Briar worker ↛ control plane | PASS (runtime) | `BRIAR_WORKER_NO_CONTROL_PLANE` |
| Briar worker has no docker.sock | PASS (runtime) | `BRIAR_WORKER_NO_DOCKER_SOCK` |
| Missing internal config blocks | PASS | `MISSING_INTERNAL_CONFIG_BLOCKS` + unit |
| Briar compose launch fails closed if net not internal | PASS (unit) | `briar_network_internal` |
| Shannon live without controlled prepare / uncontained ack | PASS (blocked) | unit tests |
| Control network → local fixture | PASS (runtime) | docker verify |
| Transparent proxy as sole boundary | NOT RELIED ON | Internal nets are the boundary |
| Shannon docker wrap named `docker` | PASS | `SHANNON_E2E_DOCKER_WRAP_ACTIVE` + unit |
| Shannon Temporal + worker `--validate-model` (local mock LLM) | PASS (runtime E2E) | `SHANNON_E2E_VALIDATE_MODEL_SUCCEEDED` (CLI exit 0) |
| Temporal host gRPC after validate-model | PASS (runtime) | dual-home + `SHANNON_E2E_TEMPORAL_HOST_READY_AFTER` |
| Worker not on host/egress nets | PASS (runtime) | `SHANNON_E2E_WORKER_NET_ISOLATED` |
| LLM mock served completions | PASS (runtime) | `SHANNON_E2E_LLM_MOCK_SERVED` |
| Shannon E2E fixture reachable / prohibited blocked | PASS (runtime) | `SHANNON_E2E_FIXTURE_*`, `SHANNON_E2E_PROHIBITED_BLOCKED` |
| Shannon E2E redirect follow / DNS blocked | PASS (runtime) | `SHANNON_E2E_REDIRECT_FOLLOW_BLOCKED`, `SHANNON_E2E_DNS_OR_CONNECT_BLOCKED` |
| Shannon E2E restart retention | PASS (runtime) | `SHANNON_E2E_RESTART_PROHIBITED_BLOCKED` |
| Temporal host reconnect after Validation COMPLETED | FIXED | dual-home Temporal; reconnect failure now fails E2E |
| Proxied destination port allowlist (default 80/443) | PASS (unit + runtime) | `PEN_PROXY_ALLOW_PORTS`, `PROXY_DENIES_DISALLOWED_PORT` |
| Metadata / IMDS resolve via proxy | PASS (unit) | `169.254.169.254` / `fd00:ec2::254` denied |
| Full Shannon exploit pipeline without ack | PASS (blocked) | `PEN_ALLOW_SHANNON_FULL_PIPELINE` default false |
| Full Shannon exploit pipeline + production LLM | NOT RUN in CI | intentional — mock + `--validate-model` only |
| Integration `test_docker_prerequisite_detection` skip locally | INTENTIONAL | skips only when Docker binary absent; runs in GHA docker-runtime |
| DNS rebinding inside upstream browsers | NOT IMPLEMENTED | residual |
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
2. Operator overrides (`PEN_REQUIRE_SCOPE=false` + dual gate, `PEN_REQUIRE_EGRESS_POLICY=false` + dual gate, `PEN_ALLOW_SKIP_SCOPE=1`, live gates) are powerful — restrict in production-like deployments. Enabling one live gate does not enable the other.
3. Network egress firewalling remains operator-owned. Launch-time DNS preflight is not in-engine containment.
4. AGPL Shannon/Briar redistribution obligations need human legal review.
