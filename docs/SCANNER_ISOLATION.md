# Scanner Execution Isolation

Status: **partial platform enforcement** — READY FOR CONTROLLED TESTING, not full in-engine containment.

Verified baseline for this document: `main` after PR #11 (`022669c`) plus Dependabot merges; worker-path work targets `0.2.0a9`.

## Execution topology (actual)

```
Assessment (MCP/CLI)
  ├─ HeadersAdapter → orchestrator Python sockets (platform-owned redirects)
  ├─ ShannonAdapter → host `npx @keygraph/shannon` → Docker CLI
  │                    → shannon-temporal + shannon-worker-* on upstream `shannon-net`
  │                    (NOT pen-scanner-*; platform cannot rewrite worker network)
  └─ BriarAdapter
       ├─ PEN_BRIAR_EXEC=compose (default)
       │    → docker compose run briar-live | briar
       │    → process on pen-scanner-live | pen-scanner-isolated
       └─ PEN_BRIAR_EXEC=host (fail-closed without PEN_ALLOW_BRIAR_HOST_NET=1)
            → host `briar` / `python -m briar` (host network namespace)
```

## Enforced vs launch-time only

| Control | Enforced at | Evidence |
|---|---|---|
| Scope authorization | Launch (adapters/MCP) | Unit + MCP tests |
| DNS→non-public / egress policy | Launch (orchestrator `getaddrinfo`) | Unit tests (mocked DNS) |
| Scope-skip ≠ egress-skip | Launch | Unit tests (0.2.0a8) |
| Egress-disable dual gate | Launch | Unit tests (0.2.0a8) |
| Briar Compose network attachment | **Worker process** (`docker compose run`) | Runtime: inspect + probe from briar container |
| `pen-scanner-isolated` no external egress | **Network** (`internal: true`) | Runtime: `BRIAR_WORKER_ISOLATED_BLOCKED` |
| Authorized fixture on `pen-scanner-live` | **Network** | Runtime: `BRIAR_LIVE_REACHES_FIXTURE` |
| Shannon worker network membership | **Not enforced by platform** | Upstream hardcoded `shannon-net` |
| In-engine DNS rebinding / redirects (Shannon/Briar browsers) | **Not enforced** | Residual |

## What each layer protects

| Component | Scope | Launch egress | Platform Docker network | In-engine DNS/redirects |
|---|---|---|---|---|
| HeadersAdapter | Yes | Yes + redirect re-check | N/A | Platform-owned (no-follow) |
| Shannon adapter | Yes | Yes + `PEN_ALLOW_SHANNON_LIVE` | **No** (upstream `shannon-net`) | **Not controlled** |
| Briar Compose (default) | Yes | Yes + `PEN_ALLOW_BRIAR_LIVE` | **Yes** (`pen-scanner-live` / isolated) | **Not controlled** |
| Briar host mode | Yes | Yes + live + `PEN_ALLOW_BRIAR_HOST_NET` | **No** (host net) | **Not controlled** |
| Gitleaks/Trivy | Path confine | N/A | `--network none` via Docker | N/A |

## Operator environment

| Variable | Default | Meaning |
|---|---|---|
| `PEN_BRIAR_EXEC` | `compose` | `compose` = platform networks; `host` = uncontained host CLI |
| `PEN_COMPOSE_DIR` | cwd | Repository root containing `docker-compose.yml` |
| `PEN_ALLOW_BRIAR_LIVE` | `false` | Required for any live Briar scan |
| `PEN_ALLOW_BRIAR_HOST_NET` | `false` | Required when `PEN_BRIAR_EXEC=host` |
| `PEN_ALLOW_SHANNON_LIVE` | `false` | Ack that Shannon workers are not platform-network-isolated |
| `PEN_REQUIRE_EGRESS_POLICY` | `true` | Launch-time destination evaluation |
| `PEN_ALLOW_EGRESS_DISABLE` | `false` | Dual gate to disable egress policy |
| `PEN_ALLOW_SKIP_SCOPE` | unset | Scope skip only; egress still enforced |
| `PEN_ALLOW_SCOPE_DISABLE` | `false` | Dual gate for `PEN_REQUIRE_SCOPE=false` |

## Remaining limitations

1. **Shannon:** workers stay on upstream `shannon-net`; no safe attach without upstream `--network` hook or fragile Docker CLI interception. Do not claim Compose isolation for Shannon.
2. **Briar Compose live** still has general egress on `pen-scanner-live`; destination allowlisting after launch (redirects/DNS rebinding inside Briar) is not a transparent proxy — launch-time policy + operator firewall remain required.
3. Compose Briar requires a **host Docker CLI** (orchestrator image intentionally has no `docker.sock`).
4. Briar Alpha / AGPL redistribution: human legal review.

## Failure behavior

- Missing scope / failed egress preflight → **blocked**
- Live Shannon without `PEN_ALLOW_SHANNON_LIVE=1` → **blocked**
- Live Briar without `PEN_ALLOW_BRIAR_LIVE=1` → **blocked**
- Live Briar host mode without `PEN_ALLOW_BRIAR_HOST_NET=1` → **blocked**
- Compose mode without Docker / compose file → **failed** (healthcheck fail-closed)
- Briar worker on isolated net reaches `1.1.1.1:443` → Docker verify **fails**
- Briar-live cannot reach local fixture → Docker verify **fails**
