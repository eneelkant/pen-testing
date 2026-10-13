# Scanner Execution Isolation

Status: **partial platform enforcement** — READY FOR CONTROLLED TESTING (not production-ready).

Baseline: `main` after PR #16 (`671b2db`) + this release (`0.2.0a10`).

## Execution topology

```
Assessment (MCP/CLI)
  ├─ HeadersAdapter → orchestrator sockets (redirect re-check)
  ├─ ShannonAdapter
  │    ├─ controlled (default when live): prepare internal shannon-net + gateway
  │    │    + PATH wrap injecting HTTP_PROXY into `docker run`
  │    └─ uncontained: PEN_ALLOW_SHANNON_UNCONTAINED_NET=1 (explicit ack)
  └─ BriarAdapter (PEN_BRIAR_EXEC=compose default)
       └─ briar-live on internal pen-scanner-live
            ├─ direct: fixture-headers (NO_PROXY)
            └─ internet: only via egress-gateway (allowlist + non-public DNS deny)
```

## Enforced vs launch-time

| Control | Boundary | Evidence |
|---|---|---|
| Scope / launch DNS egress | Launch | Unit tests |
| Briar compose network attach | Worker container | Runtime inspect |
| Briar-live **no direct internet** | Network `internal: true` | `BRIAR_LIVE_DIRECT_EGRESS_BLOCKED` |
| Briar-live → fixture | On-net | `BRIAR_LIVE_REACHES_FIXTURE` |
| Proxied host allowlist / DNS policy | Gateway process | `PROXY_DENIES_UNLISTED_HOST` + unit tests |
| Shannon-net internal (controlled) | Network + stand-in worker | `SHANNON_NET_ISOLATED_BLOCKED` |
| Shannon stand-in → gateway | On-net | `SHANNON_NET_REACHES_GATEWAY` |
| Browser ignoring HTTP_PROXY | **Not enforced** | Residual |
| Full Shannon Temporal+worker E2E scan in CI | **Not run** (keys/time) | Controlled prepare + stand-in |

## Operator gates (all default off / safe)

| Variable | Default | Role |
|---|---|---|
| `PEN_ALLOW_SHANNON_LIVE` | false | Permit live Shannon at all |
| `PEN_ALLOW_SHANNON_UNCONTAINED_NET` | false | Skip controlled shannon-net prepare |
| `PEN_ALLOW_BRIAR_LIVE` | false | Permit live Briar |
| `PEN_ALLOW_BRIAR_HOST_NET` | false | Permit `PEN_BRIAR_EXEC=host` |
| `PEN_BRIAR_EXEC` | compose | compose vs host |
| `PEN_PROXY_ALLOW_HOSTS` | empty | Deny-by-default proxied destinations |
| `PEN_ALLOW_EGRESS_DISABLE` | false | Dual gate with `PEN_REQUIRE_EGRESS_POLICY` |
| `PEN_ALLOW_SKIP_SCOPE` | false | Scope only; egress still enforced |

## Remaining limitations

1. Egress gateway is an **explicit HTTP proxy**, not transparent interception.
2. Shannon controlled mode depends on pre-creating the upstream name `shannon-net`; conflicts with a pre-existing non-internal network fail closed.
3. Full Shannon scan E2E (LLM-backed) is not exercised in CI — network prepare + worker stand-in are.
4. Briar Alpha / AGPL: see `docs/LICENSING_REVIEW.md` (open legal questions).
