# Scanner Execution Isolation

Status: **partial platform enforcement** — READY FOR CONTROLLED TESTING (not production-ready).

Baseline: `main` after PR #17 (`99bb573`) + this release (`0.2.0a11`).

## Execution topology

```
Assessment (MCP/CLI)
  ├─ HeadersAdapter → orchestrator sockets (redirect re-check)
  ├─ ShannonAdapter
  │    ├─ controlled (default when live): prepare internal shannon-net + gateway
  │    │    + PATH wrap injecting HTTP_PROXY into `docker run`
  │    │    + network Internal=true (security boundary; proxy is convenience)
  │    └─ uncontained: PEN_ALLOW_SHANNON_UNCONTAINED_NET=1 (explicit ack)
  └─ BriarAdapter (PEN_BRIAR_EXEC=compose default)
       └─ briar-live on internal pen-scanner-live (asserted Internal before launch)
            ├─ direct: fixture-headers (NO_PROXY)
            └─ internet: only via egress-gateway (allowlist + non-public DNS deny)
```

## Network architecture

| Plane | Network | Internal? | Who attaches |
|---|---|---|---|
| Control / fixtures | `pen-control` | no | orchestrator, fixture-headers |
| Default Briar workers | `pen-scanner-isolated` | **yes** | `briar` (demo / non-live) |
| Live Briar workers | `pen-scanner-live` | **yes** | `briar-live`, fixture-headers, gateway alias |
| Gateway egress leg | `pen-egress` | no | `egress-gateway` only (not Briar) |
| Shannon controlled | `shannon-net` (managed) | **yes** | Shannon workers + gateway |
| Shannon gateway leg | `pen-shannon-egress` | no | Shannon egress gateway only |

Workers must **not** attach to `pen-control` or `pen-egress`. `docker.sock` must not be mounted into workers.

**Security boundary:** Docker `Internal=true` on scanner nets. `HTTP_PROXY` / `HTTPS_PROXY` are convenience for allowlisted CONNECT via the dual-homed gateway — ignoring them must still yield no external route.

## Enforced vs launch-time

| Control | Boundary | Evidence |
|---|---|---|
| Scope / launch DNS egress | Launch | Unit tests |
| Briar compose network attach | Worker container | Runtime inspect |
| Compose / runtime nets `Internal=true` | Docker network | `COMPOSE_NETWORKS_INTERNAL_ASSERTED`, `PEN_SCANNER_*_INTERNAL` |
| Briar-live **no direct internet** | Network `internal: true` | `BRIAR_LIVE_DIRECT_EGRESS_BLOCKED` |
| Briar-live direct blocked w/ proxy unset | Network (not proxy) | `BRIAR_LIVE_NOPROXY_DIRECT_BLOCKED` |
| Briar-live restart retains isolation | Network | `BRIAR_LIVE_RESTART_DIRECT_BLOCKED` |
| Briar-live → fixture | On-net | `BRIAR_LIVE_REACHES_FIXTURE` |
| Briar worker ↛ control plane / docker.sock | Network + mounts | `BRIAR_WORKER_NO_CONTROL_PLANE`, `BRIAR_WORKER_NO_DOCKER_SOCK` |
| Missing / non-internal net blocks launch | Adapter fail-closed | Unit + `MISSING_INTERNAL_CONFIG_BLOCKS` |
| Proxied host allowlist / DNS policy | Gateway process | `PROXY_DENIES_UNLISTED_HOST` + unit tests |
| Shannon-net internal (controlled) | Network + **stand-in** worker | `SHANNON_NET_ISOLATED_BLOCKED` |
| Shannon stand-in, proxy unset | Network | `SHANNON_NET_NOPROXY_DIRECT_BLOCKED` |
| Shannon stand-in → gateway | On-net | `SHANNON_NET_REACHES_GATEWAY` |
| Real Shannon image on shannon-net | Network + **real** image | `SHANNON_REAL_WORKER_DIRECT_BLOCKED` |
| Real Shannon restart retention | Network + **real** image | `SHANNON_REAL_WORKER_RESTART_BLOCKED` |
| Full Shannon Temporal+worker LLM E2E in CI | **Not run** (keys/time) | Controlled prepare + real-image network probes |
| Transparent interception if process ignores proxy on a non-internal net | **Not a claimed boundary** | Use Internal nets |

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
| `PEN_SHANNON_WORKER_IMAGE` | `keygraph/shannon:3.4.0` | Image used for real-worker network probes |

## Remaining limitations

1. Egress gateway is an **explicit HTTP proxy**, not transparent interception — safe only because scanner nets are internal.
2. Shannon controlled mode depends on pre-creating the upstream name `shannon-net`; conflicts with a pre-existing non-internal network fail closed.
3. Full Shannon scan E2E (LLM-backed Temporal workflow) is not exercised in CI — network prepare + stand-in + real-image network probes are.
4. Briar Alpha / AGPL: see `docs/LICENSING_REVIEW.md` (open legal questions).
5. Host Briar (`PEN_BRIAR_EXEC=host`) has no Compose network isolation even with dual gates.
