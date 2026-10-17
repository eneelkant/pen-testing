# Scanner Execution Isolation

Status: **partial platform enforcement** — READY FOR CONTROLLED TESTING (not production-ready).  
See also `docs/NETWORK_ARCHITECTURE.md` for planes, guarantees, and non-claims.

Baseline: `main` after PR #18 (`a4c3bb1`) + this release (`0.2.0a12`).

## Execution topology

```
Assessment (MCP/CLI)
  ├─ HeadersAdapter → orchestrator sockets (redirect re-check)
  ├─ ShannonAdapter
  │    ├─ controlled (default when live):
  │    │    prepare internal shannon-net + gateway
  │    │    + PATH shim `docker` → shannon-docker-wrap (HTTP_PROXY convenience)
  │    │    + network Internal=true (security boundary)
  │    │    + CI E2E: npx start --validate-model → Temporal + real worker
  │    │         + local OpenAI-compatible mock (no public LLM)
  │    └─ uncontained: PEN_ALLOW_SHANNON_UNCONTAINED_NET=1 (explicit ack)
  └─ BriarAdapter (PEN_BRIAR_EXEC=compose default)
       └─ briar-live on internal pen-scanner-live (asserted Internal before launch)
            ├─ direct: fixture-headers (NO_PROXY)
            └─ internet: only via egress-gateway (allowlist + non-public DNS deny)
```

## Shannon components (real path)

| Component | Image / process | Network | Outbound |
|---|---|---|---|
| Host CLI | `npx @keygraph/shannon@3.4.0` | host | Docker API; Temporal client `127.0.0.1:7233` |
| Temporal | `temporalio/temporal:1.7.0` (`shannon-temporal`) | `shannon-net` | on-net worker RPC |
| Worker | `keygraph/shannon:3.4.0` (`shannon-worker-*`) | `shannon-net` (hardcoded) | Temporal; target; LLM via mock/proxy |
| Egress gateway | `pen-testing-egress-gateway` | `shannon-net` + `pen-shannon-egress` | allowlisted CONNECT only |
| Fixture / LLM mock / redirect | local Python fixtures | `shannon-net` | none (servers) |

Task queues are per-scan (`shannon-<hex>`). Workflow type: `pentestPipelineWorkflow` (full scan) or model-validation workflow for `--validate-model`.

## Network architecture

| Plane | Network | Internal? | Who attaches |
|---|---|---|---|
| Control / fixtures | `pen-control` | no | orchestrator, fixture-headers |
| Default Briar workers | `pen-scanner-isolated` | **yes** | `briar` |
| Live Briar workers | `pen-scanner-live` | **yes** | `briar-live`, fixture-headers, gateway |
| Gateway egress leg | `pen-egress` | no | `egress-gateway` only |
| Shannon workers / fixtures | `shannon-net` (managed) | **yes** | Temporal, Shannon workers, gateway, E2E fixtures |
| Shannon Temporal host access | `pen-shannon-host` | **no** | Temporal only (CLI ↔ `127.0.0.1:7233`) |
| Shannon gateway leg | `pen-shannon-egress` | no | Shannon egress gateway only |

**Security boundary:** Docker `Internal=true`. `HTTP_PROXY` is convenience only.

## Enforced vs launch-time

| Control | Boundary | Evidence |
|---|---|---|
| Scope / launch DNS egress | Launch | Unit tests |
| Briar compose / Internal nets | Worker | Runtime markers (`BRIAR_*`) |
| Shannon prepare (stand-in + real image probes) | Network | `SHANNON_NET_*`, `SHANNON_REAL_WORKER_*` |
| Shannon docker wrap named `docker` | PATH shim | `SHANNON_E2E_DOCKER_WRAP_ACTIVE` + unit |
| Shannon Temporal + worker `--validate-model` | Real upstream path | `SHANNON_E2E_VALIDATE_MODEL_SUCCEEDED` (CLI exit 0) |
| Temporal host gRPC after run | Dual-home Temporal | `SHANNON_E2E_TEMPORAL_HOST_READY_AFTER` |
| Worker not on host/egress nets | Runtime inspect | `SHANNON_E2E_WORKER_NET_ISOLATED` |
| Fixture reachable / prohibited blocked (proxy unset) | Network during E2E | `SHANNON_E2E_FIXTURE_*`, `SHANNON_E2E_PROHIBITED_BLOCKED` |
| Redirect follow to 1.1.1.1 blocked | Network | `SHANNON_E2E_REDIRECT_FOLLOW_BLOCKED` |
| DNS/external connect blocked | Network | `SHANNON_E2E_DNS_OR_CONNECT_BLOCKED` |
| Restart retention (real image) | Network | `SHANNON_E2E_RESTART_PROHIBITED_BLOCKED` |
| Full exploit pipeline (LLM pentest) against live targets | **Not claimed in CI** | Use `--pipeline-testing` only under operator control |
| Transparent interception on non-internal nets | **Not claimed** | — |

## Operator gates (all default off / safe)

| Variable | Default | Role |
|---|---|---|
| `PEN_ALLOW_SHANNON_LIVE` | false | Permit live Shannon |
| `PEN_ALLOW_SHANNON_UNCONTAINED_NET` | false | Skip controlled prepare |
| `PEN_ALLOW_SHANNON_FULL_PIPELINE` | false | Permit non-`--validate-model` Shannon starts |
| `PEN_PROXY_ALLOW_PORTS` | `80,443` | Proxied destination ports |
| `PEN_ALLOW_BRIAR_LIVE` / `PEN_ALLOW_BRIAR_HOST_NET` | false | Briar live / host-net |
| `PEN_BRIAR_EXEC` | compose | compose vs host |
| `PEN_PROXY_ALLOW_HOSTS` | empty | Deny-by-default proxied destinations |
| `PEN_ALLOW_EGRESS_DISABLE` | false | Dual gate with require-egress |
| `PEN_SHANNON_WORKER_IMAGE` | `keygraph/shannon:3.4.0` | Real worker image |
| `SHANNON_AI_BASE_URL` / `SHANNON_AI_MODEL` | unset | Point workers at local mock for E2E |

## Remaining limitations

1. CI Shannon E2E uses `--validate-model` (Temporal + real worker + local LLM mock), **not** a full pentest pipeline against a vulnerable app with a production LLM.
2. Egress gateway is an explicit HTTP proxy; safe because nets are internal.
3. Briar Alpha / AGPL: see `docs/LICENSING_REVIEW.md`.
4. Host Briar / Shannon uncontained remain dual-gated escape hatches.
