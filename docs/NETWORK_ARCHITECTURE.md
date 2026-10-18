# Network architecture (supported single-operator deployment)

**Status:** READY FOR CONTROLLED TESTING — not a multi-tenant SaaS fabric.  
**Baseline:** destination-policy work merged as `0.2.0a13`. Later alphas keep those controls. Proxy environment variables are not a security boundary; Docker `Internal=true` is the worker connection boundary for direct sockets.

## Planes

| Plane | Network | Internal? | Attaches | Purpose |
|---|---|---|---|---|
| Control | `pen-control` | no | orchestrator, fixtures | Operator/control plane |
| Scanner isolated | `pen-scanner-isolated` | **yes** | Briar default workers | No internet |
| Scanner live | `pen-scanner-live` | **yes** | Briar live workers | On-net fixtures; internet only via proxy |
| Egress | `pen-egress` | no | `egress-gateway` only | Public egress leg for gateway |
| Shannon workers | `shannon-net` (managed) | **yes** | Temporal (also dual-homed), Shannon workers, on-net fixtures/mock | Worker isolation |
| Shannon host gRPC | `pen-shannon-host` | **no** | Temporal only | Host CLI ↔ `127.0.0.1:7233` |
| Shannon gateway egress | `pen-shannon-egress` | no | Shannon egress-gateway | Public egress leg |

Workers must **never** attach to control, host-gRPC, or egress legs.

## Enforcement layers (what each actually does)

1. **Docker `Internal=true`** — connection boundary for workers. Direct sockets to public IPs fail even when `HTTP_PROXY` is unset or ignored. This does **not** authorize destinations by hostname; it denies off-net routes.
2. **Egress gateway (`PEN_PROXY_ALLOW_HOSTS` + resolve-time checks)** — destination-level authorization for *proxied* flows only. Empty allowlist denies all. Resolves DNS and refuses non-public / metadata answers. The gateway connects to an address from that same decision. Default ports **80/443** (`PEN_PROXY_ALLOW_PORTS`). Each proxied redirect request is checked again. Browsers that ignore the proxy are not intercepted.
3. **Launch-time orchestrator gates** — scope registry + DNS→non-public refusal before Shannon/Briar start (`core/isolation/egress.py`). Independent of skip-scope (dual-gate).
4. **Live / pipeline defaults** — `PEN_ALLOW_*` and `PEN_ALLOW_SHANNON_FULL_PIPELINE` default **false**.

## Inventory of network-capable processes

| Process | Network path | Contained by |
|---|---|---|
| Orchestrator / MCP (stdio) | Host / `pen-control` | Operator trust; no remote authn |
| Briar compose worker | `pen-scanner-isolated` or `pen-scanner-live` | Internal + optional proxy |
| Shannon Temporal | `shannon-net` + `pen-shannon-host` | Dual-home; workers stay internal |
| Shannon worker (`keygraph/shannon`) | `shannon-net` only | Internal + wrap/proxy |
| Egress gateway | dual-homed | Allowlist + port + resolve policy |
| On-net fixtures / LLM mock | scanner/shannon nets | Local only |

## Guarantees vs non-claims

| Claim | Status |
|---|---|
| Workers cannot reach public internet without proxy on Internal nets | **Demonstrated** (runtime CI) |
| Proxied destinations limited to allowlist + public resolve + ports | **Demonstrated** (unit + runtime) |
| Redirect/DNS rebinding to non-public via proxy refused | **Demonstrated** (resolve-time) |
| Transparent interception of browsers ignoring proxy | **Not claimed** — Internal net is the fallback block |
| In-engine Shannon/Briar browser navigation containment | **Not claimed** |
| Destination auth for every possible protocol/port beyond gateway | **Not claimed** |
| Multi-tenant network isolation | **N/A** — no tenant plane |

## Fail-closed prerequisites

- Missing Internal network → Briar live / Shannon controlled prepare **blocks**
- Empty `PEN_PROXY_ALLOW_HOSTS` → all CONNECT/HTTP proxy destinations **denied**
- Missing `PEN_ALLOW_SHANNON_LIVE` / full-pipeline ack → live Shannon **blocked**

## Reproduce

```bash
bash scripts/docker_runtime_verify.sh
# Markers: PEN_SCANNER_*_INTERNAL, BRIAR_*_BLOCKED, PROXY_DENIES_*, SHANNON_E2E_*
```
