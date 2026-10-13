# Shannon controlled Temporal / worker E2E

## What is exercised

Script: `scripts/shannon_e2e_verify.sh` (also invoked from `scripts/docker_runtime_verify.sh`).

| Step | Real path? |
|---|---|
| `shannon_net_prepare.sh` | Network prepare + stand-in + real-image probes |
| PATH `docker` → `shannon-docker-wrap` | Yes — intercepts Shannon `docker run` / `compose` |
| Compose override | `external: true` for managed `shannon-net` + Temporal dual-home |
| `npx @keygraph/shannon@3.4.0 start --validate-model` | **Yes** — upstream CLI |
| Temporal `shannon-temporal` | **Yes** — on `shannon-net` + `pen-shannon-host` |
| Worker `keygraph/shannon:3.4.0` | **Yes** — **only** on `shannon-net` |
| LLM | **Local mock** (`tests/fixtures/llm_mock_server.py` + `shannon_models.json`) |
| Target | On-net fixture IP (`headers_server.py`) — not a public site |

## Network architecture (Shannon plane)

| Network | Internal? | Who attaches |
|---|---|---|
| `shannon-net` | **yes** | Temporal, workers, gateway, fixtures, LLM mock |
| `pen-shannon-host` | **no** | **Temporal only** (host CLI ↔ published `127.0.0.1:7233`) |
| `pen-shannon-egress` | **no** | Egress gateway only |

Workers must never attach to `pen-shannon-host`. Isolation boundary remains `shannon-net` `Internal=true`.

## Temporal host reconnect (root cause + fix)

**Symptom:** CLI printed `Validation COMPLETED` then exited non-zero with  
`Could not read the scan outcome from Temporal at 127.0.0.1:7233`.

**Root cause:** Publishing Temporal ports from an **internal-only** Docker network makes host gRPC reconnect flaky after the workflow finishes. This is a host↔Temporal reachability issue, **not** loss of worker isolation.

**Fix:** Dual-home Temporal onto `pen-shannon-host` (non-internal) via `scripts/shannon-compose-external-net.yml`, while workers stay on internal `shannon-net`.

**Regression:** `scripts/shannon_temporal_host_ready.sh` + post-run `SHANNON_E2E_TEMPORAL_HOST_READY_AFTER`.  
E2E **fails** if Temporal reconnect errors persist — we do not treat Validation COMPLETED alone as success.

## Success markers

- `SHANNON_E2E_VALIDATION_COMPLETED`
- `SHANNON_E2E_VALIDATE_MODEL_SUCCEEDED` (adapter `status=succeeded`, no reconnect error)
- `SHANNON_E2E_TEMPORAL_HOST_READY_AFTER`
- `SHANNON_E2E_WORKER_NET_ISOLATED` / `SHANNON_E2E_LLM_MOCK_SERVED`
- Isolation: `SHANNON_E2E_PROHIBITED_BLOCKED`, redirect/DNS/restart markers

## What is not claimed

- Full pentest / exploit pipeline with production prompts
- Third-party LLM provider credentials
- Transparent proxy interception
- Legal clearance for AGPL redistribution (see `docs/LICENSING_REVIEW.md`)

## Operator rollback

1. Revert the PR / pin platform to prior version.
2. Remove CI Node setup step if unused.
3. Delete `scripts/.shannon-docker-bin/` (gitignored shim).
4. `docker rm -f shannon-temporal pen-shannon-* ; docker network rm shannon-net pen-shannon-egress pen-shannon-host`

Live Shannon remains disabled unless `PEN_ALLOW_SHANNON_LIVE=1`.
