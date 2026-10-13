# Shannon controlled Temporal / worker E2E

## What is exercised

Script: `scripts/shannon_e2e_verify.sh` (also invoked from `scripts/docker_runtime_verify.sh`).

| Step | Real path? |
|---|---|
| `shannon_net_prepare.sh` | Network prepare + stand-in + real-image probes |
| PATH `docker` → `shannon-docker-wrap` | Yes — intercepts Shannon `docker run` |
| `npx @keygraph/shannon@3.4.0 start --validate-model` | **Yes** — upstream CLI |
| Temporal `shannon-temporal` on `shannon-net` | **Yes** |
| Worker `keygraph/shannon:3.4.0` | **Yes** |
| LLM | **Local mock** (`tests/fixtures/llm_mock_server.py`) — not a cloud provider |
| Target | On-net fixture IP (`headers_server.py`) — not a public site |

## What is not claimed

- Full pentest / exploit pipeline (`pentestPipelineWorkflow` end-to-end with production prompts)
- Third-party LLM provider credentials or billing
- Transparent proxy interception

## Operator rollback

1. Revert the PR / pin platform to prior version.
2. Remove CI Node setup step if unused.
3. Delete `scripts/.shannon-docker-bin/` (gitignored shim).
4. `docker rm -f shannon-temporal pen-shannon-* ; docker network rm shannon-net pen-shannon-egress`

Live Shannon remains disabled unless `PEN_ALLOW_SHANNON_LIVE=1`.
