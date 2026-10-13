# Controlled release checklist

Use before tagging a non-alpha release. Status values: `PASS` / `FAIL` / `BLOCKED` / `N/A`.

## Security boundaries

- [ ] Live Shannon disabled by default (`PEN_ALLOW_SHANNON_LIVE` unset/false)
- [ ] Live Briar disabled by default (`PEN_ALLOW_BRIAR_LIVE` unset/false)
- [ ] Briar host-net separately gated (`PEN_ALLOW_BRIAR_HOST_NET`)
- [ ] Shannon uncontained-net separately gated (`PEN_ALLOW_SHANNON_UNCONTAINED_NET`)
- [ ] Scope-skip does not disable egress
- [ ] Egress-disable dual-gate enforced
- [ ] Docker runtime markers present on CI head:
  - `COMPOSE_NETWORKS_INTERNAL_ASSERTED`
  - `PEN_SCANNER_ISOLATED_INTERNAL=true` / `PEN_SCANNER_LIVE_INTERNAL=true`
  - `BRIAR_WORKER_ISOLATED_BLOCKED`
  - `BRIAR_WORKER_NO_CONTROL_PLANE`
  - `BRIAR_WORKER_NO_DOCKER_SOCK`
  - `BRIAR_LIVE_DIRECT_EGRESS_BLOCKED`
  - `BRIAR_LIVE_NOPROXY_DIRECT_BLOCKED`
  - `BRIAR_LIVE_RESTART_DIRECT_BLOCKED`
  - `BRIAR_LIVE_REACHES_FIXTURE`
  - `PROXY_DENIES_UNLISTED_HOST`
  - `SHANNON_NET_ISOLATED_BLOCKED` (stand-in)
  - `SHANNON_NET_NOPROXY_DIRECT_BLOCKED` (stand-in)
  - `SHANNON_NET_REACHES_GATEWAY` (stand-in)
  - `SHANNON_REAL_WORKER_DIRECT_BLOCKED` (real upstream image)
  - `SHANNON_REAL_WORKER_RESTART_BLOCKED` (real upstream image)
  - `MISSING_INTERNAL_CONFIG_BLOCKS`
- [ ] No `docker.sock` in Compose render
- [ ] Report path confinement + symlink-safe writes still pass

## Quality

- [ ] Unit + isolation + smoke green on the release SHA
- [ ] Gitleaks / dependency metadata green
- [ ] MCP nine-tool discovery green
- [ ] Docs match enforced vs launch-only claims

## Licensing / ops

- [ ] `docs/LICENSING_REVIEW.md` reviewed by qualified counsel for the intended distribution model
- [ ] `THIRD_PARTY_NOTICES.md` current
- [ ] Operator runbook: verify runtime isolation **before** enabling live gates
- [ ] Known limitations documented (browser proxy bypass, Shannon upstream coupling)

## Explicit non-claims

Do **not** claim production readiness for multi-tenant SaaS, billing, authn/z beyond local operator scope, or complete in-engine DNS/redirect containment unless separately implemented and evidenced.
