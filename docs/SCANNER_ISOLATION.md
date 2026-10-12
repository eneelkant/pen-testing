# Scanner Execution Isolation

Status: **partial platform enforcement** — READY FOR CONTROLLED TESTING, not full in-engine containment.

Verified on `main` at `93c228b` (PR #10 merge). This release hardens gate independence: scope-skip cannot disable egress, and egress disable needs a dual gate.

## What each layer protects

| Component | Scope preflight | Resolve-time egress policy | Docker network | In-engine DNS/redirects |
|---|---|---|---|---|
| Orchestrator CLI/MCP | Yes | Launch gate for remote tools | N/A (host process) | N/A |
| HeadersAdapter | Yes (fail closed) | Yes + redirect re-check | N/A | Platform-owned (no-follow) |
| Shannon adapter | Yes | Yes **before** `npx` launch + `PEN_ALLOW_SHANNON_LIVE` | Shannon spawns its own workers | **Not controlled** |
| Briar adapter (host CLI) | Yes | Yes **before** CLI launch + `PEN_ALLOW_BRIAR_LIVE` | N/A for host CLI | **Not controlled** |
| Briar Compose `briar` (`workers`) | N/A (image `--help` smoke) | N/A | `pen-scanner-isolated` **`internal: true`** | N/A for `--help` |
| Briar Compose `briar-live` | Operator-driven | Operator + launch policy if via adapter | `pen-scanner-live` (egress on) | **Not controlled** |
| Gitleaks/Trivy | N/A (local paths) | N/A | `--network none` when via Docker | N/A |

**Do not assume** that a successful URL preflight means Shannon or Briar cannot later resolve DNS differently or follow redirects to other hosts.

## Verified vs static-only

| Claim | Evidence type |
|---|---|
| Compose defines `pen-scanner-isolated` with `internal: true` | Static render assert in `scripts/docker_runtime_verify.sh` |
| Isolated network **cannot** connect to `1.1.1.1:443` | **Runtime** probe in Docker verify (PR #6) |
| Control network **can** reach local `fixture-headers` | **Runtime** probe in Docker verify (PR #6; echoed in a7) |
| No `docker.sock` in Compose | Static render grep |
| Launch-time DNS→non-public blocks Shannon/Briar subprocess | Unit tests with mocked DNS |
| Live Shannon blocked without `PEN_ALLOW_SHANNON_LIVE=1` | Unit tests (PR #6) |
| Live Briar blocked without `PEN_ALLOW_BRIAR_LIVE=1` | Unit tests (0.2.0a7) |
| Briar demo / dry-run without live gate | Unit tests (0.2.0a7) |
| `--skip-scope-check` does **not** skip launch DNS/egress | Unit tests (0.2.0a8) |
| `PEN_REQUIRE_EGRESS_POLICY=false` without dual gate | Unit tests (0.2.0a8) — blocked |
| MCP `demo=true` does not waive confirm for Shannon | Unit tests (0.2.0a8) |
| Shannon live gate does not enable Briar | Unit tests (0.2.0a8) |
| Shannon/Briar worker containers inherit platform networks | **False / not implemented** |

## Operator environment

| Variable | Default | Meaning |
|---|---|---|
| `PEN_REQUIRE_SCOPE` | `true` | Require authorization registry |
| `PEN_ALLOW_SCOPE_DISABLE` | `false` | Second gate to honor `PEN_REQUIRE_SCOPE=false` |
| `PEN_ALLOW_SKIP_SCOPE` | unset/false | Required for CLI `--skip-scope-check` (scope only; egress still enforced) |
| `PEN_REQUIRE_EGRESS_POLICY` | `true` | Launch-time destination evaluation for live remote tools |
| `PEN_ALLOW_EGRESS_DISABLE` | `false` | Second gate to honor `PEN_REQUIRE_EGRESS_POLICY=false` |
| `PEN_BLOCK_NON_PUBLIC_RESOLVED` | `true` | Deny DNS→non-public for named hosts |
| `PEN_ALLOW_NON_PUBLIC_LITERALS` | `true` | Allow scoped `127.0.0.1` / RFC1918 literals |
| `PEN_ALLOW_SHANNON_LIVE` | `false` | Explicit ack that Shannon workers are not network-isolated by this platform |
| `PEN_ALLOW_BRIAR_LIVE` | `false` | Explicit ack that host-invoked Briar is not on Compose isolation networks |
| `PEN_EGRESS_ALLOW_HOSTS` | empty | Optional extra host allowlist |

## Remaining limitations

1. Shannon Temporal/Docker workers are not attached to `pen-scanner-*` networks.
2. Host-invoked Briar CLI is not placed into the Compose isolated network automatically.
3. DNS rebinding **after** launch inside upstream engines remains an upstream/operator firewall problem.
4. Briar remains upstream Alpha; AGPL redistribution needs human legal review.

## Failure behavior

- Missing scope engine + active tool → **blocked**
- Live destination fails egress policy → **blocked** (subprocess not started)
- Live Shannon without `PEN_ALLOW_SHANNON_LIVE=1` → **blocked**
- Live Briar without `PEN_ALLOW_BRIAR_LIVE=1` → **blocked** (demo/dry-run exempt)
- `PEN_REQUIRE_EGRESS_POLICY=false` without `PEN_ALLOW_EGRESS_DISABLE=1` → **blocked**
- Shannon without Docker daemon → **blocked**
- Isolated-network runtime probe reaches external IP → Docker verify **fails**
