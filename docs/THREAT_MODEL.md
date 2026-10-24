# Threat model

**Status:** Internal engineering notes for `0.2.0a16`. This is not an independent audit, a penetration test, or a statement that the threats below are closed.

**System:** A single-operator orchestrator. It starts Shannon, Briar, and small scanners for targets listed in `scopes/registry.yaml`. The supported deployment is Docker Compose on a host the operator controls. The MCP server speaks stdio to a local client. There is no multi-user account system.

## Assets

- Authorization registry and the decision to run an active tool
- Assessment records, reports, and backup archives
- `PEN_DATA_KEY` and provider API keys in the environment
- The host Docker daemon, which the operator uses to start workers. The orchestrator container does not mount `docker.sock`
- Upstream images: Shannon worker, Temporal, Gitleaks, Trivy, and the Python base

## Actors

| Actor | Trust |
|---|---|
| Operator | Full trust for the host account that runs the CLI, Compose, and MCP client |
| Local MCP client | Same trust as the operator. The server does not authenticate a second user |
| Scan target | Untrusted. Only in-scope fixtures or assets the operator listed |
| Upstream scanner process | Untrusted code in a separate container. It must not receive the host Docker socket |
| Anyone else on the network | No access is designed for them. A remote MCP listener is refused |

## Boundaries

1. **Process boundary.** CLI and MCP run as the operator. Anyone who can start that process can use its files and environment variables.
2. **Stdio boundary.** `mcp.run` rejects `sse` and `streamable-http` before a socket is opened.
3. **Scope and egress.** Live tools check the registry. Skipping the registry does not skip destination checks. In-process rate and concurrency limits reset when the process exits.
4. **Docker network boundary.** Worker networks in Compose are `Internal=true`. The egress gateway authorizes proxied HTTP(S) only. A client that never uses the proxy is not intercepted; the internal network is what stops a direct socket.
5. **File boundary.** Assessment IO refuses symlink components. Exports stay under configured roots. Encryption applies to files this process writes when a valid Fernet key is set. The Compose service requires that key.
6. **Supply-chain boundary.** Python dependencies are pinned, scanned with OSV, and listed in a CycloneDX SBOM. Container digests are pinned. Fixed HIGH and CRITICAL image findings fail `python -m core.supply_chain images`. Unfixed findings stay visible and do not by themselves fail that command.

## Threats and what is in place

| Threat | Control in this tree | Residual |
|---|---|---|
| Unauthenticated remote use of scan tools | Stdio-only MCP; Compose publishes no orchestrator port | A local user can still run the CLI. No tenant isolation |
| Scan of an asset the operator did not list | Scope registry; default dry-run; `--live` required | The operator can point the registry at the wrong asset |
| Worker reaches a public or metadata address directly | `Internal=true`; launch-time DNS checks; gateway connects to the approved address | Browsers that ignore `HTTP(S)_PROXY` are not proxied. In-engine DNS and redirect behavior of Shannon and Briar is not claimed |
| Full Shannon exploit pipeline in CI or Compose | `PEN_ALLOW_SHANNON_FULL_PIPELINE` default off; strict doctor fails when it is on | An operator can unset strict mode and set the gate |
| Secret copied into an assessment file | Pattern redaction, then optional Fernet encryption | Unknown secret shapes pass through. Upstream container logs are not redacted |
| Plaintext assessments on the supported deployment | Compose sets `PEN_REQUIRE_DATA_ENCRYPTION` and strict doctor | Local CLI without those variables still writes plaintext |
| Backup or restore escapes the data directories | Symlinks skipped; `..` manifest paths rejected | The operator chooses the archive directory and the key |
| Claim of forensic deletion | None. Overwrite-before-unlink is documented as not forensic | Snapshots and SSDs can retain bytes |
| Known fixed vulnerabilities in upstream images | Digest pins; Trivy classification fails closed on fixed HIGH/CRITICAL | Shannon, Temporal, Gitleaks, and the Trivy scanner image currently fail that classification. Pins were not moved. See `docs/SECURITY_EXCEPTIONS.md` |
| AGPL / license obligations | `docs/LICENSING_REVIEW.md` lists the questions | Counsel has not answered them |

## Explicit non-claims

- Production readiness
- Multi-user authentication or tenant isolation
- Interception of traffic from clients that do not use the proxy
- Disk encryption, a KMS, or key escrow
- Forensic erasure
- A vulnerability waiver for unfixed or fixed image findings
- Legal clearance
- An independent security audit
