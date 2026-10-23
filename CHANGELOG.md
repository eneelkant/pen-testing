# Changelog

## 0.2.0a18 — 2026-10-23

### Security

- Backup create seals every member before any archive write, commits through a staging directory, and leaves an existing archive intact when sealing or staging fails
- Restore decrypts and checksum-verifies every member before replacing any destination file. Staging temps are removed on commit failure. A wrong key or corrupt member writes nothing
- `safe_write_text` writes to a same-directory temp file and `os.replace`s into place so a failed write does not truncate an existing record
- Encrypted manifests refuse plaintext members when encryption is required

### Supply chain

- Image scan reports record repository, tag, digest, platform, scanner version, vulnerability-database metadata, scan timestamp, exit code, finding row counts, and unique CVE counts
- Empty, schema-only, digest-mismatched, stale `CreatedAt`, stale vulnerability-database, and nonzero-exit-with-clean-body Trivy documents are `NOT_VERIFIED`
- Trivy is invoked without a severity pre-filter so UNKNOWN/unscored rows remain visible to the classifier
- CI runs the Python and upstream image scans independently, uploads both artifacts, then fails the job if either gate exits nonzero
- Digests were not changed. The fixed HIGH/CRITICAL and unscored gates remain fail-closed

### Notes

- Counsel review is still pending. This release is not an independent audit
- Not production-ready

## 0.2.0a17 — 2026-10-18

### Supply chain

- Re-scanned the pinned Shannon, Temporal, Gitleaks, and Trivy digests with Trivy 0.76.0. The vulnerability database `UpdatedAt` was still 2026-10-17 18:34:28Z. Counts matched the previous scan. Digests were not changed
- Candidate tags were scanned and rejected: Gitleaks `v8.30.1` had 60 fixed HIGH/CRITICAL findings, Temporal `1.7.3` had 25, and Temporal `1.9.1` had 7. npm `@keygraph/shannon` latest remains `3.4.0`. Trivy `0.76.0` is still the newest stable tag and still reports `CVE-2026-77214`. None of those candidates passed the fixed-finding gate, so no pin moved
- An empty Trivy document is `NOT_VERIFIED` rather than a clean scan. Unscored image findings are blocking. A vendor status of `not_affected` is not a waiver. Withdrawn records are ignored
- CI uploads `image-scan-python.json` and `image-scan-upstream.json` so a failing scan can be reviewed without scraping the log

### Notes

- Counsel review is still pending. This release is not an independent audit
- Not production-ready

## 0.2.0a16 — 2026-10-18

### Security

- The MCP entrypoint accepts stdio only. `sse` and `streamable-http` raise `PermissionError` before a listener starts. There is still no multi-user authentication
- `PEN_DOCTOR_STRICT=1` now fails when assessment encryption is off, when `PEN_DATA_KEY` is not a Fernet key, or when `PEN_ALLOW_SHANNON_FULL_PIPELINE` is set. A required-but-missing key still fails
- The Compose orchestrator sets `PEN_REQUIRE_DATA_ENCRYPTION=true`, `PEN_DOCTOR_STRICT=true`, and `PEN_DATA_KEY` from the host environment. The key is not stored in the image. `scripts/docker_runtime_verify.sh` expects doctor to fail without a key and then retries with an ephemeral key

### Supply chain

- Local Trivy 0.76.0 (vulnerability DB `UpdatedAt` 2026-10-17 18:34:28Z) reported fixed HIGH/CRITICAL findings in the pinned Shannon, Temporal, Gitleaks, and Trivy images. Digests were not moved. The CI image step scans those names and fails when fixed findings are present. Counts are in `docs/SECURITY_EXCEPTIONS.md`
- `python:3.12-slim-bookworm` at `sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258` remains 0 fixed HIGH/CRITICAL and 63 unfixed HIGH/CRITICAL rows. Unfixed rows are not a waiver

### Notes

- Local CLI use can still leave encryption off. That path is not the supported deployment
- Pattern redaction and upstream container logs are unchanged. Overwrite-before-delete is still not forensic erasure
- Counsel review in `docs/LICENSING_REVIEW.md` is still pending. This release is not an independent audit
- Not production-ready

## 0.2.0a15 — 2026-10-18

### Security

- `pen-testing run` is a dry-run unless `--live` is set. `--live` and `--dry-run` together are rejected
- Live scans that skip the authorization registry still consume `PEN_SKIP_SCOPE_RATE_LIMIT_RPS` (default 1). Skipping scope does not disable egress checks
- The egress gateway connects to the address approved in the same decision, so a later DNS change cannot retarget that connection. Proxied redirect hops are checked individually. Browsers that ignore the proxy are still bounded by Docker `Internal=true`, not by this proxy
- Assessment records are encrypted with Fernet when `PEN_DATA_KEY` is set. `PEN_REQUIRE_DATA_ENCRYPTION=1` refuses plaintext. The key is not logged
- Execution results redact logs, errors, artifact values, and metadata on `to_dict`
- `pen-testing cleanup --apply` overwrites regular files before unlink. That is not a guarantee on SSDs or snapshots
- `pen-testing backup` and `pen-testing restore` copy only regular artifact files, skip symlinks, and refuse manifest paths that escape the destination. Writes require `--apply`

### Supply chain

- Direct dependency `cryptography==50.0.2` (with `cffi==2.1.1` and `pycparser==3.11`) for file encryption
- Production and probe images used by this repository are digest-pinned. The orchestrator base is `python:3.12-slim-bookworm` at `sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258`. `python:3.14-slim-bookworm` at `sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83` is not used: Trivy 0.76.0 reported fixed highs `GHSA-6v7p-g79w-8964`, `CVE-2025-47273`, `CVE-2026-97687`, and `CVE-2026-97689`
- `python -m core.supply_chain images` runs Trivy 0.76.0 when `trivy` or Docker is available. Fixed HIGH and CRITICAL findings fail the command. Unfixed findings stay in the report and do not by themselves fail it. If neither tool is available the status is `NOT_VERIFIED`

### Operations

- `pen-testing doctor` reports encryption state and in-process limits without printing key material. `PEN_DOCTOR_STRICT=1` exits 1 when the authorization registry or a required encryption key is missing

### Notes

- Counsel review in `docs/LICENSING_REVIEW.md` is still pending
- Not production-ready

## 0.2.0a14 — 2026-10-17

### Security

- Report and assessment IO refuses symlink path components, including parent directories (`safe_read_text` / `safe_write_text`)
- Assessment records are redacted before they are stored; corrupt records and symlink reads fail closed
- CLI `export-report` inputs and outputs must stay under the work dir, reports dir, or current directory
- Redaction covers GitHub tokens, Slack tokens and webhooks, and `sk-` style keys in addition to existing patterns
- `pen-testing cleanup` removes expired local `.json` / `.md` / `.sarif` / `.log` files under the assessment and report directories. It is dry-run unless `--apply`. It does not follow or delete symlinks. MCP status checks do not delete artifacts
- Authorization records with `rate_limit_rps` are enforced on non-dry-run adapter preflight. `PEN_MAX_INFLIGHT_SCANS` bounds concurrent live CLI/MCP scans in this process

### Supply chain

- `python -m core.supply_chain audit` checks that runtime dependencies are present in `requirements/base.txt` and reports unpinned requirements without treating that report as a CVE scan
- `python -m core.supply_chain emit` writes a CycloneDX 1.5 SBOM from declared requirements. The document has no `vulnerabilities` array
- `rpds-py` is pinned to `2026.9.1`, the version resolved with `jsonschema==4.26.0` during unit tests
- Optional OSV query (`python -m core.supply_chain vuln`) records database results separately from the metadata audit

### Documentation

- `docs/READINESS_SCORECARD.md` records six milestones with PASS / PARTIAL / BLOCKED / FAIL / NOT VERIFIED
- `docs/DATA_PROTECTION.md` describes local retention, redaction, and file confinement
- `docs/LICENSING_REVIEW.md` keeps AGPL questions open; counsel review is not complete

### Notes

- Includes merged `0.2.0a13` destination policy and Shannon full-pipeline gate. This release does not replace that work
- A green metadata audit is not a claim of zero known CVEs
- Pattern redaction does not cover upstream scanner logs written outside this process
- Encryption at rest, backups, and multi-user authentication are not implemented
- Not production-ready

## 0.2.0a13 — 2026-10-13

### Security

- Shared destination policy (`core/isolation/destination_policy.py`) used by egress gateway: allowlist hosts, resolve-time non-public/metadata deny, default ports 80/443 (`PEN_PROXY_ALLOW_PORTS`)
- Gateway image copies the stdlib-only policy module; unit tests cover IPv4/IPv6 documentation ranges and IMDS
- Runtime marker `PROXY_DENIES_DISALLOWED_PORT`
- Live Shannon full pentest pipeline gated by `PEN_ALLOW_SHANNON_FULL_PIPELINE` (default off); supported path remains `--validate-model` + local mock
- Documented network planes/guarantees in `docs/NETWORK_ARCHITECTURE.md`

### Notes

- Docker `Internal=true` remains the connection boundary when clients ignore proxies; destination allowlisting applies to proxied flows
- Status remains READY FOR CONTROLLED TESTING

## 0.2.0a12 — 2026-10-13

### Security / testing

- Fix Shannon docker wrap: stage PATH shim named `docker` → `shannon-docker-wrap` (proxy injection actually intercepts `docker run`)
- Controlled Shannon Temporal + real worker E2E (`scripts/shannon_e2e_verify.sh`):
  - `npx @keygraph/shannon start --validate-model` against local OpenAI-compatible mock
  - on-net fixture reachability; prohibited destinations blocked with proxy unset
  - redirect-follow and DNS/connect blocks; restart retention on real worker image
- Dual-home Temporal on `pen-shannon-host` so host CLI gRPC to `127.0.0.1:7233` is deterministic; workers stay on internal `shannon-net` only
- E2E requires CLI success (no Temporal reconnect false-pass); post-run host readiness + worker net + mock-served regressions
- Wired into `docker_runtime_verify.sh` + CI Node setup; markers prefixed `SHANNON_E2E_*`
- Local fixtures: `tests/fixtures/llm_mock_server.py`, `redirect_server.py`, `shannon_repo/`, `shannon_models.json`

### Notes

- E2E proves Temporal + worker + network isolation with a **mock LLM**, not a full exploit pipeline or third-party provider
- Status remains READY FOR CONTROLLED TESTING

## 0.2.0a11 — 2026-10-13

### Security

- Network-level isolation assertions: scanner nets must be Docker `Internal=true`; fail closed if not
- Briar compose live path verifies the **Compose project** `pen-scanner-live` network is internal before launch (HTTP_PROXY is convenience only; refuses ambiguous host network name matches)
- Runtime proofs with proxy env explicitly unset: `BRIAR_LIVE_NOPROXY_DIRECT_BLOCKED`, `SHANNON_NET_NOPROXY_DIRECT_BLOCKED`
- Briar worker cannot reach control-plane / `docker.sock`: `BRIAR_WORKER_NO_CONTROL_PLANE`, `BRIAR_WORKER_NO_DOCKER_SOCK`
- Restart retention: `BRIAR_LIVE_RESTART_DIRECT_BLOCKED`
- Real Shannon worker image (`keygraph/shannon`) on controlled `shannon-net`: `SHANNON_REAL_WORKER_DIRECT_BLOCKED`, `SHANNON_REAL_WORKER_RESTART_BLOCKED` (distinct from stand-in markers)

### Documentation

- Scanner isolation / security validation updated for network-level (non-proxy) boundary

### Notes

- Full Shannon LLM Temporal E2E scan still not run in CI (keys/time)
- Transparent browser interception still not claimed

## 0.2.0a10 — 2026-10-13

### Security

- Briar-live network is now **internal**; direct internet blocked; optional egress only via dual-homed `egress-gateway` CONNECT proxy (deny-by-default allowlist)
- Shannon controlled mode: pre-create internal `shannon-net`, attach gateway, inject proxy via `shannon-docker-wrap`; fail closed unless prepare succeeds or `PEN_ALLOW_SHANNON_UNCONTAINED_NET=1`
- Runtime proofs: `BRIAR_LIVE_DIRECT_EGRESS_BLOCKED`, `PROXY_DENIES_UNLISTED_HOST`, `SHANNON_NET_ISOLATED_BLOCKED`, `SHANNON_NET_REACHES_GATEWAY`

### Documentation

- `docs/LICENSING_REVIEW.md` (AGPL open questions — not legal clearance)
- `docs/RELEASE_CHECKLIST.md` for controlled releases

### Notes

- Proxy is not transparent; browsers ignoring `HTTP_PROXY` remain residual
- AGPL counsel review still required before production-release claims

## 0.2.0a9 — 2026-10-13

### Security

- Briar default execution is Compose (`PEN_BRIAR_EXEC=compose`) on `pen-scanner-live` / `pen-scanner-isolated`
- Host Briar (`PEN_BRIAR_EXEC=host`) requires `PEN_ALLOW_BRIAR_HOST_NET=1` in addition to `PEN_ALLOW_BRIAR_LIVE=1`
- Docker runtime verifies the **actual** Briar worker container network membership and egress/fixture reachability
- Fixture-headers attached to `pen-scanner-live` for authorized compose-path probes
- Shannon residual clarified: workers remain on upstream `shannon-net` (not platform-attachable without upstream)

### Documentation

- Document enforced vs launch-time controls; Briar compose path vs Shannon uncontained workers

## 0.2.0a8 — 2026-10-12

### Security

- `skip_scope_check` no longer bypasses launch-time DNS/egress policy for Shannon/Briar
- Disabling `PEN_REQUIRE_EGRESS_POLICY` requires `PEN_ALLOW_EGRESS_DISABLE=1` (dual gate)
- MCP `demo=true` waives `confirm_authorized` only for Briar demo (not Shannon/headers)

### Documentation

- Document gate independence and residual in-engine isolation gaps after PR #10 merge (`93c228b`)

## 0.2.0a7 — 2026-10-12

### Security

- Live Briar requires explicit `PEN_ALLOW_BRIAR_LIVE=1` (host CLI is not on platform Compose isolation networks)
- CI concurrency no longer cancels in-flight runs on `main` (preserves post-merge Docker isolation verification)
- Docker runtime verify echoes control-network fixture probe output and fails closed if the fixture never becomes ready

### Documentation

- Reconcile isolation/security docs with `main` after PR #6–#9; document Briar live gate parity with Shannon

## 0.2.0a6 — 2026-10-12

### Security

- Live Shannon requires explicit `PEN_ALLOW_SHANNON_LIVE=1` (workers are not on platform networks)
- Docker runtime verify adds **runtime** probes: isolated network cannot reach `1.1.1.1:443`; control network reaches local fixture

### Documentation

- Reconcile isolation docs after PR #5 merge; distinguish static vs runtime evidence

## 0.2.0a5 — 2026-10-12

### Security

- Launch-time egress policy for live Shannon/Briar/Headers (`core/isolation/`)
- Dual-gate for disabling scope: `PEN_REQUIRE_SCOPE=false` requires `PEN_ALLOW_SCOPE_DISABLE=1`
- Compose: `pen-scanner-isolated` (`internal: true`) for default Briar workers; `briar-live` profile for explicit egress
- Docker runtime verify asserts isolation networks, no `docker.sock`, and runs isolation unit tests
- Headers redirects re-checked with resolve-time non-public policy

### Documentation

- `docs/SCANNER_ISOLATION.md` maps which controls apply to which engines

### Notes

- Does **not** claim in-engine Shannon/Briar DNS/redirect containment after subprocess start

## 0.2.0a4 — 2026-10-12

### Security

- Report exporters refuse final-path symlinks (`safe_write_text` / `O_NOFOLLOW`)

### Documentation

- Reconcile readiness/security docs with PR #3 merge on `main` (`c0bfe27`)

## 0.2.0a3 — 2026-10-12

### Security

- HeadersAdapter fails closed without a scope engine; http(s)-only fetches; resolve-time block for named-host→non-public DNS
- `--skip-scope-check` requires `PEN_ALLOW_SKIP_SCOPE=1`; loopback skip uses parsed hostname (not substring)
- Scheme-less `host/path` scope assets no longer authorize the whole host
- Redact URL userinfo in findings and free-text fields
- Confine Gitleaks/Trivy scan paths under work/reports/cwd; Trivy docker uses `--network none`
- Briar Compose worker: `read_only` + tmpfs

### Added

- `core/net/ssrf.py` and `core/paths.py` helpers
- Post-merge hardening regression suite (`tests/unit/test_post_merge_hardening.py`)

### Notes

- Assessment: READY FOR CONTROLLED TESTING (not production-ready for unconstrained active scanning)
- Shannon/Briar egress containment remains an upstream/operator responsibility

## 0.2.0a2 — 2026-10-12

### Security

- MCP `export_report` outdir confined to `reports_dir` / `work_dir`
- Assessment IDs required to be UUIDs (blocks path-like IDs)
- Scope validation requires absolute http(s) URLs with hostnames (non-path tools)
- Assessment `timeout_seconds` bounded to 1..86400
- Logger forced to stderr with `propagate=False` for stdio MCP safety

### Added

- MCP readiness audit, tool test matrix, and security validation docs
- MCP tool-call regression suite (`tests/unit/test_mcp_tool_calls.py`)
- GitHub Actions `docker-runtime` job + `scripts/docker_runtime_verify.sh` (Engine/Compose build, orchestrator doctor, host smoke)

### Notes

- Local Cursor agent VMs may lack Docker; runtime verification is performed on `ubuntu-latest` GitHub-hosted runners
- AI client E2E UI connections remain environment-dependent

## 0.2.0a1 — 2026-10-12

### Added

- Official MCP Python SDK (`mcp` 2.x) server with constrained tools
- Installers (`installers/install.sh`, `install.ps1`) and unified `scripts/setup_all.sh`
- Client configuration helpers for Cursor, Claude Desktop, and Gemini CLI
- Reproducible requirement sets under `requirements/`
- Client compatibility matrix and release process docs
- GitHub release workflow (tag-driven)

### Security

- MCP assessments default to `dry_run=true` and require `confirm_authorized` for live runs
- Headers redirect no-follow / cross-origin refusal retained from v0.1 readiness work

### Notes

- Alpha: Docker runtime verification may be incomplete in some environments
- ChatGPT remote MCP is documented only; not auto-deployed

## 0.1.0 — 2026-10-12

Initial orchestration platform: Shannon/Briar adapters, scope engine, reporting, Docker Compose, CI.
