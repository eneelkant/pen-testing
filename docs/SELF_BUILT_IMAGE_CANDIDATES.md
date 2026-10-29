# Self-built image candidates

**Status:** evidence pipeline. No production pin is changed by this workflow, and **neither candidate currently passes the image gate** (details below).

**Decision:** a candidate may be published or proposed as a pin only after it passes every check in [Verification](#verification), followed by a separate, reviewed pin PR.

## What the candidates change

Both Dockerfiles build on the **current production pins**, by immutable digest. A unit test enforces this.

| Candidate | Base (production pin) | Package source | Packages upgraded |
|---|---|---|---|
| `docker/candidates/shannon` | `keygraph/shannon:3.4.0@sha256:4e726ed8…` (Wolfi, glibc, apk-tools 2) | The image's own repository is `https://apk.cgr.dev/chainguard`. The public Wolfi repository `https://packages.wolfi.dev/os` is added. Its key `wolfi-signing.rsa.pub` is already trusted in the base image, so every package signature is still verified. | `curl`, `libcurl-openssl4` → 8.23.0; `libbrotlicommon1`, `libbrotlidec1`, `libbrotlienc1` → 1.2.1; `nodejs-22` → newest signed build available |
| `docker/candidates/trivy` | `aquasec/trivy:0.76.0@sha256:2416d1f7…` (Alpine 3.24.2, apk-tools 3) | Alpine's official signed `main` and `community` repositories, already configured in the image | `libcurl` → 8.23.0-r0, `brotli-libs` → 1.2.1-r0, `libexpat` → 2.9.0-r0, `musl`, `musl-utils` → 1.2.6-r3 |

The required minimum versions and the advisories they address are in `docker/candidates/requirements.json`. They come from the raw Trivy 0.76.0 reports of the pinned images in CI run 40318152278 (vulnerability DB `UpdatedAt` 2026-10-26T07:15:18Z).

After each build, the script reads `/lib/apk/db/installed` inside the image and compares each installed version with **apk's own comparator** (`apk version -t`). The result is stored as `candidate-reports/<name>-packages.tsv`, together with the full package database (`<name>-apk-installed.txt`). Any requirement that is missing, older than the minimum, or that can't be compared makes the candidate **not acceptable**, even if the vulnerability scan were clean.

## Package availability (verified 2026-10-26)

| Package | Required | apk.cgr.dev/chainguard | packages.wolfi.dev | Alpine 3.24 main |
|---|---|---|---|---|
| `nodejs-22` | ≥ 22.23.4-r0 | 22.23.2-r1 | 22.23.2-r1 (built 2026-08-07) | — |
| `curl`, `libcurl-openssl4` | ≥ 8.23.0-r0 | 8.22.0-r4 | 8.23.0-r2 | — |
| `libbrotli*` | ≥ 1.2.0-r7 | 1.2.0-r5 | 1.2.1-r1 | — |
| `libcurl`, `brotli-libs`, `libexpat`, `musl` | see requirements.json | — | — | 8.23.0-r0, 1.2.1-r0, 2.9.0-r0, 1.2.6-r3 |

### Node.js: the remaining external blocker for the package requirements

- Upstream Node.js **v22.23.4** is a security release from 2026-10-20. Its `SHASUMS256.txt` verifies against the Node.js release keys: signature by `5BE8A3F6C8A5C01D106C0AD820B1A390B168D356`, listed in `nodejs/release-keys`.
- No Wolfi or Chainguard `nodejs-22` package of 22.23.4 exists yet.
- These alternatives were evaluated and **rejected**:
  - **Dropping the upstream tarball over the apk package.** In the image, `npm-12` → `node-gyp` → `nodejs` are apk dependencies. Removing `nodejs-22` makes apk install `nodejs-26` instead. Keeping it leaves the vulnerable package installed. Faking a package that "provides" `nodejs` would lie to the scanner. Any of these routes would also hide the runtime from Trivy's OS-package detection, so future Node.js CVEs would go unreported. That is a monitoring regression, not a fix.
  - **Building `nodejs-22` 22.23.4 as a self-signed apk with melange.** Technically possible, but it adds a project-owned signing key and a from-source Node.js build to maintain. It would also fix only 6 of the Shannon candidate's ~980 blocking findings; see the next section.
- **Condition to resume:** Wolfi or Chainguard publishes `nodejs-22` ≥ 22.23.4-r0. No code change is needed: the Dockerfile already installs the newest signed build, and the requirement check will pass once it exists.

## Why neither candidate passes the gate (measured, not assumed)

The gate is unchanged: any fixed HIGH/CRITICAL or unscored finding blocks.

**Shannon:** the pinned image has 980 blocking findings in the same CI run.
- 924 are `chromium 149.0.7827.53-r0`. That is also the **newest Chromium in Wolfi**, so no package fix exists.
- 43 are application dependencies under `/app/node_modules`: Node packages, plus Rust crates in `@temporalio/core-bridge`. Only a Keygraph release can fix those.
- The candidate removes the curl, libcurl and brotli rows. The nodejs rows remain until a package exists.

**Trivy:** the OS layer fixes all five Alpine packages, but the static `trivy` binary still contains:
- Go `stdlib` v1.27.2: CVE-2026-111943, fixed in 1.27.3
- `golang.org/x/crypto` `GO-2026-5932`: unscored, and no fixed version will ever be published

An OS-package layer can't change the binary. Only an Aqua Security release can.

**Local pre-push run** (2026-10-26, pinned Trivy 0.76.0, DB `UpdatedAt` 2026-10-26T07:15:18Z; a sandbox, not CI):

| Candidate | Pin blocking | Candidate blocking | Unmet requirements | Runtime |
|---|---:|---:|---|---|
| Shannon | 980 | 975 (924 chromium, 43 app deps, 6 nodejs-22, …) | `nodejs-22` 22.23.2-r1 < 22.23.4-r0 | `--validate-model` E2E passed; worker image ID verified as the candidate |
| Trivy | 7 | 2 (Go `stdlib` CVE-2026-111943, `GO-2026-5932`) | none | `--version`, rootfs self-scan and git/libcurl linkage OK |

Authoritative counts for every run are in the workflow artifact `self-built-image-candidate-evidence`, in `<name>-summary.json`.

## Verification

`scripts/verify_self_built_candidates.sh` (CI job "Build, scan, and runtime-test candidates") does the following:

1. Builds both images for `linux/amd64`, using `docker/candidates` as the build context.
2. Records each image ID and checks the package requirements inside the built image.
3. Checks that the Trivy candidate still works:
   - `trivy --version`
   - it scans its own root filesystem, using the vulnerability database
   - `git`'s HTTP helper (the only `libcurl` consumer) resolves its libraries
4. Scans each candidate with the **pinned** Trivy 0.76.0 image, using `--image-src docker` (the exact local image) and `--platform linux/amd64`. It then takes a `trivy version --format json` database probe with the same cache.
5. Verifies the evidence with `scripts/verify_image_candidate.py`. That script reuses the project's canonical candidate policy:
   - **Published digests** go through `core.supply_chain.candidates.verify_fresh_scan`.
   - **Local tags** are bound to the exact `Metadata.ImageID` and `ArtifactName`, then pass the same classification, platform, scanner-version and database checks.
   - These conditions produce `NOT_VERIFIED`, with **unknown** (`null`) counts rather than zero: missing or malformed JSON; a pre-classified summary without raw `Results`; a wrong digest, image ID or platform; a scanner other than 0.76.0; a missing, stale or future-dated `CreatedAt` or database timestamp; a probe newer than the scan; or an incomplete package check.
6. Runs Shannon's controlled Temporal + worker `--validate-model` E2E **against the candidate**, using local fixtures and a mock model only.
   - The Shannon 3.4.0 CLI always launches the worker image `keygraph/shannon:3.4.0` by tag, so that tag points at the candidate for the duration of the run and is restored afterwards.
   - The E2E fails unless every worker container ran the candidate's image ID (`SHANNON_E2E_WORKER_IMAGE_ID_VERIFIED`).
7. Writes the job outputs `shannon_acceptable` and `trivy_acceptable` **only after every step above has succeeded**. A candidate is acceptable only if:
   - the verified scan is PASS (zero fixed HIGH/CRITICAL, zero unscored), **and**
   - every package requirement is satisfied.

On pull requests, a verified FAIL is recorded as evidence and the job can still succeed. `NOT_VERIFIED` evidence, a build failure or an E2E failure fails the job.

## Publication (manual, main only)

1. A maintainer dispatches the workflow from `main` with `publish_candidates=true`. Any other ref is refused.
2. Both candidates must be acceptable (`--require-clean`). Publication is skipped otherwise.
3. The publish job rebuilds and re-verifies the candidates, then pushes them to the dedicated GHCR candidate packages. That job is the only one with `packages: write`.
4. Each **published digest** is rescanned directly from the registry (`--image-src remote`), with a fresh database probe and an in-image package check. It must pass `verify_image_candidate.py --require-clean`.

A published candidate is **not** adopted automatically. Changing `PINNED_IMAGES` requires a separate reviewed PR with the published digest, its platform digest, raw scan evidence and SHA-256, the scanner version, the database timestamp, and the runtime evidence.

## Limits

- Package repositories are mutable, so candidate builds are not bit-reproducible. What is pinned and recorded is the base image digest, the repository URLs and signing keys, the minimum versions, and the full installed-package database of every build.
- A green "Build, scan, and runtime-test candidates" job means *the evidence is complete*, not that a candidate is clean. Check `shannon_acceptable` and `trivy_acceptable`, or the `*-summary.json` files.
- The existing pinned-image absolute and regression gates are unchanged by this work.


## Latest upstream scan context (2026-10-27)

The upstream scan in CI run [40524341823](https://github.com/eneelkant/pen-testing/actions/runs/40524341823) reported 1,091 absolute blockers across the four pinned images. Shannon had 985 blockers (420 unscored), and the regression gate identified one new unscored Chromium finding: `CVE-2026-106414`, installed `149.0.7827.53-r0`, reported fixed version `155.0.8059.39-r0`. Its gate status was `awaiting-upstream-release`.

These numbers come from a newer scan/database snapshot than the local candidate evidence above; they are not interchangeable. This report does **not** establish that a fixed Chromium build is available in the candidate's signed Wolfi/Chainguard repositories, nor that a candidate is acceptable. Re-run the candidate workflow and inspect its raw scan, package inventory, summary, and runtime evidence before deciding on any image-pin change. Do not add an ignore or treat `--ignore-unfixed` output as the release-gate result.
