# Security exception register

**Status:** Inventory of findings this repository has actually scanned. Nothing in this file is a waiver, an ignore-file entry, or an acceptance signature.

**Scanner:** Trivy 0.76.0. Vulnerability DB `UpdatedAt` 2026-10-17 18:34:28Z, downloaded 2026-10-18 01:15:57Z for the inventory below. Image sources were the registry (`--image-src remote`) for the upstream images. Docker and Trivy were not installed in the `0.2.0a18` authoring environment, so a fresh local rescan is `NOT_VERIFIED` here; CI artifacts on the PR head are the live evidence.

**Gate:** `python -m core.supply_chain images` fails on fixed HIGH or CRITICAL findings and on unscored findings. Unfixed findings are printed and do not by themselves fail the command. Empty, schema-only, digest-mismatched, stale `CreatedAt`, stale vulnerability-database, and nonzero-exit-with-clean-body Trivy documents are `NOT_VERIFIED`. There is no `.trivyignore`. A vendor status such as `not_affected` is not a waiver. No finding below is marked verified non-applicable. Reports distinguish `finding_row_count` from `unique_cve_count`.

**Owner:** repository maintainer. **Next review:** 2026-11-18.

Counsel review of `docs/LICENSING_REVIEW.md` is still pending. That is a legal question, not a CVE exception.

## Reproduction on 2026-10-18

Trivy 0.76.0. `trivy image --download-db-only` left the database at `UpdatedAt` 2026-10-17 18:34:28Z (`NextUpdate` 2026-10-18 18:34:28Z). Registry index digests for the pinned tags were unchanged. Re-scans:

| Image | Report CreatedAt | Exit classification |
|---|---|---|
| `zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46` | 2026-10-18T02:06:08.124976912Z | FAIL, 39 fixed (1 CRITICAL, 38 HIGH), 0 unfixed |
| `aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222` | 2026-10-18T02:06:07.810236233Z | FAIL, 1 fixed HIGH (`CVE-2026-77214`), 0 unfixed |

Shannon `3.4.0` index `sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e` and Temporal `1.7.0` index `sha256:9c5b386d86bca59ba08f32ddc4c51287351c8c616b6a8359f03e96a585e137f4` still resolve to those digests. Their earlier counts on this same database were 523 and 49 fixed HIGH/CRITICAL. Those pins stay.

## Candidates that were not adopted

npm `@keygraph/shannon` `latest` is `3.4.0`. There is no newer worker tag to test. Shannon's own `package/infra/compose.yml` runs `temporalio/temporal:1.7.0` with `server start-dev`. A newer Temporal tag was not substituted, because every scanned candidate still fails the fixed-finding gate and the `--validate-model` path was not run against it.

| Candidate | Index digest | CreatedAt | Fixed HIGH/CRITICAL | Decision |
|---|---|---|---|---|
| `zricethezav/gitleaks:v8.30.1` | `sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` | 2026-10-18T02:06:04.096333618Z | 60 (2 CRITICAL, 58 HIGH), including `CVE-2026-31789` | Rejected. The `8.30.1` binary accepts `detect --source --no-git --report-format json` and returned exit 0 on this tree, but the image is not cleaner than `v8.21.2` |
| `temporalio/temporal:1.7.3` | `sha256:906f9765cde508333ef191aab908bc724657b5f736cb5ead13921d9a45b33622` | 2026-10-18T02:06:06.48785756Z | 25 HIGH | Rejected. Still failing, and the Shannon E2E was not run against it |
| `temporalio/temporal:1.9.1` | `sha256:ad4c82c97bd12b417d1ea942610dbcd511afb250c4d5ed26c694009533df447e` | 2026-10-18T02:06:07.527976093Z | 7 HIGH (`CVE-2026-14456`, `CVE-2026-102941`, `CVE-2026-78669`, `CVE-2026-78667`, `CVE-2026-97031`) | Rejected. Still failing. `start-dev` compatibility with Shannon 3.4.0 was not demonstrated |
| `aquasec/trivy:0.76.0` | same pin as above | same as above | 1 HIGH | No newer stable tag on Docker Hub. `canary` was not adopted |

Gitleaks `v8.30.1` CLI check used the GitHub release binary `gitleaks_8.30.1_linux_x64.tar.gz`, not the container. Command: `gitleaks detect --source /workspace --no-git --verbose --report-format json --report-path /tmp/gitleaks-830.json`. Exit 0. No leaks. That does not clear the image.

## Python base — fixed HIGH/CRITICAL still zero; unscored now visible

Image: `python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258`

CI on `85ac470` (PR run `40005558585`), report `CreatedAt` `2026-10-23T18:46:24.556020881Z`. Result: `FAIL`. `blocking_count` 2, both `unscored` / `UNKNOWN` severity (`DLA-4845-1` on `ca-certificates` with a fixed version, and `CVE-2026-82560` on `perl-base` with an empty fixed version). Fixed HIGH/CRITICAL count remains 0. Unfixed HIGH/CRITICAL package rows remain 63. Full report without a severity pre-filter: `finding_row_count` 289, `unique_cve_count` 130. Earlier inventories that scanned only `HIGH,CRITICAL` reported `PASS` with `blocking_count` 0 because UNKNOWN rows were never emitted. That is not a waiver of the unscored gate.

The 63 unfixed HIGH/CRITICAL rows are package copies of 16 CVE ids. util-linux is eight binary packages times six CVEs (48 rows).

| CVE | Packages | Installed | Severity |
|---|---|---|---|
| CVE-2025-7458 | libsqlite3-0 | 3.40.1-2+deb12u2 | CRITICAL |
| CVE-2023-45853 | zlib1g | 1:1.2.13.dfsg-1 | CRITICAL |
| CVE-2026-11822, CVE-2026-11824 | libsqlite3-0 | 3.40.1-2+deb12u2 | HIGH |
| CVE-2026-53613, CVE-2026-53615, CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410 | bsdutils, libblkid1, libmount1, libsmartcols1, libuuid1, mount, util-linux, util-linux-extra | 2.38.1-5+deb12u3 | HIGH |
| CVE-2026-41992 | gzip | 1.12-1 | HIGH |
| CVE-2026-54369 | libacl1 | 2.3.1-3 | HIGH |
| CVE-2025-69720 | libncursesw6, libtinfo6, ncurses-base, ncurses-bin | 6.4-4 | HIGH |
| CVE-2026-84782 | libssl3, openssl | 3.0.22-1~deb12u1 | HIGH |
| CVE-2026-16742 | libsystemd0, libudev1 | 252.39-1~deb12u2 | HIGH |
| CVE-2026-9538 | perl-base | 5.36.0-7+deb12u4 | HIGH |

The orchestrator container is user `10001`, `cap_drop: ALL`, `no-new-privileges`, `read_only`, and its command is doctor. It does not mount the Docker socket. Those constraints are context for a reviewer. They are not a finding suppression. Debian had published no `FixedVersion` for these rows in this database. When a fixed digest exists, rescan it before switching the pin.

`python:3.14-slim-bookworm@sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83` is not used. An earlier scan failed on fixed highs `GHSA-6v7p-g79w-8964`, `CVE-2025-47273`, `CVE-2026-97687`, and `CVE-2026-97689`.

## Upstream images — fixed findings, pins unchanged

CI on `85ac470` (PR run `40005558585`), Trivy 0.76.0, no severity pre-filter. Status `FAIL` for each image. Top-level `blocking_count` **1068** = **641** fixed HIGH/CRITICAL + **427** unscored UNKNOWN. Digests unchanged. Artifact `image-scan-upstream`. Historical HIGH/CRITICAL-only count on `ac712a4` was 612; the increase is from a fresher vulnerability DB (fixed HIGH/CRITICAL alone is now 641) plus previously hidden UNKNOWN rows.

| Image | Report CreatedAt | Fixed HIGH/CRITICAL | Unscored | Rows / unique ids |
|---|---|---|---|---|
| `keygraph/shannon:3.4.0@sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e` | 2026-10-23T18:46:54.910207566Z | 548 (37 CRITICAL, 511 HIGH) | 419 | 1785 / 1769 |
| `temporalio/temporal:1.7.0@sha256:9c5b386d86bca59ba08f32ddc4c51287351c8c616b6a8359f03e96a585e137f4` | 2026-10-23T18:47:06.638250792Z | 51 HIGH | 4 | 135 / 99 |
| `zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46` | 2026-10-23T18:47:14.960844558Z | 40 (1 CRITICAL, 39 HIGH) | 1 | 124 / 107 |
| `aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222` | 2026-10-23T18:47:24.645779064Z | 2 HIGH (`CVE-2026-77214`, `CVE-2026-111943`) | 3 | 6 / 5 |

The Shannon and Temporal tags are the ones the `--validate-model` path starts. Replacing them changes the worker that CI isolation tests run. CI on `85ac470` still printed Docker runtime success before the image gate. The Gitleaks tag is the CI `detect` image. The Trivy tag is the scanner image the supply-chain command runs when the `trivy` binary is absent. The adapter pins in `integrations/scanners/trivy.py` (`0.58.1`) and the Gitleaks adapter were not bumped.

## Not exceptions

- OSV results for Python requirements are a separate command (`python -m core.supply_chain vuln`). They do not clear image findings.
- Pattern redaction misses unknown secret formats. Upstream container logs are outside this process.
- Overwrite-before-unlink is not forensic erasure.
- AGPL questions in `docs/LICENSING_REVIEW.md` stay open until qualified counsel answers them.
