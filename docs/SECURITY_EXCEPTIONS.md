# Security exception register

**Status:** Inventory of findings this repository has actually scanned. Nothing in this file is a waiver, an ignore-file entry, or an acceptance signature.

**Scanner:** Trivy 0.76.0. Fresh local inventory below used vulnerability DB `UpdatedAt` 2026-10-23T19:15:43.7344174Z (`NextUpdate` 2026-10-24T19:15:43Z, `DownloadedAt` 2026-10-24T01:09:38Z). Image JSON from Trivy does not embed `VulnerabilityDB`; the classifier requires `UpdatedAt` from the report or from a `trivy version --format json` probe. Historical CI inventory on `85ac470` used an earlier DB snapshot (see tables). There is no `.trivyignore`.

**Gate:** `python -m core.supply_chain images` fails on fixed HIGH or CRITICAL findings and on unscored findings. Unfixed findings are printed and do not by themselves fail the command. Empty, schema-only, digest-mismatched, stale `CreatedAt`, missing or stale vulnerability-database `UpdatedAt`, and nonzero-exit-with-clean-body Trivy documents are `NOT_VERIFIED`. A vendor status such as `not_affected` is not a waiver. No finding below is marked verified non-applicable. Reports distinguish `finding_row_count` from `unique_cve_count`.

**Owner:** repository maintainer. **Next review:** 2026-11-18.

**Merge regression baseline:** `core/supply_chain/image_baseline.json` lists the blocking findings already present in the current upstream pins so that merges can be blocked on *new* findings only (policy Option B; procedure in `docs/IMAGE_BASELINE.md`). It is not a waiver either. Its entries are digest-bound, expire within 31 days, need owner approval, and leave the absolute result unchanged. The absolute gate, which fails on every finding listed here, remains the release gate (Option A).

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

Rescan 2026-10-24 (Trivy 0.76.0). Earlier pass used DB `UpdatedAt` 2026-10-23T19:15:43Z. Follow-up candidates below used DB `UpdatedAt` 2026-10-24T01:18:19Z (`DownloadedAt` 2026-10-24T01:56:42Z), host `trivy image --image-src remote`, no severity filter. None passed zero fixed HIGH/CRITICAL and zero unscored.

| Candidate | Immutable digest | CreatedAt | Fixed HIGH/CRITICAL | Unscored | Blocking | Decision |
|---|---|---|---|---|---|---|
| `python:3.12-slim-bookworm` (tag tip) | `sha256:57d96f71de145a98e7ceca18ee4ade77bba4103a33a72dfaea026b23625c6bf0` | 2026-10-24T01:12:19Z | 0 | 2 | 2 | Rejected. Still fails unscored gate |
| `python:3.12.13-slim-bookworm` | `sha256:6e13e65c55e33adf203d77ee371cf8bf5d81bd4902ef07565721f46bf44917af` | 2026-10-24T06:12:50Z | 11 | 7 | 18 | Rejected. Worse than pinned `34386ef0…` (introduces fixed HIGH/CRITICAL) |
| `python:3.13-slim-bookworm` (tag tip) | `sha256:4cea12ab7d78a3312c85f8cab19b6971d4fe9704da25443986c0bc20a6678850` | 2026-10-24T01:56:52Z | 4 | 2 | 6 | Rejected. Introduces fixed HIGH/CRITICAL |
| `python:3.14-slim-bookworm` (tag tip) | `sha256:7dff173021016c8829ae58d5ce112ffc388073ebe67f351aeb6ba2909e35f847` | 2026-10-24T02:23:13Z | 4 | 2 | 6 | Rejected. Same fixed HIGH package set as earlier 3.14 tip (`GHSA-6v7p-g79w-8964`, `CVE-2025-47273`, `CVE-2026-97687`, `CVE-2026-97689`) plus unscored |
| `python:3.12-slim` (tag tip) | `sha256:e8a38829209aea82774882e5157e1f7c3e8c8393ff53a697b3580896e57f345c` | 2026-10-24T01:59:36Z | 0 | 1 (`CVE-2026-82560`) | 1 | Rejected. Unscored remains blocking; not bookworm pin family |
| `keygraph/shannon:3.4.0` (Hub tip; **not a new image**) | `sha256:9e53649ed684d9e6667740677474fcbe757387c7c71605eedd5f2130d0f8644a` | 2026-10-24T01:56:50Z | 551 | 419 | 970 | Not a candidate. This is the linux/amd64 child of the pinned index `4e726ed8…` (registry-verified 2026-10-24); the digest did not move |
| `zricethezav/gitleaks:v8.30.1` | `sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb` | 2026-10-24T01:12:26Z | 72 | 6 | 78 | Rejected. Worse than pinned `v8.21.2` |
| `temporalio/temporal:1.7.3` | `sha256:1683f097876c2af71ba833bd9418910601be12d4a25422f2c4ebec45113e1bc2` | 2026-10-24T01:12:25Z | 27 | 3 | 30 | Rejected |
| `temporalio/temporal:1.8.1` | `sha256:d7fe04db99586b7e20c3ee96ced04e5585be380b5a565cabb1fb40281f1a64b5` | 2026-10-24T01:56:51Z | 32 | 3 | 35 | Rejected. Still failing; Shannon path not revalidated |
| `temporalio/temporal:1.9.1` | `sha256:150d6208d7b24371e4080f49780e6061611f6279cd6908236e9a34ae5746c1b5` | 2026-10-24T01:12:23Z | 8 | 3 | 11 | Rejected |
| `aquasec/trivy:0.76.1` / `latest` | `sha256:2e6c00d711ab4ae41d8a30c2c1fd3bd3b62704c177bb120f95012e939edfb3df` | 2026-10-24T01:56:53Z | 1 | 3 | 4 | Rejected |
| `aquasec/trivy:0.76.0` (Hub tip; **not a new image**) | `sha256:166061a4a15c64a94a3aab430659e2c166dc0815fbc54a222c6d56d64132f552` | 2026-10-24T01:58:59Z | 3 | 3 | 6 | Not a candidate. This is the linux/amd64 child of the pinned index `2416d1f7…` (registry-verified 2026-10-24); the digest did not move |
| `aquasec/trivy:canary` | `sha256:307afa4f9cfb610229338d837c03f2a5623efb4dd08bef03ebb1a9598afd9b2c` | 2026-10-24T01:59:01Z | 0 | 3 | 3 | Rejected. Unscored blockers remain; canary not a pin |

Remediation branch rescan of pinned images (2026-10-24, same DB `UpdatedAt` 2026-10-24T01:18:19Z, report `CreatedAt` ~06:10Z) matched Actions run `40066307720`: Python FAIL blocking **3** (all unscored); upstream aggregate blocking **1,075** (Shannon 970 / Temporal 58 / Gitleaks 41 / Trivy 6). Full write-up: `docs/IMAGE_REMEDIATION.md`. Pins unchanged; no candidate passed.

npm `@keygraph/shannon` latest remains `3.4.0`. No `3.5.0` / `3.4.1` tags on Docker Hub. Gitleaks GitHub newest release remains `v8.30.1`.

## Automated candidate watch

`python -m core.supply_chain candidates` resolves the official Hub tags in `CANDIDATE_WATCH`, reuses fresh entries from `core/supply_chain/candidate_rejects.json` (and optional `--evidence-dir`), and scans only new digests. It never updates pins. Scheduled/manual workflow: `.github/workflows/image-candidate-monitor.yml`. Status values: `ACCEPTABLE_CANDIDATE`, `NO_ACCEPTABLE_CANDIDATE`, `NOT_VERIFIED`.

### Fresh monitor 2026-10-25 (not a pin change)

Host Trivy **0.76.0**, vulnerability DB `UpdatedAt` **2026-10-25T01:20:33.190884269Z** (`DownloadedAt` 2026-10-25T04:02:32Z). Command: `python -m core.supply_chain candidates`. Result: **`NO_ACCEPTABLE_CANDIDATE`**, `acceptable: []`.

| Watched tip | linux/amd64 digest | Blocking | Unscored | Decision |
|---|---|---:|---:|---|
| `python:3.12-slim-bookworm` | `sha256:57d96f71…` | 2 | 2 | Rejected |
| `python:3.13-slim-bookworm` | `sha256:4cea12ab…` | 6 | 2 | Rejected |
| `python:3.12-alpine3.24` / Shannon tip | (pinned digests) | — | — | `SKIPPED_PINNED` |
| `temporalio/temporal:latest` (=`1.9.1`) | `sha256:150d6208…` | 15 | 3 | Rejected; includes unscored `GO-2026-5932` (`golang.org/x/crypto`, empty FixedVersion) |
| `zricethezav/gitleaks:latest` (=`v8.30.1`) | `sha256:b109bc5f…` | 78 | 6 | Rejected (worse than pin) |
| `aquasec/trivy:latest` (=`0.76.1`) | `sha256:2e6c00d7…` | 4 | 3 | Rejected |

Main CI absolute scan on `be3a023` (run `40153361168`): Python PASS 0; upstream FAIL **1085** (Shannon 980 / Temporal 58 / Gitleaks 41 / Trivy 6). Pins unchanged. No ignore file.

## Python base — fixed HIGH/CRITICAL still zero; unscored now visible

Image: `python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258`

Local rescan 2026-10-24 with host Trivy 0.76.0, DB `UpdatedAt` 2026-10-23T19:15:43Z, report `CreatedAt` `2026-10-24T01:12:18.954095875Z`, platform `linux/amd64`. Result: `FAIL`. `blocking_count` **3**, all `unscored` / `UNKNOWN`: `DLA-4845-1` (`ca-certificates` 20250419~deb12u1 → 20250419~deb12u2), `CVE-2026-82560` (`perl-base`, empty fixed version), `DLA-4854-1` (`tzdata` 2026c-0+deb12u1 → 2026e-0+deb12u1). Fixed HIGH/CRITICAL remains 0. Full report: `finding_row_count` 290, `unique_cve_count` 131, `unfixed_count` 281. Gate not waived.

Authoritative follow-up on those three rows (no severity invented into the classifier):

| ID | Installed | Fixed in report | Trivy severity | External evidence | Disposition |
|---|---|---|---|---|---|
| `DLA-4845-1` | `ca-certificates` 20250419~deb12u1 | 20250419~deb12u2 | UNKNOWN | Debian LTS page: “ca-certificates - security update”; no CVE ids or urgency on tracker | Remains unscored / blocking |
| `CVE-2026-82560` | `perl-base` 5.36.0-7+deb12u4 | empty (`Status: affected`) | UNKNOWN | NVD CVSS 3.1 **HIGH**; OSV has CVSS_V3 vector; Debian has no fixed version for this image | Remains unscored / blocking (Trivy emitted UNKNOWN; policy does not import NVD scores to clear the gate) |
| `DLA-4854-1` | `tzdata` 2026c-0+deb12u1 | 2026e-0+deb12u1 | UNKNOWN | Debian LTS page: “tzdata - new timezone database”; no CVE ids or urgency | Remains unscored / blocking |

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

Local rescan 2026-10-24 with host Trivy 0.76.0, DB `UpdatedAt` 2026-10-23T19:15:43Z, no severity pre-filter. Status `FAIL` for each image. Aggregate upstream `blocking_count` **1069** = **642** fixed HIGH/CRITICAL + **427** unscored. Digests unchanged. No ignore file.

| Image | Report CreatedAt | Fixed HIGH/CRITICAL | Unscored | Blocking | Rows / unique ids |
|---|---|---|---|---|---|
| `keygraph/shannon:3.4.0@sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e` | 2026-10-24T01:12:26.998699302Z | 548 (37 CRITICAL, 511 HIGH) | 419 | 967 | 1785 / 1769 |
| `temporalio/temporal:1.7.0@sha256:9c5b386d86bca59ba08f32ddc4c51287351c8c616b6a8359f03e96a585e137f4` | 2026-10-24T01:12:23.115117206Z | 51 HIGH | 4 | 55 | 135 / 99 |
| `zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46` | 2026-10-24T01:12:26.361570298Z | 40 (1 CRITICAL, 39 HIGH) | 1 | 41 | 124 / 107 |
| `aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222` | 2026-10-24T01:12:20.448492501Z | 3 HIGH | 3 | 6 | 7 / 6 |

CI on `85ac470` (PR run `40005558585`), Trivy 0.76.0, no severity pre-filter. Status `FAIL` for each image. Top-level `blocking_count` **1068** = **641** fixed HIGH/CRITICAL + **427** unscored UNKNOWN. Digests unchanged. Artifact `image-scan-upstream`. Historical HIGH/CRITICAL-only count on `ac712a4` was 612; the increase is from a fresher vulnerability DB (fixed HIGH/CRITICAL alone is now 641) plus previously hidden UNKNOWN rows.

| Image (CI `85ac470`) | Report CreatedAt | Fixed HIGH/CRITICAL | Unscored | Rows / unique ids |
|---|---|---|---|---|
| Shannon `3.4.0` (same digest) | 2026-10-23T18:46:54.910207566Z | 548 (37 CRITICAL, 511 HIGH) | 419 | 1785 / 1769 |
| Temporal `1.7.0` (same digest) | 2026-10-23T18:47:06.638250792Z | 51 HIGH | 4 | 135 / 99 |
| Gitleaks `v8.21.2` (same digest) | 2026-10-23T18:47:14.960844558Z | 40 (1 CRITICAL, 39 HIGH) | 1 | 124 / 107 |
| Trivy `0.76.0` (same digest) | 2026-10-23T18:47:24.645779064Z | 2 HIGH (`CVE-2026-77214`, `CVE-2026-111943`) | 3 | 6 / 5 |

The Shannon and Temporal tags are the ones the `--validate-model` path starts. Replacing them changes the worker that CI isolation tests run. CI on `85ac470` still printed Docker runtime success before the image gate. The Gitleaks tag is the CI `detect` image. The Trivy tag is the scanner image the supply-chain command runs when the `trivy` binary is absent. The adapter pins in `integrations/scanners/trivy.py` (`0.58.1`) and the Gitleaks adapter were not bumped.

## Not exceptions

- OSV results for Python requirements are a separate command (`python -m core.supply_chain vuln`). They do not clear image findings.
- Pattern redaction misses unknown secret formats. Upstream container logs are outside this process.
- Overwrite-before-unlink is not forensic erasure.
- AGPL questions in `docs/LICENSING_REVIEW.md` stay open until qualified counsel answers them.
