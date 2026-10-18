# Security exception register

**Status:** Inventory of findings this repository has actually scanned. Nothing in this file is a waiver, an ignore-file entry, or an acceptance signature.

**Scanner:** Trivy 0.76.0. Vulnerability DB `UpdatedAt` 2026-10-17 18:34:28Z, downloaded 2026-10-18 01:15:57Z. Image sources were the registry (`--image-src remote`) for the upstream images. Docker was not installed in that environment, so the container runtime itself is `NOT VERIFIED` here.

**Gate:** `python -m core.supply_chain images` fails on HIGH or CRITICAL findings that have a non-empty `FixedVersion`. Unfixed findings are printed and do not by themselves fail the command. There is no `.trivyignore`. Pins were not changed: a newer Shannon, Temporal, Gitleaks, or Trivy tag has not been compatibility-tested.

Counsel review of `docs/LICENSING_REVIEW.md` is still pending. That is a legal question, not a CVE exception.

## Python base — unfixed, not blocking

Image: `python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258`

Report `CreatedAt` `2026-10-18T01:22:03.774118549Z`. Result: `PASS` under the fixed-finding gate. `blocking_count` 0. 63 HIGH/CRITICAL rows, all with an empty `FixedVersion`. The 63 rows are package copies of 16 CVE ids. util-linux is eight binary packages times six CVEs (48 rows).

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

Local classification on 2026-10-18. Same Trivy binary and DB. Status `FAIL` for each image. `unfixed_count` 0 in these four reports. CI step `Pinned upstream image vulnerability scan` runs the same command and is expected to fail until the digests change after a compatibility test.

| Image | Report CreatedAt | Blocking | What the rows are |
|---|---|---|---|
| `keygraph/shannon:3.4.0@sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e` | 2026-10-18T01:44:09.748799555Z | 523 (37 CRITICAL, 486 HIGH) | 485 are `chromium` 149.0.7827.53-r0. The rest include `fast-uri`, `brace-expansion`, `protobufjs`, `@grpc/grpc-js`, `js-yaml`, and other Node packages. Critical ids start `CVE-2026-106195`, `CVE-2026-106237`, `CVE-2026-13032` |
| `temporalio/temporal:1.7.0@sha256:9c5b386d86bca59ba08f32ddc4c51287351c8c616b6a8359f03e96a585e137f4` | 2026-10-18T01:44:00.472833571Z | 49 HIGH | Go `stdlib` v1.26.2, `golang.org/x/crypto`, `golang.org/x/net`, `google.golang.org/grpc`, Alpine `libcrypto3` / `libssl3` 3.5.6-r0, Thrift, Echo |
| `zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46` | 2026-10-18T01:44:00.999850114Z | 39 (1 CRITICAL, 38 HIGH) | CRITICAL `CVE-2025-68121` in Go stdlib v1.22.8. Also git 2.43.5-r0, musl, OpenSSH 9.6_p1-r1 |
| `aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222` | 2026-10-18T01:44:02.183745759Z | 1 HIGH | `CVE-2026-77214` in `libexpat` 2.8.5-r0, fixed version reported as 2.9.0-r0 |

The Shannon and Temporal tags are the ones the `--validate-model` path starts. Replacing them changes the worker that CI isolation tests run. That compatibility run was not executed in this environment (no Docker). The Gitleaks tag is the CI `detect` image. The Trivy tag is the scanner image the supply-chain command runs when the `trivy` binary is absent. The adapter pins in `integrations/scanners/trivy.py` (`0.58.1`) and the Gitleaks adapter were not bumped.

## Not exceptions

- OSV results for Python requirements are a separate command (`python -m core.supply_chain vuln`). They do not clear image findings.
- Pattern redaction misses unknown secret formats. Upstream container logs are outside this process.
- Overwrite-before-unlink is not forensic erasure.
- AGPL questions in `docs/LICENSING_REVIEW.md` stay open until qualified counsel answers them.
