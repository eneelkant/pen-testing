# Data protection and local operations

This platform is a single-operator local orchestrator. There is no multi-user authentication, tenant isolation, or remote admin API. Anyone who can run the CLI or MCP process can use that process's files and environment. Controls below apply to files this process writes.

## Secrets

- Provider environment variables are recorded as `[SET]` or booleans. Values are not printed by `doctor` or `platform_status`.
- Findings, assessment records, and report exports pass through `redact_secrets` / `redact_text` before they are stored. Nested dicts and free-text fields in those records are included.
- Redaction looks for URL userinfo, JWT-like strings, AWS-key-like strings, GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), Slack tokens and webhooks, `sk-` style keys, PEM private keys, and sensitive key names such as `private_key` and `authorization`.
- Pattern matching cannot detect every secret. A value that does not match these shapes can still be stored.
- Upstream scanner logs written by Shannon, Briar, or container engines are outside this process. This platform does not redact those logs.

## Report and assessment files

- Assessment IDs are UUIDs. Other IDs are rejected.
- Reads and writes use `O_NOFOLLOW` and refuse any existing symlink component, including parent directories.
- `export_report` and `pen-testing export-report` keep outputs under `PEN_REPORTS_DIR` or `PEN_WORK_DIR`. The CLI also allows the current directory so an operator can export a local findings file. Paths outside those roots are rejected.
- A corrupt assessment JSON file returns an error and is not partially interpreted.

## Retention

`PEN_ASSESSMENT_RETENTION_DAYS` defaults to `14`. Set it to `off` to disable cleanup.

```bash
pen-testing cleanup            # dry-run
pen-testing cleanup --apply    # delete expired artifacts
pen-testing cleanup --days 30 --apply
```

Cleanup considers regular `.json`, `.md`, `.sarif`, and `.log` files under the assessment directory and `PEN_REPORTS_DIR`. It does not follow symlinks, does not delete symlink entries, and does not run from MCP status tools.

## What is stored, and what is not protected

| Data | Location | Access | Retention | Deletion |
|---|---|---|---|---|
| Assessment JSON | `PEN_WORK_DIR` assessments directory | OS user running the process | `PEN_ASSESSMENT_RETENTION_DAYS` (default 14) | Manual `pen-testing cleanup --apply` |
| Reports (`.json`, `.md`, `.sarif`) | `PEN_REPORTS_DIR` | Same OS user | Same cutoff | Same command |
| Authorization registry | `PEN_SCOPES_FILE` (default `scopes/registry.yaml`) | Same OS user | Operator-managed | Operator-managed |
| Scanner container logs | Docker/Shannon/Briar, outside this process | Host Docker user | Upstream/engine default | Not cleaned by this CLI |

When `PEN_DATA_KEY` is unset, files are plaintext. Set it to a Fernet key to encrypt assessment records and backup members that this process writes. `PEN_REQUIRE_DATA_ENCRYPTION=1` refuses plaintext reads and writes. The key is not printed by doctor. This is not disk encryption or a managed KMS. A copy of the key decrypts the files. Backups are `pen-testing backup --apply` into a directory you choose; restore requires `--apply` and stays inside the assessment and report directories.

`pen-testing cleanup --apply` overwrites a regular file with zeros before unlink. That reduces leftover plaintext on some filesystems. It does not erase SSD wear-leveling, snapshots, or files that were already copied. Symlinks are still not deleted.

## Rate limits

`rate_limit_rps` on an authorization record is enforced for non-dry-run adapter preflight inside one process. `PEN_MAX_INFLIGHT_SCANS` (default 4, range 1–64) caps concurrent live CLI and MCP scans in that same process. Dry-run does not consume either budget. These counters reset when the process exits. They are not a cluster or multi-tenant quota. Skipping the authorization registry also skips the per-record rate limit; it does not skip egress checks.

## Supply chain metadata

```bash
python -m core.supply_chain audit
python -m core.supply_chain emit --output dist/sbom.cdx.json
python -m core.supply_chain vuln
```

The audit checks declared Python requirements. The SBOM is CycloneDX 1.5 built from `requirements/*.txt`. It intentionally has no `vulnerabilities` array. `vuln` queries the OSV API for exact versions and is a separate result: `PASS`, `FAIL`, or `NOT_VERIFIED` when the database cannot be reached. Do not read a successful audit as "no known CVEs".

`rpds-py` is pinned to `2026.9.1`, the version resolved with `jsonschema==4.26.0` when the unit suite was run. That pin is a reproducibility choice, not a vulnerability waiver.

Severity gate for `vuln`: `HIGH` and `CRITICAL` are blocking. `LOW`, `MODERATE`, and `MEDIUM` are reported and are not blocking. A vulnerability with no usable severity label is blocking. Withdrawn records are ignored. If the API cannot be reached or the response has no `results` list, the status is `NOT_VERIFIED` and the command exits 2. `querybatch` does not return a database snapshot time; `generated_at` is the client clock.
