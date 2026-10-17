# Data protection and local operations

This platform is a local orchestrator. It is not a multi-tenant service. Controls below apply to files this process writes.

## Secrets

- Provider environment variables are recorded as `[SET]` or booleans. Values are not printed by `doctor` or `platform_status`.
- Findings, assessment records, and report exports pass through `redact_secrets` / `redact_text` before they are stored.
- Redaction is best-effort pattern matching (URL userinfo, common token shapes, sensitive key names). It is not a guarantee that every upstream log line is clean. Prefer not to pass live credentials on command lines.

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

Cleanup considers regular `.json`, `.md`, `.sarif`, and `.log` files under the assessment directory and `PEN_REPORTS_DIR`. It does not follow symlinks, does not delete symlink entries, and does not run from MCP status tools. There is no remote backup.

## Supply chain metadata

```bash
python -m core.supply_chain audit
python -m core.supply_chain emit --output dist/sbom.cdx.json
```

The audit checks declared Python requirements. The SBOM is CycloneDX 1.5 built from `requirements/*.txt`. It intentionally has no `vulnerabilities` array. Do not read a successful audit as "no known CVEs". A live vulnerability database is an external dependency and is not configured here.

Unpinned `rpds-py>=0.30.0` is reported as a non-blocking finding.
