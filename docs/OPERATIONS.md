# Operations

Single-operator local deployment. There is no application database, backup daemon, or external alerting service in this repository. Do not treat this page as a managed-service runbook.

## Health

```bash
python -m core.cli doctor
PEN_DOCTOR_STRICT=1 python -m core.cli doctor
```

Default doctor prints JSON and exits 0. It is informational. `PEN_DOCTOR_STRICT=1` exits 1 when any of these are true:

- `PEN_DATA_KEY` is missing, or set to a value Fernet rejects
- the authorization file in `PEN_SCOPES_FILE` does not exist
- `PEN_MAX_INFLIGHT_SCANS` or `PEN_SKIP_SCOPE_RATE_LIMIT_RPS` is not a usable number
- `PEN_ALLOW_SHANNON_FULL_PIPELINE` is set

The Compose orchestrator sets `PEN_DOCTOR_STRICT=true` and `PEN_REQUIRE_DATA_ENCRYPTION=true`. Its command is `python -m core.cli doctor`. Without a host-provided `PEN_DATA_KEY`, that container exits 1. MCP `platform_status` reports component health and does not delete files.

No metrics backend is configured. A non-zero strict doctor exit code is the readiness signal this process can raise. Wiring that exit code to an external pager is an operator choice; this tree does not ship a webhook or a monitoring agent.

## Storage

| Path | Compose | Permissions |
|---|---|---|
| `PEN_WORK_DIR` | volume `pen_workspaces` mounted at `/work/workspaces` | orchestrator user `10001:10001` |
| `PEN_REPORTS_DIR` | volume `pen_reports` mounted at `/work/reports` | same user |
| `PEN_SCOPES_FILE` | `./scopes` mounted read-only at `/work/scopes` | host owner; container cannot rewrite the registry |

The orchestrator filesystem is `read_only` except `/tmp` and those volumes. It does not mount the Docker socket. Host backups of the volumes must be readable by the account that runs `pen-testing backup`.

## Encryption key recovery

`PEN_DATA_KEY` is a Fernet key. Compose reads it from the environment and does not store it in the image. Keep a copy outside the assessment volumes and outside git. This software cannot reconstruct a lost key. Ciphertext written with that key stays unreadable. Doctor never prints the key.

## Backup and restore

There is no scheduler in `docker-compose.yml`. Run the commands from the operator account. `--apply` is required before any file is written.

```bash
pen-testing backup --output /secure/backups/2026-10-18
pen-testing backup --output /secure/backups/2026-10-18 --apply
pen-testing restore --archive /secure/backups/2026-10-18
pen-testing restore --archive /secure/backups/2026-10-18 --apply
```

Backup copies regular assessment and report files, skips symlinks, and records a checksum manifest. Restore refuses a manifest path that leaves the destination root. An operator may schedule the same command with cron on the host. Installing that cron entry is not part of this repository.

## Retention and cleanup

`PEN_ASSESSMENT_RETENTION_DAYS` defaults to 14. `off` disables the cutoff. Cleanup is not automatic.

```bash
pen-testing cleanup
pen-testing cleanup --apply
```

`--apply` overwrites a regular file with zeros and then unlinks it. That is not forensic erasure. SSD wear-leveling, snapshots, and copies already taken are outside this command. Symlinks are not deleted.

## Rollback

Roll back by checking out the previous git SHA and recreating containers from that revision. There is no in-application migration. Assessment files encrypted with the current `PEN_DATA_KEY` still need that key after a code rollback. Image digest pins live in `core/supply_chain/images.py`; do not move them to a newer tag without a compatibility run.

## Key rotation

There is no rotate command. To move assessment files to a new key:

1. Keep the current `PEN_DATA_KEY`.
2. `pen-testing restore --archive <old-backup> --apply` into an empty work directory, or copy the existing files while that key is set.
3. Generate a new Fernet key and export it as `PEN_DATA_KEY`.
4. `pen-testing backup --output <new-backup> --apply`.
5. Store the new key outside the repository and outside the backup directory. Files written earlier stay readable only with the old key.

A wrong key, corrupt member, or checksum mismatch is detected before any destination file is replaced, so `restore --apply` does not commit partial restored data. Confirm that on a copy before deleting the old archive.

## Operator checklist

- [ ] `PEN_DATA_KEY` is set in the host environment for Compose and is absent from git, images, and doctor output
- [ ] `PEN_DOCTOR_STRICT=1` exits 0 with that key, the authorization file present, and `PEN_ALLOW_SHANNON_FULL_PIPELINE` unset
- [ ] `pen-testing backup --apply` has been run and a restore with the same key was checked on a copy
- [ ] A restore with a different key was checked to fail
- [ ] The archive and the key are stored apart from each other
- [ ] Image digests in `core/supply_chain/images.py` match `docs/SECURITY_EXCEPTIONS.md`
- [ ] Rollback is the previous git SHA, with the same `PEN_DATA_KEY` the files were written under

## What remains manual

- Custody of `PEN_DATA_KEY` and of backup directories
- Restoring Docker volumes if the host disk is lost
- Reading strict-doctor failures; nothing in this repo pages an on-call rotation
- Replacing upstream images that still have fixed vulnerabilities (see `docs/SECURITY_EXCEPTIONS.md`)
