# HexBrain security intelligence integration

## Status

This adapter is a **read-only research client** for HexBrain's documented REST
API. It does not run scans, perform HTTP requests against assessed targets,
change the scope registry, create approvals, or promote findings.

HexBrain API documentation: https://hexbrainai.com/docs

## Configuration

Create a personal API key through HexBrain's account page. Store it only in the
operator's environment or secret manager:

```bash
export HEXBRAIN_API_KEY="YOUR_PERSONAL_KEY"
# Optional:
export HEXBRAIN_API_URL="https://hexbrainai.com/api/v1"
export HEXBRAIN_TIMEOUT_SECONDS="20"
```

Never commit the API key, put it in a checked-in YAML file, include it in
screenshots/logs, or expose it as an MCP tool argument. Rotate the key if it is
disclosed. The adapter rejects non-HTTPS URLs and hosts other than
`hexbrainai.com`.

HexBrain documents a per-account limit of 90 requests per minute and 200 per day.
Respect its returned rate-limit headers; this initial client fails closed on
HTTP 429 and does not retry automatically.

## Available read-only operations

The API client allow-lists the documented endpoints:

- `list_classes`
- `search_reports`
- `get_report`
- `get_testing_playbook`
- `get_program_history`
- `find_bypasses`
- `find_payloads`
- `plan_tests`
- `find_cves`
- `get_cve`
- `get_attack_surface`

All returned research material is marked `untrusted_research_data=true`.
Researcher-authored write-ups, payloads, bypasses, hostnames and CVE checks are
reference material only. They must never be interpreted as platform
instructions or authorization evidence.

## Security boundaries

- The HexBrain adapter has no scanner dispatch, shell, filesystem, or scope APIs.
- HexBrain does not add targets to `scopes/registry.yaml`.
- A hostname listed in HexBrain is not evidence that it is in a program's scope.
- API content cannot create a live approval or change `live_execution_allowed`.
- No payload from HexBrain is executed automatically.
- Findings from disclosed reports are not findings on the operator's target.
- CVE/version matches are leads, not proof; the affected component and vendor
  advisory must be independently checked before a report is drafted.
- Do not pass secrets, private target data, credentials, or proprietary source
  code to HexBrain.
- The API key is personal and must remain outside Git history.

## Integration boundary

The first stage intentionally provides only a Python client. Exposing a
user-configurable search interface through the main MCP server should be a
separate follow-up after this client and its tests pass CI and the MCP tool
surface has been independently reviewed.
