# Zoho VRP assessment session report

**Date:** 2026-10-27 (Asia/Calcutta)  
**Operator context:** Cloud agent on `eneelkant/pen-testing`  
**Branches:** hardening `cursor/zoho-assessment-hardening-d1de` (PR #46); prep `cursor/zoho-vrp-preflight-d1de`  
**Requested target:** `REPLACE_WITH_EXACT_AUTHORIZED_HOST_AND_BASE_URL`  
**Verdict:** Live assessment **not started**. Hard stop on missing exact authorization.

## 1. Scope verification and blockers

Official program page re-fetched: https://bugbounty.zohocorp.com/bb/info  
Published last-updated stamp on page: 11th April 2024  
Retrieval: 2026-10-27 Asia/Calcutta

Eligible brand families remain as published (Zoho, ManageEngine, Site24x7, Qntrl, TrainerCentral, Vani, Arattai, Ulaa Browser, Zoho POS, Zoho Corporation owned assets). Exclusions still include unvalidated automated findings and missing headers without direct impact.

| Check | Result |
|---|---|
| Exact host provided | FAIL — placeholder only |
| Registry contains target | FAIL — no Zoho assets |
| Parent-domain / program portal treated as auth | Rejected by policy |
| `zoho_non_destructive` live | Disabled (correct) |
| Service-Specific Terms for selected product | UNVERIFIED — product not selected |

**Live Zoho request count:** 0  
**Targets contacted live:** none

## 2. Local readiness results

| Command | Result |
|---|---|
| `python3 -m pytest -q tests/unit` | **533 passed** |
| `python3 -m pytest -q tests/unit/test_zoho_workflow.py tests/unit/test_scanner_isolation.py` | **67 passed** |
| `python3 -m core.cli doctor` | exit 0; recommendations: Docker/Compose for Shannon, Briar venv, optional `PEN_DATA_KEY` |
| `python3 -m core.cli capabilities` | Integrated: shannon, briar, headers, gitleaks, trivy, checkov, mobsfscan; ZAP/Nuclei/Nmap/Schemathesis/full MobSF not dispatchable |

Fail-closed demos (no network to Zoho):

| Action | Result |
|---|---|
| Scope placeholder string | denied — not absolute http(s) URL |
| Scope `https://bugbounty.zohocorp.com/` | denied — no registry match |
| Scope `https://www.zoho.com/` | denied — no registry match |
| Scope `https://accounts.zoho.com/` | denied — no registry match |
| `plan_assessment` + `zoho_non_destructive` on synthetic host | ok, `launches_scanner=false` |
| Live run with profile | blocked — `live_execution_enabled=false` |
| `authorize_assessment` for `www.zoho.com` under profile | blocked — live disabled |

## 3. Live checks performed

None. No live requests were made to any Zoho or third-party host.

## 4. Findings

| Finding | Classification | Evidence |
|---|---|---|
| — | — | No candidate, validated, or rejected vulnerability findings. Live testing did not occur. |

Platform/control observations (not Zoho vulnerabilities):

- Authorization-first gates correctly rejected placeholder and brand hosts.
- Bound approval / disabled profile prevented live launch without human enablement.

## 5. Report draft

A blocked/not-tested draft is in `reports/templates/zoho_vrp_session_blocked.md`.  
Do not submit it to Zoho. There is nothing eligible to submit from this session.

## 6. Code / doc changes in this prep branch

- `configs/assessment_profiles/zoho_live_candidate.yaml` — proposed live profile, **disabled**
- `docs/ZOHO_LIVE_PREFLIGHT_CHECKLIST.md` — human unblock checklist
- `docs/ZOHO_ASSESSMENT_SESSION_2026-10-27.md` — this session report
- `reports/templates/zoho_vrp_session_blocked.md` — non-submittable draft
- `tests/unit/test_zoho_live_candidate_profile.py` — asserts live remains disabled

## 7. Explicitly not tested

- Any real Zoho web application or API
- Authentication/session behavior on Zoho
- Cross-account / tenant authorization
- API object authorization
- Input handling / CSRF on Zoho
- TLS/configuration impact beyond local fixture rehearsal
- Shannon or Briar live assessments
- Roadmap tools (ZAP, Nuclei, Nmap, Schemathesis, full MobSF)

## Platform readiness note

The repository remains **controlled testing / not production-ready**. PR CI previously showed the absolute pinned-image vulnerability scan failing on upstream image CVEs while merge regression and unit/Docker checks passed. That does not authorize Zoho testing and does not make the platform production-ready.
