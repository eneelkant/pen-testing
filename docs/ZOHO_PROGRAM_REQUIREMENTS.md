# Zoho Vulnerability Reward Program — requirements mapping

**Official entry point:** https://bugbounty.zohocorp.com/  
**Program information:** https://bugbounty.zohocorp.com/bb/info  
**Retrieval date:** 2026-10-27 (Asia/Calcutta)  
**Page “Last updated on” (as published):** 11th April 2024  

This document maps published program rules to repository controls. It is **not** legal advice, **not** confirmation from Zoho, and **not** authorization to test any Zoho asset.

## 1. Verified program requirements

### Scope (eligible brands / product families)

Published eligible categories:

- All Zoho branded products and applications listed at zoho.com
- All ManageEngine branded products and applications listed at manageengine.com
- Site24x7
- Qntrl
- TrainerCentral
- Vani
- Arattai
- Ulaa Browser
- Zoho POS
- Zoho Corporation owned assets

**Important:** Brand or parent-domain membership is **not** sufficient for this platform to authorize a hostname. Exact assets must be human-verified and listed in `scopes/registry.yaml`. No Zoho hostnames are registered in this repository by default.

### Researcher eligibility (summary)

- Open to individuals with age / guardian rules as published
- Excludes US-sanctioned country residents (as published)
- Excludes current Zoho employees and those employed within six months
- Excludes family members of Zoho employees

### Responsible research rules (verified)

- Avoid privacy violations, UX degradation, infrastructure disruption, and data destruction
- Report bugs to Zoho and allow reasonable remediation time before public disclosure
- If unauthorized information is accessed inadvertently: stop, notify Zoho, delete local copies
- Test only with your account or an account with explicit owner consent
- Do not exploit bugs beyond testing
- DDoS / service degradation testing is prohibited

### Submission requirements (verified)

- Submit via the program website
- Include vulnerability description, clear reproduction steps, and a proof-of-concept
- Zoho reviews within three days (as published); first reporter wins duplicates
- Bounties are discretionary (published tiers up to Low $50 / Medium $200 / High $800 / Critical $3000)

## 2. Exclusions and safety restrictions (verified)

Unvalidated automated findings and many low-impact classes are excluded, including (non-exhaustive):

- Missing best practices that are not vulnerabilities
- Self-XSS; HTML injection; sandbox/user-content XSS
- Username / email enumeration; email bombing
- Unvalidated / open redirects or tabnabbing
- Clickjacking / tapjacking without sensitive actions
- Logout or unauthenticated CSRF
- Missing cookie flags on non-sensitive cookies
- Missing security headers that do not lead directly to a vulnerability
- **Unvalidated findings from automated tools or scans**
- Social engineering; physical-access attacks
- Known-vulnerable libraries without exploitability evidence
- Rate-limit absence without security impact
- CSV injection; broken link hijacking; Unicode/Punycode phishing risk
- Upload/download of executables; pricing bypass
- Third-party 0-days within 10 days of disclosure
- Issues only on outdated browsers/platforms; low/negligible impact

Automation / volume: DDoS and activities that degrade or disrupt services are prohibited. Specific request-rate numeric limits for researchers are **UNVERIFIED** beyond the DDoS prohibition.

Service-specific terms: referenced by the program as additional constraints — exact per-product deltas are **UNVERIFIED** without reading each product’s Service-Specific Terms at assessment time.

## 3. Unverified questions requiring manual review

| ID | Question | Why it matters |
|---|---|---|
| U1 | Exact hostname / API endpoint eligibility for a chosen product | Brand lists ≠ host allowlists |
| U2 | Whether passive header/TLS checks alone are accepted as reports | Headers-without-impact are excluded |
| U3 | Researcher rate limits beyond DDoS language | Needed for automation budgets |
| U4 | Current Service-Specific Terms for the chosen product | May add exclusions |
| U5 | Whether the researcher’s account jurisdiction / eligibility still holds | Program eligibility rules |
| U6 | Evidence retention and PoC format expectations beyond “clear steps + PoC” | Submission quality |
| U7 | Whether staging or researcher tenants exist for safer testing | Avoid production impact |

Mark any asset **UNVERIFIED** until a human confirms it against the live program page and product docs.

## 4. Mapping to repository controls

| Program requirement | Existing / added control | Notes |
|---|---|---|
| Only eligible Zoho-owned assets | `scopes/registry.yaml` + `ScopeEngine` default deny | Do not add guessed hosts |
| Exact asset authorization | Exact host/URL match; no subdomain expansion | Lookalike hosts rejected |
| No DDoS / disruption | Profile `prohibited_actions`; adapters refuse destructive modes | Not a network QoS enforcer |
| Own account only | Operational runbook; not automatable | Human attestation in report template |
| No auto-validated scanner findings | `ValidationStatus` + `assess_evidence`; export refuses auto-submit | High severity ≠ validated |
| Missing headers without impact excluded | Zoho profile + reporting guidance | Informational ≠ vulnerability |
| Enumeration / email bombing excluded | Profile prohibited capabilities | Not enabled |
| Responsible disclosure | Draft export only; no auto-submit to Zoho | `export_report` / templates |
| Provide repro + PoC | Report template `reports/templates/zoho_vrp_submission.md` | Human completes |
| Bound live approval | `authorize_assessment` + `approval_id` | Cannot reuse across targets |
| Non-destructive default | `zoho_non_destructive` profile with `live_execution_enabled: false` | Synthetic fixtures only |
| Isolation of scanners | Compose internal nets + dual-gate live flags | Proven by existing isolation tests |

**This mapping does not constitute Zoho approval.**
