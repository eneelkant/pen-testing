# Zoho VRP Submission Draft — NOT FOR SUBMISSION

**Program:** Zoho Vulnerability Reward Program  
**Program URL:** https://bugbounty.zohocorp.com/bb/info  
**Assessment session:** 2026-10-27 (Asia/Calcutta)  
**Status:** BLOCKED — no live testing performed

> This draft documents a hard stop. It must **not** be submitted to Zoho.
> There is no validated vulnerability from this session.

## Summary

Live assessment was not started. The requested target remained the placeholder
`REPLACE_WITH_EXACT_AUTHORIZED_HOST_AND_BASE_URL`, and `scopes/registry.yaml`
contained no Zoho assets. Platform controls correctly refused brand/portal hosts
and kept `zoho_non_destructive` / `zoho_live_candidate` live execution disabled.

## Affected asset (exact)

- Product / brand: UNVERIFIED — not selected
- Hostname / URL: UNVERIFIED — placeholder only
- Environment: n/a

## Findings

None.

## Live request budget used

- Live requests: **0**
- Targets contacted: **none**

## Researcher attestation

- [x] No live Zoho probing was performed in this session
- [x] No customer data was accessed
- [ ] Exact authorized host provided (pending human)
- [ ] Service-Specific Terms reviewed for selected product (pending human)

## Next step

Complete `docs/ZOHO_LIVE_PREFLIGHT_CHECKLIST.md` and supply the exact authorized
host before any live assessment.
