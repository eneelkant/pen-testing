# FYERS-oriented threat model (platform + synthetic fixtures)

**Status:** Engineering threat model for preparing an *authorized* FYERS bug-bounty assessment using this repository.  
**Not a claim** that FYERS is vulnerable.  
**Not authorization** to test FYERS production systems.  
**Date:** 2026-10-27 (Asia/Calcutta)

Platform context: single-operator orchestrator (`docs/THREAT_MODEL.md`). This document adds financial-application concerns and maps them to local synthetic tests.

| Threat | Impact | Defensive control in this repo | Test approach | Safe to automate? |
|---|---|---|---|---|
| **Authn: expired/invalid access token accepted** | Session integrity failure | Synthetic auth rejects expired/invalid tokens | `SyntheticAuthService.authenticate` unit tests | Yes (local mock) |
| **Authn: revoked session reuse** | Account takeover class | Logout marks session revoked | Logout then authenticate | Yes |
| **Authn: refresh reuse after rotation** | Token theft persistence | Refresh rotation + revoked refresh set | Refresh twice with old token | Yes |
| **Authn: tokens in logs/exports/URLs** | Secret disclosure | `redact_secrets` / allowlisted exports | Nested JSON, query strings, traces | Yes |
| **MFA/OTP: expired or replayed OTP** | Auth bypass / abuse | OTP expiry, consume-once, attempt limits | Fixed synthetic OTP fixtures | Yes (never send real OTP) |
| **MFA/OTP: challenge bound to wrong session/purpose** | Cross-session step-up | Challenge stores session_id + purpose | Mismatched verify calls | Yes |
| **MFA: recovery silently bypasses auth** | Account takeover | Recovery returns uniform message; no session grant | `recovery_start` | Yes |
| **Authn errors leak account existence** | Customer enumeration (program-prohibited) | Uniform `authentication_failed` | Unknown account vs bad password | Yes |
| **Session cookie flags weak** | Session theft (browser) | Synthetic cookie sets Secure/HttpOnly/SameSite | Inspect login cookie attributes | Yes (mock only) |
| **BOLA/IDOR across accounts** | Cross-customer financial data exposure | Mock API enforces authenticated account identity | `TEST_ACCOUNT_A` vs `B` | Yes |
| **Function-level auth missing on transactions** | Unauthorized trading | Transactions disabled by default; readonly role blocked | place/cancel with readonly | Yes |
| **Body account_id overrides identity** | Tenant escape | Server ignores/rejects mismatched body account | Order get/place with spoofed id | Yes |
| **UI-only authorization** | Broken access control | Tests hit API/service layer handlers | Direct service calls | Yes |
| **Missing auth grants access** | Unauthenticated data leak | 401 without token | Null token paths | Yes |
| **Evidence bag merges accounts** | Contaminated bounty report | Evidence keys `assessment::account` | Export isolation test | Yes |
| **Cache key collision across tenants** | Cross-account data bleed in tooling | Cache keys include account_id | `cache_is_isolated` | Yes |
| **Assessment treated as trading permission** | Accidental live orders | Profile prohibits transaction capabilities; no FYERS trading integration | Profile capability checks | Yes |
| **Scanner side-effect hits order API** | Market/account impact | Default assessment tools are passive/local; trading not wired | Profile + absence of trading adapter | Yes (assert absence) |
| **Duplicate mock transactions** | Noisy fixtures / false integrity bugs | Idempotency keys on mock place_order | Repeat with same key | Yes |
| **Invalid order state transitions** | Integrity bugs in mock | Mock rejects illegal cancel/status | Cancel completed order | Yes |
| **Worker hang after cancel/timeout** | Resource exhaustion | Existing scan slot + adapter timeouts | Unit/isolation tests | Partial (existing) |
| **Secrets in MCP/CI artifacts** | Credential leak | Redaction before `_save_assessment` / export | OTP/cookie/token fixtures | Yes |
| **Out-of-scope redirect / SSRF pivot** | Internal network access | Same-origin redirect helpers; destination policy | Existing redirect/SSRF tests + port/scheme | Yes |
| **Live run with only `confirm_authorized`** | Policy bypass theater | Bound approval token required for profiles/env | Approval expiry/mismatch tests | Yes |
| **Unknown target / lookalike host** | Unauthorized testing | Default-deny registry; no subdomain expansion | `fyers.example.test` vs lookalikes | Yes |
| **Stale approval after policy change** | Unauthorized reuse | Policy fingerprint on consume | Mutate registry digest | Yes |
| **Scanner severity auto-validates finding** | False bounty claims | Evidence validator never returns `validated` automatically | Evidence unit tests | Yes |
| **Auto-submit to FYERS** | Policy/legal violation | Export marks human review; no submit client | Code review + runbook | Manual gate |
| **Dependency / container vulns** | Supply-chain risk | Existing OSV + image gates | Existing CI jobs | Yes (existing) |
| **MCP remote transport** | Unauthenticated remote scan control | Stdio-only enforcement | Existing transport tests | Yes |

## Trading integrity architectural boundary

This repository **does not** integrate FYERS trading APIs. Ordinary security assessments must never place, modify, or cancel orders. The `fyers_non_destructive` profile prohibits transaction capabilities, and `SyntheticFinancialAPI.allow_transactions` defaults to `false`. Do not invent a live trading adapter to “complete” readiness work.

## Program alignment notes

FYERS prohibits DoS/high-volume scanning, OTP/SMS to other users, credential/2FA brute force, cross-account access, and actions affecting live trading during market hours. See `docs/FYERS_PROGRAM_REQUIREMENTS.md`.
