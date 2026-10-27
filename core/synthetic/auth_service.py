"""Synthetic authentication / session / OTP service for local regression tests.

Uses fixed synthetic OTP values. Does not send SMS, email, or push messages.
Results from this service must never be reported as FYERS vulnerabilities.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(16)}"


@dataclass
class SessionRecord:
    session_id: str
    account_id: str
    access_token: str
    refresh_token: str
    created_at: datetime
    access_expires_at: datetime
    refresh_expires_at: datetime
    revoked: bool = False
    refresh_rotated_from: str | None = None


@dataclass
class OtpChallenge:
    challenge_id: str
    session_id: str
    purpose: str
    code: str
    expires_at: datetime
    attempts: int = 0
    max_attempts: int = 5
    consumed: bool = False


@dataclass
class SyntheticAuthService:
    """In-memory auth service with rotatable refresh tokens and OTP limits."""

    access_ttl_seconds: int = 300
    refresh_ttl_seconds: int = 3600
    otp_ttl_seconds: int = 120
    otp_fixed_code: str = "246801"  # synthetic only
    enable_refresh_rotation: bool = True
    _sessions: dict[str, SessionRecord] = field(default_factory=dict)
    _access_index: dict[str, str] = field(default_factory=dict)
    _refresh_index: dict[str, str] = field(default_factory=dict)
    _revoked_refresh: set[str] = field(default_factory=set)
    _otps: dict[str, OtpChallenge] = field(default_factory=dict)
    _accounts: set[str] = field(default_factory=lambda: {"TEST_ACCOUNT_A", "TEST_ACCOUNT_B"})

    def login(self, account_id: str, password: str, *, now: datetime | None = None) -> dict[str, Any]:
        moment = now or _utcnow()
        # Uniform error to avoid account-existence leakage for unknown ids.
        if account_id not in self._accounts or password != "synthetic-password":
            return {"ok": False, "error": "authentication_failed"}
        session_id = _token("sess")
        access = _token("atk")
        refresh = _token("rtk")
        record = SessionRecord(
            session_id=session_id,
            account_id=account_id,
            access_token=access,
            refresh_token=refresh,
            created_at=moment,
            access_expires_at=moment + timedelta(seconds=self.access_ttl_seconds),
            refresh_expires_at=moment + timedelta(seconds=self.refresh_ttl_seconds),
        )
        self._sessions[session_id] = record
        self._access_index[access] = session_id
        self._refresh_index[refresh] = session_id
        return {
            "ok": True,
            "session_id": session_id,
            "account_id": account_id,
            "access_token": access,
            "refresh_token": refresh,
            "access_expires_at": record.access_expires_at.isoformat(),
            "cookie": {
                "name": "SYNTH_SESSION",
                "value": session_id,
                "secure": True,
                "httponly": True,
                "samesite": "Strict",
            },
        }

    def authenticate(self, access_token: str, *, now: datetime | None = None) -> dict[str, Any]:
        moment = now or _utcnow()
        session_id = self._access_index.get(access_token)
        if not session_id:
            return {"ok": False, "error": "invalid_token"}
        session = self._sessions[session_id]
        if session.revoked:
            return {"ok": False, "error": "revoked_session"}
        if moment > session.access_expires_at:
            return {"ok": False, "error": "expired_token"}
        if session.access_token != access_token:
            return {"ok": False, "error": "invalid_token"}
        return {"ok": True, "session_id": session.session_id, "account_id": session.account_id}

    def logout(self, access_token: str) -> dict[str, Any]:
        auth = self.authenticate(access_token)
        if not auth.get("ok"):
            # Still attempt revoke by raw index for expired-but-present tokens.
            session_id = self._access_index.get(access_token)
            if not session_id:
                return {"ok": False, "error": "invalid_token"}
        else:
            session_id = auth["session_id"]
        session = self._sessions[session_id]
        session.revoked = True
        self._revoked_refresh.add(session.refresh_token)
        return {"ok": True, "session_id": session_id}

    def refresh(self, refresh_token: str, *, now: datetime | None = None) -> dict[str, Any]:
        moment = now or _utcnow()
        if refresh_token in self._revoked_refresh:
            return {"ok": False, "error": "invalid_refresh_token"}
        session_id = self._refresh_index.get(refresh_token)
        if not session_id:
            return {"ok": False, "error": "invalid_refresh_token"}
        session = self._sessions[session_id]
        if session.revoked or moment > session.refresh_expires_at:
            return {"ok": False, "error": "invalid_refresh_token"}
        if session.refresh_token != refresh_token:
            return {"ok": False, "error": "invalid_refresh_token"}

        # Rotate: invalidate previous refresh token when rotation is enabled.
        if self.enable_refresh_rotation:
            self._revoked_refresh.add(refresh_token)
            del self._refresh_index[refresh_token]
            new_refresh = _token("rtk")
            session.refresh_token = new_refresh
            session.refresh_rotated_from = refresh_token
            self._refresh_index[new_refresh] = session_id
        else:
            new_refresh = refresh_token

        # Rotate access token.
        old_access = session.access_token
        del self._access_index[old_access]
        new_access = _token("atk")
        session.access_token = new_access
        session.access_expires_at = moment + timedelta(seconds=self.access_ttl_seconds)
        self._access_index[new_access] = session_id
        return {
            "ok": True,
            "access_token": new_access,
            "refresh_token": new_refresh,
            "access_expires_at": session.access_expires_at.isoformat(),
        }

    def start_otp(
        self,
        access_token: str,
        *,
        purpose: str = "step_up",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        auth = self.authenticate(access_token, now=now)
        if not auth.get("ok"):
            return {"ok": False, "error": auth.get("error", "authentication_failed")}
        moment = now or _utcnow()
        challenge_id = _token("otp")
        challenge = OtpChallenge(
            challenge_id=challenge_id,
            session_id=auth["session_id"],
            purpose=purpose,
            code=self.otp_fixed_code,
            expires_at=moment + timedelta(seconds=self.otp_ttl_seconds),
        )
        self._otps[challenge_id] = challenge
        # Intentionally do not return the OTP code in the normal response body.
        return {
            "ok": True,
            "challenge_id": challenge_id,
            "purpose": purpose,
            "expires_at": challenge.expires_at.isoformat(),
            "delivery": "synthetic_local_only",
        }

    def verify_otp(
        self,
        access_token: str,
        challenge_id: str,
        code: str,
        *,
        purpose: str = "step_up",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        auth = self.authenticate(access_token, now=now)
        if not auth.get("ok"):
            return {"ok": False, "error": "authentication_failed"}
        challenge = self._otps.get(challenge_id)
        if challenge is None:
            return {"ok": False, "error": "invalid_challenge"}
        moment = now or _utcnow()
        if challenge.session_id != auth["session_id"] or challenge.purpose != purpose:
            return {"ok": False, "error": "challenge_mismatch"}
        if challenge.consumed:
            return {"ok": False, "error": "challenge_replay"}
        if moment > challenge.expires_at:
            return {"ok": False, "error": "otp_expired"}
        if challenge.attempts >= challenge.max_attempts:
            return {"ok": False, "error": "otp_attempts_exceeded"}
        challenge.attempts += 1
        if code != challenge.code:
            return {"ok": False, "error": "otp_invalid"}
        challenge.consumed = True
        return {"ok": True, "session_id": auth["session_id"], "purpose": purpose}

    def recovery_start(self, account_id: str) -> dict[str, Any]:
        # Uniform response: never confirm whether the account exists.
        _ = account_id
        return {
            "ok": True,
            "message": "If the account exists, a recovery challenge was created.",
            "bypasses_authentication": False,
        }

    def diagnostic_dump(self, access_token: str) -> dict[str, Any]:
        """Return a sanitized diagnostic view (no raw tokens/session secrets)."""
        auth = self.authenticate(access_token)
        if not auth.get("ok"):
            return {"ok": False, "error": "authentication_failed"}
        session = self._sessions[auth["session_id"]]
        return {
            "ok": True,
            "account_id": session.account_id,
            "session_fingerprint": hashlib.sha256(session.session_id.encode()).hexdigest()[:16],
            "revoked": session.revoked,
        }
