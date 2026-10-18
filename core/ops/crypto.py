"""Optional encryption for assessment records and backups.

The key is ``PEN_DATA_KEY``, a Fernet key (url-safe base64, 32 bytes). When it
is unset, files stay plaintext. When ``PEN_REQUIRE_DATA_ENCRYPTION`` is true,
plaintext writes and reads are refused. The key value is never included in
errors. This is application-level encryption of files this process writes. It
is not disk encryption, a KMS, or a claim about backups copied elsewhere.
"""

from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken

MAGIC = "PENENC1\n"


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


def encryption_required() -> bool:
    return _truthy("PEN_REQUIRE_DATA_ENCRYPTION")


def encryption_enabled() -> bool:
    return bool(os.environ.get("PEN_DATA_KEY", "").strip())


def encryption_status() -> dict[str, bool | str]:
    """Status safe to print. Does not include the key."""
    enabled = encryption_enabled()
    required = encryption_required()
    if required and not enabled:
        state = "required-missing"
    elif enabled:
        state = "enabled"
    else:
        state = "off"
    return {"state": state, "required": required, "enabled": enabled}


def _fernet() -> Fernet:
    raw = os.environ.get("PEN_DATA_KEY", "").strip()
    if not raw:
        raise PermissionError("PEN_DATA_KEY is not set")
    try:
        return Fernet(raw.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise PermissionError("PEN_DATA_KEY is not a valid Fernet key") from exc


def protect_text(text: str) -> str:
    """Return ciphertext when a key is configured, otherwise the original text."""
    status = encryption_status()
    if status["state"] == "required-missing":
        raise PermissionError("PEN_REQUIRE_DATA_ENCRYPTION is set but PEN_DATA_KEY is missing")
    if not status["enabled"]:
        return text
    token = _fernet().encrypt(text.encode("utf-8")).decode("ascii")
    return MAGIC + token + "\n"


def reveal_text(text: str) -> str:
    """Reverse ``protect_text``. Fail closed on a missing key or a bad token."""
    if text.startswith(MAGIC):
        payload = text[len(MAGIC) :].strip()
        if not encryption_enabled():
            raise PermissionError("Encrypted record found but PEN_DATA_KEY is not set")
        try:
            return _fernet().decrypt(payload.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeError) as exc:
            raise PermissionError("Encrypted record could not be opened") from exc
    if encryption_required():
        raise PermissionError("Refusing plaintext while PEN_REQUIRE_DATA_ENCRYPTION is set")
    return text
