"""Structured logging helpers."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any


def get_logger(name: str = "pen-testing") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def audit_event(event: str, **fields: Any) -> dict[str, Any]:
    payload = {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **fields,
    }
    get_logger("pen-testing.audit").info(json.dumps(payload, default=str))
    return payload
