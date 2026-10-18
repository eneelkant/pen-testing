"""Process-global rate-limit state must not leak between tests."""

from __future__ import annotations

import pytest

from core.scope.rate_limit import reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_process_rate_limiter():
    reset_rate_limiter()
    yield
    reset_rate_limiter()
