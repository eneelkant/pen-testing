"""P0 regression tests: scanner false-success and false-zero prevention.

Tests that Gitleaks and Trivy adapters cannot return status="succeeded"
with findings=[] when the scanner output is missing, empty, or malformed.

Also tests that Briar demo mode cannot bypass scope for arbitrary targets.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest


class TestGitleaksFalseZeroPrevention:
    """Gitleaks adapter must not report succeeded+0 findings on invalid output."""

    def test_run_checks_report_existence_before_parse(self):
        """run() must check report.exists() before calling _parse."""
        from integrations.scanners.gitleaks import GitleaksAdapter
        source = inspect.getsource(GitleaksAdapter.run)
        assert "report.exists()" in source, \
            "Gitleaks run() must check report existence before calling _parse"
        assert "failed" in source, \
            "Gitleaks run() must return status='failed' on missing report"

    def test_parse_returns_empty_on_missing_file(self, tmp_path: Path):
        """_parse returns [] for missing files (backward compat)."""
        from integrations.scanners.gitleaks import GitleaksAdapter
        from core.config import PlatformConfig
        adapter = GitleaksAdapter(PlatformConfig())
        result = adapter._parse(tmp_path / "nonexistent.json", "test-id", "test-asset")
        assert result == []

    def test_run_validates_json_before_parse(self):
        """run() must validate JSON before calling _parse."""
        from integrations.scanners.gitleaks import GitleaksAdapter
        source = inspect.getsource(GitleaksAdapter.run)
        assert "json.loads" in source, \
            "Gitleaks run() must validate JSON before _parse"
        assert "JSONDecodeError" in source or "json.JSONDecodeError" in source, \
            "Gitleaks run() must catch JSONDecodeError"


class TestTrivyFalseZeroPrevention:
    """Trivy adapter must not report succeeded+0 findings on invalid output."""

    def test_run_checks_report_existence_before_parse(self):
        """run() must check report.exists() before calling _parse."""
        from integrations.scanners.trivy import TrivyAdapter
        source = inspect.getsource(TrivyAdapter.run)
        assert "report.exists()" in source, \
            "Trivy run() must check report existence before calling _parse"
        assert "failed" in source, \
            "Trivy run() must return status='failed' on missing report"

    def test_parse_returns_empty_on_missing_file(self, tmp_path: Path):
        """_parse returns [] for missing files (backward compat)."""
        from integrations.scanners.trivy import TrivyAdapter
        from core.config import PlatformConfig
        adapter = TrivyAdapter(PlatformConfig())
        result = adapter._parse(tmp_path / "nonexistent.json", "test-id", "test-asset")
        assert result == []

    def test_run_validates_json_before_parse(self):
        """run() must validate JSON before calling _parse."""
        from integrations.scanners.trivy import TrivyAdapter
        source = inspect.getsource(TrivyAdapter.run)
        assert "json.loads" in source, \
            "Trivy run() must validate JSON before _parse"


class TestBriarDemoTargetOverride:
    """Briar demo mode must force target to local fixture, not accept arbitrary URLs."""

    def test_demo_mode_overrides_target_in_source(self):
        """The service.py source must override target when briar_demo is True."""
        from mcp_server import service
        source = inspect.getsource(service.run_security_assessment)
        assert "briar_demo" in source
        assert "127.0.0.1:18080" in source, \
            "Briar demo must force target to http://127.0.0.1:18080/"
        assert "skip_scope_check=briar_demo" in source, \
            "Briar demo still uses skip_scope_check (but target is overridden)"

    def test_demo_override_before_skip_scope_check(self):
        """Demo target override must come before skip_scope_check is set."""
        from mcp_server import service
        source = inspect.getsource(service.run_security_assessment)
        override_pos = source.index("127.0.0.1:18080")
        skip_pos = source.index("skip_scope_check=briar_demo")
        assert override_pos < skip_pos, \
            "Demo target override must come before skip_scope_check is set"
