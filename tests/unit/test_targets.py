from __future__ import annotations

import pytest

from core.targets import TargetKind, TargetSpec, validate_target


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("web_url", "https://staging.example.test/app"),
        ("api_url", "https://api.example.test/v1"),
        ("graphql_url", "https://api.example.test/graphql"),
        ("openapi_document", "specs/openapi.yaml"),
        ("source_path", "./src"),
        ("host", "STAGING.EXAMPLE.TEST."),
        ("host", "192.0.2.10"),
        ("host", "2001:db8::1"),
        ("cidr", "192.0.2.0/24"),
        ("android_artifact", "build/app.apk"),
        ("android_artifact", "build/app.aab"),
        ("ios_artifact", "build/app.ipa"),
        ("android_device", "emulator-5554"),
        ("ios_device", "00008110-001234567890001E"),
    ],
)
def test_valid_target_descriptors_parse(kind, value):
    spec = TargetSpec.parse(kind, value)
    assert spec.kind.value == kind
    assert spec.value


@pytest.mark.parametrize("value", ["", "example.test", "ftp://example.test", "//example.test"])
def test_url_requires_absolute_http_or_https_url(value):
    with pytest.raises(ValueError):
        TargetSpec.parse(TargetKind.WEB_URL, value)


@pytest.mark.parametrize(
    "value",
    [
        "https://user:secret@example.test",
        "https://example.test:99999",
        "https://bad host.test",
        "http:///missing-host",
    ],
)
def test_url_rejects_credentials_malformed_port_and_invalid_host(value):
    with pytest.raises(ValueError):
        TargetSpec.parse(TargetKind.API_URL, value)


@pytest.mark.parametrize("value", ["example.test/path", "https://example.test", "example.test:443", "bad host"])
def test_host_rejects_path_scheme_port_and_invalid_dns(value):
    with pytest.raises(ValueError):
        TargetSpec.parse(TargetKind.HOST, value)


@pytest.mark.parametrize("value", ["192.0.2.3/24", "not-a-cidr", "0.0.0.0/33"])
def test_cidr_requires_a_network_address_and_valid_prefix(value):
    with pytest.raises(ValueError):
        TargetSpec.parse(TargetKind.CIDR, value)


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        (TargetKind.OPENAPI_DOCUMENT, "schema.txt"),
        (TargetKind.ANDROID_ARTIFACT, "app.ipa"),
        (TargetKind.IOS_ARTIFACT, "app.apk"),
        (TargetKind.ANDROID_DEVICE, "../emulator"),
        (TargetKind.SOURCE_PATH, "src\x00malicious"),
    ],
)
def test_target_specific_validation_rejects_invalid_values(kind, value):
    with pytest.raises(ValueError):
        TargetSpec.parse(kind, value)


def test_target_kind_must_be_registered():
    with pytest.raises(ValueError, match="Unsupported target kind"):
        TargetSpec.parse("shell_command", "echo hello")


def test_validation_output_is_json_friendly_and_not_authorization():
    assert validate_target("host", "192.0.2.1") == {
        "kind": "host",
        "value": "192.0.2.1",
    }
