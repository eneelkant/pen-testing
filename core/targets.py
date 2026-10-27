"""Typed target descriptors for the unified assessment roadmap.

These descriptors validate syntax only. They do not grant authorization, resolve DNS,
confine filesystem paths or make any scanner safe to run. Callers must independently
apply the relevant scope policy, egress policy and local-path confinement.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePath
from urllib.parse import urlsplit


class TargetKind(str, Enum):
    WEB_URL = "web_url"
    API_URL = "api_url"
    GRAPHQL_URL = "graphql_url"
    OPENAPI_DOCUMENT = "openapi_document"
    SOURCE_PATH = "source_path"
    HOST = "host"
    CIDR = "cidr"
    ANDROID_ARTIFACT = "android_artifact"
    IOS_ARTIFACT = "ios_artifact"
    ANDROID_DEVICE = "android_device"
    IOS_DEVICE = "ios_device"


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DEVICE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_URL_KINDS = {TargetKind.WEB_URL, TargetKind.API_URL, TargetKind.GRAPHQL_URL}
_ANDROID_SUFFIXES = {".apk", ".aab"}
_IOS_SUFFIXES = {".ipa"}
_OPENAPI_SUFFIXES = {".json", ".yaml", ".yml"}


@dataclass(frozen=True)
class TargetSpec:
    """A syntax-validated target value; never an authorization grant."""

    kind: TargetKind
    value: str

    @classmethod
    def parse(cls, kind: TargetKind | str, value: str) -> "TargetSpec":
        try:
            target_kind = kind if isinstance(kind, TargetKind) else TargetKind(str(kind))
        except ValueError as exc:
            choices = ", ".join(item.value for item in TargetKind)
            raise ValueError(f"Unsupported target kind; expected one of: {choices}") from exc

        if not isinstance(value, str):
            raise ValueError("Target value must be a string")
        target = value.strip()
        if not target:
            raise ValueError("Target value is empty")
        if _CONTROL_CHARS.search(target):
            raise ValueError("Target value contains control characters")

        if target_kind in _URL_KINDS:
            cls._validate_url(target)
        elif target_kind == TargetKind.HOST:
            target = cls._normalize_host(target)
        elif target_kind == TargetKind.CIDR:
            try:
                network = ipaddress.ip_network(target, strict=True)
            except ValueError as exc:
                raise ValueError("CIDR must be a valid network address and prefix") from exc
            target = network.with_prefixlen
        elif target_kind == TargetKind.OPENAPI_DOCUMENT:
            if PurePath(target).suffix.lower() not in _OPENAPI_SUFFIXES:
                raise ValueError("OpenAPI document must use .json, .yaml or .yml")
        elif target_kind == TargetKind.ANDROID_ARTIFACT:
            if PurePath(target).suffix.lower() not in _ANDROID_SUFFIXES:
                raise ValueError("Android artifact must use a supported .apk or .aab filename")
        elif target_kind == TargetKind.IOS_ARTIFACT:
            if PurePath(target).suffix.lower() not in _IOS_SUFFIXES:
                raise ValueError("iOS artifact must use a .ipa filename")
        elif target_kind in {TargetKind.ANDROID_DEVICE, TargetKind.IOS_DEVICE}:
            if not _DEVICE_ID.fullmatch(target):
                raise ValueError("Device identifier contains unsupported characters")
        # SOURCE_PATH is deliberately not resolved here: callers must use the
        # repository's existing configured-root and symlink-confinement helpers.
        return cls(kind=target_kind, value=target)

    @staticmethod
    def _validate_url(value: str) -> None:
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            # Accessing .port validates malformed/out-of-range ports.
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("URL has an invalid hostname or port") from exc

        if parsed.scheme.lower() not in {"http", "https"} or not hostname:
            raise ValueError("URL must be an absolute http(s) URL with a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL userinfo is not allowed in a target descriptor")
        if any(ch.isspace() for ch in value):
            raise ValueError("URL must not contain whitespace")

        TargetSpec._normalize_host(hostname)

    @staticmethod
    def _normalize_host(value: str) -> str:
        host = value.strip().lower()
        if not host:
            raise ValueError("Host is empty")
        if "://" in host or any(mark in host for mark in ("/", "\\", "@", "?", "#")):
            raise ValueError("Host must not contain a scheme, path, credentials or query")

        unwrapped = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        try:
            return ipaddress.ip_address(unwrapped).compressed
        except ValueError:
            # A colon in a non-IP literal is usually a port or malformed IPv6;
            # ports belong in a URL or a separate, explicit service-port field.
            if ":" in unwrapped:
                raise ValueError("Host must be a hostname or IP literal without a port")
            try:
                ascii_host = unwrapped.rstrip(".").encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("Host is not a valid DNS name") from exc
            if len(ascii_host) > 253 or not ascii_host:
                raise ValueError("Host is not a valid DNS name")
            labels = ascii_host.split(".")
            if any(not _DNS_LABEL.fullmatch(label) for label in labels):
                raise ValueError("Host is not a valid DNS name")
            return ascii_host


def validate_target(kind: TargetKind | str, value: str) -> dict[str, str]:
    """Return a JSON-serializable descriptor after syntax-only validation."""
    spec = TargetSpec.parse(kind, value)
    return {"kind": spec.kind.value, "value": spec.value}
