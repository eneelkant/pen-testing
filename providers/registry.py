"""AI provider configuration detection (no secrets logged)."""

from __future__ import annotations

import os
from typing import Any

PROVIDER_ENV_VARS: dict[str, list[str]] = {
    "anthropic": ["ANTHROPIC_API_KEY"],
    "openai": ["OPENAI_API_KEY"],
    "xai": ["XAI_API_KEY"],
    "bedrock": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
    "deepseek": ["DEEPSEEK_API_KEY"],
    "groq": ["GROQ_API_KEY"],
    "mistral": ["MISTRAL_API_KEY"],
    "google": ["GOOGLE_API_KEY"],
    "openrouter": ["OPENROUTER_API_KEY"],
    "together": ["TOGETHER_API_KEY"],
    "ollama": ["OLLAMA_HOST"],
}


def list_provider_status() -> dict[str, Any]:
    status = {}
    for name, keys in PROVIDER_ENV_VARS.items():
        present = {k: bool(os.environ.get(k)) for k in keys}
        # Ollama may work with default host even if unset
        configured = all(present.values()) if name != "ollama" else True
        if name == "ollama":
            configured = True
        status[name] = {
            "configured": configured if name == "ollama" else all(present.values()),
            "env_present": present,
            "notes": "Local default http://127.0.0.1:11434 when OLLAMA_HOST unset"
            if name == "ollama"
            else "",
        }
    return status
