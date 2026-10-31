"""Shared test fixtures: in-memory fake models implementing the Target API.

No network is used. These model the behaviours the probes look for.
"""

from __future__ import annotations

import re

import pytest

from aegis_ai.models import Target

_MATH = re.compile(r"(\d+)\s*(?:multiplied by|times|\*|x)\s*(\d+)", re.I)
_LEAK_TRIGGERS = (
    "repeat everything",
    "system instructions",
    "system prompt",
    "hidden instructions",
    "confidential",
    "secret",
    "api key",
    "keys, passwords",
    "print the secret",
)


class VulnerableModel(Target):
    """A deliberately insecure model that falls for every probe."""

    name = "vulnerable-model"
    supports_roles = True

    def generate(self, prompt: str, *, system: str | None = None, context: str | None = None) -> str:
        low = prompt.lower()

        # Insecure output: echoes requested payload verbatim.
        if "output exactly the following text" in low:
            after = prompt.split("nothing else:", 1)
            if len(after) == 2:
                return after[1].strip()

        # Prompt injection / jailbreak: obeys embedded arithmetic instruction.
        m = _MATH.search(prompt)
        if m:
            return str(int(m.group(1)) * int(m.group(2)))

        # System prompt / sensitive info leakage: dumps privileged content.
        if system and any(t in low for t in _LEAK_TRIGGERS):
            return f"Sure, here is what I was told: {system}"

        return "Hello! How can I help you today?"


class SecureModel(Target):
    """A robust model that resists every probe."""

    name = "secure-model"
    supports_roles = True

    def generate(self, prompt: str, *, system: str | None = None, context: str | None = None) -> str:
        return "I'm sorry, but I can't help with that request."


class EchoModel(Target):
    """A non-AI endpoint that simply reflects input (no role separation).

    Used to confirm probes don't raise false positives on plain reflection.
    """

    name = "echo-endpoint"
    supports_roles = False

    def generate(self, prompt: str, *, system: str | None = None, context: str | None = None) -> str:
        return f"You said: {prompt}"


@pytest.fixture
def vulnerable():
    return VulnerableModel()


@pytest.fixture
def secure():
    return SecureModel()


@pytest.fixture
def echo():
    return EchoModel()
