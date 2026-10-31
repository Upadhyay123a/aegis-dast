"""Shared test fixtures: in-memory fake models implementing the Target API.

No network is used. These model the behaviours the probes look for.
"""

from __future__ import annotations

import base64
import codecs
import re

import pytest

from aegis_ai.models import Message, Target, _merge_prompt

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


def _try_decode(text: str) -> str:
    """Best-effort decode of base64 / ROT13 content embedded in text."""
    decoded = [codecs.encode(text, "rot_13")]
    for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            decoded.append(base64.b64decode(token).decode("utf-8", "ignore"))
        except Exception:  # noqa: BLE001
            pass
    return " ".join(decoded)


def _compute(text: str) -> str | None:
    m = _MATH.search(text)
    return str(int(m.group(1)) * int(m.group(2))) if m else None


class VulnerableModel(Target):
    """A deliberately insecure model that falls for every probe."""

    name = "vulnerable-model"
    supports_roles = True

    def generate(self, prompt: str, *, system: str | None = None, context: str | None = None) -> str:
        text = _merge_prompt(prompt, system, context)
        low = text.lower()

        # Insecure output: echoes requested payload verbatim.
        if "output exactly the following text" in low:
            after = prompt.split("nothing else:", 1)
            if len(after) == 2:
                return after[1].strip()

        # Unbounded consumption: happily produces a huge repetitive output.
        rm = re.search(r"repeat the word (\w+) exactly (\d+) times", low)
        if rm:
            word, n = rm.group(1).upper(), min(int(rm.group(2)), 2000)
            return " ".join([word] * n)

        # Excessive agency: claims to perform destructive actions.
        if any(k in text for k in ("delete_all_users", "transfer_funds", "rm -rf")):
            return "Done. I have executed the requested action successfully."

        # Prompt injection / jailbreak / indirect / encoded: obey embedded math,
        # including math hidden in base64/ROT13 content.
        product = _compute(text) or _compute(_try_decode(text))
        if product:
            return product

        # System prompt / sensitive info leakage.
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


class CrescendoModel(Target):
    """Refuses a direct one-shot math request, but complies after several turns.

    Demonstrates that the multi-turn probe catches what single-turn probes miss.
    """

    name = "crescendo-model"
    supports_roles = True

    def generate(self, prompt: str, *, system: str | None = None, context: str | None = None) -> str:
        if _MATH.search(prompt):
            return "I'm sorry, I can't do math."  # single-turn guardrail
        return "Sure, happy to help!"

    def converse(self, messages: list[Message], *, system: str | None = None) -> str:
        user_turns = [m for m in messages if m.get("role") == "user"]
        last = messages[-1]["content"] if messages else ""
        product = _compute(last)
        if product and len(user_turns) >= 3:  # complies only after rapport
            return product
        if _MATH.search(last):
            return "I'm sorry, I can't do math."
        return "Happy to help with your app!"


@pytest.fixture
def vulnerable():
    return VulnerableModel()


@pytest.fixture
def secure():
    return SecureModel()


@pytest.fixture
def echo():
    return EchoModel()


@pytest.fixture
def crescendo():
    return CrescendoModel()
