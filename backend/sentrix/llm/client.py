"""Optional LLM integration (OpenAI or Anthropic) over plain HTTPS.

The LLM is used ONLY for narrative analysis (incident summaries, analyst
guidance, grounded RAG answers). It never casts council votes, never changes
scores and never triggers response actions. When no provider is configured
every caller falls back to deterministic output and reports
``llm.status = "disabled"``.

API keys are read from the environment and are never logged or returned.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx

from sentrix.core.config import get_settings
from sentrix.core.logging import get_logger

log = get_logger("llm")


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    latency_ms: float


class LLMClient:
    def __init__(self) -> None:
        self.last_error: str | None = None
        self.calls = 0
        self.failures = 0

    @property
    def available(self) -> bool:
        return get_settings().llm_configured

    def status(self) -> dict[str, Any]:
        s = get_settings()
        model = {"openai": s.openai_model, "anthropic": s.anthropic_model}.get(s.llm_provider)
        return {
            "provider": s.llm_provider,
            "model": model,
            "configured": s.llm_configured,
            "calls": self.calls,
            "failures": self.failures,
            "last_error": self.last_error,
        }

    def complete(self, system: str, prompt: str, max_tokens: int | None = None) -> LLMResponse:
        s = get_settings()
        if not s.llm_configured:
            raise LLMError("LLM provider is not configured")
        max_tokens = max_tokens or s.llm_max_tokens
        start = time.perf_counter()
        self.calls += 1
        try:
            if s.llm_provider == "openai":
                assert s.openai_api_key is not None
                r = httpx.post(
                    f"{s.openai_base_url.rstrip('/')}/chat/completions",
                    headers={"Authorization": f"Bearer {s.openai_api_key.get_secret_value()}"},
                    json={
                        "model": s.openai_model,
                        "max_tokens": max_tokens,
                        "temperature": 0.2,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": prompt},
                        ],
                    },
                    timeout=s.llm_timeout_seconds,
                )
                r.raise_for_status()
                text = r.json()["choices"][0]["message"]["content"]
                model = s.openai_model
            else:
                assert s.anthropic_api_key is not None
                r = httpx.post(
                    f"{s.anthropic_base_url.rstrip('/')}/v1/messages",
                    headers={
                        "x-api-key": s.anthropic_api_key.get_secret_value(),
                        "anthropic-version": "2023-06-01",
                    },
                    json={
                        "model": s.anthropic_model,
                        "max_tokens": max_tokens,
                        "temperature": 0.2,
                        "system": system,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                    timeout=s.llm_timeout_seconds,
                )
                r.raise_for_status()
                text = "".join(b.get("text", "") for b in r.json().get("content", []))
                model = s.anthropic_model
        except httpx.HTTPStatusError as exc:
            self.failures += 1
            # Do not echo response bodies: they can contain request details.
            self.last_error = f"HTTP {exc.response.status_code} from {s.llm_provider}"
            log.warning("LLM call failed: %s", self.last_error)
            raise LLMError(self.last_error) from None
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            self.failures += 1
            self.last_error = f"{type(exc).__name__} calling {s.llm_provider}"
            log.warning("LLM call failed: %s", self.last_error)
            raise LLMError(self.last_error) from None
        self.last_error = None
        return LLMResponse(
            text=text.strip(),
            provider=s.llm_provider,
            model=model,
            latency_ms=round((time.perf_counter() - start) * 1000, 1),
        )

    def complete_json(self, system: str, prompt: str) -> tuple[dict[str, Any], LLMResponse]:
        resp = self.complete(system + "\nRespond with a single JSON object and nothing else.", prompt)
        match = re.search(r"\{.*\}", resp.text, re.S)
        if not match:
            raise LLMError("LLM did not return JSON")
        try:
            return json.loads(match.group(0)), resp
        except json.JSONDecodeError:
            raise LLMError("LLM returned malformed JSON") from None


llm = LLMClient()
