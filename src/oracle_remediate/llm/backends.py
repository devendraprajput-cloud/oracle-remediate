"""LLM backends (paper Section III.C, Table II).

The paper evaluates Claude Opus 4.7, a GPT-5-class model and Llama-3.3-70B at
T=0.3.  Verified provider behaviour that affects this design (Oct 2026):

* Anthropic documents that ``temperature``/``top_p``/``top_k`` set to any
  non-default value return HTTP 400 on Claude Opus 4.7 and later models.
* OpenAI GPT-5 reasoning models accept only the default ``temperature`` (1).
* Self-hosted Llama-3.3-70B (vLLM, Ollama, TGI via the OpenAI-compatible API)
  honours ``temperature``.

``temperature_policy`` therefore defaults to ``auto``: the temperature is sent
unless the model is on the documented reject list; a 400 that names a sampling
parameter triggers one retry without it.  The temperature actually applied is
recorded per run (``temperature_applied``) so results are never mis-reported as
T=0.3 when the provider ignored or rejected it.
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any

from .prompt import GenerationRequest

# Models documented to reject non-default sampling parameters.
REJECTS_TEMPERATURE = [
    re.compile(r"^claude-(opus-4-[78]|opus-5|sonnet-5)"),  # Anthropic docs: Opus 4.7+ and Sonnet 5
    re.compile(r"^(gpt-5(?!-chat)|o[134](-|$))"),  # OpenAI reasoning models: default temperature only
]


@dataclass
class LLMResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    temperature_applied: float | None = None
    latency_s: float = 0.0
    stop_reason: str | None = None


class LLMBackend:
    name = "base"

    def __init__(self, model: str, temperature: float | None = 0.3, temperature_policy: str = "auto",
                 max_tokens: int = 4096, timeout_s: float = 120.0, **_: Any):
        self.model = model
        self.temperature = temperature
        self.temperature_policy = temperature_policy
        self.max_tokens = max_tokens
        self.timeout_s = timeout_s
        self._temp_rejected = any(p.search(model) for p in REJECTS_TEMPERATURE)
        self._lock = threading.Lock()

    def _send_temperature(self) -> bool:
        if self.temperature is None or self.temperature_policy == "never":
            return False
        if self.temperature_policy == "always":
            return True
        return not self._temp_rejected

    @staticmethod
    def _is_sampling_error(e: Exception) -> bool:
        s = str(e).lower()
        return ("temperature" in s or "top_p" in s or "sampling" in s) and ("400" in s or "unsupported" in s
                                                                               or "invalid" in s or "not supported" in s)

    def complete(self, request: GenerationRequest, sample_index: int, seed: int) -> LLMResponse:
        t0 = time.time()
        send = self._send_temperature()
        try:
            resp = self._call(request, send, sample_index, seed)
        except Exception as e:  # noqa: BLE001
            if send and self.temperature_policy == "auto" and self._is_sampling_error(e):
                with self._lock:
                    self._temp_rejected = True
                resp = self._call(request, False, sample_index, seed)
            else:
                raise
        resp.latency_s = time.time() - t0
        return resp

    def _call(self, request: GenerationRequest, send_temperature: bool, sample_index: int,
              seed: int) -> LLMResponse:  # pragma: no cover - abstract
        raise NotImplementedError


class AnthropicBackend(LLMBackend):  # pragma: no cover - network
    name = "anthropic"

    def __init__(self, model: str = "claude-opus-4-7", api_key_env: str | None = None, effort: str | None = None, **kw):
        super().__init__(model, **kw)
        import anthropic
        self.client = anthropic.Anthropic(api_key=os.environ.get(api_key_env or "ANTHROPIC_API_KEY"),
                                          timeout=self.timeout_s)
        self.effort = effort

    def _call(self, request, send_temperature, sample_index, seed):
        kwargs: dict[str, Any] = {"model": self.model, "max_tokens": self.max_tokens, "system": request.system,
                                  "messages": [{"role": "user", "content": request.user}]}
        if send_temperature:
            kwargs["temperature"] = self.temperature
        if self.effort:
            kwargs["extra_body"] = {"output_config": {"effort": self.effort}}
        r = self.client.messages.create(**kwargs)
        # Select text blocks by type: newer models may return thinking blocks first.
        text = "".join(getattr(b, "text", "") for b in r.content if getattr(b, "type", "") == "text")
        return LLMResponse(text, r.usage.input_tokens, r.usage.output_tokens,
                           self.temperature if send_temperature else None, stop_reason=r.stop_reason)


class OpenAIBackend(LLMBackend):  # pragma: no cover - network
    name = "openai"
    _max_tokens_key = "max_completion_tokens"

    def __init__(self, model: str = "gpt-5", api_key_env: str | None = None, base_url: str | None = None, **kw):
        super().__init__(model, **kw)
        from openai import OpenAI
        self.client = OpenAI(api_key=os.environ.get(api_key_env or "OPENAI_API_KEY", "not-needed"),
                             base_url=base_url, timeout=self.timeout_s)

    def _call(self, request, send_temperature, sample_index, seed):
        kwargs: dict[str, Any] = {"model": self.model, self._max_tokens_key: self.max_tokens,
                                  "messages": [{"role": "system", "content": request.system},
                                               {"role": "user", "content": request.user}]}
        if send_temperature:
            kwargs["temperature"] = self.temperature
        kwargs.update(self._extra(seed))
        r = self.client.chat.completions.create(**kwargs)
        u = r.usage
        return LLMResponse(r.choices[0].message.content or "", getattr(u, "prompt_tokens", 0),
                           getattr(u, "completion_tokens", 0), self.temperature if send_temperature else None,
                           stop_reason=r.choices[0].finish_reason)

    def _extra(self, seed: int) -> dict[str, Any]:
        return {}


class OpenAICompatibleBackend(OpenAIBackend):  # pragma: no cover - network
    """Self-hosted Llama-3.3-70B via vLLM / Ollama / TGI OpenAI-compatible endpoints."""

    name = "openai_compatible"
    _max_tokens_key = "max_tokens"

    def __init__(self, model: str = "meta-llama/Llama-3.3-70B-Instruct", base_url: str | None = None, **kw):
        super().__init__(model=model, base_url=base_url or "http://localhost:8000/v1", **kw)

    def _extra(self, seed: int) -> dict[str, Any]:
        return {"seed": seed}


class LangChainBackend(LLMBackend):  # pragma: no cover - optional dependency
    """Paper Table II lists LangChain 0.3 for orchestration; any LangChain chat model can be used."""

    name = "langchain"

    def __init__(self, model: str, provider: str | None = None, **kw):
        super().__init__(model, **kw)
        from langchain.chat_models import init_chat_model
        self._init = init_chat_model
        self.provider = provider
        self._cache: dict[bool, Any] = {}

    def _chat(self, send_temperature: bool):
        if send_temperature not in self._cache:
            extra = {"temperature": self.temperature} if send_temperature else {}
            self._cache[send_temperature] = self._init(self.model, model_provider=self.provider,
                                                       max_tokens=self.max_tokens, **extra)
        return self._cache[send_temperature]

    def _call(self, request, send_temperature, sample_index, seed):
        from langchain_core.messages import HumanMessage, SystemMessage
        msg = self._chat(send_temperature).invoke([SystemMessage(request.system), HumanMessage(request.user)])
        um = getattr(msg, "usage_metadata", None) or {}
        content = msg.content if isinstance(msg.content, str) else "".join(
            c.get("text", "") for c in msg.content if isinstance(c, dict) and c.get("type") == "text")
        return LLMResponse(content, um.get("input_tokens", 0), um.get("output_tokens", 0),
                           self.temperature if send_temperature else None)


def make_backend(cfg) -> LLMBackend:
    llm = cfg.get("llm")
    common = {"temperature": llm.get("temperature"), "temperature_policy": llm.get("temperature_policy", "auto"),
              "max_tokens": int(llm.get("max_tokens", 4096)), "timeout_s": float(llm.get("timeout_s", 120))}
    b = llm["backend"]
    if b == "mock":
        from .mock import MockRemediationBackend
        return MockRemediationBackend(model=llm.get("model", "mock-remediator"), seed=int(cfg.get("seed", 7)),
                                      **llm.get("mock", {}), **common)
    if b == "anthropic":
        return AnthropicBackend(model=llm["model"], api_key_env=llm.get("api_key_env"), effort=llm.get("effort"),
                                **common)
    if b == "openai":
        return OpenAIBackend(model=llm["model"], api_key_env=llm.get("api_key_env"), base_url=llm.get("base_url"),
                             **common)
    if b == "openai_compatible":
        return OpenAICompatibleBackend(model=llm["model"], base_url=llm.get("base_url"),
                                       api_key_env=llm.get("api_key_env"), **common)
    if b == "langchain":
        return LangChainBackend(model=llm["model"], provider=llm.get("provider"), **common)
    raise ValueError(f"unknown llm backend {b}")
