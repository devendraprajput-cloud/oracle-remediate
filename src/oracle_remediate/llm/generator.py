"""LLM Remediation Generator with self-consistency (paper Sections III.C, III.D-1).

The paper uses k=5 self-consistency samples at T=0.3 and selects the plurality
remediation; for the confidence signal A and for Pass@k it draws n=10 samples.
This implementation draws ``k`` samples in normal operation and ``n`` samples
in evaluation mode (``--eval``); see docs/DESIGN_NOTES.md (D4).

A = (# samples whose canonicalised remediation equals the plurality) / (# samples drawn)

Unparseable samples count in the denominator, so a model that often fails the
schema is correctly less "confident".
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from ..models import Candidate, GenerationResult, TokenUsage
from ..verify.sqltools import canonicalize
from .backends import LLMBackend, LLMResponse
from .prompt import GenerationRequest

_FIELDS = ["remediation_sql", "rollback_sql", "verification_sql", "prerequisites", "risk_level", "assumptions",
           "rationale"]


def extract_json(text: str) -> dict:
    """Return the first JSON object in ``text`` (tolerates code fences and leading prose)."""
    t = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", t, re.S)
    if fence:
        t = fence.group(1)
    dec = json.JSONDecoder()
    for i, ch in enumerate(t):
        if ch == "{":
            try:
                obj, _ = dec.raw_decode(t[i:])
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue
    raise ValueError("no JSON object found in model output")


def _as_sql(v) -> str:
    if isinstance(v, list):
        return ";\n".join(str(x).strip().rstrip(";") for x in v if str(x).strip()) + ";"
    return str(v or "").strip()


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def parse_candidate(resp: LLMResponse, idx: int) -> Candidate:
    c = Candidate(sample_index=idx, raw_text=resp.text,
                  usage=TokenUsage(resp.input_tokens, resp.output_tokens), latency_s=resp.latency_s,
                  temperature_applied=resp.temperature_applied)
    try:
        obj = extract_json(resp.text)
    except ValueError as e:
        c.parse_error = str(e)
        return c
    missing = [f for f in ("remediation_sql", "rollback_sql", "risk_level") if f not in obj]
    c.remediation_sql = _as_sql(obj.get("remediation_sql"))
    c.rollback_sql = _as_sql(obj.get("rollback_sql"))
    c.verification_sql = _as_sql(obj.get("verification_sql"))
    c.prerequisites = _as_list(obj.get("prerequisites"))
    c.assumptions = _as_list(obj.get("assumptions"))
    c.risk_level = str(obj.get("risk_level", "")).strip().lower()
    c.rationale = str(obj.get("rationale", ""))
    if missing:
        c.parse_error = f"missing fields: {missing}"
    if c.valid:
        c.canonical = canonicalize(c.remediation_sql)
    return c


class RemediationGenerator:
    def __init__(self, backend: LLMBackend, k: int = 5, max_workers: int = 5, seed: int = 7):
        self.backend = backend
        self.k = k
        self.max_workers = max_workers
        self.seed = seed

    def generate(self, request: GenerationRequest, n: int | None = None) -> GenerationResult:
        n = n or self.k
        t0 = time.time()

        def one(i: int) -> Candidate:
            try:
                return parse_candidate(self.backend.complete(request, i, self.seed + i), i)
            except Exception as e:  # noqa: BLE001 - a failed sample is recorded, not fatal
                return Candidate(sample_index=i, parse_error=f"backend error: {type(e).__name__}: {e}")

        with ThreadPoolExecutor(max_workers=max(1, min(self.max_workers, n))) as ex:
            cands = sorted(ex.map(one, range(n)), key=lambda c: c.sample_index)

        valid = [c for c in cands if c.valid]
        counts = Counter(c.canonical for c in valid)
        plurality = None
        top = 0
        if counts:
            top = max(counts.values())
            # deterministic tie-break: the tied canonical form that appeared first
            winner = next(c.canonical for c in valid if counts[c.canonical] == top)
            plurality = next(c for c in valid if c.canonical == winner)
        usage = TokenUsage()
        for c in cands:
            usage = usage + c.usage
        temps = {c.temperature_applied for c in cands if c.parse_error is None or c.raw_text}
        return GenerationResult(
            candidates=cands, plurality=plurality, agreement=(top / n) if n else 0.0, plurality_count=top,
            backend=self.backend.name, model=self.backend.model,
            temperature_requested=self.backend.temperature,
            temperature_applied=(temps.pop() if len(temps) == 1 else None),
            usage=usage, wall_clock_s=time.time() - t0, prompt_chars=len(request.system) + len(request.user))
