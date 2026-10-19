"""Structured prompt construction (paper Section III.C).

The prompt concatenates the normalised finding, the four context classes and a
strict output schema demanding remediation SQL, rollback SQL, prerequisites,
risk level, assumptions and a verification SQL block.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from string import Template
from typing import Any

from ..controls import Control
from ..models import Finding
from ..verify.static_check import CONTROL_WHITELIST, ROLLBACK_WHITELIST

PROMPT_DIR = Path(__file__).resolve().parents[3] / "prompts"
_FALLBACK_SYSTEM = "You generate Oracle CIS remediations as a single JSON object."


@dataclass
class GenerationRequest:
    finding: Finding
    control: Control
    context: dict[str, Any] = field(default_factory=dict)
    system: str = ""
    user: str = ""


def _j(obj: Any, limit: int = 6000) -> str:
    if obj is None:
        return "(not provided -- context class disabled)"
    s = json.dumps(obj, indent=1, default=str, sort_keys=True)
    return s if len(s) <= limit else s[:limit] + "\n... (truncated)"


def _docs(docs: Any, limit: int = 6000) -> str:
    if docs is None:
        return "(not provided -- context class disabled)"
    if isinstance(docs, dict):
        return _j(docs)
    parts, total = [], 0
    for d in docs:
        block = f"[{d.get('source')} | score {d.get('score')}]\n{d.get('text', '').strip()}"
        if total + len(block) > limit:
            break
        parts.append(block)
        total += len(block)
    return "\n\n".join(parts) or "(no documents retrieved)"


def load_templates(prompt_dir: Path | None = None) -> tuple[str, Template]:
    d = prompt_dir or PROMPT_DIR
    system = (d / "system.md").read_text() if (d / "system.md").exists() else _FALLBACK_SYSTEM
    user = Template((d / "user.md").read_text()) if (d / "user.md").exists() else Template(
        "$finding_json\n$control_id\n$invariant\n$topology_json\n$dependency_json\n$documentation_text\n$policy_json")
    return system, user


def build_request(finding: Finding, control: Control, context: dict[str, Any],
                  prompt_dir: Path | None = None) -> GenerationRequest:
    system, user_t = load_templates(prompt_dir)
    user = user_t.safe_substitute(
        finding_json=_j({k: v for k, v in finding.to_dict().items() if k != "raw_audit_sql"}),
        control_id=control.id,
        cis_id=control.cis_id or "(map from licensed CIS PDF)",
        control_title=control.title,
        control_class=control.control_class,
        allowed_remediation=", ".join(sorted(CONTROL_WHITELIST.get(control.control_class, []))) or "(none)",
        allowed_rollback=", ".join(sorted(ROLLBACK_WHITELIST.get(control.control_class, []))) or "(none)",
        invariant=control.invariant() or f"(file-based check: {json.dumps(control.params)})",
        control_notes=control.notes or "-",
        topology_json=_j(context.get("topology")),
        dependency_json=_j(context.get("dependency")),
        documentation_text=_docs(context.get("documentation")),
        policy_json=_j(context.get("policy")),
    )
    return GenerationRequest(finding, control, context, system, user)
