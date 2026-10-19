"""Minimal, span-preserving parser/editor for Oracle Net ``.ora`` files.

Supports the file-based controls (paper: sixteen controls are verified by shell
commands against listener.ora / sqlnet.ora).  Instead of letting the LLM emit
shell commands, remediations for these controls use the pseudo statements
``ORA_SET <file> <KEY> = <VALUE>`` / ``ORA_UNSET <file> <KEY>``; this module
applies them while preserving every other byte of the file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class OraEntry:
    key: str  # upper-cased
    value: str
    start: int
    end: int  # exclusive, includes trailing newline if present


def parse(text: str) -> list[OraEntry]:
    """Parse top-level ``KEY = VALUE`` entries (values may span lines in parentheses)."""
    entries: list[OraEntry] = []
    i, n = 0, len(text)
    while i < n:
        line_end = text.find("\n", i)
        line_end = n if line_end < 0 else line_end
        line = text[i:line_end]
        stripped = line.split("#", 1)[0]
        if not stripped.strip() or line[:1].isspace() and "=" not in stripped:
            i = line_end + 1
            continue
        m = re.match(r"\s*([A-Za-z0-9_.$#]+)\s*=\s*(.*)$", stripped)
        if not m:
            i = line_end + 1
            continue
        key = m.group(1).upper()
        value_parts = [m.group(2)]
        depth = m.group(2).count("(") - m.group(2).count(")")
        j = line_end + 1
        end = min(line_end + 1, n)
        # continuation: unbalanced parentheses, or "KEY =" followed by a "(" block
        while j < n and (depth > 0 or not "".join(value_parts).strip()):
            le = text.find("\n", j)
            le = n if le < 0 else le
            part = text[j:le].split("#", 1)[0]
            if not part.strip():
                if depth > 0:
                    j = le + 1
                    continue
                break
            if depth == 0 and not part.strip().startswith("("):
                break
            value_parts.append(part)
            depth += part.count("(") - part.count(")")
            j = le + 1
            end = min(j, n)
        entries.append(OraEntry(key, " ".join(p.strip() for p in value_parts if p.strip()).strip(), i, end))
        i = end if end > i else line_end + 1
    return entries


def as_dict(text: str) -> dict[str, str]:
    return {e.key: e.value for e in parse(text)}


def normalize_value(v: str | None) -> str:
    return re.sub(r"\s+", "", v or "").upper()


def set_key(text: str, key: str, value: str) -> str:
    key_u = key.upper()
    for e in parse(text):
        if e.key == key_u:
            nl = "\n" if text[e.start:e.end].endswith("\n") else ""
            return text[: e.start] + f"{key_u} = {value}{nl}" + text[e.end:]
    sep = "" if not text or text.endswith("\n") else "\n"
    return text + f"{sep}{key_u} = {value}\n"


def unset_key(text: str, key: str) -> str:
    key_u = key.upper()
    for e in parse(text):
        if e.key == key_u:
            return text[: e.start] + text[e.end:]
    return text


def evaluate(text: str, params: dict, listeners: list[str]) -> list[tuple]:
    """Return violation rows for an ``ora_file`` control (empty == compliant)."""
    d = as_dict(text)
    op = params.get("op", "eq")
    if op == "absent_substring":
        sub = params["substring"].upper()
        return [(k, v) for k, v in d.items() if sub in v.upper() or sub in k]
    keys = [params["key"].replace("{listener}", ln.upper()) for ln in listeners] if "{listener}" in params.get(
        "key", "") else [params["key"]]
    rows = []
    for k in keys:
        cur = d.get(k.upper())
        if op == "eq":
            if normalize_value(cur) != normalize_value(str(params["expected"])):
                rows.append((k.upper(), cur))
        elif op == "present":
            if cur is None or not cur.strip():
                rows.append((k.upper(), cur))
        else:
            raise ValueError(f"unsupported ora_file op {op}")
    return rows
