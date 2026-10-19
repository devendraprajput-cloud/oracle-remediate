"""Document ingestion and context-augmented retrieval (paper Section III.B).

Query string (paper): control identifier + keyword extraction from the control
description + observed deviation.

Corpus: ``knowledge/`` ships short original notes written for this project.
The paper's corpus -- CIS benchmark sections, the Oracle Database Security
Guide and My Oracle Support notes -- is licensed content; ingest your own
licensed copies with ``orarem rag ingest <dir>`` (``.md`` / ``.txt``).  A file
may start with a line ``controls: id1, id2`` to tag its chunks.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path

from ..controls import Control
from ..models import Finding
from .store import Chunk, Embedder, InMemoryVectorStore, VectorStore

_STOP = set("""a an and are as at be by for from has have in is it its of on or that the this to with ensure
not no any all set is are be been was were which who than then there their they them into per each every
should must may can will""".split())


def extract_keywords(text: str, n: int = 8) -> list[str]:
    toks = [t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_$#.]{2,}", text)]
    toks = [t for t in toks if t not in _STOP]
    return [w for w, _ in Counter(toks).most_common(n)]


def build_query(control: Control, finding: Finding) -> str:
    kw = extract_keywords(" ".join([control.title, " ".join(control.keywords), control.notes]))
    return " ".join(filter(None, [control.id, control.cis_id or "", " ".join(kw),
                                  f"observed: {finding.observed_value[:300]}",
                                  f"expected: {finding.expected_value}"]))


def chunk_file(path: Path, max_chars: int = 1200) -> list[Chunk]:
    text = path.read_text(errors="replace")
    control_ids: list[str] = []
    m = re.match(r"^controls:\s*(.+)$", text.splitlines()[0]) if text else None
    if m:
        control_ids = [c.strip() for c in m.group(1).split(",") if c.strip()]
        text = "\n".join(text.splitlines()[1:])
    # split on markdown headings first, then pack paragraphs up to max_chars
    sections = re.split(r"(?m)^(?=#{1,4} )", text)
    chunks: list[Chunk] = []
    for sec in sections:
        buf = ""
        for para in re.split(r"\n\s*\n", sec):
            if len(buf) + len(para) > max_chars and buf:
                chunks.append(buf.strip())
                buf = ""
            buf += para + "\n\n"
        if buf.strip():
            chunks.append(buf.strip())
    return [Chunk(chunk_id=f"{path.name}#{i}-{hashlib.sha1(t.encode()).hexdigest()[:8]}", source=str(path.name),
                  text=t, control_ids=control_ids) for i, t in enumerate(chunks)]


class DocumentRetriever:
    def __init__(self, embedder: Embedder, store: VectorStore | None = None, top_k: int = 5):
        self.embedder = embedder
        self.store = store or InMemoryVectorStore()
        self.top_k = top_k

    def ingest_dir(self, directory: str | Path, max_chars: int = 1200) -> int:
        files = sorted(p for p in Path(directory).rglob("*")
                       if p.suffix.lower() in (".md", ".txt") and not p.name.upper().startswith("README"))
        chunks = [c for f in files for c in chunk_file(f, max_chars)]
        if chunks:
            self.store.add(chunks, self.embedder.embed([c.text for c in chunks]))
        return len(chunks)

    def retrieve(self, control: Control, finding: Finding, k: int | None = None) -> list[dict]:
        q = build_query(control, finding)
        vec = self.embedder.embed([q])[0]
        hits = self.store.search(vec, (k or self.top_k) * 2)
        # small boost for chunks explicitly tagged with this control, then truncate to k
        ranked = sorted(hits, key=lambda h: h[1] + (0.25 if control.id in h[0].control_ids else 0.0), reverse=True)
        return [{"source": c.source, "chunk_id": c.chunk_id, "score": round(s, 4), "text": c.text}
                for c, s in ranked[: (k or self.top_k)]]
