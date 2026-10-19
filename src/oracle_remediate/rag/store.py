"""Documentation context: embedders and vector stores (paper Section III.B, Table II).

Embedders
  * ``hashing``  -- deterministic feature hashing (offline, tests, CI; low quality)
  * ``bge-m3``   -- BAAI/bge-m3 via sentence-transformers (1024 dims), as in Table II
  * ``openai``   -- text-embedding-3-large (``dimensions`` set to match the store)

Stores
  * ``memory``     -- numpy cosine similarity (offline)
  * ``oracle23ai`` -- Oracle Database 23ai AI Vector Search: a VECTOR column queried
                      with VECTOR_DISTANCE(..., COSINE) and FETCH FIRST k ROWS ONLY.
                      python-oracledb (>= 2.2) binds array.array('f') to VECTOR.
"""

from __future__ import annotations

import array
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

import numpy as np

_TOKEN = re.compile(r"[A-Za-z0-9_$#.]+")


class Embedder(Protocol):
    dim: int

    def embed(self, texts: list[str]) -> np.ndarray: ...


class HashingEmbedder:
    """Feature-hashing bag of words + bigrams, L2-normalised. Deterministic, no model download."""

    def __init__(self, dim: int = 1024):
        self.dim = dim

    def embed(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, t in enumerate(texts):
            toks = [x.lower() for x in _TOKEN.findall(t)]
            feats = toks + [a + " " + b for a, b in zip(toks, toks[1:])]
            for f in feats:
                h = int(hashlib.md5(f.encode()).hexdigest(), 16)
                out[i, h % self.dim] += 1.0 if (h >> 64) & 1 else -1.0
            n = np.linalg.norm(out[i])
            if n:
                out[i] /= n
        return out


class SentenceTransformerEmbedder:  # pragma: no cover - optional heavy dependency
    def __init__(self, model: str = "BAAI/bge-m3"):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model)
        self.dim = int(self.model.get_sentence_embedding_dimension())

    def embed(self, texts: list[str]) -> np.ndarray:
        return np.asarray(self.model.encode(texts, normalize_embeddings=True), dtype=np.float32)


class OpenAIEmbedder:  # pragma: no cover - network
    def __init__(self, model: str = "text-embedding-3-large", dim: int = 1024, api_key_env: str = "OPENAI_API_KEY"):
        from openai import OpenAI
        self.client = OpenAI(api_key=os.environ.get(api_key_env))
        self.model, self.dim = model, dim

    def embed(self, texts: list[str]) -> np.ndarray:
        r = self.client.embeddings.create(model=self.model, input=texts, dimensions=self.dim)
        v = np.asarray([d.embedding for d in r.data], dtype=np.float32)
        return v / np.linalg.norm(v, axis=1, keepdims=True)


def make_embedder(name: str, dim: int) -> Embedder:
    if name == "hashing":
        return HashingEmbedder(dim)
    if name in ("bge-m3", "sentence-transformers"):
        return SentenceTransformerEmbedder()
    if name == "openai":
        return OpenAIEmbedder(dim=dim)
    raise ValueError(f"unknown embedder {name}")


@dataclass
class Chunk:
    chunk_id: str
    source: str
    text: str
    control_ids: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


class VectorStore(Protocol):
    def add(self, chunks: list[Chunk], vectors: np.ndarray) -> None: ...

    def search(self, vector: np.ndarray, k: int) -> list[tuple[Chunk, float]]: ...


class InMemoryVectorStore:
    def __init__(self):
        self.chunks: list[Chunk] = []
        self.matrix: np.ndarray | None = None

    def add(self, chunks: list[Chunk], vectors: np.ndarray) -> None:
        self.chunks.extend(chunks)
        self.matrix = vectors if self.matrix is None else np.vstack([self.matrix, vectors])

    def search(self, vector: np.ndarray, k: int) -> list[tuple[Chunk, float]]:
        if self.matrix is None or not len(self.chunks):
            return []
        sims = self.matrix @ vector.reshape(-1)
        idx = np.argsort(-sims)[:k]
        return [(self.chunks[i], float(sims[i])) for i in idx]


class Oracle23aiVectorStore:  # pragma: no cover - requires Oracle 23ai
    """Oracle Database 23ai AI Vector Search store."""

    def __init__(self, client, table: str = "ORAREM_DOC_CHUNKS", dim: int = 1024):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_$#]{0,127}", table):
            raise ValueError("invalid table name")
        self.c, self.table, self.dim = client, table.upper(), dim

    def create_schema(self) -> None:
        ddl = (f"CREATE TABLE {self.table} (chunk_id VARCHAR2(200) PRIMARY KEY, source VARCHAR2(400), "
               f"control_ids VARCHAR2(1000), meta CLOB, chunk_text CLOB, embedding VECTOR({self.dim}, FLOAT32))")
        with self.c.conn.cursor() as cur:
            try:
                cur.execute(ddl)
            except Exception as e:  # noqa: BLE001
                if "ORA-00955" not in str(e):
                    raise

    def add(self, chunks: list[Chunk], vectors: np.ndarray) -> None:
        rows = [{"id": ch.chunk_id, "src": ch.source, "cids": ",".join(ch.control_ids), "meta": json.dumps(ch.meta),
                 "txt": ch.text, "emb": array.array("f", map(float, v))} for ch, v in zip(chunks, vectors)]
        sql = (f"MERGE INTO {self.table} t USING (SELECT :id chunk_id FROM dual) s ON (t.chunk_id = s.chunk_id)\n"
               "WHEN MATCHED THEN UPDATE SET source = :src, control_ids = :cids, meta = :meta, chunk_text = :txt, "
               "embedding = :emb\nWHEN NOT MATCHED THEN INSERT (chunk_id, source, control_ids, meta, chunk_text, "
               "embedding) VALUES (:id, :src, :cids, :meta, :txt, :emb)")
        with self.c.conn.cursor() as cur:
            cur.executemany(sql, rows)
        self.c.conn.commit()

    def search(self, vector: np.ndarray, k: int) -> list[tuple[Chunk, float]]:
        sql = (f"SELECT chunk_id, source, control_ids, meta, chunk_text, "
               f"VECTOR_DISTANCE(embedding, :q, COSINE) AS dist FROM {self.table} "
               "ORDER BY dist FETCH FIRST :k ROWS ONLY")
        with self.c.conn.cursor() as cur:
            cur.execute(sql, {"q": array.array("f", map(float, vector.reshape(-1))), "k": int(k)})
            out = []
            for cid, src, cids, meta, txt, dist in cur.fetchall():
                text = txt.read() if hasattr(txt, "read") else txt
                m = meta.read() if hasattr(meta, "read") else meta
                out.append((Chunk(cid, src, text, (cids or "").split(",") if cids else [], json.loads(m or "{}")),
                            1.0 - float(dist)))
        return out


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(a @ b / (na * nb)) if na and nb else 0.0

