"""Builds a :class:`Pipeline` from configuration (simulated or live Oracle)."""

from __future__ import annotations

import platform
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config, credentials
from .context.assembler import ContextAssembler, ContextFlags
from .context.sources import OracleContextSource, SimulatedContextSource
from .controls import Catalog
from .llm.backends import make_backend
from .llm.generator import RemediationGenerator
from .pipeline import Pipeline, SimulatedSandboxProvider
from .rag.retriever import DocumentRetriever
from .rag.store import InMemoryVectorStore, make_embedder
from .scoring.policy import PolicyContext


def build_retriever(cfg: Config, client=None) -> DocumentRetriever | None:
    if not cfg.get("context.documentation"):
        return None
    emb = make_embedder(cfg.get("rag.embedder"), int(cfg.get("rag.embedding_dim")))
    store_kind = cfg.get("rag.store")
    if store_kind == "oracle23ai":
        from .db.oracle import OracleClient
        from .rag.store import Oracle23aiVectorStore
        vc = client or OracleClient(*credentials(cfg.get("rag.oracle")))
        store = Oracle23aiVectorStore(vc, cfg.get("rag.oracle.table"), emb.dim)
        return DocumentRetriever(emb, store, int(cfg.get("rag.top_k")))
    r = DocumentRetriever(emb, InMemoryVectorStore(), int(cfg.get("rag.top_k")))
    kdir = cfg.path("rag.knowledge_dir")
    if kdir and kdir.exists():
        r.ingest_dir(kdir, int(cfg.get("rag.chunk_chars")))
    return r


def build_pipeline(cfg: Config, *, eval_mode: bool = False, allow_apply: bool = False,
                   output_dir: str | None = None, sim_db=None) -> tuple[Pipeline, Any]:
    catalog = Catalog.load(cfg.path("catalog"))
    policy = PolicyContext.load(cfg.path("policy_file"))
    flags = ContextFlags.from_config(cfg)
    listeners = list(cfg.get("files.listeners") or ["LISTENER"])
    mode = cfg.get("sandbox.mode")
    target = None
    if mode == "simulated":
        from .sim.scenarios import build_database
        target = sim_db or build_database(cfg.get("sandbox.topology_profile", "single"))
        source = SimulatedContextSource(target)
        provider = SimulatedSandboxProvider(target, listeners)
    elif mode == "oracle":
        from .db.oracle import OracleClient
        from .db.shadow_pdb import OracleSandboxProvider
        t = cfg.get("target")
        target = OracleClient(*credentials(t), sysdba=bool(t.get("sysdba")))
        files = {"sqlnet_ora": cfg.get("files.sqlnet_ora"), "listener_ora": cfg.get("files.listener_ora")}
        source = OracleContextSource(target, cfg, files)
        provider = OracleSandboxProvider(cfg)
    else:
        raise ValueError(f"unknown sandbox.mode {mode!r} (simulated | oracle)")

    assembler = ContextAssembler(source, build_retriever(cfg), policy, flags)
    backend = make_backend(cfg)
    generator = RemediationGenerator(backend, k=int(cfg.get("self_consistency.k")),
                                     max_workers=int(cfg.get("llm.max_workers")), seed=int(cfg.get("seed")))
    meta = {
        "orarem_version": __version__, "python": platform.python_version(), "sandbox_mode": mode,
        "topology_profile": cfg.get("sandbox.topology_profile") if mode == "simulated" else "live",
        "backend": backend.name, "model": backend.model, "temperature": cfg.get("llm.temperature"),
        "temperature_policy": cfg.get("llm.temperature_policy"), "k": cfg.get("self_consistency.k"),
        "n_eval": cfg.get("evaluation.n"), "context_flags": flags.__dict__, "seed": cfg.get("seed"),
        "weights": cfg.get("scoring.weights"), "decision": cfg.get("decision"),
        "catalog": cfg.get("catalog"), "catalog_size": len(catalog),
    }
    pipe = Pipeline(catalog, assembler, generator, provider, policy, cfg.scoring_settings(), cfg.decision_settings(),
                    cfg.verifier_settings(), listeners=listeners, eval_mode=eval_mode,
                    n_eval=int(cfg.get("evaluation.n")), output_dir=output_dir or cfg.path("output_dir"),
                    prompt_dir=cfg.path("llm.prompt_dir") or (cfg.base_dir / "prompts"), run_meta=meta,
                    price_per_mtok=cfg.get("llm.price_per_mtok"))
    if allow_apply:
        from .apply import ProductionApplier
        pipe.applier = ProductionApplier(cfg, policy, Path(pipe.run_dir))
    return pipe, target
