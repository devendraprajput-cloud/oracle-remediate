"""Configuration loading.  Built-in defaults are deep-merged with a YAML file.

Secrets are never stored in configuration: every credential is referenced by
the *name* of an environment variable (``*_env`` keys).
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

from .scoring.confidence import ScoringSettings, Weights
from .scoring.policy import DecisionSettings, Thresholds
from .verify.verifier import VerifierSettings

DEFAULTS: dict[str, Any] = {
    "catalog": "controls/catalog.yaml",
    "policy_file": "config/policy.example.yaml",
    "output_dir": "runs",
    "seed": 7,
    "target": {
        "dsn_env": "ORAREM_TARGET_DSN",
        "user_env": "ORAREM_AUDIT_USER",
        "password_env": "ORAREM_AUDIT_PASSWORD",
        "sysdba": False,
        "containers": [],
    },
    "files": {"sqlnet_ora": None, "listener_ora": None, "listeners": ["LISTENER"]},
    "context": {
        "topology": True,
        "dependency": True,
        "documentation": True,
        "policy": True,
        "awr": {"enabled": False, "window_hours": 24},
        "top_sql_limit": 20,
        "max_rows_per_query": 50,
    },
    "rag": {
        "store": "memory",
        "top_k": 5,
        "embedder": "hashing",
        "embedding_dim": 1024,
        "knowledge_dir": "knowledge",
        "chunk_chars": 1200,
        "oracle": {
            "dsn_env": "ORAREM_VECTOR_DSN",
            "user_env": "ORAREM_VECTOR_USER",
            "password_env": "ORAREM_VECTOR_PASSWORD",
            "table": "ORAREM_DOC_CHUNKS",
        },
    },
    "llm": {
        "backend": "mock",
        "model": "mock-remediator",
        "temperature": 0.3,
        "temperature_policy": "auto",
        "max_tokens": 4096,
        "base_url": None,
        "api_key_env": None,
        "max_workers": 5,
        "timeout_s": 120,
        "effort": None,
        "price_per_mtok": {"input": None, "output": None},
        "mock": {"p_variant": 0.15, "p_wrong": 0.10, "p_unsafe": 0.05, "context_aware": True},
    },
    "self_consistency": {"k": 5},
    "evaluation": {"n": 10, "verify_all_candidates": False},
    "verifier": {"non_interference_sample": 8, "never_execute_l1_failures": True},
    "sandbox": {
        "mode": "simulated",
        "topology_profile": "single",
        "admin_dsn_env": "ORAREM_SANDBOX_ADMIN_DSN",
        "admin_user_env": "ORAREM_SANDBOX_ADMIN_USER",
        "admin_password_env": "ORAREM_SANDBOX_ADMIN_PASSWORD",
        "admin_sysdba": False,
        "cdb_sandbox": {"dsn_env": "ORAREM_CDB_SANDBOX_DSN", "user_env": "ORAREM_CDB_SANDBOX_USER",
                        "password_env": "ORAREM_CDB_SANDBOX_PASSWORD", "sysdba": False},
        "exadata": "auto",
        "clone_sql": "CREATE PLUGGABLE DATABASE {shadow} FROM {source} {clause}",
        "clone_clause_exadata": "SNAPSHOT COPY",
        "clone_clause_default": "",
        "open_sql": "ALTER PLUGGABLE DATABASE {shadow} OPEN",
        "close_sql": "ALTER PLUGGABLE DATABASE {shadow} CLOSE IMMEDIATE",
        "drop_sql": "DROP PLUGGABLE DATABASE {shadow} INCLUDING DATAFILES",
        "snapshot_views_file": "config/snapshot_views.yaml",
    },
    "scoring": {"weights": {"A": 0.40, "V": 0.30, "RB": 0.20, "R": 0.10},
                "risk_map": {"low": 1.0, "medium": 0.6, "high": 0.3}},
    "decision": {"tau_auto": 0.85, "tau_review": 0.55, "hard_floor_layers": ["L3", "L_RB"],
                 "strict_auto_apply": True},
    "apply": {
        "enabled": False,
        "require_change_window": True,
        "auto_rollback_on_failure": True,
        "dsn_env": "ORAREM_APPLY_DSN",
        "user_env": "ORAREM_APPLY_USER",
        "password_env": "ORAREM_APPLY_PASSWORD",
        "sysdba": False,
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data: dict[str, Any], base_dir: Path | None = None):
        self.data = data
        self.base_dir = base_dir or Path.cwd()

    @classmethod
    def load(cls, path: str | Path | list | None = None, overrides: dict | None = None) -> Config:
        """Load defaults, then each YAML file in order (later files override earlier ones)."""
        data = copy.deepcopy(DEFAULTS)
        base = Path.cwd()
        paths = [path] if isinstance(path, (str, Path)) else list(path or [])
        for item in paths:
            p = Path(item)
            data = deep_merge(data, yaml.safe_load(p.read_text()) or {})
            base = _find_root(p.resolve().parent)
        if overrides:
            data = deep_merge(data, overrides)
        return cls(data, base)

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def path(self, dotted: str) -> Path | None:
        v = self.get(dotted)
        if not v:
            return None
        p = Path(v)
        return p if p.is_absolute() else (self.base_dir / p)

    # ------------------------------------------------------------------ typed views
    def scoring_settings(self) -> ScoringSettings:
        w = self.get("scoring.weights")
        s = ScoringSettings(Weights(w["A"], w["V"], w["RB"], w["R"]), dict(self.get("scoring.risk_map")))
        s.weights.validate()
        return s

    def decision_settings(self) -> DecisionSettings:
        d = self.get("decision")
        return DecisionSettings(Thresholds(d["tau_auto"], d["tau_review"]), list(d["hard_floor_layers"]),
                                bool(d["strict_auto_apply"]))

    def verifier_settings(self) -> VerifierSettings:
        v = self.get("verifier")
        return VerifierSettings(int(v["non_interference_sample"]), bool(v["never_execute_l1_failures"]),
                                int(self.get("seed")))


def _find_root(start: Path) -> Path:
    """Relative paths in a config resolve against the project root (dir holding controls/)."""
    for d in (start, *start.parents):
        if (d / "controls" / "catalog.yaml").exists():
            return d
    return Path.cwd()


def credentials(cfg_section: dict[str, Any], dsn_key: str = "dsn_env", user_key: str = "user_env",
                pwd_key: str = "password_env") -> tuple[str, str, str]:
    """Resolve (dsn, user, password) from environment variables named in config."""
    missing = [cfg_section.get(k) for k in (dsn_key, user_key, pwd_key) if not os.environ.get(cfg_section.get(k) or "")]
    if missing:
        raise RuntimeError(f"missing environment variables: {', '.join(m for m in missing if m)}")
    return (os.environ[cfg_section[dsn_key]], os.environ[cfg_section[user_key]], os.environ[cfg_section[pwd_key]])
