from __future__ import annotations

from pathlib import Path

import pytest

from oracle_remediate.config import Config
from oracle_remediate.controls import Catalog
from oracle_remediate.sim.scenarios import build_database

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def catalog() -> Catalog:
    return Catalog.load(ROOT / "controls" / "catalog.yaml")


@pytest.fixture()
def db():
    return build_database("single")


@pytest.fixture()
def cfg_factory(tmp_path):
    def make(**over) -> Config:
        base = {"output_dir": str(tmp_path / "runs"),
                "llm": {"backend": "mock", "mock": {"p_variant": 0.0, "p_wrong": 0.0, "p_unsafe": 0.0}},
                "sandbox": {"mode": "simulated", "topology_profile": "single"}}
        for k, v in over.items():
            base[k] = {**base.get(k, {}), **v} if isinstance(v, dict) else v
        return Config.load(ROOT / "config" / "default.yaml", base)
    return make
