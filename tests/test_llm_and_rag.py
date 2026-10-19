import pytest

from oracle_remediate.llm.backends import LLMBackend, LLMResponse
from oracle_remediate.llm.generator import RemediationGenerator, extract_json, parse_candidate
from oracle_remediate.llm.prompt import GenerationRequest
from oracle_remediate.models import Finding
from oracle_remediate.rag.retriever import DocumentRetriever, build_query
from oracle_remediate.rag.store import HashingEmbedder


def test_extract_json_tolerates_fences_and_prose():
    assert extract_json('Here:\n```json\n{"a": 1}\n```')["a"] == 1
    assert extract_json('prefix {"remediation_sql": "x;"} suffix')["remediation_sql"] == "x;"
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_parse_candidate_list_fields():
    c = parse_candidate(LLMResponse('{"remediation_sql": ["REVOKE A FROM B"], "rollback_sql": "GRANT A TO B", '
                                    '"risk_level": "LOW"}'), 0)
    assert c.valid and c.risk_level == "low" and c.remediation_sql.endswith(";")


class Scripted(LLMBackend):
    name = "scripted"

    def __init__(self, outputs):
        super().__init__("scripted", temperature=0.3)
        self.outputs = outputs

    def _call(self, request, send_temperature, i, seed):
        return LLMResponse(self.outputs[i], temperature_applied=0.3)


def _req(catalog):
    c = catalog.get("ch6.public_exec_utl_tcp")
    return GenerationRequest(Finding(c.id), c, {}, "s", "u")


def test_plurality_and_agreement_counts_invalid_samples(catalog):
    good = '{"remediation_sql": "REVOKE EXECUTE ON SYS.UTL_TCP FROM PUBLIC;", "rollback_sql": "x", "risk_level": "low"}'
    fmt = '{"remediation_sql": "revoke  execute on sys.utl_tcp from public", "rollback_sql": "x", "risk_level": "low"}'
    other = '{"remediation_sql": "REVOKE EXECUTE ON SYS.UTL_TCP FROM SCOTT;", "rollback_sql": "x", "risk_level": "low"}'
    g = RemediationGenerator(Scripted([good, fmt, other, "garbage", good]), k=5, max_workers=1)
    r = g.generate(_req(catalog))
    assert r.plurality_count == 3 and r.agreement == pytest.approx(0.6)
    assert r.plurality.sample_index == 0 and r.temperature_applied == 0.3


class Rejecting(LLMBackend):
    name = "rejecting"

    def __init__(self):
        super().__init__("some-new-model", temperature=0.3, temperature_policy="auto")
        self.calls = []

    def _call(self, request, send_temperature, i, seed):
        self.calls.append(send_temperature)
        if send_temperature:
            raise RuntimeError("Error code: 400 - temperature is not supported for this model")
        return LLMResponse('{"remediation_sql": "x", "rollback_sql": "y", "risk_level": "low"}')


def test_temperature_auto_fallback_is_recorded(catalog):
    b = Rejecting()
    r = RemediationGenerator(b, k=2, max_workers=1).generate(_req(catalog))
    assert b.calls[:2] == [True, False] and b.calls[2] is False
    assert r.temperature_applied is None


def test_documented_models_never_receive_temperature():
    assert not LLMBackend("claude-opus-4-7")._send_temperature()
    assert not LLMBackend("gpt-5")._send_temperature()
    assert LLMBackend("meta-llama/Llama-3.3-70B-Instruct")._send_temperature()


def test_rag_retrieves_relevant_note(catalog):
    from pathlib import Path
    r = DocumentRetriever(HashingEmbedder(1024), top_k=3)
    n = r.ingest_dir(Path(__file__).resolve().parents[1] / "knowledge")
    assert n > 5
    c = catalog.get("ch4.no_public_db_links")
    hits = r.retrieve(c, Finding(c.id, c.title, "PUBLIC|REMOTE_SALES|salesdb"))
    assert hits[0]["source"] == "database_links.md"
    assert "ch4.no_public_db_links" in build_query(c, Finding(c.id))
