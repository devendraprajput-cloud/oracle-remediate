import json

from oracle_remediate.audit.auditor import SimulatedAuditTarget, run_audit
from oracle_remediate.factory import build_pipeline
from oracle_remediate.ingestion.findings import read_findings, write_findings
from oracle_remediate.models import Disposition


def _run(cfg, only=None, eval_mode=False):
    pipe, db = build_pipeline(cfg, eval_mode=eval_mode)
    findings = run_audit(pipe.catalog, SimulatedAuditTarget(db))
    if only:
        findings = [f for f in findings if f.control_id in only]
    return pipe, [pipe.process(f) for f in findings]


def test_paper_example_control_4_7_is_rejected_by_hard_floor(cfg_factory):
    _, outs = _run(cfg_factory(), only={"ch4.no_public_db_links"})
    o = outs[0]
    assert o.decision.disposition is Disposition.REJECT
    assert o.rollback.L_RB.passed == 0
    assert "L_RB" in o.decision.hard_floor


def test_dependency_context_changes_the_outcome(cfg_factory):
    _, full = _run(cfg_factory(), only={"ch6.public_exec_utl_file"})
    _, nodep = _run(cfg_factory(context={"dependency": False}), only={"ch6.public_exec_utl_file"})
    assert full[0].decision.disposition is Disposition.AUTO_APPLY
    assert nodep[0].decision.disposition is Disposition.REJECT
    assert nodep[0].verifier.L3.passed == 0


def test_out_of_scope_and_review_only(cfg_factory):
    _, outs = _run(cfg_factory(), only={"ch4.no_default_passwords", "ch5.audit_grant", "ch1.patch_level"})
    by = {o.finding.control_id: o for o in outs}
    assert by["ch4.no_default_passwords"].status == "out_of_scope"
    assert by["ch1.patch_level"].decision.disposition is Disposition.MANUAL_REVIEW
    assert by["ch5.audit_grant"].decision.disposition is Disposition.MANUAL_REVIEW
    assert by["ch5.audit_grant"].decision.overrides


def test_policy_exception_on_rac(cfg_factory):
    _, outs = _run(cfg_factory(sandbox={"topology_profile": "rac2"}), only={"ch2.remote_listener"})
    assert outs[0].status == "excepted"


def test_static_parameter_goes_to_review(cfg_factory):
    _, outs = _run(cfg_factory(), only={"ch2.audit_sys_operations"})
    o = outs[0]
    assert o.verifier.L2.passed == 0 and o.decision.disposition is Disposition.MANUAL_REVIEW


def test_full_run_writes_artifacts(cfg_factory, tmp_path):
    cfg = cfg_factory()
    pipe, db = build_pipeline(cfg)
    findings = run_audit(pipe.catalog, SimulatedAuditTarget(db))
    write_findings(findings, tmp_path / "f.csv")
    again = read_findings(tmp_path / "f.csv")
    assert [f.finding_id for f in again] == [f.finding_id for f in findings]
    summary = pipe.run(again)
    run = json.loads((pipe.run_dir / "run.json").read_text())
    assert summary["findings"] == len(findings) == len(run["outcomes"])
    assert (pipe.run_dir / "summary.md").exists() and (pipe.run_dir / "dispositions.csv").exists()
    auto = [o for o in run["outcomes"] if o["decision"]["disposition"] == "AUTO-APPLY"]
    assert auto, "expected some AUTO-APPLY outcomes on the seeded scenario"
    fdir = pipe.run_dir / "findings"
    assert any((d / "rollback.sql").exists() for d in fdir.iterdir())


def test_eval_mode_records_candidate_evaluations(cfg_factory):
    cfg = cfg_factory(llm={"backend": "mock", "mock": {"p_variant": 0.2, "p_wrong": 0.2, "p_unsafe": 0.1}})
    _, outs = _run(cfg, only={"ch6.public_exec_utl_tcp", "ch2.global_names"}, eval_mode=True)
    for o in outs:
        assert len(o.candidate_evaluations) == 10
        assert 0 < o.generation.agreement <= 1


def test_apply_is_dry_run_by_default(cfg_factory):
    cfg = cfg_factory()
    pipe, db = build_pipeline(cfg, allow_apply=True)
    f = [x for x in run_audit(pipe.catalog, SimulatedAuditTarget(db)) if x.control_id == "ch2.global_names"][0]
    o = pipe.process(f)
    assert o.decision.disposition is Disposition.AUTO_APPLY
    assert o.apply_result["status"] == "skipped"


def test_verifier_crash_is_recorded_as_failure_not_pass(cfg_factory):
    from oracle_remediate.verify.sandbox import Sandbox

    class Boom(Sandbox):
        def evaluate_invariant(self, control):
            raise RuntimeError("ORA-00942: table or view does not exist")

        def snapshot(self):
            return {}

        def execute(self, statements):
            raise AssertionError("unreachable")

    class Provider:
        def open(self, control, container, context):
            return Boom()

    pipe, db = build_pipeline(cfg_factory())
    pipe.sandboxes = Provider()
    f = [x for x in run_audit(pipe.catalog, SimulatedAuditTarget(db)) if x.control_id == "ch2.global_names"][0]
    o = pipe.process(f)
    assert o.decision.disposition is Disposition.REJECT
    assert "ORA-00942" in o.verifier.L2.detail
