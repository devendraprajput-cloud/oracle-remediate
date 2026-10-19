from oracle_remediate.cli import main
from oracle_remediate.controls import build_invariant_sql


def test_catalog_integrity(catalog):
    comp = catalog.completeness()
    assert comp["controls_in_catalog"] == len(catalog) >= 70
    assert catalog.get("4.7").id == "ch4.no_public_db_links"  # lookup by CIS id from the paper
    for c in catalog:
        sql = build_invariant_sql(c)
        if c.kind not in ("ora_file", "manual"):
            assert sql and sql.lstrip().upper().startswith(("SELECT", "WITH")), c.id


def test_cli_catalog_and_export(tmp_path, capsys):
    assert main(["catalog", "validate"]) == 0
    out = tmp_path / "audit.sql"
    assert main(["catalog", "export-sql", "--out", str(out)]) == 0
    text = out.read_text()
    assert "SET COLSEP '|'" in text and "'ch4.no_public_db_links' AS control_id" in text


def test_cli_demo_runs(tmp_path, capsys):
    assert main(["demo", "--no-noise", "--out", str(tmp_path)]) == 0
    assert "AUTO-APPLY" in capsys.readouterr().out
