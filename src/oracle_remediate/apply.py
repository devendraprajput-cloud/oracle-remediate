"""Production apply for AUTO-APPLY dispositions (paper Section III.D-2).

"AUTO-APPLY executes the remediation against production after a final
pre-flight invariant check."  Additional guard rails in this implementation:

* disabled unless BOTH ``apply.enabled: true`` in config AND ``--apply`` on the CLI
* optionally restricted to a change window from the policy file
* pre-flight: the violation must still exist (otherwise: already compliant, skip)
* post-flight: phi_c must return no rows; on failure the verified rollback is
  executed automatically (``apply.auto_rollback_on_failure``)
* every action is appended to ``apply_audit.jsonl`` in the run directory
* listener.ora / sqlnet.ora remediations are never applied automatically: the
  scripts are emitted for the operator (host access is outside the DB session)
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

from .config import Config, credentials
from .controls import Control
from .models import FindingOutcome
from .scoring.policy import PolicyContext
from .verify.sqltools import parse_script


class ProductionApplier:
    def __init__(self, cfg: Config, policy: PolicyContext, run_dir: Path, client_factory=None):
        self.cfg = cfg
        self.policy = policy
        self.run_dir = run_dir
        self._factory = client_factory

    def _client(self):
        if self._factory:
            return self._factory()
        from .db.oracle import OracleClient
        sec = self.cfg.get("apply")
        dsn, user, pwd = credentials(sec)
        return OracleClient(dsn, user, pwd, sysdba=bool(sec.get("sysdba")))

    def _log(self, rec: dict[str, Any]) -> None:
        rec["ts"] = dt.datetime.now().isoformat(timespec="seconds")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        with (self.run_dir / "apply_audit.jsonl").open("a") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")

    def apply(self, outcome: FindingOutcome, control: Control) -> dict[str, Any]:
        f = outcome.finding
        base = {"finding_id": f.finding_id, "control_id": control.id, "container": f.container}
        if not self.cfg.get("apply.enabled"):
            return self._ret(base, "skipped", "apply.enabled is false (dry run); scripts written to the run directory")
        if control.is_file_control:
            return self._ret(base, "skipped", "file-based remediation: apply the ORA_SET edits on the host manually")
        if self.cfg.get("apply.require_change_window") and not self.policy.in_change_window():
            return self._ret(base, "deferred", "outside the configured change window")
        cand = outcome.generation.plurality if outcome.generation else None
        if cand is None:
            return self._ret(base, "skipped", "no candidate")
        client = self._client()
        try:
            client.set_container(f.container)
            phi = control.invariant()
            pre = client.query(phi) if phi else None
            if pre is not None and not pre:
                return self._ret(base, "skipped", "pre-flight: violation no longer present (already compliant)")
            res = client.execute_statements(parse_script(cand.remediation_sql))
            post = client.query(phi) if phi else None
            ok = res.ok and (post is None or not post)
            if ok:
                return self._ret(base, "applied", "remediation applied; post-flight invariant satisfied",
                                 executed=res.executed)
            detail = {"errors": res.errors, "post_rows": len(post or [])}
            if self.cfg.get("apply.auto_rollback_on_failure"):
                rb = client.execute_statements(parse_script(cand.rollback_sql))
                detail["rollback"] = {"ok": rb.ok, "errors": rb.errors}
                return self._ret(base, "rolled_back", "post-flight failed; verified rollback executed", **detail)
            return self._ret(base, "failed", "post-flight failed; rollback NOT executed (disabled)", **detail)
        finally:
            client.close()

    def _ret(self, base: dict[str, Any], status: str, message: str, **extra) -> dict[str, Any]:
        rec = {**base, "status": status, "message": message, **extra}
        self._log(rec)
        return rec
