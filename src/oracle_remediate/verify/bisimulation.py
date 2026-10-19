"""Dictionary snapshots, deltas and AST-derived expected deltas (Layer 3, Section III.E-3).

A *snapshot* is ``dict[view_name, frozenset[tuple]]``.  Snapshot queries select
only stable columns (no timestamps, SCNs or audit ids), so the paper's
``normalize`` step happens by construction; ``normalize`` below additionally
drops columns matching volatile patterns for user-supplied views.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..controls import Control
from .sqltools import Statement

Snapshot = dict[str, frozenset]

# Statement kind -> dictionary views that kind may legitimately change.
EXPECTED_VIEWS: dict[str, set[str]] = {
    "GRANT": {"DBA_SYS_PRIVS", "DBA_TAB_PRIVS", "DBA_ROLE_PRIVS"},
    "REVOKE": {"DBA_SYS_PRIVS", "DBA_TAB_PRIVS", "DBA_ROLE_PRIVS"},
    "ALTER USER": {"DBA_USERS"},
    "CREATE ROLE": {"DBA_ROLES", "DBA_ROLE_PRIVS"},  # creator receives the role WITH ADMIN OPTION
    "DROP ROLE": {"DBA_ROLES", "DBA_ROLE_PRIVS", "DBA_SYS_PRIVS", "DBA_TAB_PRIVS"},
    "ALTER PROFILE": {"DBA_PROFILES"},
    "CREATE PROFILE": {"DBA_PROFILES"},
    "DROP PROFILE": {"DBA_PROFILES", "DBA_USERS"},
    "ALTER SYSTEM": {"V$PARAMETER", "V$SPPARAMETER"},
    "CREATE AUDIT POLICY": {"AUDIT_UNIFIED_POLICIES"},
    "ALTER AUDIT POLICY": {"AUDIT_UNIFIED_POLICIES"},
    "DROP AUDIT POLICY": {"AUDIT_UNIFIED_POLICIES", "AUDIT_UNIFIED_ENABLED_POLICIES"},
    "AUDIT": {"AUDIT_UNIFIED_ENABLED_POLICIES"},
    "NOAUDIT": {"AUDIT_UNIFIED_ENABLED_POLICIES"},
    "CREATE DATABASE LINK": {"DBA_DB_LINKS", "SYS.LINK$"},
    "DROP DATABASE LINK": {"DBA_DB_LINKS", "SYS.LINK$"},
}

VOLATILE_COLUMN = re.compile(r"(TIME|DATE|SCN|_TS$|^TS_|LAST_LOGIN|SEQUENCE#|AUDIT_ID|SESSIONID|ENTRY_ID)",
                             re.IGNORECASE)


def expected_views(stmts: list[Statement], control: Control) -> set[str]:
    """Expected delta derived from the remediation's AST (only whitelisted kinds count)."""
    exp: set[str] = set(v.upper() for v in control.expected_tables_extra)
    for st in stmts:
        if st.kind in ("ORA_SET", "ORA_UNSET"):
            exp.add(f"FILE:{(st.attrs.get('file') or '').lower()}")
        else:
            exp |= EXPECTED_VIEWS.get(st.kind, set())
    return exp


@dataclass
class Delta:
    changed: dict[str, dict[str, list]] = field(default_factory=dict)

    @property
    def views(self) -> set[str]:
        return set(self.changed)

    def subset_of(self, expected: set[str]) -> bool:
        return self.views <= {e.upper() if not e.startswith("FILE:") else e for e in expected}

    @property
    def empty(self) -> bool:
        return not self.changed

    def to_dict(self, limit: int = 20) -> dict:
        return {v: {"added": d["added"][:limit], "removed": d["removed"][:limit]} for v, d in self.changed.items()}


def diff(a: Snapshot, b: Snapshot) -> Delta:
    d = Delta()
    for view in sorted(set(a) | set(b)):
        ra, rb = a.get(view, frozenset()), b.get(view, frozenset())
        if ra != rb:
            d.changed[view] = {
                "added": sorted(map(_row_str, rb - ra)),
                "removed": sorted(map(_row_str, ra - rb)),
            }
    return d


def _row_str(r) -> str:
    return "|".join("" if v is None else str(v) for v in (r if isinstance(r, tuple) else (r,)))


def normalize(rows: list[tuple], columns: list[str]) -> frozenset:
    keep = [i for i, c in enumerate(columns) if not VOLATILE_COLUMN.search(c)]
    return frozenset(tuple(r[i] for i in keep) for r in rows)
