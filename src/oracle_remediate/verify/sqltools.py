"""Oracle-dialect lexer, statement splitter, classifier and canonicaliser.

This is the parser behind Layer 1 (paper Section III.E-1) and behind the
self-consistency agreement signal A (Section III.D-1), which compares
*canonicalised* remediations "up to whitespace and comment normalisation".

Design notes
------------
* The paper names an ANTLR4 Oracle PL/SQL grammar.  Layer 1 only needs the
  *statement type* of each statement plus a few structural facts (privilege
  lists, grantees, parameter names), so this module implements a small,
  dependency-free lexer with that precision.  An ANTLR adapter can be plugged
  in through :class:`StatementParser` (see ``docs/DESIGN_NOTES.md``).
* Anonymous PL/SQL blocks, stored-program DDL, ``EXECUTE``/``CALL`` and
  SQL*Plus host commands are classified as ``PLSQL_BLOCK`` / ``HOST`` and are
  never split internally.  They are not statically verifiable (dynamic SQL),
  so Layer 1 treats them as forbidden.
* File-based controls (listener.ora / sqlnet.ora) use two pseudo statements,
  ``ORA_SET <file> <KEY> = <VALUE>`` and ``ORA_UNSET <file> <KEY>``, so the
  LLM never emits shell commands.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- tokens
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$#]*")


@dataclass(frozen=True)
class Token:
    kind: str  # WORD | QIDENT | STRING | NUMBER | PUNCT
    text: str

    @property
    def upper(self) -> str:
        return self.text.upper() if self.kind == "WORD" else self.text


def strip_comments(sql: str) -> str:
    """Remove ``--`` and ``/* */`` comments that are outside quoted text."""
    out: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c in ("'", '"'):
            j = _scan_quoted(sql, i)
            out.append(sql[i:j])
            i = j
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _scan_quoted(s: str, i: int) -> int:
    """Return index just after the quoted token starting at ``i`` ('' / "" escapes)."""
    q = s[i]
    j = i + 1
    while j < len(s):
        if s[j] == q:
            if j + 1 < len(s) and s[j + 1] == q:
                j += 2
                continue
            return j + 1
        j += 1
    return len(s)


def tokenize(stmt: str) -> list[Token]:
    toks: list[Token] = []
    i, n = 0, len(stmt)
    while i < n:
        c = stmt[i]
        if c.isspace():
            i += 1
        elif c == "'":
            j = _scan_quoted(stmt, i)
            toks.append(Token("STRING", stmt[i:j]))
            i = j
        elif c == '"':
            j = _scan_quoted(stmt, i)
            toks.append(Token("QIDENT", stmt[i:j]))
            i = j
        elif c.isdigit():
            m = re.match(r"\d+(\.\d+)?", stmt[i:])
            assert m
            toks.append(Token("NUMBER", m.group(0)))
            i += len(m.group(0))
        else:
            m = _WORD.match(stmt, i)
            if m:
                toks.append(Token("WORD", m.group(0)))
                i = m.end()
            else:
                toks.append(Token("PUNCT", c))
                i += 1
    return toks


# --------------------------------------------------------------------------- splitting
_PLSQL_START = re.compile(
    r"^\s*(BEGIN|DECLARE|CREATE\s+(OR\s+REPLACE\s+)?(EDITIONABLE\s+|NONEDITIONABLE\s+)?"
    r"(PROCEDURE|FUNCTION|PACKAGE|TRIGGER|TYPE|LIBRARY|JAVA))\b",
    re.IGNORECASE,
)
_HOST_START = re.compile(r"^\s*(!|HOST\b|\$)", re.IGNORECASE)
_EXEC_START = re.compile(r"^\s*(EXEC|EXECUTE|CALL)\b", re.IGNORECASE)


def split_statements(sql: str) -> list[str]:
    """Split a script into statements on ``;`` outside quotes.

    A PL/SQL block swallows the rest of the script up to a line containing only
    ``/`` (SQL*Plus terminator) because its internal ``;`` are not separators.
    """
    text = strip_comments(sql or "")
    stmts: list[str] = []
    buf: list[str] = []
    i, n = 0, len(text)

    def flush() -> None:
        s = "".join(buf).strip()
        if s and s != "/":
            stmts.append(s)
        buf.clear()

    while i < n:
        if not "".join(buf).strip():
            rest = text[i:]
            if _PLSQL_START.match(rest):
                m = re.search(r"^\s*/\s*$", rest, re.MULTILINE)
                end = i + (m.start() if m else len(rest))
                stmts.append(text[i:end].strip())
                i = end + (len(m.group(0)) if m else 0)
                continue
            line_end = text.find("\n", i)
            line = text[i: n if line_end < 0 else line_end]
            if _HOST_START.match(line) or line.strip().upper().startswith(("ORA_SET", "ORA_UNSET")):
                # one statement per line for host commands and ORA_* pseudo statements
                stmts.append(line.strip().rstrip(";").strip())
                i = n if line_end < 0 else line_end + 1
                continue
        c = text[i]
        if c in ("'", '"'):
            j = _scan_quoted(text, i)
            buf.append(text[i:j])
            i = j
        elif c == ";":
            flush()
            i += 1
        elif c == "/" and _is_slash_line(text, i):
            flush()
            i += 1
        else:
            buf.append(c)
            i += 1
    flush()
    return [s for s in stmts if s]


def _is_slash_line(text: str, i: int) -> bool:
    ls = text.rfind("\n", 0, i) + 1
    le = text.find("\n", i)
    le = len(text) if le < 0 else le
    return text[ls:le].strip() == "/"


# --------------------------------------------------------------------------- classification
@dataclass
class Statement:
    text: str
    kind: str
    tokens: list[Token] = field(default_factory=list)
    attrs: dict = field(default_factory=dict)

    @property
    def words(self) -> list[str]:
        return [t.upper for t in self.tokens]


# Multi-word statement kinds, longest prefixes first (order matters).
_KIND_PREFIXES: list[tuple[tuple[str, ...], str]] = [
    (("CREATE", "AUDIT", "POLICY"), "CREATE AUDIT POLICY"),
    (("ALTER", "AUDIT", "POLICY"), "ALTER AUDIT POLICY"),
    (("DROP", "AUDIT", "POLICY"), "DROP AUDIT POLICY"),
    (("CREATE", "PUBLIC", "DATABASE", "LINK"), "CREATE DATABASE LINK"),
    (("CREATE", "SHARED", "PUBLIC", "DATABASE", "LINK"), "CREATE DATABASE LINK"),
    (("CREATE", "SHARED", "DATABASE", "LINK"), "CREATE DATABASE LINK"),
    (("CREATE", "DATABASE", "LINK"), "CREATE DATABASE LINK"),
    (("DROP", "PUBLIC", "DATABASE", "LINK"), "DROP DATABASE LINK"),
    (("DROP", "DATABASE", "LINK"), "DROP DATABASE LINK"),
    (("ALTER", "PLUGGABLE", "DATABASE"), "ALTER PLUGGABLE DATABASE"),
    (("CREATE", "PLUGGABLE", "DATABASE"), "CREATE PLUGGABLE DATABASE"),
    (("DROP", "PLUGGABLE", "DATABASE"), "DROP PLUGGABLE DATABASE"),
    (("ALTER", "DATABASE"), "ALTER DATABASE"),
    (("DROP", "TABLESPACE"), "DROP TABLESPACE"),
    (("ALTER", "TABLESPACE"), "ALTER TABLESPACE"),
    (("ALTER", "USER"), "ALTER USER"),
    (("CREATE", "USER"), "CREATE USER"),
    (("DROP", "USER"), "DROP USER"),
    (("CREATE", "ROLE"), "CREATE ROLE"),
    (("ALTER", "ROLE"), "ALTER ROLE"),
    (("DROP", "ROLE"), "DROP ROLE"),
    (("ALTER", "PROFILE"), "ALTER PROFILE"),
    (("CREATE", "PROFILE"), "CREATE PROFILE"),
    (("DROP", "PROFILE"), "DROP PROFILE"),
    (("ALTER", "SESSION"), "ALTER SESSION"),
    (("DROP", "TABLE"), "DROP TABLE"),
    (("TRUNCATE",), "TRUNCATE"),
    (("SHUTDOWN",), "SHUTDOWN"),
    (("STARTUP",), "STARTUP"),
    (("GRANT",), "GRANT"),
    (("REVOKE",), "REVOKE"),
    (("NOAUDIT",), "NOAUDIT"),
    (("AUDIT",), "AUDIT"),
    (("SELECT",), "SELECT"),
    (("WITH",), "SELECT"),
    (("INSERT",), "DML"),
    (("UPDATE",), "DML"),
    (("DELETE",), "DML"),
    (("MERGE",), "DML"),
    (("ORA_SET",), "ORA_SET"),
    (("ORA_UNSET",), "ORA_UNSET"),
]


def classify(stmt: str) -> Statement:
    s = stmt.strip().rstrip(";").strip()
    if _PLSQL_START.match(s) or _EXEC_START.match(s):
        return Statement(s, "PLSQL_BLOCK")
    if _HOST_START.match(s):
        return Statement(s, "HOST")
    toks = tokenize(s)
    words = [t.upper for t in toks]
    kind = "UNKNOWN"
    for prefix, k in _KIND_PREFIXES:
        if tuple(words[: len(prefix)]) == prefix:
            kind = k
            break
    if kind == "UNKNOWN" and words[:1] == ["DROP"]:
        kind = "DROP " + (words[1] if len(words) > 1 else "")
    st = Statement(s, kind, toks)
    if kind == "UNKNOWN" and words[:2] == ["ALTER", "SYSTEM"]:
        st.kind = _classify_alter_system(st)
    if kind in ("CREATE DATABASE LINK", "DROP DATABASE LINK"):
        st.attrs["public"] = "PUBLIC" in words[:4]
    if words[:2] == ["ALTER", "SYSTEM"]:
        _parse_alter_system(st)
    if kind in ("GRANT", "REVOKE"):
        st.attrs.update(parse_grant(st))
    if kind == "ALTER USER":
        st.attrs["changes_password"] = "IDENTIFIED" in words
    if kind in ("ORA_SET", "ORA_UNSET"):
        st.attrs.update(parse_ora_stmt(s))
    return st


def _classify_alter_system(st: Statement) -> str:
    w = st.words
    if len(w) > 2 and w[2] in ("SET", "RESET"):
        return "ALTER SYSTEM"
    return "ALTER SYSTEM OTHER"  # KILL SESSION, FLUSH, SWITCH LOGFILE, CHECKPOINT ...


def _parse_alter_system(st: Statement) -> None:
    """Extract ``name``/``value``/``scope``/``sid`` from ALTER SYSTEM SET|RESET."""
    toks = st.tokens
    w = st.words
    if len(w) < 4 or w[2] not in ("SET", "RESET"):
        return
    st.attrs["action"] = w[2]
    name_tok = toks[3]
    st.attrs["parameter"] = (name_tok.text.strip('"') if name_tok.kind == "QIDENT" else name_tok.text).lower()
    if w[2] == "SET":
        # value = tokens after '=' up to SCOPE/SID/COMMENT/CONTAINER/DEFERRED
        try:
            eq = next(i for i, t in enumerate(toks) if t.kind == "PUNCT" and t.text == "=")
        except StopIteration:
            return
        stop = {"SCOPE", "SID", "COMMENT", "CONTAINER", "DEFERRED"}
        vals: list[Token] = []
        for t in toks[eq + 1:]:
            if t.kind == "WORD" and t.upper in stop:
                break
            vals.append(t)
        st.attrs["value"] = _join_tokens(vals)
    for key in ("SCOPE", "SID", "CONTAINER"):
        if key in w:
            i = w.index(key)
            if i + 2 < len(toks) and toks[i + 1].text == "=":
                st.attrs[key.lower()] = toks[i + 2].text.strip("'\"").upper()


def parse_grant(st: Statement) -> dict:
    """Parse ``GRANT p[,p] [ON obj] TO g[,g] [WITH ...]`` / ``REVOKE ... FROM ...``."""
    toks = st.tokens
    w = st.words
    kw = "TO" if st.kind == "GRANT" else "FROM"
    if kw not in w:
        return {"privileges": [], "object": None, "grantees": [], "options": []}
    k_idx = w.index(kw)
    on_idx = w.index("ON") if "ON" in w[:k_idx] else None
    priv_toks = toks[1: on_idx if on_idx is not None else k_idx]
    privileges = [p.strip().upper() for p in _join_tokens(priv_toks).split(",") if p.strip()]
    obj = None
    if on_idx is not None:
        obj = _join_tokens(toks[on_idx + 1: k_idx]).replace('"', "").upper()
        if obj.startswith("DIRECTORY ") or obj.startswith("JAVA "):
            obj = obj  # kept verbatim
    rest = toks[k_idx + 1:]
    grantee_toks: list[Token] = []
    options: list[str] = []
    for i, t in enumerate(rest):
        if t.kind == "WORD" and t.upper in ("WITH", "CONTAINER", "IDENTIFIED", "CASCADE", "FORCE"):
            options = [x.upper for x in rest[i:]]
            break
        grantee_toks.append(t)
    grantees = [g.strip().replace('"', "").upper() for g in _join_tokens(grantee_toks).split(",") if g.strip()]
    return {"privileges": privileges, "object": obj, "grantees": grantees, "options": options}


def parse_ora_stmt(s: str) -> dict:
    """``ORA_SET sqlnet.ora KEY = VALUE`` or ``ORA_UNSET listener.ora KEY``."""
    m = re.match(r"^\s*(ORA_SET|ORA_UNSET)\s+(\S+)\s+([A-Za-z0-9_.$#]+)\s*(=\s*(.*))?$", s, re.IGNORECASE | re.S)
    if not m:
        return {"file": None, "key": None, "value": None, "malformed": True}
    return {
        "file": m.group(2).lower(),
        "key": m.group(3).upper(),
        "value": (m.group(5) or "").strip() if m.group(1).upper() == "ORA_SET" else None,
    }


def _join_tokens(toks: list[Token]) -> str:
    out = ""
    for t in toks:
        txt = t.upper if t.kind == "WORD" else t.text
        if not out:
            out = txt
        elif t.kind == "PUNCT" and t.text in ",).=" or out.endswith(("(", ".", "=")):
            out += txt
        else:
            out += " " + txt
    return out


def parse_script(sql: str) -> list[Statement]:
    return [classify(s) for s in split_statements(sql)]


# --------------------------------------------------------------------------- canonical form
def canonicalize(sql: str) -> str:
    """Canonical form used for self-consistency voting (Section III.D-1).

    Keywords/identifiers are upper-cased, simple quoted identifiers are
    unquoted, whitespace and comments are removed; string literals keep their
    case.  Statement order is preserved because it can be semantically
    significant (e.g. ``GRANT`` to a dependent schema before ``REVOKE`` from
    ``PUBLIC``).
    """
    stmts = split_statements(sql)
    out = []
    for s in stmts:
        st = classify(s)
        if st.kind in ("PLSQL_BLOCK", "HOST"):
            out.append(re.sub(r"\s+", " ", s.strip()).upper())
            continue
        if st.kind in ("ORA_SET", "ORA_UNSET"):
            a = st.attrs
            val = re.sub(r"\s+", "", a.get("value") or "").upper()
            out.append(f"{st.kind} {a.get('file')} {a.get('key')}" + (f"={val}" if st.kind == "ORA_SET" else ""))
            continue
        norm: list[Token] = []
        for t in st.tokens:
            if t.kind == "QIDENT" and re.fullmatch(r'"[A-Z][A-Z0-9_$#]*"', t.text):
                norm.append(Token("WORD", t.text.strip('"')))
            else:
                norm.append(t)
        out.append(_join_tokens(norm))
    return ";\n".join(out)
