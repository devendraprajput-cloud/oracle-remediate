#!/usr/bin/env bash
# Bash + SQL*Plus audit route (paper Table II: "Audit framework: Bash + SQL*Plus + Python").
#
#   export ORAREM_SQLPLUS_CONNECT='/@sales_pdb_wallet_alias'    # prefer an Oracle wallet
#   audit/run_audit.sh SALES_PDB findings.csv
#
# The connect string is passed to SQL*Plus on stdin, never on the command line.
# File-based controls (listener.ora / sqlnet.ora) are audited by `orarem audit` on the host.
set -euo pipefail
: "${ORAREM_SQLPLUS_CONNECT:?set ORAREM_SQLPLUS_CONNECT (e.g. a wallet alias /@alias)}"
CONTAINER="${1:?container label, e.g. SALES_PDB}"
OUT="${2:-findings.csv}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

orarem catalog export-sql --out "$WORK/audit.sql"
sqlplus -S -L /nolog > "$WORK/spool.lst" <<SQL
CONNECT ${ORAREM_SQLPLUS_CONNECT}
@${WORK}/audit.sql
EXIT
SQL
orarem audit --from-spool "$WORK/spool.lst" --container "$CONTAINER" --out "$OUT"
