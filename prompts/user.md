## Finding
$finding_json

## Control
- id: $control_id
- CIS id: $cis_id
- title: $control_title
- control class: $control_class
- allowed statement types (remediation): $allowed_remediation
- allowed statement types (rollback): $allowed_rollback
- machine-checkable invariant (returns rows iff NON-compliant):
```sql
$invariant
```
- notes: $control_notes

## Topology context
$topology_json

## Dependency context
$dependency_json

## Documentation context (retrieved)
$documentation_text

## Policy context
$policy_json

## Output schema (respond with exactly one JSON object)
```json
{
  "remediation_sql": "string: statements separated by ';' and newlines",
  "rollback_sql": "string: statements that restore the exact pre-remediation state",
  "verification_sql": "string: one SELECT returning no rows iff compliant",
  "prerequisites": ["string"],
  "risk_level": "low | medium | high",
  "assumptions": ["string"],
  "rationale": "string: short explanation for the reviewing DBA"
}
```
