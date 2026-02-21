# UMCS Gap Analysis Report

- Generated date: 2026-02-21
- Scope: Derived observed space from `cross-mutation-graph.html` plus `mutation-classification-template.csv`
- Constraint: Existing documents unchanged; analysis exported as new artifacts only

## 1. Coverage Snapshot

- Valid combo space: **6363**
- Observed combo space: **19**
- Total coverage ratio: **0.0030**
- Total gap ratio: **0.9970**

## 2. Top-20 High-Risk Missing Cells

| Rank | RC | Target | Operator | Discrepancy | Role | Impact | Gap Score | Prefix Coverage |
|---|---|---|---|---|---|---|---:|---:|
| 1 | RC3 | STATE_TRANSITION | REPLAY | VALIDATION_GAP | SINK | ATO | 315.90 | 0.0000 |
| 2 | RC1 | PARSER_CONTEXT | STRUCTURAL_REWRITE | CONTROL_EVASION | SINK | RCE | 315.90 | 0.0000 |
| 3 | RC1 | NAMESPACE | STRUCTURAL_REWRITE | CONTROL_EVASION | SINK | RCE | 315.90 | 0.0000 |
| 4 | RC3 | CRYPTO_PARAMETER | REPLAY | AUTH_BINDING_GAP | SINK | ATO | 315.90 | 0.0000 |
| 5 | RC1 | PAYLOAD_BODY | STRUCTURAL_REWRITE | CONTROL_EVASION | SINK | RCE | 315.90 | 0.0000 |
| 6 | RC3 | TOKEN | REPLAY | AUTH_BINDING_GAP | SINK | ATO | 315.90 | 0.0000 |
| 7 | RC3 | CRYPTO_PARAMETER | KEY_SUBSTITUTION | AUTH_BINDING_GAP | SINK | ATO | 315.90 | 0.0000 |
| 8 | RC3 | STATE_TRANSITION | REPLAY | AUTH_BINDING_GAP | SINK | ATO | 315.90 | 0.0000 |
| 9 | RC3 | TOKEN | KEY_SUBSTITUTION | AUTH_BINDING_GAP | SINK | ATO | 315.90 | 0.0000 |
| 10 | RC3 | CRYPTO_PARAMETER | REPLAY | VALIDATION_GAP | SINK | ATO | 315.90 | 0.0000 |
| 11 | RC3 | TOKEN | REPLAY | VALIDATION_GAP | SINK | ATO | 315.90 | 0.0000 |
| 12 | RC1 | PARSER_CONTEXT | STRUCTURAL_REWRITE | PARSER_DIFFERENTIAL | SINK | RCE | 315.73 | 0.0000 |
| 13 | RC1 | PAYLOAD_BODY | STRUCTURAL_REWRITE | PARSER_DIFFERENTIAL | SINK | RCE | 315.73 | 0.0000 |
| 14 | RC1 | NAMESPACE | STRUCTURAL_REWRITE | PARSER_DIFFERENTIAL | SINK | RCE | 315.73 | 0.0000 |
| 15 | RC1 | PAYLOAD_BODY | CONTEXT_SWITCH | CONTROL_EVASION | SINK | RCE | 315.70 | 0.0000 |
| 16 | RC1 | PARSER_CONTEXT | CONTEXT_SWITCH | CONTROL_EVASION | SINK | RCE | 315.70 | 0.0000 |
| 17 | RC3 | CRYPTO_PARAMETER | REPLAY | STATE_DESYNC | SINK | ATO | 315.65 | 0.0000 |
| 18 | RC3 | TOKEN | REPLAY | STATE_DESYNC | SINK | ATO | 315.65 | 0.0000 |
| 19 | RC1 | PARSER_CONTEXT | STRUCTURAL_REWRITE | STATE_DESYNC | SINK | RCE | 315.65 | 0.0000 |
| 20 | RC1 | NAMESPACE | STRUCTURAL_REWRITE | STATE_DESYNC | SINK | RCE | 315.65 | 0.0000 |

## 3. Heatmap View (RC x Impact)

| RC | Impact | Possible | Observed | Coverage | Gap |
|---|---|---:|---:|---:|---:|
| RC1 | ATO | 159 | 2 | 0.0126 | 0.9874 |
| RC1 | DATA_EXFILTRATION | 159 | 1 | 0.0063 | 0.9937 |
| RC1 | DOS | 159 | 0 | 0.0000 | 1.0000 |
| RC1 | INTEGRITY_TAMPERING | 159 | 0 | 0.0000 | 1.0000 |
| RC1 | RCE | 159 | 0 | 0.0000 | 1.0000 |
| RC2 | DATA_EXFILTRATION | 261 | 3 | 0.0115 | 0.9885 |
| RC2 | DOS | 261 | 0 | 0.0000 | 1.0000 |
| RC2 | PRIVILEGE_ESCALATION | 261 | 0 | 0.0000 | 1.0000 |
| RC2 | RECON_ENABLEMENT | 261 | 1 | 0.0038 | 0.9962 |
| RC2 | SESSION_HIJACK | 261 | 0 | 0.0000 | 1.0000 |
| RC2 | SSRF_INTERNAL_ACCESS | 261 | 2 | 0.0077 | 0.9923 |
| RC3 | ATO | 147 | 0 | 0.0000 | 1.0000 |
| RC3 | DATA_EXFILTRATION | 147 | 0 | 0.0000 | 1.0000 |
| RC3 | PRIVILEGE_ESCALATION | 147 | 0 | 0.0000 | 1.0000 |
| RC3 | SESSION_HIJACK | 147 | 0 | 0.0000 | 1.0000 |
| RC4 | ATO | 171 | 0 | 0.0000 | 1.0000 |
| RC4 | DATA_EXFILTRATION | 171 | 0 | 0.0000 | 1.0000 |
| RC4 | PRIVILEGE_ESCALATION | 171 | 0 | 0.0000 | 1.0000 |
| RC5 | ATO | 96 | 2 | 0.0208 | 0.9792 |
| RC5 | DOS | 96 | 0 | 0.0000 | 1.0000 |
| RC5 | FINANCIAL_FRAUD | 96 | 1 | 0.0104 | 0.9896 |
| RC5 | PRIVILEGE_ESCALATION | 96 | 1 | 0.0104 | 0.9896 |
| RC6 | DATA_EXFILTRATION | 84 | 0 | 0.0000 | 1.0000 |
| RC6 | DOS | 84 | 0 | 0.0000 | 1.0000 |
| RC6 | RCE | 84 | 0 | 0.0000 | 1.0000 |
| RC7 | ATO | 192 | 1 | 0.0052 | 0.9948 |
| RC7 | DATA_EXFILTRATION | 192 | 0 | 0.0000 | 1.0000 |
| RC7 | LATERAL_MOVEMENT | 192 | 0 | 0.0000 | 1.0000 |
| RC7 | RCE | 192 | 0 | 0.0000 | 1.0000 |
| RC7 | SSRF_INTERNAL_ACCESS | 192 | 1 | 0.0052 | 0.9948 |
| RC8 | ATO | 153 | 2 | 0.0131 | 0.9869 |
| RC8 | LATERAL_MOVEMENT | 153 | 0 | 0.0000 | 1.0000 |
| RC8 | PRIVILEGE_ESCALATION | 153 | 0 | 0.0000 | 1.0000 |
| RC8 | RCE | 153 | 1 | 0.0065 | 0.9935 |
| RC8 | SSRF_INTERNAL_ACCESS | 153 | 1 | 0.0065 | 0.9935 |
| RC9 | DATA_EXFILTRATION | 180 | 0 | 0.0000 | 1.0000 |
| RC9 | RECON_ENABLEMENT | 180 | 0 | 0.0000 | 1.0000 |
| RC9 | SESSION_HIJACK | 180 | 0 | 0.0000 | 1.0000 |

## 4. Interpretation Rules

- `Coverage Gap`: valid cell with no observed mapping
- `Verification Gap`: observed mapping missing strong validate-oracle path
- `Defense Gap`: observed mapping has weak or missing primary controls

## 5. Generated Artifacts

- `umcs_observed_space.csv`
- `umcs_gap_top20.csv`
- `umcs_gap_heatmap_rc_impact.csv`
- `umcs_gap_summary_by_rc.csv`
- `UMCS_Gap_Analysis_Report.md` (this file)
