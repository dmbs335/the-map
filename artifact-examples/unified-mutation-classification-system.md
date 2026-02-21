# Unified Mutation Classification System (UMCS) v1.0

---

## 1. Goal

UMCS provides one consistent classification contract for all mutation records in this repository.
It standardizes each record by 8 criteria:

1. Root Cause (RC)
2. Mutation Target
3. Mutation Operator
4. Discrepancy Type
5. Preconditions
6. Chain Role
7. Impact
8. Primary Controls

---

## 2. Record Unit

One UMCS record represents one atomic mutation variant (not a full multi-step chain).

Example:
- Atomic: "Backslash authority confusion in URL validation"
- Not atomic: "URL confusion -> SSRF -> metadata credential theft"

---

## 3. Controlled Vocabulary

### 3.1 Root Cause (`rc`)

Allowed values:

- `RC1` Injection
- `RC2` Parser and Processing Differential
- `RC3` Authentication and Credential Integrity Failure
- `RC4` Access Control and Authorization Gap
- `RC5` State, Workflow, and Concurrency Violation
- `RC6` Unsafe Deserialization and Object Reconstruction
- `RC7` Unvalidated Resource Reference
- `RC8` Trust Boundary and Isolation Failure
- `RC9` Information Leakage and Side-Channel

### 3.2 Mutation Target (`mutation_target`)

Allowed values:

- `URL`
- `PATH`
- `HEADER`
- `PARAMETER`
- `COOKIE`
- `TOKEN`
- `PAYLOAD_BODY`
- `PARSER_CONTEXT`
- `NAMESPACE`
- `SERIALIZED_OBJECT`
- `STATE_TRANSITION`
- `TRUST_CHANNEL`
- `CACHE_KEY`
- `CRYPTO_PARAMETER`

### 3.3 Mutation Operator (`mutation_operator`)

Allowed values:

- `ENCODING_SHIFT`
- `CANONICALIZATION_BYPASS`
- `DUPLICATE_KEY`
- `DELIMITER_ABUSE`
- `HEADER_POLLUTION`
- `CONTEXT_SWITCH`
- `TYPE_COERCION`
- `STRUCTURAL_REWRITE`
- `ORDER_MANIPULATION`
- `RACE_PARALLELIZATION`
- `REPLAY`
- `DOWNGRADE`
- `KEY_SUBSTITUTION`
- `GADGET_CHAINING`

### 3.3.1 Operator Execution Contract (`operator_work_units`)

`mutation_operator` must be executable as concrete work units.

Allowed work-unit values:

- `GENERATE` (create mutated candidate payloads/values)
- `TRANSFORM` (apply encoding, normalization, structural transform)
- `INJECT` (place mutation into request/message/object)
- `REORDER` (change precedence/order/step sequence)
- `PARALLELIZE` (concurrent execution for race conditions)
- `REPLAY` (reuse captured material)
- `NEGOTIATE` (force weaker protocol/algorithm path)
- `SUBSTITUTE` (replace key/header/reference material)
- `CHAIN` (compose gadget/path chain)
- `OBSERVE` (collect differential behavior)
- `VALIDATE` (assert exploitability with deterministic oracle)

Operator-to-work mapping:

| Mutation Operator | Required Work Units | Typical Success Oracle |
|---|---|---|
| `ENCODING_SHIFT` | `GENERATE`, `TRANSFORM`, `INJECT`, `OBSERVE` | Filter/parser view differs from execution view |
| `CANONICALIZATION_BYPASS` | `TRANSFORM`, `INJECT`, `OBSERVE`, `VALIDATE` | Canonical value at check-time differs from use-time |
| `DUPLICATE_KEY` | `GENERATE`, `INJECT`, `REORDER`, `OBSERVE` | First-wins vs last-wins discrepancy is observable |
| `DELIMITER_ABUSE` | `GENERATE`, `INJECT`, `OBSERVE`, `VALIDATE` | Message boundary interpreted differently across components |
| `HEADER_POLLUTION` | `GENERATE`, `INJECT`, `REORDER`, `OBSERVE` | Routing/security decision changes via header conflicts |
| `CONTEXT_SWITCH` | `TRANSFORM`, `INJECT`, `OBSERVE`, `VALIDATE` | Data context becomes executable context after processing |
| `TYPE_COERCION` | `GENERATE`, `TRANSFORM`, `INJECT`, `OBSERVE` | Runtime type differs from validation-time type |
| `STRUCTURAL_REWRITE` | `TRANSFORM`, `INJECT`, `OBSERVE`, `VALIDATE` | Parse tree/object graph differs after rewrite pass |
| `ORDER_MANIPULATION` | `REORDER`, `INJECT`, `OBSERVE`, `VALIDATE` | Security step can be skipped or applied after sensitive action |
| `RACE_PARALLELIZATION` | `PARALLELIZE`, `INJECT`, `OBSERVE`, `VALIDATE` | Multiple successful commits for one logical transaction |
| `REPLAY` | `REPLAY`, `INJECT`, `OBSERVE`, `VALIDATE` | Previously valid artifact accepted again improperly |
| `DOWNGRADE` | `NEGOTIATE`, `INJECT`, `OBSERVE`, `VALIDATE` | Strong mode bypassed and weaker mode accepted |
| `KEY_SUBSTITUTION` | `SUBSTITUTE`, `INJECT`, `OBSERVE`, `VALIDATE` | Verification succeeds with attacker-controlled key material |
| `GADGET_CHAINING` | `CHAIN`, `INJECT`, `OBSERVE`, `VALIDATE` | Controlled code path/gadget side effect is reached |

Execution requirements:

1. Every record must include at least one mutation unit (`GENERATE`/`TRANSFORM`/`REORDER`/`PARALLELIZE`/`REPLAY`/`NEGOTIATE`/`SUBSTITUTE`/`CHAIN`).
2. Every record must include `OBSERVE`.
3. High-confidence records should include `VALIDATE`.

### 3.4 Discrepancy Type (`discrepancy_type`)

Allowed values:

- `PARSER_DIFFERENTIAL`
- `VALIDATION_GAP`
- `CANONICALIZATION_GAP`
- `AUTH_BINDING_GAP`
- `AUTHZ_ENFORCEMENT_GAP`
- `STATE_DESYNC`
- `TRUST_BOUNDARY_BREAK`
- `CONTROL_EVASION`
- `SIDE_CHANNEL_LEAK`

### 3.5 Preconditions (`preconditions`)

Multi-value field. Allowed values:

- `MULTI_PARSER_PIPELINE`
- `AMBIGUOUS_INPUT_ACCEPTED`
- `UNSAFE_DEFAULT_ENABLED`
- `LEGACY_COMPAT_MODE`
- `WEAK_OR_MISSING_NORMALIZATION`
- `CROSS_COMPONENT_TRUST`
- `MISSING_EGRESS_RESTRICTION`
- `MISSING_STRICT_AUTH_VALIDATION`
- `MISSING_ATOMICITY`
- `ATTACKER_CONTROLLED_REDIRECT_OR_CALLBACK`

### 3.6 Chain Role (`chain_role`)

Allowed values:

- `ENTRY`
- `PIVOT`
- `AMPLIFIER`
- `SINK`
- `STANDALONE`

### 3.7 Impact (`impact`)

Primary impact (required) and optional secondary impact.

Allowed values:

- `ATO`
- `RCE`
- `PRIVILEGE_ESCALATION`
- `DATA_EXFILTRATION`
- `SSRF_INTERNAL_ACCESS`
- `SESSION_HIJACK`
- `FINANCIAL_FRAUD`
- `LATERAL_MOVEMENT`
- `DOS`
- `INTEGRITY_TAMPERING`
- `RECON_ENABLEMENT`

### 3.8 Primary Controls (`primary_controls`)

Multi-value field. Allowed values:

- `SINGLE_AUTHORITATIVE_PARSER`
- `REJECT_AMBIGUOUS_INPUT`
- `STRICT_CANONICALIZATION_AT_ENTRY`
- `CONTEXT_AWARE_OUTPUT_ENCODING`
- `PARAMETERIZED_EXECUTION`
- `STRICT_AUTH_ALGORITHM_ALLOWLIST`
- `DATA_LAYER_AUTHZ_ENFORCEMENT`
- `REFERENCE_ALLOWLIST_AND_RESOLUTION_CHECK`
- `EGRESS_NETWORK_SEGMENTATION`
- `IDEMPOTENCY_KEYS_AND_ATOMIC_LOCKING`
- `SAFE_DESERIALIZATION_POLICY`
- `CONSTANT_TIME_AND_GENERIC_ERRORS`
- `CONTROL_PLANE_HARDENING`

---

## 4. ID Format

Use:

`RC{n}.{TARGET}.{OPERATOR}.{IMPACT}.{NNN}`

Rules:

- `{n}` is `1..9`
- `{TARGET}` uses uppercase target code
- `{OPERATOR}` uses uppercase operator code
- `{IMPACT}` uses uppercase impact code
- `{NNN}` is a 3-digit sequence per `(RC, TARGET, OPERATOR, IMPACT)` group

Examples:

- `RC2.URL.CANONICALIZATION_BYPASS.SSRF_INTERNAL_ACCESS.001`
- `RC1.NAMESPACE.CONTEXT_SWITCH.ATO.001`
- `RC5.STATE_TRANSITION.RACE_PARALLELIZATION.FINANCIAL_FRAUD.001`

---

## 5. Record Schema

| Field | Required | Type | Rule |
|---|---|---|---|
| `mutation_id` | Yes | String | Must follow UMCS ID format |
| `title` | Yes | String | Short atomic mutation name |
| `rc` | Yes | Enum | One value from section 3.1 |
| `mutation_target` | Yes | Enum | One value from section 3.2 |
| `mutation_operator` | Yes | Enum | One value from section 3.3 |
| `operator_work_units` | Yes | Enum list | `|` separated values from section 3.3.1 |
| `operator_success_oracle` | Yes | String | Deterministic observable condition proving operator effect |
| `discrepancy_type` | Yes | Enum | One value from section 3.4 |
| `preconditions` | Yes | Enum list | `|` separated values from section 3.5 |
| `chain_role` | Yes | Enum | One value from section 3.6 |
| `impact_primary` | Yes | Enum | One value from section 3.7 |
| `impact_secondary` | No | Enum list | `|` separated values from section 3.7 |
| `primary_controls` | Yes | Enum list | `|` separated values from section 3.8 |
| `evidence_refs` | Yes | String list | File refs, CVE ids, paper ids |
| `detection_signals` | No | String | Observable signals for detection |
| `test_recipe` | No | String | Minimal reproducible test flow |
| `confidence` | Yes | Enum | `HIGH`, `MEDIUM`, `LOW` |
| `status` | Yes | Enum | `DRAFT`, `VERIFIED`, `DEPRECATED` |

---

## 6. Normalization Rules

1. Keep one record atomic. Do not mix multiple operators in one record.
2. Put multi-step relation in graph/chain metadata, not in atomic record identity.
3. Choose one primary impact only; move others to `impact_secondary`.
4. Use `|` as the only multi-value delimiter.
5. If evidence is only theoretical, set `confidence=LOW` until verified.
6. `operator_work_units` must include at least one mutation unit plus `OBSERVE`.

---

## 7. Example Mappings

| mutation_id | title | rc | mutation_target | mutation_operator | discrepancy_type | chain_role | impact_primary |
|---|---|---|---|---|---|---|---|
| `RC2.URL.CANONICALIZATION_BYPASS.SSRF_INTERNAL_ACCESS.001` | URL authority confusion via backslash | `RC2` | `URL` | `CANONICALIZATION_BYPASS` | `PARSER_DIFFERENTIAL` | `ENTRY` | `SSRF_INTERNAL_ACCESS` |
| `RC1.NAMESPACE.CONTEXT_SWITCH.ATO.001` | mXSS via HTML/SVG namespace switch | `RC1` | `NAMESPACE` | `CONTEXT_SWITCH` | `PARSER_DIFFERENTIAL` | `PIVOT` | `ATO` |
| `RC3.TOKEN.KEY_SUBSTITUTION.ATO.001` | JWT key confusion on verification | `RC3` | `TOKEN` | `KEY_SUBSTITUTION` | `AUTH_BINDING_GAP` | `SINK` | `ATO` |
| `RC5.STATE_TRANSITION.RACE_PARALLELIZATION.FINANCIAL_FRAUD.001` | Parallel double-spend race | `RC5` | `STATE_TRANSITION` | `RACE_PARALLELIZATION` | `STATE_DESYNC` | `SINK` | `FINANCIAL_FRAUD` |
| `RC7.URL.ORDER_MANIPULATION.SSRF_INTERNAL_ACCESS.001` | Allowlist bypass via redirect chain | `RC7` | `URL` | `ORDER_MANIPULATION` | `VALIDATION_GAP` | `PIVOT` | `SSRF_INTERNAL_ACCESS` |

---

## 8. Adoption Workflow

1. Parse existing mutation docs into atomic candidates.
2. Assign `rc` first, then `mutation_target`, then `mutation_operator`.
3. Attach one primary `discrepancy_type`.
4. Set `chain_role` from graph context.
5. Set `impact_primary`, then controls.
6. Mark `confidence` and `status`.

This yields consistent records for tooling generation (Burp checks, Nuclei templates, scanner seeds, and detection rules).
