#!/usr/bin/env python3
"""
Generate UMCS gap-analysis artifacts from existing repository data
without modifying existing documentation.
"""

from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


ROOT = Path(__file__).resolve().parents[3]
ART_DIR = ROOT / "the-map" / "artifact-examples"
SRC_CROSS_GRAPH = ART_DIR / "cross-mutation-graph.html"
SRC_TEMPLATE = ART_DIR / "mutation-classification-template.csv"
OUT_DIR = ART_DIR / "umcs-gap-analysis"


RC_VALUES = [f"RC{i}" for i in range(1, 10)]
ROLE_VALUES = ["ENTRY", "PIVOT", "AMPLIFIER", "SINK", "STANDALONE"]


NODE_TO_RC: Dict[str, str] = {
    # RC2
    "url_confusion": "RC2",
    "unicode": "RC2",
    "type_confusion": "RC2",
    "zip_archive": "RC2",
    "smuggling": "RC2",
    "reverse_proxy": "RC2",
    "http_header": "RC2",
    "hpp": "RC2",
    "cache_poisoning": "RC2",
    # RC1
    "xss": "RC1",
    "ssti": "RC1",
    "proto_pollution": "RC1",
    "cmd_injection": "RC1",
    "xxe": "RC1",
    "sqli": "RC1",
    "nosqli": "RC1",
    "graphql": "RC1",
    "ssi_esi": "RC1",
    # RC3
    "jwt": "RC3",
    "oauth": "RC3",
    "saml": "RC3",
    "account_takeover": "RC3",
    # RC4
    "cors": "RC4",
    "mass_assignment": "RC4",
    "idor": "RC4",
    # RC5
    "csrf": "RC5",
    "race_condition": "RC5",
    "business_logic": "RC5",
    # RC6
    "deserialization": "RC6",
    # RC7
    "ssrf": "RC7",
    "path_traversal": "RC7",
    "file_upload": "RC7",
    "open_redirect": "RC7",
    # RC8
    "secondary_ctx": "RC8",
    "implicit_trust": "RC8",
    "dns": "RC8",
    "websocket": "RC8",
    # RC9
    "cookie": "RC9",
    "dom_clobbering": "RC9",
    "ui_redressing": "RC9",
    "waf_bypass": "RC9",
}


NODE_TO_TARGET: Dict[str, str] = {
    "url_confusion": "URL",
    "unicode": "PAYLOAD_BODY",
    "type_confusion": "PARAMETER",
    "zip_archive": "SERIALIZED_OBJECT",
    "xss": "PAYLOAD_BODY",
    "ssti": "PAYLOAD_BODY",
    "proto_pollution": "PARAMETER",
    "cmd_injection": "PAYLOAD_BODY",
    "xxe": "PAYLOAD_BODY",
    "sqli": "PARAMETER",
    "nosqli": "PARAMETER",
    "graphql": "PARAMETER",
    "ssi_esi": "PAYLOAD_BODY",
    "jwt": "TOKEN",
    "oauth": "TOKEN",
    "saml": "TOKEN",
    "csrf": "STATE_TRANSITION",
    "cors": "HEADER",
    "mass_assignment": "PARAMETER",
    "idor": "PARAMETER",
    "cookie": "COOKIE",
    "account_takeover": "TOKEN",
    "smuggling": "HEADER",
    "reverse_proxy": "PATH",
    "http_header": "HEADER",
    "hpp": "PARAMETER",
    "websocket": "HEADER",
    "dns": "URL",
    "ssrf": "URL",
    "path_traversal": "PATH",
    "file_upload": "PAYLOAD_BODY",
    "deserialization": "SERIALIZED_OBJECT",
    "open_redirect": "URL",
    "dom_clobbering": "PARSER_CONTEXT",
    "ui_redressing": "PARSER_CONTEXT",
    "race_condition": "STATE_TRANSITION",
    "secondary_ctx": "TRUST_CHANNEL",
    "implicit_trust": "TRUST_CHANNEL",
    "business_logic": "STATE_TRANSITION",
    "cache_poisoning": "CACHE_KEY",
    "waf_bypass": "PAYLOAD_BODY",
}


NODE_TO_IMPACT: Dict[str, str] = {
    "account_takeover": "ATO",
    "ssrf": "SSRF_INTERNAL_ACCESS",
    "cmd_injection": "RCE",
    "deserialization": "RCE",
    "path_traversal": "DATA_EXFILTRATION",
    "cache_poisoning": "DATA_EXFILTRATION",
    "xss": "DATA_EXFILTRATION",
    "oauth": "ATO",
    "jwt": "ATO",
    "saml": "ATO",
    "csrf": "PRIVILEGE_ESCALATION",
    "idor": "DATA_EXFILTRATION",
    "mass_assignment": "PRIVILEGE_ESCALATION",
    "cors": "DATA_EXFILTRATION",
    "cookie": "SESSION_HIJACK",
    "waf_bypass": "RECON_ENABLEMENT",
    "file_upload": "RCE",
    "open_redirect": "ATO",
    "race_condition": "FINANCIAL_FRAUD",
    "business_logic": "FINANCIAL_FRAUD",
    "ui_redressing": "ATO",
    "xxe": "DATA_EXFILTRATION",
    "sqli": "DATA_EXFILTRATION",
    "nosqli": "DATA_EXFILTRATION",
    "graphql": "DATA_EXFILTRATION",
    "reverse_proxy": "PRIVILEGE_ESCALATION",
    "http_header": "PRIVILEGE_ESCALATION",
    "hpp": "PRIVILEGE_ESCALATION",
    "dns": "LATERAL_MOVEMENT",
    "secondary_ctx": "LATERAL_MOVEMENT",
    "implicit_trust": "LATERAL_MOVEMENT",
    "zip_archive": "RCE",
    "type_confusion": "PRIVILEGE_ESCALATION",
    "unicode": "CONTROL_EVASION" if False else "RECON_ENABLEMENT",  # keep enum-safe
    "url_confusion": "SSRF_INTERNAL_ACCESS",
    "dom_clobbering": "DATA_EXFILTRATION",
    "ssti": "RCE",
    "proto_pollution": "RCE",
    "ssi_esi": "RCE",
    "smuggling": "SESSION_HIJACK",
}


PATTERN_TO_OPERATOR: Dict[str, str] = {
    "parser": "CANONICALIZATION_BYPASS",
    "encoding": "ENCODING_SHIFT",
    "cache": "HEADER_POLLUTION",
    "temporal": "RACE_PARALLELIZATION",
    "trust": "ORDER_MANIPULATION",
    "escalation": "CONTEXT_SWITCH",
    "enable": "DELIMITER_ABUSE",
}


PATTERN_TO_DISCREPANCY: Dict[str, str] = {
    "parser": "PARSER_DIFFERENTIAL",
    "encoding": "CANONICALIZATION_GAP",
    "cache": "CANONICALIZATION_GAP",
    "temporal": "STATE_DESYNC",
    "trust": "TRUST_BOUNDARY_BREAK",
    "escalation": "VALIDATION_GAP",
    "enable": "CONTROL_EVASION",
}


PATTERN_TO_PRECONDITION: Dict[str, str] = {
    "parser": "MULTI_PARSER_PIPELINE|AMBIGUOUS_INPUT_ACCEPTED",
    "encoding": "WEAK_OR_MISSING_NORMALIZATION",
    "cache": "MULTI_PARSER_PIPELINE",
    "temporal": "MISSING_ATOMICITY",
    "trust": "CROSS_COMPONENT_TRUST",
    "escalation": "MISSING_STRICT_AUTH_VALIDATION",
    "enable": "UNSAFE_DEFAULT_ENABLED",
}


PATTERN_TO_CONTROL: Dict[str, str] = {
    "parser": "SINGLE_AUTHORITATIVE_PARSER|REJECT_AMBIGUOUS_INPUT",
    "encoding": "STRICT_CANONICALIZATION_AT_ENTRY",
    "cache": "STRICT_CANONICALIZATION_AT_ENTRY|REJECT_AMBIGUOUS_INPUT",
    "temporal": "IDEMPOTENCY_KEYS_AND_ATOMIC_LOCKING",
    "trust": "CONTROL_PLANE_HARDENING|REFERENCE_ALLOWLIST_AND_RESOLUTION_CHECK",
    "escalation": "DATA_LAYER_AUTHZ_ENFORCEMENT",
    "enable": "REJECT_AMBIGUOUS_INPUT|CONTROL_PLANE_HARDENING",
}


OP_TO_WORK_UNITS: Dict[str, str] = {
    "ENCODING_SHIFT": "GENERATE|TRANSFORM|INJECT|OBSERVE",
    "CANONICALIZATION_BYPASS": "TRANSFORM|INJECT|OBSERVE|VALIDATE",
    "DUPLICATE_KEY": "GENERATE|INJECT|REORDER|OBSERVE",
    "DELIMITER_ABUSE": "GENERATE|INJECT|OBSERVE|VALIDATE",
    "HEADER_POLLUTION": "GENERATE|INJECT|REORDER|OBSERVE",
    "CONTEXT_SWITCH": "TRANSFORM|INJECT|OBSERVE|VALIDATE",
    "TYPE_COERCION": "GENERATE|TRANSFORM|INJECT|OBSERVE",
    "STRUCTURAL_REWRITE": "TRANSFORM|INJECT|OBSERVE|VALIDATE",
    "ORDER_MANIPULATION": "REORDER|INJECT|OBSERVE|VALIDATE",
    "RACE_PARALLELIZATION": "PARALLELIZE|INJECT|OBSERVE|VALIDATE",
    "REPLAY": "REPLAY|INJECT|OBSERVE|VALIDATE",
    "DOWNGRADE": "NEGOTIATE|INJECT|OBSERVE|VALIDATE",
    "KEY_SUBSTITUTION": "SUBSTITUTE|INJECT|OBSERVE|VALIDATE",
    "GADGET_CHAINING": "CHAIN|INJECT|OBSERVE|VALIDATE",
}


OP_TO_DISCREPANCIES: Dict[str, Tuple[str, ...]] = {
    "ENCODING_SHIFT": ("CANONICALIZATION_GAP", "CONTROL_EVASION", "PARSER_DIFFERENTIAL"),
    "CANONICALIZATION_BYPASS": ("CANONICALIZATION_GAP", "PARSER_DIFFERENTIAL", "VALIDATION_GAP"),
    "DUPLICATE_KEY": ("PARSER_DIFFERENTIAL", "VALIDATION_GAP", "AUTHZ_ENFORCEMENT_GAP"),
    "DELIMITER_ABUSE": ("PARSER_DIFFERENTIAL", "VALIDATION_GAP", "CONTROL_EVASION"),
    "HEADER_POLLUTION": ("PARSER_DIFFERENTIAL", "TRUST_BOUNDARY_BREAK", "VALIDATION_GAP"),
    "CONTEXT_SWITCH": ("PARSER_DIFFERENTIAL", "TRUST_BOUNDARY_BREAK", "CONTROL_EVASION"),
    "TYPE_COERCION": ("VALIDATION_GAP", "AUTH_BINDING_GAP", "AUTHZ_ENFORCEMENT_GAP"),
    "STRUCTURAL_REWRITE": ("PARSER_DIFFERENTIAL", "STATE_DESYNC", "CONTROL_EVASION"),
    "ORDER_MANIPULATION": ("VALIDATION_GAP", "AUTHZ_ENFORCEMENT_GAP", "TRUST_BOUNDARY_BREAK", "STATE_DESYNC"),
    "RACE_PARALLELIZATION": ("STATE_DESYNC",),
    "REPLAY": ("AUTH_BINDING_GAP", "VALIDATION_GAP", "STATE_DESYNC"),
    "DOWNGRADE": ("AUTH_BINDING_GAP", "CONTROL_EVASION", "TRUST_BOUNDARY_BREAK"),
    "KEY_SUBSTITUTION": ("AUTH_BINDING_GAP", "TRUST_BOUNDARY_BREAK"),
    "GADGET_CHAINING": ("TRUST_BOUNDARY_BREAK", "CONTROL_EVASION", "VALIDATION_GAP"),
}


OP_TO_ROLES: Dict[str, Tuple[str, ...]] = {
    "ENCODING_SHIFT": ("ENTRY", "PIVOT", "AMPLIFIER"),
    "CANONICALIZATION_BYPASS": ("ENTRY", "PIVOT", "AMPLIFIER"),
    "DUPLICATE_KEY": ("ENTRY", "PIVOT"),
    "DELIMITER_ABUSE": ("ENTRY", "PIVOT", "AMPLIFIER"),
    "HEADER_POLLUTION": ("ENTRY", "PIVOT", "AMPLIFIER"),
    "CONTEXT_SWITCH": ("ENTRY", "PIVOT", "SINK"),
    "TYPE_COERCION": ("ENTRY", "PIVOT"),
    "STRUCTURAL_REWRITE": ("ENTRY", "PIVOT", "SINK"),
    "ORDER_MANIPULATION": ("ENTRY", "PIVOT", "SINK"),
    "RACE_PARALLELIZATION": ("ENTRY", "PIVOT", "SINK"),
    "REPLAY": ("ENTRY", "PIVOT", "SINK"),
    "DOWNGRADE": ("ENTRY", "PIVOT", "AMPLIFIER"),
    "KEY_SUBSTITUTION": ("ENTRY", "PIVOT", "SINK"),
    "GADGET_CHAINING": ("PIVOT", "SINK"),
}


TARGET_TO_OPERATORS: Dict[str, Tuple[str, ...]] = {
    "URL": ("ENCODING_SHIFT", "CANONICALIZATION_BYPASS", "ORDER_MANIPULATION", "REPLAY"),
    "PATH": ("ENCODING_SHIFT", "CANONICALIZATION_BYPASS", "DELIMITER_ABUSE", "ORDER_MANIPULATION"),
    "HEADER": ("HEADER_POLLUTION", "DELIMITER_ABUSE", "DUPLICATE_KEY", "ORDER_MANIPULATION"),
    "PARAMETER": ("DUPLICATE_KEY", "TYPE_COERCION", "ENCODING_SHIFT", "ORDER_MANIPULATION", "CANONICALIZATION_BYPASS"),
    "COOKIE": ("DUPLICATE_KEY", "HEADER_POLLUTION", "ENCODING_SHIFT", "CANONICALIZATION_BYPASS"),
    "TOKEN": ("KEY_SUBSTITUTION", "REPLAY", "DOWNGRADE", "TYPE_COERCION"),
    "PAYLOAD_BODY": ("ENCODING_SHIFT", "CONTEXT_SWITCH", "STRUCTURAL_REWRITE", "DELIMITER_ABUSE"),
    "PARSER_CONTEXT": ("CONTEXT_SWITCH", "STRUCTURAL_REWRITE", "CANONICALIZATION_BYPASS"),
    "NAMESPACE": ("CONTEXT_SWITCH", "STRUCTURAL_REWRITE"),
    "SERIALIZED_OBJECT": ("STRUCTURAL_REWRITE", "GADGET_CHAINING", "TYPE_COERCION"),
    "STATE_TRANSITION": ("ORDER_MANIPULATION", "RACE_PARALLELIZATION", "REPLAY"),
    "TRUST_CHANNEL": ("ORDER_MANIPULATION", "KEY_SUBSTITUTION", "DOWNGRADE"),
    "CACHE_KEY": ("HEADER_POLLUTION", "CANONICALIZATION_BYPASS", "DUPLICATE_KEY"),
    "CRYPTO_PARAMETER": ("DOWNGRADE", "KEY_SUBSTITUTION", "REPLAY"),
}


RC_TO_TARGETS: Dict[str, Tuple[str, ...]] = {
    "RC1": ("PAYLOAD_BODY", "PARAMETER", "NAMESPACE", "PARSER_CONTEXT", "HEADER"),
    "RC2": ("URL", "PATH", "HEADER", "PARAMETER", "COOKIE", "PARSER_CONTEXT", "CACHE_KEY", "SERIALIZED_OBJECT"),
    "RC3": ("TOKEN", "COOKIE", "HEADER", "CRYPTO_PARAMETER", "STATE_TRANSITION"),
    "RC4": ("PARAMETER", "TOKEN", "HEADER", "STATE_TRANSITION", "URL"),
    "RC5": ("STATE_TRANSITION", "PARAMETER", "TOKEN"),
    "RC6": ("SERIALIZED_OBJECT", "PAYLOAD_BODY", "PARSER_CONTEXT"),
    "RC7": ("URL", "PATH", "PARAMETER", "PAYLOAD_BODY", "HEADER"),
    "RC8": ("TRUST_CHANNEL", "HEADER", "URL", "TOKEN", "SERIALIZED_OBJECT"),
    "RC9": ("HEADER", "CACHE_KEY", "PARSER_CONTEXT", "TOKEN", "CRYPTO_PARAMETER", "URL"),
}


RC_TO_IMPACTS: Dict[str, Tuple[str, ...]] = {
    "RC1": ("RCE", "DATA_EXFILTRATION", "ATO", "DOS", "INTEGRITY_TAMPERING"),
    "RC2": ("DATA_EXFILTRATION", "PRIVILEGE_ESCALATION", "SESSION_HIJACK", "DOS", "SSRF_INTERNAL_ACCESS", "RECON_ENABLEMENT"),
    "RC3": ("ATO", "PRIVILEGE_ESCALATION", "SESSION_HIJACK", "DATA_EXFILTRATION"),
    "RC4": ("PRIVILEGE_ESCALATION", "DATA_EXFILTRATION", "ATO"),
    "RC5": ("FINANCIAL_FRAUD", "PRIVILEGE_ESCALATION", "ATO", "DOS"),
    "RC6": ("RCE", "DATA_EXFILTRATION", "DOS"),
    "RC7": ("SSRF_INTERNAL_ACCESS", "RCE", "DATA_EXFILTRATION", "LATERAL_MOVEMENT", "ATO"),
    "RC8": ("PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT", "ATO", "SSRF_INTERNAL_ACCESS", "RCE"),
    "RC9": ("RECON_ENABLEMENT", "DATA_EXFILTRATION", "SESSION_HIJACK"),
}


RC_WEIGHT = {
    "RC1": 1.30,
    "RC2": 1.00,
    "RC3": 1.35,
    "RC4": 1.10,
    "RC5": 0.95,
    "RC6": 1.20,
    "RC7": 1.25,
    "RC8": 1.05,
    "RC9": 0.80,
}

IMPACT_WEIGHT = {
    "RCE": 1.35,
    "ATO": 1.30,
    "PRIVILEGE_ESCALATION": 1.15,
    "DATA_EXFILTRATION": 1.10,
    "SSRF_INTERNAL_ACCESS": 1.10,
    "SESSION_HIJACK": 1.05,
    "FINANCIAL_FRAUD": 1.15,
    "LATERAL_MOVEMENT": 1.15,
    "DOS": 0.80,
    "INTEGRITY_TAMPERING": 1.00,
    "RECON_ENABLEMENT": 0.70,
}

ROLE_WEIGHT = {
    "ENTRY": 0.90,
    "PIVOT": 1.00,
    "AMPLIFIER": 1.05,
    "SINK": 1.20,
    "STANDALONE": 1.00,
}


@dataclass(frozen=True)
class Combo:
    rc: str
    target: str
    operator: str
    discrepancy: str
    role: str
    impact: str


def parse_edges(path: Path) -> List[Tuple[str, str, str]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    edge_re = re.compile(r"\['([^']+)','([^']+)','([^']+)'")
    return edge_re.findall(text)


def build_graph_records(edges: List[Tuple[str, str, str]]) -> List[dict]:
    in_deg = Counter()
    out_deg = Counter()
    for src, dst, _ in edges:
        out_deg[src] += 1
        in_deg[dst] += 1

    counters = Counter()
    records = []

    for src, dst, pattern in edges:
        rc = NODE_TO_RC.get(src)
        if not rc:
            continue

        target = NODE_TO_TARGET.get(src, "PAYLOAD_BODY")
        operator = PATTERN_TO_OPERATOR.get(pattern, "STRUCTURAL_REWRITE")
        discrepancy = PATTERN_TO_DISCREPANCY.get(pattern, "VALIDATION_GAP")
        impact = NODE_TO_IMPACT.get(dst, "RECON_ENABLEMENT")

        if pattern == "enable":
            role = "AMPLIFIER"
        elif dst in {"account_takeover", "cmd_injection", "deserialization", "ssrf"}:
            role = "SINK"
        elif in_deg[src] == 0:
            role = "ENTRY"
        else:
            role = "PIVOT"

        key = (rc, target, operator, impact)
        counters[key] += 1
        seq = counters[key]
        mutation_id = f"{rc}.{target}.{operator}.{impact}.{seq:03d}"

        records.append(
            {
                "mutation_id": mutation_id,
                "title": f"{src} -> {dst} via {pattern}",
                "rc": rc,
                "mutation_target": target,
                "mutation_operator": operator,
                "operator_work_units": OP_TO_WORK_UNITS.get(operator, "GENERATE|INJECT|OBSERVE"),
                "operator_success_oracle": f"Operator effect observed through {pattern} differential from {src} to {dst}",
                "discrepancy_type": discrepancy,
                "preconditions": PATTERN_TO_PRECONDITION.get(pattern, "UNSAFE_DEFAULT_ENABLED"),
                "chain_role": role,
                "impact_primary": impact,
                "impact_secondary": "",
                "primary_controls": PATTERN_TO_CONTROL.get(pattern, "CONTROL_PLANE_HARDENING"),
                "evidence_refs": "the-map/artifact-examples/cross-mutation-graph.html",
                "detection_signals": f"Cross-mutation transition observed: {src}->{dst}",
                "test_recipe": f"Replay edge pattern '{pattern}' from source '{src}' to destination '{dst}'",
                "confidence": "MEDIUM",
                "status": "DRAFT",
            }
        )
    return records


def load_template_records(path: Path) -> List[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            # Keep only fields we use if present.
            rows.append(
                {
                    "mutation_id": row.get("mutation_id", ""),
                    "title": row.get("title", ""),
                    "rc": row.get("rc", ""),
                    "mutation_target": row.get("mutation_target", ""),
                    "mutation_operator": row.get("mutation_operator", ""),
                    "operator_work_units": row.get("operator_work_units", OP_TO_WORK_UNITS.get(row.get("mutation_operator", ""), "GENERATE|INJECT|OBSERVE")),
                    "operator_success_oracle": row.get("operator_success_oracle", "Deterministic operator effect observed"),
                    "discrepancy_type": row.get("discrepancy_type", ""),
                    "preconditions": row.get("preconditions", ""),
                    "chain_role": row.get("chain_role", ""),
                    "impact_primary": row.get("impact_primary", ""),
                    "impact_secondary": row.get("impact_secondary", ""),
                    "primary_controls": row.get("primary_controls", ""),
                    "evidence_refs": row.get("evidence_refs", ""),
                    "detection_signals": row.get("detection_signals", ""),
                    "test_recipe": row.get("test_recipe", ""),
                    "confidence": row.get("confidence", "MEDIUM"),
                    "status": row.get("status", "DRAFT"),
                }
            )
        return rows


def dedupe_records(records: Iterable[dict]) -> List[dict]:
    seen = set()
    out = []
    for r in records:
        key = (
            r["rc"],
            r["mutation_target"],
            r["mutation_operator"],
            r["discrepancy_type"],
            r["chain_role"],
            r["impact_primary"],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def build_valid_space() -> Set[Combo]:
    valid = set()
    for rc in RC_VALUES:
        for target in RC_TO_TARGETS.get(rc, ()):
            for op in TARGET_TO_OPERATORS.get(target, ()):
                for disc in OP_TO_DISCREPANCIES.get(op, ()):
                    for role in OP_TO_ROLES.get(op, ()):
                        for impact in RC_TO_IMPACTS.get(rc, ()):
                            valid.add(Combo(rc, target, op, disc, role, impact))
    return valid


def combo_from_record(r: dict) -> Combo:
    return Combo(
        rc=r["rc"],
        target=r["mutation_target"],
        operator=r["mutation_operator"],
        discrepancy=r["discrepancy_type"],
        role=r["chain_role"],
        impact=r["impact_primary"],
    )


def score_missing(
    valid_space: Set[Combo], observed_space: Set[Combo]
) -> List[Tuple[Combo, float, float]]:
    prefix_possible = Counter()
    prefix_observed = Counter()
    operator_possible = Counter()
    operator_observed = Counter()
    discrepancy_possible = Counter()
    discrepancy_observed = Counter()

    for c in valid_space:
        prefix_possible[(c.rc, c.target, c.operator)] += 1
        operator_possible[c.operator] += 1
        discrepancy_possible[c.discrepancy] += 1
    for c in observed_space:
        prefix_observed[(c.rc, c.target, c.operator)] += 1
        operator_observed[c.operator] += 1
        discrepancy_observed[c.discrepancy] += 1

    scored = []
    for c in valid_space:
        if c in observed_space:
            continue
        prefix = (c.rc, c.target, c.operator)
        cov = prefix_observed[prefix] / prefix_possible[prefix] if prefix_possible[prefix] else 0.0
        op_cov = operator_observed[c.operator] / operator_possible[c.operator] if operator_possible[c.operator] else 0.0
        disc_cov = discrepancy_observed[c.discrepancy] / discrepancy_possible[c.discrepancy] if discrepancy_possible[c.discrepancy] else 0.0
        op_gap = 1.0 - op_cov
        disc_gap = 1.0 - disc_cov
        base = RC_WEIGHT[c.rc] * IMPACT_WEIGHT[c.impact] * ROLE_WEIGHT[c.role]
        rarity_boost = 1.0 + (0.30 * op_gap) + (0.20 * disc_gap)
        score = base * (1.0 - cov) * rarity_boost * 100.0
        scored.append((c, score, cov))

    scored.sort(key=lambda x: x[1], reverse=True)
    return scored


def write_csv(path: Path, rows: List[dict], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    edges = parse_edges(SRC_CROSS_GRAPH)
    graph_records = build_graph_records(edges)
    template_records = load_template_records(SRC_TEMPLATE)
    observed_records = dedupe_records(graph_records + template_records)

    observed_fields = [
        "mutation_id",
        "title",
        "rc",
        "mutation_target",
        "mutation_operator",
        "operator_work_units",
        "operator_success_oracle",
        "discrepancy_type",
        "preconditions",
        "chain_role",
        "impact_primary",
        "impact_secondary",
        "primary_controls",
        "evidence_refs",
        "detection_signals",
        "test_recipe",
        "confidence",
        "status",
    ]
    write_csv(OUT_DIR / "umcs_observed_space.csv", observed_records, observed_fields)

    valid_space = build_valid_space()
    observed_space = {combo_from_record(r) for r in observed_records if combo_from_record(r) in valid_space}

    scored_missing = score_missing(valid_space, observed_space)
    top20 = scored_missing[:20]

    top_rows = []
    for idx, (c, score, cov) in enumerate(top20, start=1):
        top_rows.append(
            {
                "rank": idx,
                "rc": c.rc,
                "mutation_target": c.target,
                "mutation_operator": c.operator,
                "discrepancy_type": c.discrepancy,
                "chain_role": c.role,
                "impact_primary": c.impact,
                "gap_score": f"{score:.2f}",
                "prefix_coverage": f"{cov:.4f}",
            }
        )
    write_csv(
        OUT_DIR / "umcs_gap_top20.csv",
        top_rows,
        ["rank", "rc", "mutation_target", "mutation_operator", "discrepancy_type", "chain_role", "impact_primary", "gap_score", "prefix_coverage"],
    )

    # Heatmap RC x Impact
    heat_rows = []
    for rc in RC_VALUES:
        for impact in RC_TO_IMPACTS.get(rc, ()):
            poss = [c for c in valid_space if c.rc == rc and c.impact == impact]
            obs = [c for c in observed_space if c.rc == rc and c.impact == impact]
            possible = len(poss)
            observed = len(obs)
            coverage = (observed / possible) if possible else 0.0
            heat_rows.append(
                {
                    "rc": rc,
                    "impact": impact,
                    "possible_combos": possible,
                    "observed_combos": observed,
                    "coverage_ratio": f"{coverage:.4f}",
                    "gap_ratio": f"{1.0 - coverage:.4f}",
                }
            )
    write_csv(
        OUT_DIR / "umcs_gap_heatmap_rc_impact.csv",
        heat_rows,
        ["rc", "impact", "possible_combos", "observed_combos", "coverage_ratio", "gap_ratio"],
    )

    # Summary
    coverage_total = len(observed_space) / len(valid_space) if valid_space else 0.0
    by_rc = []
    for rc in RC_VALUES:
        p = [c for c in valid_space if c.rc == rc]
        o = [c for c in observed_space if c.rc == rc]
        pr = len(p)
        orr = len(o)
        by_rc.append(
            {
                "rc": rc,
                "possible_combos": pr,
                "observed_combos": orr,
                "coverage_ratio": f"{(orr / pr) if pr else 0.0:.4f}",
                "gap_ratio": f"{1.0 - ((orr / pr) if pr else 0.0):.4f}",
            }
        )
    write_csv(
        OUT_DIR / "umcs_gap_summary_by_rc.csv",
        by_rc,
        ["rc", "possible_combos", "observed_combos", "coverage_ratio", "gap_ratio"],
    )

    # Markdown report
    report = []
    report.append("# UMCS Gap Analysis Report")
    report.append("")
    report.append(f"- Generated date: {date.today().isoformat()}")
    report.append("- Scope: Derived observed space from `cross-mutation-graph.html` plus `mutation-classification-template.csv`")
    report.append("- Constraint: Existing documents unchanged; analysis exported as new artifacts only")
    report.append("")
    report.append("## 1. Coverage Snapshot")
    report.append("")
    report.append(f"- Valid combo space: **{len(valid_space)}**")
    report.append(f"- Observed combo space: **{len(observed_space)}**")
    report.append(f"- Total coverage ratio: **{coverage_total:.4f}**")
    report.append(f"- Total gap ratio: **{1.0 - coverage_total:.4f}**")
    report.append("")
    report.append("## 2. Top-20 High-Risk Missing Cells")
    report.append("")
    report.append("| Rank | RC | Target | Operator | Discrepancy | Role | Impact | Gap Score | Prefix Coverage |")
    report.append("|---|---|---|---|---|---|---|---:|---:|")
    for r in top_rows:
        report.append(
            f"| {r['rank']} | {r['rc']} | {r['mutation_target']} | {r['mutation_operator']} | {r['discrepancy_type']} | {r['chain_role']} | {r['impact_primary']} | {r['gap_score']} | {r['prefix_coverage']} |"
        )
    report.append("")
    report.append("## 3. Heatmap View (RC x Impact)")
    report.append("")
    report.append("| RC | Impact | Possible | Observed | Coverage | Gap |")
    report.append("|---|---|---:|---:|---:|---:|")
    for r in sorted(heat_rows, key=lambda x: (x["rc"], x["impact"])):
        report.append(
            f"| {r['rc']} | {r['impact']} | {r['possible_combos']} | {r['observed_combos']} | {r['coverage_ratio']} | {r['gap_ratio']} |"
        )
    report.append("")
    report.append("## 4. Interpretation Rules")
    report.append("")
    report.append("- `Coverage Gap`: valid cell with no observed mapping")
    report.append("- `Verification Gap`: observed mapping missing strong validate-oracle path")
    report.append("- `Defense Gap`: observed mapping has weak or missing primary controls")
    report.append("")
    report.append("## 5. Generated Artifacts")
    report.append("")
    report.append("- `umcs_observed_space.csv`")
    report.append("- `umcs_gap_top20.csv`")
    report.append("- `umcs_gap_heatmap_rc_impact.csv`")
    report.append("- `umcs_gap_summary_by_rc.csv`")
    report.append("- `UMCS_Gap_Analysis_Report.md` (this file)")
    report.append("")
    (OUT_DIR / "UMCS_Gap_Analysis_Report.md").write_text("\n".join(report), encoding="utf-8")


if __name__ == "__main__":
    main()
