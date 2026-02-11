# The Map

A structured, comprehensive vulnerability mutation taxonomy collection — built with [Claude Code](https://claude.ai/claude-code).

## What is this?

**The Map** is a systematic classification of web security vulnerability classes, organized not by individual CVEs or blog posts, but by **structural mutation criteria**: what is mutated, what discrepancy it creates, and where it is weaponized.

Each topic is a deeply structured Markdown reference document covering the full attack surface of a vulnerability class through a three-axis taxonomy (Mutation Target, Discrepancy/Bypass Type, Attack Scenario).

## Topics

| Category | Description |
|---|---|
| **HTTP Request Smuggling** | HTTP parsing discrepancies and desync attacks |
| **SSRF** | Server-Side Request Forgery bypass taxonomy |
| **SQL Injection** | SQL injection mutation vectors |
| **OAuth** | OAuth flow exploitation patterns |
| **JWT** | JSON Web Token attack surface |
| **Cookie** | Cookie security and bypass techniques |
| **SAML** | SAML authentication attack vectors |
| **SSO** | Single Sign-On vulnerability patterns |
| **Deserialization** | Deserialization gadget chains and bypass taxonomy |
| **File Upload** | File upload restriction bypass mutations |
| **ZIP Archive** | Archive parsing differentials and exploitation |
| **URL Confusion** | URL parser inconsistency attacks |
| **Unicode** | Unicode normalization and encoding attacks |
| **IDOR / BOLA** | Broken Object Level Authorization patterns |
| **HTTP Parameter Pollution** | Parameter parsing discrepancy attacks |
| **Web Race Condition** | Concurrency and TOCTOU exploitation |
| **UI Redressing** | Clickjacking and UI deception techniques |
| **Account Takeover** | Authentication bypass chains |
| **Business Logic Vulnerabilities** | Application logic flaw patterns |
| **Secondary Context Attack** | Cross-context injection vectors |
| **Reverse Proxy Misrouting** | Proxy path confusion and routing attacks |
| **WAF Bypass** | Web Application Firewall evasion taxonomy |
| **Web Fingerprinting** | Server and application fingerprinting techniques |
| **RMI** | Java Remote Method Invocation attack surface |

## Purpose — A Foundation for AI Agents and Security Tooling

This repository is designed to serve as a **machine-readable knowledge base** for the security ecosystem. The structured, generalized taxonomy format makes it a natural foundation for:

- **AI Security Agents** — LLM-based agents can consume these taxonomies to reason about vulnerability classes, generate test cases, and guide penetration testing workflows with structured domain knowledge rather than ad-hoc prompting.
- **Taxonomy & Classification** — A unified structural framework for organizing vulnerability research that goes beyond surface-level categorization (e.g., OWASP Top 10) into mutation-level granularity.
- **Detection Rule Generation** — The mutation-target / discrepancy-type structure maps directly to detection logic. Each mutation variant can be translated into WAF rules, SIEM signatures, or DAST scanner checks.
- **Fuzzer Seed Generation** — Mutation catalogs provide systematic seed corpora for fuzzers. Instead of random mutations, fuzzers can target specific structural variations documented in each taxonomy.
- **Security Research** — A reference framework for researchers to identify gaps in existing coverage, discover unexplored mutation combinations, and build on prior work systematically.
- **Automated Vulnerability Scanning** — Scanner plugins can enumerate test cases directly from the taxonomy structure, ensuring comprehensive coverage of known mutation types.

## How it was built

Every document in this repository was researched and synthesized using **Claude Code** (Anthropic's AI coding agent). The process involved systematic multi-source research — academic papers, conference talks (BlackHat, DEF CON), CVE databases, bug bounty reports, and tooling documentation — then synthesized into unified taxonomy documents organized by generalized structural criteria.

## Structure

```
the-map/
  +-- <vulnerability-class>/
       +-- <topic>.md          # Full mutation taxonomy document
```

Each `.md` file follows a consistent three-axis classification:
1. **Axis 1 — Mutation Target**: What structural component is manipulated
2. **Axis 2 — Discrepancy Type**: What mismatch or bypass the mutation creates
3. **Axis 3 — Attack Scenario**: Real-world exploitation context mapping

## License

This is a security research reference. Use responsibly for authorized testing, defensive security, and education.
