# The Map
### Web Security Vulnerability Knowledge Base — Mutation Taxonomy & Attack Surface Reference

A structured, comprehensive vulnerability mutation taxonomy collection for security researchers, penetration testers, bug bounty hunters, and AI security agents — built with [Claude Code](https://claude.ai/claude-code).

> **Keywords**: web security knowledge base, vulnerability taxonomy, attack surface mapping, mutation catalog, penetration testing reference, bug bounty methodology, security research database, exploit variation matrix, web hacking cheatsheet, OWASP vulnerability classification, offensive security reference

---

## What is this?

**The Map** is a **security knowledge base** that systematically classifies 50+ web vulnerability classes. Unlike conventional cheatsheets or CVE lists, each topic is organized by **structural mutation criteria** — what is mutated, what discrepancy it creates, and where it is weaponized.

Each topic is a deeply structured Markdown reference document covering the full attack surface of a vulnerability class through a three-axis taxonomy (Mutation Target, Discrepancy/Bypass Type, Attack Scenario).

---

## Topics

### Injection
| Category | Description |
|---|---|
| [**SQL Injection**](sql-injection/) | SQL injection mutation vectors and filter bypass taxonomy |
| [**NoSQL Injection**](nosql/) | NoSQL injection operators, syntax variations, and blind extraction |
| [**Command Injection**](command-injection/) | OS command injection chaining, filter evasion, and shell-specific mutations |
| [**XSS**](xss/) | Cross-Site Scripting context-dependent payloads and filter bypass |
| [**SSTI**](ssti/) | Server-Side Template Injection across template engines |
| [**EL Injection**](el-injection/) | Expression Language injection in Java EE / Spring ecosystems |
| [**XXE**](xxe/) | XML External Entity injection, OOB exfiltration, and parser differentials |
| [**LDAP / XPath Injection**](ldap-xpath/) | LDAP and XPath query injection mutation taxonomy |
| [**Prototype Pollution**](prototype-pollution/) | JavaScript prototype chain pollution vectors and gadget chains |
| [**GraphQL**](graphql/) | GraphQL introspection abuse, batching attacks, and injection vectors |

### Authentication & Authorization
| Category | Description |
|---|---|
| [**Authentication Bypass & SSO**](authentication-bypass-and-sso/) | Single Sign-On and authentication bypass patterns |
| [**OAuth**](oauth/) | OAuth 2.0 flow exploitation and token theft patterns |
| [**JWT**](jwt/) | JSON Web Token algorithm confusion, key injection, and claim abuse |
| [**SAML**](saml/) | SAML assertion forgery, signature wrapping, and parser differentials |
| [**Cookie**](cookie/) | Cookie security bypass, scope confusion, and injection techniques |
| [**CSRF**](csrf/) | Cross-Site Request Forgery token bypass and SameSite evasion |
| [**CORS Misconfiguration**](cors-misconfiguration/) | Cross-Origin Resource Sharing misconfig exploitation patterns |
| [**IDOR / BOLA**](idor-bola/) | Broken Object Level Authorization and reference manipulation |
| [**Account Takeover**](account-takeover/) | Authentication bypass chains and account recovery exploitation |
| [**Mass Assignment**](mass-assignment/) | Parameter binding abuse and hidden field injection |

### HTTP & Protocol Layer
| Category | Description |
|---|---|
| [**HTTP Request Smuggling**](http-parsing-discrepancy/) | HTTP parsing discrepancies, desync attacks, and CL/TE mutations |
| [**HTTP Header**](http-header/) | HTTP header injection, smuggling, and semantic abuse |
| [**HTTP Parameter Pollution**](http-parameter-pollution/) | Parameter parsing discrepancy across backends and frameworks |
| [**Reverse Proxy Misrouting**](http-parsing-discrepancy/) | Proxy path confusion, hop-by-hop abuse, and routing attacks |
| [**Protocol-Level WAF Bypass**](http-parsing-discrepancy/) | HTTP protocol-layer WAF evasion techniques |
| [**HTTP Censorship Bypass**](http-parsing-discrepancy/) | Censorship infrastructure bypass via protocol-level mutations |
| [**WebSocket**](websocket/) | WebSocket handshake abuse, hijacking, and cross-site attacks |
| [**DNS Web Security**](dns-web-security/) | DNS rebinding, subdomain takeover, and resolver abuse |

### Server-Side Attacks
| Category | Description |
|---|---|
| [**SSRF**](ssrf/) | Server-Side Request Forgery bypass taxonomy and cloud metadata exploitation |
| [**File Upload**](file-upload/) | File upload restriction bypass mutations and content-type confusion |
| [**Deserialization**](deserialization/) | Deserialization gadget chains, format-specific attacks, and bypass taxonomy |
| [**JNDI Injection**](jndi-injection/) | JNDI lookup exploitation (Log4Shell class) and remote class loading |
| [**RMI**](rmi/) | Java Remote Method Invocation attack surface and registry abuse |
| [**JDBC Attack**](jdbc-attack/) | JDBC connection string injection and driver-specific exploitation |
| [**JAAS Attack**](jaas-attack/) | Java Authentication & Authorization Service bypass patterns |
| [**Email Smuggling**](email/) | Email header injection, SMTP smuggling, and parser abuse |

### Client-Side & UI
| Category | Description |
|---|---|
| [**UI Redressing**](ui-redressing/) | Clickjacking, drag-and-drop hijacking, and UI deception techniques |
| [**Open Redirect**](open-redirect/) | URL redirect bypass techniques and chaining with other vulns |
| [**Secondary Context Attack**](secondary-context-attack/) | Cross-context injection and inter-component trust abuse |

### Encoding & Parser Differential
| Category | Description |
|---|---|
| [**URL Confusion**](url-confusion/) | URL parser inconsistency attacks and normalization differentials |
| [**Unicode**](unicode/) | Unicode normalization, case mapping, encoding attacks, and visual spoofing |
| [**ZIP Archive**](zip-archive/) | Archive parsing differentials, path traversal, and Zip Slip exploitation |

### Application Logic
| Category | Description |
|---|---|
| [**Business Logic Vulnerabilities**](business-logic-bug/) | Application logic flaw patterns and state manipulation |
| [**State Machine Violation**](state-machine-violation/) | Workflow state bypass and process order manipulation |
| [**Web Race Condition**](web-race-condition/) | Concurrency exploitation, TOCTOU attacks, and limit-overrun |
| [**Web Timing Attack**](web-timing-attack/) | Timing side-channels for enumeration and state inference |
| [**Implicit Trust Boundary**](implicit-trust-boundary/) | Undocumented trust relationships and boundary crossing attacks |

### Infrastructure & Supply Chain
| Category | Description |
|---|---|
| [**Dependency Confusion**](dependency-confusion/) | Package manager namespace attacks and supply chain injection |
| [**Web Cache Poisoning & Deception**](web-cache-poisoning-and-deception/) | Cache key manipulation, unkeyed input abuse, and cache deception |
| [**WAF Bypass (Payload-Level)**](waf-bypass/) | Payload-level WAF evasion — encoding, chunking, and format tricks |

### Framework-Specific
| Category | Description |
|---|---|
| [**Spring**](spring/) | Spring Framework-specific attack surface and misconfiguration |
| [**ASP.NET**](asp-dot-net/) | ASP.NET specific vulnerabilities and exploitation patterns |

### Recon & Methodology
| Category | Description |
|---|---|
| [**Web Fingerprinting**](web-fingerprinting/) | Server and application fingerprinting techniques |
| [**Web Fuzzing**](web-fuzzing/) | Web fuzzing strategies, wordlist generation, and parameter discovery |
| [**Hidden Parameter Discovery**](recon/) | Undocumented parameter and endpoint enumeration |
| [**Sam Curry Style Bugs**](sam-curry/) | Real-world business logic and API misconfig case studies |
| [**Attack Style Taxonomy**](application-example/) | Cross-vulnerability attack pattern classification |

---

## Purpose — A Knowledge Base for AI Agents and Security Tooling

This repository is designed to serve as a **machine-readable security knowledge base**. The structured, generalized taxonomy format makes it a natural foundation for:

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
