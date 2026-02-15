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

### 01. Injection
| Category | Description |
|---|---|
| [**SQL Injection**](01-injection/sql-injection/sql-injection.md) | SQL injection mutation vectors and filter bypass taxonomy |
| [**NoSQL Injection**](01-injection/nosql/nosql-injection.md) | NoSQL injection operators, syntax variations, and blind extraction |
| [**Command Injection**](01-injection/command-injection/command-injection.md) | OS command injection chaining, filter evasion, and shell-specific mutations |
| [**XSS**](01-injection/xss/xss.md) | Cross-Site Scripting context-dependent payloads and filter bypass |
| [**SSTI**](01-injection/ssti/ssti.md) | Server-Side Template Injection across template engines |
| [**EL Injection**](01-injection/el-injection/el-injection.md) | Expression Language injection in Java EE / Spring ecosystems |
| [**XXE**](01-injection/xxe/xxe.md) | XML External Entity injection, OOB exfiltration, and parser differentials |
| [**LDAP / XPath Injection**](01-injection/ldap-xpath/ldap-xpath.md) | LDAP and XPath query injection mutation taxonomy |
| [**Prototype Pollution**](01-injection/prototype-pollution/prototype-pollution.md) | JavaScript prototype chain pollution vectors and gadget chains |
| [**GraphQL**](01-injection/graphql/graphql.md) | GraphQL introspection abuse, batching attacks, and injection vectors |

### 02. Authentication & Authorization
| Category | Description |
|---|---|
| [**Authentication Bypass & SSO**](02-auth/authentication-bypass-and-sso/authentication-bypass-and-sso.md) | Single Sign-On and authentication bypass patterns |
| [**OAuth**](02-auth/oauth/oauth.md) | OAuth 2.0 flow exploitation and token theft patterns |
| [**JWT**](02-auth/jwt/jwt.md) | JSON Web Token algorithm confusion, key injection, and claim abuse |
| [**SAML**](02-auth/saml/saml.md) | SAML assertion forgery, signature wrapping, and parser differentials |
| [**Cookie**](02-auth/cookie/cookie.md) | Cookie security bypass, scope confusion, and injection techniques |
| [**CSRF**](02-auth/csrf/csrf.md) | Cross-Site Request Forgery token bypass and SameSite evasion |
| [**CORS Misconfiguration**](02-auth/cors-misconfiguration/cors-misconfiguration.md) | Cross-Origin Resource Sharing misconfig exploitation patterns |
| [**IDOR / BOLA**](02-auth/idor-bola/idor-bola.md) | Broken Object Level Authorization and reference manipulation |
| [**Account Takeover**](02-auth/account-takeover/account-takeover.md) | Authentication bypass chains and account recovery exploitation |
| [**Mass Assignment**](02-auth/mass-assignment/mass-assignment.md) | Parameter binding abuse and hidden field injection |

### 03. HTTP & Protocol Layer
| Category | Description |
|---|---|
| [**HTTP Request Smuggling**](03-http-protocol/http-parsing-discrepancy/http-request-smuggling.md) | HTTP parsing discrepancies, desync attacks, and CL/TE mutations |
| [**HTTP Header**](03-http-protocol/http-header/http-header.md) | HTTP header injection, smuggling, and semantic abuse |
| [**HTTP Parameter Pollution**](03-http-protocol/http-parameter-pollution/http-parameter-pollution.md) | Parameter parsing discrepancy across backends and frameworks |
| [**WebSocket**](03-http-protocol/websocket/websocket.md) | WebSocket handshake abuse, hijacking, and cross-site attacks |
| [**gRPC / tRPC**](03-http-protocol/grpc-and-trpc/grpc-and-trpc.md) | gRPC and tRPC protocol exploitation and security patterns |
| [**DNS Web Security**](03-http-protocol/dns-web-security/dns-web-security.md) | DNS rebinding, subdomain takeover, and resolver abuse |

### 04. Server-Side Attacks
| Category | Description |
|---|---|
| [**SSRF**](04-server-side/ssrf/ssrf.md) | Server-Side Request Forgery bypass taxonomy and cloud metadata exploitation |
| [**Path Traversal**](04-server-side/path-traversal/path-traversal.md) | Directory traversal, path normalization bypass, and file access attacks |
| [**File Upload**](04-server-side/file-upload/file-upload.md) | File upload restriction bypass mutations and content-type confusion |
| [**Deserialization**](04-server-side/deserialization/deserialization.md) | Deserialization gadget chains, format-specific attacks, and bypass taxonomy |
| [**JNDI Injection**](04-server-side/jndi-injection/jndi-injection.md) | JNDI lookup exploitation (Log4Shell class) and remote class loading |
| [**RMI**](04-server-side/rmi/rmi.md) | Java Remote Method Invocation attack surface and registry abuse |
| [**JDBC Attack**](04-server-side/jdbc-attack/jdbc-attack.md) | JDBC connection string injection and driver-specific exploitation |
| [**JAAS Attack**](04-server-side/jaas-attack/jaas-attack.md) | Java Authentication & Authorization Service bypass patterns |
| [**Email Smuggling**](04-server-side/email/email-smuggling-and-parser-abuse.md) | Email header injection, SMTP smuggling, and parser abuse |

### 05. Client-Side & UI
| Category | Description |
|---|---|
| [**UI Redressing**](05-client-side/ui-redressing/ui-redressing.md) | Clickjacking, drag-and-drop hijacking, and UI deception techniques |
| [**Open Redirect**](05-client-side/open-redirect/open-redirect.md) | URL redirect bypass techniques and chaining with other vulns |
| [**Secondary Context Attack**](05-client-side/secondary-context-attack/secondary-context-attack.md) | Cross-context injection and inter-component trust abuse |
| [**Client-Side Web Security**](05-client-side/client-side-web-security/client-side-web-security.md) | Client-side security vulnerabilities and exploitation patterns |
| [**Browser Security Model**](05-client-side/browser-security-model/browser-security-model.md) | Browser security model bypass and same-origin policy violations |
| [**Browser Extension Security**](05-client-side/browser-extension-security/browser-extension-security.md) | Browser extension vulnerabilities and attack surface |
| [**Service Worker**](05-client-side/service-worker/service-worker.md) | Service Worker security issues and exploitation techniques |
| [**XS-Leak**](05-client-side/xs-leak/xs-leak.md) | Cross-site leak attacks and timing side-channels |

### 06. Encoding & Parser Differential
| Category | Description |
|---|---|
| [**URL Confusion**](06-encoding-parser/url-confusion/url-confusion.md) | URL parser inconsistency attacks and normalization differentials |
| [**Unicode**](06-encoding-parser/unicode/unicode.md) | Unicode normalization, case mapping, encoding attacks, and visual spoofing |
| [**ZIP Archive**](06-encoding-parser/zip-archive/zip-archive.md) | Archive parsing differentials, path traversal, and Zip Slip exploitation |

### 07. Application Logic
| Category | Description |
|---|---|
| [**Business Logic Vulnerabilities**](07-application-logic/business-logic-bug/business-logic-bug.md) | Application logic flaw patterns and state manipulation |
| [**State Machine Violation**](07-application-logic/state-machine-violation/state-machine-violation.md) | Workflow state bypass and process order manipulation |
| [**Web Race Condition**](07-application-logic/web-race-condition/web-race-condition.md) | Concurrency exploitation, TOCTOU attacks, and limit-overrun |
| [**Web Timing Attack**](07-application-logic/web-timing-attack/web-timing-attack.md) | Timing side-channels for enumeration and state inference |
| [**Implicit Trust Boundary**](07-application-logic/implicit-trust-boundary/implicit-trust-boundary.md) | Undocumented trust relationships and boundary crossing attacks |

### 08. Infrastructure & Supply Chain
| Category | Description |
|---|---|
| [**Dependency Confusion**](08-infrastructure/dependency-confusion/dependency-confusion.md) | Package manager namespace attacks and supply chain injection |
| [**Web Cache Poisoning & Deception**](08-infrastructure/web-cache-poisoning-and-deception/web-cache-poisoning-and-deception.md) | Cache key manipulation, unkeyed input abuse, and cache deception |
| [**WAF Bypass (Payload-Level)**](08-infrastructure/waf-bypass/waf-bypass.md) | Payload-level WAF evasion — encoding, chunking, and format tricks |
| [**CI/CD Pipeline Security**](08-infrastructure/ci-cd-pipeline-security/ci-cd-pipeline-security.md) | CI/CD pipeline vulnerabilities and supply chain attacks |
| [**API Inventory Management**](08-infrastructure/api-inventory-management/api-inventory-management.md) | API discovery, shadow APIs, and inventory management security |

### 09. Framework-Specific
| Category | Description |
|---|---|
| [**Spring**](09-frameworks/spring/spring.md) | Spring Framework-specific attack surface and misconfiguration |
| [**ASP.NET**](09-frameworks/asp-dot-net/asp-dot-net.md) | ASP.NET specific vulnerabilities and exploitation patterns |

### 10. Recon & Methodology
| Category | Description |
|---|---|
| [**Web Fingerprinting**](10-recon-methodology/web-fingerprinting/web-fingerprinting.md) | Server and application fingerprinting techniques |
| [**Web Fuzzing**](10-recon-methodology/web-fuzzing/web-fuzzing.md) | Web fuzzing strategies, wordlist generation, and parameter discovery |
| [**Hidden Parameter Discovery**](10-recon-methodology/recon/recon.md) | Undocumented parameter and endpoint enumeration |
| [**CTF Exotic Tricks**](10-recon-methodology/ctf-exotic-tricks/ctf-exotic-tricks.md) | Unconventional exploitation techniques from CTF competitions |

### 11. Security Researchers
| Researcher | Focus Areas |
|---|---|
| [**Sam Curry**](11-researchers/sam-curry/sam-curry.md) | Real-world business logic and API misconfig case studies |
| [**Orange Tsai**](11-researchers/orange-tsai/orange-tsai.md) | Advanced web exploitation and novel attack chains |
| [**Frans Rosén**](11-researchers/frans-rosen/frans-rosen.md) | Browser security and innovative client-side attacks |
| [**LiveOverflow**](11-researchers/liveoverflow/liveoverflow.md) | Security research insights and exploitation techniques |
| [**Soroush Dalili**](11-researchers/soroush-dalili/soroush-dalili.md) | IIS exploitation and web application security research |

### Artifact Examples
| Category | Description |
|---|---|
| [**Artifact Examples**](artifact-examples/) | Generated security tooling examples and proof-of-concepts (directory index) |

---

## Purpose — An Intermediate Representation for Security Knowledge

In a compiler, source code is transformed into an **Intermediate Representation (IR)** before being compiled into machine code for any target architecture. The Map serves the same role for security knowledge:

```
Security Research (papers, CVEs, writeups, conference talks)
        |
        v
    The Map (IR) — structured mutation taxonomy
        |
        v
  Burp Suite plugin / Nuclei template / WAF rule / bchecks / DAST scanner / AI agent
```

Raw security research — scattered across academic papers, blog posts, conference talks, and bug bounty reports — is valuable but not directly actionable. The Map compiles this knowledge into a **structured, machine-readable intermediate form** where every mutation variant is classified by what is mutated, why it works, and where it applies. From this IR, any number of output formats can be generated:

| Input (IR) | Output |
|---|---|
| `jwt/jwt.md` § Algorithm Confusion | Burp Scanner check for `alg` header manipulation |
| `cookie/cookie.md` § Cookie Sandwich | Nuclei template detecting RFC 2109 parsing quirks |
| `xss/xss.md` § Encoding Differentials | WAF rule set covering context-specific bypass variants |
| `ssrf/ssrf.md` § IP Representation | bchecks collection for SSRF filter bypass mutations |
| `smuggling/...` § CL.TE / TE.CL | DAST scanner test cases for HTTP desync |
| Any taxonomy document | AI agent context for automated penetration testing |

Each row in each taxonomy table is simultaneously a **test case** (offensive), a **detection signature** (defensive), and a **fuzzer seed** (discovery). Structure the knowledge once, compile it to any target.

### What this enables

- **AI Security Agents** — LLM-based agents consume these taxonomies as structured domain knowledge to reason about vulnerability classes, generate test cases, and guide penetration testing workflows — replacing ad-hoc prompting with systematic mutation coverage.
- **Security Tooling Pipeline** — Feed a taxonomy document into Claude Code and generate Burp Suite extensions, Nuclei templates, Semgrep rules, WAF configurations, or bchecks — each mutation variant maps directly to a concrete check.
- **Taxonomy & Classification** — A unified structural framework for organizing vulnerability research that goes beyond surface-level categorization (e.g., OWASP Top 10) into mutation-level granularity.
- **Fuzzer Seed Generation** — Mutation catalogs provide systematic seed corpora for fuzzers. Instead of random mutations, fuzzers can target specific structural variations documented in each taxonomy.
- **Security Research** — A reference framework for researchers to identify gaps in existing coverage, discover unexplored mutation combinations, and build on prior work systematically.
- **Novel Variant Discovery** — Because the taxonomy is organized by mutation axes rather than known payloads, it enables reasoning about **unexplored combinations** — mutations that should theoretically work but haven't been documented yet.

## How it was built

Every document in this repository was researched and synthesized using **Claude Code** (Anthropic's AI coding agent). The process involved systematic multi-source research — academic papers, conference talks (BlackHat, DEF CON), CVE databases, bug bounty reports, and tooling documentation — then synthesized into unified taxonomy documents organized by generalized structural criteria.

## Structure

```
the-map/
  ├── 01-injection/              # Injection attacks (SQL, NoSQL, XSS, etc.)
  ├── 02-auth/                   # Authentication & Authorization
  ├── 03-http-protocol/          # HTTP & Protocol Layer attacks
  ├── 04-server-side/            # Server-side vulnerabilities
  ├── 05-client-side/            # Client-side & Browser attacks
  ├── 06-encoding-parser/        # Encoding & Parser differentials
  ├── 07-application-logic/      # Business logic vulnerabilities
  ├── 08-infrastructure/         # Infrastructure & Supply Chain
  ├── 09-frameworks/             # Framework-specific vulnerabilities
  ├── 10-recon-methodology/      # Reconnaissance & Methodology
  ├── 11-researchers/            # Security researcher case studies
  ├── artifact-examples/         # Generated tooling examples
  └── README.md
```

Each category contains related vulnerability classes, with each `.md` file following a consistent three-axis classification:
1. **Axis 1 — Mutation Target**: What structural component is manipulated
2. **Axis 2 — Discrepancy Type**: What mismatch or bypass the mutation creates
3. **Axis 3 — Attack Scenario**: Real-world exploitation context mapping

## License

This is a security research reference. Use responsibly for authorized testing, defensive security, and education.
