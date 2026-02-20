# The Map
### Web Security Vulnerability Knowledge Base — Mutation Taxonomy & Attack Surface Reference

A structured, comprehensive vulnerability mutation taxonomy collection for security researchers, penetration testers, bug bounty hunters, and AI security agents — built with [Claude Code](https://claude.ai/claude-code).

> **Keywords**: web security knowledge base, vulnerability taxonomy, attack surface mapping, mutation catalog, penetration testing reference, bug bounty methodology, security research database, exploit variation matrix, web hacking cheatsheet, OWASP vulnerability classification, offensive security reference

---

## What is this?

**The Map** is a **security knowledge base** that systematically classifies 100+ web vulnerability classes across 12 categories. Unlike conventional cheatsheets or CVE lists, each topic is organized by **structural mutation criteria** — what is mutated, what discrepancy it creates, and where it is weaponized.

Each topic is a deeply structured Markdown reference document covering the full attack surface of a vulnerability class through a three-axis taxonomy (Mutation Target, Discrepancy/Bypass Type, Attack Scenario).

---

## Topics

### 01. Injection
| Category | Description |
|---|---|
| [**SQL Injection**](01-injection/sql-injection.md) | SQL injection mutation vectors and filter bypass taxonomy |
| [**NoSQL Injection**](01-injection/nosql-injection.md) | NoSQL injection operators, syntax variations, and blind extraction |
| [**Command Injection**](01-injection/command-injection.md) | OS command injection chaining, filter evasion, and shell-specific mutations |
| [**XSS**](01-injection/xss.md) | Cross-Site Scripting context-dependent payloads and filter bypass |
| [**SSTI**](01-injection/ssti.md) | Server-Side Template Injection across template engines |
| [**EL Injection**](01-injection/el-injection.md) | Expression Language injection in Java EE / Spring ecosystems |
| [**XXE**](01-injection/xxe.md) | XML External Entity injection, OOB exfiltration, and parser differentials |
| [**LDAP / XPath Injection**](01-injection/ldap-xpath.md) | LDAP and XPath query injection mutation taxonomy |
| [**Prototype Pollution**](01-injection/prototype-pollution.md) | JavaScript prototype chain pollution vectors and gadget chains |
| [**GraphQL**](01-injection/graphql.md) | GraphQL introspection abuse, batching attacks, and injection vectors |
| [**LaTeX Injection**](01-injection/latex-injection.md) | LaTeX injection mutation vectors and document processing exploitation |
| [**Protocol-Level Injection**](01-injection/protocol-level-injection.md) | Protocol-level injection across SMTP, LDAP, and other wire protocols |
| [**SSI / ESI / XSLT Injection**](01-injection/ssi-esi-xslt-injection.md) | Server-Side Includes, Edge Side Includes, and XSLT injection for RCE |
| [**ORM Misuse → SQL Injection**](01-injection/orm-misuse-sql-injection.md) | ORM query function misuse leading to SQL injection |
| [**CSV Formula Injection**](01-injection/csv-formula-injection.md) | Spreadsheet formula injection via CSV/Excel export functionality |
| [**CSS Injection**](01-injection/css-injection.md) | CSS-based data exfiltration and style injection attacks |

### 02. Authentication & Authorization
| Category | Description |
|---|---|
| [**Authentication Bypass & SSO**](02-auth/authentication-bypass-and-sso.md) | Single Sign-On and authentication bypass patterns |
| [**OAuth**](02-auth/oauth.md) | OAuth 2.0 flow exploitation and token theft patterns |
| [**JWT**](02-auth/jwt.md) | JSON Web Token algorithm confusion, key injection, and claim abuse |
| [**SAML**](02-auth/saml.md) | SAML assertion forgery, signature wrapping, and parser differentials |
| [**CORS Misconfiguration**](02-auth/cors-misconfiguration.md) | Cross-Origin Resource Sharing misconfig exploitation patterns |
| [**IDOR / BOLA**](02-auth/idor-bola.md) | Broken Object Level Authorization and reference manipulation |
| [**Account Takeover**](02-auth/account-takeover.md) | Authentication bypass chains and account recovery exploitation |
| [**Mass Assignment**](02-auth/mass-assignment.md) | Parameter binding abuse and hidden field injection |
| [**Cryptographic Implementation Vulnerabilities**](02-auth/cryptographic-implementation-vulnerabilities.md) | Web-context cryptographic implementation flaws and bypass patterns |

### 03. HTTP & Protocol Layer
| Category | Description |
|---|---|
| [**HTTP Request Smuggling**](03-http-protocol/http-parsing-discrepancy/http-request-smuggling.md) | HTTP parsing discrepancies, desync attacks, and CL/TE mutations |
| [**HTTP Header**](03-http-protocol/http-header.md) | HTTP header injection, smuggling, and semantic abuse |
| [**HTTP Parameter Pollution**](03-http-protocol/http-parameter-pollution.md) | Parameter parsing discrepancy across backends and frameworks |
| [**WebSocket**](03-http-protocol/websocket.md) | WebSocket handshake abuse, hijacking, and cross-site attacks |
| [**gRPC / tRPC**](03-http-protocol/grpc-and-trpc.md) | gRPC and tRPC protocol exploitation and security patterns |
| [**Reverse Proxy Misrouting**](03-http-protocol/http-parsing-discrepancy/reverse-proxy-misrouting.md) | Reverse proxy path normalization discrepancies and access control bypass |
| [**Protocol-Level WAF Bypass**](03-http-protocol/http-parsing-discrepancy/protocol-level-waf-bypass.md) | Protocol-level WAF evasion via HTTP parsing differentials |
| [**HTTP Censorship Bypass**](03-http-protocol/http-parsing-discrepancy/http-censorship-bypass.md) | HTTP-based censorship circumvention techniques |
| [**HTTP/3 QUIC Protocol Smuggling**](03-http-protocol/http-parsing-discrepancy/http3-quic-protocol-smuggling.md) | HTTP/3 and QUIC protocol-level smuggling and parsing differentials |

### 04. Server-Side Attacks
| Category | Description |
|---|---|
| [**SSRF**](04-server-side/ssrf.md) | Server-Side Request Forgery bypass taxonomy and cloud metadata exploitation |
| [**Path Traversal**](04-server-side/path-traversal.md) | Directory traversal, path normalization bypass, and file access attacks |
| [**File Upload**](04-server-side/file-upload.md) | File upload restriction bypass mutations and content-type confusion |
| [**Deserialization**](04-server-side/deserialization.md) | Deserialization gadget chains, format-specific attacks, and bypass taxonomy |
| [**JNDI Injection**](04-server-side/jndi-injection.md) | JNDI lookup exploitation (Log4Shell class) and remote class loading |
| [**RMI**](04-server-side/rmi.md) | Java Remote Method Invocation attack surface and registry abuse |
| [**JDBC Attack**](04-server-side/jdbc-attack.md) | JDBC connection string injection and driver-specific exploitation |
| [**JAAS Attack**](04-server-side/jaas-attack.md) | Java Authentication & Authorization Service bypass patterns |
| [**Email Smuggling**](04-server-side/email-smuggling-and-parser-abuse.md) | Email header injection, SMTP smuggling, and parser abuse |
| [**File Download**](04-server-side/file-download.md) | Arbitrary file download, forced download, and file access control bypass |
| [**Arbitrary File Write → RCE**](04-server-side/arbitrary-file-write-to-rce.md) | Cross-platform arbitrary file write to RCE chain taxonomy |
| [**Document & Media Processing RCE**](04-server-side/document-media-processing-library-rce.md) | Document/media processing library exploitation (ImageMagick, Ghostscript, etc.) |
| [**JMX Attack**](04-server-side/jmx-attack.md) | Java Management Extensions attack surface and MBean abuse |
| [**HTTP Pipelining Attack**](04-server-side/http-pipelining-attack.md) | HTTP pipelining abuse, response queue poisoning, and desync attacks |
| [**Arbitrary Object Instantiation**](04-server-side/arbitrary-object-instantiation.md) | Arbitrary object instantiation and class loading exploitation |

### 05. Client-Side & UI
| Category | Description |
|---|---|
| [**Cookie Security**](05-client-side/cookie.md) | Cookie security bypass, scope confusion, and injection techniques |
| [**CSRF**](05-client-side/csrf.md) | Cross-Site Request Forgery token bypass and SameSite evasion |
| [**UI Redressing**](05-client-side/ui-redressing.md) | Clickjacking, drag-and-drop hijacking, and UI deception techniques |
| [**Open Redirect**](05-client-side/open-redirect.md) | URL redirect bypass techniques and chaining with other vulns |
| [**Browser Security Model**](05-client-side/browser-security-model.md) | Browser security model bypass and same-origin policy violations |
| [**Browser Extension Security**](05-client-side/browser-extension-security.md) | Browser extension vulnerabilities and attack surface |
| [**DOM Clobbering**](05-client-side/dom-clobbering.md) | DOM Clobbering attacks via named access and prototype chain pollution |
| [**Service Worker**](05-client-side/service-worker.md) | Service Worker security issues and exploitation techniques |
| [**XS-Leak**](05-client-side/xs-leak.md) | Cross-site leak attacks and timing side-channels |
| [**Mutation XSS (mXSS)**](05-client-side/mutation-xss.md) | DOM mutation-based XSS via sanitizer/parser differentials |
| [**Universal XSS (uXSS)**](05-client-side/universal-xss.md) | Browser-level universal XSS vulnerabilities |
| [**Cross-Site Script Inclusion (XSSI)**](05-client-side/cross-site-script-inclusion.md) | Cross-site script inclusion and JSONP data theft |
| [**Relative Path Overwrite (RPO)**](05-client-side/rpo.md) | Relative path overwrite for stylesheet injection and content hijacking |
| [**Desktop & Hybrid App Security**](05-client-side/desktop-hybrid-app-security.md) | Electron, CEF, and desktop/hybrid application security |

### 06. Encoding & Parser Differential
| Category | Description |
|---|---|
| [**URL Confusion**](06-encoding-parser/url-confusion.md) | URL parser inconsistency attacks and normalization differentials |
| [**Unicode**](06-encoding-parser/unicode.md) | Unicode normalization, case mapping, encoding attacks, and visual spoofing |
| [**Type Confusion & Coercion**](06-encoding-parser/type-confusion-and-coercion.md) | Type confusion, coercion abuse, and implicit conversion vulnerabilities |
| [**ZIP Archive**](06-encoding-parser/zip-archive.md) | Archive parsing differentials, path traversal, and Zip Slip exploitation |

### 07. Application Logic
| Category | Description |
|---|---|
| [**Business Logic Vulnerabilities**](07-application-logic/business-logic-bug.md) | Application logic flaw patterns and state manipulation |
| [**State Machine Violation**](07-application-logic/state-machine-violation.md) | Workflow state bypass and process order manipulation |
| [**Web Race Condition**](07-application-logic/web-race-condition.md) | Concurrency exploitation, TOCTOU attacks, and limit-overrun |
| [**Web Timing Attack**](07-application-logic/web-timing-attack.md) | Timing side-channels for enumeration and state inference |
| [**Implicit Trust Boundary**](07-application-logic/implicit-trust-boundary.md) | Undocumented trust relationships and boundary crossing attacks |
| [**Numeric & Boundary Logic**](07-application-logic/numeric-and-boundary-logic.md) | Integer overflow, boundary value abuse, and numeric logic flaws |

### 08. Infrastructure & Supply Chain
| Category | Description |
|---|---|
| [**Dependency Confusion**](08-infrastructure/dependency-confusion.md) | Package manager namespace attacks and supply chain injection |
| [**Web Cache Poisoning & Deception**](08-infrastructure/web-cache-poisoning-and-deception.md) | Cache key manipulation, unkeyed input abuse, and cache deception |
| [**WAF Bypass (Payload-Level)**](08-infrastructure/waf-bypass.md) | Payload-level WAF evasion — encoding, chunking, and format tricks |
| [**CI/CD Pipeline Security**](08-infrastructure/ci-cd-pipeline-security.md) | CI/CD pipeline vulnerabilities and supply chain attacks |
| [**API Inventory Management**](08-infrastructure/api-inventory-management.md) | API discovery, shadow APIs, and inventory management security |
| [**Container & Orchestration RCE**](08-infrastructure/container-orchestration-infrastructure-rce.md) | Container escape, Kubernetes exploitation, and orchestration infrastructure RCE |
| [**Developer Toolchain & Build System RCE**](08-infrastructure/developer-toolchain-build-system-rce.md) | Build tool, IDE plugin, and developer toolchain exploitation for RCE |
| [**Nginx Vulnerability Taxonomy**](08-infrastructure/nginx-vulnerability-taxonomy.md) | Nginx-specific misconfigurations, alias traversal, and off-by-slash attacks |
| [**Jetty Vulnerability Taxonomy**](08-infrastructure/jetty-vulnerability-taxonomy.md) | Eclipse Jetty-specific vulnerabilities and exploitation patterns |
| [**Secondary Context Attack**](08-infrastructure/secondary-context-attack.md) | Cross-context injection and inter-component trust abuse |

### 09. Frameworks & Languages
| Category | Description |
|---|---|
| [**Spring**](09-frameworks-and-languages/spring.md) | Spring Framework-specific attack surface and misconfiguration |
| [**ASP.NET**](09-frameworks-and-languages/asp-dot-net.md) | ASP.NET specific vulnerabilities and exploitation patterns |
| [**PHP**](09-frameworks-and-languages/php.md) | PHP-specific vulnerabilities, type juggling, and deserialization |
| [**Ruby on Rails**](09-frameworks-and-languages/ruby-on-rails.md) | Rails-specific vulnerabilities, mass assignment, and ERB injection |
| [**Django**](09-frameworks-and-languages/django.md) | Django-specific vulnerabilities and ORM exploitation |
| [**Symfony**](09-frameworks-and-languages/symfony.md) | Symfony framework-specific vulnerabilities and exploitation |
| [**Next.js**](09-frameworks-and-languages/nextjs.md) | Next.js SSR/SSG security patterns and middleware bypass |
| [**Modern JS Frameworks**](09-frameworks-and-languages/modern-js-frameworks.md) | React, Angular, Vue security patterns and SSR vulnerabilities |
| [**Adobe Experience Manager (AEM)**](09-frameworks-and-languages/aem.md) | AEM-specific attack surface, dispatcher bypass, and OSGi exploitation |
| [**Salesforce Lightning Platform**](09-frameworks-and-languages/salesforce-lightning-platform-security.md) | Salesforce Lightning security, Aura/LWC exploitation, and SOQL injection |
| [**SAP**](09-frameworks-and-languages/sap.md) | SAP-specific web vulnerabilities and exploitation patterns |
| [**ORM Leak**](09-frameworks-and-languages/orm-leak.md) | ORM information leakage and query manipulation patterns |

### 10. Recon & Methodology
| Category | Description |
|---|---|
| [**Web Fingerprinting**](10-recon-methodology/web-fingerprinting.md) | Server and application fingerprinting techniques |
| [**Web Fuzzing**](10-recon-methodology/web-fuzzing.md) | Web fuzzing strategies, wordlist generation, and parameter discovery |
| [**Reconnaissance**](10-recon-methodology/recon.md) | Undocumented parameter and endpoint enumeration |

### 11. Security Researchers
| Researcher | Focus Areas |
|---|---|
| [**Sam Curry**](11-researchers/sam-curry.md) | Real-world business logic and API misconfig case studies |
| [**Orange Tsai**](11-researchers/orange-tsai.md) | Advanced web exploitation and novel attack chains |
| [**Frans Rosén**](11-researchers/frans-rosen.md) | Browser security and innovative client-side attacks |
| [**LiveOverflow**](11-researchers/liveoverflow.md) | Security research insights and exploitation techniques |
| [**Soroush Dalili**](11-researchers/soroush-dalili.md) | IIS exploitation and web application security research |

### 12. Miscellaneous
| Category | Description |
|---|---|
| [**AI/LLM Security**](12-misc/ai-llm-security.md) | AI/LLM prompt injection, jailbreak, agent exploitation, and model security |
| [**Web Application DoS**](12-misc/web-application-dos.md) | Application-layer denial of service via ReDoS, hash collision, resource exhaustion |
| [**DNS Web Security**](12-misc/dns-web-security.md) | DNS rebinding, subdomain takeover, and resolver abuse |
| [**WordPress**](12-misc/wordpress.md) | WordPress-specific vulnerabilities, plugin exploitation, and misconfigurations |
| [**NAT Slipstreaming**](12-misc/nat-slipstreaming.md) | NAT/firewall bypass via browser-initiated protocol confusion |
| [**Dynamic Rendering Engine Exploitation**](12-misc/dynamic-rendering-engine-exploitation.md) | Headless browser and dynamic rendering engine exploitation |
| [**CTF Exotic Tricks**](12-misc/ctf-exotic-tricks.md) | Unconventional exploitation techniques from CTF competitions |

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
  ├── 01-injection/              # Injection attacks (16 topics)
  ├── 02-auth/                   # Authentication & Authorization (9 topics)
  ├── 03-http-protocol/          # HTTP & Protocol Layer attacks (9 topics)
  │   └── http-parsing-discrepancy/  # HTTP parsing differential sub-category
  ├── 04-server-side/            # Server-side vulnerabilities (15 topics)
  ├── 05-client-side/            # Client-side & Browser attacks (14 topics)
  ├── 06-encoding-parser/        # Encoding & Parser differentials (4 topics)
  ├── 07-application-logic/      # Business logic vulnerabilities (6 topics)
  ├── 08-infrastructure/         # Infrastructure & Supply Chain (10 topics)
  ├── 09-frameworks-and-languages/  # Framework & Language-specific (12 topics)
  ├── 10-recon-methodology/      # Reconnaissance & Methodology (3 topics)
  ├── 11-researchers/            # Security researcher case studies (5 topics)
  ├── 12-misc/                   # Miscellaneous (7 topics)
  ├── skills/                    # Claude Code skill definitions (9 skills)
  ├── artifact-examples/         # Generated tooling examples & visualizations
  └── README.md
```

Each category contains related vulnerability classes, with each `.md` file following a consistent three-axis classification:
1. **Axis 1 — Mutation Target**: What structural component is manipulated
2. **Axis 2 — Discrepancy Type**: What mismatch or bypass the mutation creates
3. **Axis 3 — Attack Scenario**: Real-world exploitation context mapping

## License

This is a security research reference. Use responsibly for authorized testing, defensive security, and education.
