# The Map — Root-Cause Web Attack Taxonomy

> A root-cause-based classification of all attack techniques documented across the project.
> Unlike kill-chain models (MITRE ATT&CK), this taxonomy groups techniques by **why the vulnerability exists** — the fundamental security principle violated — making it directly actionable for both offensive testing and defensive hardening.

---

## Why Root-Cause Over Kill-Chain?

| Dimension | Kill-Chain (MITRE ATT&CK Style) | Root-Cause (This Taxonomy) |
|---|---|---|
| **Top-level axis** | Attacker's objective (Initial Access, Execution, ...) | Why the vulnerability exists |
| **Same technique** | Scattered across multiple tactics (SQLi in Initial Access, Execution, Collection, Exfiltration) | Unified under one root cause (Injection) |
| **Red Team utility** | "What phase am I in?" | "I found an injection point — what are ALL my options?" |
| **Blue Team utility** | "Which phase to detect?" | "How do I eliminate this entire class of vulnerability?" |
| **Deduplication** | Same technique repeated under 3-4 tactics | Each technique appears once, with impact cross-references |

---

## How to Read This Document

| Element | Format | Example |
|---------|--------|---------|
| **Root Cause** | `RC#` | `RC1` — Injection |
| **Technique Class** | `RC#.T##` | `RC1.T01` — SQL Injection |
| **Variant** | `RC#.T##.V##` | `RC1.T01.V01` — WHERE Clause Tautology |
| **Source Document** | `[doc-name]` | Links to original mutation taxonomy file |
| **Secondary RC** | `→ RC#` | Cross-reference to other root causes involved |

---

## Root Cause Overview Matrix

| ID | Root Cause | Core Principle Violated | Technique Count | Key Sources |
|---|---|---|---|---|
| **RC1** | Injection — Data/Control Plane Confusion | Input/output separation | 13 classes | [sql-injection], [xss], [ssti], [xxe], [command-injection], ... |
| **RC2** | Parser & Processing Differential | Consistent interpretation | 12 classes | [http-request-smuggling], [url-confusion], [unicode], [hpp], ... |
| **RC3** | Authentication & Credential Integrity Failure | Identity verification | 9 classes | [jwt], [saml], [oauth], [ato], [cookie], ... |
| **RC4** | Access Control & Authorization Gap | Authorization enforcement | 6 classes | [idor-bola], [mass-assignment], [cors-misconfiguration], ... |
| **RC5** | State, Workflow & Concurrency Violation | State integrity | 6 classes | [state-machine-violation], [web-race-condition], [csrf], [business-logic-vuln], ... |
| **RC6** | Unsafe Deserialization & Object Reconstruction | Data/code separation | 8 classes | [deserialization], ... |
| **RC7** | Unvalidated Resource Reference | Reference validation | 6 classes | [ssrf], [open-redirect], [file-upload], [rmi], [jdbc-attack], ... |
| **RC8** | Trust Boundary & Isolation Failure | Trust verification | 8 classes | [implicit-trust-boundary], [secondary-context-attack], [dns-web-security], [dependency-confusion], ... |
| **RC9** | Information Leakage & Side-Channel | Information minimization | 7 classes | [web-timing-attack], [web-fingerprinting], [web-cache-poisoning-and-deception], ... |
| — | Cross-Cutting: Security Control Evasion | Defense completeness | 7 classes | [waf-bypass], [cookie], [ui-redressing], ... |
| — | Cross-Cutting: Reconnaissance & Methodology | — | 4 classes | [web-fingerprinting], [web-fuzzing], [recon], [sam-curry] |

---

## RC1 — Injection: Data/Control Plane Confusion

*Untrusted input is interpreted as part of a control language, command syntax, or structural markup.*

**Core Pattern**: The application constructs executable statements/markup by concatenating user input, allowing the attacker to break out of the data context and inject control syntax.

> **Red Team**: Identify every point where user input enters an interpreter (SQL engine, shell, template engine, HTML renderer, XML parser, LDAP server). Test for context escape using that interpreter's metacharacters.
> **Blue Team**: Enforce data/control separation — parameterized queries, context-aware output encoding, allowlist validation. Never concatenate untrusted input into executable syntax.

| ID | Technique | Variants | Source |
|---|---|---|---|
| **RC1.T01** | **SQL Injection** | | [sql-injection] |
| RC1.T01.V01 | WHERE Clause Tautology | `OR 1=1` authentication bypass | [sql-injection] §1-1 |
| RC1.T01.V02 | UNION-Based Injection | Cross-table data extraction via column matching | [sql-injection] §1-2 |
| RC1.T01.V03 | Stacked Queries | Multi-statement execution via `;` separator | [sql-injection] §1-3 |
| RC1.T01.V04 | Subquery Injection | Nested SELECT in WHERE/FROM/SELECT clause | [sql-injection] §1-4 |
| RC1.T01.V05 | Boolean-Based Blind | True/false response differential inference | [sql-injection] §5-1 |
| RC1.T01.V06 | Time-Based Blind | `SLEEP()`/`BENCHMARK()` delay measurement | [sql-injection] §5-2 |
| RC1.T01.V07 | Error-Based Extraction | Data embedded in database error messages | [sql-injection] §5-3 |
| RC1.T01.V08 | Out-of-Band Exfiltration | DNS/HTTP channel via `UTL_HTTP`, `LOAD_FILE` | [sql-injection] §5-4 |
| RC1.T01.V09 | Second-Order Injection | Stored payload triggered in later query | [sql-injection] §6-1 |
| RC1.T01.V10 | DBMS-Specific Exploitation | MySQL `/*!*/`, PostgreSQL `COPY`, MSSQL `xp_cmdshell`, Oracle `UTL_*` | [sql-injection] §3 |
| RC1.T01.V11 | OS Command via SQL | File write (`INTO OUTFILE`), command exec (`xp_cmdshell`) | [sql-injection] §3-3 |
| RC1.T01.V12 | ORM/Framework Layer Bypass | Raw query escape through ORM abstraction | [sql-injection] §8-2 |
| RC1.T01.V13 | Wire Protocol Smuggling | Direct binary protocol injection bypassing SQL parser | [sql-injection] §8-1 |
| RC1.T01.V14 | JSON-Based SQL Bypass | JSON operators in SQL context to evade WAF | [sql-injection] §7-2 |
| **RC1.T02** | **NoSQL Injection** | | [nosql] |
| RC1.T02.V01 | Operator Injection | `$gt`, `$ne`, `$regex` in query objects | [nosql] §1 |
| RC1.T02.V02 | $where JavaScript Execution | Server-side JS eval in MongoDB query | [nosql] §2 |
| RC1.T02.V03 | Aggregation Pipeline Abuse | `$lookup`, `$merge` for cross-collection access | [nosql] §3 |
| RC1.T02.V04 | Blind NoSQL Inference | Regex/timing-based data extraction | [nosql] §4 |
| **RC1.T03** | **Command Injection** | | [command-injection] |
| RC1.T03.V01 | Shell Metacharacter Chaining | `;`, `|`, `&&`, `||`, backtick, `$()` | [command-injection] §1 |
| RC1.T03.V02 | Argument Injection | `--option` injection, `-` prefix abuse | [command-injection] §2 |
| RC1.T03.V03 | Environment Variable Manipulation | `PATH`, `IFS`, `LD_PRELOAD` injection | [command-injection] §3 |
| RC1.T03.V04 | Wildcard/Glob Injection | Filename expansion as argument injection | [command-injection] §4 |
| RC1.T03.V05 | Shell-Specific Bypass | Bash brace expansion, `$'\x41'` ANSI-C quoting | [command-injection] §5 |
| **RC1.T04** | **Cross-Site Scripting (XSS)** | | [xss] |
| RC1.T04.V01 | HTML Element Context | Direct `<script>`, event handlers, embedded objects | [xss] §1 |
| RC1.T04.V02 | HTML Attribute Context | Quote breakout, event handler injection, special attribute semantics | [xss] §2 |
| RC1.T04.V03 | JavaScript Context | String literal breakout, dynamic code execution sinks, template literals | [xss] §3 |
| RC1.T04.V04 | URL/URI Context | `javascript:`, `data:` protocol injection, parser differentials | [xss] §4 |
| RC1.T04.V05 | CSS Context | Legacy `expression()`, data exfiltration via CSS | [xss] §5 |
| RC1.T04.V06 | DOM Manipulation | DOM clobbering, prototype pollution → XSS, `postMessage` abuse | [xss] §6 |
| RC1.T04.V07 | Mutation XSS (mXSS) | Node flattening, namespace confusion, encoding-level mutation | [xss] §7 |
| RC1.T04.V08 | Stored/Persistent XSS | Payload stored server-side, rendered to other users | [xss] §11 |
| RC1.T04.V09 | Blind XSS | Payload triggers in admin/internal panel | [xss] §11 |
| RC1.T04.V10 | Framework-Specific XSS | Client-side template injection, markdown rendering, SSTI → XSS | [xss] §9 |
| **RC1.T05** | **Server-Side Template Injection (SSTI)** | | [ssti] |
| RC1.T05.V01 | Jinja2/Python | `{{config.__class__.__mro__}}` chain to RCE | [ssti] §1 |
| RC1.T05.V02 | Twig/PHP | `{{_self.env.registerUndefinedFilterCallback}}` | [ssti] §2 |
| RC1.T05.V03 | Freemarker/Java | `<#assign>` built-in exec | [ssti] §3 |
| RC1.T05.V04 | Velocity/Java | `#set($x=...)` class loading chain | [ssti] §4 |
| RC1.T05.V05 | Thymeleaf/Spring | Preprocessing `__${...}__` expression injection | [ssti] §5 |
| RC1.T05.V06 | Pebble/Handlebars/Others | Engine-specific sandbox escape | [ssti] §6 |
| **RC1.T06** | **Expression Language Injection** | | [el-injection] |
| RC1.T06.V01 | OGNL (Struts) | Object-Graph Navigation Language to RCE | [el-injection] §1 |
| RC1.T06.V02 | SpEL (Spring) | Spring Expression Language injection | [el-injection] §2 |
| RC1.T06.V03 | MVEL | MVFLEX Expression Language code execution | [el-injection] §3 |
| RC1.T06.V04 | JBoss EL / Unified EL | Java EE expression evaluation | [el-injection] §4 |
| **RC1.T07** | **XML External Entity Injection (XXE)** | | [xxe] |
| RC1.T07.V01 | Classic External Entity | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | [xxe] §1 |
| RC1.T07.V02 | Parameter Entity OOB | DTD parameter entity for blind exfiltration | [xxe] §2 |
| RC1.T07.V03 | SVG/DOCX/XLSX Vector | XXE through document format upload | [xxe] §3 |
| RC1.T07.V04 | XInclude Injection | `<xi:include>` as XXE alternative | [xxe] §4 |
| RC1.T07.V05 | SSRF via XXE | Entity pointing to internal URLs | [xxe] §5 |
| **RC1.T08** | **LDAP/XPath Injection** | | [ldap-xpath] |
| RC1.T08.V01 | LDAP Filter Syntax Manipulation | `)(|(cn=*))` tautology, wildcard abuse | [ldap-xpath] §1 |
| RC1.T08.V02 | Blind LDAP Inference | Boolean/error-based attribute extraction | [ldap-xpath] §2 |
| RC1.T08.V03 | XPath Predicate Injection | `' or '1'='1` in XPath query context | [ldap-xpath] §3 |
| RC1.T08.V04 | XPath Blind Extraction | `substring()`, `string-length()` character-by-character | [ldap-xpath] §4 |
| **RC1.T09** | **GraphQL Injection & Abuse** | | [graphql] |
| RC1.T09.V01 | Introspection Schema Extraction | Full type system disclosure via `__schema` | [graphql] §1 |
| RC1.T09.V02 | Batch Query Abuse | Alias-based parallel query execution | [graphql] §2 |
| RC1.T09.V03 | Nested Query DoS | Deeply nested relationships for resource exhaustion | [graphql] §3 |
| RC1.T09.V04 | Field Suggestion Enumeration | Auto-complete/did-you-mean as oracle | [graphql] §4 |
| RC1.T09.V05 | Directive Injection | Custom directive manipulation | [graphql] §5 |
| **RC1.T10** | **JNDI Injection** | | [jndi-injection] |
| RC1.T10.V01 | LDAP Reference Injection | Remote object factory loading via LDAP | [jndi-injection] §1 |
| RC1.T10.V02 | RMI Reference Injection | Remote class loading via RMI | [jndi-injection] §2 |
| RC1.T10.V03 | Log4Shell Class (CVE-2021-44228) | `${jndi:ldap://...}` in log messages | [jndi-injection] §3 |
| RC1.T10.V04 | Deserialization via JNDI | Serialized object in JNDI response | [jndi-injection] §4 |
| **RC1.T11** | **HTTP Header Injection (CRLF)** | | [http-header] |
| RC1.T11.V01 | Response Splitting | CRLF injection to create second HTTP response | [http-header] §1 |
| RC1.T11.V02 | Header Injection | Arbitrary header insertion via `\r\n` | [http-header] §2 |
| RC1.T11.V03 | Set-Cookie Injection | Session fixation via injected cookie header | [http-header] §3 |
| **RC1.T12** | **Email Header Injection & SMTP Smuggling** | | [email] |
| RC1.T12.V01 | Email Header Injection | `\r\n` in From/To/Subject fields | [email] §1 |
| RC1.T12.V02 | SMTP Command Smuggling | `\n.\r\n` sequence to inject SMTP commands | [email] §2 |
| RC1.T12.V03 | MIME Boundary Abuse | Multipart boundary manipulation for content injection | [email] §3 |
| **RC1.T13** | **Prototype Pollution** | | [prototype-pollution] |
| RC1.T13.V01 | `__proto__` Property Injection | Direct prototype chain modification via user input | [prototype-pollution] §1 |
| RC1.T13.V02 | `constructor.prototype` Path | Alternative prototype access path | [prototype-pollution] §2 |
| RC1.T13.V03 | Server-Side Gadgets → RCE | Pollution to `child_process`, `shell` options | [prototype-pollution] §3 |
| RC1.T13.V04 | Client-Side Gadgets → XSS | Pollution to `innerHTML`, `srcdoc`, script sources | [prototype-pollution] §4 |
| RC1.T13.V05 | Denial of Service via Pollution | Crash through type confusion or infinite loop | [prototype-pollution] §5 |

---

## RC2 — Parser & Processing Differential

*Two or more components interpret the same input according to different rules, creating exploitable gaps between what each component "sees."*

**Core Pattern**: The front-end (proxy, WAF, cache) and back-end (application server, database, file system) disagree on how to parse a message, path, or data structure. The attacker crafts input that is benign to the security layer but malicious to the processing layer — or vice versa.

> **Red Team**: Map every processing chain (CDN → WAF → Proxy → Application → Backend). At each boundary, test for parsing disagreements — different path normalization, header interpretation, encoding handling, body boundary detection.
> **Blue Team**: Minimize processing layers. Normalize input at a single authoritative point. Use the same parser library across layers. Reject ambiguous input rather than interpreting it.

| ID | Technique | Variants | Source |
|---|---|---|---|
| **RC2.T01** | **HTTP Request Smuggling** | | [http-request-smuggling] |
| RC2.T01.V01 | CL.TE Classic Smuggling | Content-Length vs Transfer-Encoding disagreement | [http-request-smuggling] §1-1 |
| RC2.T01.V02 | TE.CL Classic Smuggling | Reversed CL.TE priority | [http-request-smuggling] §1-1 |
| RC2.T01.V03 | CL.0 / 0.CL Zero-Length | Implicit zero body desync | [http-request-smuggling] §1-2 |
| RC2.T01.V04 | H2.CL / H2.TE HTTP/2 Downgrade | Protocol conversion framing mismatch | [http-request-smuggling] §1-3 |
| RC2.T01.V05 | Chunk Extension Smuggling (TERM.EXT) | Newline in chunk extension desync | [http-request-smuggling] §2-1 |
| RC2.T01.V06 | Pause-Based / Timing Desync | Temporal body arrival manipulation | [http-request-smuggling] §1-4 |
| RC2.T01.V07 | TLS Upgrade Desync (Opossum Attack) | Cross-protocol TLS desync | [http-request-smuggling] §6 |
| RC2.T01.V08 | TE Value Pollution | `xchunked`, tab/space injection in Transfer-Encoding | [http-request-smuggling] §2-1 |
| RC2.T01.V09 | Content-Length Obfuscation | Whitespace, signs, duplicate headers | [http-request-smuggling] §2-2 |
| RC2.T01.V10 | H2 Binary Header Mutation | CRLF injection, pseudo-header abuse | [http-request-smuggling] §2-3 |
| RC2.T01.V11 | Response Queue Poisoning | Steal other user's response via queue desync | [http-request-smuggling] §7 |
| **RC2.T02** | **URL Parsing Differential** | | [url-confusion] |
| RC2.T02.V01 | Authority Component Confusion | `@` notation, backslash as delimiter | [url-confusion] §2-1 |
| RC2.T02.V02 | Path Delimiter Disagreement | Cache key vs origin path interpretation | [url-confusion] §5-5 |
| RC2.T02.V03 | Fragment Handling Inconsistency | `#` fragment sent to server | [url-confusion] §3 |
| RC2.T02.V04 | Scheme Confusion | `javascript:`, `data:`, protocol-relative URLs | [url-confusion] §1-2 |
| RC2.T02.V05 | Double/Triple URL Encoding | Multi-pass decode differential between layers | [url-confusion] §8-2 |
| RC2.T02.V06 | Backslash vs Forward Slash | Windows-style path confusion | [url-confusion] §4 |
| **RC2.T03** | **Unicode & Encoding Differential** | | [unicode] |
| RC2.T03.V01 | Overlong UTF-8 Encoding | Non-shortest-form byte sequences | [unicode] §1-1 |
| RC2.T03.V02 | NFKC/NFC Normalization Bypass | Compatibility decomposition creates new characters | [unicode] §2-1 |
| RC2.T03.V03 | Charset Mismatch | UTF-7, Latin-1 vs UTF-8 interpretation divergence | [unicode] §1-3 |
| RC2.T03.V04 | Best-Fit / Worst-Fit Substitution | Charset conversion maps exotic char to dangerous one | [unicode] §5 |
| RC2.T03.V05 | Case Mapping Differential | Locale-specific case folding (`ı` → `I` in Turkish) | [unicode] §2-3 |
| RC2.T03.V06 | Zero-Width Character Injection | ZWSP, ZWJ, ZWNJ invisible in display but present in logic | [unicode] §4-1 |
| RC2.T03.V07 | BiDi Text Manipulation | RTLO/LRI reordering for filename/URL deception | [unicode] §3-2 |
| RC2.T03.V08 | Homoglyph Substitution | Visually identical characters from different scripts | [unicode] §6-1 |
| **RC2.T04** | **HTTP Parameter Pollution** | | [hpp] |
| RC2.T04.V01 | Duplicate Parameter Precedence | First-wins vs last-wins across frontend/backend | [hpp] §1-1 |
| RC2.T04.V02 | Query-Body Cross-Pollution | Parameter source merge confusion | [hpp] §2-2 |
| RC2.T04.V03 | JSON Duplicate Key Injection | RFC 8259 ambiguity — last-wins vs first-wins | [hpp] §3-1 |
| RC2.T04.V04 | Server-Side Parameter Injection | Internal API parameter override via HPP | [hpp] §8-1 |
| RC2.T04.V05 | Array/Object Notation Confusion | `param[]` vs `param` vs `param[0]` across frameworks | [hpp] §4 |
| **RC2.T05** | **Reverse Proxy Path Confusion** | | [reverse-proxy-misrouting] |
| RC2.T05.V01 | Path Normalization Differential | Dot-segment, trailing slash, case handling mismatch | [reverse-proxy-misrouting] §1 |
| RC2.T05.V02 | Semicolon Path Parameter (Tomcat `..;/`) | Java servlet path parameter stripping | [reverse-proxy-misrouting] §1-2 |
| RC2.T05.V03 | Double Decode Path Traversal | `%252e%252e` decoded differently per layer | [reverse-proxy-misrouting] §4-1 |
| RC2.T05.V04 | Encoded Slash Handling | `%2f` vs `/` interpretation mismatch | [reverse-proxy-misrouting] §4-2 |
| RC2.T05.V05 | Host Header Routing Confusion | Proxy routes to attacker-supplied Host value | [reverse-proxy-misrouting] §2 |
| RC2.T05.V06 | HTTP/2 Pseudo-Header Exploitation | `:scheme`, `:authority` injection in H2 | [reverse-proxy-misrouting] §3 |
| RC2.T05.V07 | Ingress Controller Annotation Injection | Nginx config injection (IngressNightmare) | [reverse-proxy-misrouting] §7-2 |
| RC2.T05.V08 | Underscore/Hyphen Header Confusion | `X_Custom` vs `X-Custom` normalization | [reverse-proxy-misrouting] §5-3 |
| RC2.T05.V09 | X-Original-URL / X-Rewrite-URL Override | IIS routing bypass via header injection | [reverse-proxy-misrouting] §5-2 |
| RC2.T05.V10 | Hop-by-Hop Header Stripping Abuse | `Connection:` removes security-critical headers | [reverse-proxy-misrouting] §5-3 |
| **RC2.T06** | **Cookie Parsing Differential** | | [cookie] |
| RC2.T06.V01 | Legacy RFC 2109 Parsing (`$Version`) | Phantom cookie structure bypass | [cookie] §2-1 |
| RC2.T06.V02 | Quoted-Value Parsing Divergence | Quote-absorbing semicolon leaks HttpOnly values | [cookie] §2-2 |
| RC2.T06.V03 | Out-of-Bounds Character Injection | Control chars in cookie name/value | [cookie] §2-3 |
| RC2.T06.V04 | Cookie Sandwich Attack | RFC 2109 parsing to extract HttpOnly cookie content | [cookie] §1-2 |
| **RC2.T07** | **SAML Parser Differential** | | [saml] |
| RC2.T07.V01 | Dual XML Parser Assertion Divergence | Signature validation and assertion extraction use different parsers | [saml] §2 |
| RC2.T07.V02 | XML Comment Injection | `<!-- -->` splits username for one parser but not another | [saml] §2-2 |
| RC2.T07.V03 | Namespace Confusion | XML namespace handling differs between parsers | [saml] §2-3 |
| **RC2.T08** | **ZIP Structure Inconsistency** | | [zip] |
| RC2.T08.V01 | Central Directory vs Local Header | File name/size mismatch between headers | [zip] §3-1 |
| RC2.T08.V02 | File Name Encoding Differential | UTF-8 vs CP437 vs Shift_JIS interpretation | [zip] §3-2 |
| RC2.T08.V03 | ZIP Polyglot | Dual-format file (EXE+ZIP, PDF+ZIP) | [zip] §6 |
| RC2.T08.V04 | Mark-of-the-Web (MotW) Bypass | ADS stripping, nested archive MotW loss | [zip] §5-1 |
| **RC2.T09** | **Content-Type & MIME Confusion** | *→ also RC7 (file upload)* | [file-upload] |
| RC2.T09.V01 | Content-Type vs Extension Mismatch | Server serves file based on extension, browser sniffs MIME | [file-upload] §2 |
| RC2.T09.V02 | Multipart Boundary Interpretation | WAF vs backend parse boundary differently | [file-upload] §4 |
| RC2.T09.V03 | Polyglot File Construction | Valid under multiple formats (GIF+PHP, JPEG+JS) | [file-upload] §3-2 |
| RC2.T09.V04 | Magic Byte Prepending | GIF89a/PNG header before PHP/JS payload | [file-upload] §3-1 |
| RC2.T09.V05 | `filename*=UTF-8''` Encoding Bypass | RFC 6266 encoded filename evades WAF | [file-upload] §4-3 |
| **RC2.T10** | **Web Cache Key Discrepancy** | | [web-cache-poisoning-and-deception] |
| RC2.T10.V01 | Unkeyed Input Poisoning | Header/cookie not in cache key but affects response | [web-cache-poisoning-and-deception] §1 |
| RC2.T10.V02 | Path Delimiter Cache Deception | `/profile.css` cached as static, serves dynamic content | [web-cache-poisoning-and-deception] §2 |
| RC2.T10.V03 | Cache Key Normalization Mismatch | URL normalization differs between cache and origin | [web-cache-poisoning-and-deception] §3 |
| RC2.T10.V04 | CDN Cache Poisoning via Headers | `X-Forwarded-Host`, `X-Original-URL` in cached response | [web-cache-poisoning-and-deception] §4 |
| **RC2.T11** | **Protocol-Level WAF Bypass** | | [protocol-level-waf-bypass] |
| RC2.T11.V01 | HTTP/2 Binary Encoding Bypass | WAF inspects HTTP/1.1 text, misses H2 binary framing | [protocol-level-waf-bypass] §1 |
| RC2.T11.V02 | Chunked Encoding Evasion | Chunk extension/trailer fields invisible to WAF | [protocol-level-waf-bypass] §2 |
| RC2.T11.V03 | Header Smuggling Through Proxy | Headers stripped/rewritten between proxy layers | [protocol-level-waf-bypass] §3 |
| **RC2.T12** | **HTTP Censorship Infrastructure Bypass** | | [http-censorship-bypass] |
| RC2.T12.V01 | DPI Evasion via Segmentation | TCP segment splitting across inspection boundary | [http-censorship-bypass] §1 |
| RC2.T12.V02 | SNI Manipulation | TLS ClientHello SNI spoofing/omission | [http-censorship-bypass] §2 |
| RC2.T12.V03 | Domain Fronting | CDN-based host header vs SNI mismatch | [http-censorship-bypass] §3 |

---

## RC3 — Authentication & Credential Integrity Failure

*Flaws in verifying identity, validating authentication materials, or managing credential lifecycle.*

**Core Pattern**: The application fails to correctly verify "who you are" — either through weak cryptographic validation, logic flaws in authentication flows, or inadequate lifecycle management of credentials/sessions.

> **Red Team**: Test every authentication mechanism — JWT signature verification, OAuth flow integrity, session management, MFA enforcement, password reset flow, token predictability. Look for algorithm confusion, step-skipping, and token reuse.
> **Blue Team**: Use well-tested authentication libraries. Enforce strict algorithm allowlists. Implement proper session lifecycle (invalidation on password change, rotation on login). Use hardware-backed MFA. Apply defense-in-depth across all auth paths.

| ID | Technique | Variants | Source |
|---|---|---|---|
| **RC3.T01** | **JWT Verification Bypass** | | [jwt] |
| RC3.T01.V01 | None Algorithm Bypass | `"alg":"none"` removes signature verification | [jwt] §1-1 |
| RC3.T01.V02 | Algorithm Confusion (RS256→HS256) | Public key used as HMAC secret | [jwt] §1-2 |
| RC3.T01.V03 | `kid` SQL Injection / Path Traversal | Key ID resolves to attacker-controlled key | [jwt] §2-1 |
| RC3.T01.V04 | `jku` SSRF | JWKS URL points to attacker's key server | [jwt] §2-2 |
| RC3.T01.V05 | `jwk` Self-Signed Key Embedding | Attacker embeds own public key in header | [jwt] §2-3 |
| RC3.T01.V06 | `x5u`/`x5c` Certificate Injection | X.509 chain manipulation | [jwt] §2-4 |
| RC3.T01.V07 | Weak HMAC Key Brute-Force | Offline dictionary attack on JWT secret | [jwt] §3-1 |
| RC3.T01.V08 | ECDSA Implementation Flaw | Psychic Signatures (CVE-2022-21449), nonce reuse | [jwt] §3-2 |
| RC3.T01.V09 | PBES2 Billion Hashes DoS | Key derivation cost amplification | [jwt] §3-3 |
| RC3.T01.V10 | JWS/JWE Confusion | Sign/encrypt type confusion | [jwt] §7-1 |
| RC3.T01.V11 | Claim Manipulation (`sub`, `role`, `scope`) | Identity/authorization claim tampering | [jwt] §4 |
| RC3.T01.V12 | Token Lifecycle Abuse | Non-revocable JWT, refresh token theft | [jwt] §6, §7-4 |
| **RC3.T02** | **SAML Assertion Forgery** | *→ also RC2 (parser differential)* | [saml] |
| RC3.T02.V01 | XML Signature Wrapping (XSW) | Relocate signed element, inject unsigned assertion | [saml] §1 |
| RC3.T02.V02 | Golden SAML | Forged assertions with stolen IdP signing key | [saml] §5-1 |
| RC3.T02.V03 | Silver SAML | Forged assertions with externalized cert (Entra ID) | [saml] §5-1 |
| RC3.T02.V04 | Certificate Validation Failure | Untrusted/self-signed certificate accepted | [saml] §5-2 |
| RC3.T02.V05 | SAML XXE Injection | External entity in SAML XML message | [saml] §6 |
| **RC3.T03** | **OAuth Flow Exploitation** | | [oauth] |
| RC3.T03.V01 | Redirect URI Manipulation | Open redirect leaks authorization code/token | [oauth] §1 |
| RC3.T03.V02 | Authorization Code Injection | CSRF callback with attacker's code | [oauth] §2-1 |
| RC3.T03.V03 | IdP Mix-Up Attack | Confuse RP about which IdP issued token | [oauth] §8-2 |
| RC3.T03.V04 | Device Authorization Grant Abuse | Device code phishing | [oauth] §8-3 |
| RC3.T03.V05 | Dynamic Client Registration Abuse | Register malicious OAuth client | [oauth] §3-1 |
| RC3.T03.V06 | Scope Manipulation | Request elevated scopes beyond consent | [oauth] §5-2 |
| RC3.T03.V07 | Consent Bypass | Skip consent screen via parameter manipulation | [oauth] §5-1 |
| RC3.T03.V08 | Implicit Flow Token Interception | Fragment leak via open redirect chain | [oauth] §2-2 |
| RC3.T03.V09 | Refresh Token Theft & Reuse | Long-lived token compromise | [oauth] §7 |
| **RC3.T04** | **SSO Authentication Bypass** | | [authentication-bypass-and-sso] |
| RC3.T04.V01 | Token Relay / Forwarding Attack | SSO token replayed to unauthorized service | [authentication-bypass-and-sso] §1 |
| RC3.T04.V02 | Provider Confusion | Multiple IdP handling creates identity mismatch | [authentication-bypass-and-sso] §2 |
| RC3.T04.V03 | Response Manipulation | SSO assertion modified in transit | [authentication-bypass-and-sso] §3 |
| **RC3.T05** | **Credential Recovery Exploitation** | | [ato] |
| RC3.T05.V01 | Predictable Reset Token | Weak PRNG, `MD5(timestamp)`, sequential token | [ato] §2-1 |
| RC3.T05.V02 | Host Header Poisoning for Token Theft | Reset link domain controlled by attacker | [ato] §2-2 |
| RC3.T05.V03 | Token-User Decoupling | Own reset token applied to victim's account | [ato] §2-3 |
| RC3.T05.V04 | OTP Brute-Force | 4-6 digit code exhaustion without rate limit | [ato] §2-3 |
| **RC3.T06** | **MFA Bypass** | | [ato] |
| RC3.T06.V01 | MFA Step Skip | Direct access to post-MFA endpoint | [ato] §4-2 |
| RC3.T06.V02 | MFA Prompt Fatigue / Bombing | Push notification exhaustion | [ato] §4-3 |
| RC3.T06.V03 | SIM Swap | Carrier social engineering for SMS MFA | [ato] §4-3 |
| RC3.T06.V04 | AiTM Phishing (Evilginx/Modlishka) | Real-time proxy captures post-MFA session | [ato] §4-3 |
| RC3.T06.V05 | MFA Flow Logic Bypass | Parameter manipulation in MFA verification | [ato] §4-2 |
| **RC3.T07** | **Session Management Failure** | | [cookie], [ato] |
| RC3.T07.V01 | Session Non-Invalidation on Password Change | Old sessions survive credential reset | [ato] §1-1 |
| RC3.T07.V02 | Session Non-Invalidation on Logout | Server-side session not destroyed | [cookie] §8-2 |
| RC3.T07.V03 | Long-Lived "Remember Me" Token | 30-90 day persistent cookie abuse | [cookie] §7-3 |
| RC3.T07.V04 | Pass-the-Cookie / Token Replay | Stolen post-MFA session cookie reuse | [cookie] §7-3 |
| RC3.T07.V05 | Session Fixation | Attacker sets known session ID pre-authentication | [ato] §3-1, [cookie] §8-1 |
| RC3.T07.V06 | Browser Cookie Database Extraction | SQLite/DPAPI/Keychain cookie theft | [cookie] §7-1 |
| RC3.T07.V07 | Chrome AppBound Encryption Bypass | CBC padding oracle on elevation service | [cookie] §7-1 |
| RC3.T07.V08 | Cookie-Bite (Malicious Extension) | Browser extension exfiltrates session tokens | [cookie] §7-2 |
| **RC3.T08** | **Credential Brute-Force & Replay** | | [ato] |
| RC3.T08.V01 | Credential Stuffing | Automated leaked credential testing | [ato] §6-1 |
| RC3.T08.V02 | Password Spraying | Common passwords across many accounts | [ato] §6-1 |
| RC3.T08.V03 | Magic Link / Passwordless Token Theft | Token interception via email/Referer/redirect | [ato] §9 |
| RC3.T08.V04 | Deep Link Hijacking (Mobile) | Malicious app intercepts auth link | [ato] §9 |
| **RC3.T09** | **Pre-Account Takeover** | | [ato] |
| RC3.T09.V01 | Classic-Federated Merge | Pre-create account, auto-link on victim's OAuth login | [ato] §1-1 |
| RC3.T09.V02 | Trojan Identifier | Pre-add secondary auth factors to victim's account | [ato] §1-1 |
| RC3.T09.V03 | Non-Verifying IdP Exploit | IdP without email verification → identity claim | [ato] §1-1 |
| RC3.T09.V04 | Unexpired Email Change Token | Pending change completes after account recovery | [ato] §1-1 |

---

## RC4 — Access Control & Authorization Gap

*Missing, incomplete, or inconsistently enforced authorization checks on resources, functions, or object properties.*

**Core Pattern**: The server performs authentication (knows who you are) but fails to verify authorization (whether you should access this specific resource/function). This can manifest as missing checks, inconsistent enforcement across endpoints, or client-side-only restrictions.

> **Red Team**: For every authenticated action, test: (1) access with different user's identifier, (2) access without auth, (3) access via different HTTP method, (4) access via different API version, (5) modify hidden/read-only fields. Automate IDOR testing with sequential/predictable identifiers.
> **Blue Team**: Implement authorization at the data access layer (not controller). Use authorization middleware consistently. Enforce object-level checks for every data operation. Deny by default. Use unpredictable identifiers (UUIDv4).

| ID | Technique | Variants | Source |
|---|---|---|---|
| **RC4.T01** | **Broken Object-Level Authorization (BOLA/IDOR)** | | [idor-bola] |
| RC4.T01.V01 | Sequential ID Manipulation | `user_id=1001→1002` integer enumeration | [idor-bola] §1-1 |
| RC4.T01.V02 | UUIDv1 Timestamp Prediction | Narrow UUID space via known creation time | [idor-bola] §1-2 |
| RC4.T01.V03 | Encoded ID Reversal | Base64/hash decode or brute-force | [idor-bola] §1-3 |
| RC4.T01.V04 | REST Sub-Resource Traversal | Nested resource ID swap (`/users/1/orders/2` → `/users/2/orders/2`) | [idor-bola] §4-1 |
| RC4.T01.V05 | GraphQL Node/Alias Enumeration | Global ID query, alias-based mass access | [idor-bola] §4-2 |
| RC4.T01.V06 | Cross-Tenant Object Access | Tenant/org ID manipulation | [idor-bola] §5-3 |
| RC4.T01.V07 | Blind IDOR (Write-Only) | Modify victim's data without confirmation feedback | [idor-bola] §6-2 |
| RC4.T01.V08 | Collection Endpoint Leakage | Unfiltered listing returns all users' data | [idor-bola] §4-1 |
| RC4.T01.V09 | Aggregation Endpoint Leakage | Stats/reports span across unauthorized scope | [idor-bola] §5-4 |
| **RC4.T02** | **Function-Level Authorization Gap (BFLA)** | | [business-logic-vuln], [idor-bola] |
| RC4.T02.V01 | Direct Admin Endpoint Access | Forced browsing to `/admin/`, `/internal/` | [business-logic-vuln] §3-1 |
| RC4.T02.V02 | Unprotected Admin Function | UI hidden but endpoint accessible | [business-logic-vuln] §3-1 |
| RC4.T02.V03 | API Version Bypass | Legacy `/v1/` without auth controls | [business-logic-vuln] §3-3 |
| RC4.T02.V04 | HTTP Method Switching | GET blocked → POST allowed (or vice versa) | [idor-bola] §3-1 |
| RC4.T02.V05 | Admin Registration Exposure | Public `/admin/register` access | [ato] §8-2 |
| RC4.T02.V06 | Invitation Role Tampering | Modify role in invitation token/link | [ato] §8-2 |
| **RC4.T03** | **Object Property-Level Manipulation (BOPLA)** | | [idor-bola], [mass-assignment] |
| RC4.T03.V01 | Boolean Admin Flag Injection | `isAdmin=true` in request body | [mass-assignment] §1-1 |
| RC4.T03.V02 | Role/Permission String Injection | `role=admin` parameter binding | [mass-assignment] §1-2 |
| RC4.T03.V03 | Account State Manipulation | `verified=true`, `active=true` override | [mass-assignment] §1-3 |
| RC4.T03.V04 | Sensitive Field Over-Exposure | Unfiltered full object in API response | [idor-bola] §5-2 |
| RC4.T03.V05 | Read-Only Field Overwrite | Modify immutable fields via PATCH/PUT | [idor-bola] §5-2 |
| RC4.T03.V06 | Spring4Shell Class Loader Access | Property chain traversal to RCE | [mass-assignment] §5-1 |
| RC4.T03.V07 | Prototype Pollution via Binding | `__proto__` through framework auto-binding | [mass-assignment] §5-3 |
| **RC4.T04** | **CORS Misconfiguration** | | [cors-misconfiguration] |
| RC4.T04.V01 | Reflected Origin Trust | `Access-Control-Allow-Origin` echoes request Origin | [cors-misconfiguration] §1 |
| RC4.T04.V02 | Null Origin Allowance | Sandboxed iframe sends `Origin: null` | [cors-misconfiguration] §2 |
| RC4.T04.V03 | Wildcard with Credentials | `*` origin + `Allow-Credentials: true` | [cors-misconfiguration] §3 |
| RC4.T04.V04 | Subdomain Trust Exploitation | Regex bypass via `evil-example.com` | [cors-misconfiguration] §4 |
| **RC4.T05** | **Cross-Tenant Boundary Violation** | *→ also RC8* | [idor-bola], [implicit-trust-boundary] |
| RC4.T05.V01 | Tenant ID Manipulation | Switch `org_id`/`tenant_id` parameter | [idor-bola] §5-3 |
| RC4.T05.V02 | Shared Resource Leakage | Multi-tenant resource without isolation | [implicit-trust-boundary] §3 |

---

## RC5 — State, Workflow & Concurrency Violation

*Application fails to enforce correct execution order, atomicity, request intent, or state transition constraints.*

**Core Pattern**: The application assumes clients will follow the intended workflow (step 1 → step 2 → step 3) and makes sequential requests, but doesn't enforce this server-side. Attackers skip steps, replay requests, modify state out-of-order, or exploit race windows between check and action.

> **Red Team**: For every multi-step flow, test skipping intermediate steps (go directly to final step). For every limited resource (balance, stock, coupons), send parallel requests. For every state-changing action, test CSRF. For every business rule, test boundary values.
> **Blue Team**: Enforce state machine transitions server-side. Use database-level locks or compare-and-swap for atomic operations. Implement anti-CSRF tokens with SameSite cookies. Validate all business rules server-side with idempotency keys.

| ID | Technique | Variants | Source |
|---|---|---|---|
| **RC5.T01** | **State Machine Bypass** | | [state-machine-violation] |
| RC5.T01.V01 | Step Skipping (Direct-to-Final) | Bypass payment/verification step entirely | [state-machine-violation] §1-1 |
| RC5.T01.V02 | Backward State Transition | "Shipped" → "Pending" rollback | [state-machine-violation] §1-3 |
| RC5.T01.V03 | Terminal State Re-Entry | Reopen closed claim/cancelled subscription | [state-machine-violation] §1-4, [business-logic-vuln] §2-2 |
| RC5.T01.V04 | Approval Chain Bypass | Skip intermediate approval steps | [state-machine-violation] §1-1 |
| RC5.T01.V05 | Parallel Path Exploitation | Multiple concurrent valid paths through workflow | [state-machine-violation] §2 |
| **RC5.T02** | **Race Condition / TOCTOU** | | [web-race-condition] |
| RC5.T02.V01 | Resource Limit Overrun | Parallel requests bypass balance/stock/vote limits | [web-race-condition] §1 |
| RC5.T02.V02 | Double-Spend | Concurrent withdraw exceeds available balance | [web-race-condition] §1-1 |
| RC5.T02.V03 | Authentication Race | Concurrent login bypasses credential verification | [web-race-condition] §2 |
| RC5.T02.V04 | Object Partial Construction Race | Access uninitialized fields during object creation | [web-race-condition] §3 |
| RC5.T02.V05 | Token-Identity Binding Race | Misroute token/session to wrong user | [web-race-condition] §4 |
| RC5.T02.V06 | File Upload Race | Access uploaded file before validation/deletion | [file-upload] §9 |
| **RC5.T03** | **Cross-Site Request Forgery (CSRF)** | | [csrf] |
| RC5.T03.V01 | Missing CSRF Token | State-changing action without token validation | [csrf] §1 |
| RC5.T03.V02 | Token Validation Bypass | Token present but not properly verified | [csrf] §2 |
| RC5.T03.V03 | SameSite Bypass (Lax+POST) | Form POST within 2-minute top-level navigation window | [csrf] §3, [cookie] §1-1 |
| RC5.T03.V04 | Method Override CSRF | `_method=POST` via GET request | [csrf] §4 |
| RC5.T03.V05 | Subdomain CSRF | Cookie tossing enables cross-subdomain CSRF | [csrf] §5 |
| RC5.T03.V06 | CSRF Email/Password Change → ATO | Cross-site credential change without current password | [ato] §7-2 |
| **RC5.T04** | **Business Logic Price & Quantity Manipulation** | | [business-logic-vuln] |
| RC5.T04.V01 | Client-Side Price Override | User-supplied price accepted by server | [business-logic-vuln] §1-1 |
| RC5.T04.V02 | Negative Quantity Injection | Qty=-5 creates credit instead of charge | [business-logic-vuln] §1-2 |
| RC5.T04.V03 | Integer Overflow in Cart Total | Signed integer wraparound to negative | [business-logic-vuln] §1-2 |
| RC5.T04.V04 | Currency Confusion / Rounding Abuse | Decimal precision or exchange rate manipulation | [business-logic-vuln] §6 |
| **RC5.T05** | **Coupon, Promo & Financial Logic Abuse** | | [business-logic-vuln] |
| RC5.T05.V01 | Coupon Stacking | Multiple coupons where only one allowed | [business-logic-vuln] §2-3 |
| RC5.T05.V02 | Coupon/Promo Replay | Reuse single-use discount code | [business-logic-vuln] §2-3 |
| RC5.T05.V03 | Infinite Money Loop | Gift card → promo → gift card cycle | [business-logic-vuln] §2-3 |
| RC5.T05.V04 | Payment Callback Forgery | Forge payment gateway webhook confirmation | [business-logic-vuln] §10-1 |
| RC5.T05.V05 | Refund/Return Abuse | Refund without return, or double refund | [business-logic-vuln] §10-1 |
| **RC5.T06** | **Subscription & Lifecycle Abuse** | | [business-logic-vuln] |
| RC5.T06.V01 | Trial Extension / Account Cycling | Repeated free tier access via new accounts | [business-logic-vuln] §10-3 |
| RC5.T06.V02 | Downgrade Feature Retention | Keep premium features after plan downgrade | [business-logic-vuln] §10-3 |
| RC5.T06.V03 | Vote/Rating/Leaderboard Manipulation | Multi-account ballot stuffing, score falsification | [business-logic-vuln] §10-5 |
| RC5.T06.V04 | Cart/Reservation Bombing | Reserve all inventory without completing purchase | [business-logic-vuln] §5-3 |

---

## RC6 — Unsafe Deserialization & Object Reconstruction

*Untrusted data controls object instantiation, class loading, or code execution through deserialization/reflection mechanisms.*

**Core Pattern**: The application reconstructs objects from serialized data without verifying the class types being instantiated. Language features (magic methods, property-oriented programming, reflection) allow the attacker to chain existing class methods ("gadgets") into arbitrary code execution.

> **Red Team**: Identify serialization formats in use (Java `ObjectInputStream`, Python Pickle, PHP `unserialize`, .NET `BinaryFormatter`, YAML). Test with known gadget chains (ysoserial, PHPGGC). Check for format-crossing deserialization (JSON→XML→XXE). Test ML model loading endpoints.
> **Blue Team**: Never deserialize untrusted data. Use format-specific safe alternatives (JSON instead of native serialization). Implement strict allowlists (not blocklists) for permitted classes. Use JEP 290 object input filters in Java. Validate ML model integrity before loading.

| ID | Technique | Variants | Source |
|---|---|---|---|
| **RC6.T01** | **Java Deserialization** | | [deserialization] |
| RC6.T01.V01 | Commons Collections Gadget Chains | `InvokerTransformer`, `ChainedTransformer` | [deserialization] §8-1 |
| RC6.T01.V02 | TemplatesImpl Code Execution | Bytecode injection via `_bytecodes` field | [deserialization] §8-1 |
| RC6.T01.V03 | Spring Framework Gadgets | Spring-specific POP chains | [deserialization] §1-1 |
| RC6.T01.V04 | JEP 290 Blocklist Bypass | New gadgets not covered by blocklist | [deserialization] §7-1 |
| RC6.T01.V05 | Dormant/Latent Gadget Activation | Chains activated by dependency update | [deserialization] §1-2 |
| **RC6.T02** | **Python Deserialization** | | [deserialization] |
| RC6.T02.V01 | Pickle `__reduce__` RCE | `os.system()` via reduce protocol | [deserialization] §8-2 |
| RC6.T02.V02 | Marshal Module Exploitation | Lower-level serialization abuse | [deserialization] §8-2 |
| RC6.T02.V03 | YAML `unsafe_load` | PyYAML arbitrary object instantiation | [deserialization] §4-2 |
| RC6.T02.V04 | Scanner Evasion (Callable Substitution) | `pip.main()` instead of `os.system` | [deserialization] §7-2 |
| **RC6.T03** | **PHP Deserialization** | | [deserialization] |
| RC6.T03.V01 | `unserialize()` POP Chains | `__wakeup`/`__destruct` method exploitation | [deserialization] §8-3 |
| RC6.T03.V02 | PHAR Metadata Deserialization | `phar://` stream wrapper triggers unserialize | [deserialization] §4-3 |
| RC6.T03.V03 | PHPGGC Gadget Chains | Automated PHP gadget chain generation | [deserialization] §8-3 |
| **RC6.T04** | **.NET Deserialization** | | [deserialization] |
| RC6.T04.V01 | BinaryFormatter RCE | `ysoserial.net` gadget chains | [deserialization] §8-4 |
| RC6.T04.V02 | ViewState Deserialization | ASP.NET ViewState with known machineKey | [deserialization] §8-4 |
| RC6.T04.V03 | TypeNameHandling JSON.NET | `$type` metadata injection in JSON | [deserialization] §8-4 |
| **RC6.T05** | **YAML Arbitrary Instantiation** | | [deserialization] |
| RC6.T05.V01 | SnakeYAML Constructor Injection | Java class instantiation via YAML tags | [deserialization] §4-2 |
| RC6.T05.V02 | Ruby YAML Deserialization | `Psych.unsafe_load` gadget chains | [deserialization] §4-2 |
| **RC6.T06** | **React Flight / Modern Framework Exploitation** | | [deserialization] |
| RC6.T06.V01 | Server Component Protocol Manipulation | Prototype pollution → RCE via React Flight | [deserialization] §2-3 |
| **RC6.T07** | **ML Model Poisoning** | | [deserialization] |
| RC6.T07.V01 | PyTorch/Keras/Joblib Model RCE | `torch.load()`, `keras.models.load_model()` backdoor | [deserialization] §9-1 |
| RC6.T07.V02 | Sleepy Pickle (Stealthy Tampering) | In-place model modification during deserialization | [deserialization] §9-1 |
| RC6.T07.V03 | ML Framework Pipeline Exploitation | vLLM ZeroMQ pickle, LangChain prompt injection → deser | [deserialization] §9-2 |
| **RC6.T08** | **Gadget Chain Engineering** | | [deserialization] |
| RC6.T08.V01 | Automated Gadget Mining (FLASH, ODDFuzz) | Static/dynamic analysis for chain discovery | [deserialization] §1-3 |
| RC6.T08.V02 | Cross-Library Chain Construction | Gadgets spanning multiple dependency libraries | [deserialization] §1-1 |
| RC6.T08.V03 | Nested/Format-Crossing Deserialization | JSON→XML→XXE chain, CosmicSting-style | [deserialization] §5-1 |
| RC6.T08.V04 | Polyglot Payload Construction | Valid under multiple formats simultaneously | [deserialization] §6 |
| RC6.T08.V05 | Broken File Bypass (nullifAI) | Payload executes before parse error triggers filter | [deserialization] §7-2 |

---

## RC7 — Unvalidated Resource Reference

*User-supplied input controls which resource the server accesses — URL, file path, class name, connection string — without adequate validation.*

**Core Pattern**: The application uses user input to construct a reference to an internal or external resource (URL, file path, class name, database connection), but fails to restrict which resources can be accessed. The attacker redirects the reference to unintended targets.

> **Red Team**: Find every parameter that takes a URL, file path, hostname, or resource identifier. Test with internal IPs (127.0.0.1, 169.254.169.254), file paths (`../../etc/passwd`), alternative protocols (`gopher://`, `file://`), DNS rebinding. Check file upload for path traversal in filenames.
> **Blue Team**: Allowlist permitted domains/paths/protocols. Resolve DNS and validate IP before connection (beware TOCTOU with DNS rebinding). Use dedicated download agents with network isolation. Strip path traversal sequences at the file system layer.

| ID | Technique | Variants | Source |
|---|---|---|---|
| **RC7.T01** | **Server-Side Request Forgery (SSRF)** | | [ssrf] |
| RC7.T01.V01 | IP Address Obfuscation | Octal, hex, decimal, IPv6 mapped, IPv4-compatible | [ssrf] §1 |
| RC7.T01.V02 | DNS Rebinding | Time-of-check IP validation bypass | [ssrf] §6-1 |
| RC7.T01.V03 | Protocol Smuggling (Gopher) | Cross-protocol interaction via gopher:// | [ssrf] §3-3 |
| RC7.T01.V04 | Cloud Metadata Service Access | `169.254.169.254` for IAM credential theft | [ssrf] §8 |
| RC7.T01.V05 | Redirect Chain Bypass | HTTP 30x redirect from allowed to internal host | [ssrf] §7-1 |
| RC7.T01.V06 | URL Parser Confusion | Authority/path confusion in SSRF filter | [ssrf] §2, → RC2 |
| RC7.T01.V07 | Blind SSRF OOB Callback | Data exfiltrated in outbound request URL/body | [ssrf] §7-3 |
| **RC7.T02** | **Open Redirect** | | [open-redirect] |
| RC7.T02.V01 | Parameter-Based Redirect | `?redirect_url=https://evil.com` | [open-redirect] §1 |
| RC7.T02.V02 | URL Validation Bypass | Domain matching tricks, protocol-relative URLs | [open-redirect] §2 |
| RC7.T02.V03 | OAuth Token Theft via Open Redirect | Redirect URI manipulation chains to token leak | [open-redirect] §3, → RC3 |
| RC7.T02.V04 | Phishing Amplification | Trusted domain used in phishing URL | [open-redirect] §4 |
| **RC7.T03** | **File Path Traversal** | | [file-upload], [zip] |
| RC7.T03.V01 | Upload Filename Path Traversal | `../../` in uploaded file name | [file-upload] §5-1 |
| RC7.T03.V02 | Zip Slip | Archive entry with `../` path traversal | [zip] §1-1 |
| RC7.T03.V03 | Symlink Escape | Archive symlinks pointing to sensitive files | [zip] §2 |
| RC7.T03.V04 | Null Byte Truncation | `file.php%00.jpg` extension bypass (legacy) | [file-upload] §1-3 |
| RC7.T03.V05 | Shell Metacharacter in Filename | Backtick, `$()`, pipe injection via filename | [file-upload] §5-2 |
| **RC7.T04** | **Remote Code/Class Loading** | | [rmi], [jndi-injection] |
| RC7.T04.V01 | RMI Registry Deserialization | `bind`/`rebind` payload injection | [rmi] §1-1 |
| RC7.T04.V02 | RMI Remote Class Loading | Client/server codebase URL abuse | [rmi] §6 |
| RC7.T04.V03 | JMX MBean Exploitation | MBean-based code execution | [rmi] §4 |
| RC7.T04.V04 | JNDI Reference Injection | Remote class loading via LDAP/RMI reference | [jndi-injection] §1-2, [rmi] §5 |
| **RC7.T05** | **JDBC Connection Attack** | | [jdbc-attack] |
| RC7.T05.V01 | Connection String Injection | Attacker controls JDBC URL parameters | [jdbc-attack] §1 |
| RC7.T05.V02 | Driver-Specific Exploitation | MySQL `allowUrlInLocalInfile`, PostgreSQL `loggerFile` | [jdbc-attack] §2 |
| RC7.T05.V03 | Fake MySQL Server Attack | Rogue server triggers `LOAD DATA LOCAL` file read | [jdbc-attack] §3 |
| **RC7.T06** | **Webhook/Callback Manipulation** | *→ also RC8* | [secondary-context-attack] |
| RC7.T06.V01 | Attacker-Controlled Callback URL | SSRF via webhook/notification destination | [secondary-context-attack] §2-3 |
| RC7.T06.V02 | Notification Channel Hijack | Redirect notifications to attacker endpoint | [idor-bola] §4-4 |

---

## RC8 — Trust Boundary & Isolation Failure

*Components assume implicit trust in other components, domains, or services without independent verification.*

**Core Pattern**: The system trusts that internal services, sibling domains, package registries, or cross-origin messages are inherently safe. Attackers exploit these assumptions to cross trust boundaries — impersonating trusted components, hijacking DNS, poisoning supply chains, or abusing cross-origin communication.

> **Red Team**: Map all inter-service communication, domain trust relationships, and cross-origin interactions. Test internal header spoofing (`X-Forwarded-For`, `x-envoy-internal`). Test DNS rebinding. Check for subdomain takeover. Test postMessage origin validation.
> **Blue Team**: Verify identity at every trust boundary (mTLS between services, origin validation for postMessage, DNSSEC). Never trust headers from untrusted sources. Use network segmentation. Pin internal dependencies. Implement least-privilege IAM roles.

| ID | Technique | Variants | Source |
|---|---|---|---|
| **RC8.T01** | **Microservice / Inter-Service Trust Exploitation** | | [implicit-trust-boundary] |
| RC8.T01.V01 | Internal Service Blind Trust | Service B trusts all requests from Service A without verification | [implicit-trust-boundary] §9-1 |
| RC8.T01.V02 | Service Mesh Header Spoofing | `x-envoy-internal: true` impersonation | [reverse-proxy-misrouting] §5-1 |
| RC8.T01.V03 | API Gateway Bypass | Direct backend access skipping gateway auth via SSRF/network | [idor-bola] §8-1 |
| RC8.T01.V04 | Internal API Privilege Assumption | Internal endpoints lack authentication entirely | [implicit-trust-boundary] §2 |
| **RC8.T02** | **Confused Deputy / Cloud Delegation** | | [secondary-context-attack] |
| RC8.T02.V01 | Cross-Tenant Role Assumption | Cloud IAM confused deputy in delegation chain | [secondary-context-attack] §5-1 |
| RC8.T02.V02 | BFF/API Gateway Path Escape | Traverse proxy path boundaries to internal services | [secondary-context-attack] §1 |
| RC8.T02.V03 | Secondary Injection via Notifications | Malicious data delivered through trusted notification channel | [secondary-context-attack] §3 |
| **RC8.T03** | **DNS-Based Trust Bypass** | | [dns-web-security] |
| RC8.T03.V01 | DNS Rebinding | Same-origin policy bypass via DNS TTL manipulation | [dns-web-security] §1 |
| RC8.T03.V02 | Subdomain Takeover | Dangling CNAME/A record pointing to unclaimed service | [dns-web-security] §2 |
| RC8.T03.V03 | DNS Resolver Abuse | Rebinding defense bypass, DNS pinning evasion | [dns-web-security] §3 |
| **RC8.T04** | **Supply Chain Trust Exploitation** | | [dependency-confusion] |
| RC8.T04.V01 | Dependency Confusion | Public package name shadows private internal package | [dependency-confusion] §1 |
| RC8.T04.V02 | Typosquatting | Near-identical package name with malicious payload | [dependency-confusion] §2 |
| RC8.T04.V03 | Registry Priority Abuse | Package manager prefers public over private registry | [dependency-confusion] §3 |
| RC8.T04.V04 | Compromised Dependency Activation | Supply chain compromise completes dormant gadget chains | [deserialization] §1-2 |
| **RC8.T05** | **Cookie Domain Scope Exploitation** | | [cookie] |
| RC8.T05.V01 | Cookie Tossing (Subdomain Injection) | Sibling subdomain sets same-name cookie | [cookie] §5-2 |
| RC8.T05.V02 | Parent Domain Cookie Scope | Cookie set for `.example.com` affects all subdomains | [cookie] §5-1 |
| RC8.T05.V03 | Cookie Jar Overflow | Force eviction of HttpOnly cookies by overflowing jar | [cookie] §5-1 |
| **RC8.T06** | **Cross-Origin Communication Trust** | | [secondary-context-attack] |
| RC8.T06.V01 | PostMessage Origin Validation Failure | Missing or regex-bypassable origin check | [secondary-context-attack] §4 |
| RC8.T06.V02 | Cross-Window Communication Abuse | `window.opener`, `window.name` data leak | [secondary-context-attack] §4 |
| **RC8.T07** | **WebSocket Trust Bypass** | | [websocket] |
| RC8.T07.V01 | Cross-Site WebSocket Hijacking (CSWSH) | WebSocket handshake without origin/CSRF validation | [websocket] §1 |
| RC8.T07.V02 | WebSocket Upgrade Smuggling | Upgrade request used to smuggle HTTP requests | [websocket] §2 |
| RC8.T07.V03 | WebSocket Tunneling | Bidirectional channel bypasses security controls | [websocket] §3 |
| **RC8.T08** | **JAAS Trust & Authentication Service Abuse** | | [jaas-attack] |
| RC8.T08.V01 | LoginModule Configuration Override | Modify JAAS config to bypass authentication | [jaas-attack] §1 |
| RC8.T08.V02 | Subject/Principal Manipulation | Tamper with authenticated principal chain | [jaas-attack] §2 |
| RC8.T08.V03 | Callback Handler Exploitation | Custom callback handler logic flaws | [jaas-attack] §3 |

---

## RC9 — Information Leakage & Side-Channel

*Unintended information disclosure through observable system behavior, error messages, timing differences, or cached state.*

**Core Pattern**: The system reveals internal state — existence of resources, database content, technology stack, user data — through indirect channels: response timing, error messages, cache behavior, or rendering differences. Attackers use these oracles to extract data that was never intended to be exposed.

> **Red Team**: Measure response time differentials for user enumeration, SQL blind extraction, and cryptographic token verification. Check error messages for stack traces, framework versions, internal paths. Test for XS-Leaks and cache probing. Look for exposed API documentation.
> **Blue Team**: Normalize response times for security-sensitive operations. Use generic error messages. Disable debug output in production. Set proper cache headers. Implement rate limiting on enumeration-susceptible endpoints. Remove introspection in production.

| ID | Technique | Variants | Source |
|---|---|---|---|
| **RC9.T01** | **Timing-Based Information Extraction** | | [web-timing-attack] |
| RC9.T01.V01 | User/Account Existence Oracle | Response time differs for valid vs invalid users | [web-timing-attack] §1-1 |
| RC9.T01.V02 | Database Query Timing Differential | SQL execution time leaks record existence | [web-timing-attack] §1-3 |
| RC9.T01.V03 | Cryptographic Timing Oracle | Token/MAC verification byte-by-byte timing | [web-timing-attack] §4 |
| RC9.T01.V04 | Connection Pool State Inference | Pool exhaustion timing reveals internal state | [web-timing-attack] §2 |
| **RC9.T02** | **Server & Application Fingerprinting** | | [web-fingerprinting] |
| RC9.T02.V01 | HTTP Response Header Analysis | Server software, framework, version from headers | [web-fingerprinting] §5-1 |
| RC9.T02.V02 | Error Response Fingerprinting | Tech stack identification from error pages | [web-fingerprinting] §5-2 |
| RC9.T02.V03 | Protocol Behavior Fingerprinting | HTTP/2, HTTP/3, TLS handshake differences | [web-fingerprinting] §5-3 |
| RC9.T02.V04 | Multi-Layer Architecture Detection | CDN/WAF/proxy/backend chain identification | [web-fingerprinting] §5-4 |
| RC9.T02.V05 | Framework and CMS Detection | Paths, headers, cookies, static files | [web-fingerprinting] §6-1 |
| RC9.T02.V06 | WAF and Security Layer Detection | WAF vendor and ruleset identification | [web-fingerprinting] §6-3 |
| RC9.T02.V07 | TLS Fingerprinting (JA3/JA4) | Client/server identification via TLS handshake | [web-fingerprinting] §1-2 |
| RC9.T02.V08 | TCP/IP Stack Fingerprinting | OS detection via TCP behavior | [web-fingerprinting] §1-1 |
| **RC9.T03** | **Cross-Site Information Leakage (XS-Leaks)** | | [web-timing-attack] |
| RC9.T03.V01 | XS-Search (Cross-Site Search) | Timing-based content inference from cross-origin | [web-timing-attack] §3-5 |
| RC9.T03.V02 | Cache State Probing | Detect resource presence via cache timing | [web-timing-attack] §3-3 |
| RC9.T03.V03 | Frame Counting / Error Event | Resource existence via iframe load events | [web-timing-attack] §3 |
| **RC9.T04** | **API & Schema Exposure** | | [graphql], [business-logic-vuln] |
| RC9.T04.V01 | GraphQL Introspection in Production | Full schema extraction via `__schema` | [graphql] §1 |
| RC9.T04.V02 | Swagger/OpenAPI Documentation Exposure | API specification publicly accessible | [business-logic-vuln] §9-1 |
| RC9.T04.V03 | Shadow/Debug Endpoint Discovery | Undocumented admin, actuator, debug endpoints | [business-logic-vuln] §9-1 |
| **RC9.T05** | **Error-Based Information Disclosure** | | [business-logic-vuln] |
| RC9.T05.V01 | Stack Trace / Debug Output Leakage | Internal paths, library versions, SQL queries in errors | [business-logic-vuln] §7-2 |
| RC9.T05.V02 | Business Rule Exposure via Errors | Threshold, constraint, and validation rule disclosure | [business-logic-vuln] §7-1 |
| RC9.T05.V03 | Metadata Leakage | EXIF, HTTP headers, API response over-exposure | [business-logic-vuln] §7-2 |
| **RC9.T06** | **Cache-Based Information Leakage** | | [web-cache-poisoning-and-deception] |
| RC9.T06.V01 | Web Cache Deception | Trick cache into storing authenticated response for attacker | [web-cache-poisoning-and-deception] §5 |
| RC9.T06.V02 | Response Queue Poisoning → Data Theft | Smuggled request steals other user's cached response | [http-request-smuggling] §7 |
| **RC9.T07** | **Pixel & Rendering Side-Channel** | | [ui-redressing] |
| RC9.T07.V01 | SVG Filter Cross-Origin Pixel Access | Timing/rendering side-channel pixel steal | [ui-redressing] §6-1 |
| RC9.T07.V02 | CSS Timing Side-Channel | Pixel color inference via CSS selector timing | [ui-redressing] §6-2 |
| RC9.T07.V03 | Drag-and-Drop Content Exfiltration | Invisible drag target to attacker page | [ui-redressing] §4-2 |
| **RC9.T08** | **Client/Browser Fingerprinting** | | [web-fingerprinting] |
| RC9.T08.V01 | Canvas/WebGL/WebGPU Fingerprinting | GPU-based unique identifier generation | [web-fingerprinting] §2 |
| RC9.T08.V02 | Audio Fingerprinting | AudioContext processing differences | [web-fingerprinting] §2-4 |
| RC9.T08.V03 | CSS and Font Fingerprinting | Font enumeration, CSS feature detection | [web-fingerprinting] §3 |
| RC9.T08.V04 | Behavioral/Biometric Fingerprinting | Keystroke, mouse, touch dynamics | [web-fingerprinting] §8 |
| RC9.T08.V05 | Encrypted Traffic Fingerprinting | Website identification through VPN/Tor via packet analysis | [web-fingerprinting] §7 |

---

## Cross-Cutting: Security Control Evasion

*Not a root cause, but an amplifier — techniques that bypass security controls to enable exploitation of underlying root-cause vulnerabilities.*

> These techniques don't create vulnerabilities themselves, but allow attackers to bypass defenses that would otherwise prevent exploitation of RC1–RC9 vulnerabilities.

| ID | Technique | Amplifies | Source |
|---|---|---|---|
| **CC1** | **WAF Payload Evasion** | RC1 (Injection), RC2 (Differential) | [waf-bypass] |
| CC1.V01 | Encoding Mutation (URL, Unicode, Hex, Double) | Multi-layer encoding bypass | [waf-bypass] §1 |
| CC1.V02 | Content-Type Switching | JSON/XML/multipart format rotation | [waf-bypass] §2-4 |
| CC1.V03 | JSON Operator Injection | JSON syntax bypasses SQL/XSS regex | [waf-bypass] §2-1 |
| CC1.V04 | Processing Limit Exploitation | Exceed WAF buffer/param/body size limits | [waf-bypass] §7-3 |
| CC1.V05 | ML-Based WAF Evasion | Adversarial inputs against ML classifiers | [waf-bypass] §7-2 |
| CC1.V06 | Origin IP Exposure / CDN Bypass | Direct-to-origin requests avoiding WAF | [waf-bypass] §9-1 |
| CC1.V07 | Comment/Whitespace Obfuscation (SQL) | `/*!50000SELECT*/`, tab/newline substitution | [sql-injection] §2-2, §2-3 |
| CC1.V08 | Case & Keyword Mutation | `SeLeCt`, keyword splitting, null byte | [sql-injection] §2-4 |
| **CC2** | **XSS Filter/Sanitizer Bypass** | RC1.T04 (XSS) | [xss] |
| CC2.V01 | Tag Obfuscation | Case variation, null bytes, attribute tricks | [xss] §8 |
| CC2.V02 | DOMPurify Bypass (mXSS) | Node flattening, regex bypass, prototype pollution | [xss] §7 |
| CC2.V03 | CSP Bypass | `unsafe-inline`, `base-uri`, JSONP gadgets, `script-src` wildcards | [xss] §8 |
| **CC3** | **Deserialization Filter Bypass** | RC6 (Deserialization) | [deserialization] |
| CC3.V01 | Blocklist Incompleteness (JEP 290) | New gadget classes not on blocklist | [deserialization] §7-1 |
| CC3.V02 | Base64/Compression/Multi-Layer Wrapping | Encoding obfuscation | [deserialization] §6-1 |
| CC3.V03 | Scanner Evasion (Alternative Callables) | Substitute known-bad functions | [deserialization] §7-2 |
| **CC4** | **File Upload Validation Bypass** | RC7.T03 (File Path), RC2.T09 (MIME) | [file-upload] |
| CC4.V01 | Extension Blocklist Evasion | `.phtml`, case variation, trailing chars, double extension | [file-upload] §1-1 |
| CC4.V02 | Content Transformation Survival | Payload in EXIF/ICC profile survives image resize | [file-upload] §3-3 |
| CC4.V03 | Server Config Override Upload | `.htaccess`, `.user.ini`, `web.config` as execution enablers | [file-upload] §6 |
| **CC5** | **Cookie Defense Bypass** | RC3 (Auth), RC5 (CSRF) | [cookie] |
| CC5.V01 | SameSite=Lax Bypass (Top-Level POST) | Cross-site cookie within 2-min Lax+POST window | [cookie] §1-1 |
| CC5.V02 | HttpOnly Bypass (Cookie Sandwich) | Extract HttpOnly cookie value via RFC 2109 parsing | [cookie] §1-2 |
| CC5.V03 | `__Host-` Prefix Bypass | Unicode normalization or `$Version` prefix evasion | [cookie] §1-3 |
| **CC6** | **Rate Limit / Anti-Automation Bypass** | RC3 (Brute-Force), RC5 (Logic) | [business-logic-vuln] |
| CC6.V01 | IP/Key/Agent Rotation | Distributed source rotation | [business-logic-vuln] §5-1 |
| CC6.V02 | Endpoint Variant Bypass | Same function via different URL path | [business-logic-vuln] §5-1 |
| CC6.V03 | Session Reset Counter Bypass | New session resets rate limit counter | [business-logic-vuln] §5-1 |
| **CC7** | **Iframe / UI Security Bypass** | RC9.T07 (Pixel Leakage) | [ui-redressing] |
| CC7.V01 | X-Frame-Options Bypass | Frame-buster bypass via `sandbox` attribute | [ui-redressing] §1-4 |
| CC7.V02 | DoubleClickjacking (Window Swap) | Cross-window timing exploit bypasses frame protections | [ui-redressing] §2-1 |
| CC7.V03 | Cursor Deception | Custom CSS cursor displacement | [ui-redressing] §5 |
| CC7.V04 | Mobile Tapjacking (TapTrap) | Animation-driven overlay on mobile | [ui-redressing] §7-2 |

---

## Cross-Cutting: Reconnaissance & Methodology

*Attacker activities for target understanding and attack surface discovery. Not a root cause, but a prerequisite for exploiting RC1–RC9.*

| ID | Activity | Key Techniques | Source |
|---|---|---|---|
| **RM1** | **Web Fingerprinting** | Server/framework/WAF detection, TLS fingerprinting, protocol behavior analysis | [web-fingerprinting] |
| **RM2** | **Web Fuzzing** | Parameter fuzzing, path brute-force, wordlist generation, mutation strategies | [web-fuzzing] |
| **RM3** | **Hidden Parameter Discovery** | Undocumented parameter enumeration, header discovery, API endpoint mapping | [recon] |
| **RM4** | **Real-World Attack Chaining** | Multi-vulnerability chain case studies (Sam Curry style) | [sam-curry] |
| **RM5** | **Identifier Predictability Analysis** | Sequential ID enumeration, UUIDv1 prediction, encoded ID reversal | [idor-bola] §1 |

---

## Framework-Specific Mapping

*Framework-specific vulnerabilities are not a separate root cause — they are instances of RC1–RC9 manifested through framework-specific features.*

### Spring Framework → [spring]

| Root Cause | Framework Manifestation |
|---|---|
| RC1 (Injection) | SpEL injection, Thymeleaf SSTI preprocessing |
| RC4 (Access Control) | Spring4Shell mass assignment via class loader property chain |
| RC6 (Deserialization) | Spring-specific gadget chains, HTTP invoker |
| RC7 (Resource Reference) | Actuator endpoint exposure, SSRF via Spring Cloud |
| RC9 (Info Leakage) | Actuator health/env endpoint data exposure |

### ASP.NET → [asp-dot-net]

| Root Cause | Framework Manifestation |
|---|---|
| RC2 (Parser Differential) | Path traversal via IIS normalization, `X-Original-URL` override |
| RC6 (Deserialization) | ViewState deserialization, BinaryFormatter, TypeNameHandling |
| RC1 (Injection) | Razor template injection, parameter binding abuse |
| RC4 (Access Control) | Web.config handler mapping override |

---

## Cross-Reference: Source Document → Root Cause

| Source Document | Primary RC | Secondary RC | Key Techniques |
|---|---|---|---|
| [sql-injection](../sql-injection/sql-injection.md) | **RC1** | RC9 (blind extraction) | RC1.T01 |
| [nosql](../nosql/nosql-injection.md) | **RC1** | RC9 (blind extraction) | RC1.T02 |
| [command-injection](../command-injection/command-injection.md) | **RC1** | — | RC1.T03 |
| [xss](../xss/xss.md) | **RC1** | RC2 (mXSS), CC2 (filter bypass) | RC1.T04 |
| [ssti](../ssti/ssti.md) | **RC1** | — | RC1.T05 |
| [el-injection](../el-injection/) | **RC1** | — | RC1.T06 |
| [xxe](../xxe/xxe.md) | **RC1** | RC7 (SSRF via XXE) | RC1.T07 |
| [ldap-xpath](../ldap-xpath/ldap-xpath.md) | **RC1** | — | RC1.T08 |
| [graphql](../graphql/graphql.md) | **RC1** | RC4 (authz), RC9 (schema exposure) | RC1.T09 |
| [jndi-injection](../jndi-injection/jndi-injection.md) | **RC1** | RC7 (resource reference) | RC1.T10 |
| [http-header](../http-header/http-header.md) | **RC1** | RC2 (header parsing) | RC1.T11 |
| [email](../email/) | **RC1** | RC2 (SMTP parsing) | RC1.T12 |
| [prototype-pollution](../prototype-pollution/prototype-pollution.md) | **RC1** | RC6 (gadgets → RCE) | RC1.T13 |
| [http-request-smuggling](../http-parsing-discrepancy/http-request-smuggling.md) | **RC2** | RC8 (trust boundary) | RC2.T01 |
| [url-confusion](../url-confusion/url-confusion.md) | **RC2** | RC7 (SSRF/redirect) | RC2.T02 |
| [unicode](../unicode/unicode.md) | **RC2** | CC1 (WAF evasion) | RC2.T03 |
| [hpp](../http-parameter-pollution/hpp.md) | **RC2** | RC1 (injection enabler) | RC2.T04 |
| [reverse-proxy-misrouting](../http-parsing-discrepancy/reverse-proxy-misrouting.md) | **RC2** | RC4 (ACL bypass), RC8 (trust) | RC2.T05 |
| [cookie](../cookie/cookie.md) | **RC2** (parsing), **RC3** (session), **RC8** (scope) | CC5 (defense bypass) | RC2.T06, RC3.T07, RC8.T05 |
| [saml](../saml/saml.md) | **RC3** | RC2 (parser diff), RC1 (XXE) | RC3.T02, RC2.T07 |
| [web-cache-poisoning-and-deception](../web-cache-poisoning-and-deception/) | **RC2** | RC9 (cache deception) | RC2.T10, RC9.T06 |
| [protocol-level-waf-bypass](../http-parsing-discrepancy/protocol-level-waf-bypass.md) | **RC2** | CC1 (WAF evasion) | RC2.T11 |
| [http-censorship-bypass](../http-parsing-discrepancy/http-censorship-bypass.md) | **RC2** | — | RC2.T12 |
| [jwt](../jwt/jwt.md) | **RC3** | RC4 (claim escalation) | RC3.T01 |
| [oauth](../oauth/oauth.md) | **RC3** | RC7 (redirect), RC4 (scope) | RC3.T03 |
| [authentication-bypass-and-sso](../authentication-bypass-and-sso/) | **RC3** | — | RC3.T04 |
| [ato](../account-takeover/ato.md) | **RC3** | RC5 (CSRF → ATO) | RC3.T05–RC3.T09 |
| [idor-bola](../idor-bola/idor-bola.md) | **RC4** | RC9 (enumeration) | RC4.T01 |
| [mass-assignment](../mass-assignment/mass-assignment.md) | **RC4** | RC1 (prototype pollution) | RC4.T03 |
| [cors-misconfiguration](../cors-misconfiguration/) | **RC4** | RC8 (cross-origin trust) | RC4.T04 |
| [state-machine-violation](../state-machine-violation/) | **RC5** | — | RC5.T01 |
| [web-race-condition](../web-race-condition/) | **RC5** | — | RC5.T02 |
| [csrf](../csrf/csrf.md) | **RC5** | RC3 (session auth) | RC5.T03 |
| [business-logic-vuln](../business-logic-bug/business-logic-vuln.md) | **RC5** | RC4 (authz), RC9 (info leak) | RC5.T04–RC5.T06, RC4.T02 |
| [deserialization](../deserialization/deserialization.md) | **RC6** | RC1 (nested injection) | RC6.T01–RC6.T08 |
| [ssrf](../ssrf/ssrf.md) | **RC7** | RC2 (URL parsing), RC8 (trust) | RC7.T01 |
| [open-redirect](../open-redirect/) | **RC7** | RC3 (token theft) | RC7.T02 |
| [file-upload](../file-upload/file-upload.md) | **RC7** (path), **RC2** (MIME) | RC5 (race), RC1 (XSS) | RC7.T03, RC2.T09 |
| [rmi](../rmi/rmi.md) | **RC7** | RC6 (deserialization) | RC7.T04 |
| [jdbc-attack](../jdbc-attack/jdbc-attack.md) | **RC7** | — | RC7.T05 |
| [zip](../zip-archive/zip.md) | **RC7** (path), **RC2** (structure) | CC4 (validation) | RC7.T03, RC2.T08 |
| [implicit-trust-boundary](../implicit-trust-boundary/) | **RC8** | RC4 (authz) | RC8.T01 |
| [secondary-context-attack](../secondary-context-attack/) | **RC8** | RC7 (callback SSRF) | RC8.T02, RC8.T06 |
| [dns-web-security](../dns-web-security/) | **RC8** | RC7 (rebinding → SSRF) | RC8.T03 |
| [dependency-confusion](../dependency-confusion/) | **RC8** | — | RC8.T04 |
| [websocket](../websocket/websocket.md) | **RC8** | RC5 (CSWSH ≈ CSRF) | RC8.T07 |
| [jaas-attack](../jaas-attack/jaas-attack.md) | **RC8** | RC3 (auth bypass) | RC8.T08 |
| [web-timing-attack](../web-timing-attack/) | **RC9** | — | RC9.T01, RC9.T03 |
| [web-fingerprinting](../web-fingerprinting/) | **RC9** | — | RC9.T02, RC9.T08 |
| [ui-redressing](../ui-redressing/ui-redressing.md) | **RC9** (pixel), CC7 (UI bypass) | RC5 (click → state change) | RC9.T07, CC7 |
| [waf-bypass](../waf-bypass/payload-level-waf-bypass.md) | **CC1** | — | CC1 |
| [web-fuzzing](../web-fuzzing/web-fuzzing.md) | **RM2** | — | RM2 |
| [recon](../recon/) | **RM3** | — | RM3 |
| [sam-curry](../sam-curry/sam-curry.md) | **RM4** | — | RM4 |
| [spring](../spring/spring.md) | RC1, RC4, RC6, RC7 | RC9 | Framework-specific |
| [asp-dot-net](../asp-dot-net/asp-dot-net.md) | RC2, RC6, RC1 | RC4 | Framework-specific |

---

## Impact Mapping: Root Cause → Achievable Impact

*The same root cause can lead to different impacts depending on context. This matrix shows what each RC can achieve.*

| Impact | RC1 | RC2 | RC3 | RC4 | RC5 | RC6 | RC7 | RC8 | RC9 |
|---|---|---|---|---|---|---|---|---|---|
| **Remote Code Execution** | SQLi→cmd, SSTI, EL, XXE→SSRF | Smuggling→pipeline | — | Mass Assignment (Spring4Shell) | — | Primary impact | JNDI, RMI, JDBC | — | — |
| **Authentication Bypass** | SQLi auth bypass | SAML parser diff | Primary impact | — | CSRF→auth change | — | — | Service trust bypass | — |
| **Data Exfiltration** | SQLi, XXE, XSS | Cache deception | Token theft | IDOR mass access | — | Deser→file read | SSRF→metadata | Cross-tenant | Timing, XS-Leaks |
| **Privilege Escalation** | — | Path confusion ACL bypass | JWT claim, OAuth scope | Primary impact | State skip→admin | — | — | Confused deputy | — |
| **Account Takeover** | XSS→cookie steal | — | Primary impact | — | CSRF→email change | — | Open redirect→token | SSO linking | — |
| **Denial of Service** | — | Smuggling→desync | PBES2 DoS | — | Cart bombing | Zip bomb, ReDoS | — | — | — |
| **Financial Fraud** | — | — | — | — | Primary impact | — | — | — | — |
| **Lateral Movement** | — | Smuggling→hijack | SSO token relay | Cross-tenant IDOR | — | — | SSRF→internal | Primary impact | — |

---

## Statistics

| Metric | Count |
|---|---|
| **Root Causes** | 9 |
| **Cross-Cutting Categories** | 2 (Security Control Evasion + Recon & Methodology) |
| **Technique Classes** | 88 |
| **Specific Variants** | 340+ |
| **Source Documents Mapped** | 52+ |

---

## Design Rationale

### Why 9 Root Causes?

Each root cause maps to a **fundamental security principle** that is violated:

| RC | Security Principle Violated |
|---|---|
| RC1 — Injection | **Input/Output Separation**: Data and control planes must be distinct |
| RC2 — Parser Differential | **Consistent Interpretation**: All components must parse input identically |
| RC3 — Authentication Failure | **Identity Verification**: Identity claims must be cryptographically verified |
| RC4 — Access Control Gap | **Authorization Enforcement**: Every resource access must be authorized |
| RC5 — State Violation | **State Integrity**: State transitions must be enforced server-side with atomicity |
| RC6 — Deserialization | **Data/Code Separation**: Untrusted data must never become executable code |
| RC7 — Resource Reference | **Reference Validation**: Resource references from user input must be constrained |
| RC8 — Trust Boundary | **Trust Verification**: Every trust boundary requires independent verification |
| RC9 — Information Leakage | **Information Minimization**: Systems must reveal only what is necessary |

### Practical Application

**Red Team Workflow**: Find an input vector → Identify which root cause applies → Enumerate all variants under that RC → Test systematically.

**Blue Team Workflow**: Identify which root causes your application is exposed to → Implement the corresponding security principle → Verify that all technique variants are mitigated.

**Detection Engineering**: Each RC maps to distinct detection patterns — injection signatures (RC1), header anomalies (RC2), auth failure patterns (RC3), access pattern anomalies (RC4), state inconsistencies (RC5), serialized object markers (RC6), outbound request anomalies (RC7), internal traffic anomalies (RC8), timing/error patterns (RC9).

---

*This taxonomy was synthesized from the [the-map](../README.md) vulnerability research collection. Built for defensive security research, AI agent consumption, and systematic penetration testing workflows.*
