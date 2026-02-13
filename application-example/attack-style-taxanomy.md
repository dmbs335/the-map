# The Map — Web Attack Taxonomy (MITRE ATT&CK Style)

> A unified classification of all attack techniques documented across the project, organized into **Tactics** (strategic objectives) and **Techniques/Sub-Techniques** (specific methods), following MITRE ATT&CK's hierarchical ID convention.

---

## How to Read This Document

| Element | Format | Example |
|---------|--------|---------|
| **Tactic** | `TA####` | `TA0001` — Reconnaissance |
| **Technique** | `T####` | `T1001` — Server Fingerprinting |
| **Sub-Technique** | `T####.###` | `T1001.001` — HTTP Response Header Analysis |
| **Source Document** | `[doc-name]` | Links to original taxonomy file |

---

## Tactic Overview Matrix

| ID | Tactic | Description | Technique Count |
|---|---|---|---|
| **TA0001** | Reconnaissance | Gathering information about target systems, technology stacks, and users | 10 |
| **TA0002** | Resource Development | Preparing infrastructure, payloads, gadget chains, and tooling | 6 |
| **TA0003** | Initial Access | Gaining entry to the application through injection, upload, or protocol abuse | 14 |
| **TA0004** | Execution | Achieving code execution on server or client through deserialization, template injection, etc. | 8 |
| **TA0005** | Persistence | Maintaining access through sessions, tokens, configuration override, or account linking | 7 |
| **TA0006** | Privilege Escalation | Elevating from low-privilege to admin or cross-tenant access | 8 |
| **TA0007** | Defense Evasion | Bypassing WAFs, filters, scanners, security headers, and validation | 14 |
| **TA0008** | Credential Access | Stealing or forging authentication tokens, session cookies, passwords, or keys | 10 |
| **TA0009** | Lateral Movement | Pivoting between services, tenants, or trust boundaries | 6 |
| **TA0010** | Collection | Extracting data through IDOR, blind inference, timing oracles, or data leakage | 8 |
| **TA0011** | Exfiltration | Moving stolen data out via OOB channels, DNS, redirects, or cache abuse | 5 |
| **TA0012** | Impact | Causing denial of service, data manipulation, financial fraud, or UI deception | 8 |

---

## TA0001 — Reconnaissance

*Gathering information about the target's technology stack, architecture, users, and attack surface.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T1001** | **Server & Technology Fingerprinting** | | [web-fingerprinting] |
| T1001.001 | HTTP Response Header Analysis | Identify server software, framework, version from headers | [web-fingerprinting] §5-1 |
| T1001.002 | Error Response Fingerprinting | Differentiate tech stack from error pages and debug output | [web-fingerprinting] §5-2 |
| T1001.003 | Protocol Behavior Fingerprinting | HTTP/2, HTTP/3, TLS behavior differences | [web-fingerprinting] §5-3 |
| T1001.004 | Multi-Layer Architecture Fingerprinting | Detect proxy/CDN/WAF/backend chain | [web-fingerprinting] §5-4 |
| T1001.005 | Framework and CMS Detection | Identify frameworks from paths, headers, cookies | [web-fingerprinting] §6-1 |
| T1001.006 | WAF and Security Layer Detection | Identify WAF vendor and ruleset | [web-fingerprinting] §6-3 |
| **T1002** | **Network Protocol Fingerprinting** | | [web-fingerprinting] |
| T1002.001 | TCP/IP Stack Fingerprinting | OS detection via TCP behavior | [web-fingerprinting] §1-1 |
| T1002.002 | TLS Fingerprinting (JA3/JA4) | Client/server identification via TLS handshake | [web-fingerprinting] §1-2 |
| T1002.003 | HTTP/2-HTTP/3 Fingerprinting | Protocol-level behavior analysis | [web-fingerprinting] §1-3 |
| **T1003** | **Client/Browser Fingerprinting** | | [web-fingerprinting] |
| T1003.001 | Canvas/WebGL/WebGPU Fingerprinting | GPU-based unique identifier generation | [web-fingerprinting] §2 |
| T1003.002 | Audio Fingerprinting | AudioContext processing differences | [web-fingerprinting] §2-4 |
| T1003.003 | CSS and Font Fingerprinting | Font enumeration, CSS feature detection | [web-fingerprinting] §3 |
| T1003.004 | Behavioral/Biometric Fingerprinting | Keystroke, mouse, touch dynamics | [web-fingerprinting] §8 |
| **T1004** | **User and Account Enumeration** | | [ato], [web-timing-attack] |
| T1004.001 | Username Enumeration via Differential Response | Login/reset response difference | [ato] §6-2 |
| T1004.002 | Timing-Based Existence Oracle | Response time differences for valid vs invalid | [web-timing-attack] §1-1 |
| T1004.003 | Business Rule Exposure via Error Messages | Threshold/constraint leak in errors | [business-logic-vuln] §7-1 |
| **T1005** | **API Schema Discovery** | | [idor-bola], [business-logic-vuln] |
| T1005.001 | GraphQL Introspection Abuse | Full schema extraction | [idor-bola] §4-2, [business-logic-vuln] §9-1 |
| T1005.002 | API Documentation Exposure | Swagger/OpenAPI spec leak | [business-logic-vuln] §9-1 |
| T1005.003 | Shadow Endpoint Discovery | Undocumented admin/debug endpoints | [business-logic-vuln] §9-1 |
| **T1006** | **Encrypted Traffic Fingerprinting** | | [web-fingerprinting] |
| T1006.001 | Website Fingerprinting via Packet Analysis | Traffic pattern analysis through VPN/Tor | [web-fingerprinting] §7 |
| **T1007** | **RMI/Service Enumeration** | | [rmi] |
| T1007.001 | RMI Registry Enumeration | Discover bound remote objects | [rmi] §9-1 |
| T1007.002 | Method Signature Brute-Forcing | Discover callable methods on RMI objects | [rmi] §3-2 |
| **T1008** | **Identifier Predictability Analysis** | | [idor-bola] |
| T1008.001 | Sequential ID Enumeration | Auto-increment PK brute-force | [idor-bola] §1-1 |
| T1008.002 | UUIDv1 Timestamp Prediction | Narrow UUID space via known creation time | [idor-bola] §1-2 |
| T1008.003 | Encoded ID Reversal (Base64, Hash) | Decode or brute-force obscured IDs | [idor-bola] §1-3 |
| **T1009** | **Timing Side-Channel Information Gathering** | | [web-timing-attack] |
| T1009.001 | Database Query Timing Differential | Infer record existence via response time | [web-timing-attack] §1-3 |
| T1009.002 | XS-Leaks / Cross-Site Search | Browser-side timing leaks | [web-timing-attack] §3 |
| T1009.003 | Cache State Probing | Detect resource presence via cache timing | [web-timing-attack] §3-3 |
| **T1010** | **Pricing/Algorithm Reverse Engineering** | | [business-logic-vuln] |
| T1010.001 | Business Rule Probing | Systematic input variation to expose thresholds | [business-logic-vuln] §7-1 |

---

## TA0002 — Resource Development

*Preparing tools, payloads, gadget chains, and infrastructure for attacks.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T2001** | **Gadget Chain Construction** | | [deserialization] |
| T2001.001 | Property-Oriented Programming (POP) Chains | Library/framework class chain to RCE | [deserialization] §1-1 |
| T2001.002 | Dormant/Latent Gadget Activation | Chains activated by dependency updates | [deserialization] §1-2 |
| T2001.003 | Automated Gadget Mining (FLASH, ODDFuzz) | Static/dynamic analysis for chain discovery | [deserialization] §1-3 |
| **T2002** | **Payload Construction** | | [sql-injection], [file-upload] |
| T2002.001 | Polyglot File Construction | Files valid under multiple formats | [file-upload] §3-2 |
| T2002.002 | SQL Injection Payload Crafting | UNION, stacked, blind payloads | [sql-injection] §1 |
| T2002.003 | Serialized Object Payload Generation | ysoserial, PHPGGC, pickle crafting | [deserialization] §4 |
| **T2003** | **Phishing Infrastructure** | | [ato] |
| T2003.001 | AiTM Reverse Proxy Setup (Evilginx) | Real-time credential/session capture | [ato] §4-3 |
| T2003.002 | Device Code Phishing Campaign | OAuth device authorization abuse | [ato] §4-3 |
| **T2004** | **Malicious Model/Package Preparation** | | [deserialization] |
| T2004.001 | ML Model File Poisoning | Pickle-based backdoors in .pt/.h5 files | [deserialization] §9-1 |
| T2004.002 | Sleepy Pickle (Stealthy Model Tampering) | In-place model modification during deser | [deserialization] §9-1 |
| T2004.003 | Supply Chain Package Poisoning | Compromised dependencies completing gadgets | [deserialization] §1-2 |
| **T2005** | **Unicode Payload Preparation** | | [unicode] |
| T2005.001 | Homoglyph Domain Registration | Confusable character domain spoofing | [unicode] §6-1 |
| T2005.002 | BiDi Text Payload Crafting | RTLO/LRI filename/code deception | [unicode] §3-2 |
| **T2006** | **Credential Collection Infrastructure** | | [ato] |
| T2006.001 | Credential Stuffing List Preparation | Breached credential optimization | [ato] §6-1 |
| T2006.002 | Infostealer Deployment | Cookie/credential harvesting malware | [cookie] §7-2 |

---

## TA0003 — Initial Access

*Gaining the initial foothold into the application or system.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T3001** | **SQL Injection** | | [sql-injection] |
| T3001.001 | WHERE Clause Tautology | `OR 1=1` authentication bypass | [sql-injection] §1-1 |
| T3001.002 | UNION-Based Injection | Cross-table data extraction | [sql-injection] §1-2 |
| T3001.003 | Stacked Queries | Multi-statement execution | [sql-injection] §1-3 |
| T3001.004 | Second-Order Injection | Stored payload triggered later | [sql-injection] §6-1 |
| T3001.005 | JSON-Based SQL WAF Bypass | JSON operators in SQL context | [sql-injection] §7-2 |
| T3001.006 | ORM/Framework Layer Bypass | Raw query through ORM escape | [sql-injection] §8-2 |
| **T3002** | **Server-Side Request Forgery (SSRF)** | | [ssrf] |
| T3002.001 | IP Address Obfuscation (Octal, Hex, IPv6) | Numeric representation bypass | [ssrf] §1 |
| T3002.002 | DNS Rebinding | Time-of-check IP change | [ssrf] §6-1 |
| T3002.003 | Protocol Smuggling via Gopher | Cross-protocol interaction | [ssrf] §3-3 |
| T3002.004 | Cloud Metadata Service Access | 169.254.169.254 exploitation | [ssrf] §8 |
| T3002.005 | Redirect Chain Bypass | HTTP redirect following to internal | [ssrf] §7-1 |
| **T3003** | **HTTP Request Smuggling** | | [http-request-smuggling] |
| T3003.001 | CL.TE / TE.CL Classic Smuggling | Content-Length vs Transfer-Encoding | [http-request-smuggling] §1-1 |
| T3003.002 | CL.0 / 0.CL Zero-Length Smuggling | Implicit zero body desync | [http-request-smuggling] §1-2 |
| T3003.003 | H2.CL / H2.TE HTTP/2 Downgrade Smuggling | Protocol conversion framing mismatch | [http-request-smuggling] §1-3 |
| T3003.004 | Chunk Extension Smuggling (TERM.EXT) | Newline in chunk extension desync | [http-request-smuggling] §2-1 |
| T3003.005 | Pause-Based / Timing Desync | Temporal body arrival manipulation | [http-request-smuggling] §1-4 |
| T3003.006 | TLS Upgrade Desync (Opossum Attack) | Cross-protocol TLS desync | [http-request-smuggling] §6 |
| **T3004** | **File Upload Exploitation** | | [file-upload] |
| T3004.001 | Extension Validation Bypass | Alternative extensions, double extension, null byte | [file-upload] §1 |
| T3004.002 | Content-Type / Magic Byte Manipulation | MIME spoofing, header prepending | [file-upload] §2, §3 |
| T3004.003 | Multipart Parser Differential | WAF vs backend parsing mismatch | [file-upload] §4 |
| T3004.004 | Path Traversal via Filename | `../../` in uploaded filename | [file-upload] §5-1 |
| T3004.005 | Server Configuration Override (.htaccess) | Upload config files to change execution rules | [file-upload] §6 |
| T3004.006 | Upload Race Condition | Access before validation/deletion | [file-upload] §9 |
| **T3005** | **Deserialization Attack** | | [deserialization] |
| T3005.001 | Java ObjectInputStream RCE | Commons Collections, TemplatesImpl chains | [deserialization] §8-1 |
| T3005.002 | Python Pickle RCE | `__reduce__` arbitrary code execution | [deserialization] §8-2 |
| T3005.003 | PHP unserialize POP Chains | `__wakeup`/`__destruct` exploitation | [deserialization] §8-3 |
| T3005.004 | .NET BinaryFormatter/ViewState RCE | ysoserial.net gadget chains | [deserialization] §8-4 |
| T3005.005 | YAML Arbitrary Object Instantiation | SnakeYAML, PyYAML unsafe loading | [deserialization] §4-2 |
| T3005.006 | React Flight Protocol Exploitation | Prototype pollution → RCE | [deserialization] §2-3 |
| T3005.007 | PHAR Metadata Deserialization | `phar://` stream wrapper trigger | [deserialization] §4-3 |
| T3005.008 | Nested/Format-Crossing Deserialization | JSON→XML→XXE chain (CosmicSting) | [deserialization] §5-1 |
| **T3006** | **OAuth/SSO Flow Exploitation** | | [oauth], [sso] |
| T3006.001 | Redirect URI Manipulation | Open redirect token/code leak | [oauth] §1 |
| T3006.002 | Authorization Code Injection | CSRF callback with attacker's code | [oauth] §2-1 |
| T3006.003 | IdP Mix-Up Attack | Confuse RP about which IdP issued token | [oauth] §8-2 |
| T3006.004 | Device Authorization Grant Abuse | Device code phishing | [oauth] §8-3 |
| T3006.005 | Dynamic Client Registration Abuse | Register malicious client | [oauth] §3-1 |
| **T3007** | **SAML Authentication Bypass** | | [saml] |
| T3007.001 | XML Signature Wrapping (XSW) | Move signed element, inject assertion | [saml] §1 |
| T3007.002 | Parser Differential Exploitation | Dual-parser assertion divergence | [saml] §2 |
| T3007.003 | Golden/Silver SAML | Forged assertions with stolen keys | [saml] §5-1 |
| T3007.004 | SAML XXE Injection | External entity in SAML message | [saml] §6 |
| **T3008** | **JWT Token Forgery** | | [jwt] |
| T3008.001 | None Algorithm Bypass | Remove signature verification | [jwt] §1-1 |
| T3008.002 | Algorithm Confusion (RS256→HS256) | Public key as HMAC secret | [jwt] §1-2 |
| T3008.003 | Header Parameter Injection (kid, jku, jwk) | Control key resolution | [jwt] §2 |
| T3008.004 | Weak Key Brute-Force | Crack HMAC secret | [jwt] §3-1 |
| **T3009** | **Credential Replay & Brute-Force** | | [ato] |
| T3009.001 | Credential Stuffing | Automated leaked credential testing | [ato] §6-1 |
| T3009.002 | Password Spraying | Common passwords across many accounts | [ato] §6-1 |
| T3009.003 | OTP/MFA Brute-Force | Exhaustive 4-6 digit code guessing | [ato] §4-1 |
| **T3010** | **Pre-Account Takeover** | | [ato] |
| T3010.001 | Classic-Federated Merge | Pre-create account, auto-link on OAuth | [ato] §1-1 |
| T3010.002 | Trojan Identifier | Pre-add secondary auth factors | [ato] §1-1 |
| T3010.003 | Non-Verifying IdP Exploit | IdP without email verification | [ato] §1-1 |
| **T3011** | **Secondary Context Attack** | | [secondary-context-attack] |
| T3011.001 | BFF/API Gateway Path Escape | Traverse proxy path boundaries | [secondary-context-attack] §1 |
| T3011.002 | Webhook/Callback SSRF | Attacker-controlled callback URLs | [secondary-context-attack] §2-3 |
| T3011.003 | Confused Deputy (Cloud Delegation) | Cross-tenant role assumption | [secondary-context-attack] §5 |
| **T3012** | **Reverse Proxy Misrouting** | | [reverse-proxy-misrouting] |
| T3012.001 | Path Normalization Differential | Dot-segment, semicolon, encoding mismatch | [reverse-proxy-misrouting] §1 |
| T3012.002 | Host Header SSRF via Proxy | Proxy routes to attacker-supplied host | [reverse-proxy-misrouting] §2 |
| T3012.003 | HTTP/2 Pseudo-Header Exploitation | `:scheme`, `:authority` injection | [reverse-proxy-misrouting] §3 |
| T3012.004 | Ingress Controller Annotation Injection | IngressNightmare — Nginx config injection | [reverse-proxy-misrouting] §7-2 |
| **T3013** | **HTTP Parameter Pollution** | | [hpp] |
| T3013.001 | Duplicate Parameter Precedence Abuse | First-wins vs last-wins mismatch | [hpp] §1-1 |
| T3013.002 | Query-Body Cross-Pollution | Parameter source merge confusion | [hpp] §2-2 |
| T3013.003 | JSON Duplicate Key Injection | RFC 8259 ambiguity exploitation | [hpp] §3-1 |
| T3013.004 | Server-Side Parameter Injection | Internal API parameter override | [hpp] §8-1 |
| **T3014** | **RMI/JNDI Remote Code Execution** | | [rmi] |
| T3014.001 | RMI Registry Deserialization | bind/rebind payload injection | [rmi] §1-1 |
| T3014.002 | JNDI Reference Injection | Remote class loading via LDAP/RMI | [rmi] §5 |
| T3014.003 | JMX Exploitation | MBean code execution | [rmi] §4 |
| T3014.004 | Remote Class Loading | Client/server codebase abuse | [rmi] §6 |

---

## TA0004 — Execution

*Achieving code execution on target systems.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T4001** | **Server-Side Code Execution via Deserialization** | | [deserialization] |
| T4001.001 | Magic Method Chain Execution | `readObject`, `__reduce__`, `__wakeup` | [deserialization] §3 |
| T4001.002 | JNDI Injection → Remote Class Load | Deserialization triggers JNDI lookup | [deserialization] §5-2 |
| T4001.003 | Template Injection via Deserialized Data | SSTI through deserialized values | [deserialization] §5-2 |
| **T4002** | **Server-Side Processing Pipeline RCE** | | [file-upload] |
| T4002.001 | ImageMagick Delegate Injection (ImageTragick) | SVG/MVG command execution | [file-upload] §7-1 |
| T4002.002 | GhostScript Command Execution | PostScript/EPS processing RCE | [file-upload] §7-1 |
| T4002.003 | ExifTool RCE | DjVu filename Perl evaluation | [file-upload] §7-1 |
| **T4003** | **Client-Side Code Execution** | | [secondary-context-attack], [cookie] |
| T4003.001 | Stored XSS via File Upload | SVG/HTML inline rendering | [file-upload] §8-2 |
| T4003.002 | Prototype Pollution → RCE (Node.js) | `__proto__` chain to child_process | [deserialization] §8-6 |
| **T4004** | **SQL-Based Code Execution** | | [sql-injection] |
| T4004.001 | OS Command via SQL (xp_cmdshell, COPY) | DBMS command execution features | [sql-injection] §3-3 |
| T4004.002 | File Write via SQL (INTO OUTFILE) | Write webshell via SQL | [sql-injection] §3-1 |
| **T4005** | **Command Injection via Filename** | | [file-upload] |
| T4005.001 | Shell Metacharacter in Filename | Backtick, `$()`, pipe injection | [file-upload] §5-2 |
| **T4006** | **ML Model Execution** | | [deserialization] |
| T4006.001 | PyTorch/Keras/Joblib Model RCE | `torch.load()`, `keras.models.load_model()` | [deserialization] §9-1 |
| T4006.002 | ML Framework Exploitation (vLLM, LangChain) | ZeroMQ pickle, prompt injection → deser | [deserialization] §9-2 |
| **T4007** | **Archive Extraction Exploitation** | | [zip] |
| T4007.001 | Zip Slip Path Traversal | `../../` in archive entry names | [zip] §1-1, [file-upload] §7-3 |
| T4007.002 | Symlink Escape | Archive symlinks to sensitive files | [zip] §2, [file-upload] §7-3 |
| **T4008** | **Server Configuration Manipulation** | | [file-upload] |
| T4008.001 | .htaccess Handler Override | `AddType` PHP execution on any extension | [file-upload] §6-1 |
| T4008.002 | .user.ini auto_prepend | PHP include injection | [file-upload] §6-2 |
| T4008.003 | web.config Handler Mapping | IIS handler reconfiguration | [file-upload] §6-3 |

---

## TA0005 — Persistence

*Maintaining access to the compromised application or account.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T5001** | **Session Persistence** | | [ato], [cookie] |
| T5001.001 | Unexpired Session After Password Reset | Session survives credential change | [ato] §1-1 |
| T5001.002 | Session Non-Invalidation on Logout | Server-side session not destroyed | [cookie] §8-2 |
| T5001.003 | Long-Lived "Remember Me" Token Abuse | 30-90 day persistent cookies | [cookie] §7-3 |
| T5001.004 | Pass-the-Cookie / Token Replay | Stolen post-MFA session reuse | [cookie] §7-3 |
| **T5002** | **Account Linking Persistence** | | [ato], [oauth] |
| T5002.001 | Trojan Secondary Auth Factor | Pre-planted backup email/phone persists | [ato] §1-1 |
| T5002.002 | Dangling OAuth Connection | Deleted social account's link persists | [ato] §5-2 |
| T5002.003 | Unexpired Email Change Token | Pending change completed after recovery | [ato] §1-1 |
| **T5003** | **Configuration-Based Persistence** | | [file-upload] |
| T5003.001 | Uploaded .htaccess/.user.ini Persistence | Permanent handler/include override | [file-upload] §6 |
| **T5004** | **Token Lifecycle Abuse** | | [jwt], [oauth] |
| T5004.001 | Non-Revocable JWT Exploitation | Stateless tokens valid until expiry | [jwt] §7-4 |
| T5004.002 | Refresh Token Theft & Reuse | Long-lived refresh token compromise | [oauth] §7-2 |
| **T5005** | **Cookie-Based Persistence** | | [cookie] |
| T5005.001 | Cookie-Bite (Malicious Browser Extension) | Extension exfiltrates Azure Entra ID tokens | [cookie] §7-2 |
| T5005.002 | Infostealer Malware Harvesting | Systematic browser cookie extraction | [cookie] §7-2 |
| **T5006** | **Subscription/Trial Abuse Persistence** | | [business-logic-vuln] |
| T5006.001 | Trial Extension / Account Cycling | Repeated free tier access | [business-logic-vuln] §10-3 |
| T5006.002 | Downgrade Feature Retention | Keep premium features after downgrade | [business-logic-vuln] §10-3 |
| **T5007** | **Golden/Silver SAML Persistence** | | [saml] |
| T5007.001 | Forged SAML Assertions | Persistent admin access with stolen signing key | [saml] §5-1 |

---

## TA0006 — Privilege Escalation

*Elevating access rights from user to admin, cross-tenant, or cross-role.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T6001** | **Mass Assignment / Property Injection** | | [mass-assignment] |
| T6001.001 | Boolean Admin Flag Injection | `isAdmin=true` in request body | [mass-assignment] §1-1 |
| T6001.002 | Role/Permission String Injection | `role=admin` parameter | [mass-assignment] §1-2 |
| T6001.003 | Account State Manipulation | `verified=true`, `active=true` | [mass-assignment] §1-3 |
| T6001.004 | Spring4Shell Class Loader Access | Property chain to RCE | [mass-assignment] §5-1 |
| T6001.005 | Prototype Pollution (JavaScript) | `__proto__` property override | [mass-assignment] §5-3 |
| **T6002** | **Vertical Privilege Escalation** | | [business-logic-vuln], [idor-bola] |
| T6002.001 | Direct Admin Endpoint Access | Forced browsing to `/admin/` | [business-logic-vuln] §3-1 |
| T6002.002 | Function-Level Authorization Gap | Protected panel, unprotected function | [business-logic-vuln] §3-1 |
| T6002.003 | HTTP Method Switching for Bypass | GET blocked, POST allowed | [idor-bola] §3-1 |
| T6002.004 | API Version Bypass | Legacy API without auth controls | [business-logic-vuln] §3-3 |
| **T6003** | **Horizontal Privilege Escalation (IDOR/BOLA)** | | [idor-bola] |
| T6003.001 | Sequential ID Manipulation | `user_id=1001→1002` | [idor-bola] §1-1 |
| T6003.002 | BOLA via REST Sub-Resource Traversal | Nested resource ID swap | [idor-bola] §4-1 |
| T6003.003 | GraphQL Node/Alias Enumeration | Global ID query, alias-based mass access | [idor-bola] §4-2 |
| T6003.004 | Cross-Tenant Object Access | Tenant ID manipulation | [idor-bola] §5-3 |
| T6003.005 | Blind IDOR (Write-Only) | Modify victim's data without feedback | [idor-bola] §6-2 |
| **T6004** | **JWT Claim Escalation** | | [jwt] |
| T6004.001 | Identity Claim Manipulation (`sub`, `email`) | Change subject to admin | [jwt] §4-1 |
| T6004.002 | Authorization Claim Manipulation (`role`, `scope`) | Elevate permissions in token | [jwt] §4-2 |
| **T6005** | **State Machine Privilege Bypass** | | [state-machine-violation] |
| T6005.001 | Approval Chain Bypass | Skip intermediate approval steps | [state-machine-violation] §1-1 |
| T6005.002 | MFA Step Skip | Access post-MFA endpoint directly | [ato] §4-2 |
| **T6006** | **OAuth Scope Escalation** | | [oauth] |
| T6006.001 | Scope Manipulation | Request elevated scopes | [oauth] §5-2 |
| T6006.002 | Consent Bypass | Skip consent screen | [oauth] §5-1 |
| **T6007** | **Registration-Based Escalation** | | [ato] |
| T6007.001 | Admin Registration Endpoint Exposure | Public `/admin/register` access | [ato] §8-2 |
| T6007.002 | Invitation System Role Tampering | Modify role in invitation token | [ato] §8-2 |
| **T6008** | **Object Property Level Manipulation (BOPLA)** | | [idor-bola] |
| T6008.001 | Sensitive Field Exposure | Unfiltered full object in API response | [idor-bola] §5-2 |
| T6008.002 | Read-Only Field Overwrite | Modify immutable fields via PATCH | [idor-bola] §5-2 |

---

## TA0007 — Defense Evasion

*Bypassing security controls including WAFs, filters, validators, and security headers.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T7001** | **WAF Rule Evasion** | | [waf-bypass] |
| T7001.001 | Payload Encoding Mutation (URL, Unicode, Hex) | Multi-layer encoding bypass | [waf-bypass] §1 |
| T7001.002 | Content-Type Confusion | JSON/XML/multipart switching | [waf-bypass] §2-4 |
| T7001.003 | HTTP Parameter Pollution Split | Fragmented payload across params | [hpp] §8-3 |
| T7001.004 | JSON-Based SQL/XSS Evasion | JSON operators bypassing regex | [waf-bypass] §2-1 |
| T7001.005 | Processing Limit Exploitation | Exceed WAF buffer/param limits | [waf-bypass] §7-3 |
| T7001.006 | ML-Based WAF Evasion | Adversarial inputs against ML models | [waf-bypass] §7-2 |
| T7001.007 | Origin IP Exposure | Direct-to-origin bypassing CDN/WAF | [waf-bypass] §9-1 |
| **T7002** | **Cookie Security Bypass** | | [cookie] |
| T7002.001 | SameSite Bypass (Lax+POST, Method Override) | Cross-site cookie sending | [cookie] §1-1 |
| T7002.002 | HttpOnly Bypass (Cookie Sandwich) | RFC 2109 parsing to leak HttpOnly | [cookie] §1-2 |
| T7002.003 | Cookie Prefix Bypass (__Host-) | Unicode normalization, `$Version` | [cookie] §1-3 |
| T7002.004 | Cookie Tossing (Subdomain Injection) | Same-name cookie from sibling domain | [cookie] §5-2 |
| **T7003** | **Transfer-Encoding Obfuscation** | | [http-request-smuggling] |
| T7003.001 | TE Value Pollution | `xchunked`, tab/space injection | [http-request-smuggling] §2-1 |
| T7003.002 | Content-Length Obfuscation | Whitespace, signs, duplicates | [http-request-smuggling] §2-2 |
| T7003.003 | H2 Binary Header Mutation | CRLF injection, pseudo-header abuse | [http-request-smuggling] §2-3 |
| **T7004** | **Encoding and Normalization Evasion** | | [unicode], [url-confusion] |
| T7004.001 | Overlong UTF-8 Encoding | Non-shortest-form encoding | [unicode] §1-1 |
| T7004.002 | Unicode Normalization Bypass (NFKC/NFC) | Compatibility decomposition bypass | [unicode] §2-1 |
| T7004.003 | Double/Triple URL Encoding | Multi-pass decode differential | [url-confusion] §8-2 |
| T7004.004 | Charset Mismatch Exploitation | UTF-7, Latin-1 vs UTF-8 | [unicode] §1-3 |
| T7004.005 | Best-Fit/WorstFit Character Substitution | Charset conversion injection | [unicode] §5 |
| **T7005** | **SQL Injection Filter Evasion** | | [sql-injection] |
| T7005.001 | Comment-Based Obfuscation | `/*!50000SELECT*/` inline comment | [sql-injection] §2-3 |
| T7005.002 | Whitespace Substitution | Tab, newline, `%a0` for space | [sql-injection] §2-2 |
| T7005.003 | Case & Keyword Mutation | `SeLeCt`, `SELECT%00` | [sql-injection] §2-4 |
| T7005.004 | Wire Protocol Smuggling | Direct binary protocol injection | [sql-injection] §8-1 |
| **T7006** | **Deserialization Filter Bypass** | | [deserialization] |
| T7006.001 | JEP 290 Blocklist Incompleteness | New gadgets not on blocklist | [deserialization] §7-1 |
| T7006.002 | Scanner Evasion (Callable Substitution) | `pip.main()` instead of `os.system` | [deserialization] §7-2 |
| T7006.003 | Base64/Compression Wrapping | Multi-layer encoding obfuscation | [deserialization] §6-1 |
| T7006.004 | Broken File Bypass (nullifAI) | Payload executes before parse error | [deserialization] §7-2 |
| **T7007** | **File Upload Validation Bypass** | | [file-upload] |
| T7007.001 | Extension Blocklist Evasion | `.phtml`, case variation, trailing chars | [file-upload] §1-1 |
| T7007.002 | Magic Byte Prepending | GIF89a/PNG header before payload | [file-upload] §3-1 |
| T7007.003 | Content Transformation Survival | Payload in EXIF/ICC survives resize | [file-upload] §3-3 |
| T7007.004 | `filename*=UTF-8''` Encoding Bypass | RFC 6266 WAF evasion | [file-upload] §4-3 |
| **T7008** | **Path Confusion for ACL Bypass** | | [reverse-proxy-misrouting] |
| T7008.001 | Semicolon Path Parameter (Tomcat `..;/`) | Java servlet path stripping | [reverse-proxy-misrouting] §1-2 |
| T7008.002 | Double Decode Path Traversal | `%252e%252e` proxy/backend differential | [reverse-proxy-misrouting] §4-1 |
| T7008.003 | Encoded Slash Handling Differential | `%2f` vs `/` interpretation | [reverse-proxy-misrouting] §4-2 |
| **T7009** | **SAML Signature Bypass** | | [saml] |
| T7009.001 | Signature Wrapping (XSW) | Signed element relocation | [saml] §1-1 |
| T7009.002 | Certificate Validation Failure | Untrusted cert accepted | [saml] §5-2 |
| **T7010** | **Invisible Character Injection** | | [unicode] |
| T7010.001 | Zero-Width Character Injection | ZWSP, ZWJ, ZWNJ in identifiers | [unicode] §4-1 |
| T7010.002 | Unicode Tag Character Injection | U+E0001-U+E007F invisible payload | [unicode] §4-2 |
| **T7011** | **ZIP Security Bypass** | | [zip] |
| T7011.001 | Mark-of-the-Web (MotW) Bypass | ADS stripping, nested archive | [zip] §5-1 |
| T7011.002 | Central Directory Manipulation | Header/directory inconsistency | [zip] §3-1 |
| T7011.003 | ZIP Polyglot (EXE+ZIP, PDF+ZIP) | Dual-format bypass | [zip] §6 |
| **T7012** | **Header Smuggling Through Proxy** | | [reverse-proxy-misrouting] |
| T7012.001 | Underscore/Hyphen Header Confusion | PHP `$_SERVER` normalization | [reverse-proxy-misrouting] §5-3 |
| T7012.002 | Hop-by-Hop Header Stripping Abuse | `Connection:` removes security headers | [reverse-proxy-misrouting] §5-3 |
| T7012.003 | X-Original-URL / X-Rewrite-URL Override | IIS routing bypass | [reverse-proxy-misrouting] §5-2 |
| **T7013** | **Rate Limit / Throttle Bypass** | | [business-logic-vuln] |
| T7013.001 | Distributed Source Rotation | IP/key/agent rotation | [business-logic-vuln] §5-1 |
| T7013.002 | Endpoint Variant Bypass | Same function, different URL path | [business-logic-vuln] §5-1 |
| T7013.003 | Session Reset Bypass | New session resets rate counter | [business-logic-vuln] §5-1 |
| **T7014** | **CSP / Iframe Security Bypass** | | [ui-redressing] |
| T7014.001 | Frame-Buster Bypass via Sandbox | `sandbox` attribute without `allow-top-navigation` | [ui-redressing] §1-4 |
| T7014.002 | DoubleClickjacking (Window Swap) | Cross-window timing exploit | [ui-redressing] §2-1 |

---

## TA0008 — Credential Access

*Stealing or forging authentication credentials, tokens, and secrets.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T8001** | **Password Reset Token Exploitation** | | [ato] |
| T8001.001 | Predictable Token (Timestamp/Sequential) | Weak PRNG, MD5(timestamp) | [ato] §2-1 |
| T8001.002 | Host Header Poisoning for Token Theft | Reset link redirected to attacker | [ato] §2-2 |
| T8001.003 | Token-User Decoupling Bypass | Own token + victim's user ID | [ato] §2-3 |
| T8001.004 | Token Brute-Force (Short OTP) | 4-6 digit code exhaustion | [ato] §2-3 |
| **T8002** | **Session Token Theft** | | [cookie], [ato] |
| T8002.001 | XSS-Based Cookie Exfiltration | `document.cookie` theft | [ato] §7-1 |
| T8002.002 | Cookie Jar Overflow → HttpOnly Deletion | Force eviction + replacement | [cookie] §5-1 |
| T8002.003 | Browser Cookie Database Extraction | SQLite/DPAPI/Keychain extraction | [cookie] §7-1 |
| T8002.004 | Chrome AppBound Encryption Bypass (C4) | CBC padding oracle on elevation service | [cookie] §7-1 |
| T8002.005 | Network-Level Cookie Interception | HTTP sniffing, SSL stripping | [cookie] §6-1 |
| **T8003** | **OAuth/OIDC Token Theft** | | [oauth] |
| T8003.001 | Authorization Code Interception | Redirect URI leak | [oauth] §2-1 |
| T8003.002 | Implicit Flow Token Interception | Fragment leak via open redirect | [oauth] §2-2 |
| T8003.003 | Refresh Token Theft | Long-lived token compromise | [oauth] §7-1 |
| **T8004** | **JWT Key Material Exposure** | | [jwt] |
| T8004.001 | JWKS Endpoint Key Confusion | Malicious JWK in `jku`/`jwk` header | [jwt] §5-1 |
| T8004.002 | Weak HMAC Secret Cracking | Offline brute-force of JWT secret | [jwt] §3-1 |
| **T8005** | **MFA Bypass** | | [ato] |
| T8005.001 | MFA Prompt Bombing / Fatigue | Push notification exhaustion | [ato] §4-3 |
| T8005.002 | SIM Swap | Carrier social engineering | [ato] §4-3 |
| T8005.003 | AiTM Phishing (Real-Time Proxy) | Evilginx/Modlishka session capture | [ato] §4-3 |
| T8005.004 | MFA Flow Logic Bypass | Parameter manipulation, step skip | [ato] §4-2 |
| **T8006** | **Session Fixation** | | [cookie], [ato] |
| T8006.001 | URL-Based Session Fixation | Known session ID in URL | [ato] §3-1 |
| T8006.002 | Cross-Subdomain Cookie Fixation | Parent domain cookie injection | [cookie] §8-1 |
| **T8007** | **Cryptographic Key Theft** | | [saml], [jwt] |
| T8007.001 | SAML Signing Key Compromise | AD FS key extraction for Golden SAML | [saml] §5-1 |
| T8007.002 | XXE → Key Leak → JWT Forgery | Nested deserialization key extraction | [deserialization] §5-2 |
| **T8008** | **CSRF-Based Credential Change** | | [ato] |
| T8008.001 | CSRF Email Change → Account Takeover | Cross-site email change request | [ato] §7-2 |
| T8008.002 | CSRF Password Change | No current password required | [ato] §7-2 |
| **T8009** | **Cookie Parsing Exploitation** | | [cookie] |
| T8009.001 | Legacy RFC 2109 Parsing ($Version) | Phantom cookie WAF bypass | [cookie] §2-1 |
| T8009.002 | Quoted-Value Parsing Differential | Quote-absorbing semicolon leak | [cookie] §2-2 |
| T8009.003 | Out-of-Bounds Character Injection | Control chars in cookie name/value | [cookie] §2-3 |
| **T8010** | **Magic Link / Passwordless Token Theft** | | [ato] |
| T8010.001 | Magic Link Token Interception | Email/Referer/redirect leak | [ato] §9 |
| T8010.002 | Deep Link Hijacking (Mobile) | Malicious app intercepts auth link | [ato] §9 |

---

## TA0009 — Lateral Movement

*Pivoting between services, tenants, or trust boundaries within an application ecosystem.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T9001** | **Microservice Trust Boundary Exploitation** | | [implicit-trust-boundary], [secondary-context-attack] |
| T9001.001 | Inter-Service Trust Assumption | Service B trusts Service A blindly | [implicit-trust-boundary] §9-1 |
| T9001.002 | Service Mesh Header Manipulation | `x-envoy-internal` spoofing | [reverse-proxy-misrouting] §5-1 |
| T9001.003 | API Gateway Bypass (Direct Backend Access) | Skip gateway auth via SSRF/network | [idor-bola] §8-1 |
| **T9002** | **Cross-Tenant Pivoting** | | [idor-bola], [implicit-trust-boundary] |
| T9002.001 | Tenant ID Manipulation | Switch `org_id`/`tenant_id` parameter | [idor-bola] §5-3 |
| T9002.002 | Cross-Tenant Role Assumption (Cloud) | Confused deputy in cloud delegation | [secondary-context-attack] §5-1 |
| **T9003** | **OAuth/SSO Account Linking Exploitation** | | [oauth], [ato] |
| T9003.001 | Email-Based Auto-Linking | IdP returns victim's email → merge | [ato] §5-2 |
| T9003.002 | Domain Ownership Change | Google OAuth domain takeover | [ato] §5-2 |
| **T9004** | **SSRF to Internal Service Pivoting** | | [ssrf], [rmi] |
| T9004.001 | SSRF-to-RMI Pivoting | HTTP SSRF to internal RMI endpoint | [rmi] §7-1 |
| T9004.002 | Cloud Metadata → IAM Credential Theft | SSRF to 169.254.169.254 | [ssrf] §8 |
| **T9005** | **Cache Poisoning for Cross-User Impact** | | [cookie], [reverse-proxy-misrouting] |
| T9005.001 | Web Cache Poisoning via Unkeyed Input | Cookie/header-varied response cached | [cookie] §6-3 |
| T9005.002 | Cache Deception (Store Authenticated Page) | Victim's data cached for attacker | [reverse-proxy-misrouting] §7-3 |
| **T9006** | **Response Queue Poisoning** | | [http-request-smuggling] |
| T9006.001 | Smuggled Request → Steal Other User's Response | Response queue desync | [http-request-smuggling] |
| T9006.002 | HEAD Request Cache Poisoning | CL in HEAD response desync | [http-request-smuggling] |

---

## TA0010 — Collection

*Extracting sensitive data from the application.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T10001** | **Blind SQL Injection Data Extraction** | | [sql-injection] |
| T10001.001 | Boolean-Based Inference | True/false response differential | [sql-injection] §5-1 |
| T10001.002 | Time-Based Inference | `SLEEP()`/`BENCHMARK()` delay | [sql-injection] §5-2 |
| T10001.003 | Error-Based Extraction | Data in error messages | [sql-injection] §5-3 |
| T10001.004 | Out-of-Band Channel (DNS/HTTP) | `LOAD_FILE`, `UTL_HTTP`, DNS exfil | [sql-injection] §5-4 |
| **T10002** | **IDOR Mass Data Exfiltration** | | [idor-bola] |
| T10002.001 | Range Enumeration | Iterate sequential IDs | [idor-bola] §1-1 |
| T10002.002 | Collection Endpoint Data Leak | Unfiltered listing endpoint | [idor-bola] §4-1 |
| T10002.003 | Aggregation Endpoint Leak | Stats/reports across users | [idor-bola] §5-4 |
| **T10003** | **XXE File Exfiltration** | | [saml], [file-upload] |
| T10003.001 | SVG/XLSX/DOCX → XXE → File Read | XML entity expansion in uploads | [file-upload] §7-2 |
| T10003.002 | SAML XXE → Server File Access | External entity in SAML assertion | [saml] §6-1 |
| **T10004** | **Timing-Based Data Extraction** | | [web-timing-attack] |
| T10004.001 | XS-Search (Cross-Site Search) | Timing-based content inference | [web-timing-attack] §3-5 |
| T10004.002 | Cryptographic Timing Oracle | Key/token byte-by-byte extraction | [web-timing-attack] §4 |
| **T10005** | **Information Disclosure via Business Logic** | | [business-logic-vuln] |
| T10005.001 | Verbose API Response Over-Exposure | Full object with internal fields | [business-logic-vuln] §7-2 |
| T10005.002 | Error-Triggered Data Disclosure | Stack traces, debug output | [business-logic-vuln] §7-2 |
| T10005.003 | Metadata Leakage | EXIF, HTTP headers, API schemas | [business-logic-vuln] §7-2 |
| **T10006** | **Pixel-Level Data Extraction** | | [web-fingerprinting], [ui-redressing] |
| T10006.001 | SVG Filter Cross-Origin Pixel Access | Timing/rendering pixel steal | [ui-redressing] §6-1 |
| T10006.002 | CSS Timing Side-Channel | Pixel color inference via CSS | [ui-redressing] §6-2 |
| **T10007** | **Drag-and-Drop Data Extraction** | | [ui-redressing] |
| T10007.001 | Content Exfiltration via Drag | Invisible drag target to attacker page | [ui-redressing] §4-2 |
| **T10008** | **JWT Token Data Leakage** | | [jwt] |
| T10008.001 | Token Leakage via Referer/URL/Logs | JWT in URL parameters exposed | [jwt] §6-1 |

---

## TA0011 — Exfiltration

*Moving collected data out of the target environment.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T11001** | **Out-of-Band SQL Exfiltration** | | [sql-injection] |
| T11001.001 | DNS-Based Exfiltration | Data in DNS query subdomains | [sql-injection] §5-4 |
| T11001.002 | HTTP-Based OOB Exfiltration | `UTL_HTTP`, `xp_cmdshell curl` | [sql-injection] §5-4 |
| **T11002** | **SSRF-Based Data Exfiltration** | | [ssrf] |
| T11002.001 | Blind SSRF OOB Callback | Data in outbound request URL/body | [ssrf] §7-3 |
| T11002.002 | Cloud Metadata Credential Exfiltration | IAM tokens via metadata service | [ssrf] §8 |
| **T11003** | **Cache-Based Data Exposure** | | [reverse-proxy-misrouting] |
| T11003.001 | Web Cache Deception | Trick cache into storing auth response | [reverse-proxy-misrouting] §7-3 |
| T11003.002 | CDN Cache Poisoning → C2 Channel | Location header as covert channel | [http-request-smuggling] |
| **T11004** | **Token/Credential Relay** | | [ato], [cookie] |
| T11004.001 | Host Header Poisoning → Reset Token Relay | Token sent to attacker domain | [ato] §2-2 |
| T11004.002 | OAuth Redirect → Token Relay | Auth code/token sent to attacker | [oauth] §1-1 |
| **T11005** | **Notification Channel Hijack** | | [idor-bola] |
| T11005.001 | Webhook URL Manipulation | Redirect notifications to attacker | [idor-bola] §4-4 |
| T11005.002 | Second-Order Notification Exfiltration | Data exfiltrated via future notifications | [idor-bola] §6-3 |

---

## TA0012 — Impact

*Causing denial of service, data manipulation, financial fraud, or user deception.*

| ID | Technique | Sub-Techniques | Source |
|---|---|---|---|
| **T12001** | **Denial of Service (Application Logic)** | | [business-logic-vuln], [zip] |
| T12001.001 | Zip Bomb / Decompression Bomb | Small archive → petabytes decompressed | [zip] §4, [file-upload] §7-3 |
| T12001.002 | Cart/Reservation Bombing | Reserve all inventory without buying | [business-logic-vuln] §5-3 |
| T12001.003 | Cookie Bomb | Oversized cookies → 413 lockout | [cookie] §5-1 |
| T12001.004 | Expensive Query Abuse | Trigger computationally heavy operations | [business-logic-vuln] §5-3 |
| T12001.005 | ReDoS / Regex Bomb | Catastrophic backtracking in regex | [waf-bypass] §7-1 |
| **T12002** | **Financial Fraud** | | [business-logic-vuln] |
| T12002.001 | Price/Amount Manipulation | Client-supplied price override | [business-logic-vuln] §1-1 |
| T12002.002 | Negative Quantity Injection | Qty=-5 creates credit | [business-logic-vuln] §1-2 |
| T12002.003 | Integer Overflow in Cart Total | Signed wraparound to negative | [business-logic-vuln] §1-2 |
| T12002.004 | Coupon/Promo Stacking and Replay | Unlimited discount application | [business-logic-vuln] §2-3 |
| T12002.005 | Infinite Money Loop (Gift Card Cycle) | Promo → gift card → promo loop | [business-logic-vuln] §2-3 |
| T12002.006 | Double-Spend via Race Condition | Parallel requests bypass balance check | [web-race-condition] §1-1 |
| T12002.007 | Payment Callback Manipulation | Forge payment gateway webhook | [business-logic-vuln] §10-1 |
| **T12003** | **UI Redressing / Clickjacking** | | [ui-redressing] |
| T12003.001 | Transparent Iframe Overlay | Classic clickjacking | [ui-redressing] §1-1 |
| T12003.002 | DoubleClickjacking | Window swap on double-click | [ui-redressing] §2-1 |
| T12003.003 | Keystroke/Gesture Hijacking | Focus stealing key capture | [ui-redressing] §3 |
| T12003.004 | Mobile Tapjacking (TapTrap) | Animation-driven overlay | [ui-redressing] §7-2 |
| T12003.005 | Cursor Deception | Custom cursor displacement | [ui-redressing] §5 |
| **T12004** | **State Machine Manipulation** | | [state-machine-violation] |
| T12004.001 | Step Skipping (Direct-to-Final) | Bypass payment/verification step | [state-machine-violation] §1-1 |
| T12004.002 | Backward State Transition | "Shipped" → "Pending" rollback | [state-machine-violation] §1-3 |
| T12004.003 | Terminal State Re-Entry | Reopen closed claim/subscription | [business-logic-vuln] §2-2 |
| **T12005** | **Race Condition Exploitation** | | [web-race-condition] |
| T12005.001 | Resource Limit Overrun (TOCTOU) | Parallel requests bypass balance/stock | [web-race-condition] §1 |
| T12005.002 | Authentication Race Bypass | Concurrent login credential bypass | [web-race-condition] §2 |
| T12005.003 | Object Partial Construction Race | Access uninitialized fields | [web-race-condition] §3 |
| T12005.004 | Token-Identity Binding Race | Misroute token to wrong user | [web-race-condition] §4 |
| **T12006** | **Visual/Social Deception** | | [unicode], [ui-redressing] |
| T12006.001 | Homoglyph Domain Spoofing | Confusable character phishing | [unicode] §6-1 |
| T12006.002 | BiDi Text Filename Deception | RTLO makes .exe appear as .txt | [unicode] §3-2 |
| T12006.003 | Invisible Prompt Injection (LLM) | Zero-width chars in AI prompts | [unicode] §7-1 |
| **T12007** | **Data Integrity Manipulation** | | [business-logic-vuln] |
| T12007.001 | Refund/Return Abuse | Refund without return | [business-logic-vuln] §10-1 |
| T12007.002 | Vote/Rating Manipulation | Multi-account ballot stuffing | [business-logic-vuln] §10-5 |
| T12007.003 | Leaderboard/Score Manipulation | Client-side score falsification | [business-logic-vuln] §10-5 |
| **T12008** | **URL Confusion Exploitation** | | [url-confusion] |
| T12008.001 | Scheme Substitution (javascript:, data:) | Protocol handler abuse | [url-confusion] §1-2 |
| T12008.002 | Authority Component Confusion (@ notation) | Userinfo redirect deception | [url-confusion] §2-1 |
| T12008.003 | Path Delimiter Confusion | Cache key vs origin path mismatch | [url-confusion] §5-5 |

---

## Cross-Reference: Source Document → Techniques

| Source Document | Primary Tactics | Key Techniques |
|---|---|---|
| [account-takeover](account-takeover/ato.md) | TA0003, TA0005, TA0008 | T3009, T3010, T5001, T8001, T8005 |
| [business-logic-vuln](business-logic-vuln/business-logic-vuln.md) | TA0006, TA0007, TA0010, TA0012 | T6002, T7013, T10005, T12002, T12004 |
| [cookie](cookie/cookie.md) | TA0005, TA0007, TA0008 | T5001, T7002, T8002, T8009 |
| [deserialization](deserialization/deserialization.md) | TA0002, TA0003, TA0004 | T2001, T3005, T4001, T4006 |
| [file-upload](file-upload/file-upload.md) | TA0003, TA0004, TA0007 | T3004, T4002, T7007 |
| [http-parameter-pollution](http-parameter-pollution/hpp.md) | TA0003, TA0007 | T3013, T7001 |
| [http-request-smuggling](http-parsing-discrepancy/http-request-smuggling.md) | TA0003, TA0007, TA0009 | T3003, T7003, T9006 |
| [reverse-proxy-misrouting](http-parsing-discrepancy/reverse-proxy-misrouting.md) | TA0003, TA0007, TA0009 | T3012, T7008, T7012 |
| [idor-bola](idor-bola/idor-bola.md) | TA0006, TA0010 | T6003, T6008, T10002 |
| [implicit-trust-boundary](implicit-trust-boundary/implicit-trust-boundary.md) | TA0007, TA0009 | T9001, T9002 |
| [jwt](jwt/jwt.md) | TA0003, TA0006, TA0008 | T3008, T6004, T8004 |
| [logic-bug](logic-bug/logic-bug.md) | TA0006, TA0007, TA0012 | T6002, T6005, T12004 |
| [mass-assignment](mass-assignment/mass-assignment.md) | TA0006 | T6001 |
| [oauth](oauth/oauth.md) | TA0003, TA0006, TA0008 | T3006, T6006, T8003 |
| [rmi](rmi/rmi.md) | TA0001, TA0003 | T1007, T3014 |
| [saml](saml/saml.md) | TA0003, TA0007, TA0008 | T3007, T7009, T8007 |
| [secondary-context-attack](secondary-context-attack/secondary-context-attack.md) | TA0003, TA0009 | T3011, T9001 |
| [sql-injection](sql-injection/sql-injection.md) | TA0003, TA0004, TA0010, TA0011 | T3001, T4004, T10001, T11001 |
| [sso](sso/sso.md) | TA0003, TA0006 | T3006, T3007, T3008 |
| [ssrf](ssrf/ssrf.md) | TA0003, TA0009, TA0011 | T3002, T9004, T11002 |
| [state-machine-violation](state-machine-violation/state-machine-violation.md) | TA0006, TA0012 | T6005, T12004 |
| [ui-redressing](ui-redressing/ui-redressing.md) | TA0010, TA0012 | T10006, T12003 |
| [unicode](unicode/unicode.md) | TA0007, TA0012 | T7004, T7010, T12006 |
| [url-confusion](url-confusion/url-confusion.md) | TA0007, TA0012 | T7004, T12008 |
| [waf-bypass](waf-bypass/waf-bypass.md) | TA0007 | T7001 |
| [web-fingerprinting](web-fingerprinting/web-fingerprinting.md) | TA0001 | T1001, T1002, T1003 |
| [web-race-condition](web-race-condition/web-race-condition.md) | TA0012 | T12005 |
| [web-timing-attack](web-timing-attack/web-timing-attack.md) | TA0001, TA0010 | T1009, T10004 |
| [zip-archive](zip-archive/zip.md) | TA0004, TA0007, TA0012 | T4007, T7011, T12001 |

---

## Statistics

| Metric | Count |
|---|---|
| **Tactics** | 12 |
| **Techniques** | 104 |
| **Sub-Techniques** | 318 |
| **Source Documents** | 28 |

---

*This taxonomy was synthesized from the [the-map](README.md) vulnerability research collection. Built for defensive security research, AI agent consumption, and systematic penetration testing workflows.*
