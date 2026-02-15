# Sam Curry Bug Bounty Research Techniques & Methodologies Taxonomy

---

## Classification Structure

This taxonomy organizes Sam Curry's documented vulnerability discovery techniques across three analytical dimensions:

**Axis 1: Attack Surface Component** — The structural target of reconnaissance or exploitation. This primary axis divides techniques by what system component is being analyzed or manipulated (infrastructure, authentication, APIs, caching layers, etc.).

**Axis 2: Exploitation Mechanism** — The type of discrepancy or bypass created. These cross-cutting patterns explain *why* each technique succeeds:

| Mechanism Type | Definition | Common Indicators |
|----------------|------------|-------------------|
| **Validation Bypass** | Input or authentication checks circumvented through encoding, path manipulation, or parser confusion | Regex failures, client-side checks, weak allowlists |
| **Authorization Mismatch** | Privilege checks fail to restrict access to resources or functions | IDOR, missing access controls, sequential IDs |
| **Path/Routing Confusion** | Frontend and backend interpret request routing differently | Proxy traversal, normalization issues, URL parsing gaps |
| **Parser Differential** | Multiple parsers disagree on input interpretation | Header handling, encoding, protocol edge cases |
| **State Inconsistency** | Temporal gaps between validation and consumption | Race conditions, TOCTOU, async operations |
| **Trust Boundary Violation** | External input treated as trusted or improperly isolated | SSRF, injection, prototype pollution |

**Axis 3: Attack Scenario** — The deployment context and ultimate impact (covered in §9).

### Core Research Philosophy

Curry's methodology emphasizes:
1. **Realistic mindset over automation** — Custom implementations and edge cases missed by scanners
2. **Architectural understanding** — Identifying trust boundaries and privilege differentials (e.g., customer vs. employee portals)
3. **Systematic enumeration** — Testing character sets, path variations, parameter arrays methodically
4. **Chain construction** — Combining low-severity findings into critical impact sequences

---

## §1. Infrastructure Reconnaissance & Discovery

Infrastructure mapping establishes the attack surface before targeted exploitation. These techniques identify exposed services, misconfigurations, and forgotten endpoints.

### §1-1. IP Range & Subdomain Enumeration

Comprehensive asset discovery through systematic scanning and DNS resolution.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **CIDR Block Scanning** | Enumerate entire IP ranges owned by target organization | 17.0.0.0/8 scan revealed 25,000 Apple web servers across apple.com, icloud.com |
| **CNAME Following** | Resolve CNAMEs to discover production infrastructure patterns | `my.subaru.com` → `mys.prod.subarucs.com` led to `portal.prod.subarucs.com` admin panel |
| **HTTP Header Fingerprinting** | Catalog server technologies and framework versions via response headers | Index servers by status codes, frameworks, error signatures |
| **Screenshot Automation** | Visual cataloging of accessible interfaces for manual review | Dashboard of 10,000+ endpoints with thumbnails for pattern recognition |

**Key Insight**: Employee-facing infrastructure (portals, admin panels) typically has broader permissions than customer applications, making subdomain enumeration critical for privilege escalation pathways.

### §1-2. Directory & Endpoint Discovery

Brute-forcing hidden paths and analyzing client-side code to map backend structure.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Directory Brute-Forcing** | Tools like FFuF, dirsearch enumerate common paths | `/assets/_js/` directory exposed `login.js` containing password reset endpoint |
| **JavaScript Source Analysis** | Extract API routes, credentials, configuration from client bundles | Airline APIs found in archived `console.points.com` JavaScript after public removal |
| **Archive.org Reconnaissance** | Retrieve deleted documentation and historical configurations | Points.com API documentation recovered from Wayback Machine snapshots |
| **Actuator/Debug Endpoint Scanning** | Probe for Spring Boot Actuator, debug panels, health checks | `/viewer/actuator/heapdump` exposed valid authentication cookies |

### §1-3. Automated Vulnerability Scanning

Identifying known CVEs and misconfigurations as entry points.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **CVE Scanning** | Check for public exploits in discovered services | 22 Apple VPN servers vulnerable to Cisco CVE-2020-3452 (local file read) |
| **Error Message Leakage** | Parse error responses for tokens, stack traces, internal paths | Spotify access tokens leaked in application error messages |
| **Default Credential Testing** | Attempt common passwords on discovered admin interfaces | ClubWPT admin console protected by "123456" password |

---

## §2. Authentication & Session Management

Authentication mechanisms determine initial access. These techniques bypass or subvert credential validation, multi-factor authentication, and session handling.

### §2-1. Unauthenticated Access

Gaining entry without valid credentials through design flaws or missing checks.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Unauthenticated Password Reset** | Reset endpoints lack email ownership verification or token validation | `POST /forgotPassword/resetPassword.json` accepted arbitrary email + new password (Subaru) |
| **Hidden Password Fields** | Default credentials embedded in HTML source or configuration | `value="###INvALID#%!3"` in registration form enabled manual `cs_login` authentication |
| **Hardcoded Credentials** | Usernames/passwords in environment variables, source code, or configuration files | Usernames hardcoded in ClubWPT env vars; Flask app using literal string "secret" as session key |
| **Email Enumeration** | Differential responses reveal account existence for credential stuffing | `/adminProfile/getSecurityQuestion.json` returned valid security questions vs. "Invalid email" |

### §2-2. Multi-Factor Authentication Bypass

Circumventing 2FA through client-side manipulation or improper enforcement.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Client-Side 2FA Removal** | JavaScript modal enforcement without server-side validation | Commenting out `$('#securityQuestionModal').modal('show');` bypassed Subaru 2FA entirely |
| **2FA Implementation Flaw** | Race conditions, backup codes, or recovery flows without rate limits | ClubWPT 2FA bypass allowed full admin access to back office |

### §2-3. Session Token Exploitation

Stealing, forging, or escalating privileges through session manipulation.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Weak Session Secrets** | Predictable signing keys allow token forgery | `console.points.com` Flask cookie signed with "secret"; unsigned, modified to admin, re-signed |
| **Heap Dump Credential Harvesting** | Extract valid session tokens from memory dumps | Spring Boot `/actuator/heapdump` parsed with Eclipse Memory Analyzer for `acack` tokens |
| **Token Leakage in Responses** | Credentials exposed in API responses, headers, or error messages | Virgin Atlantic macID and macKey exposed in `/login1.php` HTTP response |
| **JWT Fragment Capture** | OAuth flows leak tokens in URL fragments via cache poisoning | Cache-poisoned redirect captured JWT from victim URL fragment (§7-2) |

### §2-4. Username & Account Discovery

Enumerating valid accounts for targeted attacks.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Differential Response Analysis** | Timing, error messages, or HTTP codes differ for valid vs. invalid accounts | Security question endpoint disclosed account existence (Subaru) |
| **Username Brute-Forcing** | Systematically test common patterns, especially for short lengths | 1-3 character admin usernames on Jive platform (`cs_login`) |
| **OSINT + Email Pattern Matching** | LinkedIn profiles + naming conventions generate candidate emails | `[first_initial][last]@subaru.com` pattern validated via security question endpoint |

---

## §3. Authorization & Access Control

Authorization flaws enable horizontal (accessing other users' data) and vertical (privilege escalation) attacks. These are among the most common and impactful vulnerabilities in modern applications.

### §3-1. Insecure Direct Object References (IDOR)

Manipulating object identifiers to access unauthorized resources.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Numeric ID Enumeration** | Sequential or predictable identifiers lack ownership validation | `itemId` parameter in App Store Connect allowed modifying any app's game center settings |
| **UUID/GUID Manipulation** | Even non-sequential IDs may be guessable or leaked elsewhere | Traversing `lpId` UUID parameters with `../../` bypassed restrictions |
| **Array Parameter Exploitation** | JSON arrays allow batch enumeration of many IDs in single request | `dsIds` array in Find My Friends enumerated Apple user IDs and retrieved associated emails |
| **VIN-Based Vehicle Access** | Vehicle Identification Numbers used as authorization token | VIN + dealer token enabled lock/unlock/start/stop/locate on 15M+ Kia vehicles |

**Cross-Reference**: IDOR often combines with §4-2 (directory traversal) and §3-2 (improper authorization) to escalate impact.

### §3-2. Improper Authorization Checks

Missing or flawed permission validation on sensitive operations.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Missing Function-Level Checks** | Administrative functions accessible to non-admin users | MFi Portal allowed retrieval of ~50,000 company applications via sequential IDs |
| **Path Traversal Authorization Bypass** | URL path manipulation circumvents IP or role restrictions | `GET /admin;/` bypassed IP allowlist on Jive admin console |
| **Dealer/Partner API Abuse** | Third-party access tokens grant excessive permissions | Registering as Kia dealer provided API access to bind any vehicle to attacker account |

### §3-3. Privilege Escalation

Elevating access from low-privilege to administrative roles.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Session Cookie Role Modification** | Weak signing allows tampering with privilege flags | Flask cookie unsigned, "isAdmin" set to true, re-signed with cracked secret |
| **Account Type Confusion** | Systems fail to distinguish employee vs. customer credentials | LDAP authentication issues allowed non-employees to access Mercedes internal networks |
| **Primary User Takeover** | Multi-user systems allow attacker to become primary owner | Kia API allowed setting victim as secondary user, attacker as primary owner |

---

## §4. API Architecture & Routing

Modern applications rely heavily on REST APIs and microservices. Exploiting routing logic, proxy architectures, and parameter handling reveals unintended functionality.

### §4-1. Backend-for-Frontend (BFF) Proxy Traversal

BFF patterns expose internal services via proxied paths. Directory traversal through these proxies reaches protected backends.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Path Traversal via Proxy** | User-controlled path segments traverse to internal endpoints | `/bff/proxy/stream/v1/me/../../../search/v1/Accounts` accessed Microsoft Graph (Starbucks) |
| **Backslash Encoding Bypass** | WAF/parser differences in handling `\` vs `/` in paths | `..\..\..` (unencoded backslashes) succeeded where `..%2f` failed |
| **WAF Evasion via Segment Insertion** | Valid path segments between traversal sequences bypass pattern matching | `web\..\.\..\ ` bypassed consecutive traversal detection |

The Starbucks case demonstrates fundamental BFF risk: a single input validation failure in the proxy layer exposes all backend services. The `/bff/proxy/` prefix indicated a Backend-for-Frontend architecture where client-side paths map to internal microservices. By embedding traversal sequences in user-controlled `:streamItemId` parameters, attackers navigated 6 directories deep to reach `/search/v1/Accounts`, yielding OData query access to 99 million customer records.

### §4-2. Parameter Manipulation & Injection

API parameters define request scope and routing. Manipulating these values accesses unintended data or endpoints.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **lpId (Loyalty Program ID) Traversal** | Parameter intended for scoping used for path construction | `"lpId":"../../v1/search/orders/?"` exposed 22.7M Points.com order records |
| **Batch Request Exploitation** | Array parameters allow mass data exfiltration in single call | `dsIds` JSON array enumerated hundreds of Apple user IDs per request |
| **X-Original-URL Header Injection** | Custom headers override request routing | `X-Original-URL: /admin` bypassed URL-based access controls (§7-2) |

### §4-3. API Authentication Weaknesses

OAuth, MAC, and custom authentication schemes often contain implementation flaws.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Token Generation with Minimal Data** | APIs issue auth tokens without verifying requester owns the account | United Airlines generated authorization token using only surname + rewards number |
| **Credential Exposure in Responses** | macID/macKey or similar secrets leaked in HTTP bodies/headers | Virgin Atlantic API response included macKeyIdentifier and macKey for OAuth MAC signing |
| **God Token Abuse** | High-privilege "internal" tokens used by frontend, reusable by attacker | Points.com frontend used elevated token with global permissions; discovered via network analysis |

---

## §5. Input Processing & Injection

Injection flaws occur when untrusted input is embedded in commands, queries, or markup without sanitization.

### §5-1. SQL Injection

SQL injection remains critical despite age due to custom implementations and obscure database engines.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Union-Based Injection (Vertica)** | Stack queries with `_/_/` closing comments; `/**/` between FROM clauses | Unauthenticated Vertica endpoints at `/gsf/` lacked automated tool support, required manual exploitation |
| **Authentication Bypass** | Inject payloads in login forms to bypass authentication logic | FlyCASS (TSA) SQL injection allowed logging in as airline administrator, adding fake employees to KCM/CASS |

The TSA FlyCASS case is particularly notable: SQL injection in a third-party airline management system allowed creating fictitious employees with Known Crewmember (KCM) and Cockpit Access Security System (CASS) privileges, effectively bypassing airport security and gaining cockpit access credentials. Disclosed April 2024, patched May 2024, but coordination broke down after DHS initially responded, then ceased communication.

### §5-2. Command Injection

Operating system command execution via unsanitized parameters.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Filename Argument Injection** | Parameters passed directly to CLI tools without escaping | ePublisher EPUB validation: `-itc_provider [INJECTABLE]` allowed `\|\|test123` for arbitrary execution |
| **Quote Character Testing** | Systematically test `;`, `\|`, `&&`, backticks, `$()` to identify escape points | Curry emphasizes "What characters will it allow?" rather than assuming standard patterns |

### §5-3. CRLF Injection

Injecting carriage return and line feed characters to manipulate protocols that rely on line-based parsing.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Email Header Injection** | `\r\n` in email input adds arbitrary headers (From, CC, BCC) | Exploited in mailing systems missed by automated scanners |
| **HTTP Response Splitting** | CRLF in response headers enables cache poisoning, XSS | Often combined with caching layers for persistent attacks |

---

## §6. Cross-Site Scripting (XSS)

XSS allows attackers to execute JavaScript in victim contexts, enabling account takeover, data theft, and worm propagation.

### §6-1. DOM-Based XSS

Client-side parsing creates vulnerability when dynamically manipulating page structure.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Style Tag Splitting** | Inject `</sty` in first tag, `le>` in second; DOM concatenation breaks sanitization | Parser concatenates split tags, bypassing filters that check complete tags |
| **Hyperlink Regex Bypass** | URL patterns confuse automatic hyperlinking and tag removal | `https://domain.com/#<script></script>https://domain.com/onmouseover=...` |

### §6-2. Stored XSS

Persisted payloads execute on every victim visit, enabling worm behavior.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Wormable XSS via Contact Propagation** | Payload sends itself to all victim contacts automatically | iCloud.com XSS in email functionality could self-replicate to every address in victim's contacts |
| **Headless Browser XSS** | Inject into server-side rendering engines (PhantomJS, Puppeteer) | iBooks banner generation via PhantomJS 2.1.1 enabled XSS → SSRF → AWS metadata (§6-3) |

### §6-3. XSS-to-SSRF Chains

XSS in server-side browsers becomes SSRF when rendering engine makes outbound requests.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Iframe-Based Metadata Retrieval** | Inject `<iframe src="http://169.254.169.254/...">` in server-rendered content | PhantomJS rendered malicious iframe, fetched AWS EC2 metadata, exposed security credentials |
| **Screenshot Function Exploitation** | Upload HTML/SVG with external resource references | Server-side screenshot tools fetch attacker-controlled URLs, enabling internal network scanning |

---

## §7. Cache & Proxy Layer Exploitation

Caching proxies (Varnish, CDNs) and reverse proxies create opportunities when frontend and backend disagree on request interpretation.

### §7-1. Cache Poisoning Detection

Identifying cacheable responses is the prerequisite for poisoning attacks.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Cache Header Analysis** | `Age:` indicates cache duration; `X-Cache: HIT` confirms CDN serving; `Via: 1.1 varnish` reveals proxy | These headers identify cacheable endpoints for subsequent poisoning |
| **Unique Parameter Testing** | Add `?uniqueParam=random` to prevent cache hits during testing | Ensures responses reflect current backend state, not cached artifacts |

### §7-2. HTTP Path Normalization Abuse

Proxies and backends normalize paths differently, enabling routing confusion.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **X-Original-URL Header Injection** | Override actual request path with arbitrary value | `GET /?unique=1` + `X-Original-URL: /admin` cached as homepage but executed `/admin` logic |
| **Backslash vs. Forward Slash Normalization** | IIS accepts `https:\\` as valid scheme in Location headers | Combined with `//` to single `/` normalization: `https:\\attacker.com/path//work` bypassed same-site checks |
| **Double Slash Collapsing** | Proxies reduce `//` to `/`, backends may not | Control character injection creates parser differentials |

**Rocket League Case Study**: The OAuth redirect flow was vulnerable to cache poisoning via `X-Original-URL` header. By crafting a unique URL (`?param=unique`) with `X-Original-URL: https:\\attacker.com/path//work`, the attacker poisoned the cache so legitimate victims visiting the OAuth endpoint received a redirect to the attacker's domain. Since OAuth tokens appeared in URL fragments, the attacker JavaScript captured JWTs for account takeover without user interaction.

### §7-3. Secondary Context Bugs

Architectural patterns where frontend applications proxy requests to backend APIs create "secondary contexts" with distinct trust boundaries.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Swagger/OpenAPI Leakage via Traversal** | Traverse to `/api-docs`, `/swagger.json` to map internal endpoints | Once internal API structure known, find unauthenticated endpoints |
| **Blind Secondary Context Exploitation** | Full HTTP response not visible; use timing, error codes to infer success | Test control characters (`?`, `#`, `&`) to understand request chaining behavior |
| **Router Secret Extraction** | Exposed endpoints leak encryption keys for other parameters | Router serial numbers encrypted with leaked secret, enabling parameter forgery |

---

## §8. Server-Side Request Forgery (SSRF)

SSRF occurs when attackers induce server-side applications to make requests to unintended locations, typically internal networks or cloud metadata services.

### §8-1. URL Validation Bypass

Circumventing allowlists, blocklists, or parser-based checks.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **URL Username Injection** | Append `@attacker.com` to trusted domain | `https://p37-mailws.icloud.com@attacker.com` bypassed domain suffix validation |
| **DNS Rebinding** | Domain initially resolves to safe IP, later to internal IP | Requires control over DNS server; exploits TOCTOU between validation and usage |
| **Protocol Confusion** | Use `file://`, `gopher://`, `dict://` where `http://` expected | Bypass schemes that only validate HTTP/HTTPS |

### §8-2. Screenshot & Rendering-Based SSRF

Server-side rendering engines fetch external resources, enabling network probing.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Headless Browser Image Loading** | Inject `<img src="http://internal-host/">` in server-rendered HTML/PDF | PhantomJS XSS payloads loaded internal resources during book banner generation (§6-3) |
| **SVG External Entity** | SVG files reference external resources via `<image href="">` | Similar to XXE but through graphics rendering |

### §8-3. Cloud Metadata Exploitation

Cloud platforms expose instance metadata at link-local addresses (169.254.169.254).

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **AWS EC2 Metadata Retrieval** | Access `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | Returns temporary AWS credentials with instance IAM role permissions |
| **Internal Maven Repository Access** | SSRF to internal artifact servers retrieves source code, binaries | iCloud Pages SSRF bypassed URL validation, accessed internal Maven repos |

**Note**: Full response SSRF (where attacker sees complete HTTP response) is significantly more valuable than blind or semi-blind SSRF. Curry noted this as "the most elusive bug" during Apple research, with many blind SSRFs found but fewer full-response instances.

---

## §9. Attack Scenario Mapping

This section maps the techniques (§1–§8) to real-world attack scenarios based on deployment architecture and impact.

### Vehicle & IoT Remote Control

**Architecture**: Telematics systems with mobile apps, dealer portals, admin panels
**Primary Techniques**: §3-1 (VIN-based IDOR), §2-1 (unauthenticated password reset), §3-2 (dealer API abuse), §4-3 (weak token generation)
**Cases**: Subaru STARLINK, Kia (license plate attack), 16-20 auto manufacturers

**Attack Flow**:
1. Enumerate dealer API endpoints via subdomain scanning (§1-1)
2. Register as dealer or compromise dealer credentials (§2-1, §3-2)
3. Resolve license plate to VIN via third-party services
4. Use VIN + dealer token to bind victim vehicle (§3-1)
5. Execute lock/unlock/start/locate commands

**Impact**: Complete remote vehicle control, GPS tracking, physical safety risk

---

### Mass Data Exfiltration

**Architecture**: Customer databases behind API gateways, BFF proxies, or search endpoints
**Primary Techniques**: §4-1 (BFF proxy traversal), §4-2 (parameter manipulation), §3-1 (IDOR batch enumeration), §5-1 (SQL injection)
**Cases**: Starbucks (99M records), Points.com (22.7M orders), Apple (Find My Friends enumeration), Chess.com (50M records)

**Attack Flow**:
1. Identify BFF proxy or search API endpoints (§1-2)
2. Test directory traversal payloads with backslash encoding (§4-1)
3. Discover internal OData/GraphQL/search APIs
4. Use pagination, array parameters, or SQL injection for bulk extraction (§4-2, §5-1)

**Impact**: PII leakage (emails, phones, addresses, partial credit cards, passwords), GDPR/regulatory violations

---

### Account Takeover (ATO)

**Architecture**: Authentication systems with flaws in validation, session management, or OAuth flows
**Primary Techniques**: §2-1 (unauthenticated password reset), §2-3 (session token exploitation), §6-2 (wormable XSS), §7-2 (cache poisoning for token theft)
**Cases**: Rocket League (cache-poisoned OAuth), iCloud (wormable XSS), Subaru (unauthenticated password reset)

**Attack Flow (OAuth Cache Poisoning)**:
1. Identify cacheable OAuth redirect endpoint (§7-1)
2. Poison cache with `X-Original-URL` pointing to attacker domain (§7-2)
3. Victim visits legitimate OAuth flow, receives poisoned redirect
4. JWT fragment captured by attacker JavaScript
5. Reuse JWT to authenticate as victim

**Impact**: Full account compromise, financial fraud, identity theft

---

### Administrative Access Escalation

**Architecture**: Employee portals, admin panels, back-office systems with weak authentication or exposed endpoints
**Primary Techniques**: §1-1 (subdomain enumeration for admin panels), §2-1 (hardcoded credentials), §2-2 (2FA bypass), §3-3 (privilege escalation), §2-3 (weak session secrets)
**Cases**: ClubWPT (source code exposure + 2FA bypass), Points.com (Flask session forgery), Apple (Jive admin console path traversal)

**Attack Flow (Session Cookie Privilege Escalation)**:
1. Discover admin portal via CNAME following or directory brute-forcing (§1-1, §1-2)
2. Obtain low-privilege session cookie
3. Crack Flask/JWT signing secret or identify hardcoded secret (§2-3)
4. Unsign cookie, modify role/privilege flags, re-sign
5. Access administrative functions

**Impact**: Backend database access, customer PII, ability to modify system configurations, financial fraud

---

### Infrastructure & Supply Chain Compromise

**Architecture**: Internal services, CI/CD pipelines, cloud infrastructure exposed via SSRF, leaked credentials, or misconfigurations
**Primary Techniques**: §8-3 (cloud metadata), §1-3 (actuator/heap dumps), §2-3 (credential harvesting), §4-3 (god token abuse)
**Cases**: Apple (AWS metadata via PhantomJS SSRF, heap dump session tokens, internal Maven repos), auto manufacturers (GitHub/Slack SSO access)

**Attack Flow (Heap Dump Credential Harvesting)**:
1. Discover Spring Boot Actuator endpoints via directory brute-forcing (§1-2)
2. Download heap dump from `/actuator/heapdump`
3. Parse with Eclipse Memory Analyzer to extract session tokens, API keys
4. Reuse tokens to access internal applications (§2-3)
5. Pivot to GitHub, Slack, internal networks

**Impact**: Source code theft, supply chain poisoning, lateral movement to internal networks

---

### Physical Security Bypass

**Architecture**: Third-party systems managing access control or security screening
**Primary Techniques**: §5-1 (SQL injection), §3-2 (missing authorization), §2-1 (account creation without verification)
**Cases**: TSA FlyCASS (Known Crewmember SQL injection), airport security bypass

**Attack Flow**:
1. Identify third-party vendor managing access control system
2. Exploit SQL injection in admin login (§5-1)
3. Authenticate as airline administrator
4. Create fictitious employee with security clearances
5. Use credentials to bypass physical checkpoints

**Impact**: Airport security circumvention, cockpit access, critical infrastructure risk

---

### Protocol & Service Exploitation

**Architecture**: Specialized protocols (TR-069, EPP) managing network infrastructure
**Primary Techniques**: §1-3 (CVE scanning), §2-1 (authentication bypass via replay), §4-2 (parameter manipulation)
**Cases**: Cox modems (TR-069 port 7547 abuse), EPP servers (ccTLD DNS control)

**Attack Flow (Modem Management)**:
1. Discover TR-069 (port 7547) exposed on ISP modems
2. Identify APIs with inconsistent authentication (some require auth, some don't)
3. Replay requests multiple times to bypass authentication via state confusion (§2-1)
4. Search accounts by name, retrieve PII, execute commands against modem MAC addresses

**Impact**: Mass modem compromise, customer PII access, network configuration changes, denial of service

---

## §10. CVE & Bounty Mapping (2020–2025)

This table links documented techniques to specific vulnerability disclosures and bug bounty rewards.

| Mutation Combination | Case / CVE | Impact | Bounty / Timeline |
|---------------------|-----------|--------|-------------------|
| §5-1 + §2-1 | **TSA FlyCASS SQL Injection** | Authentication bypass → Known Crewmember + Cockpit Access credentials | No bounty (government); Disclosed Apr 2024, Patched May 2024 |
| §2-1 + §2-2 + §3-2 | **Subaru STARLINK** | Unauthenticated password reset + 2FA bypass → Remote vehicle control (US/Canada/Japan fleet) | Undisclosed; Nov 2024 discovery, patched within 24 hours |
| §3-1 + §3-2 + §4-3 | **Kia Vehicles** | Dealer API abuse + VIN-based IDOR → Remote lock/unlock/start/locate on 15M+ vehicles (license plate only) | Undisclosed; Disclosed Jun 2024, Patched Aug 2024 |
| §4-1 + §4-2 | **Starbucks** | BFF proxy traversal (backslash encoding) → Microsoft Graph OData access to 99M customer records | $4,000; Reported May 16, 2020, Patched May 17, 2020 |
| §4-2 + §2-3 + §3-1 | **Points.com** | Directory traversal (lpId parameter) + weak Flask secret → 22.7M airline/hotel loyalty records + admin access | Undisclosed; Mar–May 2023, response within 10 min, full remediation <1 hour |
| §1-2 + §2-1 + §2-3 | **ClubWPT Gold** | Source code exposure (GitHack) + hardcoded credentials + 2FA bypass → Full back office access | Undisclosed; Jun 2025, patched same day |
| §8-1 + §8-3 + §6-3 | **Apple iCloud Pages SSRF** | URL whitelist bypass (@attacker.com) → Internal Maven repo source code retrieval + AWS metadata | Part of $288,500 total (55 vulnerabilities); Jul–Oct 2020 |
| §6-2 | **Apple iCloud Wormable XSS** | Stored XSS in email → Self-replicating via victim contacts (iCloud.com, Mac.com) | Part of $288,500 total; Critical severity (11 critical, 29 high, 13 medium, 2 low) |
| §2-3 + §3-3 | **Apple Heap Dump Credential Theft** | Spring Boot Actuator `/heapdump` → Valid employee `acack` tokens → Multi-application access | Part of $288,500 total |
| §3-1 + §4-2 | **Apple IDOR (App Store Connect)** | `itemId` numeric enumeration → Modify any app's game center settings | Part of $288,500 total |
| §3-1 + §4-2 | **Apple IDOR (Find My Friends)** | `dsIds` array parameter → Enumerate user IDs + retrieve associated emails (batch hundreds per request) | Part of $288,500 total |
| §5-2 + §2-1 | **Apple ePublisher Command Injection** | Unsanitized `-itc_provider` parameter → Arbitrary shell execution via `\|\|test123` | Part of $288,500 total |
| §5-1 | **Apple Vertica SQL Injection** | Unauthenticated `/gsf/` endpoints → Union-based injection (custom Vertica syntax) | Part of $288,500 total |
| §7-2 + §7-3 + §6-3 | **Rocket League Cache Poisoning** | X-Original-URL + path normalization (backslashes, double slashes) → OAuth JWT fragment theft | Undisclosed; Timing not specified |
| §2-1 + §4-3 | **Auto Industry (16 manufacturers)** | SSO misconfigurations + VIN-based IDOR → Remote vehicle control (Toyota, Nissan, Infiniti, Genesis, Honda, Acura, Lexus); BMW/Mercedes internal network access | Undisclosed; Disclosed Jan 2023 |
| §2-1 + §4-2 | **Cox Modems (TR-069)** | Inconsistent authentication (replay bypass) → Remote command execution on millions of modems + customer PII | Undisclosed; DEF CON 32 presentation Aug 2024 |

**Total Documented Bounty**: $288,500+ (Apple engagement alone); many cases remain undisclosed or involve government/large enterprises without public bounties.

---

## §11. Detection & Exploitation Tools

This matrix covers both offensive tools used during research and defensive tools for identifying similar vulnerabilities.

### Offensive Tools

| Tool | Target Scope | Core Technique | Usage Pattern |
|------|-------------|----------------|---------------|
| **Burp Suite Professional** | HTTP/S traffic interception, manipulation, analysis | Proxy all requests; Intruder for parameter fuzzing; Repeater for manual testing | Primary platform for all web application testing; Justin Gardner used Intruder to enumerate Starbucks internal endpoints |
| **FFuF** | Directory and file brute-forcing | Fast Go-based fuzzer for discovering hidden paths | Discovered `/assets/_js/login.js` on Subaru admin portal |
| **dirsearch** | Directory enumeration | Python-based recursive directory scanner | Alternative to FFuF for path discovery |
| **Amass / Subfinder** | Subdomain enumeration | Passive DNS, certificate transparency, brute-forcing | Initial reconnaissance for discovering admin portals, employee infrastructure |
| **cookie-monster** | Flask session secret cracking | Brute-force Flask signing keys | Cracked Points.com "secret" signing key |
| **flask-unsign** | Flask cookie manipulation | Unsign, modify, re-sign Flask session cookies | Modified Points.com admin cookie for privilege escalation |
| **Eclipse Memory Analyzer (MAT)** | Heap dump parsing | Extract objects, strings, credentials from Java heap dumps | Parsed Apple Spring Boot Actuator heap dumps for session tokens |
| **SQLMap** | SQL injection automation | Detect and exploit SQL injection (though manual exploitation often required) | Standard tool, though Vertica DB required manual techniques |
| **Wayback Machine / archive.org** | Historical snapshot retrieval | Access deleted documentation, old configurations | Retrieved Points.com API docs after public removal |
| **GitHack** | Exposed .git directory exploitation | Reconstruct source code from publicly accessible .git folders | ClubWPT source code fully exposed; reconstructed via GitHack |
| **Nuclei** | Template-based vulnerability scanning | YAML templates for CVEs, misconfigurations | Likely used for CVE-2020-3452 Cisco VPN scanning on Apple infrastructure |

### Defensive Tools

| Tool | Detection Capability | Limitations |
|------|---------------------|-------------|
| **Burp Scanner / DAST** | Automated XSS, SQLi, path traversal detection | Misses logic flaws, custom implementations; Curry emphasizes scanners fail on "mailing systems" and unique code |
| **Semgrep / CodeQL** | Static analysis for injection patterns, IDOR candidates | Requires access to source code; high false positive rate on authorization issues |
| **Cloud Security Posture Management (CSPM)** | Detect exposed actuators, open S3 buckets, overly permissive IAM | Only effective if cloud resources properly tagged and inventoried |
| **Web Application Firewalls (WAF)** | Block common injection payloads, traversal attempts | Bypassed via encoding (backslashes vs. forward slashes), segment insertion; requires constant rule updates |
| **API Gateway Rate Limiting** | Prevent brute-forcing, batch enumeration | Ineffective against IDOR if authorization checks missing; can be bypassed via race conditions |

---

## §12. Summary: Core Principles & Structural Insights

### The Fundamental Pattern: Trust Boundary Mismatches

Across Sam Curry's research portfolio, a unifying theme emerges: **architectural trust boundaries fail when components disagree on the interpretation of input, identity, or authorization scope**. These discrepancies manifest in three recurring structural patterns:

**1. Frontend-Backend Privilege Differentials**

The distinction between customer-facing and employee-facing infrastructure creates a persistent attack surface. When authentication mechanisms assume geographic isolation (IP allowlists), domain separation (customer.example.com vs. admin.example.com), or simple "security through obscurity" (hidden admin panels), subdomain enumeration and CNAME following reliably expose high-privilege systems. The Subaru STARLINK case epitomizes this: the admin portal existed on a guessable subdomain with unauthenticated password reset and client-side 2FA, while the customer mobile app was "properly secured."

**Why Incremental Patches Fail**: Adding 2FA to an admin portal is ineffective if the authentication check is client-side JavaScript. Restricting IP ranges fails when path traversal bypasses the proxy enforcing the restriction (`/admin;/`). The structural solution requires **enforcing consistent authentication at every layer** (application, proxy, database) and **eliminating client-side security controls**.

**2. Parser Differentials Between Components**

Modern web architectures chain multiple parsers: browser → CDN → WAF → reverse proxy → application framework → backend service. Each component normalizes, interprets, or routes requests slightly differently. This creates mutation spaces:
- **URL parsing**: `https:\\attacker.com` accepted as valid Location header (IIS) vs. browser interpretation
- **Path normalization**: `\..` vs. `/..` vs. `..%2f` treated differently by proxies and applications
- **Header handling**: `X-Original-URL` overrides actual request path in some proxies but not others
- **Encoding**: Backslashes bypass WAF rules tuned for forward slashes

The Starbucks BFF proxy traversal, Rocket League cache poisoning, and Apple SSRF URL bypass all exploit these parser differentials.

**Why Incremental Patches Fail**: Fixing one encoding variation (blocking `..%2f`) leaves others (`\..`). Adding a WAF rule for consecutive traversal (`/..\..\`) is bypassed by inserting valid segments (`web\..\.\..`). The structural solution requires **canonical input transformation at the earliest possible boundary** (e.g., normalizing all paths to forward slashes, decoding all percent-encoding before validation) and **validating against an allowlist of known-good states** rather than blocklisting bad patterns.

**3. Implicit Authorization via Metadata**

Many systems assume possession of an identifier (VIN, rewards number, email address) implies authorization to access the associated resource. This breaks in multi-tenant environments or when identifiers are easily enumerable:
- **VIN numbers**: Visible on dashboards, sequential, resolvable from license plates
- **Rewards numbers**: Printed on cards, shared in emails, incremental
- **Numeric IDs**: Sequential or predictable, leakable via timing attacks or error messages

The Kia license plate attack chain exemplifies this: license plate → VIN → vehicle control. Points.com, Apple IDOR, and auto industry vulnerabilities follow the same pattern.

**Why Incremental Patches Fail**: Randomizing IDs (switching from incremental integers to UUIDs) only prevents enumeration, not exploitation if leaked. Rate limiting slows attacks but doesn't eliminate the underlying authorization gap. The structural solution requires **server-side ownership checks on every resource access**: `SELECT * FROM vehicles WHERE vin = ? AND owner_id = current_user_id()`. Possession of a VIN or UUID must never be conflated with authorization.

---

### Methodology: Realistic Mindset Over Automation

Curry's philosophy prioritizes **manual analysis and creative testing over automated scanner output**. Key principles:

**1. "What characters will it allow?"** — Systematically test boundary characters (`;`, `|`, `&&`, `\`, `#`, `?`) rather than assuming standard injection patterns. This discovered the ePublisher command injection (`||test123`) and backslash-based traversal.

**2. "Approach with a realistic mindset"** — Automated scanners miss custom implementations, especially:
   - Mailing systems (CRLF injection opportunities)
   - Business logic flows (multi-step processes, state machines)
   - API parameter combinations (array batch requests)

**3. Focus on architectural privilege differentials** — Employee portals, dealer APIs, and admin panels have broader permissions than customer applications. Enumeration effort should prioritize these.

**4. Chain low-severity findings into critical impact** — Individual vulnerabilities (email enumeration, client-side 2FA, weak session secret) combine into full account takeover. Single SSRF becomes RCE when chained with cloud metadata access.

---

### The Structural Solution: Defense in Depth with Consistent Enforcement

No single mitigation addresses the entire taxonomy. A layered approach is required:

**Layer 1: Input Canonicalization**
- Normalize all inputs (URLs, paths, encodings) to a single canonical form at the earliest boundary
- Reject ambiguous inputs rather than attempting to interpret them
- Use allowlists (known-good patterns) over blocklists (known-bad patterns)

**Layer 2: Explicit Authorization Everywhere**
- Every resource access must validate ownership/permission server-side
- Possession of an identifier (ID, VIN, email) is never proof of authorization
- Implement consistent RBAC/ABAC across all services, including internal APIs

**Layer 3: Eliminate Client-Side Security**
- Never enforce authentication, authorization, or sensitive logic in JavaScript
- Client-side validation is UX, not security
- Use HTTP-only, Secure, SameSite cookies; avoid embedding tokens in URLs

**Layer 4: Minimize Trust Boundaries**
- Reduce the number of components that interpret untrusted input (fewer parsers = fewer differentials)
- Use OAuth/OIDC properly: validate tokens server-side, never trust client-provided identity claims
- Isolate internal services (metadata endpoints, admin panels) via network segmentation, not just authentication

**Layer 5: Continuous Verification**
- Automated scanners for known patterns (SQLi, XSS), but invest in manual pentest for logic flaws
- Monitor for anomalies: mass IDOR enumeration (hundreds of requests with sequential IDs), unusual OAuth flows, privilege escalations
- Bug bounty programs provide external validation of security posture

---

### Future-Proofing Against This Attack Surface

As applications increasingly rely on microservices, BFF proxies, and third-party integrations, the **number of trust boundaries multiplies**. Each boundary is a potential parser differential or authorization mismatch. Organizations should:

1. **Map all trust boundaries explicitly** — Document every point where external input crosses into a new context (CDN → proxy → app → database; customer API → employee API)
2. **Standardize authentication/authorization libraries** — Avoid custom implementations; use proven frameworks (OAuth 2.1, OIDC, SAML) with secure defaults
3. **Assume identifiers are public** — Design authorization models that function even if all IDs (VINs, UUIDs, account numbers) are known to attackers
4. **Test for parser differentials** — Use differential fuzzing tools (e.g., HTTP Garden for HTTP parsing, URL fuzzing suites) to identify discrepancies between components
5. **Invest in adversarial review** — External security researchers (bug bounties, pentests) bring creative exploitation perspectives that internal teams miss

---

*This taxonomy was created for defensive security research, vulnerability understanding, and security awareness purposes. All cases documented are from public disclosures and responsible vulnerability reporting.*

---

## References

### Primary Sources

- Sam Curry's Blog: https://samcurry.net/
- [We Hacked Apple for 3 Months: Here's What We Found](https://samcurry.net/hacking-apple)
- [Hacking Subaru: Tracking and Controlling Cars via the STARLINK Admin Panel](https://samcurry.net/hacking-subaru)
- [Hacking Kia: Remotely Controlling Cars With Just a License Plate](https://samcurry.net/hacking-kia)
- [Leaked Secrets and Unlimited Miles: Hacking the Largest Airline and Hotel Rewards Platform](https://samcurry.net/points-com)
- [Hacking Starbucks and Accessing Nearly 100 Million Customer Records](https://samcurry.net/hacking-starbucks)
- [Abusing HTTP Path Normalization and Cache Poisoning to Steal Rocket League Accounts](https://samcurry.net/abusing-http-path-normalization-and-cache-poisoning-to-steal-rocket-league-accounts)
- [Hacking the World Poker Tour: Inside ClubWPT Gold's Back Office](https://samcurry.net/hacking-clubwpt-gold)
- [Web Hackers vs. The Auto Industry: Critical Vulnerabilities in Ferrari, BMW, Rolls Royce, Porsche, and More](https://samcurry.net/web-hackers-vs-the-auto-industry)

### Conference Presentations

- [DEF CON 32: Hacking Millions of Modems (and Investigating Who Hacked My Modem)](https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/DEF%20CON%2032%20-%20Sam%20Curry%20-%20Hacking%20Millions%20of%20Modems%20(and%20Investigating%20Who%20Hacked%20My%20Modem).pdf)

### News & Analysis

- [Researchers find SQL injection to bypass airport TSA security checks](https://www.bleepingcomputer.com/news/security/researchers-find-sql-injection-to-bypass-airport-tsa-security-checks/)
- [Hackers Could Have Remotely Controlled Kia Cars Using Only License Plates](https://thehackernews.com/2024/09/hackers-could-have-remotely-controlled.html)
- [55 New Security Flaws Reported in Apple Software and Services](https://thehackernews.com/2020/10/apple-security.html)
- [Points.com Vulnerabilities Allowed Customer Data Theft](https://www.securityweek.com/points-com-vulnerabilities-allowed-customer-data-theft-rewards-program-hacking/)
- [Motivation and Methodology with Sam Curry (Zlz)](https://blog.criticalthinkingpodcast.io/p/motivation-and-methodology-with-sam-curry)

### Collaborative Research

Research conducted with: Brett Buerhaus, Ben Sadeghipour, Samuel Erb, Tanner Barnes, Ian Carroll, Shubham Shah, Justin Rhinehart, Neiko Rivera, Maik Robert, and others.

---

**Document Version**: 2025.1
**Last Updated**: February 2025
**Scope**: Techniques documented through public disclosures as of February 2025