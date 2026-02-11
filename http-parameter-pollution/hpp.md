# HTTP Parameter Pollution (HPP) Mutation/Variation Taxonomy

---

## Classification Structure

HTTP Parameter Pollution (HPP) exploits the fundamental absence of a standardized specification for how HTTP parameters with duplicate names should be handled. RFC 3986 defines URI syntax and RFC 7230–7235 define HTTP message semantics, but **neither prescribes behavior when multiple parameters share the same name**. This specification gap means every web technology — servers, frameworks, proxies, WAFs — implements its own parsing logic, creating a rich attack surface wherever two or more components process the same request.

This taxonomy organizes the entire HPP mutation space along three axes:

- **Axis 1 — Mutation Target (Primary):** The structural component or transport layer through which parameter pollution is introduced. This is the organizing principle of the document body (§1–§8).
- **Axis 2 — Mutation Mechanism (Cross-cutting):** The specific technique used to create a parsing discrepancy between components. A single mutation target may be exploited through multiple mechanisms.
- **Axis 3 — Attack Scenario (Mapping):** The real-world exploitation outcome achieved by combining a mutation target with a mechanism.

### Axis 2: Mutation Mechanism Summary

| Mechanism | Description |
|-----------|-------------|
| **Duplicate Injection** | Submitting the same parameter name multiple times with different values |
| **Precedence Abuse** | Exploiting first-wins vs. last-wins vs. concatenation differences between components |
| **Delimiter Injection** | Injecting encoded delimiters (`&`, `=`, `#`, `;`) to create/modify parameters |
| **Array Notation Abuse** | Using `param[]`, `param[0]`, or `param[key]` to bypass singular parameter validation |
| **Encoding Differential** | Using URL encoding, double encoding, or Unicode to evade pattern matching |
| **Structured Format Breakout** | Escaping from JSON/XML value context to inject new key-value pairs |
| **Truncation** | Using `#` or null bytes to remove downstream parameters from processing |
| **Cross-Transport Confusion** | Mixing parameter sources (query + body + cookie) that the application merges |

### Foundation: Framework Parameter Precedence Table

This table is the cornerstone of all HPP attacks. The discrepancy between any two rows enables exploitation when those technologies coexist in a request processing pipeline.

| Technology / Framework | Duplicate Parameter Behavior | Result for `?a=1&a=2` |
|------------------------|------------------------------|------------------------|
| **ASP.NET / IIS** | Concatenates all occurrences (comma-separated) | `a = "1,2"` |
| **PHP / Apache** | Last occurrence wins | `a = "2"` |
| **Python Django** | Last occurrence wins | `a = "2"` |
| **Python Flask** | First occurrence wins | `a = "1"` |
| **Python Tornado** | Last occurrence wins | `a = "2"` |
| **Ruby on Rails / WEBrick** | Last occurrence wins (supports `&` and `;` delimiters) | `a = "2"` |
| **Java JSP / Tomcat** | First occurrence wins | `a = "1"` |
| **Spring MVC / Tomcat** | Concatenates all occurrences (comma-separated) | `a = "1,2"` |
| **Node.js / Express** | Concatenates or creates array | `a = "1,2"` or `a = ["1","2"]` |
| **Go (net/http Get)** | First occurrence wins | `a = "1"` |
| **Go (net/http Query)** | Returns all as array | `a = ["1","2"]` |
| **Perl / CGI** | Returns all as array | `a = ["1","2"]` |
| **Python Zope** | Returns all as array | `a = ["1","2"]` |

---

## §1. Query String Parameter Pollution

The classic and most widely studied HPP vector. Query string parameters are visible, easily modified, and parsed by every component in the request chain — proxies, WAFs, caches, load balancers, and application servers.

### §1-1. Duplicate Parameter Injection

The foundational HPP technique: submitting the same parameter name multiple times in the query string and exploiting differential parsing between components.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **First-vs-Last Precedence Split** | WAF validates the first occurrence; backend processes the last (or vice versa). Attacker places benign value in the validated position and malicious value in the processed position. | Two components with opposite precedence (e.g., Flask WAF + PHP backend) |
| **Concatenation Exploitation** | ASP.NET or Spring MVC concatenates duplicates with commas. Attacker splits a payload across parameters so each fragment is individually benign but the concatenated result is malicious. | Backend uses ASP.NET, Spring MVC, or Node.js concatenation |
| **Array Promotion** | Submitting duplicates causes the backend to create an array where scalar was expected, triggering type confusion in downstream logic. | Go, Perl, Zope, or Express array-mode parsing |
| **Selective Parameter Shadowing** | An attacker-supplied duplicate overrides a hardcoded or hidden parameter set by the application (e.g., `role=user` hardcoded, attacker adds `role=admin`). | Application appends user input to a base query string containing fixed parameters |

**Example — Concatenation-based XSS (ASP.NET):**
```
GET /search?q=1'&q=alert(1)&q='2 HTTP/1.1
```
ASP.NET concatenates to: `q = "1',alert(1),'2"`. When inserted into a JavaScript context like `var x = 'USER_INPUT';`, this becomes valid executable JavaScript via the comma operator: `var x = '1',alert(1),'2';`.

### §1-2. Delimiter Injection

Injecting URL-encoded query string delimiters within parameter values to create, modify, or remove parameters as perceived by the backend.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Ampersand Injection (`%26`)** | Injecting `%26` within a value to create a new parameter from the backend's perspective: `name=peter%26role=admin`. | Backend decodes before parsing, or double-decodes |
| **Equals Sign Injection (`%3D`)** | Injecting `%3D` to redefine parameter boundaries: `param=value%3Dadmin`. | Backend interprets decoded `=` as key-value separator |
| **Semicolon Delimiter Confusion** | Some servers (e.g., Ruby WEBrick, Java Servlet) accept `;` as an alternative parameter delimiter. Injecting `;` creates parameters invisible to components that only recognize `&`. | Mixed delimiter support in the processing chain |
| **Hash Truncation (`%23`)** | Injecting URL-encoded `#` to truncate everything after it from the server-side perspective: `name=peter%23&role=admin` causes the backend to see only `name=peter`. | Server-side request construction that passes `#` through to an internal API |

**Example — Parameter Injection via Ampersand:**
```
POST /api/update
name=peter%26access_level=admin
```
If the backend decodes and re-parses: `name=peter&access_level=admin` — an entirely new parameter is injected.

### §1-3. Encoding Differential

Exploiting differences in how components decode URL-encoded, double-encoded, or Unicode-encoded parameter names and values.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Double URL Encoding** | WAF decodes once and sees benign input; backend decodes twice and sees malicious payload. `%2526` → WAF sees `%26` (literal) → backend decodes to `&` (delimiter). | WAF performs single decode; backend performs double decode |
| **Mixed Encoding** | Combining percent-encoding with Unicode or HTML entities within parameter values to bypass signature matching. | WAF pattern matching operates on raw bytes; backend normalizes before processing |
| **Parameter Name Encoding** | Encoding the parameter name itself (`%72ole=admin` → `role=admin`) to bypass parameter-name-based allowlists. | WAF filters by parameter name without decoding |
| **Overlong UTF-8 Sequences** | Using non-shortest-form UTF-8 encodings (e.g., `%C0%AE` for `.`) that some parsers normalize while others reject or pass through. | Differential UTF-8 validation between components |

---

## §2. POST Body Parameter Pollution

Parameters submitted in the HTTP request body via `application/x-www-form-urlencoded` follow the same key=value&key=value syntax as query strings but operate in a different processing context with distinct security implications.

### §2-1. Body Duplicate Injection

Identical to §1-1 in mechanism but applied to POST body parameters. The key difference is that POST body parameters are often processed by different code paths than query parameters.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **POST Body Precedence Split** | Same as §1-1 but within the body. WAF and backend disagree on which duplicate to process. | Components with different precedence for body parameters |
| **Body Parameter Override of Hidden Fields** | Injecting duplicates of hidden form field values (CSRF tokens, user IDs, role indicators) to override application-set values. | Application trusts hidden field values without server-side re-validation |

### §2-2. Query-Body Cross-Pollution

Exploiting how applications merge or prioritize parameters from different sources (query string vs. POST body).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Query Override of Body** | Submitting a parameter in both the query string and POST body. Some frameworks prioritize query string; others prioritize body. Attacker places the override in whichever source takes precedence. | Framework merges sources with defined priority (e.g., Express `req.query` vs. `req.body`) |
| **Body Override of Query** | Reverse of above: body parameter overrides a query string parameter that the application assumes is immutable. | Application sets parameters in the URL but framework allows body override |
| **Merged Source Confusion** | Frameworks like PHP's `$_REQUEST` merge GET, POST, and COOKIE with a configurable priority order (`variables_order` / `request_order` in `php.ini`). Attacker exploits the merge priority. | PHP with default `$_REQUEST` usage |

**Example — PHP `$_REQUEST` Merge:**
```
GET /transfer?amount=100 HTTP/1.1
Content-Type: application/x-www-form-urlencoded

amount=99999
```
If the application reads from `$_REQUEST` and `request_order` is `"GP"` (GET then POST), POST overrides GET. If `"PG"`, GET overrides POST. The attacker targets whichever source the application does NOT validate.

---

## §3. Structured Data Format Pollution

When applications process parameters in structured formats (JSON, XML, GraphQL), parameter pollution extends beyond simple duplicate keys to exploit format-specific parsing behaviors.

### §3-1. JSON Duplicate Key Injection

RFC 8259 (JSON) states that object member names "SHOULD be unique" but does not mandate it, leaving behavior implementation-defined.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Last-Key-Wins Override** | Injecting a duplicate JSON key where the parser uses the last occurrence: `{"role":"user","role":"admin"}`. | Backend JSON parser uses last-key-wins (Python `json`, most implementations) |
| **First-Key-Wins Override** | Same technique but targeting parsers that use the first key. Attacker places malicious value first. | Frontend validates with last-key-wins parser; backend uses first-key-wins |
| **Parser Differential** | WAF/validation layer and backend use different JSON parsers with different duplicate-key behaviors. Benign value in one position, malicious in the other. | Mixed JSON parser implementations in the pipeline |
| **Comment-Based Hiding** | Some JSON parsers support comments (`//`, `/* */`) while others don't. Attacker hides a malicious duplicate key inside a comment that one parser ignores and another processes: `{"role":"user", /* "role":"admin", */ "name":"test"}`. | Mixed comment support (e.g., JSON5 vs. strict JSON) |

### §3-2. JSON Value Breakout

Escaping from a JSON string value to inject new key-value pairs at the object level.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Quote Escape Breakout** | Input `peter","role":"admin` injected into `{"name":"USER_INPUT"}` produces `{"name":"peter","role":"admin"}`. | Server constructs JSON via string concatenation without proper escaping |
| **Encoding Layer Bypass** | Client sends JSON with escaped payload `{"name":"peter\",\"role\":\"admin\"}`. Server decodes the escapes before embedding in a downstream JSON request. | Double-processing: decode then re-embed without re-encoding |
| **Numeric/Type Confusion** | Large integers (`999...999`), scientific notation, or special float values (`NaN`, `Infinity`) are parsed differently across JSON libraries, enabling validation bypass. | Numeric comparison after parsing with different precision |
| **Unicode Escape Abuse** | Using `\uXXXX` sequences that normalize differently across parsers. Truncation via `\ud800` (unpaired surrogate) causes some parsers to stop processing. | Differential Unicode normalization |

### §3-3. XML Parameter Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Duplicate Element Override** | Submitting duplicate XML elements where the parser processes the first or last: `<role>user</role><role>admin</role>`. | XML processing without schema validation |
| **Attribute Duplication** | Duplicate XML attributes: `<user role="user" role="admin">`. Behavior varies by parser. | Lenient XML parser that doesn't reject duplicate attributes |
| **CDATA Injection** | Breaking out of a value context using CDATA sections to inject new elements. | XML constructed via string concatenation |

### §3-4. GraphQL Parameter Pollution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Query Argument Duplication** | Submitting duplicate arguments in a GraphQL query: `query { user(id: "1", id: "admin") { ... } }`. | GraphQL server doesn't validate argument uniqueness |
| **Variable Override** | Defining a variable in both the query variables JSON and inline, exploiting precedence differences. | Mixed variable resolution |
| **Batch Query Parameter Smuggling** | Sending batched queries where parameter names from one query leak into or override parameters of another. | Batching enabled without isolation |
| **REST Path Injection via ID** | When GraphQL acts as an API gateway, injecting path traversal in ID arguments: `user(id: "1/../../admin")` that gets interpolated into a REST URL. | Backend constructs REST URLs from GraphQL arguments |

---

## §4. Cookie Parameter Pollution

Cookies represent a distinct parameter transport that is often merged with GET/POST parameters by frameworks, creating cross-source pollution opportunities.

### §4-1. Cookie-Request Merge Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cookie Override via `$_REQUEST`** | PHP's `$_REQUEST` superglobal merges GET, POST, and COOKIE values. Attacker sets a cookie with the same name as a critical parameter, exploiting the merge priority. | Application uses `$_REQUEST` with cookie priority |
| **Cookie Duplicate Injection** | Sending multiple `Cookie` headers or multiple values with the same name in a single header. Server behavior varies: some use first, some use last. | Multiple Cookie header handling varies by server |
| **Cookie-Header Confusion** | Some CDNs/proxies extract parameters from cookies differently than the origin server, creating precedence mismatches. | CDN cookie parsing differs from origin |

### §4-2. Cookie Injection for Parameter Pollution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CRLF-to-Cookie Injection** | CRLF injection in response headers to set attacker-controlled cookies that will pollute future requests. | CRLF injection vulnerability exists |
| **Subdomain Cookie Pollution** | Setting cookies from a subdomain (e.g., `evil.example.com`) that are sent to the main domain, overriding application parameters stored in cookies. | Application shares cookie scope with untrusted subdomains |

---

## §5. HTTP Header Parameter Pollution

HTTP headers themselves can be polluted, particularly headers that carry parameter-like data or influence parameter processing.

### §5-1. Header Duplication

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Duplicate Header Injection** | Sending duplicate HTTP headers (e.g., two `Host` headers, two `Content-Type` headers). Proxies and backends may use different occurrences. | RFC 7230 §3.2.2: recipients may handle duplicate headers differently unless the field is defined as a comma-separated list |
| **Content-Type Confusion** | Sending both `Content-Type: application/x-www-form-urlencoded` and `Content-Type: application/json`. Proxy parses body as form data; backend parses as JSON (or vice versa). | Differential Content-Type processing in pipeline |
| **X-Forwarded-For Pollution** | Injecting duplicate or crafted `X-Forwarded-For` headers to manipulate IP-based access controls or rate limiting. | Application trusts `X-Forwarded-For` without proxy-chain validation |

### §5-2. Header-as-Parameter Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Custom Header Parameter Binding** | Some frameworks bind specific headers to parameters (e.g., `X-HTTP-Method-Override`). Attacker injects headers that override request method or parameters. | Framework supports header-based parameter override |
| **Transfer-Encoding / Content-Length Interaction** | While primarily an HTTP smuggling vector, TE/CL discrepancies can cause different parameter sets to be parsed from the same request body by different components. | Cross-reference: HTTP Request Smuggling taxonomy |

---

## §6. REST URL Path Parameter Pollution

When applications embed user input into server-side API URL paths, path-based parameter pollution becomes possible.

### §6-1. Path Traversal in URL Parameters

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Dot-Dot-Slash Override** | Injecting `../` sequences in a path parameter to traverse to a different API endpoint: `username=peter%2f..%2fadmin` → `/api/users/peter/../admin` → `/api/users/admin`. | Server-side path normalization resolves traversal sequences |
| **Path Segment Injection** | Injecting `/` characters to add entirely new path segments, potentially accessing different API endpoints or resources. | Input embedded directly into URL path without sanitization |

### §6-2. Path Truncation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Query String Initiation** | Injecting `%3F` (encoded `?`) to start a query string within a path parameter, causing everything after to be treated as query parameters rather than path: `name=peter%3Frole=admin`. | Backend re-parses the constructed URL |
| **Fragment Truncation** | Injecting `%23` (encoded `#`) to truncate the URL, removing downstream path segments or query parameters from processing. | Fragment identifier handled on the server side |

---

## §7. Multipart Form Data Pollution

`multipart/form-data` encoding introduces boundary-based parsing that creates unique pollution opportunities.

### §7-1. Multipart Duplicate Fields

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Duplicate Part Names** | Including multiple parts with the same `name` in `Content-Disposition`. Parsing behavior (first, last, array) varies by framework. | Framework-specific multipart parsing, analogous to §1-1 |
| **Boundary Confusion** | Manipulating the multipart boundary string to cause different parsers to identify different part boundaries, effectively hiding or revealing parameters. | Lenient boundary parsing in one component vs. strict in another |

### §7-2. Content-Disposition Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Filename-as-Parameter** | Injecting parameter-like data in the `filename` field of `Content-Disposition`, which some backends process as a parameter value. | Backend extracts data from filename field |
| **Quoted vs. Unquoted Value Confusion** | Discrepancies in how components handle quoted vs. unquoted values in `Content-Disposition: form-data; name="param"` vs. `name=param`. | Mixed quoting tolerance |

---

## §8. Application Logic Parameter Pollution

Beyond transport-layer pollution, HPP can target application-specific logic patterns that construct, forward, or validate parameters.

### §8-1. Server-Side Request Parameter Injection

When the application constructs internal API requests using user-supplied input without proper encoding.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Internal API Parameter Override** | User input is embedded into a server-side query string to an internal API: `GET /internal?name=USER_INPUT&token=SECRET`. Attacker injects `peter%26token=ATTACKER_TOKEN` to override the secret token. | Server constructs internal URLs via string concatenation |
| **Microservice Parameter Forwarding** | In microservice architectures, Gateway A forwards user parameters to Service B. Attacker adds parameters intended for Service B that Gateway A doesn't validate. | No parameter allowlist at the gateway level |
| **Backend Parameter Cloaking** | Injecting parameters that are invisible to frontend validation but processed by the backend (e.g., `admin=true`, `debug=1`, `internal=yes`). | Backend processes parameters not in the frontend form |

### §8-2. Business Logic Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Transaction Parameter Manipulation** | Polluting financial parameters: `amount=10&amount=10000` or `from=attacker&from=victim` to alter transaction source/destination/amount. | Application uses polluted parameter without validation |
| **OTP/Password Reset Hijacking** | Duplicating the email/phone parameter in password reset or OTP flows: `email=victim@example.com&email=attacker@example.com`. Application generates token for victim but sends to attacker. | OTP generation reads first email; delivery reads last (or vice versa) |
| **API Key / Token Override** | Appending duplicate `api_key` or `token` parameters to override hardcoded keys: `?api_key=app_default&api_key=attacker_key`. Backend uses the attacker's key for authorization. | Server processes last API key occurrence |
| **Privilege Escalation via Hidden Parameters** | Injecting parameters like `role=admin`, `is_staff=true`, or `access_level=administrator` that the application processes during user creation or profile update. | Mass assignment: framework binds all request parameters to model attributes |
| **Rate Limit / Business Rule Bypass** | Polluting parameters that control rate limiting, pricing, or quotas: `quantity=1&quantity=999` or `discount=0&discount=100`. | Application logic reads polluted values for business-critical decisions |

### §8-3. WAF / Filter Evasion via HPP

Using HPP not as the primary attack, but as an evasion technique to deliver other attack payloads past security filters.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Split Payload Concatenation** | Splitting an XSS, SQLi, or command injection payload across multiple parameters that the backend concatenates. WAF sees benign fragments; backend assembles the attack. Example: `q=SELECT&q=*&q=FROM&q=users` → ASP.NET: `q = "SELECT,*,FROM,users"`. | Backend concatenates (ASP.NET, Spring MVC, Node.js) |
| **Comma Operator Abuse (JavaScript)** | Splitting JavaScript across comma-concatenated parameters. `q=1'&q=alert(1)&q='2` → `1',alert(1),'2` — valid JS via the comma operator. | ASP.NET concatenation + reflected output in JS context |
| **WAF Parameter Limit Exhaustion** | Sending a very large number of parameters to exhaust the WAF's parsing buffer or parameter limit, causing it to stop analyzing and pass the request through. The malicious parameter is placed after the limit. | WAF has a maximum parameter count/size threshold |
| **Encoding Split** | Splitting encoded characters across duplicates: `%2` in one parameter, `7` in the next, where concatenation produces `%27` (single quote). | Concatenation + re-decoding after merge |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|----------------------------|
| **WAF Bypass → XSS/SQLi** | WAF + ASP.NET/Spring backend with concatenation behavior | §1-1 + §8-3 |
| **Account Takeover** | Password reset / OTP flow with email parameter processing | §1-1 + §8-2 |
| **Privilege Escalation** | Framework with mass assignment + hidden parameter injection | §2-1 + §8-2 |
| **Internal API Exploitation** | Microservice architecture with string-concatenated URLs | §6-1 + §8-1 |
| **IDOR / Authorization Bypass** | Object ID parameters polluted with admin/other-user IDs | §1-1 + §2-2 + §8-2 |
| **Cache Poisoning** | CDN caches response keyed on one parameter; application processes another | §1-1 + §5-1 |
| **Business Logic Abuse** | E-commerce / financial application without parameter deduplication | §2-1 + §8-2 |
| **Security Filter Evasion** | Any pipeline with WAF/IDS and concatenating backend | §1-3 + §3-2 + §8-3 |
| **SSRF Chain** | Server constructs internal URLs from user parameters | §6-1 + §6-2 + §8-1 |
| **JSON API Exploitation** | APIs processing JSON with duplicate keys or string-concatenated JSON construction | §3-1 + §3-2 |

---

## CVE / Bounty Mapping (2021–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-1 + §8-3 (WAF bypass via concatenation) | Ethiack WAF Research (2025) — 17 WAF configurations tested | 70.6% bypass rate with complex HPP payloads. AWS WAF Managed Rules, Cyber Security Cloud, F5 rule sets fully bypassed. Only Google Cloud Armor (ModSecurity), Azure WAF (DRS 2.1), and open-appsec blocked all manual payloads. |
| §1-1 (Client-side reflected HPP) | CVE-2025-59977 (Juniper Junos Space) | Medium severity. Reflected client-side HPP in web interface. |
| §1-1 (Client-side reflected HPP) | CVE-2021-0269 (Juniper Junos OS J-Web) | Client-side HPP in J-Web management interface. |
| §1-3 + §3-2 (Encoding differential) | CVE-2025-7783 (form-data library < 2.5.4, 3.0.0–3.0.3, 4.0.0–4.0.3) | Critical (CVSS 9.4). Insufficiently random values in form-data boundary generation enables HPP. High confidentiality and integrity impact. |
| §8-2 (OTP hijacking) | Multiple bug bounty reports (2023–2025) | Account takeover via duplicated email parameter in password reset flows. OTP generated for victim, sent to attacker. |
| §8-2 (Transaction manipulation) | Multiple bug bounty reports | Financial parameter manipulation in payment flows via duplicate `from`/`amount` parameters. |
| §8-2 (Mass assignment + HPP) | GitHub mass assignment incident (2012) — landmark case | Public key uploaded to any organization via parameter binding abuse. Led to widespread adoption of strong parameter patterns. |
| §8-3 (Split payload WAF bypass) | Multiple HackerOne / Bugcrowd reports (2024–2025) | XSS via split payloads across duplicate parameters on ASP.NET applications. Bounties ranging $500–$5,000. |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Burp Suite Scanner** (Commercial) | Automated SSPP and client-side HPP detection | Detects "suspicious input transformations" by injecting parameters and analyzing differential responses |
| **Backslash Powered Scanner** (Burp BApp) | Server-side injection including parameter pollution | Injects special characters and analyzes response variations to identify injection points |
| **HPPFuzZBu5t3R** (Open Source) | Dedicated HPP vulnerability detection | Tests duplicate parameters with comma-separated and file-based inputs; concurrent request scanning |
| **PAPAS** (Research Prototype) | Automated HPP discovery | Black-box scanning: injects parameters and analyzes generated output to identify HPP vulnerabilities |
| **Acunetix** (Commercial) | Web vulnerability scanning including HPP | Automated HPP detection with remediation suggestions |
| **Nuclei** (Open Source) | Template-based web vulnerability scanning | Supports HTTP fuzzing templates for parameter injection testing |
| **ZAP (OWASP)** (Open Source) | Web application security scanning | HPP scanner plugin (active scanner) for automated detection |
| **wfuzz** (Open Source) | Web application fuzzer | Brute-forces GET/POST parameters for injection point discovery |
| **Param Miner** (Burp BApp) | Hidden parameter discovery | Discovers unlinked parameters that may be susceptible to pollution |

---

## Summary: Core Principles

### The Root Cause

HTTP Parameter Pollution exists because of a **specification gap combined with implementation diversity**. HTTP standards define how parameters are transmitted but not how duplicates should be resolved. Every framework, server, proxy, and WAF independently decided on a behavior — first-wins, last-wins, concatenation, array, or error — and these decisions were never coordinated. The result is that **any request processing pipeline with two or more components has potential for parameter interpretation mismatch**.

### Why Incremental Fixes Fail

HPP is not a single vulnerability but a **class of semantic mismatches**. Fixing the application's parameter handling doesn't address the discrepancy between the WAF and the application, or between the proxy and the backend. Each new component added to the architecture (CDN, API gateway, service mesh sidecar, cloud WAF) introduces a new parsing layer with its own duplicate-parameter behavior. Patching individual instances is a game of whack-a-mole because the fundamental condition — multiple independent parameter parsers in the same request path — is an architectural feature of modern web applications, not a bug.

Furthermore, the attack surface has expanded beyond classic query-string duplication into JSON duplicate keys, GraphQL argument pollution, multipart boundary confusion, and structured format injection. Each new data format and API paradigm reintroduces the same fundamental problem in a new context.

### The Structural Solution

A comprehensive defense requires:

1. **Canonical parameter normalization** at the first entry point: deduplicate, decode, and validate parameters once, then pass a normalized representation downstream. All downstream components must use this canonical form rather than re-parsing the raw request.
2. **Explicit parameter schemas** (allowlists of expected parameter names, types, and cardinalities) enforced at every boundary. Reject requests with unexpected duplicates rather than silently choosing one.
3. **Consistent serialization** when constructing internal API requests: use parameterized query building or structured serialization libraries rather than string concatenation.
4. **Defense-in-depth testing**: specifically test for HPP across all parameter transports (query, body, JSON, headers, cookies, multipart) and across all component boundaries in the pipeline.

---

## References

- di Paola, S. & Carettoni, L. (2009). "HTTP Parameter Pollution." OWASP AppSec EU.
- Balduzzi, M. et al. (2011). "Automated Discovery of Parameter Pollution Vulnerabilities in Web Applications." NDSS Symposium.
- Bui, T. et al. (2012). "ARC: Protecting Against HTTP Parameter Pollution Attacks Using Application Request Caches." ACNS.
- Mendes, B. (2025). "Bypassing WAFs for Fun and JS Injection with Parameter Pollution." Ethiack Research Blog.
- PortSwigger (2024). "Server-side Parameter Pollution." Web Security Academy.
- OWASP (2024). "Testing for HTTP Parameter Pollution." WSTG v4.2.
- CAPEC-460: HTTP Parameter Pollution (HPP). MITRE.
- CWE-235: Improper Handling of Extra Parameters. MITRE.

---

*This document was created for defensive security research and vulnerability understanding purposes.*
