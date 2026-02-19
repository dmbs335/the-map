# IIS/ASP.NET Parsing & Interpretation Mismatch Taxonomy

**A Comprehensive Mutation Catalog of Parser Differential Vulnerabilities in Microsoft Web Stack**

---

## Classification Structure

This taxonomy organizes parser differential vulnerabilities in Microsoft's IIS and ASP.NET stack according to three orthogonal axes:

**Axis 1: Mutation Target** — The structural component being modified (HTTP framing, URL/path, headers, session state, object serialization). This forms the primary organizational structure (§1–§5).

**Axis 2: Discrepancy Type** — The nature of the parsing/interpretation mismatch created between components. These cross-cutting patterns apply across all mutation targets:

| Discrepancy Type | Definition | Typical Component Pair |
|-----------------|------------|----------------------|
| **Framing Mismatch** | Front-end and back-end disagree on message boundaries | Proxy ↔ IIS |
| **Path Interpretation Delta** | Different layers parse URLs/paths inconsistently | IIS ↔ NTFS ↔ Authorization |
| **Encoding/Charset Delta** | Character encoding handled differently | WAF ↔ ASP.NET Runtime |
| **Routing/Pool Confusion** | Request routed to unintended application context | IIS Metabase ↔ CLR AppDomain |
| **Type Confusion** | Object type interpreted differently during deserialization | Formatter ↔ Runtime Type System |

**Axis 3: Attack Scenario** — The weaponized impact context (detailed in dedicated section).

### Fundamental Mechanism

Microsoft's web stack involves multiple parsing and interpretation layers:
```
External Request → Front-End Proxy → IIS HTTP Parser → URL Rewriting →
Authorization Filter → ASP.NET Pipeline → Application Code → NTFS/Database
```

Each layer may apply different:
- **Character encoding/decoding rules** (UTF-7, UTF-8, URL encoding, double encoding)
- **Normalization algorithms** (case folding, path canonicalization, Unicode normalization)
- **Parsing strictness** (tolerant vs. strict RFC compliance)
- **State tracking** (stateful vs. stateless components)

When these layers disagree, an attacker can craft inputs that are interpreted differently by security-critical components (authentication, authorization, WAF) versus execution-critical components (file handlers, deserializers, runtime). This creates exploitable **interpretation deltas**.

---

## §1. HTTP Message Framing Mutations

HTTP message framing determines request boundaries in pipelined or multiplexed connections. When front-end and back-end servers disagree on where one request ends and another begins, attackers can smuggle partial requests into the body of legitimate requests, causing the back-end to interpret them as separate requests.

### §1-1. Content-Length / Transfer-Encoding Mismatch

The foundational HTTP smuggling technique exploits RFC 7230 ambiguity: when both `Content-Length` (CL) and `Transfer-Encoding: chunked` (TE) headers are present, TE should take precedence — but not all implementations agree.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CL.TE Desync** | Front-end uses CL, back-end uses TE. Attacker sends both headers; front-end forwards entire message, back-end stops reading at chunk terminator (`0\r\n\r\n`), leaving remainder in socket buffer as "next request". | IIS 6/7 as back-end with chunking-aware front-end |
| **TE.CL Desync** | Front-end uses TE, back-end uses CL. Attacker sends request with TE header but also includes CL. Front-end processes chunks, back-end reads only CL bytes, leaving smuggled request in buffer. | IIS 8+ with reverse proxies that prefer TE |
| **TE.0 (Zero-Body Desync)** | Back-end ignores both CL and TE, treating body length as zero. Entire message body becomes "next request". Discovered in 2024 affecting Google Cloud Load Balancer + IIS. | IIS misconfiguration or strict parser mode |

**Example (CL.TE)**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
```
Front-end sees 44-byte body; back-end processes chunk (`0\r\n\r\n`) and treats remainder as new request.

### §1-2. Transfer-Encoding Header Obfuscation

When one parser fails to recognize a `Transfer-Encoding` header due to obfuscation, it falls back to `Content-Length`, creating a mismatch.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Whitespace Injection** | Extra spaces/tabs around header value | `Transfer-Encoding: chunked` (trailing space) |
| **Capitalization Variation** | Mixed case in header name | `Transfer-encoding:`, `TrAnSfEr-EnCoDiNg:` |
| **Duplicate TE Headers** | Multiple TE headers, some parsers use first, others last | Two `Transfer-Encoding:` headers with conflicting values |
| **Non-Standard Characters** | Null bytes, vertical tabs, form feeds | `Transfer-Encoding: \x00chunked` |
| **Quoted Values** | IIS may ignore quoted TE values | `Transfer-Encoding: "chunked"` |

IIS historically had lenient header parsing, accepting malformed headers that strict parsers reject.

### §1-3. Chunk Extension Parsing Differential

RFC 7230 allows chunk extensions (`{size};{extension}\r\n`). Implementations vary in handling malformed extensions.

| Subtype | Mechanism | CVE Reference |
|---------|-----------|---------------|
| **Malformed Extension Injection** | Parser A ignores invalid extensions, Parser B rejects entire chunk. ASP.NET Core (.NET 9+) was vulnerable to lenient chunk extension parsing allowing smuggling. | CVE-2025-55315 (2025) |
| **Extension Overflow** | Excessively long extension causes buffer issues or parser bypass | IIS 6/7 legacy parsing |

**Example (CVE-2025-55315)**:
```http
POST / HTTP/1.1
Transfer-Encoding: chunked

5;malformed\x00extension
AAAAA
0

GET /admin HTTP/1.1
```

.NET's lenient parser accepted malformed extensions, creating framing mismatch with stricter front-ends.

### §1-4. Obsolete Line Folding (OLF) Abuse

HTTP/1.1 deprecated "line folding" (continuing header values on next line with whitespace), but IIS retained support.

| Subtype | Mechanism | CVE Reference |
|---------|-----------|---------------|
| **OPTIONS + OLF + Expect** | Combining `OPTIONS` method, obsolete line folding, and `Expect: 100-continue` creates processing discrepancy in Akamai CDN + IIS. | CVE-2025-32094 (2025) |

**Example**:
```http
OPTIONS / HTTP/1.1
Expect: 100-continue
Transfer-Encoding:
 chunked

{smuggled request}
```

First server interprets TE as absent (due to OLF), second server recognizes it.

### §1-5. HTTP Pipelining Abuse

HTTP/1.1 allows pipelining (sending multiple requests without waiting for responses), but IIS and proxies handle pipeline boundaries inconsistently.

| Subtype | Mechanism | Exploitation Context |
|---------|-----------|---------------------|
| **Pipeline Injection** | Embedding complete HTTP request in body of POST, exploiting parser that processes pipeline before fully consuming body | IIS 6/7 with keep-alive |
| **Partial Request Smuggling** | Sending incomplete request followed by pipeline, causing desync | Proxy buffering mismatch |

**Cross-reference**: Often combined with WAF bypass (§3) by using pipelining to evade request inspection.

---

## §2. URL/Path Component Mutations

IIS URL/path handling involves multiple transformation stages: HTTP parser → URL decoding → path normalization → NTFS filesystem lookup → authorization check. Discrepancies between these stages enable powerful bypass techniques.

### §2-1. NTFS Alternate Data Stream (ADS) Exploitation

NTFS supports alternate data streams (metadata attached to files), accessed via `filename:stream:type` syntax. IIS historically parsed these inconsistently.

| Subtype | Mechanism | Affected Versions |
|---------|-----------|------------------|
| **::$DATA Extension Bypass** | Accessing `file.asp::$DATA` causes IIS to serve source code instead of executing ASP. IIS parses extension as `asp::$DATA` (not `.asp`), bypassing script handler mapping. | IIS 4/5 (classic vulnerability, 2000s) |
| **:$I30:$INDEX_ALLOCATION Auth Bypass** | Accessing `/protected:$I30:$INDEX_ALLOCATION/file.asp` causes IIS to check authorization on parent directory but serve file from protected directory. | IIS 5.1/6.0 |
| **Directory Traversal via ADS** | Using `/../../target:stream` to traverse directories while evading path validation | IIS 6.0 |

**Example (Auth Bypass)**:
```http
GET /admin:$I30:$INDEX_ALLOCATION/config.aspx HTTP/1.1
```
IIS authorization layer checks `/admin` permissions, but filesystem resolves to actual file in `/admin/` using NTFS stream syntax.

**Discovery**: First variant discovered by Brett Moore (2000), `:$I30` variant by researchers including Soroush Dalili (2010).

### §2-2. Tilde (~) Short Name Disclosure (8.3 Enumeration)

Windows creates 8.3 "short names" for files/folders with long names. IIS exposes these via tilde notation, enabling directory enumeration even when directory browsing is disabled.

| Subtype | Mechanism | HTTP Method |
|---------|-----------|-------------|
| **GET-based Enumeration** | `GET /LONGFI~1.ASP` returns 200 if short name exists, 404 otherwise. Allows brute-forcing first 6 characters + extension. | `GET` |
| **OPTIONS-based Enumeration** | Newer IIS versions (8+) patched GET method but remained vulnerable via `OPTIONS`. Discovered 2014. | `OPTIONS` |
| **Wildcard Expansion** | Using `*` in short name queries: `/LONGF*.ASP` | Both methods |

**Exploitation Process**:
1. Send `OPTIONS /ABCDEF~1.ASP` — 404 response
2. Send `OPTIONS /SECRET~1.ASP` — 200 response → first 6 chars confirmed
3. Iterate through extensions to find full short name
4. Use dictionary/fuzzing to recover full filename

**Impact**: Reveals hidden admin panels, backup files (`.bak~1`), config files.

**Tools**: `IIS-ShortName-Scanner` (GitHub: irsdl/IIS-ShortName-Scanner), Burp extension by PortSwigger.

**Discovery**: Original GET variant by Soroush Dalili and Ali Abbasnejad (2010, disclosed 2012); OPTIONS variant by Dalili (2014).

### §2-3. Semicolon Path Truncation

IIS interprets semicolons (`;`) in URLs as path separators or parameter delimiters, but NTFS and ASP.NET may interpret them differently.

| Subtype | Mechanism | Affected Versions |
|---------|-----------|------------------|
| **Extension Bypass via Semicolon** | Upload `malicious.asp;.jpg`. Web application validates extension as `.jpg` (allowed), but IIS executes as `.asp` (interprets `;` as delimiter). | IIS 6/7 (2009 vulnerability) |
| **Path Truncation** | `/admin/protected.aspx;.css` — WAF/filter sees `.css` (static file), IIS executes `.aspx`. | IIS 6/7/8 |
| **Authentication Bypass** | `/secure;/public.aspx` — authorization checks `secure;`, filesystem resolves to `secure`. | IIS 7.5 variants |

**Example (2009 Discovery)**:
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=---

-----
Content-Disposition: form-data; name="file"; filename="shell.asp;.jpg"

<%eval request("cmd")%>
-----
```
Application allows `.jpg` upload, but accessing `/uploads/shell.asp;.jpg` executes ASP code.

**Discovery**: Soroush Dalili (2009), widely publicized 2009-2010.

### §2-4. Cookieless Session Pattern Injection

ASP.NET's cookieless session feature embeds session IDs in URLs via `/(S(session_id))/` pattern. IIS and ASP.NET parse these patterns differently, enabling authentication and application pool bypass.

| Subtype | Mechanism | CVE Reference |
|---------|-----------|---------------|
| **PathInfo Auth Bypass** | Insert cookieless pattern after `.aspx` extension: `/protected/admin.aspx/(S(X))/`. IIS authorization checks `/protected/admin.aspx` (protected), but ASP.NET runtime treats `/(S(X))/` as PathInfo and executes file. | CVE-2023-36899 (2023) |
| **Dual Cookieless Pattern** | Use pattern twice: `/app/(S(X))/protected/(S(Y))/file.aspx`. Exploits parser confusion when multiple patterns present. | CVE-2023-36899 |
| **Application Pool Confusion** | `/parentApp/(S(X))/childApp/file.aspx` — causes `childApp` to execute using `parentApp`'s application pool, enabling privilege escalation. | CVE-2023-36560 (2023) |

**Example (Auth Bypass)**:
```http
GET /admin/config.aspx/(S(abc123))/ HTTP/1.1
```
URL filter blocks `/admin/config.aspx`, but ASP.NET processes request.

**Impact**:
- Bypass URL-based authorization rules
- Access restricted directories
- Escalate privileges across application pools

**Discovery**: Soroush Dalili (2023), dubbed "Cookieless DuoDrop".

### §2-5. WebDAV URL Normalization Bypass

When WebDAV module is enabled, IIS performs additional URL normalization that can create authorization mismatches.

| Subtype | Mechanism | Affected Versions |
|---------|-----------|------------------|
| **Trailing Slash Normalization** | WebDAV normalizes `/admin/` to `/admin`, but authorization checks path with slash. Accessing without slash bypasses ACL. | IIS 6.0 with WebDAV |
| **Unicode Normalization Bypass** | WebDAV applies Unicode normalization (NFKC/NFKD) differently than authorization layer. `%u2215` (division slash) normalizes to `/`. | IIS 6/7 |
| **HTTP Method Override** | Using WebDAV methods (`PROPFIND`, `OPTIONS`) bypasses authorization rules configured only for GET/POST. | All IIS with WebDAV |

**Example (2009 MS09-020)**:
```http
GET /admin HTTP/1.1
Translate: f
```
WebDAV `Translate` header causes URL rewriting, bypassing authentication configured on `/admin/` (with trailing slash).

**CVE**: MS09-020, MS10-065.

---

## §3. Header Encoding Mutations

ASP.NET and IIS support multiple character encodings and custom headers, creating opportunities for WAF bypass and smuggling.

### §3-1. Charset Parameter Abuse in Content-Type

ASP.NET inspects multiple headers for charset information. An attacker can use lesser-known headers to specify encodings that bypass WAF inspection.

| Subtype | Mechanism | Affected Component |
|---------|-----------|-------------------|
| **Custom Charset Header** | ASP.NET respects proprietary `X-Content-Type-Charset` header. WAF inspects `Content-Type` only, missing payload encoded in charset specified by custom header. | ASP.NET 2.0-4.x |
| **Content-Type Override** | Sending both `Content-Type: text/plain` (for WAF) and `Content-Type: application/x-www-form-urlencoded; charset=UTF-7` (second instance parsed by ASP.NET). | IIS 7+ with dual header tolerance |
| **UTF-7 Encoding** | Encoding malicious payload in UTF-7, which WAF doesn't decode but ASP.NET does: `+ADw-script+AD4-`. | ASP.NET with UTF-7 support |

**Example**:
```http
POST /api/comment HTTP/1.1
Content-Type: text/plain
X-Content-Type-Charset: UTF-7

+ADw-script+AD4-alert(document.domain)+ADw-/script+AD4-
```
WAF sees `text/plain`, ASP.NET decodes UTF-7 to `<script>alert(document.domain)</script>`.

**Discovery**: Soroush Dalili (2018), presented at OWASP AppSec EU 2018.

### §3-2. Request Encoding Header Injection

IIS and ASP.NET support various encoding-related headers that can be abused to smuggle requests.

| Subtype | Mechanism |
|---------|-----------|
| **Accept-Charset Manipulation** | Specifying exotic charsets to trigger decoding errors that bypass validation |
| **Content-Encoding Abuse** | Using `Content-Encoding: gzip` with malformed compression to evade inspection |

### §3-3. Custom Header Injection for HTTP Pipelining

Injecting custom headers containing full HTTP requests, exploiting parsers that process headers before body validation.

| Subtype | Mechanism |
|---------|-----------|
| **Foo Header Injection** | `Foo: bar\r\n\rTransfer-Encoding: chunked` — the `\r\n\r` sequence tricks parser into treating remainder as new request body. |

**Example (from BurpSuiteHTTPSmuggler)**:
```http
POST / HTTP/1.1
Host: target.com
Foo: bar
Transfer-Encoding: chunked

0


GET /admin HTTP/1.1
Host: target.com
```

**Tool**: BurpSuiteHTTPSmuggler (NCC Group, developed by Soroush Dalili).

---

## §4. Session/State Management Mutations

ASP.NET's session management involves IIS metabase, application pools, and CLR AppDomains. Manipulating session identifiers can confuse routing logic.

### §4-1. Cookieless Session Hijacking

Beyond authentication bypass (§2-4), cookieless sessions enable session fixation and hijacking.

| Attack Type | Mechanism |
|------------|-----------|
| **URL-based Session Fixation** | Attacker sends victim link with embedded session ID: `/app/(S(attacker_session))/`. Victim authenticates using attacker's session. |
| **Session ID Leakage** | Session IDs in URL leak via Referer header, proxy logs, browser history. |

**Mitigation**: Disable cookieless sessions (`<sessionState cookieless="UseCookies" />`).

### §4-2. Application Pool Confusion

Exploiting cookieless pattern to force execution in parent application pool (§2-4 CVE-2023-36560).

**Privilege Escalation Scenario**:
- `/parentApp/` runs as SYSTEM (high privilege)
- `/parentApp/childApp/` runs as IIS_USRS (low privilege)
- Accessing `/parentApp/(S(X))/childApp/file.aspx` executes `file.aspx` in SYSTEM context

**Impact**: Sandbox escape, privilege escalation, cross-app attacks.

---

## §5. Object Serialization Mutations

.NET applications use various serializers (BinaryFormatter, NetDataContractSerializer, Json.NET, LosFormatter). Malicious serialized objects can invoke "gadget chains" leading to RCE.

### §5-1. .NET Formatter Gadget Chains

| Formatter | Common Gadget | Impact |
|-----------|---------------|--------|
| **BinaryFormatter** | `ObjectDataProvider` → `Process.Start()` | RCE via arbitrary process execution |
| **NetDataContractSerializer** | `SoapFormatter` gadget chains | RCE via type confusion |
| **Json.NET (Newtonsoft)** | `TypeNameHandling.All` → gadget invocation | RCE via polymorphic deserialization |
| **LosFormatter (ViewState)** | ASP.NET ViewState deserialization → gadget chain | RCE in web apps using ViewState |

**Tool**: `ysoserial.net` — generates deserialization payloads for .NET formatters.

**Key Contributors**: pwntester (original), Soroush Dalili (maintainer, added gadgets: DataSetOldBehaviourFromFile, GenericPrincipal, `--bridgedgadgetchains` feature).

### §5-2. Type Confusion via Polymorphic Deserialization

When deserializer trusts client-supplied type metadata, attacker can specify malicious types.

| Attack Pattern | Mechanism |
|---------------|-----------|
| **Type Substitution** | Replacing expected type with malicious type implementing same interface but with dangerous logic |
| **Gadget Bridging** | Chaining multiple gadgets across assemblies to reach dangerous sink (file I/O, process execution) |

**CVE Examples**: CVE-2018-8284, CVE-2018-8421 (SharePoint deserialization, discovered by Dalili).

---

## Attack Scenario Mapping (Axis 3)

This table maps mutation categories to real-world attack scenarios.

| Scenario | Architecture | Primary Mutation Categories | Impact |
|----------|-------------|----------------------------|--------|
| **HTTP Request Smuggling** | CDN/Proxy + IIS | §1 (all subtypes) | Cache poisoning, session hijacking, credential theft |
| **Authentication Bypass** | IIS + URL-based AuthZ | §2-1, §2-4, §2-5 | Unauthorized access to admin panels, config files |
| **WAF Bypass** | WAF + IIS + ASP.NET | §1-5, §2-3, §3 (all) | Payload delivery, XSS, SQLi, command injection |
| **Information Disclosure** | Public IIS server | §2-1 (::$DATA), §2-2 (tilde) | Source code exposure, directory enumeration, config leakage |
| **Privilege Escalation** | Multi-tenant IIS | §2-4 (app pool confusion), §4-2 | Cross-application compromise, sandbox escape |
| **Remote Code Execution** | ASP.NET application | §5 (deserialization), §2-3 (file upload) | Full system compromise |
| **Session Hijacking** | ASP.NET with cookieless | §4-1 | Account takeover, session fixation |

---

## CVE / Bounty Mapping (2009–2025)

| Mutation Combination | CVE / Case | Impact / Bounty | Year |
|---------------------|-----------|----------------|------|
| §2-3 (Semicolon Extension Bypass) | No CVE (public disclosure) | File upload → RCE, highly critical | 2009 |
| §2-1 (:$I30 Auth Bypass) | MS10-065 | Authentication bypass, IIS 5.1/6.0 | 2010 |
| §2-2 (Tilde Enumeration GET) | Public disclosure (Dalili & Abbasnejad) | Information disclosure | 2012 |
| §2-2 (Tilde Enumeration OPTIONS) | Public disclosure (Dalili) | Bypass of GET-based fix | 2014 |
| §5-2 (SharePoint Deserialization) | CVE-2018-8284, CVE-2018-8421 | RCE in SharePoint, critical | 2018 |
| §3-1 (Charset WAF Bypass) | Research presentation (OWASP AppSec EU) | WAF bypass methodology | 2018 |
| §2-4 + §4-2 (Cookieless DuoDrop) | CVE-2023-36899, CVE-2023-36560 | Auth bypass + privilege escalation | 2023 |
| §1-3 (Chunk Extension Parsing) | CVE-2025-55315 (.NET) | HTTP smuggling in ASP.NET Core | 2025 |
| §1-4 (OLF + OPTIONS) | CVE-2025-32094 (Akamai + IIS) | HTTP smuggling via obsolete line folding | 2025 |
| §1-1 (TE.0 Desync) | Public research (Google Cloud) | Smuggling in GCP + IIS | 2024 |
| §2-1 (::$DATA) | MS00-019 | Source code disclosure | 2000 |

**Note**: Soroush Dalili contributed to $10k+ bug bounty (Tesla, Microsoft SQL Reporting Services, CVE-2020-0618).

---

## Detection & Exploitation Tools

### Offensive Tools

| Tool | Target Scope | Core Technique | Source |
|------|-------------|---------------|--------|
| **BurpSuiteHTTPSmuggler** | HTTP smuggling + WAF bypass | Automated CL.TE/TE.CL/header obfuscation testing | [GitHub: nccgroup/BurpSuiteHTTPSmuggler](https://github.com/nccgroup/BurpSuiteHTTPSmuggler) |
| **IIS-ShortName-Scanner** | Tilde enumeration (§2-2) | Brute-force 8.3 short names via GET/OPTIONS | [GitHub: irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner) |
| **ysoserial.net** | .NET deserialization (§5) | Gadget chain payload generation for multiple formatters | [GitHub: pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net) |
| **Smuggler (Python)** | HTTP smuggling | CLI-based CL.TE/TE.CL scanner | defparam/smuggler |
| **http2smugl** | HTTP/2 smuggling | H2 request smuggling detection | Wallarm Labs |

### Defensive Tools

| Tool | Detection Capability | Mechanism |
|------|---------------------|-----------|
| **Qualys WAS (QID 150300)** | HTTP smuggling | CL.TE differential testing |
| **ModSecurity + OWASP CRS** | Generic anomaly detection | Header validation, encoding detection |
| **F5 iRules** | Smuggling prevention | Strict HTTP parsing, single CL/TE enforcement |

### Research Tools

| Tool | Purpose |
|------|---------|
| **HTTP Garden** | Differential HTTP parser testing across implementations |
| **Turbo Intruder (Burp)** | High-speed smuggling attack testing with timing analysis |

---

## Summary: Core Principles

### Root Cause: Layered Parsing with Inconsistent Semantics

Microsoft's web stack inherits decades of backward compatibility, resulting in multiple parsing layers with divergent interpretations of HTTP, URLs, and encodings. The fundamental vulnerability is **semantic ambiguity**: the HTTP and URI RFCs allow sufficient flexibility (or are sufficiently vague) that two RFC-compliant implementations can disagree on how to parse the same input.

Key design decisions that enable this vulnerability class:

1. **Lenient Parsing Philosophy**: IIS historically favored permissive parsing to ensure compatibility with legacy clients, accepting malformed headers, obsolete syntax (line folding), and non-standard encodings. This leniency creates gaps between strict security components (WAFs, authorization filters) and permissive execution components (ASP.NET runtime, filesystem).

2. **Multi-Stage URL Processing**: URLs traverse multiple transformation stages (HTTP parsing → URL decoding → normalization → NTFS resolution), each with different rules. NTFS features like alternate data streams and 8.3 short names were designed for compatibility, not security, creating powerful bypass primitives when exposed via HTTP.

3. **Implicit Trust Between Components**: IIS assumes that if a request passes the HTTP parser, it's structurally valid; authorization layers assume that if a path passes validation, it's safe. This implicit trust chain breaks when an attacker can craft input that satisfies one component's validation but triggers different behavior in another.

4. **State Management Complexity**: ASP.NET's cookieless session feature required embedding state into URLs, but IIS (stateless HTTP server) and ASP.NET (stateful application framework) handle these patterns differently, creating routing and authorization mismatches.

### Why Incremental Patches Fail

Microsoft has patched many specific instances (MS09-020, MS10-065, CVE-2023-36899), but new variants continue to emerge (CVE-2025-55315, CVE-2025-32094) because:

- **Whack-a-Mole Problem**: Fixing one parsing discrepancy (e.g., blocking `:$I30`) doesn't address the underlying semantic ambiguity. Attackers find alternative encodings, different NTFS streams, or new header obfuscation techniques.

- **Backward Compatibility Constraints**: Microsoft cannot enforce strict RFC compliance without breaking legacy applications. Disabling alternate data streams, 8.3 names, or cookieless sessions would disrupt existing deployments.

- **Emergent Complexity**: HTTP/2, HTTP/3, and new features (chunked extensions, Unicode normalization) introduce new parsing surfaces. Each addition creates new potential for discrepancies.

### Structural Solution

Eliminating this vulnerability class requires architectural changes:

1. **Unified Parsing Layer**: Implement a single, canonical HTTP/URL parser shared by IIS, ASP.NET, authorization modules, and WAFs. All components must operate on the same parsed representation (not re-parsing raw input).

2. **Strict Mode by Default**: Reject ambiguous inputs at the earliest layer. If a request contains both CL and TE, return 400 Bad Request. If a URL contains NTFS stream notation, reject unless explicitly required.

3. **Least Privilege Encoding**: Disable legacy features (8.3 names, alternate data streams, cookieless sessions, obsolete line folding) unless explicitly enabled per-application with security warnings.

4. **Differential Testing in CI/CD**: Integrate tools like HTTP Garden and custom differential fuzzers into Microsoft's build pipeline to detect parsing discrepancies before release.

5. **Protocol-Level Mitigation**: Adopt HTTP/2 and HTTP/3 universally, as they enforce stricter framing (binary framing eliminates CL/TE smuggling). However, HTTP/2 introduces its own smuggling risks (demonstrated by Kettle 2021), requiring careful implementation.

**Practical Mitigations (Short-Term)**:
- Disable WebDAV if not needed
- Disable 8.3 short name generation: `fsutil behavior set disable8dot3 1`
- Use cookie-based sessions (`cookieless="UseCookies"`)
- Deploy WAF with strict HTTP validation (e.g., reject dual CL/TE)
- Use Content Security Policy (CSP) to limit impact of XSS via encoding bypass
- Monitor for anomalous HTTP methods (`OPTIONS`, `PROPFIND`) in logs

---

## Research Attribution & Sources

This taxonomy synthesizes findings from multiple researchers and sources. Key contributors to the vulnerability classes documented:

**Primary Research**:
- Soroush Dalili (NCC Group / SecProject): IIS semicolon (2009), tilde enumeration (2010–2014), cookieless DuoDrop (2023), BurpSuiteHTTPSmuggler tool, ysoserial.net maintainer
- Ali Abbasnejad: Co-discoverer of tilde enumeration (2010)
- James Kettle (PortSwigger): HTTP desync attacks framework (2019), HTTP/2 smuggling (2021)
- Brett Moore: Early NTFS stream vulnerabilities (2000s)
- pwntester: Original ysoserial.net creator

**Conference Presentations**:
- [WAF Bypass Techniques Using HTTP Standard and Web Servers' Behaviour](https://archive.org/details/youtube-tSf_IXfuzXk) (OWASP AppSec EU 2018) - Soroush Dalili
- [HTTP Desync Attacks: Smashing into the Cell Next Door](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) (Black Hat USA 2019) - James Kettle
- [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2) (Black Hat USA 2021) - James Kettle

**Blog Posts & Advisories**:
- [Microsoft IIS Semi-Colon Vulnerability](https://soroush.me/blog/2009/12/microsoft-iis-semi-colon-vulnerability/) - Soroush Dalili (2009)
- [Microsoft IIS tilde character vulnerability](https://soroush.me/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf) - Dalili & Abbasnejad (2012)
- [Cookieless DuoDrop: IIS Auth Bypass & App Pool Privesc](https://soroush.me/blog/2023/08/cookieless-duodrop-iis-auth-bypass-app-pool-privesc-in-asp-net-framework-cve-2023-36899/) - Soroush Dalili (2023)
- [Understanding CVE-2025-55315: .NET Request Smuggling](https://andrewlock.net/understanding-the-worst-dotnet-vulnerability-request-smuggling-and-cve-2025-55315/) - Andrew Lock (2025)
- [CVE-2025-32094: HTTP Request Smuggling Via OPTIONS + OLF](https://www.akamai.com/blog/security/cve-2025-32094-http-request-smuggling) - Akamai (2025)

**Tools & GitHub**:
- [BurpSuiteHTTPSmuggler](https://github.com/nccgroup/BurpSuiteHTTPSmuggler)
- [IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
- [ysoserial.net](https://github.com/pwntester/ysoserial.net)

**Academic Papers**:
- Linhart et al., "HTTP Request Smuggling" (2005) - foundational research
- Arul et al., "Attacking Websites Using HTTP Request Smuggling: Empirical Testing" (IEEE 2021)

**CVE Databases**:
- [NIST NVD](https://nvd.nist.gov/)
- [Microsoft Security Response Center](https://msrc.microsoft.com/)
- [Wordfence Intelligence (Soroush Dalili)](https://www.wordfence.com/threat-intel/vulnerabilities/researchers/soroush-dalili)

---

*This document was created for defensive security research, penetration testing, and vulnerability understanding purposes. All techniques should only be used in authorized security testing contexts.*

**Document Version**: 1.0
**Last Updated**: February 2025
**Scope**: IIS 4.0–10.0, ASP.NET Framework 2.0–4.8, ASP.NET Core 1.0–9.0
