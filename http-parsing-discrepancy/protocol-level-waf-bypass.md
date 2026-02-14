# Protocol-Level WAF Bypass — Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy covers **protocol-level WAF bypass techniques** — mutations that exploit how HTTP requests are structured, parsed, framed, routed, and delivered at the transport and protocol layer. These bypasses are **payload-agnostic**: they work regardless of what attack payload (SQLi, XSS, RCE, etc.) is being delivered. The WAF is evaded not because it fails to recognize the malicious content, but because protocol-level discrepancies cause the WAF to see a different request than the backend does, or cause the request to bypass the WAF entirely.

> **Companion document:** Payload-level bypass techniques (encoding, syntax obfuscation, grammar evasion, ML evasion) are covered in the [Payload-Level WAF Bypass Taxonomy](../waf-bypass/payload-level-waf-bypass.md).

### Organizational Axes

**Axis 1 — Protocol Component (Primary Structure):** *What protocol-layer element is being manipulated?* This axis defines the top-level sections (§1–§9). Categories range from HTTP message framing (request smuggling) through header/method manipulation, content-type parsing, URL normalization, and parameter handling, to protocol upgrades and architectural network-level bypasses.

**Axis 2 — Discrepancy Type (Cross-Cutting):** *What kind of mismatch between the WAF and the backend does the manipulation exploit?*

| Discrepancy Type | Mechanism | Typical Bypass Categories |
|---|---|---|
| **Parser Differential** | WAF and backend parse the same bytes differently (boundary, charset, JSON, XML, multipart) | §1, §4 |
| **Normalization Mismatch** | WAF and backend apply normalization in different order or with different algorithms | §5 |
| **Structural Blind Spot** | WAF does not inspect certain request locations (headers, cookies, WebSocket frames, multipart parts) | §2, §6 |
| **Framing Disagreement** | WAF and backend disagree on where one request ends and the next begins | §1 |
| **Architectural Bypass** | Request reaches the backend without passing through the WAF at all | §8, §9 |
| **Resource Exhaustion** | WAF's processing capacity is overwhelmed, causing fail-open | §7 |

### Fundamental Insight

Protocol-level bypasses are structurally more powerful than payload-level bypasses because they are **transport-agnostic** — a single protocol-level bypass can deliver *any* attack payload through the WAF. A request smuggling desync, an H2C upgrade, or an origin IP exposure provides a universal channel that bypasses all WAF rules simultaneously, regardless of their sophistication. This is why the most critical WAF bypass CVEs (CVE-2025-55315 CVSS 9.9, BreakingWAF affecting 40%+ of CDN-protected sites) are protocol-level, not payload-level.

---

## §1. HTTP Request Smuggling & Framing Attacks

Request smuggling exploits disagreements between front-end (WAF/proxy/load balancer) and backend servers about where one HTTP request ends and the next one begins. This creates a "smuggled" request that the WAF never inspects as a standalone request, allowing arbitrary payloads to reach the backend uninspected.

### §1-1. Classic Desync (CL vs. TE)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CL.TE Desync** | WAF/front-end uses `Content-Length`; backend uses `Transfer-Encoding: chunked`. The front-end forwards what it thinks is one request; the backend interprets the trailing bytes as the start of a second (smuggled) request. | Front-end prioritizes CL; backend prioritizes TE |
| **TE.CL Desync** | Inverse: front-end uses `Transfer-Encoding`; backend uses `Content-Length`. The smuggled request is embedded after the chunked terminator. | Front-end prioritizes TE; backend prioritizes CL |

### §1-2. Obfuscated Transfer-Encoding (TE.TE)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Whitespace in TE Header** | `Transfer-Encoding : chunked` or `Transfer-Encoding\t: chunked` — subtle whitespace causes one side to reject the TE header and fall back to CL. | Different TE header parsing strictness |
| **TE Value Obfuscation** | `Transfer-Encoding: xchunked`, `Transfer-Encoding: chunked1`, or `Transfer-Encoding:\nchunked` — mutated TE values that one side accepts and the other rejects. | One parser is lenient with TE values |
| **Multiple TE Headers** | Send multiple `Transfer-Encoding` headers with different or conflicting values. One side uses the first, the other uses the last. | WAF and backend disagree on duplicate TE resolution |

### §1-3. Bodyless Desync (0.CL)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **0.CL Desync** | Front-end treats the request as having no body (no CL, no TE); backend reads `Content-Length` bytes. Creates a deadlock broken by early-response gadgets — endpoints that respond before consuming the full body (static files, redirects, `Expect: 100-continue`). | Backend reads CL on requests the front-end considers bodyless |
| **GET with Body** | Send a GET request with a `Content-Length` header and body. The WAF may ignore the body for GET requests; the backend processes it. | WAF doesn't inspect bodies of GET requests |

### §1-4. Chunk-Level Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Chunk Extension Abuse** | Append extensions to chunk headers (`a;extension=value\r\n`). Inconsistent handling of extensions between WAF and backend causes framing disagreement. CVE-2025-55315 (ASP.NET Core, CVSS 9.9) demonstrated this with high severity. | WAF and backend handle chunk extensions differently |
| **Chunk Size Obfuscation** | Use leading zeros (`00000a`), whitespace around chunk size, or mixed-case hex (`0A` vs `0a`) in chunk size fields. | WAF's chunked parser is strict; backend is lenient (or vice versa) |
| **Chunked Body with Trailer Headers** | Inject malicious headers in the trailer section after the final `0\r\n` chunk. Some backends merge trailer headers with request headers; the WAF may not inspect trailers. | Backend processes chunked trailer headers |

### §1-5. HTTP/2 Request Smuggling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **H2.CL Smuggling** | WAF/front-end speaks HTTP/2; backend receives downgraded HTTP/1.1. During translation, the front-end generates `Content-Length` from HTTP/2 DATA frames inconsistently, enabling smuggling. | Front-end downgrades HTTP/2 to HTTP/1.1 |
| **H2.TE Smuggling** | HTTP/2 forbids `Transfer-Encoding`, but some front-ends pass it through during downgrade. The backend then processes chunked encoding from a request that HTTP/2 should have prevented. | Front-end does not strip TE during downgrade |
| **Header Injection via HTTP/2 Binary Framing** | HTTP/2 allows header values that would be invalid in HTTP/1.1 (containing `\r\n`). If the front-end doesn't sanitize during downgrade, headers can be injected into the HTTP/1.1 request. | Front-end does not sanitize headers during protocol downgrade |

---

## §2. Header Manipulation & Injection

Exploiting how WAFs parse, validate, and act on HTTP headers — including header name resolution, duplicate handling, and blind spots in which headers are inspected.

### §2-1. Injection via Uninspected Headers

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Non-Standard Header Injection** | Place payloads in headers the WAF doesn't inspect: `X-Forwarded-For`, `X-Originating-IP`, `Referer`, `User-Agent`, custom `X-` headers. Backend uses these headers in SQL queries, templates, or log output. | Backend trusts and processes non-standard headers |
| **Trusted Proxy Headers** | Inject `X-Forwarded-Host`, `X-Real-IP`, `X-Forwarded-Proto`, or `Forwarded` headers. Backend uses these for routing, URL generation, or access control decisions. | Backend trusts proxy headers without validation |
| **Framework-Specific Headers** | Use framework-specific headers like `x-middleware-subrequest` (Next.js, CVE-2025-29927) to bypass middleware-level authorization. | Backend framework has internal header contracts |

### §2-2. Header Parsing Discrepancies

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Header Name Obfuscation** | Add whitespace, tabs, or underscore/hyphen confusion in header names: `Transfer-Encoding\t: chunked`, `Content_Type` vs `Content-Type`. | WAF and backend differ in header name parsing |
| **Header Value Line Folding** | Use HTTP/1.1 obsolete line folding (`\r\n\t` or `\r\n `) to split a header value across lines. Modern parsers may not support this; legacy backends might. | Backend supports obs-fold; WAF does not |
| **Duplicate Headers** | Send the same header multiple times with different values. RFC 7230 behavior varies: some implementations use the first, others the last, others concatenate. | WAF and backend disagree on duplicate header resolution |
| **Header Separator Confusion** | Use `\r\n` vs `\n` as header line terminators. Some parsers accept bare `\n`; strict parsers require `\r\n`. Can cause header merging/splitting discrepancies. | Different line terminator handling |

### §2-3. Header Size & Count Overflow

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Large Header Values** | Send extremely long header values that exceed the WAF's parsing buffer, causing truncation or skip of subsequent headers. | WAF has header value size limits |
| **Excessive Header Count** | Send a very large number of headers to exceed the WAF's header count limit, causing it to stop parsing before reaching the header containing the payload. | WAF has a maximum header count |
| **Header Order Manipulation** | Place critical headers (e.g., `Content-Type`, `Transfer-Encoding`) after a large number of decoy headers, beyond the WAF's parsing limit. | WAF inspects headers up to a count/size limit |

---

## §3. HTTP Method & Version Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Method Override Headers** | Use `X-HTTP-Method-Override: PUT` or `X-Method-Override: DELETE` with a POST request. The WAF applies POST rules; the backend processes it as PUT/DELETE. | Backend framework respects method override headers |
| **Uncommon HTTP Methods** | Use methods like `PATCH`, `OPTIONS`, `TRACE`, `PROPFIND`, `MOVE`, `COPY`. WAF rules may only cover GET/POST, allowing other methods to pass uninspected. | WAF rules are method-specific |
| **HTTP/0.9 Downgrade** | Send an HTTP/0.9 request (no headers, just `GET /path`). Some backends still support this; the WAF may not parse HTTP/0.9 requests. | Backend supports legacy HTTP/0.9 |
| **HTTP Version String Mutation** | Use `HTTP/1.0` instead of `HTTP/1.1`, or malformed version strings (`HTTP/1.2`, `HTTP/2.0`). WAF behavior may differ based on version parsing. | WAF and backend handle version strings differently |

---

## §4. Content-Type & Body Parsing Manipulation

Mutations that exploit how WAFs select and execute body parsers based on the Content-Type header. The WAF must replicate the exact parsing behavior of the backend framework — a structurally impossible task given the diversity of backend implementations.

### §4-1. Content-Type Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Type Switching** | Send a JSON body with `Content-Type: application/x-www-form-urlencoded` or vice versa. The WAF applies the wrong parser. | Backend auto-negotiates body format regardless of Content-Type |
| **Unknown Content-Type** | Use a rare or invented Content-Type (`application/x-custom`). The WAF skips body inspection; the backend's framework may still parse it as form data or JSON. | WAF falls through to no-parse on unknown types |
| **Dual Charset Declaration** | Use `Content-Type: application/json; charset=utf-8; charset=utf-7`. The WAF uses the first charset; the backend uses the last (or vice versa). | WAF and backend disagree on charset precedence |
| **Charset-Based Encoding Swap** | Declare `charset=ibm500`, `charset=shift_jis`, or `charset=ibm037` to encode the payload in a character set the WAF cannot decode. | Backend converts from declared charset to UTF-8 |
| **Parameter Injection in Content-Type** | Add extra parameters to the Content-Type header (`boundary=X; evil=payload`) that interfere with the WAF's header parser. | WAF's Content-Type parser is fragile |

### §4-2. Multipart/Form-Data Evasion

Multipart parsing is one of the richest protocol-level bypass surfaces. Research in 2025 (WAFFLED) identified 351 distinct multipart-based bypasses across major WAFs, as no multipart parser fully complies with the RFC.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Boundary Manipulation** | Alter the boundary delimiter — remove leading `\r\n`, use quoted boundaries, add whitespace or extra hyphens. The WAF fails to identify part boundaries; the backend's parser is more tolerant. | WAF implements strict boundary matching |
| **Missing Closing Boundary** | Omit the closing boundary (`--boundary--`). Many backends accept the truncated multipart body; the WAF may reject or misparse it. | Backend accepts incomplete multipart messages |
| **Duplicate Content-Disposition** | Include multiple `Content-Disposition` headers in a single part with conflicting `name` values. The WAF inspects one; the backend uses the other. | WAF and backend disagree on header precedence |
| **Part-Level Charset Override** | Set a `charset` parameter on individual part headers, causing the WAF to decode the part differently than the backend. | Backend respects part-level charset declarations |
| **Filename/Field Injection** | Place payloads in the `filename` parameter of Content-Disposition, or use unusual field names that the WAF does not inspect. | WAF only inspects the `name` parameter, not `filename` |
| **Multipart within Multipart** | Nest a multipart body inside a multipart part (RFC 2046 allows this). Most WAFs do not recurse into nested multipart structures. | Backend framework handles nested multipart |
| **Extra Headers in Parts** | Add custom headers within multipart parts. Some WAFs only parse standard headers (Content-Disposition, Content-Type) and ignore others where payloads can hide. | Backend processes or reflects custom part headers |

### §4-3. JSON Parser Discrepancies

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JSON with Comments** | Some JSON parsers (e.g., JSON5, JSONC) accept comments (`//`, `/* */`). Inject comments around keywords to break WAF pattern matching. | Backend uses a lenient JSON parser |
| **Nested JSON Structures** | Deeply nest objects/arrays to exceed WAF parsing depth limits: `{"a":{"b":{"c":{"d":"<payload>"}}}}`. | WAF has a recursion/depth limit on JSON parsing |
| **Duplicate JSON Keys** | Send `{"id": "safe", "id": "malicious"}`. WAF may inspect the first value; backend uses the last (per RFC 8259, behavior is implementation-defined). | WAF and backend disagree on duplicate key handling |
| **JSON Encoding Discrepancies** | WAF parses raw JSON bytes while backend resolves `\uXXXX` escapes, surrogate pairs, or multi-byte UTF-8 within JSON strings differently. | WAF does not fully resolve JSON string encoding |

### §4-4. XML Parser Discrepancies

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **XML Namespace Confusion** | Declare custom namespaces that alter element name resolution. The WAF matches on the prefixed name; the backend resolves the namespace to the canonical element. | WAF does not perform namespace resolution |
| **XML Parameter Entities** | Use parameter entities (`%entity;`) in external DTD references to inject content the WAF cannot resolve at parse time. | Backend processes external entities |
| **XML Encoding Declaration** | Specify an encoding in the XML declaration (`<?xml encoding="UTF-16"?>`) that the WAF doesn't handle, causing it to misparse the body. | WAF supports only UTF-8 XML parsing |
| **DOCTYPE Manipulation** | Declare internal DTD subsets with entity definitions that restructure the document content after entity resolution, invisible to the WAF. | WAF does not resolve DTD entity definitions |

---

## §5. URL & Path Manipulation

Mutations targeting the URL structure — path, query string, and hostname — to evade WAF rules that match on specific URL patterns. The bypass relies on the WAF and backend normalizing URLs differently.

### §5-1. Path Normalization Discrepancies

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Path Traversal Sequences** | Insert `../` or encoded variants (`%2e%2e%2f`, `..%5c`) to reach protected paths while evading path-based WAF rules. | WAF normalizes paths differently than the backend/OS |
| **Double Slash Collapse** | Use `//admin//secret` — some normalizers collapse double slashes; others preserve them. WAF matches on the raw path; backend normalizes. | Different slash-collapsing behavior |
| **Dot Segment Insertion** | Insert `/./` segments: `/admin/./secret`. The WAF may not normalize these; the backend resolves them. | WAF does not apply RFC 3986 path normalization |
| **Trailing Dot in Hostname** | Add a trailing dot to the hostname (`example.com.`). DNS treats this as equivalent; some WAF host-matching rules do not. | WAF host-based rules use exact string matching |
| **OS-Specific Path Semantics** | On Windows: use backslashes (`\`), 8.3 short names (`PROGRA~1`), ADS (`file.txt::$DATA`), case insensitivity. On certain file systems: use Unicode normalization of filenames. | Backend runs on an OS with alternative path semantics |
| **URL Path Parameter (Matrix)** | Use path parameters: `/admin;bypass=true/secret`. Some frameworks strip path parameters before routing; the WAF sees the full path including the parameter. | Backend framework strips path parameters |
| **Percent-Encoded Query Delimiter** | Encode `?` as `%3F` in the URL path. The WAF misidentifies where the query string begins, hiding payloads in the path component from path-specific rules (CVE-2024-1019). | WAF decodes percent-encoding before splitting path/query |

### §5-2. Query String Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Parameter Order Shuffling** | Reorder query parameters. Some WAF rules match on specific parameter positions or early-terminating regex. | WAF regex is position-dependent |
| **Parameter Name Pollution** | Add decoy parameters with similar names (`username`, `user%6eame`, `user%00name`) to confuse WAF parameter extraction. | WAF and backend resolve parameter names differently |
| **Fragment Identifier Abuse** | On server-side: fragments (`#`) are normally stripped by clients, but in certain proxy configurations or custom parsers, fragment content may be forwarded to the backend. | Non-standard proxy/parser forwards fragment |

---

## §6. Parameter & Input Channel Manipulation

Mutations that exploit which input channels the WAF inspects and how duplicate/distributed parameters are handled.

### §6-1. HTTP Parameter Pollution (HPP)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Duplicate Parameter — First vs. Last** | Send `id=1&id=2 UNION SELECT...`. If the WAF checks the first value and the backend uses the last (or vice versa), the malicious value evades inspection. | WAF and backend disagree on duplicate parameter precedence |
| **Parameter Splitting** | Split an attack payload across multiple parameters with the same name: `q=SEL&q=ECT`. If the backend concatenates them, the payload reconstructs; the WAF sees only fragments. | Backend concatenates same-name parameters |
| **Cross-Location Pollution** | Place part of the payload in the query string and part in the POST body. WAF may inspect only one location; the backend merges both sources. | Backend merges GET and POST parameters |
| **Array Parameter Abuse** | Use array notation (`id[]=1&id[]=malicious`) or JSON arrays in parameters. WAF may extract only scalar values; the backend processes the array. | Backend framework supports array parameters |

### §6-2. Alternate Input Channels

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cookie Injection** | Place payloads in cookie values. Some WAFs do not fully inspect cookie contents or have reduced rule sets for cookies. | Backend reflects or processes cookie values |
| **Header-Based Payload Delivery** | Inject payloads via `Referer`, `User-Agent`, `X-Forwarded-Host`, or custom headers. WAF rules typically focus on URL, query, and body parameters. | Backend uses header values in SQL, templates, or logs |
| **File Upload Content** | Embed payloads within uploaded file content (SVG with JavaScript, CSV with formulas, XML with XXE). WAFs may not deeply parse uploaded file contents. | Backend processes uploaded file content |
| **WebSocket Messages** | After an initial HTTP upgrade handshake, subsequent WebSocket frames may not pass through the WAF's HTTP inspection engine. | WAF does not inspect WebSocket frame payloads |

---

## §7. Processing Limit Exploitation

Mutations that overwhelm the WAF's processing capacity, causing it to fail-open (allow traffic through uninspected) or truncate inspection.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Oversized Body** | Send a request body exceeding the WAF's maximum inspection size. The WAF inspects only the first N bytes; the payload is placed beyond the cutoff. | WAF has a body inspection size limit |
| **Excessive Nesting / Recursion** | Deeply nest JSON objects, XML elements, or multipart structures to exceed the WAF's recursion limit, causing it to skip deep content inspection. | WAF has a depth limit on structured content |
| **High Request Rate** | Flood the WAF with benign requests to exhaust its processing capacity, causing it to fail-open and pass subsequent malicious requests uninspected. | WAF is configured to fail-open under load |
| **Slow/Fragmented Delivery** | Send the payload extremely slowly (Slowloris-style) or as many small TCP fragments. Some WAFs time out or reassemble incorrectly. | WAF has timeouts or incomplete TCP reassembly |
| **Chunked Transfer Abuse for Size** | Send an extremely large number of very small chunks, each requiring WAF processing. The overhead of parsing thousands of chunk headers degrades WAF performance. | WAF processes each chunk individually |

---

## §8. Protocol Version & Upgrade Exploitation

Mutations that exploit HTTP protocol version differences, connection upgrades, and binary framing to bypass WAF inspection that is only effective for standard HTTP/1.1 text-based parsing.

### §8-1. HTTP/2 Pseudo-Header Abuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Pseudo-Header Manipulation** | Manipulate `:method`, `:path`, `:authority` pseudo-headers in ways that the WAF's HTTP/2 parser does not validate but the backend accepts after downgrade. | WAF's HTTP/2 parsing is less strict than HTTP/1.1 parsing |
| **Duplicate Pseudo-Headers** | Send duplicate `:path` or `:method` pseudo-headers. HTTP/2 spec forbids this, but some implementations accept it and use the last value. | Backend accepts malformed HTTP/2 frames |
| **Invalid Characters in Pseudo-Headers** | Include characters in HTTP/2 headers that would cause injection when downgraded to HTTP/1.1 (e.g., spaces in `:path`). | Front-end does not validate pseudo-header contents |

### §8-2. H2C (HTTP/2 Cleartext) Smuggling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Connection Upgrade Bypass** | Send `Upgrade: h2c` with `Connection: Upgrade, HTTP2-Settings` to upgrade to cleartext HTTP/2. Once upgraded, the reverse proxy stops inspecting individual requests — routing, auth, and WAF rules are bypassed for all subsequent frames. | Reverse proxy forwards the Upgrade header to the backend |
| **Cloud WAF Global Bypass** | In cloud WAF environments, if the initial upgrade request passes, all subsequent HTTP/2 frames bypass the WAF entirely, providing a full global bypass. | Cloud WAF does not strip the Upgrade header |

### §8-3. WebSocket & Protocol Upgrade

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **WebSocket Tunnel** | After upgrading to WebSocket, send malicious payloads in WebSocket frames. Most WAFs do not inspect WebSocket traffic. | WAF only inspects HTTP traffic, not WebSocket frames |
| **Cross-Protocol Smuggling** | Use `Upgrade` or `CONNECT` to establish a tunnel through the WAF, then send arbitrary protocols (including raw HTTP to internal services) through the tunnel. | WAF allows protocol upgrade/tunneling |
| **CONNECT Method Tunneling** | Use HTTP CONNECT to establish a TCP tunnel through the proxy/WAF. Traffic within the tunnel is opaque to the WAF. | WAF/proxy allows CONNECT to arbitrary destinations |

---

## §9. Architectural & Network-Level Bypass

Bypasses that avoid the WAF entirely by reaching the origin server through alternative network paths, exploiting misconfigured architectures, or leveraging the deployment topology. These are the most powerful bypasses — they provide **complete WAF circumvention** for all request types.

### §9-1. Origin IP Exposure

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **DNS History / Certificate Transparency** | Discover the origin server's real IP address through historical DNS records, CT logs, or SSL certificate scans (Censys, Shodan). Send requests directly to the origin IP, bypassing the CDN/WAF entirely. | Origin server accepts connections from non-CDN IPs |
| **Subdomain/Service Enumeration** | Find subdomains or related services (mail, FTP, API) that resolve to the origin IP and are not fronted by the WAF. | Not all services are behind the WAF |
| **Information Disclosure** | The origin IP leaks through error pages, debug headers (`X-Backend-Server`), email headers (`Received`), or SSRF responses. | Application or infrastructure leaks origin information |
| **CDN/WAF IP Range Misconfiguration** | CDN/WAF providers share IP ranges. If the origin doesn't restrict incoming connections to the WAF's IP range, any attacker who discovers the origin IP can bypass the WAF. Impacts 40%+ of CDN/WAF-protected sites (BreakingWAF, 2025). | Origin server does not whitelist WAF provider IP ranges |

### §9-2. Alternate Endpoint & Routing Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **API Endpoint Disparity** | Access GraphQL (`/graphql`), REST API, or internal API endpoints that are not covered by WAF rules. GraphQL is particularly vulnerable because all queries go to a single URL, defeating URL-pattern-based rules. | WAF rules don't cover all API endpoints |
| **Backend Administrative Interfaces** | Access `/admin`, `/debug`, `/actuator`, `/server-status`, or framework-specific management endpoints that bypass or have reduced WAF rules. | Management endpoints have weaker WAF coverage |
| **Server-Side Request Forgery (SSRF)** | Trigger the application to make internal requests to itself or other backend services, bypassing the WAF which only sits on the external perimeter. | Application has SSRF vulnerabilities |
| **IPv6 vs. IPv4 Disparity** | If the WAF is configured only for IPv4, accessing the backend via its IPv6 address may bypass WAF inspection. | WAF is not configured for IPv6 traffic |

### §9-3. IP & Network-Level Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **IP Rotation / Residential Proxies** | Use large pools of rotating residential, mobile, or ISP-grade IP addresses to distribute malicious requests and evade IP reputation–based blocking. | WAF relies on IP reputation or rate limiting |
| **TOR / VPN / Cloud Function Egress** | Route requests through TOR, VPN services, or serverless function IP ranges (AWS Lambda, GCP Cloud Functions) that have clean reputations. | WAF uses IP-based blocklists |
| **Geographic IP Selection** | Use IP addresses from geographic regions that the WAF is configured to allow, bypassing geo-blocking rules. | WAF has geography-based allow/deny rules |

---

## §10. Attack Scenario Mapping

Protocol-level bypasses are transport-agnostic — once a bypass channel is established, any attack payload can be delivered. The table below maps specific protocol-level techniques to the attack scenarios they most commonly enable.

| Scenario | Protocol-Level Techniques |
|---|---|
| **Authentication Bypass** | §1 (request smuggling) + §8 (protocol upgrade) + §9-2 (admin endpoints) + §2-1 (framework headers) |
| **Cache Poisoning** | §1 (smuggling for desync) + §2-2 (header manipulation) + §5-1 (path confusion) |
| **Request Routing Hijack** | §1 (smuggling) + §2-1 (Host/Authority header injection) + §5-1 (path normalization) |
| **WAF Denial of Service** | §7 (processing limits) + §1-4 (chunk manipulation) + §9-3 (IP flooding) |
| **Full WAF Bypass (Any Payload)** | §8-2 (H2C smuggling) + §9-1 (origin IP) + §8-3 (WebSocket tunnel) |
| **Internal Service Access** | §9-2 (SSRF) + §8-3 (CONNECT tunneling) + §1 (smuggling to internal routes) |
| **SQL/XSS/RCE Delivery** | §4-2 (multipart evasion) + §6-1 (HPP) + §6-2 (alternate input channels) + §4-1 (content-type confusion) |
| **Path Traversal / LFI** | §5-1 (path normalization) + §6-1 (cross-location pollution) + §2-2 (header injection) |
| **API Abuse** | §9-2 (endpoint disparity) + §4-3 (JSON parser discrepancy) + §6-1 (HPP) |

---

## §11. CVE / Bounty Mapping (2024–2025)

| Technique | CVE / Case | Impact |
|---|---|---|
| §1-4 (Chunk Extension Abuse) | CVE-2025-55315 (ASP.NET Core) | CVSS 9.9. HTTP request smuggling via chunk extensions. Microsoft's highest-severity ASP.NET Core CVE |
| §9-1 (Origin IP Exposure) | BreakingWAF (Zafran, 2025) | Affects 40%+ of CDN/WAF-protected sites including JPMorganChase, Visa, Intel |
| §5-1 (Path Normalization) + §5-1 (Percent-Encoded Query Delimiter) | CVE-2024-1019 (ModSecurity 3.0.0–3.0.11) | CVSS 8.6. URL path payload hidden from WAF path rules via percent-encoded `?` |
| §2-1 (Framework Header) + §9-2 (Alternate Endpoint) | CVE-2025-29927 (Next.js middleware bypass) | Authorization middleware bypass via `x-middleware-subrequest` header |
| §4-2 (Multipart/Boundary) + §4-1 (Content-Type Confusion) | WAFFLED (ACSAC 2025) | 1,207 bypasses across AWS WAF, Azure, Cloud Armor, Cloudflare, ModSecurity |
| §8-2 (H2C Smuggling) | Azure WAF H2C Bypass (Assetnote) | Global WAF bypass via HTTP/2 cleartext upgrade |
| §2-2 (Header) + §6-1 (HPP) | WAFManis (Black Hat 2024) | 311 protocol-level evasion cases discovered across multiple WAFs |
| §5-1 (Path Confusion) | ModSecurity v2/v3 Path Confusion (SicuraNext, 2024) | Multiple path confusion bugs enabling rule bypass on both v2 and v3 branches |
| §9-1 (Origin IP) | Cloudflare Origin IP Bypass (HackerOne #1536299) | WAF bypass by sending requests directly to origin IP |

---

## §12. Detection & Testing Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **WAFFLED** (Fuzzer) | Multipart/Content-Type parsing discrepancies across AWS, Azure, Cloud Armor, Cloudflare, ModSecurity | Content-type-specific fuzzing: mutates boundaries, charsets, namespaces, multipart structure |
| **WAFManis** (Framework) | Protocol-level WAF evasion testing | Systematic mutation of HTTP protocol features (headers, methods, encoding) |
| **Burp Suite — Request Smuggler** | HTTP/1.1 and HTTP/2 request smuggling detection | CL.TE, TE.CL, H2.CL, H2.TE desync testing |
| **Burp Suite — Param Miner** | Hidden parameter and header discovery | Discovers backend-processed headers the WAF doesn't inspect |
| **h2cSmuggler** (Bishop Fox) | H2C upgrade bypass testing | Automates HTTP/2 cleartext upgrade attack through reverse proxies |
| **http2smugl** (Scanner) | HTTP/2 request smuggling detection | Tests load balancers for HTTP/2 smuggling vulnerabilities |
| **WhatWaf** (Scanner) | WAF fingerprinting and bypass | Detects WAF vendor/version, attempts known bypasses from plugin database |
| **WAFW00F** (Fingerprinter) | WAF identification | Fingerprints 100+ WAF products via response analysis |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **HTTP Normalizer** (WAFFLED project) | RFC-compliant request normalization | Proxy that validates/normalizes HTTP requests against RFC standards; blocked all WAFFLED bypasses |
| **ModSecurity CRS** (OWASP) | Generic WAF rule set | Regex-based rules with paranoia levels; protocol-level rules for smuggling, HPP |

---

## §13. Summary: Core Principles

### The Protocol-Level Advantage

Protocol-level WAF bypasses are structurally more powerful than payload-level bypasses for three reasons:

1. **Universality.** A single protocol-level bypass (H2C upgrade, origin IP exposure, request smuggling) delivers *any* attack payload through the WAF. Payload-level bypasses must be customized for each WAF rule and each attack type.

2. **Invisibility.** Smuggled requests, tunneled connections, and direct-to-origin traffic are often invisible to the WAF's logging and alerting — the WAF may not even know a bypass occurred. Payload-level bypasses still pass through the WAF; they just evade detection.

3. **Persistence.** Protocol-level bypasses often remain viable across WAF rule updates. A new SQLi rule doesn't fix a smuggling vulnerability. Origin IP exposure persists regardless of how many rules are added.

### The Parsing Asymmetry Problem

The fundamental challenge is that WAFs must **parse HTTP messages identically** to the backend — but they are **not the backend**. Every difference in how message boundaries are determined (§1), how headers are parsed (§2), how content types are interpreted (§4), how paths are normalized (§5), how parameters are extracted (§6), and how protocol upgrades are handled (§8) becomes a bypass vector. The 2025 WAFFLED research demonstrated this comprehensively: by fuzzing only protocol-level elements (boundaries, charsets, namespaces) while keeping payloads constant, researchers found 1,207 bypasses across five major WAF vendors.

### Structural Defenses

1. **Strict RFC-compliant request normalization** at the edge (HTTP Normalizer), rejecting malformed or ambiguous requests before they reach the WAF or backend.
2. **End-to-end HTTP/2** without downgrade, eliminating the HTTP/1.1 text-based ambiguities that enable request smuggling.
3. **Origin network isolation**: firewall rules ensuring the origin server only accepts traffic from WAF provider IP ranges.
4. **Elimination of early-response gadgets** that enable 0.CL desync attacks.
5. **Defense-in-depth**: application-layer security (parameterized queries, output encoding, input validation) as the primary defense, with the WAF as a supplementary probabilistic filter.

---

## References

- WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls (ACSAC 2025) — https://arxiv.org/html/2503.10846v1
- BreakingWAF: Widespread WAF Bypass via Origin IP Exposure (Zafran, 2025) — https://www.zafran.io/resources/breaking-waf
- CVE-2024-1019: ModSecurity Path Normalization Bypass — https://nvd.nist.gov/vuln/detail/CVE-2024-1019
- ModSecurity Path Confusion Bugs (SicuraNext, 2024) — https://blog.sicuranext.com/modsecurity-path-confusion-bugs-bypass/
- H2C Smuggling in the Wild (Assetnote / Bishop Fox) — https://www.assetnote.io/resources/research/h2c-smuggling-in-the-wild
- WAFManis: Protocol-Level WAF Evasion Testing (Black Hat USA 2024) — presented by Ryan Kane & Rushank Shetty
- HTTP Request Smuggling Using Chunk Extensions — CVE-2025-55315 (F5 DevCentral) — https://community.f5.com/kb/security-insights/http-request-smuggling-using-chunk-extensions-cve-2025-55315/344118
- Breaking Down Multipart Parsers: File Upload Validation Bypass (SicuraNext) — https://blog.sicuranext.com/breaking-down-multipart-parsers-validation-bypass/
- When WAFs Go Awry: Common Detection & Evasion Techniques (MDSec, 2024) — https://www.mdsec.co.uk/2024/10/when-wafs-go-awry-common-detection-evasion-techniques-for-web-application-firewalls/
- Awesome-WAF (0xInfection, GitHub) — https://github.com/0xInfection/Awesome-WAF
- 2026 WAF Security Test: Key Findings (Check Point) — https://blog.checkpoint.com/securing-the-cloud/waf-security-test-results-2026-why-prevention-first-matters-more-than-ever
- Miggo Research: More than Half of Public Vulnerabilities Bypass Leading WAFs (2025) — https://www.helpnetsecurity.com/2025/12/18/miggo-research-waf-vulnerability-bypass/

---

*This document was created for defensive security research and vulnerability understanding purposes.*
