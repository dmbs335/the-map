# Client-Side Web Security Mutation & Variation Taxonomy

**Version:** 2025.2
**Scope:** Browser-based attack vectors exploiting client-side parsing, state management, and cross-origin mechanisms
**Coverage:** Side-channel leaks, browser security model bypass, desync attacks, CSRF evolution, and parser differentials

---

## Classification Structure

This taxonomy organizes client-side web attack vectors across three axes:

**Axis 1 (Mutation Target)** — The structural component being exploited: Browser state & storage mechanisms, cross-origin communication channels, frame & window hierarchy, HTTP layer, timing & side channels, and parser/normalization boundaries. This axis structures the main body of the document (§1-§7).

**Axis 2 (Discrepancy Type)** — The nature of the exploit mechanism created by the mutation. These cross-cutting types apply across all categories:

| Discrepancy Type | Definition | Common Manifestation |
|-----------------|------------|---------------------|
| **Parsing Differential** | Different interpretation by browser components | WAF vs browser, header parsing, normalization gaps |
| **Validation Bypass** | Circumventing input/output/origin checks | SameSite bypass, origin validation, sandbox escape |
| **State Confusion** | Exploiting stateful browser behavior | Connection desync, cache poisoning, history manipulation |
| **Information Disclosure** | Unauthorized data inference via side channels | Timing leaks, cache probing, frame counting, resource timing |
| **Origin/Sandbox Bypass** | Circumventing Same-Origin Policy or sandbox | Null origin exploitation, postMessage bypass, CORS misconfig |
| **Type Confusion** | Exploiting type system weaknesses | DOM clobbering, prototype pollution, property injection |
| **Protocol Violation** | Intentional violation of HTTP/browser specs | Content-Length desync, malformed headers, parser exploits |

**Axis 3 (Attack Scenario)** — The deployment context and ultimate impact. Mapped at the end of this document showing which mutation categories combine to enable specific attack scenarios.

### Fundamental Mechanism: Browser as Trust Boundary

Client-side attacks exploit the fundamental tension between **composability** (browsers must allow cross-origin interactions) and **isolation** (browsers must protect sensitive data). This creates multiple interpretation boundaries:

1. **Browser-Server Boundary** — HTTP parsing, caching, connection management
2. **Origin Boundary** — Same-Origin Policy, CORS, postMessage
3. **Frame Boundary** — iframe isolation, window hierarchy, sandbox attributes
4. **Storage Boundary** — Cookies, cache, localStorage, sessionStorage
5. **Timing Boundary** — Observable differences in resource loading, computation, network

Each boundary represents an opportunity for differential interpretation, making client-side security a distributed systems problem where attackers exploit discrepancies between intended policy and actual browser behavior.

---

## §1. Cross-Site Information Leakage (XS-Leaks)

Cross-site leaks (XS-Leaks) are browser-based side-channel attacks that exploit legitimate web platform features to infer information across origins, bypassing the Same-Origin Policy.

### §1-1. HTTP Header Length & Content Leaks

These attacks exploit variable-length HTTP headers to infer information about cross-origin responses.

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **ETag Length Leak** | Server generates variable-length ETag headers based on content size (e.g., Apache hex format). Attacker uses CSRF to manipulate response size, then measures ETag length via HTTP 431 (Request Header Too Large) by padding URL to threshold. Detects via history.length changes (431 causes "replace" vs "push"). | Server uses variable-length ETags (Apache, Nginx, Tomcat, H2O), enforces header size limits (Node.js 16 KiB default), Chromium browser. | [arkark Blog 2025](https://blog.arkark.dev/2025/12/26/etag-length-leak) |
| **Content-Length Timing** | Measure response size via timing differences when browser validates Content-Length before processing body. Larger responses take longer to receive. | Network timing observable, target doesn't use chunked encoding. | - |
| **Header Count Enumeration** | Infer number of custom headers (e.g., Set-Cookie count) by approaching header size limit and detecting failures. | Server returns variable number of headers based on state. | - |

**Cross-reference**: Combines with §5-2 (history manipulation) and §3-1 (cache timing).

### §1-2. Resource Timing & Load Detection

Exploit performance APIs and observable timing differences to infer resource characteristics.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **PerformanceResourceTiming Leak** | Use `performance.getEntriesByType('resource')` to measure precise timing of cross-origin resource loads. Timing differences reveal cache hits, redirects, or resource size. | Resource timing API not restricted, CORS not blocking timing info. |
| **onload vs onerror Events** | Embed cross-origin resource (image, script, iframe) and measure whether `onload` (success) or `onerror` (failure) fires. Infers existence, validity, or error state. | Resource accessible via tags, error details not sanitized. |
| **Frame Counting (history.length)** | Navigate to cross-origin URL in popup/iframe, measure `history.length` changes. Different values indicate redirects, errors, or specific page states. | History API accessible, navigation creates entries. |

### §1-3. Cache-Based Leaks

Exploit browser cache state to infer whether specific resources were previously loaded.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cache Probing via Timing** | Load resource, clear it from cache (if possible), reload and measure timing. Faster reload indicates cache hit. Infers if victim visited specific pages. | Timing differences observable (Chrome ~10-50ms), cache not partitioned. |
| **Cache Partitioning Bypass** | Exploit incomplete cache partitioning implementations. Even with partitioned caches, some resources (fonts, HSTS, etc.) may leak across partitions. | Cache partitioning not fully deployed, shared cache keys. |
| **Service Worker Cache Oracle** | Register service worker on attacker origin, intercept fetch events for cross-origin resources, measure cache state via timing or cache API. | Service worker allowed on attacker origin, cross-origin cache observable. |

### §1-4. JavaScript Execution & State Inference

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CORB/CORP Bypass Detection** | Attempt to load cross-origin resource as script/fetch. Measure whether CORB (Cross-Origin Read Blocking) or CORP (Cross-Origin Resource Policy) blocked it. Different block behaviors reveal content type. | CORB/CORP behavior observable, error messages differ. |
| **Global Pollution Detection** | Load cross-origin script (if CORS allows), check if specific global variables were defined. Infers script content or user state. | Script sets globals, attacker can inspect `window` object. |
| **Error Message Differences** | Trigger errors in cross-origin contexts (CSP violation, script error, etc.), measure differences in console messages or exception handling. | Error messages leak information, observable via error events. |

---

## §2. Browser Security Model Bypass

Attacks targeting the fundamental isolation mechanisms browsers use to separate origins, frames, and sandboxed contexts.

### §2-1. Same-Origin Policy (SOP) Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Null Origin Exploitation** | Create sandboxed iframe without `allow-same-origin` attribute. Origin becomes `null`. When comparing `event.origin === window.origin`, both are string `"null"`, bypassing validation. Allows postMessage injection to pages expecting non-null origin checks. | Target validates `event.origin === window.origin` without checking for `null`. | [Critical Thinking Ep. 151](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-151-client-side-advanced-topics-with-rhynorater) |
| **Subdomain Takeover SOP Bypass** | Compromise subdomain (via subdomain takeover, XSS, or hosting malicious content). Same-site context allows bypassing SameSite cookie restrictions and accessing sibling domains. | Sibling domain vulnerable, cookies use domain-scope. | - |
| **document.domain Mutation** | Both attacker and target set `document.domain` to parent domain (e.g., `example.com`). Browsers treat them as same-origin. Deprecated but still supported in legacy browsers. | Both pages set matching `document.domain`, feature not disabled. | - |

### §2-2. Iframe Sandbox Bypass

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **window.open Sandbox Inheritance** | Sandboxed iframe with `allow-popups` calls `window.open()`. Opened popup inherits sandbox restrictions unless `allow-popups-to-escape-sandbox` is set. Popup has `null` origin, enabling null origin attacks (§2-1). | Sandboxed iframe with `allow-popups` but not `allow-popups-to-escape-sandbox`. | [HackTricks](https://book.hacktricks.xyz/pentesting-web/postmessage-vulnerabilities/bypassing-sop-with-iframes-1) |
| **Sandbox Attribute Mutation** | Sandboxed iframe with `allow-scripts` and `allow-same-origin` can modify its own `sandbox` attribute via DOM manipulation, removing restrictions. | Iframe has both `allow-scripts` and `allow-same-origin`. | [Medium](https://leapcell.medium.com/a-deep-dive-into-javascript-sandboxing-bbb0773a8633) |
| **CORS Null Origin Bypass** | Server trusts `Origin: null` in CORS checks. Attacker creates sandboxed iframe (which sends `null` origin), makes cross-origin XHR request, server returns `Access-Control-Allow-Origin: null`. | Server CORS policy explicitly allows `null` origin. | [PortSwigger Forum](https://forum.portswigger.net/thread/cors-vulnerability-with-trusted-null-origin-origin-header-null-for-xhr-request-made-from-iframe-with-sandbox-attribute-daaf528f) |

### §2-3. postMessage Vulnerabilities

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **Wildcard Origin Bypass** | Target sends postMessage with `targetOrigin: "*"`. Any origin can receive message, enabling data exfiltration. | Developer uses `"*"` instead of specific origin. | [YesWeHack](https://www.yeswehack.com/learn-bug-bounty/introduction-postmessage-vulnerabilities) |
| **indexOf Origin Validation** | Target validates origin using `event.origin.indexOf("example.com")`. Attacker uses `attackerexample.com` or `example.com.attacker.com`, bypassing check. | Weak substring-based origin validation. | [PortSwigger Web Security Academy](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source) |
| **postMessage XSS** | Target receives postMessage and inserts `event.data` into DOM without sanitization. Attacker sends `<img src=x onerror=alert(1)>` via postMessage from malicious iframe. | Application uses `innerHTML`, `document.write`, or similar sinks with unsanitized postMessage data. | [CyberCX](https://cybercx.com.au/blog/post-message-vulnerabilities/) |
| **Frame Reference Hijacking** | Target posts message to `window.opener` or `window.parent` without validating recipient origin. Attacker opens target in popup, receives sensitive data. | Target trusts frame relationships without origin validation. | - |

### §2-4. CORS Misconfiguration

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Reflected Origin CORS** | Server reflects `Origin` header into `Access-Control-Allow-Origin` without validation. Any origin can make credentialed cross-origin requests. | CORS policy copies `Origin` header, `Access-Control-Allow-Credentials: true`. |
| **Subdomain Wildcard Expansion** | Server allows `*.example.com` via regex but doesn't anchor properly. Attacker uses `attackerexample.com` or `example.com.attacker.com`. | Regex-based CORS validation without proper anchors. |
| **Pre-flight Bypass** | CORS pre-flight (OPTIONS request) checks origin, but actual GET/POST request doesn't re-validate. Race condition or caching allows bypass. | Pre-flight and main request validation differ. |

---

## §3. Client-Side Desync (CSD) Attacks

Client-Side Desync exploits browser-server connection state management to poison browser cache or execute XSS by desyncing HTTP connection layers.

### §3-1. Connection Desynchronization

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **CL.0 Desync (Browser-Powered)** | Server ignores or mishandles `Content-Length: 0` on POST requests. Browser sends body anyway. Server reads body as next request, desyncing connection. Attacker injects prefix into subsequent request. | Server doesn't enforce Content-Length, browser and server HTTP parsers differ, HTTP/1.1 only (HTTP/2 not vulnerable). | [PortSwigger Research](https://portswigger.net/research/browser-powered-desync-attacks) |
| **Content-Length Mismatch** | Attacker sends POST with `Content-Length` header but incomplete body. Server waits for full body, browser sends next request before server finishes reading. Next request appended to partial body. | Server buffers based on Content-Length, browser sends pipelined requests. | [Cobalt Blog](https://www.cobalt.io/blog/a-dive-into-client-side-desync-attacks) |
| **Transfer-Encoding Smuggling (Browser)** | Send `Transfer-Encoding: chunked` with malformed chunk size. Browser and server parse chunks differently. | Server accepts TE but browser uses CL, or vice versa. | - |

### §3-2. Browser Cache Poisoning via CSD

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **JavaScript Injection via Desync** | Use CSD to inject attacker-controlled response prefix. Next request (e.g., to `/static/app.js`) receives malicious prefix. Browser caches poisoned JavaScript. All users requesting `/static/app.js` execute attacker's code. | Target resource is cacheable, desync exploitable, cache keying doesn't include request ID. | [PortSwigger Lab](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-browser-cache-poisoning-via-client-side-desync) |
| **Open Redirect Chain** | Combine CSD with open redirect. Desync causes server to respond to attacker's injected Host header. Browser cache stores redirect to attacker domain. | Open redirect + CSD + cacheable redirect response. | [Redbot Security](https://redbotsecurity.com/client-side-desync/) |

---

## §4. CSRF Evolution & SameSite Bypass

Modern CSRF attacks that bypass traditional protections like X-Frame-Options and SameSite cookies.

### §4-1. CSRF Despite XFO Deprecation

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **X-Frame-Options Deprecation Exploit** | Browsers deprecated `X-Frame-Options: ALLOW-FROM` directive. Legacy applications rely on XFO, but modern browsers ignore it. Attacker embeds target in iframe despite XFO. | Application uses `ALLOW-FROM`, modern browser ignores it, no CSP frame-ancestors fallback. | [Critical Thinking Ep. 161](https://www.criticalthinkingpodcast.io/) |
| **CSP frame-ancestors Bypass** | CSP `frame-ancestors` uses origin matching. Attacker exploits subdomain takeover or sibling domain to frame target from allowed origin. | CSP allows broad origin patterns, sibling domain compromised. | - |

### §4-2. SameSite Cookie Bypass

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **SameSite Lax 2-Minute Window** | Chrome allows SameSite=Lax cookies in POST requests if cookie was set <2 minutes ago. Attacker triggers cookie refresh (logout + login, OAuth flow), then immediately sends CSRF POST within 2-minute window. | Browser enforces Lax-2min exception, application has cookie refresh mechanism. | [PortSwigger](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions) |
| **SameSite via Client-Side Redirect** | Application contains client-side redirect (JavaScript `window.location`). Attacker chains: `attacker.com` → `target.com/redirect?url=/csrf-endpoint`. Redirect makes request "same-site" from browser's perspective. | Client-side redirect to attacker-controlled URL parameter, works for all SameSite levels. | [PulseSecurity](https://pulsesecurity.co.nz/articles/samesite-lax-csrf) |
| **Sibling Domain CSRF** | Attacker compromises sibling subdomain (e.g., `uploads.example.com` via XSS or file upload). Makes same-site request to `api.example.com`. SameSite cookies sent. | Sibling domain vulnerable, cookies scoped to parent domain. | [PortSwigger](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions) |
| **HTTP Method Override** | Framework supports `_method` parameter to override HTTP method. Attacker sends GET request with `?_method=POST`. SameSite Lax allows GET, framework processes as POST. | Framework uses method override (Symfony, Rails), SameSite=Lax. | [Hazanasec Blog](https://hazanasec.github.io/2023-07-30-Samesite-bypass-method-override.md/) |
| **OAuth-Based Cookie Refresh** | Application has logout CSRF + OAuth login. Attacker forces logout, triggers OAuth login (refreshes session cookie), immediately exploits Lax-2min window. | Logout CSRF + OAuth login + Lax default. | [Medium Renwa](https://medium.com/@renwa/bypass-samesite-cookies-default-to-lax-and-get-csrf-343ba09b9f2b) |

### §4-3. Cross-Consumer Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Consumer State Pollution** | Multi-tenant application shares state between consumers. Attacker creates account, pollutes shared resource (template, config, cached object), victim consumes poisoned data. | Multi-tenant architecture with shared state, insufficient isolation. |
| **Tenant Confusion** | Application uses tenant identifier from user input without validation. Attacker sends CSRF with different tenant ID, performing action on victim tenant. | Tenant ID from untrusted source, CSRF protection missing. |

---

## §5. Cookie Security & Partitioning

Attacks exploiting cookie handling, partitioning mechanisms, and storage isolation.

### §5-1. Cookie Partitioning (CHIPS) Attacks

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **CHIPS Keying Confusion** | Cookies with `Partitioned` attribute keyed by `(scheme, eTLD+1, top-level site)`. Attacker embeds target in iframe, sets partitioned cookie. If application logic assumes cookie uniqueness across contexts, can cause confusion. | Application uses partitioned cookies, logic assumes global cookie scope. | [Critical Thinking Ep. 151](https://blog.criticalthinkingpodcast.io/p/hackernotes-ep-151-client-side-advanced-topics-with-rhynorater) |
| **Partition Key Collision** | Attacker finds two different top-level contexts that produce same partition key. Sets cookie in one context, accesses in another. | Partition keying algorithm has collisions, rare. | - |
| **Non-Partitioned Fallback** | Browser doesn't support `Partitioned` attribute (Firefox, Safari as of 2025). Cookie becomes non-partitioned third-party cookie, accessible across contexts. | Application assumes all browsers support CHIPS, no fallback. | [MDN](https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/Privacy_sandbox/Partitioned_cookies) |

### §5-2. Cookie Tossing & Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cookie Tossing** | Attacker controls subdomain (e.g., `attacker.example.com`), sets cookie for parent domain `Domain=example.com`. When victim visits `target.example.com`, receives both legitimate and attacker cookies. Application may process attacker cookie first. | Subdomain controllable, cookies scoped to parent domain, application doesn't validate cookie source. |
| **Cookie Shadowing** | Attacker sets cookie with same name but different scope (path, domain). Browser sends multiple cookies with same name. Application uses first/last, attacker controls priority. | Application doesn't handle duplicate cookie names, cookie priority exploitable. |
| **Cookie Bomb** | Send request with thousands of cookies or extremely large cookie values. Server exhausts memory parsing cookies, causing DoS. | Server doesn't limit cookie count/size, parses all cookies before validation. |

---

## §6. Parser Differential Attacks

Exploiting differences in how browsers, proxies, WAFs, and servers parse HTTP requests and responses.

### §6-1. WAF Bypass via Parser Differentials

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **Cloudflare WAF Bypass** | Craft request that Cloudflare WAF parses differently than origin server. Example: use header like `Transfer-Encoding : chunked` (space before colon). Cloudflare normalizes, origin processes chunked encoding. | WAF normalization differs from backend, HTTP smuggling conditions. | [Critical Thinking Ep. 160](https://www.criticalthinkingpodcast.io/) |
| **Header Obfuscation** | Use uncommon header formats (tab separators, line folding, UTF-8 encoded headers). WAF passes request, backend interprets malicious payload. | WAF and backend header parsers differ. | - |
| **Path Normalization Bypass** | WAF normalizes path (e.g., `/admin/../user`), allows request. Backend doesn't normalize, processes as `/admin/`. | WAF and backend path normalization algorithms differ. | - |

### §6-2. Mail Header Parsing XSS

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **Unsubscribe Link XSS** | Email unsubscribe mechanism parses email headers to extract recipient/token. Attacker sends email with malicious header (e.g., `X-Unsubscribe-Token: <script>alert(1)</script>`). Web interface renders header without sanitization. | Email header parsing + unsanitized rendering in web UI. | [Critical Thinking Ep. 160](https://www.criticalthinkingpodcast.io/) |
| **MIME Type Confusion** | Multipart email with nested content types. Email client and web UI parse MIME boundaries differently. Web UI renders attacker-controlled part as HTML. | MIME parsing differential, web rendering without sanitization. | - |

---

## §7. Media & Audio-Based Exfiltration

Attacks using audio, video, or media channels to exfiltrate data or bypass security controls.

### §7-1. DTMF Tone Exfiltration

| Subtype | Mechanism | Key Condition | Reference |
|---------|-----------|---------------|-----------|
| **Voice Call DTMF Leakage** | User enters sensitive data (credit card) via phone keypad. Each digit generates DTMF tone. Call recording or eavesdropping (DECT wireless) captures tones. Attacker decodes tones to retrieve digits. | Call recording enabled, DTMF masking not implemented, eavesdropping possible. | [Critical Thinking Ep. 161](https://www.criticalthinkingpodcast.io/) |
| **WebRTC Audio Stream Exfiltration** | Application uses WebRTC for audio/video. Attacker injects JavaScript to capture audio stream, encode sensitive data as DTMF tones in background audio, exfiltrate via WebRTC data channel. | WebRTC enabled, attacker can inject JS, audio stream accessible. | - |

### §7-2. Media Timing Channels

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Video Frame Rate Leak** | Embed cross-origin video, measure frame rate via `requestAnimationFrame`. Different content types (static vs dynamic) have different frame rates. | Video accessible, frame rate observable. |
| **Audio Fingerprinting** | Play audio, measure Web Audio API nodes or output timing. Infer system state (CPU load, codec support) revealing user identity or environment. | Web Audio API accessible, timing differences observable. |

---

## Attack Scenario Mapping (Axis 3)

This table maps attack scenarios to the primary mutation categories that enable them.

| Attack Scenario | Architectural Context | Primary Mutation Categories | Notable Cases |
|----------------|----------------------|---------------------------|---------------|
| **XSS via Cache Poisoning** | Cached static resources, CSD exploitable | §3-1 (desync), §3-2 (cache poison), §6-1 (WAF bypass) | Browser-powered desync XSS |
| **CSRF Bypassing Modern Protections** | Applications with SameSite cookies, OAuth flows | §4-2 (SameSite bypass), §4-1 (XFO deprecation), §2-1 (subdomain takeover) | Lax-2min exploit chains |
| **Cross-Site Data Exfiltration** | Single-page applications, personalized content | §1-1 (ETag leak), §1-2 (timing), §1-3 (cache probing), §1-4 (state inference) | ETag length leak, XS-Leaks |
| **Origin Bypass for Privilege Escalation** | Multi-origin applications, iframe-heavy sites | §2-1 (SOP bypass), §2-2 (sandbox bypass), §2-3 (postMessage) | Null origin exploitation |
| **Session Hijacking via Cookie Attacks** | Subdomain-scoped cookies, multi-tenant apps | §5-2 (cookie tossing), §4-3 (cross-consumer), §2-1 (subdomain takeover) | Cookie shadowing chains |
| **WAF/Security Control Bypass** | Cloudflare, AWS WAF, Akamai protected sites | §6-1 (parser differential), §3-1 (CSD), §6-2 (mail header) | HTTP smuggling variants |
| **Sensitive Data Interception** | VoIP systems, contact centers, WebRTC apps | §7-1 (DTMF exfil), §1-2 (timing), §7-2 (media timing) | Call recording leaks |

---

## CVE / Bounty Mapping (2024-2025)

| Mutation Combination | CVE / Case | Impact / Bounty | CVSS Score |
|---------------------|-----------|----------------|------------|
| §1-1 (ETag leak) + §5-1 (history) | ETag Length Leak (arkark 2025) | Cross-origin information disclosure via HTTP 431 + history.length oracle | - |
| §3-1 (CSD) + §3-2 (cache poison) | Browser-Powered Desync (Kettle 2022) | XSS via browser cache poisoning, affects single-server deployments | HIGH |
| §4-2 (SameSite bypass) | SameSite Lax-2min Bypass | CSRF on protected endpoints via cookie refresh + 2-minute window | MEDIUM |
| §2-1 (null origin) + §2-3 (postMessage) | Null Origin postMessage Bypass | Origin validation bypass enabling XSS via sandboxed iframe | MEDIUM |
| §6-1 (WAF bypass) | Cloudflare Parser Differential | WAF bypass via Transfer-Encoding header obfuscation | - |
| §2-2 (sandbox) | CVE-2025-2783 (Chrome Mojo) | Sandbox escape via Mojo IPC validation failure, enables RCE | CRITICAL |
| §7-1 (DTMF) | CVE-2017-16778 (Fermax Intercom) | Authorization bypass via DTMF injection | HIGH |
| §1-3 (cache timing) + §1-2 (timing) | CVE-2025-22234 (Spring Security) | Username enumeration via timing attack (30-100ms difference) | MEDIUM |
| §5-2 (cache poison) | CVE-2025-49005 (Next.js) | Cache poisoning via improper cache key separation | - |
| §2-2 (sandbox) | CVE-2025-4609 (Chromium IPC) | Sandbox escape via ipcz IPC flaw, affects Cursor/Windsurf editors | CRITICAL |
| §2-2 (sandbox) | CVE-2025-31191 (macOS) | Sandbox escape via security-scoped bookmarks | HIGH |

---

## Detection & Mitigation Tools

### Offensive Tools (Reconnaissance & Exploitation)

| Tool | Type | Target | Core Technique |
|------|------|--------|---------------|
| **XSLeaks.dev** | Web Platform | XS-Leaks | Comprehensive XS-Leaks attack database and testing tools |
| **DOM Invader** | Burp Extension | postMessage, DOM | Automated postMessage vulnerability detection, DOM clobbering |
| **DesyncCL0** | CLI | Client-Side Desync | Detect CSD vulnerabilities via automated request fuzzing |
| **http-desync-guardian** | Library | HTTP Desync | Validate HTTP requests for smuggling/desync conditions |
| **DTMF Decoder** | Audio Tool | DTMF Exfiltration | Decode DTMF tones from audio recordings |

### Defensive Tools (Scanning & Monitoring)

| Tool | Type | Target | Core Technique |
|------|------|--------|---------------|
| **Burp Scanner** | DAST | All client-side | Detects CORS, postMessage, XS-Leaks, CSRF bypass |
| **CSP Evaluator** | Static Analysis | CSP policies | Identifies CSP bypasses, weak frame-ancestors |
| **Observatory by Mozilla** | Scanner | Security headers | Validates SameSite, CSP, CORS, cookie security |
| **SecurityHeaders.com** | Scanner | HTTP headers | Audits X-Frame-Options, CSP, HSTS, cookie attributes |
| **OWASP ZAP** | DAST | Web apps | Detects CSRF, XSS, CORS issues, header injection |

### Browser Security Features & APIs

| Feature | Type | Protection | Adoption |
|---------|------|-----------|----------|
| **SameSite Cookies** | Cookie Attribute | CSRF protection via Lax/Strict | Default in Chrome 80+, partial in Firefox/Safari |
| **Cookie Partitioning (CHIPS)** | Privacy | Third-party cookie isolation | Chrome 114+, not in Firefox/Safari |
| **Cross-Origin-Opener-Policy (COOP)** | HTTP Header | Isolate window context from cross-origin | Modern browsers |
| **Cross-Origin-Embedder-Policy (COEP)** | HTTP Header | Require CORS for cross-origin resources | Modern browsers |
| **Fetch Metadata** | HTTP Headers | Provides Sec-Fetch-* headers for origin validation | Chrome 80+, Firefox 90+ |
| **Storage Partitioning** | Browser Feature | Isolate cache/storage by top-level site | Safari, Chrome (rolling out) |

---

## Summary: Core Principles

### What Makes Client-Side Mutation Space Possible?

The vulnerability surface stems from **four fundamental properties**:

1. **Composability vs Isolation Paradox** — Browsers must allow cross-origin resource loading (images, scripts, fonts, iframes) for the web to function, but must also prevent information leakage. Every observable difference (timing, error messages, cache state, frame counts) becomes a side channel.

2. **Multi-Layer Parsing Boundaries** — A single HTTP request traverses: browser → proxy → WAF → load balancer → application server. Each layer parses headers, body, and URLs independently. Discrepancies in parsing (path normalization, header folding, encoding) create smuggling/desync opportunities.

3. **Stateful Browser Behavior** — Browsers maintain state (cookies, cache, history, connections) that persists across origins. Attackers exploit this state to infer information (cache timing), poison resources (cache poisoning), or bypass protections (SameSite via client-side redirects).

4. **Trust Boundary Ambiguity** — Browsers trust certain inputs implicitly: cookies from parent domains, postMessage from iframes, CORS headers from servers. Applications assume browser enforces policies (SameSite, X-Frame-Options), but browsers have exceptions (Lax-2min window, XFO deprecation). This trust gap enables bypasses.

### Why Incremental Patches Fail

Each CVE fix addresses a specific mutation instance but doesn't close the structural gaps:

- **ETag Length Leak** → Servers can use constant-length ETags. But this doesn't address §1-2 timing leaks, §1-3 cache probing, or §1-4 CORB detection. Side channels persist.
- **SameSite Lax-2min** → Chrome could remove the 2-minute exception. But §4-2 client-side redirects, sibling domain bypasses, and method override remain. Fundamental issue: "same-site" is broader than "same-origin".
- **Null Origin Bypass** → Applications can check `event.origin !== "null"`. But §2-2 window.open inheritance, §2-4 CORS null trust, and sandbox attribute mutation remain. Trust model is fundamentally broken.

Incremental fixes play "whack-a-mole" because they address symptoms (specific parser bugs, timing windows, validation gaps) rather than root causes (composability vs isolation, multi-layer parsing, stateful browsers).

### Structural Solution

A comprehensive defense requires addressing the **five boundaries** simultaneously:

1. **Browser-Server Boundary** → Strict HTTP parsing without legacy quirks; consistent header/body/URL handling across all components; disable HTTP/1.1 pipelining; enforce HTTP/2 stream isolation.

2. **Origin Boundary** → Explicit origin validation in all postMessage/CORS handlers (reject `null`, validate against allowlist); use Fetch Metadata headers (`Sec-Fetch-Site`, `Sec-Fetch-Mode`) for request context; deploy COOP/COEP to isolate window contexts.

3. **Frame Boundary** → Avoid `allow-same-origin` + `allow-scripts` in sandbox; validate all cross-frame communication origins; use CSP `frame-ancestors` instead of deprecated X-Frame-Options; isolate sensitive operations from embeddable contexts.

4. **Storage Boundary** → Set cookies with `SameSite=Strict` + `Secure` + `HttpOnly` + `Partitioned` (where supported); use short-lived tokens instead of long-lived cookies; implement CSRF tokens for state-changing operations; scope cookies narrowly (path, domain).

5. **Timing Boundary** → Limit precision of timing APIs (Performance API, Date.now); add random jitter to response times; implement cache-control headers to prevent resource timing; avoid variable-length outputs based on secrets (ETags, error messages).

Additionally:

- **Defense in Depth** — Never rely on browser protections alone (SameSite, CSP, CORS). Application must validate all inputs, origins, and state.
- **Fail Closed** — On ambiguous origin (null, mismatch), parsing errors, or unexpected state, reject the request/message.
- **Principle of Least Composability** — Minimize cross-origin interactions; use `Cross-Origin-Resource-Policy: same-origin` by default; disable legacy features (document.domain, X-Frame-Options ALLOW-FROM).

The fundamental insight: **Client-side security is a game of observable differences**. Every timing gap, cache hit, error message, or frame count is a potential side channel. Defense requires eliminating observable differences at all five boundaries, not just patching individual leaks.

---

## References

### Research Publications
- [Cross-Site ETag Length Leak](https://blog.arkark.dev/2025/12/26/etag-length-leak) - arkark, December 2025
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks) - James Kettle, Black Hat USA 2022
- [XS-Leaks Wiki](https://xsleaks.dev/) - Comprehensive cross-site leak database
- [The Leaky Web: Automated Discovery of Cross-Site Information Leaks](https://ieeexplore.ieee.org/document/10179311/) - IEEE S&P 2023

### Podcast & Conference Sources
- [Critical Thinking - Bug Bounty Podcast](https://www.criticalthinkingpodcast.io/)
  - Episode 151: Client-Side Advanced Topics (Cookie partitioning, iframe tricks, URL parsing)
  - Episode 156: Cross-Site ETag Leaks, AI Agents
  - Episode 160: Cloudflare WAF Bypass, Mail Unsubscribe XSS
  - Episode 161: CSRF despite XFO, DTMF Exfiltration

### Security Advisories & CVEs
- [CVE-2025-2783: Chrome Mojo Sandbox Escape](https://fidelissecurity.com/vulnerabilities/cve-2025-2783/)
- [CVE-2025-4609: Chromium IPC Sandbox Escape](https://www.ox.security/blog/the-aftermath-of-cve-2025-4609-critical-sandbox-escape-leaves-1-5m-developers-vulnerable/)
- [CVE-2025-22234: Spring Security Timing Attack](https://www.cve.news/cve-2025-22234/)
- [CVE-2025-49005: Next.js Cache Poisoning](https://www.wiz.io/vulnerability-database/cve/cve-2025-49005)
- [CVE-2017-16778: Fermax Intercom DTMF Injection](https://github.com/breaktoprotect/CVE-2017-16778-Intercom-DTMF-Injection)

### Standards & Documentation
- [OWASP XS-Leaks Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html)
- [Cookies Having Independent Partitioned State (CHIPS)](https://developer.mozilla.org/en-US/docs/Web/Privacy/Guides/Privacy_sandbox/Partitioned_cookies)
- [SameSite Cookies Explained](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [Cross-Origin-Opener-Policy (COOP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)

### Tools & Frameworks
- [HackTricks: Bypassing SOP with Iframes](https://book.hacktricks.xyz/pentesting-web/postmessage-vulnerabilities/bypassing-sop-with-iframes-1)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [GitHub: xsleaks/xsleaks](https://github.com/xsleaks/xsleaks)
- [GitHub: DesyncCL0](https://github.com/riramar/DesyncCL0)

### Industry Blogs & Tutorials
- [YesWeHack: Introduction to postMessage Vulnerabilities](https://www.yeswehack.com/learn-bug-bounty/introduction-postmessage-vulnerabilities)
- [CyberCX: Cross-Site Leaks Attacks and Mitigations](https://cybercx.com.au/blog/cross-site-leaks-attacks/)
- [Cobalt: A Dive into Client-Side Desync Attacks](https://www.cobalt.io/blog/a-dive-into-client-side-desync-attacks)
- [PulseSecurity: SameSite Lax CSRF Exploitation](https://pulsesecurity.co.nz/articles/samesite-lax-csrf)

---

*This document was created for defensive security research and vulnerability understanding purposes. Version 2025.2 — Last updated: February 2025.*
