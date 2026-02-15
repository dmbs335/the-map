# Web Cache Poisoning & Deception — Mutation/Variation Taxonomy

---

## Classification Structure

Web cache attacks exploit **discrepancies** between how a **caching layer** (CDN, reverse proxy, browser cache, or application-level cache) and an **origin server** (web server, framework, application) interpret the same HTTP request. The attacker's goal is one of two things:

- **Cache Poisoning (WCP):** Force the cache to store a *malicious* response (XSS payload, redirect, error page, altered content) and serve it to subsequent legitimate users.
- **Cache Deception (WCD):** Trick the cache into storing a *victim's sensitive* response (authentication tokens, PII, session data) so the attacker can retrieve it later.

Both attack families share the same root cause — **parser discrepancy between caching and serving components** — but differ in who generates the harmful content (attacker vs. victim) and the direction of information flow (attacker→victim vs. victim→attacker).

### Axis 1 — Mutation Target (Primary Structure)

The taxonomy is organized by **what structural component of the HTTP request the attacker manipulates** to create the cache discrepancy. There are nine top-level categories:

| § | Mutation Target | Core Mechanism |
|---|----------------|----------------|
| 1 | URL Path Structure | Delimiter/extension/directory confusion between cache rules and origin routing |
| 2 | URL Path Normalization | Dot-segment resolution and encoding/decoding differences |
| 3 | Unkeyed Request Headers | Headers excluded from cache key but influencing origin response |
| 4 | Query String & Parameters | Parameter exclusion, cloaking, and unkeyed query poisoning |
| 5 | HTTP Method & Body | Fat GET, method override, body-parameter confusion |
| 6 | Cache Key Construction | Key injection, normalization, port exclusion, structural collisions |
| 7 | Malformed Headers & Error Responses | Provoking cacheable error pages via oversized/invalid headers |
| 8 | Framework & Application-Level Caches | Internal cache mechanisms, fragment caching, middleware bypass |
| 9 | Client-Side & Browser Caches | Client-side desync, browser cache poisoning, service worker abuse |

### Axis 2 — Discrepancy Type (Cross-Cutting)

Each mutation works because it creates a specific type of mismatch:

| Discrepancy Type | Description |
|-----------------|-------------|
| **Path Interpretation** | Cache and origin disagree on what endpoint a URL maps to |
| **Delimiter Recognition** | Cache and origin recognize different characters as path/parameter delimiters |
| **Normalization Asymmetry** | Cache and origin apply different URL normalization (decode, resolve, case-fold) |
| **Key Inclusion/Exclusion** | A request component influences the response but is not part of the cache key |
| **Size/Format Tolerance** | Cache accepts a request the origin rejects (or vice versa), causing error caching |
| **Protocol/Method Semantics** | Cache and origin disagree on how HTTP methods, bodies, or protocol features work |
| **Content-Type / Routing** | Cache determines cacheability from URL shape; origin determines content from routing logic |

### Axis 3 — Attack Scenario (Impact Mapping)

| Scenario | Direction | Primary Impact |
|----------|-----------|---------------|
| **Stored XSS via Cache** | Poisoning | Attacker injects script payload cached for all users |
| **Denial of Service (DoS)** | Poisoning | Error page or broken redirect cached, blocking legitimate access |
| **Open Redirect Hijacking** | Poisoning | Malicious redirect cached, phishing or credential theft |
| **Resource Import Hijacking** | Poisoning | Cached JS/CSS import points to attacker-controlled domain |
| **Sensitive Data Theft** | Deception | Victim's auth tokens, PII, or session data cached and retrieved by attacker |
| **Account Takeover (ATO)** | Deception | Auth tokens cached via deception, enabling full account compromise |
| **Response Queue Poisoning** | Poisoning | Desync causes persistent cross-user response mixing |

---

## §1. URL Path Structure Mutations

URL path structure mutations exploit the fact that caching layers and origin servers use **different rules to determine what a URL path means**. Caches typically decide whether to store a response based on static extension rules (`.js`, `.css`, `.png`), static directory prefixes (`/static/`, `/assets/`), or exact-match file names (`/robots.txt`). Origin servers, meanwhile, use framework-specific routing logic that may ignore trailing segments, strip delimiters, or interpret extensions differently.

### §1-1. Static Extension Appending (Classic WCD)

The original web cache deception technique appends a static file extension to a dynamic endpoint, tricking the cache into treating the response as a cacheable static resource while the origin ignores the appended segment.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Trailing path segment** | `/account/profile/nonexistent.css` — origin ignores `/nonexistent.css` via REST-style routing; cache sees `.css` extension and stores | Origin uses REST-style path mapping; cache uses traditional file-extension rules |
| **Dot-extension via delimiter** | `/account/profile;foo.css` — origin treats `;` as delimiter and serves `/account/profile`; cache sees `.css` and caches | Origin framework uses `;` as delimiter (e.g., Java Spring matrix variables) |
| **Format extension stripping** | `/account/profile.css` — Ruby on Rails strips `.css` as format specifier and serves profile; cache caches as static CSS | Rails or similar framework that treats `.` as format delimiter |
| **Null-byte truncation** | `/account/profile%00.js` — OpenLiteSpeed truncates at `%00`; cache sees `.js` extension | Origin server that treats encoded null byte as string terminator |
| **Newline truncation** | `/account/profile%0a.css` — Nginx (in rewrite mode) truncates at `%0a`; cache sees `.css` | Nginx with specific rewrite configurations |

### §1-2. Static Directory Rule Exploitation

Many CDNs cache all responses under specific directory prefixes (e.g., `/static/`, `/assets/`, `/media/`). When the origin server normalizes path traversal sequences but the cache evaluates rules before normalization, an attacker can map a dynamic endpoint into a static directory's cache scope.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Encoded dot-segment traversal** | `/static/..%2faccount/profile` — cache matches `/static/` prefix and caches; origin normalizes `..%2f` to `../` and serves `/account/profile` | CDN evaluates rules before path normalization; origin normalizes before routing |
| **Double-encoded traversal** | `/static/..%252f..%252faccount` — first decoding by proxy yields `..%2f`; second decoding by origin yields `../` | Multi-layer proxy chain with incremental decoding |
| **Delimiter + traversal combo** | `/account;/static/../profile` — origin strips at `;` and serves `/account`; cache sees `/static/` directory match after normalization | Origin delimiter + cache normalization interaction |

### §1-3. Exact-Match File Rule Exploitation

Some caches have exact-match rules for well-known static files like `/robots.txt`, `/favicon.ico`, or `/sitemap.xml`. These can be exploited by constructing a path that the cache matches exactly but the origin resolves differently.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Path traversal to exact match** | `/account/profile%2f..%2frobots.txt` — origin resolves to `/robots.txt` (static); cache key collision stores dynamic content under exact-match rule | Depends on specific normalization order at cache vs. origin |
| **Reverse traversal** | `/robots.txt/..%2faccount/profile` — cache matches `/robots.txt` prefix; origin normalizes and serves `/account/profile` | Cache evaluates exact-match before normalization |

### §1-4. Wildcard Cache Rule Exploitation

CDNs may apply wildcard caching rules (e.g., `/share/*` for all content under a path prefix). If an attacker can escape the intended scope of the wildcard via path traversal, arbitrary endpoints become cacheable.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Encoded path escape** | `/share/%2f..%2fapi/auth/session` — CDN matches `/share/*` wildcard and caches; origin decodes `%2f..%2f` and serves `/api/auth/session` containing auth tokens | CDN does not decode URL-encoded slashes before rule evaluation; origin does ($6,500 bounty on ChatGPT) |
| **Backslash confusion** | `/share\..\..\api/auth/session` — IIS normalizes backslashes to forward slashes; CDN treats backslashes as literal characters within wildcard scope | Microsoft IIS origin behind non-IIS CDN |

---

## §2. URL Path Normalization Mutations

Normalization mutations specifically target **how and when** caches and origins resolve URL encoding, dot-segments (`.`, `..`), case folding, and slash collapsing. Unlike §1 (which focuses on cache *rule* triggers), §2 focuses on **cache key computation** — making two semantically different requests resolve to the same cache key, or making one request mean different things to cache and origin.

### §2-1. Dot-Segment Resolution Asymmetry

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cache normalizes, origin doesn't** | `/poisoned-path/../target-page` — cache resolves to `/target-page` (key); origin receives literal `/../` and returns 404 or different content | Cache applies RFC 3986 dot-segment removal before keying; origin does not |
| **Origin normalizes, cache doesn't** | `/static/..%2faccount` — cache keys the full literal string; origin resolves to `/account` and returns sensitive data | Origin decodes+resolves before routing; cache stores under literal key |
| **Selective segment resolution** | `/static/%2e%2e/account` — double-encoded dots decoded differently across layers | Multi-stage decoding pipeline with inconsistent depth |

### §2-2. URL Encoding/Decoding Asymmetry

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Encoded delimiter divergence** | `/account%3fparam=val` — cache keys literal `%3f`; origin decodes to `?` and treats as query string | Cache does not decode before keying; origin decodes in routing |
| **Encoded slash divergence** | `/share/%2f..%2fapi/session` — CDN treats `%2f` as literal; origin decodes to `/` and resolves traversal | Cloudflare CDN + most origin servers |
| **Double encoding** | `/%252e%252e/admin` — first decode yields `%2e%2e`; second decode yields `..`; different layers stop at different decode depths | Proxy chain with multiple decode stages |
| **Encoded XSS normalization** | `/?q=%3Cscript%3E` — browsers URL-encode `<script>` in address bar, but cache key normalizes the encoding; attacker issues raw unencoded request to poison the key | Cache normalizes URL encoding in key; browser always encodes special chars |

### §2-3. Backslash and Separator Normalization

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Backslash-to-slash conversion** | `/static\..\..\account` — IIS/Windows converts `\` to `/`; CDN treats `\` as literal path character | Windows-based origin behind Linux/Unix CDN |
| **Double-slash collapsing** | `//static/../account` — some servers collapse `//` to `/`; cache preserves literal key | Apache with `MergeSlashes On` vs. CDN without slash normalization |

---

## §3. Unkeyed Request Header Mutations

Unkeyed header mutations exploit headers that **influence the origin server's response** but are **excluded from the cache key**. Because the cache key doesn't differentiate requests with different header values, a malicious response generated via a poisoned header gets served to all subsequent users requesting the same URL.

### §3-1. Host and Routing Header Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **X-Forwarded-Host injection** | Attacker sends `X-Forwarded-Host: evil.com` — origin uses this header to generate absolute URLs in the response (meta tags, Open Graph, resource imports); cache stores response with attacker-controlled URLs | Origin reflects X-Forwarded-Host in response body; header is unkeyed |
| **X-Host / X-Forwarded-Server** | Same mechanism via alternative forwarding headers; some frameworks check multiple host-related headers in priority order | Framework falls back to non-standard host headers |
| **X-Original-URL / X-Rewrite-URL** | Origin uses these headers to override the request path entirely; attacker can make a cacheable URL return the response for a different path | IIS/ASP.NET or specific reverse proxy configurations |
| **Duplicate Host header** | Two `Host` headers with different values — cache keys on one, origin routes on another | Proxy and origin disagree on which Host header to use |

### §3-2. Resource Import Poisoning

When unkeyed headers influence dynamically generated URLs for JavaScript, CSS, or image imports in the response HTML, the attacker can redirect these resource loads to their own domain.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JavaScript import hijack** | `X-Forwarded-Host: evil.com` causes `<script src="https://evil.com/main.js">` in cached response | Origin generates absolute script URLs from host header |
| **CSS import hijack** | Same mechanism targeting stylesheet `<link>` tags; attacker can inject CSS-based data exfiltration | Origin generates absolute CSS URLs from host header |
| **Meta tag / Open Graph poisoning** | Poisoned `og:image` or `og:url` tags in cached response; used for phishing via social media previews | Origin reflects host in meta tags |

### §3-3. Response Manipulation via Forwarding Headers

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **X-Forwarded-Scheme / X-Forwarded-Proto** | Injecting `X-Forwarded-Proto: http` causes origin to generate 301 redirect to HTTPS version with attacker-controlled host; cached redirect loops or redirects to malicious domain | Origin issues protocol-upgrade redirects based on unkeyed proto header |
| **X-Forwarded-Port** | Injecting non-standard port causes malformed redirect URLs in cached response, resulting in DoS | Origin appends port from unkeyed header to redirect Location |

### §3-4. Vary Header Evasion

The `Vary` response header instructs caches to include additional request headers in the cache key. However, many CDNs ignore or poorly implement `Vary`.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CDN ignores Vary entirely** | Response includes `Vary: X-Custom-Header` but CDN caches without differentiating on that header; attacker poisons with custom header value affecting all users | Cloudflare and several CDNs ignore Vary for non-standard headers |
| **Selective Vary enforcement** | CDN respects `Vary: Accept-Encoding` but ignores `Vary: Cookie` or `Vary: Authorization` | CDN only implements Vary for a whitelist of headers |
| **User-Agent Vary poisoning** | If `Vary: User-Agent` is respected, attacker poisons cache for specific User-Agent strings (e.g., Googlebot) to serve malicious content to crawlers | Cache segments by User-Agent but attacker can target specific values |

### §3-5. Cookie-Based Cache Poisoning

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unkeyed cookie reflection** | Cookie value (e.g., language preference, tracking ID) is reflected in response body but excluded from cache key; attacker injects XSS via cookie | Application reflects cookie values in HTML; cache doesn't key on Cookie |
| **Cookie-controlled routing** | Cookie determines A/B test variant or locale; cached variant served to all users regardless of their cookie | Cache ignores Cookie header; origin uses it for content determination |

---

## §4. Query String & Parameter Mutations

These mutations exploit how caches include, exclude, or parse URL query parameters relative to the cache key.

### §4-1. Unkeyed Query String

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Entire query string excluded** | Cache keys only on the path; query parameters like `?q=<script>alert(1)</script>` are reflected in response but not part of the key; reflected XSS becomes stored | CDN configured to strip entire query string from key; origin reflects params in HTML |
| **Selective parameter exclusion** | Specific parameters (e.g., `utm_content`, `fbclid`) excluded from key; attacker smuggles payload through excluded parameter | Marketing/tracking parameters explicitly excluded from cache key |

### §4-2. Parameter Cloaking

Parameter cloaking exploits **differences in how caches and origins parse URL parameters** to hide a malicious parameter value inside an excluded parameter.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Semicolon delimiter divergence** | `/search?q=safe&utm_content=x;q=<script>` — cache excludes `utm_content` (and everything after it via regex); Rails/Spring treats `;` as parameter delimiter, extracting `q=<script>` separately | Framework uses `;` as alternative `&` delimiter; cache regex doesn't account for it |
| **Question mark reuse** | `/search?q=safe?utm_content=payload&!&callback=alert(1)` — cache regex treats second `?` as part of excluded parameter name; Varnish/origin parses differently | Varnish URL parsing quirk with repeated `?` characters |
| **Akamai-transform cloaking** | `GET /page?x=1?akamai-transform=payload` — Akamai excludes its internal `akamai-transform` parameter; attacker uses `?` to bridge into excluded scope | Akamai CDN with built-in unkeyed internal parameters |

### §4-3. Parameter Pollution for Cache Deception

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **reqIdentifier / cache-matching params** | Application uses specific parameter (e.g., GraphQL `reqIdentifier`) for request deduplication; attacker crafts GET with same parameter value to retrieve cached POST response containing PII | Application-level cache uses URL parameter for key matching; ignores auth context |
| **Callback parameter override** | JSONP endpoint with `callback` parameter — attacker overrides via cloaked parameter to inject arbitrary function name wrapping sensitive data | JSONP endpoint with cacheable response and cloakable callback param |

---

## §5. HTTP Method & Request Body Mutations

These mutations exploit discrepancies in how caches and origins handle HTTP methods, request bodies, and method override mechanisms.

### §5-1. Fat GET Requests

A "fat GET" is a GET request with a body. Most HTTP specifications do not forbid this, but behavior varies wildly across implementations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Body parameter override** | `GET /report?target=user1` with body `target=user2` — cache keys on URL (`target=user1`); origin reads body parameter (`target=user2`); cached response for `user1` contains `user2`'s data | Cloudflare, Rack::Cache, or similar CDN that forwards GET bodies; origin framework reads body params on GET |
| **Invisible parameter injection** | `GET /api/data` with body `admin=true` — cache key contains no parameters; origin processes body parameter and returns admin data for all subsequent requesters | Origin framework does not distinguish GET body from POST body parameters |

### §5-2. HTTP Method Override (HMO)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **X-HTTP-Method-Override header** | `GET /resource` with `X-HTTP-Method-Override: POST` — cache keys on GET; origin processes as POST, potentially returning different content or triggering side effects | Origin respects method override headers; cache keys on original method |
| **_method parameter override** | `GET /resource?_method=DELETE` — cache keys include `_method`; origin interprets as DELETE request | Framework-specific method override via query parameter (Rails, Laravel) |

### §5-3. Unkeyed HTTP Method

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **POST/GET key collision** | Cache does not include HTTP method in key; POST request with XSS payload in body gets cached; subsequent GET requests receive the poisoned response | Cache implementation omits method from key; origin returns different content for POST vs. GET |

---

## §6. Cache Key Construction Mutations

These mutations directly attack the **structure and computation of the cache key itself**, rather than the content that gets cached.

### §6-1. Cache Key Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Delimiter-based key collision** | Attacker crafts `Origin: '-alert(1)-'__` header; cache concatenates key fields without escaping, producing identical key to a request with `?x=2__Origin='-alert(1)-'` | Cache key uses unescaped delimiters; Akamai and similar CDNs |
| **Header-param key collision** | Keyed header value matches keyed parameter pattern after concatenation; two semantically different requests produce same key hash | Cache key hashing algorithm doesn't escape field boundaries |

### §6-2. Cache Key Normalization Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **URL-decode normalization** | Cache decodes `%3f` to `?` in key computation; attacker's `/%3fproduct=firefox` and victim's `/?product=firefox` share same key; attacker's request returns broken redirect that poisons the cached key | Nginx-style URL-decode before keying; backend doesn't decode path |
| **Case normalization** | Cache lowercases key; attacker sends `/ADMIN` to poison the cache for `/admin` | Case-insensitive cache key; case-sensitive origin routing |
| **Scheme normalization** | Cache ignores HTTP vs. HTTPS in key; attacker poisons via HTTP to affect HTTPS users | Cache key excludes scheme; both protocols reach same cache |

### §6-3. Unkeyed Port

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Port-based redirect poisoning** | Attacker sends `Host: example.com:1337` — cache key includes only hostname; origin generates redirect to `example.com:1337/path`; cached redirect sends all users to non-existent port (DoS) or attacker-controlled port | Cache strips port from Host header in key; origin includes port in redirect Location |

---

## §7. Malformed Headers & Error Response Caching (CPDoS)

Cache-Poisoned Denial of Service (CPDoS) attacks force the origin to generate an **error response** via malformed requests, then get that error cached for all users.

### §7-1. HTTP Header Oversize (HHO)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Oversized header injection** | Attacker adds large junk header (e.g., `X-Oversized: AAAA...` at 10KB) — cache accepts and forwards (limit: 16KB); origin rejects (limit: 8KB) with 400 error; cache stores 400 for all users | Cache header size limit > origin header size limit |
| **Accumulated header size** | Multiple moderate-sized headers that individually pass cache validation but collectively exceed origin limit | Origin computes total header size; cache checks per-header |

### §7-2. HTTP Meta Character (HMC)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Control character injection** | Header value contains `\r`, `\n`, `\a`, or other meta characters — cache forwards; origin returns 400 error; cached error serves as DoS | Cache tolerates meta characters in headers; origin strictly validates |
| **Null byte in header** | `X-Custom: value\x00garbage` — cache passes; origin truncates or rejects | Inconsistent null-byte handling between layers |

### §7-3. HTTP Method Override (HMO-DoS)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Method override to blocked method** | `GET /resource` with `X-HTTP-Method-Override: DELETE` — cache keys on GET; origin processes as DELETE and returns 405 Method Not Allowed; cached 405 blocks all GET requests | Origin respects method override; cache stores error response for original method |

### §7-4. CRLF Injection → Response Splitting Cache Poisoning

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Header injection via CRLF** | Attacker injects `\r\nX-Injected: value` or `\r\n\r\n<html>malicious</html>` into a header — origin reflects injected headers/body; cache stores the split/modified response | Origin reflects header values without CRLF sanitization; cache stores full response |
| **Set-Cookie injection** | CRLF injection adds `Set-Cookie: session=attacker` to cached response; all users receive attacker's session cookie | Same as above, targeting cookie headers |

---

## §8. Framework & Application-Level Cache Mutations

These mutations target **application-internal caching mechanisms** rather than CDN or reverse proxy caches. Because internal caches often lack the security hardening of CDN products, they present unique attack surfaces.

### §8-1. Internal Cache Fragment Poisoning

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Fragment caching poisoning** | Application-level caches (e.g., WordPress WP Rocket) cache individual HTML fragments rather than full pages; poisoning a fragment affects every page that includes it | Application uses fragment/partial caching; fragments are keyed differently from full pages |
| **Blind internal poisoning** | Error on an internally-cached page (e.g., admin panel accessible only internally) poisons the fragment; the poisoned fragment is then served on public pages that include it | Internal pages share fragment cache with public pages |

### §8-2. Framework Routing Cache Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Next.js Pages Router poisoning** | Crafted request with specific headers/params poisons the internal Next.js cache for a server-side rendered route; all subsequent users receive poisoned HTML (CVE-2024-46982) | Next.js pages router with SSR; internal cache enabled (default) |
| **Next.js RSC payload confusion** | Request for HTML content returns React Server Component (RSC) payload instead due to missing Vary header for RSC-distinguishing header; cached RSC payload served as HTML breaks page rendering (CVE-2025-49005) | Next.js 15.3.0–15.3.2; CDN does not distinguish RSC vs. HTML requests |
| **Middleware authorization bypass** | `x-middleware-subrequest` header bypasses Next.js middleware auth checks; combined with cache poisoning, unauthenticated content gets cached for authenticated routes (CVE-2025-29927) | Next.js middleware-based auth; attacker adds internal header |

### §8-3. Framework Race Condition Cache Poisoning

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Race-condition stale cache** | Exploiting a framework's intended race condition in cache invalidation to serve stale/poisoned content during the invalidation window | Framework uses optimistic cache update with race window |

---

## §9. Client-Side & Browser Cache Mutations

These mutations target the **victim's browser cache** rather than shared server-side caches. The impact is typically limited to a single user but can be persistent.

### §9-1. Client-Side Desync → Browser Cache Poisoning

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CSD resource poisoning** | Attacker desyncs victim's browser HTTP/1.1 connection via client-side desync; uses desynced connection to store malicious redirect in browser cache for a static resource (e.g., `/main.js`); subsequent page loads execute attacker-controlled script | Target server supports HTTP/1.1 (no H2); vulnerable to client-side desync; victim visits attacker-controlled page first |
| **CSD + resource import** | After desyncing, attacker triggers resource import from target domain; desynced response poisons browser cache entry for that resource | Same as above; specific resource import timing required |

### §9-2. Response Queue Poisoning → Cache Cross-Contamination

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **H2.TE response queue poisoning** | HTTP/2 to HTTP/1.1 downgrade with TE smuggling desyncs the response queue; front-end persistently maps responses to wrong requests; victims receive each other's responses | Front-end supports H2; back-end uses H/1.1; TE header not stripped during downgrade |
| **CL.TE/TE.CL queue poisoning** | Classic request smuggling poisons the response queue; if responses are cached, the cache stores another user's response under the attacker's requested URL | Any HRS vulnerability on a caching front-end |

### §9-3. Service Worker Cache Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SW scope poisoning** | If an attacker can register or modify a service worker (via XSS or cache poisoning of the SW registration script), they can persistently intercept and modify all requests within the SW scope | Service worker registration endpoint cacheable; or SW script import poisonable |
| **Stale SW cache** | Legitimate service worker caches a poisoned response; even after server-side fix, SW continues serving poisoned content until cache expires or user clears data | Application uses service worker with aggressive caching strategy |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Required Architecture | Primary Mutation Categories | Impact |
|----------|----------------------|---------------------------|--------|
| **Stored XSS via CDN cache** | CDN + origin with reflected input | §3 (unkeyed headers) + §4 (unkeyed params) + §6 (key normalization) | Mass XSS affecting all visitors |
| **Account Takeover via WCD** | CDN with static rules + REST origin | §1 (path structure) + §2 (normalization) | Auth token theft → ATO |
| **Cache-Poisoned DoS** | Any caching layer + error-caching | §7 (CPDoS: HHO/HMO/HMC) + §6 (unkeyed port) | Website unavailability |
| **Resource Import Hijacking** | CDN + origin reflecting host headers | §3-2 (resource import) + §1/§2 (path poisoning) | Persistent malware delivery |
| **Framework-Internal Poisoning** | Next.js / WP Rocket / internal cache | §8 (framework caches) | XSS, DoS, auth bypass |
| **Browser-Persistent Attack** | HTTP/1.1 origin + victim browser | §9 (client-side desync + browser cache) | Per-user persistent compromise |
| **WAF/ACL Bypass** | WAF + origin with path confusion | §1 + §2 (path mutations) | Access control circumvention |
| **Response Queue Hijack** | H2 front-end + H/1.1 back-end + cache | §9-2 (queue poisoning) | Cross-user data leakage |

---

## CVE / Bounty Mapping (2019–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-4 + §2-2 (wildcard rule + encoded path escape) | ChatGPT Wildcard WCD (2024) | Account takeover via auth token theft; $6,500 bounty |
| §8-2 (Next.js pages router internal cache) | CVE-2024-46982 | DoS + potential stored XSS; patched in Next.js 13.5.7 / 14.2.10 |
| §8-2 (Next.js RSC Vary header) | CVE-2025-49005 | Cache poisoning via RSC payload confusion; patched in 15.3.3 |
| §8-2 (Next.js middleware bypass) | CVE-2025-29927 | Middleware auth bypass; chainable with cache poisoning |
| §7-1 (HHO CPDoS) | CVE-2019-0941 (IIS) | Denial of service via oversized header; Microsoft patch |
| §7 (CPDoS variants) | Amazon CloudFront CPDoS (2019) | DoS; Amazon stopped caching 400 errors by default |
| §5-1 (Fat GET) | GitHub cache poisoning (2020) | Parameter override in abuse reporting; fixed |
| §3-1 (X-Forwarded-Host) | Red Hat Keycloak (2018) | Stored XSS via poisoned resource imports |
| §1-1 (classic WCD) | ChatGPT WCD original (2023) | Account takeover via `.css` extension appending |
| §6-1 + §2 (Azure cache key confusion) | OpenAI/Azure (2024) | Arbitrary cache poisoning + DoS on Azure-hosted services |
| §7-3 (HMO CPDoS) | Play Framework (2019) | DoS via method override; patched in 1.5.3 / 1.4.6 |

---

## Detection Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **Param Miner** (Burp Extension) | Offensive | Unkeyed inputs (§3, §4) | Automated header/cookie/parameter guessing; observes response differences to identify unkeyed inputs |
| **CacheKiller** (Burp Extension) | Offensive | URL parsing discrepancies (§1, §2) | Tests delimiter handling, normalization behavior, and path confusion across CDN/origin pairs |
| **Web Cache Vulnerability Scanner (WCVS)** (CLI) | Offensive | Multi-technique (§1–§7) | Go-based CLI with crawler; tests poisoning and deception techniques with built-in payloads |
| **autoPoisoner** (CLI) | Offensive | Unkeyed headers (§3) | Automated domain-wide header injection testing at scale |
| **Toxicache** (CLI) | Offensive | Multi-injection (§3, §4, §7) | Go-based URL list scanner testing multiple injection techniques |
| **HCache** (Research) | Offensive/Research | WCP detection at scale (§3–§7) | Systematic test case generation; multi-threaded testing; academic methodology from ACM CCS 2024 |
| **WCD Scanner** (Burp Extension) | Offensive | Web cache deception (§1) | Tests path-based deception via extension appending and delimiter abuse |
| **Nuclei** (CLI) | Offensive | Template-based scanning | Community templates for known cache poisoning patterns |
| **Cache Deception Armor** (CDN Feature) | Defensive | WCD prevention (§1) | Cloudflare feature that validates the response Content-Type matches the cached extension |
| **Varnish VCL** (Configuration) | Defensive | Cache key hardening (§3–§6) | Custom VCL rules to strip/normalize dangerous headers and parameters |

---

## Summary: Core Principles

### The Fundamental Property

Web cache attacks exist because **caching is inherently a simplification**. A cache key is a lossy compression of the full HTTP request — it must discard some information to be useful (otherwise every unique request would miss the cache). The discarded information creates the attack surface: any request component that **influences the response but is not in the cache key** is an exploitable "unkeyed input." Similarly, any difference in how the cache and origin **interpret the same request** creates a "parser discrepancy" that can be weaponized.

### Why Incremental Fixes Fail

Each fix addresses a specific mutation — stripping one header, blocking one delimiter, normalizing one encoding — but the combinatorial space of (servers x CDNs x frameworks x configurations) is enormous. A fix on Cloudflare doesn't apply to Akamai; a fix in Nginx doesn't apply to IIS. More fundamentally, many discrepancies arise from **RFC ambiguities** (e.g., whether semicolons are parameter delimiters, how to handle encoded path traversal, whether GET bodies are valid) that different implementations resolve differently. Until HTTP parsing is fully standardized and uniformly implemented, new discrepancies will continue to emerge.

### Structural Solutions

1. **Cache key = full request semantics**: Include all response-influencing components in the cache key, or ensure they are stripped before reaching the origin.
2. **Parse-then-cache consistency**: The cache must parse the URL using the *exact same rules* as the origin — or must cache based on the origin's parsed interpretation, not its own.
3. **Response-driven cacheability**: Only cache responses explicitly marked as cacheable (`Cache-Control: public`); never infer cacheability from URL shape (extension, directory prefix).
4. **Content-Type validation**: Verify that the response `Content-Type` matches the URL's implied type before caching (Cloudflare's Cache Deception Armor approach).
5. **Sensitive endpoint protection**: Mark all authenticated/personalized responses with `Cache-Control: no-store, private` at the application layer, regardless of URL structure.

---

## References

- PortSwigger Research — *Practical Web Cache Poisoning* (2018): https://portswigger.net/research/practical-web-cache-poisoning
- PortSwigger Research — *Web Cache Entanglement: Novel Pathways to Poisoning* (2020): https://portswigger.net/research/web-cache-entanglement
- PortSwigger Research — *Gotta Cache 'em All: Bending the Rules of Web Cache Exploitation* (2024): https://portswigger.net/research/gotta-cache-em-all
- Mirheidari et al. — *Cached and Confused: Web Cache Deception in the Wild*, USENIX Security 2020
- Mirheidari et al. — *Web Cache Deception Escalates!*, USENIX Security 2022
- Guo et al. — *Internet's Invisible Enemy: Detecting and Measuring Web Cache Poisoning in the Wild*, ACM CCS 2024: https://dl.acm.org/doi/10.1145/3658644.3690361
- Nguyen, Lo Iacono, Federrath — *Your Cache Has Fallen: Cache-Poisoned Denial-of-Service Attack*, ACM CCS 2019: https://cpdos.org/
- Harel — *ChatGPT Account Takeover - Wildcard Web Cache Deception* (2024): https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html
- zhero_web_security — *Next.js, Cache, and Chains: The Stale Elixir* (2024): https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir
- Berto et al. — *A Methodology for Web Cache Deception Vulnerability Discovery*, CLOSER 2024
- PortSwigger Web Security Academy — *Web Cache Poisoning*: https://portswigger.net/web-security/web-cache-poisoning
- PortSwigger Web Security Academy — *Web Cache Deception*: https://portswigger.net/web-security/web-cache-deception
- Hackmanit — *Web Cache Vulnerability Scanner*: https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
- HCache Research Tool: https://github.com/phantomnothingness/HCache

---

*This document was created for defensive security research and vulnerability understanding purposes.*
