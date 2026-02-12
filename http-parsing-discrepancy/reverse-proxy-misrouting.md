# Reverse Proxy Misrouting — Mutation/Variation Taxonomy

---

## Classification Structure

Reverse proxy misrouting encompasses all attacks that exploit discrepancies between how a reverse proxy (or load balancer, CDN, service mesh sidecar) interprets, transforms, and routes an HTTP request versus how the backend/origin server processes that same request. The fundamental precondition is a **multi-component architecture** where at least two systems parse the same request independently, and where differences in parsing, normalization, or routing logic create exploitable gaps.

This taxonomy organizes the attack surface along three axes:

**Axis 1 — Mutation Target (Primary Structure):** The structural component of the request being manipulated to induce misrouting. This axis defines the main body of the document: path normalization, host/authority, HTTP/2 pseudo-headers, URL encoding, routing headers, TLS/SNI layer, proxy configuration rules, and connection/protocol semantics.

**Axis 2 — Discrepancy Type (Cross-Cutting):** The nature of the parsing/interpretation mismatch between the proxy and backend. Every technique exploits one of these discrepancy types regardless of the mutation target.

| Discrepancy Type | Description |
|---|---|
| **Normalization Differential** | Proxy and backend apply different path normalization rules (dot-segments, case, slashes) |
| **Decoding Differential** | Different URL-decoding stages (single vs. double decode, percent-encoding interpretation) |
| **Routing Logic Bypass** | Routing decision uses a different view of the request than the backend's actual processing |
| **Protocol Conversion Confusion** | HTTP/2→HTTP/1.1 (or other protocol downgrades) introduces semantic loss or injection points |
| **Configuration Scope Mismatch** | ACL/auth rules apply to a scope that doesn't match the backend's resource mapping |
| **Semantic Ambiguity** | Ambiguity in RFC specifications leads to divergent but "correct" implementations |

**Axis 3 — Attack Scenario (Mapping):** Described in §8, mapping mutation categories to real-world exploitation outcomes.

---

## §1. Path Normalization Differentials

The most prolific category of reverse proxy misrouting. Different HTTP servers normalize URL paths in fundamentally incompatible ways — dot-segments, trailing slashes, encoded characters, and special sequences are resolved at different stages and with different rules between the proxy and backend.

### §1-1. Dot-Segment Resolution Discrepancy

When the proxy and backend differ in whether, when, and how they resolve `/../` and `/./` sequences, an attacker can craft a path that the proxy considers safe but the backend resolves to a restricted resource.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Proxy-preserves / Backend-resolves** | Proxy forwards `/public/../admin/secret` as-is; backend normalizes to `/admin/secret` | Proxy performs ACL check on literal path; backend normalizes before routing |
| **Backend-preserves / Proxy-resolves** | Proxy normalizes path before ACL check, but backend receives the pre-normalized form via a different header or variable | Backend uses raw `REQUEST_URI` rather than the proxy-normalized path |
| **Partial dot-segment resolution** | Proxy resolves `/../` but not `/..;/` or `/%2e%2e/`; backend resolves all forms | Backend treats encoded or decorated dot-segments as equivalent to literal `..` |
| **Asymmetric `/..` handling** | Apache resolves `/path/..` to `/` but Nginx treats trailing `/..` as a literal path component | Multi-tier architecture with Apache behind Nginx or vice versa |

Example: `GET /public/..%2fadmin/config HTTP/1.1` — Nginx proxy sees literal path, applies ACL for `/public/`; Apache backend decodes `%2f` to `/`, resolves `..` → routes to `/admin/config`.

### §1-2. Semicolon-Based Path Parameter Confusion

Java application servers (Tomcat, Jetty, WildFly) treat semicolons in paths as parameter delimiters (per Servlet spec), stripping everything between `;` and the next `/`. Most reverse proxies treat the semicolon as an ordinary character.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Tomcat `/..;/` traversal** | Proxy sees `/app/..;/manager/html` as a path under `/app/`; Tomcat strips `;/` → resolves `/app/../manager/html` → `/manager/html` | Nginx/Apache proxy + Tomcat backend |
| **Jetty `;param` stripping** | Path `/restricted;.css` matches proxy's static-file rule but Jetty routes to `/restricted` | Jetty backend with proxy caching or ACL based on extension |
| **Arbitrary parameter injection** | `/path;jsessionid=ATTACKER_VALUE/resource` bypasses path-based ACL while injecting session parameters | Java backend that processes path parameters before routing |

Example: `GET /safe/..;/admin/dashboard HTTP/1.1` — Proxy ACL matches `/safe/` prefix → allowed; Tomcat normalizes to `/admin/dashboard`.

### §1-3. Trailing Slash and Slash Normalization

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Missing trailing slash redirect** | Proxy forwards `/admin` to backend; backend redirects to `/admin/` with sensitive info in redirect body | Proxy ACL blocks `/admin/` but not `/admin` (or vice versa) |
| **Double-slash collapse differential** | Proxy preserves `//admin/secret`; backend collapses to `/admin/secret` | Backend applies slash deduplication; proxy does not |
| **Backslash-to-forward-slash conversion** | Proxy preserves `\admin`; IIS/Windows backend converts to `/admin` | Windows-based backend behind Linux proxy |

### §1-4. Fragment and Query String Boundary Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Fragment in URI path** | Proxy forwards `GET /admin#/../public HTTP/1.1`; some backends strip `#fragment` before routing, others include it | Envoy historically did not strip fragment from URI path (GHSA-r222-74fw-jqr9) |
| **Query string path injection** | Path `/safe?/../../admin` — proxy extracts path as `/safe`, backend treats query as path continuation | Backend framework with unusual query string parsing |
| **Null byte truncation** | `/admin%00.jpg` — proxy sees `.jpg` extension (static file), backend truncates at null byte → routes to `/admin` | Legacy backends (older PHP, C-based handlers) |

---

## §2. Host / Authority Header Manipulation

Reverse proxies route requests to backend pools based on the `Host` header (HTTP/1.1) or `:authority` pseudo-header (HTTP/2). When the proxy trusts this value without validation, attackers can redirect requests to arbitrary internal or external destinations.

### §2-1. Direct Host Header Misrouting (Routing-Based SSRF)

The most straightforward form: the proxy uses the `Host` header to select the backend, and an attacker supplies an internal hostname or IP.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Internal IP routing** | `Host: 169.254.169.254` or `Host: 10.0.0.1` — proxy routes to cloud metadata service or internal host | Proxy forwards to whatever host is specified without allowlist |
| **Internal hostname routing** | `Host: admin-panel.internal` — proxy resolves internal DNS and routes request | Proxy has DNS access to internal network; no host validation |
| **Port-based routing escape** | `Host: internal-service:8080` — proxy routes to non-standard port on internal service | Proxy parses and respects port in Host header for routing |
| **Absolute-URL request line** | `GET http://internal.host/admin HTTP/1.1` — some proxies route based on request-line URL rather than Host header | Proxy supports absolute-form request targets (RFC 7230 §5.3.2) |

Example: `GET / HTTP/1.1\r\nHost: 169.254.169.254\r\n` → Proxy routes to AWS metadata endpoint → attacker retrieves IAM credentials.

### §2-2. Host Header Override via Auxiliary Headers

When the proxy preserves the original `Host` for routing but the backend trusts an override header for its own routing or URL generation.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **X-Forwarded-Host injection** | Proxy routes via `Host`; backend constructs URLs/redirects using `X-Forwarded-Host: attacker.com` | Backend framework trusts `X-Forwarded-Host` for URL generation |
| **X-Host / X-Original-URL** | Some backends accept `X-Host`, `X-Original-URL`, or `X-Rewrite-URL` to override the routing target | IIS URL Rewrite, certain ASP.NET configurations |
| **Forwarded header RFC 7239** | `Forwarded: host=attacker.com` — standardized header that some backends prioritize over `Host` | Backend uses the `Forwarded` header for host determination |
| **Duplicate Host headers** | First `Host` header used by proxy for routing; second `Host` header used by backend | Different implementations pick first vs. last header |

### §2-3. Host Header Poisoning via Domain Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Subdomain injection** | `Host: expected.com.attacker.com` — proxy validates prefix; DNS resolves to attacker | Prefix-based host validation (not suffix/exact) |
| **Port injection as host** | `Host: expected.com:@attacker.com` — URL parser confusion between userinfo and host components | Backend that parses Host header as a URL |
| **Null byte injection** | `Host: allowed.com%00.attacker.com` — proxy validates `allowed.com`; backend sees different value after null | Legacy C-based string handling in backend |
| **Tab/space injection** | `Host: allowed.com\tattacker.com` — proxy reads first token, backend reads second | Different whitespace handling in header parsing |

---

## §3. HTTP/2 Pseudo-Header Exploitation

HTTP/2 introduces four mandatory pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`) that replace the HTTP/1.1 request line and `Host` header. When a proxy downgrades HTTP/2 to HTTP/1.1 for the backend, the conversion process creates novel injection points.

### §3-1. `:scheme` Pseudo-Header Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Absolute-URL injection via :scheme** | Setting `:scheme` to `http://internal.host/path?` causes HAProxy to construct request line: `GET http://internal.host/path?://original.host/ HTTP/1.1` | HAProxy 2.x — places non-standard :scheme values directly in request line |
| **Virtual host access via :scheme** | `:scheme: https://vhost2.internal` — backend proxy parses the full URL from request line, routes to different virtual host | Backend that supports absolute-form request targets |
| **Protocol confusion via :scheme** | `:scheme: gopher` or `:scheme: file` — backend interprets as different protocol handler | Backend with multi-protocol URL handling |

### §3-2. `:authority` / `:path` Mismatch

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Authority-path divergence** | `:authority: public.com` (passes proxy ACL) + `:path: /admin` — proxy routes by authority; backend routes by path | Proxy ACL is authority-based; backend is path-based |
| **CRLF injection in pseudo-headers** | `:path: /safe\r\nHost: internal\r\n\r\nGET /admin` — HTTP/2 binary framing doesn't restrict header values the same way | Proxy that doesn't sanitize pseudo-header values during downgrade |
| **Path injection via :authority** | `:authority: host/../../admin` — if proxy concatenates authority and path unsafely during downgrade | Improper HTTP/2 → HTTP/1.1 reconstruction |

### §3-3. `:method` Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Whitespace/special char in :method** | Envoy (≤1.18.3) allows arbitrary values with special characters in `:method` — injecting `GET /admin HTTP/1.1\r\n` as the method | Envoy proxy with insufficient pseudo-header validation |
| **Method override for routing** | `:method: OPTIONS` passes proxy ACL (CORS preflight allowed) but backend processes as `POST` via `X-HTTP-Method-Override` header | Backend that honors method override headers |

---

## §4. URL Encoding / Decoding Differentials

The most mechanistically precise category: exploiting differences in when and how URL percent-encoding is decoded, re-encoded, or preserved across the proxy-backend boundary.

### §4-1. Double Decoding

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Proxy-decodes + Backend-decodes** | `%252e%252e` → proxy decodes once to `%2e%2e` → forwards → backend decodes to `..` | Proxy performs one decode pass; backend performs another (CVE-2025-0108 pattern) |
| **Rewrite-induced double decode** | Proxy URL rewrite module decodes path for rule matching, re-encodes for forwarding; backend decodes again | IIS URL Rewrite, Apache mod_rewrite with B flag missing |
| **Selective character double decode** | Only specific characters like `/` (`%2f` → `%252f`) are double-encoded; backend decodes both layers | Proxy normalizes `%2f` but preserves `%252f` |

Example (CVE-2025-0108): `GET /unauth/%2e%2e/php/ztp_gate.php HTTP/1.1` — Nginx decodes to `/unauth/../php/...` but does not resolve dot-segments for non-matching location; Apache decodes and resolves → accesses PHP handler with auth disabled.

### §4-2. Encoded Slash and Special Character Handling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Encoded forward slash (`%2f`)** | Proxy treats `%2f` as literal character in path component; backend decodes to `/` creating new path segments | Apache `AllowEncodedSlashes` directive; Envoy GHSA-4987-27fx-x6cf |
| **Encoded backslash (`%5c`)** | Proxy ignores `%5c`; Windows/IIS backend converts to `\` → path separator | Windows backend behind Linux proxy |
| **Encoded dot (`%2e`)** | `/path/%2e%2e/secret` — proxy sees encoded dots as regular characters; backend decodes → traversal | Backend that normalizes after URL-decoding |
| **Non-standard encoding** | Overlong UTF-8 sequences (`%c0%af` for `/`), Unicode normalization (`%ef%bc%8f` fullwidth `/`) | Legacy backends with loose URL parsing |

### §4-3. Encoding Preservation vs. Normalization

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Proxy normalizes, backend expects raw** | Proxy decodes `%41` to `A`; backend ACL expects `%41` pattern and fails to match | Backend with regex-based path matching on raw URI |
| **Proxy preserves, backend normalizes** | Proxy forwards `%2e%2e%2fadmin` as-is; backend decodes → path traversal to `/admin` | Backend with aggressive URL normalization |
| **Re-encoding inconsistency** | Proxy decodes then re-encodes using different rules (e.g., uppercase vs. lowercase hex) | Caching layers that use encoded path as cache key |

---

## §5. Routing Headers and Metadata Manipulation

Beyond `Host`, many reverse proxies and backend frameworks use auxiliary headers or request metadata to make routing decisions.

### §5-1. Forwarded-For / Client-IP Based Routing

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **X-Forwarded-For ACL bypass** | Proxy applies IP-based ACL on `X-Forwarded-For`; attacker injects `X-Forwarded-For: 127.0.0.1` to appear as localhost | Proxy trusts client-supplied `X-Forwarded-For` without stripping |
| **X-Real-IP override** | Backend restricts admin access to specific IPs via `X-Real-IP`; attacker injects header pre-proxy | Proxy appends rather than replaces `X-Real-IP` |
| **Internal header trust** | `X-Envoy-Internal: true` or `X-Forwarded-Proto: https` — backend grants elevated access to "internal" requests | Envoy/Istio historically trusted `x-envoy-*` headers from external IPs (GHSA-ffhv-fvxq-r6mf) |

### §5-2. Custom Routing Headers

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **X-Original-URL / X-Rewrite-URL** | IIS backends process `X-Original-URL` to determine the actual request path, bypassing proxy-level ACLs | IIS with URL Rewrite behind any proxy |
| **X-Forwarded-Prefix injection** | Injecting `X-Forwarded-Prefix: /admin` causes backend to prepend prefix to all routes, changing which controller handles the request | Spring Boot applications that trust `X-Forwarded-Prefix` |
| **Backend routing headers** | Custom headers like `X-Backend-Server`, `X-Route-To`, `X-Upstream` that some load balancers expose for debugging | Proxy leaks or honors debugging/routing headers in production |

### §5-3. Header Smuggling Through Proxy

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Underscore/hyphen confusion** | Proxy blocks `X-Internal-Auth` but backend (e.g., PHP's `$_SERVER`) converts underscores: `X_Internal_Auth` bypasses proxy rule | PHP, CGI backends that normalize header names |
| **Header name case sensitivity** | Proxy blocks `Transfer-Encoding` but allows `transfer-encoding` or `Transfer-encoding` — backend processes both | Proxy with case-sensitive header matching |
| **Hop-by-hop header abuse** | `Connection: X-Important-Header` — proxy strips `X-Important-Header` as hop-by-hop, removing security-critical metadata | Backend relies on header that proxy strips via Connection |
| **Line folding (obs-fold)** | Header value continues on next line with leading whitespace; proxy may interpret differently from backend | Legacy HTTP/1.1 obs-fold support differences |

---

## §6. TLS / SNI Layer Misrouting

When the proxy performs TLS-based routing (SNI routing, mTLS validation), discrepancies between TLS-layer identity and HTTP-layer identity create misrouting opportunities.

### §6-1. SNI-Based Routing Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SNI-Host mismatch** | TLS ClientHello SNI = `allowed.com` (passes TLS-level ACL); HTTP `Host: restricted-internal.com` (routes to different backend) | Proxy routes by SNI but backend routes by Host header |
| **Multiple SNI values** | Sending two SNI extensions — proxy reads first value for routing; backend reads second | Non-conformant TLS stacks that accept multiple SNI |
| **IP address in SNI** | RFC discourages IP in SNI but many implementations accept it; backend may interpret differently | SNI-based routing where IP addresses bypass hostname validation |
| **Null byte in SNI** | `allowed.com\x00.attacker.com` — proxy validates `allowed.com`; backend sees full string | Legacy TLS implementations with C-string handling |

### §6-2. TLS Termination Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **h2c smuggling** | Client sends HTTP/2 cleartext (h2c) upgrade request; proxy forwards it; backend interprets differently | Proxy that forwards `Connection: Upgrade, HTTP2-Settings` to backend (BishopFox h2cSmuggler) |
| **TLS-to-plaintext downgrade** | Proxy terminates TLS and forwards plaintext HTTP to backend; attacker on network can observe/modify | Missing TLS between proxy and backend (common in cloud) |
| **mTLS bypass via proxy** | Proxy terminates mTLS, validates client cert, then forwards as plain HTTP; backend trusts all proxy traffic | Backend loses client identity after proxy TLS termination |

---

## §7. Proxy Configuration and Mapping Rule Exploitation

Misrouting through misconfigured proxy rules — the routing logic itself is the vulnerable component, independent of parser differentials.

### §7-1. Path Mapping Misconfiguration

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Nginx off-by-slash** | `location /images { alias /data/images/; }` — request `/images../secret` resolves to `/data/secret` via path traversal outside alias | Missing trailing slash in `location` when using `alias` |
| **Overly broad proxy_pass** | `location /api/ { proxy_pass http://backend/; }` — request `/api/../admin` may normalize to `/admin` on backend | Nginx regex vs. prefix location matching ambiguity |
| **Open proxy misconfiguration** | `<Proxy "*">` in Apache mod_proxy — allows CONNECT/GET to any host through the proxy | Apache misconfiguration; CONNECT method enabled |
| **Regex capture group escape** | Proxy uses `location ~ /api/(.*)` and forwards `$1` to backend; attacker controls captured group content | Improper sanitization of regex-captured path components |

### §7-2. Ingress Controller / Service Mesh Misrouting

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Annotation injection (IngressNightmare)** | Attacker-controlled Ingress annotations inject arbitrary Nginx configuration directives including `proxy_pass` targets | Kubernetes ingress-nginx ≤1.11.4 / ≤1.12.0 (CVE-2025-1097, CVE-2025-1098, CVE-2025-24514) |
| **Istio x-envoy header manipulation** | External attacker sends `x-envoy-original-dst-host` to override Envoy's routing decision | Istio mesh without strict external header sanitization |
| **Service mesh path-based routing bypass** | Virtual service routes `/api/*` to service A; `/api/..%2f../internal` bypasses to different service | Service mesh that doesn't normalize paths before route matching |
| **Ingress class confusion** | Multiple ingress controllers with overlapping rules; attacker crafts request that matches unintended controller | Multi-controller Kubernetes clusters with ambiguous routing |

### §7-3. Cache-Proxy Routing Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Path mapping for cache deception** | CDN caches based on path extension (`.css`, `.jpg`); origin routes based on path prefix — `/account/settings/x.css` is cached as static but serves dynamic content | CDN with REST-style origin behind it (PortSwigger "Gotta Cache 'em All" research) |
| **Path delimiter confusion for caching** | `/account%23.css` — CDN interprets `%23` as part of path (caches it); origin decodes to `#` (ignores fragment, serves `/account`) | Different delimiter handling between cache and origin |
| **Cache key normalization mismatch** | CDN normalizes cache key differently from origin routing; two different URLs map to same cache key or vice versa | Cloudflare/Fastly/Varnish normalization rules vs. origin behavior |
| **Smuggled request cache poisoning** | Smuggled request on a keep-alive connection poisons cache entries for other users (CVE-2025-4366 Pingora pattern) | Proxy caching with HTTP/1.1 keep-alive; body consumption skipped on cache hits |

---

## §8. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Authentication Bypass** | Multi-tier proxy chain (Nginx→Apache→App) where auth is checked at proxy layer | §1-1, §1-2, §4-1 (double decoding to bypass auth location patterns) |
| **ACL / Authorization Bypass** | Proxy enforces path-based access rules; backend processes different path | §1 (all), §4-2, §5-3 (header smuggling past ACL) |
| **Routing-Based SSRF** | Load balancer/proxy routes by Host header to internal network | §2-1, §3-1, §6-1 (SNI mismatch) |
| **Cloud Metadata Access** | Cloud-deployed proxy that can route to `169.254.169.254` | §2-1 (Host header routing) |
| **Internal Network Pivoting** | Privileged proxy with access to internal network segments | §2-1, §7-1 (open proxy), §5-1 (IP header spoofing) |
| **Cache Poisoning / Deception** | CDN or cache proxy in front of origin | §7-3, §1-3 (slash normalization), §4-3 (encoding affects cache key) |
| **WAF Bypass** | WAF appliance/service as first proxy in chain | §1 (path confusion), §4 (encoding bypass), §5-3 (header smuggling) |
| **Kubernetes Cluster Takeover** | Ingress controller with injectable annotations | §7-2 (annotation injection → RCE → secrets access) |
| **Cross-Tenant Data Access** | Multi-tenant proxy routing to shared backend pools | §2-3 (host manipulation), §6-1 (SNI confusion) |

---

## §9. CVE / Bounty Mapping (2018–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §1-1 + §4-1 (double decode + dot-segment) | CVE-2025-0108 (Palo Alto PAN-OS) | CVSS 10.0. Full authentication bypass on firewall management interface via Nginx→Apache path confusion |
| §7-3 + smuggled body (cache poisoning) | CVE-2025-4366 (Cloudflare Pingora) | High severity. Request smuggling on cache hits; leaks visitor URLs to attacker via 301 redirect chain |
| §7-2 (annotation injection) | CVE-2025-1974 (Kubernetes ingress-nginx) | CVSS 9.8. Unauthenticated RCE → cluster takeover. 43% of cloud environments vulnerable |
| §7-2 (annotation injection) | CVE-2025-1097, CVE-2025-1098, CVE-2025-24514 (Kubernetes ingress-nginx) | Arbitrary Nginx config injection via annotation fields |
| §4-2 (encoded slash bypass) | GHSA-4987-27fx-x6cf (Envoy) | Path traversal via `%2f` and `%5c`; bypasses RBAC, ext_authz, rate limiting |
| §1-1 (dot-segment non-normalization) | GHSA-xcx5-93pw-jw2w (Envoy) | Path traversal via `/../` bypasses access control and rate limiting |
| §1-4 (fragment in path) | GHSA-r222-74fw-jqr9 (Envoy) | `#fragment` in URI bypasses path-based authorization |
| §5-1 (x-envoy header trust) | GHSA-ffhv-fvxq-r6mf (Envoy/Istio) | External attacker sends `x-envoy-*` headers; treated as internal traffic |
| §1-2 (semicolon path param) | CVE-2018-11759 (Apache Tomcat mod_jk) | Reverse proxy ACL bypass via Tomcat path parameter handling |
| §1-1 + §4-2 (path normalization) | CVE-2018-1271 (Spring Framework) | Directory traversal via reverse proxy path confusion |
| §1-1 + §1-2 | CVE-2018-3760, CVE-2018-7212 (Ruby on Rails, Sinatra) | Path normalization 0-days chained for RCE in production |
| §4-1 (encoding differential) | CVE-2024-27306, CVE-2024-39573 (Apache HTTP Server) | Incorrectly encoded request URLs bypass authentication via mod_proxy |
| §2-1 (Host-based SSRF) | Shopify HackerOne #429617 | Reverse proxy misrouting to internal services |
| §2-1 (Host-based SSRF) | Yahoo Bug Bounty | $15,000. Routing-based SSRF via Host header manipulation |
| §2-1 + §7-1 (Host SSRF + routing) | DoD networks (Cracking the Lens) | $30,000+. Systematic exploitation of reverse proxy misrouting across military infrastructure |
| §7-1 (Nginx off-by-slash) | Multiple HackerOne reports | Path traversal via misconfigured Nginx alias directives |

---

## §10. Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Burp Suite + Collaborator Everywhere** (Extension) | Host header SSRF, backend decloaking | Injects payloads into headers to identify backend routing behavior; OOB detection via Collaborator |
| **h2cSmuggler** (BishopFox) | h2c upgrade smuggling | Tests HTTP/2 cleartext upgrade paths through proxies to bypass access controls |
| **weird_proxies** (GrrrDog, Wiki/Labs) | Nginx, Apache, HAProxy, Varnish, Traefik, Envoy, CDNs | Cheat sheet + lab environments documenting behavioral differences across proxy implementations |
| **MisConfig_HTTP_Proxy_Scanner** (lijiejie) | Misconfigured forward/reverse proxies | Scans for open proxy misconfigurations enabling SSRF and internal access |
| **PortSwigger Reverse Proxy Detector** (Burp Extension) | Proxy detection | Identifies presence and type of reverse proxy via response analysis |
| **Tomcat-ReverseProxy-Bypasser** (Ravaan21) | Tomcat behind proxy | Automates `/..;/` and semicolon-based path traversal attempts against Tomcat+proxy architectures |
| **Nuclei** (ProjectDiscovery) | Proxy misconfigurations, known CVEs | Template-based scanning for reverse proxy vulnerabilities including open proxy, path traversal, host routing |
| **T-Reqs** (HTTP Fuzzer) | HTTP parser differentials | Grammar-based HTTP fuzzer that generates mutated requests to find parsing discrepancies between components |
| **SmartScanner** | Path traversal + proxy bypass | Automated testing of path traversal through Nginx/Apache restriction bypasses |
| **ffuf** (Fast Web Fuzzer) | Path fuzzing through proxy | High-speed directory/path bruteforcing useful for discovering proxy-backend normalization differences |

---

## §11. Summary: Core Principles

**The root cause of all reverse proxy misrouting is semantic fragmentation.** Every component in a multi-tier web architecture independently parses, normalizes, and interprets the same HTTP request. The HTTP specification (RFC 9110/9112) is intentionally flexible on many parsing details — path normalization order, percent-encoding equivalence, header precedence — and this flexibility becomes a vulnerability when two components in series make different choices. The request that the proxy evaluates for access control is not the same request the backend processes for routing.

**Incremental patches fail because the attack surface is combinatorial.** Each proxy implementation (Nginx, Apache, HAProxy, Envoy, Traefik, Caddy, cloud CDNs) combined with each backend server (Tomcat, IIS, Express, Spring, Django, Rails, PHP-FPM) creates a unique matrix of parsing behaviors. A fix for one proxy-backend pair does not protect another. Moreover, as architectures grow more layered — CDN → WAF → load balancer → ingress controller → service mesh sidecar → application server — each additional layer multiplies the number of potential parsing differentials. The introduction of HTTP/2 and HTTP/3 adds protocol conversion as yet another source of semantic loss.

**A structural solution requires parsing unification and defense-in-depth.** The proxy that enforces access control must see *exactly* the same request that the backend will process — achieved either by (1) normalizing the request into a canonical form at the outermost proxy and forwarding only the canonical form, or (2) having the backend re-validate all access control decisions rather than trusting the proxy's determination. In practice, the most resilient architectures combine both: aggressive normalization at the edge (decode, resolve dot-segments, strip path parameters, lowercase, validate Host against allowlist) with redundant authorization at the application layer that does not depend on path matching or header trust.

---

## References

- Assetnote Research: *Nginx/Apache Path Confusion to Auth Bypass in PAN-OS* (CVE-2025-0108), 2025
- Orange Tsai: *Breaking Parser Logic! Take Your Path Normalization Off and Pop 0days Out*, Black Hat USA 2018
- James Kettle (PortSwigger): *Cracking the Lens: Targeting HTTP's Hidden Attack-Surface*, Black Hat USA 2017
- James Kettle (PortSwigger): *Gotta Cache 'em All: Bending the Rules of Web Cache Exploitation*, Black Hat USA 2024
- GrrrDog: *weird_proxies — Reverse Proxies Cheatsheet*, GitHub Wiki
- Acunetix / Invicti: *A Fresh Look on Reverse Proxy Related Attacks*, 2021
- ProjectDiscovery: *Abusing Reverse Proxies, Part 1: Metadata* and *Part 2: Internal Access*, 2023
- Cloudflare: *Resolving a Request Smuggling Vulnerability in Pingora* (CVE-2025-4366), 2025
- ZeroPath: *Cache Poisoning Reloaded: Deep Dive into CVE-2025-4366*, 2025
- Wiz Research: *IngressNightmare — Unauth RCE in Kubernetes Ingress-NGINX* (CVE-2025-1974), 2025
- BishopFox: *h2cSmuggler — HTTP/2 Cleartext Smuggling*, GitHub
- Envoy Proxy Security Advisories: GHSA-xcx5-93pw-jw2w, GHSA-4987-27fx-x6cf, GHSA-r222-74fw-jqr9, GHSA-ffhv-fvxq-r6mf
- Invicti: *SSRF Vulnerabilities Caused by SNI Proxy Misconfigurations*
- Joshua Rogers: *proxy_pass: Nginx's Dangerous URL Normalization of Paths*, 2024

---

*This document was created for defensive security research and vulnerability understanding purposes.*
