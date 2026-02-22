# Next.js Framework Source-Level Security Analysis: Meta-Structural Extraction

> **Target**: Next.js 13.x – 16.x (App Router + Pages Router)
> **Sources**: github.com/vercel/next.js, nextjs.org/docs, nextjs.org/blog
> **Date**: 2026-02
> **CVEs Covered**: CVE-2025-66478 (CVSS 10.0), CVE-2025-29927 (CVSS 9.1), CVE-2024-34351, CVE-2024-46982, CVE-2025-57822, and 27+ total GHSA advisories

---

## Executive Summary

The fundamental security problem in Next.js stems from the **convergence of server and client execution contexts into a single codebase with implicit trust boundaries**. In traditional web architectures, server and client were separate applications with a clear HTTP boundary. Next.js blurs this line: Server Components and Client Components coexist in the same file, Server Actions are invoked through client-side POST requests, internal coordination headers flow alongside external request headers, and the build pipeline separates code based on string directives (`"use server"`, `"use client"`).

The 7 meta-patterns identified in this analysis all share a common structure: **implicit trust across explicit boundaries**. Server secrets leak into client bundles, internal headers are trusted from external requests, cache keys fail to distinguish response formats, and deserialization endpoints trust arbitrary payloads — patterns repeated across 13+ CVEs.

---

## Classification Structure

### Axis 1 — Meta-Patterns (Design-Level Structural Root Causes)

| Code | Meta-Pattern | Description |
|------|-------------|-------------|
| **MP1** | Abstraction Leakage | Server/client boundary hidden behind component abstractions, making security decisions opaque |
| **MP2** | Internal Header Trust | Client-controllable HTTP headers used as internal control signals without origin verification |
| **MP3** | Convention-as-Security | Security properties depend on naming conventions or configuration conventions rather than structural guarantees |
| **MP4** | Performance-Security Tradeoff | Aggressive caching, image optimization proxying, and static generation create security attack surfaces |
| **MP5** | Platform Assumption Mismatch | Designed for Vercel infrastructure; security assumptions break in self-hosted environments |
| **MP6** | Single-Layer Security Architecture | Structural fragility of using middleware as the sole authentication/authorization enforcement point |
| **MP7** | Deserialization Trust Boundary | RSC Flight protocol trusts client-supplied serialized data without validation |

### Axis 2 — Attack Outcome

| Outcome | Symbol |
|---------|--------|
| Remote Code Execution | **RCE** |
| Authentication/Authorization Bypass | **AUTHZ** |
| Server-Side Request Forgery | **SSRF** |
| Sensitive Data Exposure | **INFO** |
| Cache Poisoning / Denial of Service | **CACHE/DoS** |
| Cross-Site Scripting | **XSS** |

---

## §1. RSC Flight Protocol Deserialization Attacks (MP7)

The React Server Components "Flight" protocol represents a fundamentally new trust boundary in web applications. The server serializes component trees, closures, and references into a wire format consumed by the client runtime. When the deserialization path fails to validate the structural integrity of incoming payloads, the server can be tricked into executing arbitrary code.

### §1-1. Arbitrary Module Invocation (React2Shell)

**Design Philosophy**: The RSC Flight protocol uses directives like `$F` (function reference) and `$T` (temporary reference) to serialize server function references. This design enables transparent function invocation between server and client.

**Implementation Mechanism**: When a client sends a POST request to a Server Action endpoint, the Flight deserializer reconstructs objects from the payload. In vulnerable versions, the deserializer did not validate that references point to legitimately exported server functions, allowing an attacker to inject crafted `$F` directives referencing arbitrary module exports.

**Security Implication**: Unauthenticated RCE with no user interaction, low complexity. Default `create-next-app` App Router projects were vulnerable without additional configuration.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Arbitrary Module Invocation** | Attacker crafts Flight payload with `$F` directive referencing any server module and export, causing the server to invoke attacker-chosen functions with attacker-supplied arguments | React 19.x with `react-server-dom-webpack/turbopack/parcel`; any App Router endpoint | **RCE** |
| **Self-Reference Gadget (Source Leak)** | Crafted payload causes a server function to receive itself as an argument. When the function stringifies or processes this, the server returns the function's source code in the response | Server function that returns data including stringified arguments | **INFO** |
| **Infinite Loop DoS** | Specially crafted deserialization payload creates circular references or recursive resolution that hangs the server process, preventing all future HTTP requests | Any App Router endpoint accepting Flight payloads | **DoS** |

**Real-World Case**: CVE-2025-55182 (React, CVSS 10.0) / CVE-2025-66478 (Next.js). Actively exploited within hours of disclosure by China-nexus threat groups (confirmed by AWS Security Blog). Disclosed December 3, 2025; secret rotation advisory issued.

**Root Cause Analysis**: The RSC protocol's value proposition is transparent server-client function invocation. To achieve this transparency, the serialization format must express arbitrary module references, and the deserializer resolved these references without validating against an export allowlist. A classic case of convenience-driven design leading to remote code execution.

```
// Vulnerable path: Client → Flight payload → Server deserializer → Arbitrary module load → RCE
// Fix: Deserializer validates references against legitimate export list
```

**Source Location**: `react-server-dom-webpack/src/ReactFlightServer.js`, `react-server-dom-turbopack/src/ReactFlightServer.js`

---

## §2. Middleware Layer Attacks (MP2, MP6)

Next.js middleware (renamed to "Proxy" in v16) serves as the primary enforcement point for authentication, authorization, CSP headers, rate limiting, and request transformation. Middleware executes *before* route handlers, making it a critical security gate. When this gate is bypassed or manipulated, all downstream protections fail.

### §2-1. Internal Header Trust Exploitation

**Design Philosophy**: The framework uses internal headers for coordination between middleware invocations, load balancers, and routing layers. When these headers are trusted without origin validation, external attackers can spoof them.

**Implementation Mechanism** (`packages/next/src/server/web/adapter.ts`):

```typescript
// Vulnerable code (pre-patch)
export async function adapter(params) {
  const request = params.request
  const subrequest = request.headers.get('x-middleware-subrequest')

  if (subrequest) {
    const subrequestParts = subrequest.split(':')
    if (subrequestParts.includes(params.page)) {
      return NextResponse.next() // Middleware skipped entirely!
    }
  }
  return params.handler(request)
}
```

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Middleware Recursion Guard Spoofing** | Injecting `x-middleware-subrequest` header with the middleware path causes the framework to skip all middleware execution entirely | Next.js 11.1.4–15.2.2; single HTTP header injection | **AUTHZ** |
| **Recursion Depth Bypass** | `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` — exceeds MAX_RECURSION_DEPTH (5) to trigger middleware skip | Next.js 15.x (after recursion guard addition) | **AUTHZ** |

**Real-World Case**: CVE-2025-29927 (CVSS 9.1). Disclosed March 2025 by zhero_web_security. A single header addition bypasses all middleware-based authorization. Since official documentation, tutorials, and starter templates explicitly encourage middleware as the primary authentication layer, all affected applications were fully exposed. ProjectDiscovery released Nuclei detection templates within days.

**Patch**: Cryptographic validation using a randomized key generated at build time. External requests have `x-middleware-subrequest` stripped at the server entry point.

**Root Cause Analysis**: HTTP headers have no built-in origin authentication. Any mechanism using a client-controllable channel as a security-critical internal signal is fundamentally vulnerable to spoofing. This is the same vulnerability class as Apache's `X-Original-URL` / `X-Rewrite-URL` header trust and various frameworks trusting `X-Forwarded-For` for access control.

### §2-2. Route Matching and Path Confusion

Middleware path matching and the application router process URLs through different code paths. The middleware matcher uses a pattern-matching library while the router uses its own route resolution logic. These normalization differences create attack opportunities.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Pathname-Dependent Auth Bypass** | URL encoding, trailing slashes, case variations, or normalization differences evade middleware pattern matching while still reaching the target route | Next.js 9.5.5–14.2.14; middleware using string-based path checks | **AUTHZ** |
| **API Route Direct Access** | Middleware may only guard page routes but not API routes (`/api/*`), allowing direct access to data endpoints that lack their own authorization checks | Applications relying solely on middleware for API auth | **AUTHZ** |
| **Data Route Bypass** | The same data is accessible through multiple URL patterns (HTML, RSC/JSON, `/_next/data/{BUILD_ID}/{page}.json`). Middleware protecting `/admin` may not protect `/_next/data/build-id/admin.json` | Pages Router + middleware authorization | **AUTHZ** |
| **Catch-All Route Confusion** | Dynamic route segments (`[...slug]`) and optional catch-all routes (`[[...slug]]`) may match unexpectedly, serving content from unintended handlers | Complex routing hierarchies with overlapping patterns | **AUTHZ** |

**Real-World Case**: CVE-2024-51479 (CVSS 7.5). Middleware pathname matching flaw in Next.js 9.5.5–14.2.14 enabling authorization bypass.

**Root Cause Analysis**: Middleware operates at the URL level, but security decisions require data-level context. URL multiplexing — where the same resource is accessible through multiple URL pathways — amplifies this mismatch. Next.js's decision to force middleware execution on `_next/data` routes even when excluded from matchers acknowledges this problem. The v16 rename from `middleware.ts` to `proxy.ts` intends to discourage its use as an authorization layer.

### §2-3. Middleware Response Manipulation

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **NextResponse SSRF via Location Header** | Passing a `Location` header through `NextResponse.next()` causes the framework to perform a server-side fetch to that URL and return the response | Next.js middleware reflecting request headers into NextResponse; self-hosted | **SSRF** |
| **CSP Header Injection** | Middleware bypass allows attackers to remove or modify Content-Security-Policy headers, weakening client-side XSS protections | Applications using middleware to inject CSP headers | **XSS** |

**Real-World Case**: CVE-2025-57822 (CVSS 6.5). SSRF via middleware Location header reflection in self-hosted deployments.

---

## §3. Server Action Attack Surface (MP1, MP2, MP5)

Functions declared with `"use server"` automatically create public HTTP endpoints. The official documentation explicitly acknowledges this: "a Server Action is a Server Function used in a specific way... Behind the scenes, Server Actions are always implemented using POST."

### §3-1. Host Header SSRF

**Design Philosophy**: When a Server Action calls `redirect()`, the framework uses the incoming request's `Host` header to construct the target URL.

**Implementation Mechanism** (`packages/next/src/server/app-render/action-handler.ts`):

```typescript
// Vulnerable code (pre-patch)
async function createForwardedActionResponse(req, res, host) {
  const proto = getRequestMeta(req, 'isSSL') ? 'https' : 'http'
  const fetchUrl = new URL(`${proto}://${host.value}${forwardedPath}`)
  // host.value derives from client-controllable Host header
  const response = await fetch(fetchUrl.toString(), { method: 'POST', ... })
}
```

Host resolution order: `x-forwarded-host` → `host` → `req.headers.host` — all client-controllable.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Host Header Redirect SSRF** | Spoofing the `Host` header causes the server to fetch from an attacker-controlled host; the attacker's server redirects to internal resources (AWS metadata, etc.) | Next.js < 14.1.1; self-hosted; Server Action with relative path redirect | **SSRF** |
| **Next-Action Header SSRF** | Requests with `Next-Action` header beginning with a leading slash cause the server to fetch the specified path, enabling blind SSRF to internal services | Next.js < 14.1.1; Server Actions enabled | **SSRF** |

**Real-World Case**: CVE-2024-34351 (CVSS 7.5). Discovered by Assetnote, published as "Digging for SSRF in NextJS Apps." AWS metadata endpoint (`http://169.254.169.254`) IAM credential theft demonstrated.

**Key Pattern — Platform Assumption Mismatch**: Vercel's edge infrastructure strips and validates the `Host` header, making the same code safe on Vercel but vulnerable when self-hosted. The canonical "works on Vercel, vulnerable elsewhere" pattern.

### §3-2. CSRF Circular Validation

**Implementation Mechanism**:

```typescript
// CSRF validation: Origin header compared against Host header
function validateCSRF(originDomain, forwardedHost, host) {
  if (originDomain === host || originDomain === forwardedHost) return true
  return false
}
```

Both `Origin` and `Host` are client-supplied. When an attacker sets both to the same value, the comparison is tautologically true. Additional protection exists via the `Next-Action` custom header requirement (browsers enforce CORS for cross-origin requests with custom headers) and the `serverActions.allowedOrigins` configuration, but the default is an empty array.

Official blog: "Server Actions doesn't use CSRF tokens, therefore HTML sanitization is crucial."

### §3-3. Server Action ID Predictability

Server Actions are identified by hash-based IDs derived from file paths and export names. These IDs are visible in the client-side JavaScript bundle, network requests (`Next-Action` header), and RSC Flight payloads.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Action ID Enumeration** | Extracting action IDs from client JS bundle analysis or brute-forcing by hashing common file paths/export names | Any App Router application with Server Actions | **INFO/AUTHZ** |
| **Direct Invocation Without UI** | Sending POST requests directly with discovered action IDs bypasses client-side UI logic that was intended to gate access | Authorization relying solely on middleware | **AUTHZ** |
| **Closure Variable Capture** | Server functions closing over sensitive variables (API keys, DB connections) may expose them through deserialization artifacts or error messages | Server functions using variables from outer scope | **INFO** |

**Official Security Guide Acknowledgment**: "The `'use server'` annotation exposes an end point that makes all exported functions invokable by the client. The identifiers is currently a hash of the source code location. As long as a user gets the handle to the id of an action, it can invoke it with any arguments. As a result, those functions should always start by validating that the current user is allowed to invoke this action."

---

## §4. Data Serialization and State Exposure (MP1, MP3)

### §4-1. Server-Side Props Leakage

Next.js serializes server-side data into HTML responses as embedded JSON for client consumption. Any sensitive data included in this transfer is visible to anyone viewing the page source.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **__NEXT_DATA__ Exposure** | Return values from `getServerSideProps`/`getStaticProps` are embedded in a `<script id="__NEXT_DATA__">` tag. API keys, internal URLs, tokens, DB query results exposed | Props containing sensitive data; Pages Router | **INFO** |
| **RSC Payload Data Leak** | Props passed from Server Components to Client Components are serialized via the Flight protocol and transmitted to the browser | Sensitive data passed as props to Client Components | **INFO** |
| **Build ID Information Disclosure** | `BUILD_ID` is exposed in `__NEXT_DATA__` and static asset URLs, enabling direct access to data routes (`/_next/data/{BUILD_ID}/...`) | All Next.js applications | **INFO** |

**Official Security Guide Warning**:

```tsx
// DANGEROUS: Entire database row sent to client
export async function Page({ params: { slug } }) {
  const [rows] = await sql`SELECT * FROM user WHERE slug = ${slug}`;
  return <Profile user={rows[0]} />;
}

// SAFE: Only necessary fields returned via DTO
export async function getProfileDTO(slug) {
  const userData = await sql`SELECT * FROM user WHERE slug = ${slug}`;
  const currentUser = await getCurrentUser();
  return {
    username: canSeeUsername(currentUser) ? userData.username : null,
    phonenumber: canSeePhoneNumber(currentUser, userData.team) ? userData.phonenumber : null,
  };
}
```

### §4-2. Environment Variable Exposure

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **NEXT_PUBLIC_ Prefix Misuse** | Variables prefixed with `NEXT_PUBLIC_` are inlined as string literals into the client JS bundle at build time. Once built, permanently exposed | Sensitive variables with `NEXT_PUBLIC_` prefix | **INFO** |
| **Client-Side Reference of Server Variables** | Even without the `NEXT_PUBLIC_` prefix, server env vars referenced in client code paths are inlined during the build | Server env vars accidentally imported in client code | **INFO** |
| **Environment Variable Expansion** | In `.env` files, `NEXT_PUBLIC_URL=https://api.com/$SECRET_TOKEN` expands the secret and inlines it into client code | Variable expansion in env files | **INFO** |

**Root Cause Analysis**: Security properties are determined by a string prefix naming convention. No type system enforcement, no build-time warnings, no runtime validation. `NEXT_PUBLIC_DATABASE_PASSWORD` is silently exposed to every client. The simplest developer experience (prefix naming) was chosen over structural safety (separate config files, type-safe environment access, compile-time analysis).

### §4-3. State Serialization Injection

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **JSON Injection in Hydration Script** | `window.__PRELOADED_STATE__ = ${JSON.stringify(state)}` without escaping `<` characters allows `</script><script>malicious()</script>` injection | State containing user-controlled strings; missing `<` → `\u003c` escaping | **XSS** |

---

## §5. Caching Layer Attacks (MP4)

Next.js aggressively caches responses for performance — ISR, stale-while-revalidate, CDN caching, and RSC payload caching. Each caching mechanism introduces poisoning and deception opportunities. 5+ separate cache poisoning CVEs demonstrate this pattern.

### §5-1. Response Cache Poisoning

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Internal Header Cache Key Manipulation** | Injecting `x-now-route-matches` headers or `__nextDataReq` query parameters causes SSR routes to produce JSON responses instead of HTML. CDN caches the JSON under the same cache key | Next.js 13.5.1–14.2.9 Pages Router with non-dynamic SSR routes | **CACHE/DoS** |
| **204 Response Cache Poisoning** | Crafted requests trigger HTTP 204 responses; CDNs caching 204s replace valid pages with empty responses | Next.js 15.1.0–15.1.7 with ISR or CDN caching 204 responses | **CACHE/DoS** |
| **RSC/HTML Format Confusion** | Page requests receive RSC Flight payloads instead of HTML or vice versa. Missing `Vary` header causes CDN to cache wrong format | Next.js App Router 15.3.0–15.3.2 | **CACHE/DoS** |
| **x-middleware-prefetch Poisoning** | Adding this header to prefetch requests returns empty JSON `{}`. When cached by CDN, the page becomes inaccessible | Pages Router behind CDN | **CACHE/DoS** |
| **x-invoke-status Manipulation** | Internal header overwrites status code to 200, making error pages comply with standard cache rules | Pages Router behind CDN | **CACHE/DoS** |
| **Response Cache Batcher Race Condition** | The response-cache batcher deduplicates concurrent requests via a single shared Promise. During ISR revalidation windows, a timing-based race causes transient `pageProps` from one user's SSR response to leak into another user's cached response — no header injection required | Pages Router with response-cache batcher; concurrent requests during ISR revalidation | **INFO/CACHE** |

**Key Research**: zhero_web_security — "Next.js, Cache, and Chains: The Stale Elixir" (2024), "Next.js and Cache Poisoning: A Quest for the Black Hole" (2024-2025), "Eclipse on Next.js" (2025).

**Root Cause Analysis**: Cache key computation omits security-relevant request properties (internal headers, response format, authentication state). A ternary operator setting a minimum `revalidate=1` default violated the "non-dynamic SSR routes should not be cached" invariant by creating a cacheable response with `s-maxage=1`. Performance-first philosophy pushes security to a secondary concern.

---

## §6. Image Optimization and URL Handling SSRF (MP4, MP5)

### §6-1. Image Optimization SSRF

The `/_next/image` endpoint is a server-side proxy by design — it fetches client-specified URLs, optimizes them, and returns the result. This is architecturally an SSRF surface.

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Wildcard Image Domain** | `images.remotePatterns` with `**` patterns or overly broad configuration allows the image optimizer to fetch internal services, cloud metadata endpoints, localhost | `next.config.js` with permissive image configuration | **SSRF** |
| **SVG Injection via Image Optimization** | When `dangerouslyAllowSVG: true` is enabled, the image optimizer serves SVG files containing embedded JavaScript, creating a stored XSS vector | `dangerouslyAllowSVG: true` in image configuration | **XSS** |
| **Image URL SSRF with Host Override** | Manipulating the `Host` header in requests to the image optimization endpoint redirects server-side fetches | Next.js < 14.1.1; self-hosted deployments | **SSRF** |
| **Content Injection via Image** | Attacker-controlled external image sources trigger file downloads with arbitrary content and filenames, enabling phishing | Next.js image optimization + external sources | **INFO** |
| **Backslash URL Redirect** | `/_next/image` endpoint processes URL parameter containing backslash (`\`) that triggers an open redirect — WHATWG URL parsing converts `\` to `/`, altering the request target to an external domain | Self-hosted Next.js with permissive `images.remotePatterns`; WHATWG backslash normalization | **SSRF** |

**Security Evolution**: `domains` (simple hostname list) → `remotePatterns` (protocol, hostname, port, pathname restrictions) → `search` restriction added → `localPatterns` added. Each tightening represents a previously discovered bypass.

---

## §7. Server/Client Component Boundary Confusion (MP1, MP3)

### §7-1. Opaque Abstraction of the Server-Client Boundary

**Design Philosophy**: The RSC value proposition is making server and client code feel like a "unified programming model." This intentionally obscures what is fundamentally a security boundary.

**Security Implication**: Developers think in "components" but must reason about "trust boundaries." Passing props from Server to Client Components looks like normal prop passing but is actually serialization + network transmission.

| Risk Pattern | Description | Detection |
|-------------|-------------|-----------|
| **Full database objects as props** | Passing entire DB objects to Client Components serializes and transmits all fields | Overly broad props types in `"use client"` files |
| **Conditional rendering gate exposure** | `{isAdmin && <AdminPanel />}` — boolean state visible in RSC payload | Sensitive conditional rendering |
| **API keys as props** | Passing API keys as props for client-side fetching | Secrets passed to Client Components |
| **`.bind()` vs closure** | Closure variables are encrypted, but values passed via `.bind()` are NOT encrypted | `.bind(null, sensitiveValue)` patterns |

**Official Security Guide**: "Client Components that render through Server-side Rendering (SSR) should be considered as the same security policy as the browser client." Even during SSR, Client Components must be treated with browser-equivalent trust.

### §7-2. Directive Boundary Confusion

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Transitive Import Leakage** | Mixed `"use server"` and `"use client"` module graphs create transitive import paths where server-only code (containing secrets, DB queries) is included in client bundles | Complex module dependency graphs spanning server/client | **INFO** |
| **server-only Package Limitations** | The `server-only` package blocks direct imports but may not catch transitive inclusions through complex re-export chains | Complex re-export chains | **INFO** |

### §7-3. Taint API Limitations

Next.js offers experimental React Taint APIs (`taintObjectReference`, `taintUniqueValue`) with critical limitations:

- `taintObjectReference` is bypassed by destructuring — extracting fields from a tainted object and passing them individually is not caught
- `taintUniqueValue` does not block derived values
- Experimental and requires explicit opt-in
- Functions and classes are blocked from Client Component transfer by default, but plain objects and strings are not

---

## §8. Build Pipeline and Development Tooling (MP3)

### §8-1. Source Map and Source Code Exposure

| Subtype | Mechanism | Key Condition | Impact |
|---------|-----------|---------------|--------|
| **Production Source Map Exposure** | `productionBrowserSourceMaps: true` makes `.map` files publicly accessible, revealing complete original source code | Explicit sourcemap configuration; forgotten build artifacts | **INFO** |

### §8-2. Default Configuration Security Gaps

| Configuration | Default | Security Impact | Recommendation |
|--------------|---------|-----------------|----------------|
| `poweredByHeader` | `true` | Exposes `X-Powered-By: Next.js`, enabling framework fingerprinting | Set to `false` |
| `serverActions` | Enabled (14.x+) | Exposes Server Actions attack surface even if not used | Disable if unused |
| Security Headers | None | No CSP, HSTS, X-Frame-Options configured by default | Configure via `next.config.js` `headers()` or middleware |
| `images.dangerouslyAllowSVG` | `false` | Prevents JS execution in SVG images | Keep default |
| `images.remotePatterns` | `[]` (empty) | No remote image proxying (secure default) | Explicitly configure only required sources |
| Error Pages | Framework default | Development mode exposes framework version, internal paths | Custom error pages; ensure `NODE_ENV=production` |

---

## CVE / Bounty Mapping Table

| CVE | Year | CVSS | Root Cause | Affected Versions | Meta-Pattern |
|-----|------|------|-----------|-------------------|-------------|
| CVE-2025-55182 / CVE-2025-66478 | 2025.12 | 10.0 | RSC Flight deserialization RCE | Next.js 14.3+/15.x/16.x (React 19.x) | MP7 |
| CVE-2025-67779 / CVE-2025-55184 | 2025.12 | 7.5 | RSC Flight circular reference DoS | Same as above | MP7 |
| CVE-2025-55183 | 2025.12 | 5.3 | RSC self-reference gadget source leak | React 19.0–19.2.0 | MP7 |
| CVE-2025-29927 | 2025.03 | 9.1 | `x-middleware-subrequest` bypass | Next.js 11.1.4–15.2.2 | MP2, MP6 |
| CVE-2024-51479 | 2024.11 | 7.5 | Middleware pathname matching flaw | Next.js 9.5.5–14.2.14 | MP2, MP6 |
| CVE-2024-34351 | 2024.02 | 7.5 | Host header SSRF (Server Actions) | Next.js < 14.1.1 (self-hosted) | MP2, MP5 |
| CVE-2024-34350 | 2024 | 7.5 | HTTP Request Smuggling (rewrite) | — | MP2 |
| CVE-2024-46982 | 2024.09 | 7.5 | Internal header cache poisoning | Next.js 13.5.1–14.2.9 | MP4 |
| CVE-2025-49826 | 2025 | 7.5 | 204 response cache poisoning DoS | Next.js 15.1.0–15.1.7 | MP4 |
| CVE-2025-57822 | 2025 | 6.5 | Middleware Location header SSRF | Next.js < 14.2.32 / 15.4.7 | MP2, MP5 |
| CVE-2025-57752 | 2025 | 6.2 | Image cache key confusion | — | MP4 |
| CVE-2025-32421 | 2025 | Medium | RSC/HTML format confusion cache poisoning | Next.js 15.3.0–15.3.2 | MP4 |
| CVE-2025-55173 | 2025 | 4.3 | Image content injection | — | MP4 |
| CVE-2022-23646 | 2022 | Moderate | Image CSP misconfiguration | — | MP4 |
| CVE-2021-39178 | 2021 | Moderate | Image SVG XSS | — | MP4 |
| CVE-2021-37699 | 2021 | Moderate | Open Redirect (error page) | Next.js 10.0.5–11.0.1 | MP5 |
| Eclipse (no CVE) | 2025 | High | Cache batcher race condition | Pages Router + ISR | MP4 |

---

## Appendix A: Meta-Pattern ↔ Attack ↔ Defense Mapping

| Meta-Pattern | Representative Vulnerabilities | Attack Technique | Source Location | Mitigation |
|-------------|-------------------------------|-----------------|----------------|-----------|
| MP1 (Abstraction Leakage) | Data leaks, CVE-2025-55183 | Over-passing props, RSC payload analysis | RSC rendering pipeline | Data Access Layer + DTOs, `server-only`, Taint API |
| MP2 (Internal Header Trust) | CVE-2025-29927, CVE-2024-34351 | `x-middleware-subrequest` spoofing, `Host` spoofing | `adapter.ts`, `action-handler.ts` | Strip internal headers at reverse proxy, cryptographic validation |
| MP3 (Convention-as-Security) | `NEXT_PUBLIC_` leaks, directive confusion | Env var prefix mistakes, import chain analysis | Build pipeline | Separate config files, `server-only` package, build auditing |
| MP4 (Perf-Security Tradeoff) | CVE-2024-46982, CVE-2025-49826 | Internal header/parameter cache poisoning | Cache layer, image optimizer | `Vary` headers, security-aware cache keys, CDN config audit |
| MP5 (Platform Mismatch) | CVE-2024-34351, CVE-2025-57822 | Host/X-Forwarded-Host spoofing on self-hosted | Server entry point | Reverse proxy Host enforcement, `allowedHosts`, network restrictions |
| MP6 (Single-Layer Security) | CVE-2025-29927 chain attacks | Middleware bypass → all protections fail | Middleware architecture | Defense-in-depth: verify auth in middleware + Server Component + Server Action |
| MP7 (Deserialization Trust) | CVE-2025-66478 (React2Shell) | Flight payload manipulation, arbitrary module invocation | RSC Flight protocol | Patch React/Next.js, WAF rules, restrict Flight endpoint access |

---

## Appendix B: Security Checklist

### Versions and Patches
- [ ] Next.js >= 15.2.3 or >= 14.2.25 (CVE-2025-29927 patch)
- [ ] React 19.1.0+ (CVE-2025-55182 patch)
- [ ] All RSC-related CVE patches verified for latest patch versions

### Configuration Verification
- [ ] `poweredByHeader: false`
- [ ] `images.dangerouslyAllowSVG: false` confirmed
- [ ] No wildcards in `images.remotePatterns`
- [ ] `productionBrowserSourceMaps: false` confirmed
- [ ] `NODE_ENV=production` in production deployments
- [ ] Security response headers configured (CSP, HSTS, X-Frame-Options, etc.)
- [ ] `serverActions.allowedOrigins` explicitly configured

### Authentication/Authorization
- [ ] **Never rely on middleware alone** — verify auth independently in Server Components and Server Actions
- [ ] Re-verify current user authorization inside every Server Action
- [ ] Validate Server Action arguments (zod, etc.)
- [ ] Re-read cookies/session for each data access — never pass auth state as props/params
- [ ] Use allowlists rather than denylists for pathname-based authorization

### Data Protection
- [ ] Data Access Layer (DAL) pattern applied
- [ ] Audit `"use client"` file props for overly broad types
- [ ] No secrets in `NEXT_PUBLIC_` prefixed environment variables
- [ ] No sensitive data exposed in `__NEXT_DATA__`
- [ ] Server-only modules protected with `server-only` package
- [ ] Audit all props passed from Server to Client Components for sensitive data

### Infrastructure
- [ ] Self-hosted: **reverse proxy** enforces `Host` header and strips internal headers
- [ ] `x-middleware-subrequest` stripped from external requests (defense-in-depth)
- [ ] CDN cache configuration audited: `Vary` headers respected, 204 responses not cached
- [ ] Image optimizer blocked from accessing internal IP ranges

### Custom Route Auditing
- [ ] `route.tsx` (Route Handler): manual CSRF protection implemented
- [ ] `middleware.ts` / `proxy.ts`: traditional penetration testing techniques applied
- [ ] `[param]` dynamic routes: parameter validation confirmed
- [ ] Static/ISR pages: security maintained without middleware

---

## Appendix C: Secure Code Pattern Examples

### Middleware + Server Component Dual Authorization

```typescript
// proxy.ts (v16) / middleware.ts — First layer
export function proxy(request: NextRequest) {
  const token = request.cookies.get('session-token')
  if (!token && request.nextUrl.pathname.startsWith('/admin')) {
    return NextResponse.redirect(new URL('/login', request.url))
  }
  return NextResponse.next()
}

// app/admin/page.tsx — Second layer (independent verification)
import { getServerSession } from 'next-auth'
import { redirect } from 'next/navigation'

export default async function AdminPage() {
  const session = await getServerSession()
  if (!session) redirect('/login') // Independent of middleware

  const users = await getAdminUsers(session.user.id) // Uses DAL
  return <UserTable users={users} />
}
```

### Server Action Authorization + Input Validation

```typescript
// VULNERABLE
"use server"
export async function deletePost(id: number) {
  await db.query('DELETE FROM posts WHERE id = $1', [id])
}

// SECURE
"use server"
import { z } from 'zod'
import { getCurrentUser } from '@/data/auth'

const schema = z.object({ id: z.number().int().positive() })

export async function deletePost(rawInput: unknown) {
  const { id } = schema.parse(rawInput)     // Input validation
  const user = await getCurrentUser()         // Re-verify authorization
  if (!user) throw new Error('Unauthorized')

  const post = await getPost(id)
  if (post.authorId !== user.id && !user.isAdmin) {
    throw new Error('Forbidden')
  }
  await db.query('DELETE FROM posts WHERE id = $1', [id])
}
```

### Data Access Layer (DTO Pattern)

```typescript
// data/user-dto.ts
import 'server-only'
import { cache } from 'react'
import { cookies } from 'next/headers'

export const getCurrentUser = cache(async () => {
  const token = (await cookies()).get('AUTH_TOKEN')
  const decoded = await decryptAndValidate(token)
  return new User(decoded.id) // class prevents accidental serialization
})

export async function getProfileDTO(slug: string) {
  const userData = await sql`SELECT * FROM user WHERE slug = ${slug}`
  const currentUser = await getCurrentUser()

  return {
    username: canSeeUsername(currentUser) ? userData.username : null,
    phonenumber: canSeePhoneNumber(currentUser, userData.team)
      ? userData.phonenumber : null,
    // Never include sensitive fields: password, token, etc.
  }
}
```

---

## Appendix D: Version-by-Version Security Changes

| Version | Security Change | Breaking Change | Notes |
|---------|----------------|-----------------|-------|
| 16.0 | `middleware.ts` → `proxy.ts` rename | Yes (codemod provided) | Discourages use as auth layer |
| 15.5 | Node.js runtime middleware (stable) | No | Edge Runtime restriction lifted |
| 15.2.3 | CVE-2025-29927 patch (cryptographic `x-middleware-subrequest` validation) | No | Affects all versions since 11.1.4 |
| 15.0.5+ | CVE-2025-66478 patch (React2Shell) | No | Requires React 19.1.0+ |
| 14.2.25 | CVE-2025-29927 patch (14.x backport) | No | — |
| 14.2.10 | CVE-2024-46982 patch (cache poisoning) | No | Internal header validation + cache key differentiation |
| 14.1.1 | CVE-2024-34351 patch (SSRF) | No | `originalHost.value` → `process.env.__NEXT_PRIVATE_HOST` |
| 14.0 | Server Action closure variable encryption | No | Build-time private key generation |
| 13.1 | `skipMiddlewareUrlNormalize` flag | No | Fine-grained path normalization control |
| — | `domains` → `remotePatterns` (image config) | Gradual | Previous `domains` deprecated |

---

## Appendix E: Key Researchers and Publications

| Researcher/Organization | Publication | Contribution |
|------------------------|-------------|-------------|
| **zhero_web_security** (Rachid Allam) | "The Stale Elixir", "Black Hole", "Eclipse on Next.js", "The Corrupt Middleware" | CVE-2025-29927, cache poisoning series, batcher race condition. Most prolific Next.js security researcher as of 2025 |
| **Assetnote** | "Digging for SSRF in NextJS Apps" | CVE-2024-34351. Documented Vercel vs self-hosted security gap. Established Next.js pentest methodology |
| **Lachlan Davidson** | React2Shell discovery | CVE-2025-55182/CVE-2025-66478 (CVSS 10.0) responsible disclosure |
| **RyotaK** (Flatt Security) | RSC DoS/Source Leak | CVE-2025-55183, CVE-2025-55184 discovery |
| **JFrog, Wiz, Akamai, Microsoft, AWS, Trend Micro** | Independent React2Shell analyses (2025.12) | Attack mechanics, detection signatures, cloud impact analysis |
| **Sam Curry** | "Exploiting Web3's Hidden Attack Surface" (2022) | Netlify + Next.js UXSS |
| **ProjectDiscovery** | Nuclei templates | CVE-2025-29927, CVE-2024-34351, CVE-2024-46982 detection |

---

## Appendix F: Detection Tools

| Tool | Type | Detection Scope |
|------|------|----------------|
| **Nuclei** | DAST | Framework-specific CVE templates: CVE-2025-29927, CVE-2024-34351, CVE-2024-46982, etc. |
| **Semgrep** | SAST | `dangerouslySetInnerHTML`, `NEXT_PUBLIC_` misuse, unsafe redirect patterns |
| **Burp Suite** | DAST | Middleware bypass, header injection, cache poisoning manual testing |
| **Arcjet** | Runtime | Real-time detection of middleware bypass attempts and suspicious header patterns |
| **Socket.dev** | SCA | Behavioral analysis of npm packages in the Next.js dependency tree |
| **npm audit / Dependabot** | SCA | Known CVE matching against installed Next.js/React versions |
| **DOMPurify** | Runtime | Safe HTML rendering with `dangerouslySetInnerHTML` |
| **next-safe** | Hardening | Automated security header configuration for Next.js |

---

## Core Principles Summary

**1. Zero Trust Boundary Enforcement**: Every framework layer must independently validate its inputs rather than trusting coordination headers or serialized data from adjacent layers.

**2. Explicit Security Boundaries**: Server-only code must be physically separated from client-accessible code at the build level, not merely annotated with directives. The Data Access Layer pattern achieves this.

**3. Defense-in-Depth Authentication**: Authentication verification must be performed independently at middleware, Server Component, and Server Action levels. Middleware is "a helpful optimization" not "a security guarantee."

**4. Cache-Aware Security**: Cache keys must incorporate content type, authentication state, and response format to prevent poisoning and deception.

**5. Self-Hosted Security Parity**: The implicit protections provided by Vercel infrastructure (header stripping, Host validation, automatic patching) must be explicitly reproduced in self-hosted environments.

---

## References

- React Security Blog: Critical Security Vulnerability in React Server Components (December 2025)
- Next.js Security Advisory: CVE-2025-66478 — https://nextjs.org/blog/CVE-2025-66478
- Next.js Security Update: December 11, 2025 — https://nextjs.org/blog/security-update-2025-12-11
- Next.js Blog: How to Think About Security in Next.js — https://nextjs.org/blog/security-nextjs-server-components-actions
- Next.js Docs: Data Security — https://nextjs.org/docs/app/guides/data-security
- ProjectDiscovery: CVE-2025-29927 Technical Analysis — https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass
- Assetnote: Digging for SSRF in NextJS Apps — https://www.assetnote.io/resources/research/advisory-next-js-ssrf-cve-2024-34351
- zhero_web_security: Next.js and the Corrupt Middleware — https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware
- zhero_web_security: Next.js, Cache, and Chains: The Stale Elixir — https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir
- zhero_web_security: Next.js and Cache Poisoning: A Quest for the Black Hole — https://zhero-web-sec.github.io/research-and-things/nextjs-and-cache-poisoning-a-quest-for-the-black-hole
- zhero_web_security: Eclipse on Next.js — https://zhero-web-sec.github.io/research-and-things/eclipse-on-nextjs-conditioned-exploitation-of-an-intended-race-condition
- Akamai: CVE-2025-55182 React and Next.js Server Functions Deserialization RCE — https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce
- AWS Security Blog: China-nexus Groups Exploit React2Shell (December 2025)
- Resecurity: React2Shell Explained — https://www.resecurity.com/blog/article/react2shell-explained-cve-2025-55182-from-vulnerability-discovery-to-exploitation
- Sam Curry: Exploiting Web3's Hidden Attack Surface: Universal XSS on Netlify's Next.js Library (2022)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
