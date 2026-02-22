# Modern JavaScript Framework Security — Mutation/Variation Taxonomy

---

## Classification Structure

Modern JavaScript frameworks (React, Next.js, Vue, Nuxt.js, Angular, Svelte, SvelteKit, Astro, Remix) have converged on a shared architectural pattern: server-side rendering (SSR) with client-side hydration, file-based routing with middleware layers, server-originated data fetching (server components, server actions, loaders), and aggressive caching for performance. Each of these architectural layers introduces a distinct trust boundary, and the security of the entire stack depends on the correct enforcement of those boundaries.

This taxonomy organizes the complete attack surface of modern JS frameworks under **Axis 1: Mutation Target** — the structural component being attacked. Nine top-level categories correspond to the nine principal attack surfaces. Within each category, subtypes are organized by the specific mechanism exploited.

**Axis 2: Discrepancy Type** provides the cross-cutting explanation for *why* each mutation works. The following discrepancy types recur throughout the taxonomy:

| Discrepancy Type | Description |
|------------------|-------------|
| **Deserialization Trust Boundary** | Server deserializes client-supplied data without validating its structural integrity against the expected schema |
| **Header Trust Without Validation** | Framework trusts HTTP headers (e.g., `x-middleware-subrequest`, `x-forwarded-host`) as authoritative without verifying origin |
| **Client/Server Boundary Confusion** | Code or data meant for server-only execution leaks to the client, or client input reaches server execution paths |
| **Cache Key/Content Mismatch** | Cache layer stores or serves content keyed on manipulable request properties, creating poisoning or deception |
| **URL/Path Parsing Differential** | Different components (middleware, router, adapter, URL parser) interpret the same URL differently |
| **Output Encoding Context Mismatch** | Data safe in one rendering context (HTML, JSON, URL) becomes dangerous when consumed in another |
| **Prototype Chain Manipulation** | Object property injection through `__proto__` or `constructor.prototype` alters application behavior globally |
| **Build-Time/Runtime Boundary Confusion** | Secrets or configuration safe at build time become exposed in client bundles at runtime |
| **Authorization Scope Mismatch** | Framework-level auth checks can be bypassed due to routing logic gaps or header spoofing |

**Axis 3: Attack Scenario** maps mutations to their real-world impact: Remote Code Execution (RCE), Authentication/Authorization Bypass, Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), Sensitive Data Exposure, Denial of Service (DoS), Cache Poisoning/Deception, and Supply Chain Compromise.

---

## §1. Server-Side Rendering Protocol Attacks

The React Server Components (RSC) "Flight" protocol — and its equivalents in other frameworks — represents a fundamentally new trust boundary in web applications. The server serializes component trees, closures, and references into a wire format consumed by the client runtime. When the deserialization path fails to validate the structural integrity of incoming payloads, the server can be tricked into executing arbitrary code.

### §1-1. Insecure Deserialization in RSC Flight Protocol

The RSC Flight protocol uses directives like `$F` (function reference) and `$T` (temporary reference) to serialize server function references. When a client sends a POST request to a server action endpoint, the Flight deserializer reconstructs objects from the payload. If the deserializer does not validate that references point to legitimate, exported server functions, an attacker can inject crafted directives that resolve to arbitrary module exports.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Arbitrary Module Invocation** | Attacker crafts Flight payload with `$F` directive referencing any server module and export, causing the server to invoke attacker-chosen functions with attacker-supplied arguments | React 19.x with `react-server-dom-webpack/turbopack/parcel`; any endpoint accepting Flight payloads |
| **Self-Reference Gadget (Source Leak)** | Crafted payload causes a server function to receive itself as an argument. When the function stringifies or processes this, the server returns the function's source code in the response | Server function that returns data including stringified arguments |
| **Infinite Loop DoS** | Specially crafted deserialization payload creates circular references or recursive resolution that hangs the server process, preventing all future HTTP requests | Any App Router endpoint accepting Flight payloads |

The arbitrary module invocation subtype — widely known as "React2Shell" — received a CVSS 10.0 score and was actively exploited within hours of disclosure. Standard `create-next-app` projects using the App Router are vulnerable by default because the Flight protocol endpoint is enabled without additional configuration. The attack requires no authentication, no user interaction, and has low complexity.

### §1-2. Server Function Enumeration and Boundary Leakage

Server actions declared with `"use server"` are intended to execute only on the server. However, the mechanism for exposing these functions to client invocation creates an enumerable attack surface.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Action ID Enumeration** | Server actions are identified by deterministic IDs derived from file paths and export names. Attackers can enumerate valid action IDs by analyzing the client bundle or brute-forcing common patterns | Any App Router application with server actions |
| **Closure Variable Capture** | Server functions that close over sensitive variables (API keys, database connections) may expose these through deserialization artifacts or error messages | Server functions using variables from outer scope |
| **Directive Boundary Confusion** | Mixing `"use server"` and `"use client"` in module graphs can create paths where server-only code is inadvertently bundled for the client | Complex module dependency graphs spanning server/client |

---

## §2. Routing and Middleware Layer Attacks

Modern JS frameworks use middleware as the primary enforcement point for authentication, authorization, CSP headers, rate limiting, and request transformation. The middleware executes *before* route handlers, making it a critical security gate. When this gate can be bypassed or manipulated, all downstream protections fail.

### §2-1. Internal Header Trust Exploitation

Frameworks use internal headers to coordinate between middleware invocations, load balancers, and routing layers. When these headers are trusted without origin validation, external attackers can spoof them.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Middleware Recursion Guard Spoofing** | Next.js uses `x-middleware-subrequest` to prevent infinite middleware loops. By injecting this header with the correct middleware path, an attacker causes the framework to skip all middleware execution entirely | Next.js 11.1.4–15.2.2; single HTTP header injection |
| **Forwarded-Host Spoofing** | Astro's Node adapter constructs `Astro.url` from `x-forwarded-host`, `x-forwarded-proto`, and `x-forwarded-port` without validation. Spoofing these headers allows hostname override, protocol injection, and port manipulation | Astro with Node adapter, self-hosted; no upstream header stripping |
| **Forwarded-Proto Non-Special Scheme** | Injecting non-standard protocol schemes (e.g., `x-forwarded-proto: x:admin?`) into Astro creates URLs without leading slashes. The `prependForwardSlash` function adds the slash during routing but *after* middleware checks, creating a path discrepancy | Astro with middleware-based access control |

The Next.js middleware bypass (CVE-2025-29927, CVSS 9.1) is notable for its simplicity: a single header addition bypasses all middleware-based authorization. Any application relying on Next.js middleware for authentication — a pattern encouraged by the official documentation — was fully exposed.

### §2-2. Route Matching and Path Confusion

Different layers in the framework stack may parse the same URL path differently, creating opportunities to reach routes that should be blocked.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Pathname-Dependent Auth Bypass** | When middleware authorization depends on `pathname` matching (e.g., `startsWith('/admin')`), attackers use path normalization differences, trailing slashes, encoded characters, or case variations to evade pattern matching while still reaching the target route | Next.js < 14.2.15; middleware using string-based path checks |
| **API Route Direct Access** | Middleware may only guard page routes but not API routes (`/api/*`), allowing direct access to data endpoints that lack their own authorization checks | Applications relying solely on middleware for API auth |
| **Catch-All Route Confusion** | Dynamic route segments (`[...slug]`) and optional catch-all routes (`[[...slug]]`) may match unexpectedly, serving content from unintended handlers | Complex routing hierarchies with overlapping patterns |
| **Adapter-Specific Path Bypass** | Platform adapters (Cloudflare, Node, Netlify) may normalize paths differently than the core router, allowing domain restriction bypass or unauthorized content serving | Astro Cloudflare adapter 11.0.3–12.6.5 (CVE-2025-58179) |

### §2-3. Middleware Response Manipulation

When middleware can be tricked into performing unintended actions through response header manipulation, the consequences extend beyond access control.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **NextResponse SSRF via Location Header** | Passing a `Location` header through `NextResponse.next()` causes the framework to perform a server-side fetch to that URL and return the response, creating a full SSRF primitive | Next.js middleware reflecting request headers into NextResponse; self-hosted |
| **CSP Header Injection** | Middleware bypass allows attackers to remove or modify Content-Security-Policy headers, weakening client-side XSS protections for all subsequent page loads | Applications using middleware to inject CSP headers |

---

## §3. Client-Side Rendering and Injection Attacks

Despite the "secure by default" promise of modern frameworks (auto-escaping in JSX, template compilation), multiple patterns allow client-side code injection. The attack surface has shifted from classic reflected XSS to framework-specific gadgets.

### §3-1. Unsafe API Misuse

Every major framework provides escape hatches from auto-escaping. Developers use these for legitimate purposes (markdown rendering, rich text, CMS content), but any user-influenced data passing through these APIs creates direct XSS.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **dangerouslySetInnerHTML (React)** | Directly injects raw HTML into the DOM, bypassing React's escaping. Malicious script tags, event handlers, or SVG payloads execute immediately | User-controlled data passed without sanitization |
| **v-html Directive (Vue)** | Vue's `v-html` renders raw HTML without escaping. Identical risk to `dangerouslySetInnerHTML` | User-controlled data in v-html binding |
| **innerHTML Binding (Angular)** | Angular's `[innerHTML]` property binding. While Angular sanitizes by default, bypassing via `bypassSecurityTrustHtml()` creates direct injection | Developer explicitly bypassing Angular sanitizer |
| **{@html} Tag (Svelte)** | Svelte's `{@html}` renders raw HTML. No built-in sanitization | User-controlled data in @html expression |
| **set:html Directive (Astro)** | Astro's `set:html` injects raw HTML into rendered output | User-controlled data in set:html |

### §3-2. URL Protocol Injection

Framework auto-escaping protects HTML content contexts but does *not* validate URL schemes in `href`, `src`, `action`, or `formAction` attributes.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **javascript: URI in href** | User-controlled URLs in `<a href={userInput}>` allow `javascript:` protocol execution on click. React warns since v16.9 but does not block | Any dynamically rendered link with user-provided URL |
| **javascript: URI in navigateTo** | Nuxt.js `navigateTo()` function with SSR accepts `javascript:` URLs that bypass protocol checks, executing arbitrary script on the client during hydration | Nuxt.js with SSR, user-controlled navigation targets |
| **data: URI Injection** | `data:text/html` or `data:image/svg+xml` URIs containing embedded scripts bypass URL scheme allowlists that only check for `javascript:` | Incomplete URL validation (allowlist misses data: scheme) |

### §3-3. Template Injection

When server-side template engines are integrated with SSR frameworks, or when framework template syntax is exposed to user input, injection becomes possible.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Server-Side Template Injection (SSTI)** | Developers integrating EJS, Pug, or Handlebars with Next.js/Nuxt.js route handlers may pass user input directly into template rendering, allowing arbitrary code execution | Explicit template engine integration with user input |
| **Client-Side Template Injection (CSTI)** | When Vue templates are compiled at runtime with user-controlled content, Vue's expression evaluation executes arbitrary JavaScript. Angular expression injection in older versions (< 1.6) allows sandbox escape | Runtime template compilation with user data; AngularJS < 1.6 |
| **Markdown Parser Bypass** | Markdown-to-HTML libraries used by Nuxt Content, MDX, or custom CMS integrations may fail to sanitize embedded HTML, allowing `<script>` or `javascript:` injection through markdown content | @nuxtjs/mdc < 0.13.3 (CVE-2025-24981); MDX without sanitization |
| **Server-Side MDX Evaluation RCE** | Documentation platforms compiling MDX (Markdown + JSX) server-side evaluate embedded expressions as executable code during static site generation. Attacker-authored MDX content containing `{fetch('...').then(r=>r.text()).then(eval)}` achieves RCE during the build, enabling `process.env` exfiltration and filesystem access | Server-side MDX compilation with user-controlled content; Mintlify (CVE-2025-67843); any MDX-based documentation platform without expression sandboxing |

### §3-4. Hydration and DOM Manipulation Attacks

The transition from server-rendered HTML to client-interactive application (hydration) creates a unique attack surface where the DOM state differs between server and client.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hydration Mismatch Injection** | When server-rendered HTML contains attacker-controlled content that differs from what the client expects, the hydration process may preserve malicious DOM elements that the client would not have rendered | SSR with user-controlled content that creates DOM structure differences |
| **DOM Clobbering via Framework Gadgets** | Malicious HTML elements with crafted `id` or `name` attributes override global JavaScript variables. When framework code reads these variables (e.g., `document.currentScript`, `import.meta.url`), attackers control execution flow | Scriptless HTML injection + framework code that reads DOM properties |
| **Search Parameter Script Injection** | SvelteKit's boot script includes unsanitized search parameters from `tracked` search params, enabling script injection through URL parameters | SvelteKit with tracked search params (CVE-2025-32388) |
| **Error Template Injection** | SvelteKit's static `error.html` template contained unescaped placeholders, allowing content injection when error pages were served | SvelteKit < 2.8.3 (CVE-2024-53262) |
| **Netlify Deployment UXSS via Next.js Routing** | Netlify's deployment infrastructure interacts with Next.js client-side routing to create a universal XSS condition. The Netlify-specific Next.js runtime library processes URLs in a way that allows attacker-controlled path segments to be rendered as executable script content across all pages served by the affected deployment, impacting Web3 applications built on the Netlify+Next.js stack | Netlify-hosted Next.js applications using the affected runtime library version (Sam Curry, 2022) |

---

## §4. Data Serialization and State Exposure

Modern frameworks serialize server-side data into the HTML response for client consumption. This serialization layer — `__NEXT_DATA__`, Redux hydration scripts, environment variable inlining — creates a direct channel for sensitive data leakage.

### §4-1. Server-Side Props Leakage

Frameworks transfer data from server to client by embedding serialized JSON in the initial HTML response. Any sensitive data included in this transfer is visible to anyone viewing the page source.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **__NEXT_DATA__ Exposure** | Next.js pages using `getServerSideProps` or `getStaticProps` embed their return values in a `<script id="__NEXT_DATA__">` tag. API keys, internal URLs, user tokens, or database query results included in props are exposed in page source | Props containing sensitive data; Pages Router |
| **RSC Payload Data Leak** | React Server Component payloads transmitted as Flight protocol data may contain server-side data that was intended to remain on the server | Server components passing sensitive data to client components |
| **Loader Data Exposure (Remix/SvelteKit)** | Remix `loader` functions and SvelteKit `load` functions transfer data to the client. Over-fetching database fields (e.g., returning full user objects including password hashes) exposes data | Loader/load functions returning unsanitized database queries |

### §4-2. Environment Variable Exposure

Modern build tools inline environment variables at build time, creating a persistent record of configuration values in the client bundle.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **NEXT_PUBLIC_ Prefix Misuse** | Variables prefixed with `NEXT_PUBLIC_` are inlined into the client bundle at build time. Developers accidentally prefix sensitive variables (API secrets, database URLs) with `NEXT_PUBLIC_` | Sensitive variables with NEXT_PUBLIC_ prefix |
| **Client-Side Reference of Server Variables** | Even without the `NEXT_PUBLIC_` prefix, if server-only environment variables are referenced in client-side code, they are inlined during the build process | Server env vars accidentally imported in client code paths |
| **Vite define/env Exposure** | Vite's `define` configuration or `.env` files with `VITE_` prefix expose variables to the client bundle. `import.meta.env.VITE_*` values are statically replaced at build time | Sensitive variables with VITE_ prefix |
| **Source Code Exposure via RSC Bug** | A crafted HTTP request to a vulnerable server action causes React to return the actual JavaScript source of the function in the response, potentially exposing hardcoded secrets | React 19.0–19.2.0; server functions with hardcoded secrets (CVE-2025-55183) |

### §4-3. State Serialization Injection

When server-side state (Redux store, authentication tokens, user data) is serialized into HTML for client hydration, improper escaping creates script injection vectors.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JSON Injection in Hydration Script** | Server-rendered state embedded as `window.__PRELOADED_STATE__ = ${JSON.stringify(state)}` without escaping `<` characters allows an attacker who controls state data to break out of the script context with `</script><script>malicious()</script>` | State containing user-controlled strings; missing `<` → `\u003c` escaping |
| **Template Literal State Injection** | When state is embedded using template literals instead of `JSON.stringify`, special characters in the data can escape the string context | Custom state serialization without proper escaping |

---

## §5. URL and Request Handling Attacks (SSRF)

Modern frameworks process URLs in multiple contexts: image optimization, server action redirects, API proxying, and header-based URL construction. Each represents an SSRF entry point.

### §5-1. Image Optimization SSRF

Built-in image optimization endpoints (`/_next/image` in Next.js) accept external URLs as parameters and fetch them server-side. When allowlists are misconfigured, this becomes an SSRF primitive.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Wildcard Image Domain** | Setting `images.remotePatterns` to `*` or using overly broad patterns allows the image optimizer to fetch any URL, including internal services, cloud metadata endpoints, and localhost | `next.config.js` with permissive image configuration |
| **SVG Injection via Image Optimization** | When `dangerouslyAllowSVG` is enabled, the image optimizer serves SVG files that may contain embedded JavaScript, creating a stored XSS vector | `dangerouslyAllowSVG: true` in image configuration |
| **Image URL SSRF with Host Override** | Manipulating the `Host` header in requests to the image optimization endpoint redirects server-side fetches to attacker-controlled destinations | Next.js < 14.1.1; self-hosted deployments |

### §5-2. Server Action Redirect SSRF

When server actions perform HTTP redirects, the framework may follow redirects server-side based on manipulable header values.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Host Header Redirect** | Next.js server actions use the `Host` header to construct redirect URLs. Spoofing this header causes the server to fetch from an attacker-controlled host | Next.js < 14.1.1 (CVE-2024-34351); self-hosted |
| **Next-Action Header SSRF** | Requests with `Next-Action` header beginning with a leading slash cause the server to fetch the specified path, enabling blind SSRF to internal services | Next.js < 14.1.1; server actions enabled |

### §5-3. Header-Based URL Construction SSRF

When frameworks construct URLs from request headers for internal routing or API calls, header injection enables SSRF.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **x-forwarded-host SSRF** | Astro's `createRequest` function constructs the full request URL from `x-forwarded-host` without validation. When application code uses `Astro.url` for API calls, the attacker controls the target hostname | Astro with Node adapter; application reusing `Astro.url` for fetches (CVE-2025-61925) |
| **x-forwarded-proto Scheme Injection** | Injecting protocol schemes through `x-forwarded-proto` in Astro forces URL construction with attacker-controlled schemes, enabling SSRF when the URL is used for server-side fetches | Astro with Node adapter (CVE-2025-64525); also a bypass of CVE-2025-61925 fix |
| **Middleware Location Header Reflection** | Reflecting incoming request headers (including `Location`) through `NextResponse.next()` causes the framework to perform a server-side fetch to the attacker-specified URL | Next.js middleware reflecting headers; self-hosted (CVE-2025-57822) |

---

## §6. Caching Layer Attacks

Modern frameworks aggressively cache responses for performance — Incremental Static Regeneration (ISR), stale-while-revalidate, CDN caching, and RSC payload caching. Each caching mechanism introduces poisoning and deception opportunities.

### §6-1. Response Cache Poisoning

An attacker manipulates request parameters to cause a malicious or corrupted response to be stored in the cache and served to subsequent users.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Internal Header Cache Key Manipulation** | Injecting headers like `x-now-route-matches` or query parameters like `__nextDataReq` in Next.js causes SSR routes to produce JSON responses instead of HTML. When the CDN caches these, all subsequent visitors receive broken or manipulated content | Next.js 13.5.1–14.2.9 Pages Router with non-dynamic SSR routes (CVE-2024-46982) |
| **204 Response Cache Poisoning** | Crafting requests that cause Next.js to return HTTP 204 responses, which are then cached by CDNs configured to cache 204s, creates DoS conditions where valid pages return empty responses | Next.js 15.1.0–15.1.7 with ISR or CDN caching 204 responses (CVE-2025-49826) |
| **RSC/HTML Format Confusion** | Page requests for HTML content receive RSC (Flight protocol) payloads instead, or vice versa. When cached, this serves incomprehensible data to browsers expecting HTML | Next.js App Router 15.3.0–15.3.2 (CVE-2025-32421) |
| **Cache Deception via Data Headers** | Manipulating response data to include cache-control directives (`s-maxage`, `stale-while-revalidate`) through header injection causes CDNs to cache pages containing sensitive user data | Applications with cache-control headers derived from user-controllable values |
| **Response Cache Batcher Race Condition** | Next.js response-cache batcher deduplicates concurrent requests to the same page by sharing a single Promise. Racing the batcher during the brief window between cache-miss detection and response storage causes transient `pageProps` from one user's SSR response to leak into another user's cached response — enabling cross-user data exposure and cache poisoning without any header injection | Next.js Pages Router with response-cache batcher enabled; concurrent requests during ISR revalidation window (zhero-web-sec "Eclipse on Next.js" research, 2025) |

### §6-2. Cache-Based XSS Amplification

Cache poisoning combined with XSS payload injection creates persistent, widely-distributed attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Stored XSS via Header Injection + Cache** | Injecting `x-forwarded-proto: javascript:/links#/;alert('XSS')//` in Astro causes `Astro.url` to construct URLs with `javascript:` protocol. When cached, every visitor to the poisoned page receives the XSS payload in page links | Astro with Node adapter + CDN caching (CVE-2025-64525 chain) |
| **Cached Malicious State** | Poisoning the cache with responses containing manipulated `__NEXT_DATA__` allows attackers to serve modified application state to all users | Cache poisoning primitive (§6-1) + state data in response |

---

## §7. Build and Bundling Pipeline Attacks

The build pipeline (Webpack, Vite, Turbopack, Rollup, esbuild) transforms source code into production bundles. Vulnerabilities in the build tools themselves, or misconfigurations that expose build artifacts, create attack surfaces that persist in deployed applications.

### §7-1. Source Map and Source Code Exposure

Source maps reverse the minification/bundling process, exposing the full original source code including comments, variable names, and file structure.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Production Source Map Exposure** | When `productionBrowserSourceMaps: true` is set in Next.js config, or source maps are left in the deployment, `.map` files are publicly accessible and reveal the complete source code | Explicit source map configuration; forgotten build artifacts |
| **Astro SSR Source Map Leak** | Astro 5.0.3–5.0.6 with `sourcemap: true` exposes server-side source code to the public, including server-only logic and secrets | Astro 5 SSR with sourcemaps enabled (CVE-2024-56159) |
| **webpack-dev-server Cross-Origin Theft** | webpack-dev-server fails to validate `Sec-Fetch-Mode` and `Sec-Fetch-Site` headers, allowing an attacker's webpage to load JavaScript bundles from a developer's local dev server, stealing source code | webpack-dev-server in development without proper CORS (CVE-2025-30359) |

### §7-2. Build Tool File Access Bypass

Development servers provide file serving capabilities with deny lists to prevent access to sensitive files. When these deny lists can be bypassed, configuration files, environment files, and source code are exposed.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Vite Query Parameter Bypass** | Adding `?inline&import` or `?raw&import` query parameters to file URLs bypasses Vite's `server.fs.deny` configuration, exposing contents of blocked files (`.env`, `package.json`, private keys) | Vite < 6.0.12, 5.4.15, 4.5.10 (CVE-2025-31125); actively exploited in the wild |
| **Vite Information Exposure** | Using `?import&raw` URL parameters on restricted files exposes their contents through the development server | Vite < 3.2.11, 4.5.5, 5.2.14, 5.3.6, 5.4.6 (CVE-2024-45811) |

### §7-3. Build-Time Code Injection

The build process transforms and bundles code, creating opportunities for malicious code injection at the tool level.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DOM Clobbering in Webpack Output** | Webpack's `AutoPublicPathRuntimeModule` uses `document.currentScript` to determine the public path. DOM clobbering this property with a crafted HTML element allows path override, enabling script loading from attacker-controlled origins | Scriptless HTML injection in webpack-bundled application (CVE-2024-43788) |
| **DOM Clobbering in Rollup Bundles** | Rollup's handling of `import.meta.url` creates a DOM clobbering gadget where attacker-controlled HTML elements can override the URL resolution, redirecting dynamic imports to malicious scripts | Rollup-bundled scripts with `import.meta.url` usage + HTML injection |
| **Build Plugin Compromise** | Malicious Babel plugins, PostCSS plugins, or custom Webpack loaders introduced through dependency confusion or supply chain attacks execute arbitrary code at build time with full file system access | Untrusted build-time dependencies |

---

## §8. Dependency and Supply Chain Attacks

The JavaScript ecosystem's deep dependency trees create an enormous attack surface. A typical Next.js application pulls in 500–1,500 transitive dependencies, any one of which can be compromised.

### §8-1. Package Registry Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Typosquatting** | Attackers publish packages with names similar to popular ones (e.g., `lodahs` for `lodash`, `reacr` for `react`), hoping developers mistype during installation | Developer typo during `npm install` |
| **Dependency Confusion** | Attackers publish packages to the public npm registry with names matching private/internal package names. Package managers may fetch the public malicious version instead of the private one | Organizations using unscoped private packages |
| **Star-Jacking** | Cloning popular repositories and building false credibility through stars and downloads, then publishing malicious packages that appear trustworthy | Developers evaluating packages by popularity metrics alone |
| **Account Takeover and Token Theft** | Phishing campaigns targeting package maintainers steal npm tokens/2FA credentials, enabling malicious version publication of legitimate packages | Maintainer accounts without hardware 2FA; phished credentials |

### §8-2. Self-Propagating Supply Chain Malware

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Wormable Package Compromise** | The "Shai-Hulud" worm demonstrated self-propagating behavior: malicious code in one package automatically uses stolen npm tokens to inject itself into other packages maintained by the compromised developer | Compromised npm tokens with publish permissions; September 2025 incident affected 200+ packages |
| **Postinstall Script Exploitation** | Packages execute arbitrary code during `npm install` via `postinstall` scripts. A compromised dependency can exfiltrate environment variables, inject backdoors, or download remote payloads at install time | Any package with `scripts.postinstall` in `package.json` |
| **CDN Compromise** | Third-party CDN-hosted libraries are modified at the CDN level. The Polyfill.io incident compromised 100,000+ websites by weaponizing a trusted CDN endpoint | Applications loading scripts from third-party CDNs without SRI hashes |

### §8-3. Ecosystem-Targeted Campaigns

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Framework-Specific Package Targeting** | Malicious packages specifically target React, Vue, and Vite ecosystems with destructive payloads designed to modify project files or exfiltrate credentials | Installing unvetted packages from npm; Socket.dev reported targeted campaigns in 2025 |
| **Lock File Manipulation** | Attackers submit PRs that modify `package-lock.json` or `yarn.lock` to point to compromised package versions while the `package.json` appears unchanged | PR reviews that don't carefully examine lock file changes |

---

## §9. Framework-Specific APIs and Gadget Chains

Each framework exposes unique APIs and follows distinct patterns that create framework-specific vulnerability classes. These are not general web vulnerabilities but emerge from the specific design decisions of each framework.

### §9-1. Prototype Pollution in Framework Internals

JavaScript's prototype chain allows property injection through `__proto__` or `constructor.prototype` to propagate to all objects inheriting from the polluted prototype.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Vue Template Compiler Pollution** | CVE-2024-6783 allows prototype pollution through Vue 2's template compiler, enabling XSS by injecting properties that alter template rendering behavior | Vue 2.x with runtime template compilation; attacker can set Object.prototype properties |
| **Vue-i18n handleFlatJson Pollution** | The `handleFlatJson` function in vue-i18n processes dot-notation keys without filtering `__proto__`, allowing property injection. In Node.js contexts, this can escalate to command injection if polluted properties reach `exec` or `eval` | vue-i18n < 9.14.2 (CVE-2025-27597) |
| **Angular Expressions Pollution** | The `angular-expressions` library is vulnerable to prototype pollution through crafted expression evaluation | angular-expressions (CVE-2024-54152) |
| **Deep Merge/Clone Gadgets** | Libraries commonly used with frameworks (lodash.merge, lodash.defaultsDeep, jQuery.extend) allow prototype pollution when processing user-controlled objects | Any framework using vulnerable merge/clone utilities |

### §9-2. CSP Bypass via Framework Features

Content Security Policy is designed to prevent XSS, but framework-specific features can undermine CSP enforcement.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **AngularJS Sandbox Escape** | AngularJS < 1.6 template expressions can be used to escape the sandbox and execute arbitrary JavaScript, bypassing CSP when AngularJS is loaded from a whitelisted CDN | CSP whitelisting AngularJS CDN; AngularJS < 1.6 |
| **JSONP Endpoint Exploitation** | When CSP whitelists a domain that hosts JSONP endpoints, attackers use JSONP callbacks to execute arbitrary JavaScript | CSP with broad domain whitelists (e.g., `*.googleapis.com`) |
| **Whitelisted CDN Redirect** | If a whitelisted domain has an open redirect, attackers chain the redirect to another whitelisted domain's JSONP endpoint, bypassing CSP path restrictions (browsers validate host, not path during redirects) | CSP with multiple whitelisted domains, one having open redirect |
| **Trusted Types Bypass** | Implementation errors in Trusted Types policies, combined with framework features like dynamic template compilation, can create bypass opportunities | Trusted Types with incomplete policy coverage |
| **Framework Middleware CSP Removal** | Middleware bypass (§2-1) allows removal of CSP headers entirely, disabling all CSP protections for affected pages | CVE-2025-29927 + CSP set via middleware |

### §9-3. CSRF in Modern SPAs

Modern SPAs often rely on token-based authentication (JWTs in localStorage), which is not automatically sent with cross-origin requests. However, when cookies are used, CSRF remains a significant threat.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Missing CSRF Protection on Server Actions** | Next.js server actions accept POST requests without built-in CSRF token validation. If the application uses cookies for authentication, cross-site requests can invoke server actions | Cookie-based auth + server actions without custom CSRF protection |
| **SameSite=None Cookie Exploitation** | Applications setting `SameSite=None` for cross-subdomain compatibility expose all cookie-authenticated endpoints to CSRF | Cookies with SameSite=None |
| **XSS-to-CSRF Escalation** | Once XSS is achieved (via any method in §3), attackers can read CSRF tokens from the DOM and forge requests, making CSRF protection irrelevant | Any exploitable XSS vulnerability + CSRF-token-protected endpoints |
| **HTML-over-the-wire framework token leakage** | Frameworks like Turbo (Hotwire/Rails), htmx, Unpoly, Phoenix LiveView, and Laravel Livewire replace JSON APIs with server-rendered HTML fragments delivered via fetch. Cross-origin form submissions to these endpoints produce HTML responses containing CSRF tokens, session state, or `<turbo-stream>` DOM mutation instructions. The framework processes the response and injects it into the DOM — leaking tokens via attacker-injected `<link>`/`<img>` tags or executing declarative DOM mutations from untrusted HTML | Cookie-based auth + HTML-over-the-wire framework that processes HTML responses without origin validation (see `csrf.md` §6-3) |

### §9-4. Development Tooling Exploitation

Framework development tools run with elevated privileges and may be inadvertently exposed.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Nuxt DevTools RCE Chain** | CVE-2025-52662 chains XSS in Nuxt DevTools → authentication token exfiltration → WebSocket path traversal → arbitrary file write, achieving full RCE in development environments | Nuxt DevTools < 2.6.4; accessible from network |
| **SvelteKit Remote Functions DoS/SSRF** | SvelteKit's experimental Remote Functions feature enables server crash and SSRF through crafted requests to remote function endpoints | SvelteKit with experimental `remoteFunction` feature enabled (CVE-2025-67647) |
| **Devalue Deserialization DoS** | The `devalue` library used by SvelteKit for serialization is vulnerable to memory/CPU exhaustion through crafted payloads, causing server crashes | SvelteKit with devalue (CVE-2026-22775, CVE-2026-22774) |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Remote Code Execution** | React 19 + App Router; Build pipeline | §1-1 (RSC deserialization) + §7-3 (build injection) + §8 (supply chain) |
| **Authentication/Authorization Bypass** | Next.js middleware-based auth; SPA with cookie auth | §2-1 (header spoofing) + §2-2 (path confusion) + §9-3 (CSRF) |
| **Cross-Site Scripting** | SSR + CDN caching; user-generated content | §3 (all client-side injection) + §6-2 (cache amplification) + §4-3 (state injection) |
| **Server-Side Request Forgery** | Self-hosted Next.js/Astro; image optimization | §5 (all SSRF subtypes) + §2-3 (middleware SSRF) |
| **Sensitive Data Exposure** | Pages Router with SSR props; Vite dev server | §4 (all data exposure) + §7-1 (source maps) + §7-2 (file access bypass) |
| **Denial of Service** | ISR with CDN; RSC endpoints; SvelteKit with devalue | §1-1 (infinite loop) + §6-1 (cache poisoning) + §9-4 (devalue DoS) |
| **Cache Poisoning / Deception** | CDN-fronted Next.js/Astro | §6 (all cache attacks) + §2-1 (header manipulation as prerequisite) |
| **Supply Chain Compromise** | npm-based applications; CDN-loaded scripts | §8 (all supply chain) + §7-3 (build plugin compromise) |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-1 (RSC Deserialization RCE) | CVE-2025-55182 (React) / CVE-2025-66478 (Next.js) | CVSS 10.0. Unauthenticated RCE. Actively exploited within hours by China-nexus threat groups. Affects React 19.x + Next.js 14.3+/15.x/16.x |
| §1-1 (RSC DoS) | CVE-2025-55184 / CVE-2025-67779 | CVSS 7.5. Infinite loop hanging server process, blocking all HTTP requests |
| §4-2 (Source Code Exposure) | CVE-2025-55183 | CVSS 5.3. Server function source code + hardcoded secrets leaked via crafted requests |
| §2-1 (Middleware Bypass) | CVE-2025-29927 (Next.js) | CVSS 9.1. Single header bypasses all middleware-based auth. Affects Next.js 11.1.4–15.2.2 |
| §2-2 (Pathname Auth Bypass) | CVE-2024-51479 (Next.js) | Middleware pathname matching flaw. Affects Next.js 9.5.5–14.2.14 |
| §5-2 (Server Action SSRF) | CVE-2024-34351 (Next.js) | SSRF via Host header manipulation in server actions. Affects Next.js < 14.1.1 |
| §5-3 (Middleware SSRF) | CVE-2025-57822 (Next.js) | SSRF via Location header in NextResponse.next(). Affects self-hosted < 14.2.32 / 15.4.7 |
| §6-1 (Cache Poisoning) | CVE-2024-46982 (Next.js) | CVSS 7.5. SSR cache poisoning via internal headers. Affects 13.5.1–14.2.9 |
| §6-1 (Cache Poisoning DoS) | CVE-2025-49826 (Next.js) | Cache poisoning via 204 responses. Affects 15.1.0–15.1.7 with ISR |
| §6-1 (RSC Format Confusion) | CVE-2025-32421 (Next.js) | RSC/HTML format confusion cache poisoning. Affects App Router 15.3.0–15.3.2 |
| §6-1 (Cache Batcher Race) | Eclipse on Next.js (zhero-web-sec, 2025) | Cross-user data exposure via response-cache batcher race condition during ISR revalidation |
| §5-3 + §6-2 (Astro Header SSRF/XSS) | CVE-2025-61925 / CVE-2025-64525 (Astro) | CVSS 6.5. SSRF + cache poisoning XSS via x-forwarded-* headers. CVE-2025-64525 is a bypass of the CVE-2025-61925 fix |
| §2-2 (Astro Adapter Bypass) | CVE-2025-58179 (Astro) | Cloudflare adapter domain restriction bypass. SSRF + XSS |
| §7-1 (Astro Source Map Leak) | CVE-2024-56159 (Astro) | Server source code exposure via sourcemaps in SSR mode. Affects Astro 5.0.3–5.0.6 |
| §3-2 (Nuxt navigateTo XSS) | GHSA-fh84-8j5f-fvpm (Nuxt.js) | XSS via javascript: URL in navigateTo with SSR |
| §3-3 (Nuxt MDC XSS) | CVE-2025-24981 (Nuxt.js) | XSS via javascript: URL bypass in markdown parser. Affects @nuxtjs/mdc < 0.13.3 |
| §9-4 (Nuxt DevTools RCE) | CVE-2025-52662 (Nuxt.js) | XSS → token theft → path traversal → file write → RCE chain in dev environments |
| §3-4 (SvelteKit Search Param XSS) | CVE-2025-32388 (SvelteKit) | XSS via unsanitized search params in boot script |
| §3-4 (SvelteKit Error Template XSS) | CVE-2024-53262 (SvelteKit) | XSS via unescaped error.html template. Affects SvelteKit < 2.8.3 |
| §9-4 (SvelteKit DoS/SSRF) | CVE-2025-67647 (SvelteKit) | Server crash + SSRF via experimental Remote Functions |
| §9-4 (SvelteKit Devalue DoS) | CVE-2026-22775 / CVE-2026-22774 | Memory/CPU exhaustion in devalue deserialization |
| §9-1 (Vue Prototype Pollution) | CVE-2024-6783 (Vue.js) | Prototype pollution → XSS via template compiler in Vue 2 |
| §9-1 (vue-i18n Pollution) | CVE-2025-27597 (vue-i18n) | Prototype pollution via handleFlatJson → potential RCE in Node.js contexts |
| §7-2 (Vite File Access) | CVE-2025-31125 (Vite) | File access bypass via query parameters. Actively exploited. Affects Vite < 6.0.12 |
| §7-2 (Vite Info Exposure) | CVE-2024-45811 (Vite) | File content exposure via ?import&raw |
| §7-3 (Webpack DOM Clobbering) | CVE-2024-43788 (Webpack) | XSS via DOM clobbering in AutoPublicPathRuntimeModule |
| §7-1 (webpack-dev-server Source Theft) | CVE-2025-30359 | Cross-origin source code theft from development server |
| §8-1 (npm Supply Chain) | September 2025 npm incident | 18 packages, 2.6B weekly downloads compromised. Shai-Hulud worm: 200+ packages |
| §8-2 (CDN Compromise) | Polyfill.io (June 2024) | 100,000+ websites compromised via CDN-level script modification |
| §3-3 (MDX Evaluation RCE) | CVE-2025-67843 (Mintlify) | Server-side MDX expression evaluation during SSG achieves RCE. $5,000 bounty. Affected Discord, Vercel, Cursor documentation sites |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Semgrep** (SAST) | React, Vue, Angular, Next.js code patterns | AST-based pattern matching with framework-specific rules for dangerouslySetInnerHTML, unsafe URL handling, env var exposure |
| **ESLint Security Plugins** (SAST) | JavaScript/TypeScript source code | `eslint-plugin-security`, `eslint-plugin-react`, and custom rules for framework-specific anti-patterns |
| **Snyk Code** (SAST/SCA) | Source code + npm dependencies | AI-powered code scanning + comprehensive dependency vulnerability database |
| **Socket.dev** (SCA) | npm supply chain | Behavioral analysis of npm packages; detects install scripts, network access, and filesystem manipulation |
| **npm audit / Dependabot** (SCA) | npm dependency tree | Known CVE matching against installed dependency versions |
| **Nuclei** (DAST) | Deployed applications | YAML-based templates for CVE-2025-29927, CVE-2024-34351, CVE-2024-46982, and other framework-specific vulnerabilities |
| **Burp Suite** (DAST) | HTTP traffic analysis | Active scanning with extensions for Next.js middleware bypass, header injection, cache poisoning |
| **next-safe** (Hardening) | Next.js security headers | Automated CSP, HSTS, and security header configuration for Next.js applications |
| **DOMPurify** (Runtime) | Client-side HTML sanitization | Safe rendering of user HTML with dangerouslySetInnerHTML / v-html |
| **Arcjet** (Runtime) | Next.js middleware monitoring | Real-time detection of middleware bypass attempts and suspicious header patterns |

---

## Summary: Core Principles

**The fundamental property** that makes modern JS frameworks vulnerable is the **convergence of server and client execution contexts into a single codebase with implicit trust boundaries**. Unlike traditional web architectures where the server and client were separate applications with a clear HTTP boundary, modern frameworks blur this line: server components and client components coexist in the same file, server actions are invoked through client-side POST requests, and the build pipeline must decide what goes where. Every misclassification — a server secret in a client bundle, a trusted internal header from an external request, a cache key that doesn't distinguish between formats — becomes a vulnerability.

**Incremental patches fail** because the attack surface is architectural, not implementation-specific. Fixing the `x-middleware-subrequest` header validation (CVE-2025-29927) doesn't address the design pattern of trusting internal coordination headers from external sources. Patching the Flight protocol deserializer (CVE-2025-55182) doesn't solve the fundamental problem that server functions are exposed as HTTP endpoints that accept arbitrary payloads. Each fix addresses one manifestation while the underlying pattern — implicit trust across explicit boundaries — persists. The September 2025 npm supply chain incident further demonstrates that even if the framework itself is secure, the ecosystem's dependency model creates a parallel attack surface that cannot be patched at the framework level.

**A structural solution** requires three shifts: (1) **Zero-trust boundary enforcement** where every framework layer independently validates its inputs rather than trusting coordination headers or serialized data from adjacent layers; (2) **Explicit security boundaries** where server-only code is physically separated from client-accessible code at the build level, not just annotated with directives; and (3) **Defense-in-depth caching** where cache keys incorporate content type, authentication state, and response format to prevent poisoning and deception. The React2Shell vulnerability (CVSS 10.0, exploited in hours) should serve as a watershed moment: the RSC Flight protocol's trust model was fundamentally broken, not merely misconfigured.

---

## References

- React Security Blog: Critical Security Vulnerability in React Server Components (December 2025)
- Next.js Security Advisory: CVE-2025-66478 (December 2025)
- Next.js Security Advisory: CVE-2025-29927 Middleware Authorization Bypass (March 2025)
- ProjectDiscovery: CVE-2025-29927 Technical Analysis
- Datadog Security Labs: Understanding CVE-2025-29927
- Assetnote: Digging for SSRF in NextJS Apps
- zhero_web_security: Astro Framework and Standards Weaponization
- zhero_web_security: Next.js and Cache Poisoning — A Quest for the Black Hole
- DeepStrike: Next.js Security Testing Guide for Bug Hunters and Pentesters
- Intigriti: Hacking Next.js Targets — Advanced SSRF Exploitation Guide
- JFrog: React2Shell — All You Need to Know
- AWS Security Blog: China-nexus Groups Exploit React2Shell (December 2025)
- Microsoft Security Blog: Defending Against CVE-2025-55182 (December 2025)
- Trend Micro: CVE-2025-55182 Analysis, PoC, and In-the-Wild Exploitation
- OX Security: Millions of Servers Vulnerable to RCE in React Components
- Wiz: Critical Vulnerability in React CVE-2025-55182
- Akamai: CVE-2025-55182 React and Next.js Server Functions Deserialization RCE
- Svelte Blog: CVEs Affecting the Svelte Ecosystem (January 2026)
- Snyk: Vue-i18n Prototype Pollution CVE-2025-27597
- Snyk: Vite Information Exposure CVE-2024-45811
- UpGuard: Actively Exploited Vite Vulnerability CVE-2025-31125
- Socket.dev: Malicious npm Packages Target React, Vue, and Vite Ecosystems
- CISA: Widespread Supply Chain Compromise Impacting npm Ecosystem (September 2025)
- Palo Alto Networks: Breakdown of npm Supply Chain Attack (September 2025)
- The Hacker News: Why React Didn't Kill XSS — The New JavaScript Injection Playbook (July 2025)
- PortSwigger Research: Top 10 Web Hacking Techniques of 2025
- Kodem: Security Issues in Popular Full-Stack Frameworks
- Semgrep: A Technical Deep Dive into JavaScript Vulnerability Detection
- Sam Curry: "Exploiting Web3's Hidden Attack Surface: Universal XSS on Netlify's Next.js Library" (2022) — UXSS affecting Web3 applications via Next.js library vulnerability on Netlify
- kibty, "how to hack discord, vercel and more with one easy trick" (2025) — Server-side MDX evaluation RCE in Mintlify (CVE-2025-67843). Cross-tenant static asset XSS, path traversal, deployment downgrade. $5,000 bounty. https://kibty.town/blog/mintlify

---

*This document was created for defensive security research and vulnerability understanding purposes.*
