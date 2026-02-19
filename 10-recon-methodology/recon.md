# Hidden Parameter Discovery — Mutation / Variation Taxonomy

---

## Classification Structure

Hidden Parameter Discovery encompasses all techniques used to identify **undocumented, unlisted, or obfuscated parameters** that a web application or API processes but does not expose through normal user interfaces, documentation, or client-side code. These parameters — whether query strings, body fields, headers, cookies, or path segments — often lack adequate validation precisely because developers rely on obscurity rather than access control.

This taxonomy is organized along three axes:

- **Axis 1 — Discovery Vector**: *How* the hidden parameter is found. This is the primary organizational axis, covering static analysis, dynamic probing, traffic archaeology, protocol-layer manipulation, schema enumeration, and inference techniques.
- **Axis 2 — Parameter Location**: *Where* the parameter resides in the HTTP transaction (query string, body, header, cookie, path, fragment). This is a cross-cutting dimension; most discovery vectors apply to multiple locations.
- **Axis 3 — Exploitation Impact**: *What* vulnerability the discovered parameter enables — privilege escalation, injection, cache poisoning, information disclosure, or access control bypass. This maps discovery to real-world consequences.

### Axis 2 Summary: Parameter Locations

| Location | Transport | Common Examples |
|----------|-----------|-----------------|
| **Query String** | `GET ?key=value` | `debug`, `admin`, `verbose`, `_method` |
| **Body (Form)** | `POST application/x-www-form-urlencoded` | `role`, `is_admin`, `user_id` |
| **Body (JSON)** | `POST application/json` | `{"__proto__": {}}`, `{"role": "admin"}` |
| **Body (XML)** | `POST application/xml` | Entity-injected parameters, attribute fields |
| **Body (Multipart)** | `POST multipart/form-data` | File metadata fields, boundary-embedded params |
| **HTTP Header** | Request headers | `X-Forwarded-Host`, `X-Debug`, `X-Original-URL` |
| **Cookie** | `Cookie:` header | `admin=true`, `debug=1`, `lang` |
| **URL Path Segment** | `/api/v2/users/PARAM` | REST resource IDs, version selectors |
| **Fragment** | `#key=value` | Client-side routing parameters |

---

## §1. Static Source Analysis

Static source analysis discovers hidden parameters by examining application artifacts — HTML, JavaScript, CSS, configuration files, and API specifications — without sending probing requests. This is the lowest-noise discovery method and often reveals parameters before any active testing begins.

### §1-1. HTML and DOM Inspection

The simplest form of parameter discovery: examining rendered and raw HTML for input elements, forms, and embedded data.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hidden Input Fields** | `<input type="hidden" name="role" value="user">` — browsers submit these with form data but do not render them visually. Modifying the `value` attribute before submission can alter server-side behavior. | Form-based submission; server trusts client-provided values |
| **Disabled / Read-Only Fields** | `<input disabled name="price" value="100">` — disabled fields are not submitted by default but can be enabled via DOM manipulation or by crafting a raw request including the parameter. | Server processes the parameter if present, regardless of the `disabled` attribute |
| **HTML Comments** | `<!-- TODO: add ?admin_panel=true for internal testing -->` — developer annotations left in production HTML reveal parameter names, internal endpoints, and debug flags. | Comments not stripped during build/deploy |
| **Data Attributes** | `<div data-api-key="..." data-endpoint="/api/internal">` — custom `data-*` attributes store configuration values consumed by JavaScript, often revealing API keys and internal paths. | Frontend framework stores config in DOM |
| **Meta Tags and Link Elements** | `<meta name="csrf-param" content="authenticity_token">` — framework-generated meta tags expose parameter naming conventions and CSRF token field names. | Server-side templating injects meta configuration |

### §1-2. JavaScript Analysis

JavaScript files are the richest static source for parameter discovery. Modern SPAs embed extensive routing, API interaction, and parameter handling logic in client-side bundles.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **URL Construction Patterns** | Functions like `fetch('/api/users?' + 'role=' + role)` or template literals ``/api/${endpoint}?debug=${flag}`` reveal both endpoint paths and parameter names through string concatenation analysis. | Parameters hardcoded or constructed in JS |
| **Query/Body Parsing Functions** | Calls to `URLSearchParams.get('admin')`, `req.query.debug`, `new URL(x).searchParams` expose which parameter names the application expects to receive and process. | Application-specific parsing logic in client bundle |
| **AJAX/Fetch Configuration Objects** | Request configuration objects `{method: 'POST', body: JSON.stringify({role, permissions, isAdmin})}` enumerate every field the API accepts, including those not exposed in the UI. | API calls defined in JavaScript |
| **Route Definitions** | SPA router configurations like `{path: '/admin/:userId', component: AdminPanel}` reveal REST-style path parameters and the existence of hidden administrative routes. | Client-side routing framework (React Router, Vue Router, Angular) |
| **Conditional / Feature-Flag Logic** | `if (params.get('beta_feature')) { enableExperimentalUI() }` — feature flags and A/B testing parameters embedded in conditional branches indicate parameters that activate hidden functionality. | Feature gating implemented client-side |
| **Environment / Config Objects** | `window.__CONFIG__ = {apiBase: '/internal-api', debugMode: false, adminEmail: '...'}` — global configuration objects injected by server-side rendering expose internal settings and parameter defaults. | SSR injects config into global scope |

### §1-3. Source Map Exploitation

When webpack, Rollup, or similar bundlers deploy source maps (`.map` files) to production, the original unminified source code can be fully recovered.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct `.map` File Access** | Appending `.map` to any JavaScript URL (e.g., `app.bundle.js.map`) or following `//# sourceMappingURL=` comments retrieves the mapping file. Tools like `unwebpack-sourcemap` reconstruct the full project directory structure from these files. | Source maps deployed to production (common in SPAs) |
| **Recovered API Client Code** | Extracted source code reveals complete API client libraries with every endpoint, parameter, request/response type, and error handling path — far beyond what the minified bundle exposes. | Application uses typed API clients (TypeScript interfaces, GraphQL codegen) |
| **Internal Documentation Strings** | Comments like `// HACK: remove before release — admin bypass: ?_superuser=1` survive in source maps even when stripped from production bundles. | Developer comments present in source |

### §1-4. API Specification Leakage

API documentation frameworks often expose machine-readable specifications that enumerate every parameter an API accepts, including those intended to be internal.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Swagger / OpenAPI Exposure** | Endpoints like `/swagger.json`, `/api-docs`, `/v2/api-docs`, `/openapi.yaml` return complete API schemas listing all parameters, types, required/optional status, and example values. Even when the Swagger UI is disabled, the JSON/YAML spec may remain accessible. | API docs endpoint not access-controlled |
| **GraphQL Introspection** | The introspection query `{__schema{types{name,fields{name,args{name}}}}}` returns the complete type system including every field, argument, enum value, and mutation — even those not used by the official frontend. | Introspection not disabled in production |
| **GraphQL Field Suggestion Abuse** | When introspection is disabled, deliberately malformed queries trigger error messages like `Did you mean 'adminDeleteUser'?` — suggestion-based enumeration tools (Clairvoyance) reconstruct schemas from these hints. | Error messages include field suggestions |
| **WSDL / WADL Exposure** | SOAP services expose WSDL files at `?wsdl` that define every operation and parameter. REST services sometimes expose WADL at `/application.wadl`. | Legacy service description endpoints active |
| **gRPC Reflection** | gRPC's server reflection service (`grpc.reflection.v1alpha.ServerReflection`) returns complete service and message definitions, revealing all RPC methods and their parameter types. | Reflection service enabled in production |

---

## §2. Dynamic Probing and Fuzzing

Dynamic probing discovers parameters by sending requests with candidate parameter names and observing whether the server's response changes. This is the most direct discovery method but requires careful differential analysis to distinguish genuine parameter acceptance from noise.

### §2-1. Brute-Force Parameter Enumeration

Systematically testing large wordlists of candidate parameter names against target endpoints.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Linear Wordlist Fuzzing** | Each candidate parameter is tested individually in a separate request. Response attributes (status code, body length, headers, response time) are compared to a baseline. Deviations indicate the parameter is processed. | Endpoint produces observable response differences |
| **Binary Search Batching** | Multiple candidate parameters are included in a single request (e.g., 128 at once). If the response changes, the batch is bisected recursively until the responsible parameter is isolated. This reduces total request count from O(n) to O(n/batch + log₂(batch)) for each hit. ParamMiner uses this approach to test ~65,000 parameters efficiently. | Server ignores unknown parameters without erroring |
| **Content-Type Rotation** | The same parameter wordlist is tested across multiple body formats — `application/x-www-form-urlencoded`, `application/json`, `multipart/form-data`, `application/xml` — because servers often accept parameters in formats not used by the official client. | Server parses multiple content types |
| **HTTP Method Rotation** | Parameters are tested across `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS` because different methods may expose different parameter sets. An endpoint accepting `GET ?id=1` may also accept `POST {"id": 1, "role": "admin"}`. | Endpoint handler processes multiple methods |

### §2-2. Differential Response Analysis

The core detection mechanism underlying all dynamic probing — identifying when a server's behavior changes in response to a parameter.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Status Code Differential** | A valid hidden parameter may change the response from `200` to `302`, `403`, or `500` — or from an error to success. For example, adding `?debug=true` might return a `200` with debug output instead of the normal page. | Parameter affects control flow |
| **Body Length Differential** | Response body size changes indicate the parameter influences output content. A parameter like `verbose=1` may add diagnostic information, increasing body length measurably. | Parameter adds/removes content |
| **Header Differential** | New or modified response headers (e.g., `X-Debug-Info`, `Set-Cookie`, `Cache-Control` changes) indicate parameter processing even when the body appears identical. | Parameter triggers header-level side effects |
| **Timing Differential** | Parameters that trigger additional processing (database queries, external API calls, file operations) produce measurable response time differences. A parameter like `export=csv` may add seconds of processing time. | Parameter triggers computationally distinct code path |
| **Reflection Detection** | If the parameter value appears in the response body (reflected), it confirms the parameter is processed. This also immediately flags XSS potential. | Server reflects input in output |
| **Error Message Differential** | Invalid values for a valid parameter produce specific error messages (e.g., `"Invalid value for 'role': must be one of [user, admin, moderator]"`), confirming the parameter exists and revealing its valid values. | Verbose error handling enabled |

### §2-3. Debug and Internal Parameter Probing

Targeted probing for well-known debug, testing, and administrative parameter names that developers frequently leave active in production.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Debug Mode Activation** | Parameters like `debug`, `_debug`, `test`, `verbose`, `trace`, `_trace`, `XDEBUG_SESSION`, `phpinfo` activate diagnostic output, stack traces, SQL queries, or profiling data. | Debug handler not disabled in production |
| **Template / Rendering Override** | Parameters like `template`, `theme`, `layout`, `view`, `render` may override which template is used to render the response, potentially enabling SSTI or information disclosure. | Template engine accepts runtime override |
| **Callback / JSONP Parameters** | `callback`, `jsonp`, `cb` parameters wrap JSON responses in function calls. If reflected without sanitization, they enable XSS: `callback=alert(1)//`. | JSONP support active |
| **Format / Output Parameters** | `format=json`, `output=xml`, `type=csv`, `_format=debug` may switch the response format, sometimes exposing raw data structures or debug representations. | Application supports multiple output formats |
| **Method Override Parameters** | `_method=DELETE`, `X-HTTP-Method-Override: PUT` allow REST method overriding via parameters or headers, potentially accessing destructive operations from `GET`/`POST` requests. | Framework method-override middleware active |

---

## §3. Traffic and Archive Mining

Discovering parameters by analyzing historical, cached, or third-party records of the target application's traffic patterns — without generating new probing requests.

### §3-1. Web Archive Enumeration

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Wayback Machine URL Mining** | The Internet Archive indexes multiple versions of web pages over time. Querying the CDX API (`web.archive.org/cdx/search/cdx?url=target.com/*&output=json&fl=original`) returns all historically archived URLs with their query parameters, revealing parameters that may have been removed from the current version but are still processed server-side. | Target has sufficient archival history |
| **Common Crawl Extraction** | Common Crawl's petabyte-scale web corpus can be queried for all URLs matching a domain, extracting parameter patterns from billions of crawled pages. Arjun's default 25,890-name wordlist was partially derived from Common Crawl data. | Target included in Common Crawl datasets |
| **Google Cache / Cached Pages** | Cached versions of pages in search engines may reveal parameters present in older versions of the application. Google dorks like `site:target.com inurl:?debug` surface indexed URLs with specific parameters. | Search engine has indexed parameterized URLs |

### §3-2. Search Engine and OSINT Dorking

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Google Dorking** | `site:target.com inurl:?admin`, `site:target.com filetype:json`, `site:target.com inurl:api` — targeted search queries surface indexed pages containing specific parameter patterns or API endpoints. | Search engine indexes target URLs with parameters |
| **GitHub / Source Code Repository Dorking** | Searching `"target.com" password OR api_key OR secret` in public repositories reveals hardcoded API parameters, internal endpoint paths, configuration files, and developer notes referencing hidden parameters. | Developers or CI/CD have committed target-related code publicly |
| **Shodan / Censys Banner Analysis** | Internet-wide scan databases index HTTP response headers and page content. Searching for target-specific response patterns may reveal non-standard headers or parameters across different IP ranges and ports. | Target infrastructure indexed by scan services |

### §3-3. Proxy History and Traffic Replay

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Burp Suite Site Map Harvesting** | After crawling or manual browsing, the Burp Suite site map contains every observed URL, parameter, header, and cookie. The GAP (Get All Parameters) extension extracts all parameter names and generates custom wordlists from this corpus. | Sufficient manual browsing or automated crawling performed |
| **Cross-Endpoint Parameter Transplant** | Parameters observed on one endpoint (e.g., `?user_id` on `/profile`) are systematically tested on all other endpoints (e.g., `/settings`, `/api/data`). Parameters are often processed by middleware that applies to multiple routes. | Shared middleware or framework-level parameter processing |
| **ZAP / mitmproxy Log Analysis** | Exporting and parsing traffic logs from any intercepting proxy to build domain-specific parameter dictionaries. Automated scripts extract unique parameter names, values, and patterns. | Proxy history available from testing session |

---

## §4. Protocol and Format Manipulation

Discovering hidden parameters by exploiting how servers parse, transform, and route HTTP messages — leveraging format ambiguities, encoding differences, and processing pipeline discrepancies.

### §4-1. HTTP Parameter Pollution (HPP)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Duplicate Parameter Injection** | Submitting the same parameter name multiple times (`?role=user&role=admin`). Different technologies handle duplicates differently: PHP uses the **last** value, ASP.NET **concatenates** all values, Node.js/Express uses the **first** value. If a WAF checks one occurrence but the application processes another, the attacker's value prevails. | Technology-specific duplicate handling differs between security layer and application |
| **Server-Side Parameter Pollution (SSPP)** | When user input is embedded into a server-side request to an internal API without proper encoding, injecting `&admin=true` or `#` (URL-encoded) into the input can add or truncate parameters in the internal request. For example, input `peter%26role%3Dadmin` becomes `name=peter&role=admin` in the backend query. | Application constructs internal API requests using user input |
| **Path Parameter Injection** | In REST-style APIs, injecting path traversal sequences (`../admin`) or additional path segments into user-controlled path parameters can access different API resources. Input `userID=123/../../admin/config` may resolve to `/api/admin/config`. | REST URL construction uses string concatenation |
| **Query String Truncation** | Injecting a URL-encoded `#` character (`%23`) into a parameter value truncates the server-side query string at that point, removing subsequent parameters (e.g., security constraints like `&verified=true`) from the internal request. | Server-side request includes attacker-controlled value before security-critical parameters |

### §4-2. Content-Type Juggling

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JSON ↔ Form Switching** | Changing `Content-Type: application/x-www-form-urlencoded` to `Content-Type: application/json` (or vice versa) while adjusting body format. Many frameworks auto-detect and parse both formats, but WAFs or validation logic may only inspect one format. Parameters rejected in form encoding may be accepted in JSON. | Framework parses body based on Content-Type header; validation only covers one format |
| **JSON ↔ XML Switching** | Changing to `Content-Type: application/xml` enables XXE attacks on endpoints that normally accept JSON. The server-side parser may accept XML and map elements to the same parameter names, adding attack surface (entity expansion, external entity inclusion). | Server-side parser supports multiple formats |
| **Multipart Boundary Manipulation** | Crafting multipart bodies with unusual boundary strings, nested parts, or mixed content types within parts. Discrepancies between how WAFs and applications parse multipart boundaries can hide parameters from inspection. | WAF and application parse multipart differently |
| **Charset Encoding Tricks** | Specifying unusual charsets (`Content-Type: application/json; charset=utf-7`, or dual charsets `charset=utf-8;charset=utf-16`) causes the WAF to parse with one encoding while the application uses another, hiding malicious parameter values. | WAF charset handling differs from application |
| **text/plain Abuse** | Sending `Content-Type: text/plain` with a JSON or form-encoded body. Some applications parse the body regardless of Content-Type, while WAFs configured to inspect only `application/json` or `application/x-www-form-urlencoded` skip inspection entirely. | Application parses body independent of Content-Type; WAF filters by Content-Type |

### §4-3. Encoding and Escaping Variations

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Double URL Encoding** | Parameter names like `%2564ebug` (double-encoded `debug`) bypass filters that decode only once. The application's second decoding pass reveals the actual parameter name. | Multi-layer decoding in request pipeline |
| **Unicode Normalization** | Using Unicode equivalents (`\u0064ebug` for `debug`, fullwidth characters `ｄｅｂｕｇ`) that normalize to ASCII parameter names after server-side processing. | Server performs Unicode normalization |
| **Null Byte Injection** | Inserting `%00` within parameter names or values (`debug%00=true`) may terminate string processing in C-based parsers while being ignored by higher-level frameworks, creating parameter parsing discrepancies. | Mixed C/native and managed language processing |
| **JSON Key Variations** | JSON parsers may accept duplicate keys (`{"role":"user","role":"admin"}`), Unicode-escaped keys (`{"\u0072ole":"admin"}`), or keys with whitespace/special characters. Different parsers handle these inconsistently. | Backend JSON parser has permissive key handling |

---

## §5. Schema and Type System Enumeration

Discovering hidden parameters through structured API schemas, type systems, and reflection capabilities that programmatically describe available fields and operations.

### §5-1. GraphQL Schema Enumeration

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Full Introspection Query** | The standard introspection query returns every type, field, argument, enum value, and directive in the schema — including internal fields like `deleteUser`, `setRole`, or `adminConfig` that no frontend query uses. | Introspection enabled (common in development, often left in production) |
| **Suggestion-Based Reconstruction** | When introspection is disabled, sending queries with intentionally misspelled field names triggers error suggestions: `Cannot query field "admi". Did you mean "admin", "adminPanel"?`. Tools like Clairvoyance automate iterative reconstruction of the full schema from these suggestions. | GraphQL error messages include field suggestions |
| **Enum Value Discovery** | Introspection reveals all enum values including internal states: `enum UserRole { USER MODERATOR ADMIN SUPER_ADMIN INTERNAL_SERVICE }`. These values can be used in mutations to escalate privileges. | Enum types not filtered from introspection response |
| **Deprecated Field Access** | Fields marked `@deprecated` in the schema are still functional — deprecation is a documentation hint, not an access control mechanism. Deprecated fields often represent legacy functionality with weaker security controls. | Deprecated fields remain queryable |
| **Mutation Argument Enumeration** | Introspection reveals all arguments accepted by mutations, including optional arguments not used by the official client. A `updateUser` mutation may accept `role`, `permissions`, or `isVerified` arguments that the UI never sends. | Mutations accept more arguments than the UI exposes |

### §5-2. REST API Schema Inference

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **OPTIONS / CORS Preflight Enumeration** | `OPTIONS` requests may return `Allow` headers listing supported methods, and CORS headers revealing allowed origins and headers — including custom header-based parameters like `X-Admin-Token`. | Server responds to OPTIONS with detailed capability information |
| **Error-Driven Schema Discovery** | Sending malformed requests (wrong types, missing required fields) triggers validation errors that reveal the expected schema: `"Missing required field: email. Expected fields: name, email, role, department"`. | Verbose validation error messages enabled |
| **API Versioning Differential** | Comparing parameter sets across API versions (`/v1/users` vs `/v2/users`) reveals parameters added, removed, or renamed. Older versions often accept parameters that have been removed from newer versions but remain functional on legacy endpoints. | Multiple API versions co-exist |
| **Wildcard / Mass Assignment Probing** | Sending requests with extra JSON fields (`{"name":"test","role":"admin","isActive":true}`) and checking if the additional fields are persisted. Frameworks with automatic model binding (Rails `params.permit!`, Django `ModelForm`, Spring `@ModelAttribute`) may accept any field matching a database column. | ORM/framework auto-binds request parameters to model attributes |

---

## §6. Inference and Side-Channel Discovery

Discovering hidden parameters through indirect observation — timing differences, error behavior, cache behavior, and other side effects that reveal parameter processing without explicit confirmation in the response body.

### §6-1. Timing-Based Inference

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Database Query Timing** | A valid parameter that triggers a database lookup produces measurably longer response times than an ignored parameter. If `?user_id=1` adds 50ms compared to baseline, the parameter is processed even if the response body is identical. | Parameter triggers backend data access |
| **Conditional Processing Timing** | Parameters like `export=pdf` may trigger expensive operations (PDF generation, report compilation) producing large timing deltas (seconds vs. milliseconds). | Parameter activates computationally expensive code path |
| **Authentication Check Timing** | Parameters related to authorization (e.g., `admin_token`) may trigger additional authentication checks that produce timing differences — a valid parameter name with an invalid value may still take longer than a nonexistent parameter. | Authorization middleware triggers on specific parameter names |

### §6-2. Cache Behavior Analysis

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unkeyed Parameter Discovery** | Parameters excluded from the cache key can poison cached responses. If adding `?utm_source=test` does not change the `X-Cache` behavior (still returns `HIT`), the parameter is unkeyed. If the parameter value is reflected in the response, it enables cache poisoning: all subsequent users receive the attacker's injected content. | CDN/cache excludes certain parameters from cache key |
| **Unkeyed Header Discovery** | Headers like `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL` may be processed by the application but excluded from the cache key. ParamMiner's "Guess Headers" function systematically tests for unkeyed headers by injecting values and checking for cache behavior differences. | Reverse proxy/CDN excludes headers from cache key |
| **Cache Key Normalization** | Some caches normalize query parameters (sorting, deduplication, decoding) before key generation. If the cache normalizes `?B=2&A=1` to `?A=1&B=2` but the application processes them in original order, parameter ordering can create cache poisoning conditions. | Cache and application normalize differently |
| **Fat GET / Keyed Body Discovery** | Some caches incorrectly cache `GET` requests that include a body ("fat GET"). If the body content is not part of the cache key, body parameters can poison the cache. Testing involves sending `GET` requests with `Content-Type` and body parameters. | Cache does not account for GET request bodies |

### §6-3. Error-Based Inference

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Stack Trace Parameter Leakage** | When a parameter triggers an error, stack traces may reveal other parameter names processed in the same code path, internal variable names, and function signatures that indicate additional hidden parameters. | Debug/verbose error mode enabled |
| **Type Coercion Errors** | Sending a string value for a numeric parameter (`?count=abc`) produces type errors that confirm the parameter exists and reveal its expected type: `"Cannot convert 'abc' to integer for parameter 'count'"`. | Application performs type checking with verbose errors |
| **Rate Limit / Throttle Differential** | Hidden parameters related to rate limiting (`?burst`, `?limit`, `?throttle`) may be discoverable by observing whether they alter rate-limit response headers (`X-RateLimit-Remaining`) or delay enforcement. | Rate limiter reads parameters from request |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Condition | Primary Mutation Categories |
|----------|-------------------------|---------------------------|
| **Privilege Escalation / Mass Assignment** | Framework auto-binds request params to model; `role`, `is_admin`, `permissions` fields unprotected | §2-3 + §5-2 (wildcard probing + schema inference) |
| **IDOR / Access Control Bypass** | Hidden `user_id`, `account_id`, or `org_id` parameters accepted without authorization check | §2-1 + §3-3 (fuzzing + cross-endpoint transplant) |
| **Cache Poisoning** | Unkeyed parameters/headers reflected in cached responses | §6-2 + §4-1 (cache analysis + HPP) |
| **Injection (XSS, SQLi, CMDi)** | Hidden parameter reflected in output or passed to database/OS command without sanitization | §1-2 + §2-2 (JS analysis + differential response with reflection) |
| **Information Disclosure** | Debug parameters activate verbose output, stack traces, or internal configuration dumps | §2-3 + §1-3 (debug probing + source map exploitation) |
| **Server-Side Request Manipulation** | Hidden URL/host parameters passed to server-side HTTP client (SSRF chain) | §4-1 + §2-1 (SSPP + parameter fuzzing) |
| **Authentication Bypass** | Hidden parameters override auth state (`?authenticated=true`, `?bypass_mfa=1`) or method override (`_method=DELETE`) | §2-3 + §4-1 (debug/internal probing + method override) |
| **Prototype Pollution** | Hidden `__proto__`, `constructor.prototype` fields in JSON body accepted by merge/assign functions | §5-2 + §4-2 (mass assignment probing + content-type juggling) |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §5-2 (Mass Assignment) | CVE-2025-2304 — Camaleon CMS 2.9.0 `permit!` in UsersController allows any registered user to escalate to administrator by injecting `role` parameter | Critical privilege escalation |
| §4-3 (JSON Key) + §5-2 | CVE-2024-38983 — `mini-deep-assign` prototype pollution via `__proto__` key in deep merge | RCE / DoS / XSS via prototype pollution |
| §5-1 (GraphQL Introspection) | CVE-2025-27507 — ZITADEL Admin API IDOR via introspection-discovered gRPC methods; non-admin users access admin operations | Unauthorized admin access |
| §6-2 (Unkeyed Header) | Multiple — `X-Forwarded-Host` cache poisoning across CDNs | XSS via cached response poisoning |
| §2-3 (Debug Param) | Multiple bug bounty reports — `?debug=true`, `_debug=1` exposing database credentials, API keys, internal IPs in production | Information disclosure ($500–$5,000+ bounties) |
| §5-2 (Mass Assignment) | CVE-2024-7041 — IDOR via hidden parameter allowing unauthorized data access | Broken access control |
| §4-2 (Content-Type Juggling) | WAFFLED research (2025) — 1,207+ WAF bypasses via content-type parsing discrepancies across AWS WAF, Cloudflare, Azure, ModSecurity | WAF bypass enabling downstream injection |
| §1-3 (Source Map) | Multiple bounty programs — Webpack sourcemaps revealing admin endpoints, enabling account takeover via undocumented password-change API | Account takeover ($2,000–$10,000+ bounties) |

---

## Detection Tools

### Offensive / Discovery Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Arjun** (Python) | GET/POST/JSON parameter fuzzing | Wordlist-based brute-force with 25,890 default params (CommonCrawl + SecLists derived); differential response analysis |
| **x8** (Rust) | Hidden parameter discovery across all HTTP methods | High-performance parallel fuzzing with custom wordlist support; multiple encoding support |
| **ParamMiner** (Burp Extension) | Query, header, and cookie parameter discovery | Binary search batching (~65,000 params/request); built-in wordlist + in-scope traffic harvesting; cache poisoning detection |
| **GAP / GetAllParams** (Burp Extension) | Passive parameter collection from traffic | Extracts all parameter names from site map; generates custom wordlists from observed traffic |
| **ParamSpider** (Python) | Wayback Machine URL parameter mining | Queries web archive CDX API; filters and extracts unique parameter names from historical URLs |
| **Clairvoyance** (Python) | GraphQL schema reconstruction | Suggestion-based field enumeration when introspection is disabled; iterative schema recovery |
| **debugHunter** (Go) | Debug parameter detection | Tests common debug/test parameter names against targets; detects diagnostic output activation |
| **LinkFinder** (Python) | JavaScript endpoint/parameter extraction | Regex-based extraction of URLs, paths, and parameters from JS files |
| **Webcrack** (Node.js) | JavaScript deobfuscation and webpack unpacking | Deobfuscates obfuscator.io output; unminifies; extracts original source from bundles |
| **unwebpack-sourcemap** (Python) | Source map extraction | Reconstructs full project directory from deployed `.map` files |
| **ffuf** (Go) | General-purpose web fuzzer | FUZZ keyword substitution for parameter name/value fuzzing; supports multiple positions |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **WAF (ModSecurity, Cloudflare, AWS WAF)** | Parameter-based attack detection | Rule-based inspection of known attack patterns in parameter values; limited coverage of unknown parameters |
| **API Gateways (Kong, Apigee)** | Parameter allowlisting | Schema validation against OpenAPI spec; reject unknown parameters |
| **Strong Parameter Patterns** | Mass assignment prevention | Framework-level parameter allowlisting (Rails `params.require().permit()`, Django `ModelForm.fields`) |
| **GraphQL Armor / Escape** | GraphQL security hardening | Disable introspection, suppress suggestions, depth limiting, field-level authorization |

---

## Summary: Core Principles

### Root Cause: Obscurity as Access Control

The fundamental property that makes hidden parameter discovery possible is the **conflation of obscurity with security**. Web applications universally process more parameters than they document — debug flags left from development, administrative fields protected only by their absence from the UI, framework-level automatic binding that accepts any matching field name. The application's "visible" interface (HTML forms, API documentation, client-side code) represents only a subset of its actual input surface. Every undocumented parameter processed server-side is a potential attack vector that bypasses all client-side validation and UI-level access controls.

### Why Incremental Fixes Fail

Removing individual hidden parameters is a game of whack-a-mole. New parameters are continuously introduced through framework upgrades (adding new config parameters), developer debugging (adding temporary debug flags), feature development (adding parameters gated by feature flags), and third-party integrations (adding callback/webhook parameters). Each new code deployment potentially introduces new hidden parameters. WAF-based detection cannot solve this because the attack is not in the parameter *value* but in the parameter's *existence* — WAFs are designed to detect malicious values, not to enforce parameter allowlists.

### Structural Solutions

The structural solution requires **positive security models**: explicit parameter allowlisting at every processing layer. This means strict parameter schemas at the API gateway (rejecting any parameter not in the OpenAPI spec), framework-level strong parameter patterns (Rails `permit`, Django explicit `fields`), disabled debug/introspection/reflection in production deployments, source map exclusion from production builds, and treating parameter names as part of the access control surface — not just their values. The shift from "block known bad" to "allow known good" is the only approach that scales against the continuously expanding parameter surface.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- OWASP Web Security Testing Guide — Testing for HTTP Parameter Pollution
- PortSwigger Web Security Academy — Server-Side Parameter Pollution, Web Cache Poisoning, GraphQL API Vulnerabilities
- PayloadsAllTheThings — Hidden Parameters Reference (swisskyrepo)
- YesWeHack — Parameter Discovery Quick Guide; Discover & Map Hidden Endpoints
- Intigriti — Finding Hidden Input Parameters: Advanced Enumeration Guide
- WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls (2025)
- Arjun GitHub Repository (s0md3v) — HTTP Parameter Discovery Suite
- x8 GitHub Repository (Sh1Yo) — Hidden Parameters Discovery Suite
- Clairvoyance — GraphQL Schema Reconstruction Tool
- debugHunter — Hidden Debugging Parameter Discovery Tool
- PortSwigger Param Miner — Burp Suite Extension Documentation
- GraphQL Official Documentation — Introspection System
- HackTricks — GraphQL Pentesting, Cache Poisoning, Parameter Pollution
- The Hacker Recipes — Content-Type Juggling, HTTP Parameter Pollution
