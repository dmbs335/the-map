# Secondary Context Attack — Mutation/Variation Taxonomy

> **Scope**: Vulnerabilities where user-controlled data traverses a trust boundary between two processing contexts (frontend ↔ backend, proxy ↔ origin, gateway ↔ microservice, cloud service ↔ IAM) and the receiving context interprets it differently than the sending context validated it. This encompasses Sam Curry's "Attacking Secondary Contexts in Web Applications" class and its structural relatives across the modern web stack.

---

## Classification Structure

Secondary Context Attacks exploit a fundamental architectural pattern: **a trusted intermediary forwards user input to a downstream system under different semantic rules than those under which the input was originally validated**. The intermediary (proxy, BFF, API gateway, GraphQL layer, cloud service) creates a "secondary context" — a second processing environment where the input is reinterpreted, re-parsed, or re-routed.

Three orthogonal axes classify the full mutation space:

### Axis 1 — Injection Vector (WHAT user-controlled element is weaponized)

The structural component of the request that carries the payload across the context boundary.

### Axis 2 — Discrepancy Type (WHAT semantic mismatch is exploited)

The nature of the interpretation gap between the two contexts.

| Discrepancy Type | Definition |
|---|---|
| **Path Normalization Differential** | The two contexts normalize URL paths differently (encoding, dot-segments, delimiters) |
| **Parser Differential** | The two contexts use different URL/header/body parsers with incompatible RFC compliance |
| **Trust Boundary Collapse** | The downstream context implicitly trusts requests from the intermediary, dropping authz checks |
| **Semantic Role Confusion** | A data structure field (e.g., `r->filename`) is treated as a URL in one context and a filesystem path in another |
| **Routing Table Divergence** | The proxy routing rules don't match the backend's endpoint map, creating reachable-but-unintended routes |
| **Delegation Confusion** | A service assumes that a request from another service carries that service's privileges, not an attacker's |

### Axis 3 — Attack Scenario (WHERE it's weaponized)

| Scenario | Architecture |
|---|---|
| **BFF/Proxy Path Escape** | Backend-for-Frontend or reverse proxy forwarding to internal microservices |
| **API Gateway Bypass** | Centralized gateway routing to per-service backends |
| **GraphQL Relay Pivot** | GraphQL layer translating queries/mutations into REST calls |
| **Cloud Service Confused Deputy** | Cloud-managed service assuming IAM roles on behalf of tenants |
| **Cache Layer Exploitation** | CDN/cache interpreting paths differently than origin server |
| **Service Mesh Identity Theft** | Sidecar proxy sharing trust context with compromised containers |
| **Webhook/Callback SSRF** | Application making server-side requests to user-supplied callback URLs |

---

## §1. Path Traversal Across Context Boundaries

The most direct form of secondary context attack: injecting directory traversal sequences into parameters that the intermediary forwards as part of a URL path to a downstream service.

### §1-1. BFF Proxy Path Escape

The Backend-for-Frontend pattern aggregates multiple internal APIs behind a single origin. A route like `/bff/proxy/{service}/{path}` constructs an internal URL by concatenating a base address with user-supplied path segments. If the BFF does not canonicalize the path before forwarding, traversal sequences reach the internal service verbatim.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct `../` in path parameter** | A parameterized segment (e.g., `:streamItemId`) accepts traversal sequences; the BFF concatenates them into the internal URL | BFF performs no path canonicalization; WAF does not inspect deep path segments |
| **Mixed separator traversal** | Using backslash-dot sequences (`web\..\..\`) to bypass WAF pattern matching while the backend normalizes to forward slashes | Windows-based backends or backends that normalize `\` → `/`; WAF only checks `/..` patterns |
| **Double-encoding traversal** | Sending `%252e%252e%252f` so the proxy decodes once (to `%2e%2e%2f`) and the backend decodes again (to `../`) | Proxy and backend perform URL decoding at different pipeline stages |
| **Null-byte truncation** | Appending `%00` after a traversal path to truncate extension checks or suffix matching | Legacy backends (PHP, older Java) that pass paths through C-string APIs |

The Starbucks `/bff/proxy/` vulnerability is the canonical example: traversal from a parameterized endpoint reached an internal Microsoft Graph instance exposing ~100 million customer records ($4,000 bounty).

### §1-2. API Gateway Route Escape

API gateways (Kong, AWS API Gateway, Apigee, custom Nginx/HAProxy configs) map external route prefixes to internal service addresses. Path traversal in the suffix portion escapes the intended service scope.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Prefix-stripping traversal** | Gateway strips `/api/v1/` prefix and forwards the remainder; payload `/api/v1/../../admin/` reaches backend as `/admin/` | Gateway strips prefix before normalization; backend normalizes dot-segments |
| **Missing trailing slash** | `location /api` (no trailing slash) proxied to `http://backend/v1/`; requesting `/api../` reaches `http://backend/` root | Nginx `proxy_pass` without matching trailing slash on both location and upstream |
| **Encoded-slash bypass** | `%2f` in the path survives gateway routing but gets decoded by the backend, creating a new path segment | Gateway treats `%2f` as literal character in routing; backend decodes it as `/` |

Azure API Management disclosed three high-severity vulnerabilities in this class, including SSRF via CORS proxy and path traversal in hosting proxy.

### §1-3. GraphQL Relay Path Injection

GraphQL servers acting as BFFs translate query arguments into REST API calls to backend microservices. The `ID` scalar type performs no format validation by default, accepting arbitrary strings including traversal payloads.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ID field traversal** | A GraphQL `ID` argument like `contactId` is interpolated into a REST URL (`/api/contacts/{id}`); injecting `../../other-service` pivots to a different backend endpoint | Backend constructs URLs via string concatenation; no UUID validation on ID fields |
| **Relay Node global ID abuse** | The Relay specification requires every node to be accessible via a globally unique base64-encoded ID (`typename:id`); forging IDs for other types accesses cross-type data | Relay node resolution doesn't verify that the requesting user has access to the resolved type |
| **Nested resolver chain traversal** | A deeply nested GraphQL query triggers multiple sequential REST calls; traversal in an intermediate field redirects a downstream call | Each resolver independently constructs backend URLs; no path validation between resolution steps |

Error messages from failed traversal attempts often leak internal routing structure (e.g., `Cannot GET /api/contacts/../../admin`), enabling incremental path discovery.

---

## §2. URL/Host Routing Manipulation

Rather than traversing within a path, these mutations manipulate which **host or service** the intermediary routes the request to.

### §2-1. Host Header Injection Through Proxy

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Host override via `X-Forwarded-Host`** | Proxy trusts `X-Forwarded-Host` for backend routing; attacker overrides it to reach an internal virtual host | Backend uses Host header for virtual host resolution; proxy doesn't sanitize forwarded headers |
| **Absolute URI host confusion** | Sending an absolute URI in the request line (`GET http://internal-host/path HTTP/1.1`) causes the proxy to route to the specified host | Proxy implements HTTP/1.1 absolute-URI parsing and forwards to the authority component |
| **HTTP/2 `:authority` pseudo-header mismatch** | The `:authority` pseudo-header disagrees with the `Host` header; proxy routes on one, backend authorizes on the other | Proxy and backend extract the routing host from different headers |

### §2-2. SNI-Based Routing Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SNI regex bypass** | TLS-terminating load balancer uses a regex to match SNI hostname; unescaped `.` or missing `$` anchor allows `legitimate.com.attacker.com` to match | Regex pattern lacks proper escaping and anchoring |
| **SNI/Host desync** | SNI indicates one service for TLS routing; the decrypted HTTP Host header targets a different internal service | TLS terminator routes on SNI; backend routes on Host; no consistency check |

### §2-3. Webhook and Callback URL SSRF

Applications that accept user-supplied URLs for callbacks, webhooks, or integrations create a direct secondary context: the server's HTTP client becomes the downstream processor.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct internal URL** | Webhook URL points to `http://169.254.169.254/latest/meta-data/` or internal service addresses | No allowlist validation or SSRF protection on callback URLs |
| **DNS rebinding** | URL resolves to a public IP during validation but to `127.0.0.1` at request time (short TTL) | Validation and request occur in separate DNS resolution contexts (TOCTOU) |
| **Redirect chain SSRF** | URL points to an attacker server that 302-redirects to an internal address | Application follows redirects without re-validating each hop against the allowlist |
| **Protocol smuggling** | URL uses `gopher://`, `dict://`, or `file://` scheme to interact with non-HTTP internal services | HTTP client library supports multiple protocols; scheme validation only checks for `http(s)` |

Webhook SSRF has seen a 452% surge between 2023-2024, driven by the explosion of AI/ML pipelines and integration platforms that accept model endpoint URLs.

---

## §3. Parser Differential Exploitation

When the intermediary and the backend use different parsers (URL parsers, HTTP parsers, path normalizers), the same byte sequence produces different semantic interpretations.

### §3-1. URL Parser Differentials

Different programming languages implement different URL RFCs. NodeJS follows WHATWG; Ruby and Go follow RFC 3986 strictly; Python's `urllib` has its own quirks. When a validation layer uses one parser and the request executor uses another, the semantic gap becomes exploitable.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Authority confusion via `@`** | `http://allowlisted-host@evil-host/` — validator extracts `allowlisted-host` as the authority; request library sends to `evil-host` | Validator parses userinfo differently from the HTTP client |
| **Backslash-as-delimiter confusion** | WHATWG treats `\` as equivalent to `/` in the authority; RFC 3986 parsers treat it as part of the path or userinfo | Proxy follows WHATWG; backend follows RFC 3986 (or vice versa) |
| **Fragment truncation differential** | `http://evil-host#@allowlisted-host` — one parser ignores the fragment (sending to `evil-host`), another includes it in authority resolution | Different fragment-handling behavior between validation parser and HTTP client |
| **Extra-slash authority confusion** | `http:///evil-host/` — parsers disagree on whether the empty authority means localhost or the next segment is the authority | Parser treats triple-slash as empty authority + path vs. scheme + authority |
| **Encoded-dot path confusion** | `http://host/%2e%2e/secret` — validator sees a literal `%2e%2e` path segment; backend decodes it as `../` | Validation occurs before URL decoding; request execution occurs after |

The Log4Shell patch bypass (CVE-2021-45046) exploited an incomplete fix in the initial patch: in non-default configurations (PatternLayout using Thread Context Map/MDC data), the `allowedLdapHosts`/`allowedLdapClasses` restrictions could be bypassed to perform JNDI lookups. This was a configuration-level bypass, not a URL parser differential.

### §3-2. HTTP Server Semantic Confusion

Within a single HTTP server (notably Apache httpd), different modules interpret the same internal data structure differently, creating intra-server secondary contexts.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Filename confusion** | `mod_rewrite` treats `r->filename` as a URL; `mod_alias` treats it as a filesystem path; a RewriteRule output that looks like a URL gets served as a local file | Apache httpd with RewriteRule + mod_alias/mod_proxy interaction |
| **DocumentRoot confusion** | RewriteRule mapping causes httpd to check both relative and absolute paths; injecting an absolute path escapes DocumentRoot | Apache with permissive RewriteRule patterns |
| **Handler confusion** | `mod_proxy` treats `r->filename` as a URL to proxy; a crafted request triggers proxy behavior on what should be a local file handler | Misconfigured `SetHandler` or `ProxyPass` with overlapping path patterns |
| **`?`-based ACL bypass** | Appending `?` to a URL bypasses Apache's built-in `<Location>` ACL matching while the backend still serves the content | Apache ACL pattern matching doesn't account for query-string-prefixed path segments |

This class yielded 9 new vulnerabilities and 20 exploitation techniques in a single Apache httpd audit (CVE-2024-38472 through CVE-2024-38477, addressed in httpd 2.4.60).

### §3-3. Proxy ↔ Backend Normalization Mismatch

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Nginx decode-before-route vs. backend decode-after-route** | Nginx normalizes and decodes the path before matching `location` directives; the backend receives the decoded form and may decode again | Double-decoding gap between Nginx and backend |
| **Tomcat `/..;/` normalization** | Tomcat treats `/..;/` as `/../` and normalizes it; Nginx/HAProxy pass it through verbatim, so Tomcat receives a path the proxy's ACL didn't evaluate | Tomcat behind a reverse proxy that doesn't understand `;` as a path parameter separator |
| **Non-printable character bypass** | Characters like `\xa0` don't trigger Nginx ACL rules but are stripped by the backend, revealing the protected path underneath | Proxy ACL uses character-class matching that excludes non-printable bytes |
| **Case-sensitivity mismatch** | Proxy ACL matching is case-sensitive (`/Admin` ≠ `/admin`); backend filesystem or router is case-insensitive | Windows backend or case-insensitive routing framework behind a Unix-based proxy |

---

## §4. Trust Boundary Collapse in Microservice Architectures

When inter-service communication is assumed to be trusted, the secondary context (the receiving microservice) drops authorization checks that the primary context (the gateway) was supposed to enforce.

### §4-1. Implicit Trust in Internal APIs

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Gateway-only authz** | Authentication and authorization are enforced only at the API gateway; internal microservices accept any request from the internal network | Microservices have no independent authz; network segmentation is flat |
| **Privilege inheritance assumption** | Internal service assumes a request from Service A carries Service A's privileges, not the end user's | No end-user identity propagation (JWT forwarding, mTLS with user context) between services |
| **Debug/admin endpoint exposure** | Internal services expose Swagger, health checks, metrics, or admin endpoints on the same port; traversal from the gateway reaches them | No path-based filtering at the service level; internal endpoints not segmented |
| **Centralized authz path bypass** | Gateway enforces ACL via path matching (`/admin/*` → require admin role); traversal payload `/public/../admin/` reaches backend after normalization | Gateway checks the raw path; backend normalizes before routing |

The Starbucks attack chain demonstrated this pattern: after path traversal escaped the BFF proxy, the internal Microsoft Graph instance had no additional authentication, exposing 100 million records.

### §4-2. Service Mesh and Sidecar Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Sidecar certificate theft ("Sidecar Siphon")** | Compromised application container reads the sidecar's mTLS private key from the shared filesystem, then impersonates any service | Sidecar and application share a network namespace and filesystem; SA token accessible at `/var/run/secrets/` |
| **iptables bypass via `CAP_NET_ADMIN`** | Container with `CAP_NET_ADMIN` rewrites iptables rules that route traffic through the Envoy sidecar, enabling direct backend access | Container has elevated Linux capabilities |
| **Sidecar injection bypass (UID 1337)** | Creating a pod with UID 1337 prevents Istio sidecar injection, allowing unmonitored communication | Service account has pod creation rights; no admission controller validates sidecar presence |
| **Ambient mesh ztunnel bypass** | In Istio Ambient Mesh, the ztunnel node agent handles mTLS; compromising the node allows intercepting all pod traffic | Node-level compromise; no per-pod isolation of crypto material |

### §4-3. GraphQL Authorization Gap

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Edge-only authorization** | Authorization is checked when resolving the top-level query field but not when traversing edges to related objects | Schema design assumes graph traversal implies authorization |
| **Mutation privilege escalation** | A mutation intended for user-scoped data accepts an arbitrary ID, modifying another user's data via the backend API | Backend REST API has no per-user scoping; GraphQL layer doesn't inject user context |
| **Introspection-guided enumeration** | Introspection reveals internal types, fields, and relationships not intended for external use, guiding secondary context exploration | Introspection enabled in production; schema includes internal-only types |

---

## §5. Cloud Service Delegation Confusion (Confused Deputy)

Cloud platforms manage services that assume IAM roles on behalf of tenants. When the delegation chain doesn't properly bind the caller's identity, an attacker can trick the service into assuming arbitrary roles.

### §5-1. Cross-Tenant Role Assumption

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ARN validation bypass** | Cloud service validates role ARN format but accepts case variations (e.g., `servicerolearn` vs `serviceRoleArn`), bypassing the validation check | Case-insensitive parameter handling in API; validation only checks one casing |
| **Missing `ExternalId` enforcement** | Cross-account role trust policy doesn't require `ExternalId`; any entity that knows the role ARN can assume it via the confused deputy service | Trust policy uses `sts:AssumeRole` without `sts:ExternalId` condition |
| **Overly permissive trust policy** | Role trusts an entire AWS service principal (`service.amazonaws.com`) without account-scoping conditions (`aws:SourceAccount`, `aws:SourceArn`) | No condition keys in the trust policy; service operates across all accounts |
| **CloudTrail log injection** | Attacker triggers a service to write CloudTrail logs into a victim's S3 bucket (lacking condition keys), poisoning the audit trail | S3 bucket policy trusts `cloudtrail.amazonaws.com` without account restriction |

The AWS AppSync confused deputy vulnerability (AWS-2022-009) allowed cross-tenant role assumption via a case-sensitivity bypass in the `serviceRoleArn` parameter. A 2024 survey found 37% of vendors implementing AWS integrations had not implemented `ExternalId` correctly.

### §5-2. Service-Chaining Escalation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Internal SSRF from managed service** | Cloud-managed service (e.g., Lambda, AppSync) makes internal API calls; SSRF in the service reaches the cloud control plane or metadata service | Service runs in a VPC with access to `169.254.169.254` or internal APIs |
| **Function-to-function privilege confusion** | Serverless function A invokes function B with A's execution role; B assumes the caller is authorized for the action | No caller identity verification in the invoked function; role-based trust only |
| **Storage event trigger manipulation** | Attacker uploads a crafted object to a shared bucket, triggering a Lambda function that processes it with elevated privileges | Event-driven architecture without input validation in the triggered function |

---

## §6. Cache Layer Context Divergence

CDNs and caching proxies create a secondary context where the **cache key** (how the request is identified) can differ from the **origin interpretation** (how the request is processed), enabling both cache deception and cache poisoning.

### §6-1. Path Confusion for Cache Deception

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Static extension appending** | Requesting `/api/user/profile.css` — cache sees a static resource and caches it; origin ignores the extension and serves the dynamic profile | Cache uses extension-based caching rules; origin uses path-prefix routing |
| **Delimiter confusion** | `/api/user/profile;.css` or `/api/user/profile%23.css` — delimiter terminates the path at the origin but is included in the cache key | Cache and origin disagree on which characters are path delimiters |
| **Dot-segment normalization gap** | `/static/../api/user/profile` — cache normalizes to `/api/user/profile` (non-static, uncached); but origin receives it as a request matching `/static/` prefix (cached) | Cache normalizes before keying; origin matches the raw path |

ChatGPT suffered a wildcard web cache deception vulnerability (2024) that enabled account takeover through this class of attack.

### §6-2. Path Confusion for Cache Poisoning

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unkeyed header injection** | Cache doesn't include headers like `X-Forwarded-Host` in the cache key; attacker poisons the cached response for all users | CDN strips varying headers from cache key; origin reflects them in response |
| **Path parameter cache key collision** | `/page;param=value` and `/page` produce the same cache key but different origin responses | Cache ignores path parameters; origin uses them for content selection |
| **Normalization-based key collision** | URL-encoded path and decoded path produce the same cache key but trigger different origin behaviors | Cache normalizes the key; origin receives the raw (encoded) request |

---

## §7. Second-Order / Stored Secondary Context Attacks

Unlike the real-time proxy-based attacks above, these mutations involve **storing** a payload in one context that is later **retrieved and processed** in a different context.

### §7-1. Stored URL/Path Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Second-order SSRF** | A URL stored in a database (profile avatar, webhook config) is later fetched by a background job or internal service | Storage validation is looser than execution-time validation; or validation only occurs at storage time |
| **Stored path traversal** | A filename stored via upload is later used in a file-serving endpoint with a different path resolution context | Upload handler sanitizes for web paths; download handler constructs filesystem paths |
| **Template injection via stored context** | User input stored in a template variable is later rendered in a server-side template engine (Jinja2, Thymeleaf) without re-escaping | Template renders in a different security context than the input was validated for |

### §7-2. Cross-Protocol Context Switching

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **HTTP → SMTP injection** | Data validated for HTTP context is used to construct SMTP commands (password reset, notification emails) | Email body/header is constructed via string concatenation with user input; CRLF injection possible |
| **HTTP → LDAP injection** | User input validated for web form context is interpolated into an LDAP query | No LDAP-specific escaping; only HTML/SQL escaping applied |
| **HTTP → Shell command injection** | Web input passed to a system command via an internal API that constructs shell strings | Internal API trusts input from the web service; no command escaping at the execution boundary |
| **REST → GraphQL injection** | User input from a REST endpoint is forwarded to an internal GraphQL endpoint without proper escaping | REST handler doesn't escape GraphQL special characters (`{`, `}`, `"`) |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|---|---|---|---|
| **BFF/Proxy Path Escape** | App → BFF proxy → internal microservices | §1-1, §3-3, §4-1 | Internal API access, mass data exfiltration |
| **API Gateway Bypass** | Client → API gateway → backend services | §1-2, §2-1, §3-3, §4-1 | AuthZ bypass, admin endpoint access |
| **GraphQL Relay Pivot** | Client → GraphQL → REST backends | §1-3, §4-3 | Cross-service data access, IDOR |
| **Cloud Confused Deputy** | Attacker → managed service → IAM roles | §5-1, §5-2 | Cross-tenant access, privilege escalation |
| **Cache Exploitation** | Client → CDN/cache → origin | §6-1, §6-2, §3-1 | Account takeover, stored XSS, data theft |
| **Service Mesh Pivot** | Compromised pod → sidecar → other services | §4-2 | Lateral movement, identity theft |
| **Webhook/Callback SSRF** | App → HTTP client → attacker URL → internal | §2-3 | Cloud metadata theft, internal scanning |
| **Stored Secondary Context** | Write (Context A) → Read (Context B) | §7-1, §7-2 | RCE, SSRF, data manipulation |

---

## CVE / Bounty Mapping (2022–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §1-1 + §4-1 (BFF traversal + trust collapse) | Starbucks BFF proxy (2020) | ~100M customer records exposed. $4,000 bounty |
| §3-2 (Apache filename confusion) | CVE-2024-38472 (Apache httpd 2.4.59) | Windows UNC SSRF via `r->filename` confusion |
| §3-2 (Apache handler confusion) | CVE-2024-39573 (Apache httpd) | `mod_rewrite` proxy handler substitution → SSRF |
| §3-2 (Apache handler confusion) | CVE-2024-38476 (Apache httpd) | Malicious backend output → code execution |
| §3-2 (Apache handler confusion) | CVE-2024-38477 (Apache httpd) | DoS via `mod_proxy` crash |
| §3-3 (Tomcat `/..;/` normalization) | CVE-2018-11759, CVE-2025-55752 | Path traversal → ACL bypass, potential RCE with PUT enabled |
| §1-2 + §3-3 (Nginx proxy_pass traversal) | ChatGPT SSRF/ATO (2024) | Full account takeover via `/public/../secret-endpoint` pattern |
| §5-1 (Cloud confused deputy) | AWS-2022-009 (AppSync) | Cross-tenant IAM role assumption via case-sensitivity bypass |
| §5-1 (Cloud confused deputy) | Amazon DataZone (2024) | Cross-account role association by unauthorized project members |
| §3-1 (Configuration-level bypass) | CVE-2021-45046 (Log4Shell bypass) | Incomplete patch bypass via non-default MDC/Thread Context Map configurations → RCE |
| §6-1 (Cache path confusion) | ChatGPT Web Cache Deception (2024) | Account takeover via cached dynamic responses |
| §1-2 (API gateway traversal) | Azure API Management (2024) | SSRF + path traversal in CORS/hosting proxies |
| §3-3 (Spring path normalization) | CVE-2024-38819 (Spring Framework) | Directory traversal via functional web framework static resource handling |
| §1-3 + §4-1 (GraphQL ID traversal) | Omnissa Workspace ONE UEM | Secondary context path traversal in enterprise MDM |
| §4-2 (Sidecar certificate theft) | Istio sidecar siphon (2024) | mTLS identity theft via shared namespace |
| §2-2 (SNI routing bypass) | Various cloud LB configs | SSRF to arbitrary backends via SNI regex bypass |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Burp Suite Professional** (Scanner) | All §1–§7 subtypes | Active/passive scanning with path traversal, header injection, and cache probing payloads |
| **DotDotPwn** (Fuzzer) | §1 path traversal variants | Systematic traversal payload generation across encoding schemes |
| **Nuclei** (Scanner) | Known CVEs (§3-2, §3-3) | Template-based scanning for known secondary context CVEs (e.g., CVE-2024-38473 template) |
| **ffuf / feroxbuster** (Fuzzer) | §1, §4-1 endpoint discovery | Directory/path brute-forcing with traversal-aware wordlists |
| **graphql-cop** (GraphQL Scanner) | §1-3, §4-3 | GraphQL-specific security auditing including ID injection and introspection abuse |
| **SSRFmap** (Exploitation) | §2-3 webhook SSRF | Automated SSRF exploitation with protocol handler and cloud metadata modules |
| **Param Miner** (Burp Extension) | §6-1, §6-2 cache attacks | Discovers unkeyed parameters and headers for cache poisoning/deception |
| **nginx-alias-traversal** (Burp Extension) | §1-2, §3-3 Nginx misconfigs | Detects off-by-slash and alias traversal in Nginx configurations |
| **Semgrep / CodeQL** (SAST) | §7 stored secondary context | Static analysis rules for unsanitized cross-context data flow |
| **Prowler / ScoutSuite** (Cloud Audit) | §5 confused deputy | IAM policy analysis for missing `ExternalId`, overly permissive trust policies |

---

## Summary: Core Principles

### The Root Cause: Semantic Fragmentation Across Trust Boundaries

Secondary context attacks exist because modern applications are architecturally fragmented — decomposed into layers (proxies, gateways, BFFs, microservices, cloud services, caches) where each layer implements its own parser, normalizer, router, and authorization logic. **The vulnerability is not in any single component but in the semantic gap between components.** A path, URL, header, or identifier that is "safe" under the rules of Context A can become "dangerous" under the rules of Context B.

### Why Incremental Patches Fail

Each fix addresses a specific encoding bypass, a specific normalization inconsistency, or a specific missing validation check. But the mutation space is combinatorial: `N` intermediary types × `M` backend types × `K` encoding schemes × `J` path normalization behaviors. New framework versions, new cloud services, and new architectural patterns continuously introduce new secondary contexts. The Apache httpd case is illustrative: a single deep audit revealed 9 vulnerabilities and 20 exploitation techniques in code that had been running for decades, because the architectural technical debt (modules sharing `r->filename` with different semantics) was never addressed structurally.

### What a Structural Solution Looks Like

1. **Parse once, propagate parsed**: User input should be parsed into a structured, validated representation at the outermost boundary and forwarded in parsed form (not as a raw string) to all downstream contexts. GraphQL `ID` fields should enforce `UUID` types, not accept arbitrary strings. BFF proxies should construct internal URLs from validated components, never via string concatenation.

2. **Zero-trust inter-service communication**: Every microservice must independently verify authorization for every request, regardless of whether the request arrives from a trusted gateway. The gateway provides defense-in-depth, not a security perimeter.

3. **Normalize before deciding**: Any component that makes a routing, caching, or authorization decision based on a URL path must normalize (decode, resolve dot-segments, canonicalize) the path **before** making the decision, using the **same normalization** as the downstream processor.

4. **Condition-scoped cloud delegation**: IAM trust policies must always include `aws:SourceArn` and `aws:SourceAccount` (or equivalent) conditions. The `ExternalId` parameter must be validated on the backend, not just displayed in the UI.

5. **Architectural boundary auditing**: Security reviews should explicitly map every context boundary (proxy→backend, gateway→service, service→service, service→cloud API) and verify that input semantics are preserved across each boundary. The secondary context attack surface is proportional to the number of context boundaries in the architecture.

---

## References

- Sam Curry, "Attacking Secondary Contexts in Web Applications," Kernelcon 2020 — [InfoconDB](https://infocondb.org/con/kernelcon/kernelcon-2020/attacking-secondary-contexts-in-web-applications)
- Sam Curry, "Hacking Starbucks and Accessing Nearly 100 Million Customer Records" — [samcurry.net](https://samcurry.net/hacking-starbucks)
- Orange Tsai, "Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server!" Black Hat USA 2024 — [blog.orange.tw](https://blog.orange.tw/posts/2024-08-confusion-attacks-en/)
- SilentRobots, "Exploiting GraphQL Secondary Context Attacks" — [silentrobots.com](https://www.silentrobots.com/exploiting-graphql-secondary-context-attacks/)
- SL Cyber, "Secondary Context Path Traversal in Omnissa Workspace ONE" — [slcyber.io](https://slcyber.io/research-center/secondary-context-path-traversal-in-omnissa-workspace-one-uem/)
- Datadog Security Labs, "A Confused Deputy Vulnerability in AWS AppSync" — [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/appsync-vulnerability-disclosure/)
- Sonarsource, "Security Implications of URL Parsing Differentials" — [sonarsource.com](https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/)
- Claroty Team82, "Exploiting URL Parsing Confusion" — [claroty.com](https://claroty.com/team82/research/exploiting-url-parsing-confusion)
- PortSwigger Research, "Gotta Cache 'em All: Bending the Rules of Web Cache Exploitation" — [portswigger.net](https://portswigger.net/research/gotta-cache-em-all)
- Nokline, "ChatGPT Account Takeover — Wildcard Web Cache Deception" — [nokline.github.io](https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html)
- Joshua Rogers, "proxy_pass: nginx's Dangerous URL Normalization of Paths" — [joshua.hu](https://joshua.hu/proxy-pass-nginx-decoding-normalizing-url-path-dangerous)
- Acunetix, "A Fresh Look on Reverse Proxy Related Attacks" — [acunetix.com](https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/)
- Qualys, "Fortifying Your Cloud Against Cross-Service Confused Deputy Attacks" — [blog.qualys.com](https://blog.qualys.com/vulnerabilities-threat-research/2025/07/24/fortifying-your-cloud-against-cross-service-confused-deputy-attacks)
- Praetorian, "AWS IAM Assume Role Vulnerabilities Found in Many Top Vendors" — [praetorian.com](https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities/)
- InstaTunnel, "The Sidecar Siphon: Exploiting Identity Leaks in Service Mesh Architectures" — [instatunnel.my](https://instatunnel.my/blog/the-sidecar-siphon-exploiting-identity-leaks-in-service-mesh-architectures)
- Zayl Security, "Confused Deputy Problem — How to Hack Cloud Integrations" — [zayl.dk](https://zayl.dk/posts/01-confused-deputy/)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
