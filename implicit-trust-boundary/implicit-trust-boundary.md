# Implicit Trust Boundaries in Web Applications — Mutation/Variation Taxonomy

---

## Classification Structure

An **Implicit Trust Boundary** violation occurs when a system component assumes—without explicit verification—that data, identity, or context received from another component is trustworthy. Unlike explicit access control failures (missing authentication, broken authorization), these vulnerabilities arise from **architectural assumptions** embedded in the system's design: that internal traffic is safe, that headers injected by proxies are authentic, that the browser's same-origin model is sufficient, or that serialized data from a "trusted" peer hasn't been tampered with.

The taxonomy is organized along three orthogonal axes:

- **Axis 1 — Trust Boundary Location** (Primary axis): The architectural seam where implicit trust exists. This is *where* in the system stack the assumption is made. Ten top-level categories cover the full spectrum from network infrastructure to supply chain.
- **Axis 2 — Trust Assumption Type** (Cross-cutting axis): *What* is being implicitly trusted — identity/source, data integrity, prior authorization, isolation guarantees, or default configuration safety.
- **Axis 3 — Exploitation Impact** (Mapping axis): *What* the attacker achieves by violating the boundary — access control bypass, credential theft, RCE, cache poisoning, account takeover, or data exfiltration.

### Trust Assumption Types (Axis 2 Summary)

| Assumption Type | Definition | Typical Violation Pattern |
|----------------|-----------|--------------------------|
| **Source Identity** | The system trusts the claimed origin/sender of a request | Header spoofing, origin reflection, forged tokens |
| **Data Integrity** | The system trusts that input data hasn't been tampered with | Deserialization of untrusted data, template injection, parameter pollution |
| **Prior Authorization** | The system trusts that upstream components already performed auth checks | Microservice lateral movement, proxy bypass, direct origin access |
| **Isolation Guarantee** | The system trusts that boundaries provide adequate separation | Subdomain cookie tossing, iframe sandbox escape, DNS rebinding |
| **Configuration Safety** | The system trusts that defaults and standard configurations are secure | GraphQL introspection enabled, permissive CORS, wildcard postMessage |

---

## §1. Network & Infrastructure Trust Boundaries

Network-layer implicit trust is the oldest and most fundamental category. Systems assume that requests originating from within the network perimeter, from localhost, or from link-local addresses are inherently trustworthy. Cloud environments have amplified this by placing metadata services on predictable internal addresses.

### §1-1. Cloud Metadata Service Trust

Cloud providers expose instance metadata on link-local addresses (e.g., `169.254.169.254`). Applications running within cloud instances implicitly trust their network environment to prevent external access to these endpoints.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **IMDSv1 Credential Theft** | SSRF to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` retrieves temporary IAM credentials without authentication | AWS IMDSv1 enabled (no token requirement); application has any SSRF vector |
| **Azure IMDS Token Extraction** | SSRF to `http://169.254.169.254/metadata/identity/oauth2/token` with `Metadata: true` header obtains managed identity tokens | Azure IMDS; header injection possible or header automatically added by SSRF context |
| **GCP Metadata Credential Access** | SSRF to `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` with `Metadata-Flavor: Google` header | GCP environment; custom header injection available |
| **Alternative IP Representation Bypass** | Metadata endpoint accessed via decimal (`2852039166`), hex (`0xA9FEA9FE`), octal, or IPv6-mapped representations to evade blocklists | SSRF filter uses string matching rather than IP normalization |

A notable example is CVE-2025-53767 (Azure OpenAI SSRF, CVSS 10.0), which allowed metadata token retrieval through insufficient URL validation.

### §1-2. Internal Network / Localhost Trust

Applications and services behind load balancers or firewalls assume that internal-origin traffic is authorized. This creates a trust boundary at the network perimeter that SSRF and DNS rebinding attacks can cross.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SSRF to Internal APIs** | Server-side request forged to internal service endpoints (e.g., `http://internal-admin:8080/api/users`) | Application accepts user-controlled URLs; internal services lack authentication |
| **Webhook Callback Exploitation** | User-supplied webhook URL points to internal addresses; application makes callbacks without URL validation | Webhook feature accepts arbitrary callback URLs |
| **Localhost Admin Panel Access** | SSRF to `http://127.0.0.1/admin` bypasses IP-based ACLs that trust localhost | Admin interface bound to all interfaces but restricted by source IP |
| **Container Co-tenancy Trust** | Containers sharing an EC2 instance (ECS EC2) exist in the same trust domain; compromising one enables lateral movement | Shared compute without enforced network isolation between containers |

### §1-3. Proxy-to-Origin Direct Access

When security controls (WAF, CDN, anti-DDoS) sit in front of the origin server, the architecture assumes all traffic flows through the proxy layer. Direct access to the origin bypasses these controls entirely.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Origin IP Discovery** | Attacker discovers the origin server's IP (via DNS history, certificate transparency, error messages) and connects directly, bypassing CDN/WAF | Origin server doesn't restrict incoming connections to proxy IPs |
| **Proxy Header Forgery at Origin** | Direct connection to origin allows forging headers like `CF-Connecting-IP` or `X-Forwarded-For` that the origin trusts | Origin trusts proxy-injected headers without verifying the request came through the proxy |

---

## §2. HTTP Header Trust Boundaries

HTTP headers form a particularly rich trust boundary because they are simultaneously user-controlled and relied upon by applications for security decisions. Headers injected by reverse proxies (to convey client identity, protocol, or host information) are indistinguishable from client-supplied headers at the application layer unless explicitly stripped or validated.

### §2-1. Client Identity Headers

Headers like `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, and `CF-Connecting-IP` are intended to convey the original client's IP address through proxy chains. Applications trust these for access control, rate limiting, and logging.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **X-Forwarded-For Spoofing for ACL Bypass** | Attacker injects `X-Forwarded-For: 127.0.0.1` to appear as localhost; admin panels restricted to internal IPs become accessible | Application reads first/last XFF value without proxy chain validation |
| **Rate Limit Evasion via IP Rotation** | Attacker rotates `X-Forwarded-For` values per request, causing rate limiter to count each as a different client | Rate limiter trusts XFF without verifying proxy chain authenticity |
| **Multi-Value Header Confusion** | Large comma-delimited IP lists in XFF headers confuse parsers: some read the first value, others read the last | Inconsistent XFF parsing between proxy and application layers |
| **Proxy Bypass Direct IP Spoofing** | When connecting directly to the origin (bypassing proxy), attacker forges any proxy-injected header | Origin doesn't verify that the request actually traversed the proxy |

### §2-2. Host and Routing Headers

The `Host` header, `X-Forwarded-Host`, and `X-Forwarded-Proto` are trusted for URL generation, routing, and security decisions. Their manipulation can poison caches, hijack password resets, and enable SSRF.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Host Header Password Reset Poisoning** | Injected `Host: attacker.com` causes password reset emails to contain attacker-controlled URLs | Application uses Host header to generate email links without validation |
| **X-Forwarded-Host URL Generation** | Application trusts `X-Forwarded-Host` for constructing absolute URLs in responses, enabling redirect manipulation | Framework automatically reads XFH; no allowlist enforced |
| **Routing-Based SSRF** | Manipulated Host header causes reverse proxy to route request to an attacker-controlled or internal backend | Proxy routes based on unvalidated Host; no backend allowlist |
| **Duplicate Host Header Confusion** | Two `Host` headers with different values; proxy uses one, backend uses the other | Proxy and backend disagree on which duplicate takes precedence |
| **Wrapped Host Header** | Indented second Host header bypasses duplicate-header rejection but is parsed by the backend | Backend ignores leading whitespace; proxy treats indented headers as continuations |

### §2-3. Protocol and Encoding Headers

Headers like `Content-Type`, `Transfer-Encoding`, and `Content-Length` are trusted to describe the request body. Mismatches between components' interpretation of these headers enable request smuggling and body parsing confusion.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CL-TE / TE-CL Smuggling** | Proxy and backend disagree on whether `Content-Length` or `Transfer-Encoding` determines body framing; attacker smuggles a second request | Proxy and backend support different precedence rules for CL vs. TE |
| **0-CL Desync** | Front-end treats request as having no body; backend reads Content-Length bytes, creating a deadlock broken by early-response gadgets | Backend does not reject zero-length body with non-zero CL |
| **Content-Type Mismatch** | Application trusts client-supplied `Content-Type` to select body parser; attacker sends JSON body with `application/xml` Content-Type to trigger different parsing logic | Application routes to parser based on CT without validating actual content format |

---

## §3. Origin & Cross-Origin Trust Boundaries

The browser's same-origin policy (SOP) is the fundamental trust boundary in client-side web security. However, multiple mechanisms exist to intentionally relax SOP, and each relaxation point creates an implicit trust boundary that can be exploited through misconfiguration or insufficient validation.

### §3-1. CORS Misconfiguration

Cross-Origin Resource Sharing (CORS) headers allow servers to declare which origins may access their resources. Misconfigurations create implicit trust in untrusted origins.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Origin Reflection** | Server dynamically reflects the request's `Origin` header in `Access-Control-Allow-Origin` without validation, trusting any origin | Lazy CORS implementation that echoes origin; `Allow-Credentials: true` |
| **Null Origin Trust** | Server allows `Origin: null` with credentials; attacker triggers null origin via sandboxed iframes or `data:` URIs | Null origin whitelisted; `Access-Control-Allow-Credentials: true` |
| **Regex Bypass in Origin Validation** | Origin check uses `indexOf()` or weak regex: `trusted.com.attacker.com` or `trustedXcom` matches `/trusted.com/` | Substring or regex matching rather than exact origin comparison |
| **Subdomain Wildcard Trust** | CORS policy trusts `*.example.com`; attacker exploits XSS on any subdomain to make credentialed cross-origin requests | Any subdomain has an XSS vulnerability; wildcard subdomain CORS policy |
| **Pre-flight Cache Poisoning** | Attacker manipulates cached pre-flight response to allow malicious origins for the cache duration | Pre-flight responses cached with overly long max-age |

### §3-2. postMessage Origin Validation

The `window.postMessage()` API enables cross-origin communication. The implicit trust boundary is in the receiver's origin validation logic — or its absence.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Missing Origin Check** | Message event handler processes all messages regardless of `event.origin`, trusting any sender | No origin validation in `message` event listener |
| **Substring Origin Match** | Validation uses `event.origin.indexOf("trusted.com")`, which matches `trusted.com.attacker.com` | `indexOf()` or `includes()` used instead of strict equality |
| **Regex Dot Escape** | Origin regex `/safe.example.com/` matches `safeXexample.com` because `.` is a regex wildcard | Unescaped dots in origin validation regex |
| **Wildcard Target Origin** | Sender uses `postMessage(data, "*")` instead of specifying the target origin; any window can receive the message | Wildcard `*` used as target origin with sensitive data |
| **Null Source Bypass** | Attacker creates iframe that sends postMessage and is immediately deleted; `event.source` becomes `null`, bypassing source-based validation | Validation relies on `event.source` existence rather than origin |
| **String.prototype.search() Confusion** | Validation uses `origin.search("trusted.com")` which implicitly converts the string argument to a regex | `search()` method used for origin validation |

### §3-3. Domain Relaxation and Subdomain Trust

Subdomains share an implicit trust relationship through cookie scoping, document.domain relaxation, and SameSite policies. Compromising any subdomain can cascade across the entire domain.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cookie Tossing** | Subdomain sets `Domain=.example.com` cookie that overrides the parent domain's cookie, enabling session fixation or configuration hijacking | Attacker controls any subdomain (via takeover or XSS); cookies lack `__Host-` prefix |
| **Subdomain Takeover** | Dangling CNAME record pointing to deprovisioned cloud service; attacker claims the service and controls the subdomain | Orphaned DNS CNAME; cloud service allows external registration |
| **document.domain Relaxation** | Two subdomains set `document.domain = "example.com"` to communicate; any compromised subdomain gains full DOM access | Legacy `document.domain` usage (being deprecated) |
| **SameSite Cookie Scope** | Cookies with `SameSite=Lax` or `None` are sent to all subdomains in same-site context; subdomain compromise exposes session tokens | Session cookies scoped broadly; any subdomain attackable |
| **Related-Domain CSP Bypass** | CSP trusts `*.example.com`; attacker uses XSS on a sibling subdomain as a script source | CSP uses subdomain wildcards; any subdomain has injectable content |

---

## §4. Authentication & Token Trust Boundaries

Authentication systems contain multiple implicit trust boundaries around token generation, validation, and the assumptions about which claims to trust and which to verify. These boundaries are especially subtle in federated authentication (OAuth, SAML, OIDC) where multiple parties participate.

### §4-1. JWT Claim Trust

JSON Web Tokens embed claims and algorithm metadata in their header and payload. The implicit trust boundary lies in which parts of the token the verifier trusts vs. independently validates.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Algorithm Confusion (RS256→HS256)** | Attacker changes `alg` from RS256 to HS256 and signs with the RSA public key (which is publicly known) as the HMAC secret | Server trusts client-supplied `alg` header; uses same key object for both algorithms |
| **`alg: none` Bypass** | Token header set to `alg: "none"` with empty signature; server accepts without verification | Server doesn't enforce algorithm; accepts none as valid |
| **JKU/X5U Key Injection** | Attacker modifies `jku` (JSON Web Key Set URL) or `x5u` (X.509 URL) to point to attacker-controlled key server | Server fetches key from URL specified in token without domain allowlist |
| **KID Path Traversal** | `kid` (Key ID) parameter used in file path or database query; attacker injects traversal or SQLi payload | `kid` concatenated into file path or query without sanitization |
| **Audience Confusion** | Token issued for Service A (audience) accepted by Service B because audience claim is not validated | Multi-service environment; services share signing keys but don't validate `aud` |
| **Issuer Trust Without Verification** | Application trusts any token with a valid signature from a known issuer without checking if that issuer *should* issue tokens for this resource | Broad issuer trust; no per-resource issuer binding |

### §4-2. OAuth/OIDC Trust Boundaries

OAuth and OpenID Connect delegate authentication to identity providers (IdPs). Trust boundaries exist at every handoff point: redirect URIs, token exchanges, and scope validation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Implicit Grant Token Substitution** | In implicit flow, client receives access token directly; attacker replaces token in URL fragment with one obtained from a different client | Client doesn't verify that the token was issued for its own `client_id` |
| **Open Redirect → Token Theft** | OAuth redirect_uri validation allows subdirectory or subdomain variations; attacker chains with open redirect to leak authorization code | Lax redirect_uri matching (prefix, subdomain wildcard) |
| **Mixed Token Endpoint Trust** | Resource server accepts access tokens without verifying which authorization server issued them or for which audience | Shared signing keys across authorization servers; no audience validation |
| **PKCE Downgrade** | Attacker strips `code_challenge` from authorization request; authorization server doesn't enforce PKCE, falling back to code-only flow | PKCE not mandatory; server accepts requests without code_challenge |
| **State Parameter Absence/Predictability** | CSRF via OAuth: attacker initiates OAuth flow and tricks victim into completing it with attacker's authorization code | Missing or predictable `state` parameter; no CSRF protection on callback |

### §4-3. SAML Trust Boundaries

SAML's XML-based assertions create unique trust boundaries around signature validation, assertion parsing, and attribute extraction.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **XML Signature Wrapping (XSW)** | Attacker moves signed assertion to a non-validated location and inserts forged assertion where the application reads it | Application validates signature on one XML node but reads identity from another (CVE-2024-45409, CVE-2024-6800) |
| **Comment Injection in NameID** | Comment inserted in NameID value (e.g., `admin@example.com<!---->.attacker.com`) parsed differently by IdP and SP | IdP and SP use different XML parsers with different comment handling |
| **Assertion Replay** | Valid SAML assertion reused after its intended session; no timestamp or one-time-use validation | Missing `NotOnOrAfter` enforcement; no assertion ID tracking |
| **Recipient Mismatch** | Assertion intended for Service Provider A accepted by Service Provider B | SP doesn't validate `Recipient` attribute in `SubjectConfirmationData` |

---

## §5. Input Processing Trust Boundaries

When applications process structured input (serialized objects, template expressions, query languages), they cross a trust boundary between the untrusted external world and the trusted internal execution environment. The implicit assumption is that the input conforms to expected structure and doesn't contain executable payloads.

### §5-1. Deserialization Trust

Deserialization converts untrusted byte streams into live objects within the application's runtime. The trust boundary is between "data" (safe) and "code" (dangerous) — deserialization collapses this distinction.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Java Gadget Chain RCE** | Attacker crafts serialized Java object containing a chain of class invocations (gadget chain) that culminates in `Runtime.exec()` | Application deserializes untrusted Java objects; gadget classes on classpath (Commons Collections, Spring, etc.) |
| **PHP Magic Method Abuse** | Serialized PHP object triggers `__wakeup()`, `__destruct()`, or `__toString()` with attacker-controlled properties | Application calls `unserialize()` on user input; exploitable magic methods in loaded classes |
| **Python Pickle RCE** | Pickle's `__reduce__` method allows arbitrary function execution during deserialization | Application uses `pickle.loads()` on untrusted input |
| **React Server Components Deserialization** | Flight protocol payloads deserialized on server; malicious serialized data injected through client-controlled RSC payloads | React Server Components with Server Functions; prototype validation missing (CVE-2025-55182) |
| **.NET ViewState Tampering** | ViewState deserialization with known or weak machine key allows arbitrary object instantiation | Machine key leaked or default; ViewState MAC validation disabled or bypassable (CVE-2025-53690) |

### §5-2. Template Engine Trust

Server-side template engines are designed to render trusted templates with untrusted data. SSTI occurs when untrusted input is concatenated directly into the template string itself, crossing from the data context into the code context.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct Template Concatenation** | User input inserted directly into template string: `render("Hello " + userInput)` instead of `render("Hello {{name}}", {name: userInput})` | Developer concatenates user input into template rather than passing as context variable |
| **Sandbox Escape** | Template engine sandbox restricts available objects, but attacker traverses object graph to reach `os.system()` or equivalent | Sandbox doesn't fully restrict access to runtime internals; MRO traversal possible (Jinja2, Twig, Freemarker) |
| **WAF Filter Bypass via String Construction** | Attacker builds restricted strings from arithmetic operations, list indices, or encoding to bypass pattern-based WAF rules | WAF uses regex/string matching; template engine allows dynamic string construction |

### §5-3. Query Language Trust

GraphQL, SQL, LDAP, and other query languages have trust boundaries between query structure (trusted) and parameter values (untrusted).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **GraphQL Introspection Disclosure** | Introspection queries expose full schema including internal types, deprecated fields, and hidden mutations | Introspection enabled in production (default in many frameworks); CVE-2024-50312 |
| **GraphQL Depth/Complexity Bypass** | Attacker crafts deeply nested or aliased queries that exceed intended limits through regex bypass (`__schema` with special characters) or fragmented queries | Depth limits implemented via regex pattern matching rather than AST analysis |
| **Batch Query Abuse** | Multiple mutations sent in single request bypass per-request rate limits or authorization checks | Batching enabled; authorization checked per-request not per-operation |

---

## §6. Caching & Intermediary Trust Boundaries

Caches create implicit trust boundaries by assuming that the "cache key" (the subset of request attributes used to identify equivalent requests) fully captures the security-relevant differences between requests. Any request attribute that affects the response but is *not* part of the cache key is an implicit trust boundary violation waiting to happen.

### §6-1. Web Cache Poisoning

Cache poisoning exploits the gap between what the cache considers equivalent requests (the cache key) and what actually influences the response (unkeyed inputs).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unkeyed Header Injection** | Attacker injects malicious content via headers not in the cache key (e.g., `X-Forwarded-Host`); response is cached and served to other users | Application reflects unkeyed header in response; cache stores the poisoned response |
| **Unkeyed Cookie Poisoning** | Cookie value affects response content but isn't part of cache key; attacker's cookie value cached for all users | Cookie influences rendered content; cache doesn't include cookies in key |
| **Fat GET Poisoning** | Cache keys only on URL and headers; attacker sends GET with body that influences response | Application processes GET request body; cache ignores body in key |
| **Host Header Cache Poisoning** | Injected Host header changes links/assets in response; cached response serves attacker-controlled URLs to all users | Host header reflected in response; not normalized in cache key (CVE-2024-40686) |

### §6-2. Web Cache Deception

The inverse of poisoning: the attacker tricks the cache into storing a victim's personalized/authenticated response and then retrieves it.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Path Confusion** | Attacker crafts URL like `/account/settings/nonexistent.css`; origin serves dynamic account page, cache stores it as static CSS file | Cache determines cacheability by file extension; origin ignores trailing path segments |
| **Delimiter Discrepancy** | URL like `/account%2Fsettings.css` interpreted differently by cache (path) and origin (decoded) | Cache and origin disagree on delimiter/encoding handling |

---

## §7. Client-Side Security Model Trust Boundaries

Browsers implement multiple security mechanisms (SOP, CSP, sandbox) that applications rely on. Implicit trust boundaries exist in the assumption that these mechanisms are correctly configured and cannot be circumvented from within.

### §7-1. Content Security Policy (CSP) Trust

CSP restricts which resources a page can load. The trust boundary is between the CSP policy's intent and the actual execution environment — trusted scripts can become gadgets that undermine the policy.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Script Gadget Exploitation** | Trusted script (e.g., from CDN whitelisted in CSP) contains a gadget that dynamically creates `<script>` tags from attacker-controlled input | CSP whitelists a CDN or domain hosting scripts with dynamic loading behavior |
| **base-uri Injection** | Injected `<base href="https://attacker.com/">` causes relative script imports to load from attacker's server; `strict-dynamic` propagates trust | CSP lacks `base-uri` directive; application uses relative script paths |
| **Nonce Exfiltration** | Attacker extracts the CSP nonce from DOM (`document.querySelector("[nonce]")`) and reuses it to inject inline scripts | Nonce accessible via DOM API; XSS vector exists in same page context |
| **DOM Clobbering for CSP Bypass** | Attacker injects HTML elements that shadow JavaScript globals, redirecting trusted script behavior | CSP allows `unsafe-inline` for styles or specific script sources that rely on DOM globals |
| **JSONP Endpoint Abuse** | JSONP endpoint on CSP-whitelisted domain used to execute arbitrary JavaScript via callback parameter | CSP whitelists domain hosting JSONP endpoint; callback parameter not sanitized |

### §7-2. Iframe Sandbox Trust

The `sandbox` attribute restricts iframe capabilities. The trust boundary is the assumption that these restrictions cannot be escaped.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **allow-scripts + allow-same-origin Escape** | Same-origin sandboxed iframe with both permissions can remove its own sandbox attribute via DOM manipulation | Both `allow-scripts` and `allow-same-origin` set on same-origin iframe |
| **javascript: Link Navigation** | Clicking `javascript:` URL in sandboxed iframe executes in parent's context, accessing parent's cookies | Sandboxed iframe permits navigation; parent page cookies accessible |
| **Top Navigation Abuse** | Sandboxed iframe with `allow-top-navigation` changes parent page's location to attacker-controlled URL | `allow-top-navigation` set without `allow-top-navigation-by-user-activation` |
| **Third-Party Iframe Supply Chain** | Trusted third-party iframe source compromised; all embedding pages affected | Application embeds third-party iframes without subresource integrity or ongoing monitoring |

### §7-3. Client-Side Validation Trust

Applications that perform security checks only on the client side implicitly trust the browser environment, which the user fully controls.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Client-Only Input Validation** | Validation exists only in JavaScript; attacker sends requests directly to API bypassing browser | No server-side validation; client-side checks treated as security controls |
| **Hidden Field / Disabled Element Trust** | Application trusts that hidden form fields or disabled inputs cannot be modified | Server processes all submitted values without verifying they match expected state |
| **Client-Side Access Control** | UI elements hidden via CSS/JS for unauthorized users, but API endpoints lack authorization checks | Authorization enforced by hiding buttons/links rather than server-side checks |

---

## §8. DNS Resolution Trust Boundaries

DNS resolution is trusted to map hostnames to the correct IP addresses. Attacks that manipulate DNS responses or exploit timing gaps in resolution can cross trust boundaries by making a trusted hostname resolve to an attacker-controlled address.

### §8-1. DNS Rebinding

DNS rebinding exploits the gap between hostname-based access control (SOP, CORS) and the actual network endpoint the hostname resolves to.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Classic DNS Rebinding** | Attacker's domain resolves to attacker IP initially, then rebinds to victim's internal IP (e.g., `127.0.0.1`); browser treats subsequent requests as same-origin | Target service on internal network has no authentication; DNS TTL short or ignored |
| **Time-of-Check-Time-of-Use (TOCTOU)** | URL validation resolves hostname to safe IP, but actual request (microseconds later) resolves to internal IP | Application validates URL at one point in time; DNS record changes between validation and use |
| **MCP Server Exploitation** | Model Context Protocol servers on localhost targeted via DNS rebinding; AI agents access internal tools through rebinding attacks | MCP server bound to localhost without authentication; no Origin/Host validation (CVE-2024-28224 pattern) |
| **IoT/Smart Device Access** | DNS rebinding targets devices on local network (routers, cameras, printers) that trust any same-network request | Devices use IP-based or no authentication; accessible on local network |

### §8-2. SSRF DNS Resolution Trust

Server-side URL validation trusts DNS resolution to be stable and honest. Attackers exploit DNS to bypass URL allowlists and blocklists.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DNS Rebinding for SSRF Bypass** | Server validates that hostname resolves to public IP; attacker's DNS returns public IP for validation, then internal IP for actual request | Double-resolution TOCTOU; no pinning of DNS results |
| **DNS Wildcard Confusion** | Attacker uses `*.attacker.com` resolving to internal IPs; passes domain-based allowlist checks | Allowlist uses domain pattern matching; doesn't validate resolved IP |
| **Subdomain Delegation for Internal Resolution** | Attacker delegates subdomain DNS to return internal IP addresses while parent domain is on allowlist | Broad domain allowlisting; no IP-level validation of resolved addresses |

---

## §9. Service-to-Service (Microservice) Trust Boundaries

In microservice architectures, the implicit trust boundary is between services. The legacy assumption — "if a request reaches this service, it must have been authorized by the API gateway" — creates a flat trust plane where compromising one service enables lateral movement to all.

### §9-1. Internal Service Authentication Trust

The most common implicit trust violation: internal services assume that network reachability implies authorization.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Gateway-Only Authentication** | API gateway validates user tokens, but internal services accept any request without re-verification | Services trust all internal traffic; no service-to-service authentication |
| **Service Identity Propagation Failure** | Service A validates user token, calls Service B with its own service identity; Service B grants Service A's full permissions regardless of original user's authorization | No user context propagation; service-level credentials used for inter-service calls |
| **Sidecar/Service Mesh Bypass** | Attacker connects directly to service port, bypassing the mTLS sidecar proxy that enforces authentication | Service accepts connections on non-mesh ports; no iptables/network policy enforcement |

### §9-2. Authorization Context Propagation

When requests traverse multiple services, authorization context can be lost, inflated, or confused.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Privilege Escalation via Service Chaining** | User-context lost across service hops; downstream service uses calling service's elevated privileges | No end-to-end user identity propagation; services use service accounts for downstream calls |
| **Confused Deputy** | Service A makes request to Service B on behalf of user, but Service B cannot distinguish between Service A's own requests and user-delegated requests | No delegation/impersonation framework; Service B trusts Service A's identity alone |
| **Scope Inflation** | OAuth scope for user narrower than service-to-service scope; internal call uses broader service credentials | Services issued broad scopes for operational convenience; user scope not propagated |

---

## §10. Supply Chain & Dependency Trust Boundaries

Modern web applications implicitly trust their dependency tree — package registries, CDN-hosted scripts, build toolchains, and CI/CD pipelines. Each dependency relationship creates a trust boundary where the application assumes the external component is safe.

### §10-1. Package Registry Trust

Applications trust that packages from registries (npm, PyPI, RubyGems) are what they claim to be and haven't been compromised.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Dependency Confusion** | Internal package name (e.g., `@corp/utils`) doesn't exist on public registry; attacker publishes a higher-version package with same name to public registry | Private registry fallback to public; no scope/namespace enforcement; package manager checks public registry |
| **Typosquatting** | Package with similar name to popular package (`loddash` vs `lodash`) contains malicious code | Developer typo; no verification of package authenticity before install |
| **Maintainer Account Compromise** | Attacker compromises npm/PyPI maintainer account and publishes malicious update to legitimate package | Maintainer lacks MFA; no package signing; September 2025 npm attack (chalk, debug, ansi-styles, 2.6B weekly downloads) |
| **Phantom Package Claiming** | Packages referenced in documentation/scripts but never published; attacker registers them | Package name referenced but never claimed on registry |

### §10-2. Third-Party Script Trust

Applications embed scripts from CDNs, analytics providers, and widget services, implicitly trusting them not to be compromised.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CDN Compromise** | Compromised CDN serves malicious version of popular library to all consumers | Scripts loaded without Subresource Integrity (SRI); no fallback verification |
| **Third-Party Script Injection** | Analytics/widget script updated by vendor to include malicious functionality (e.g., credit card skimming) | No SRI; no Content Security Policy restricting script behavior; Magecart-style attacks |
| **Preinstall Script Execution** | npm packages execute arbitrary code during `npm install` via `preinstall` scripts | Default npm configuration allows lifecycle scripts; no `--ignore-scripts` flag |
| **Self-Replicating Worm** | Malicious package steals developer credentials and uses them to publish infected versions of the developer's other packages | Developer credentials stored in npmrc; no MFA; November 2025 Shai-Hulud worm (796 packages) |

### §10-3. Build Pipeline Trust

CI/CD pipelines implicitly trust their inputs: source code, environment variables, build scripts, and artifact registries.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CI Secret Exfiltration** | Malicious PR or dependency accesses CI environment variables containing secrets | CI runs untrusted code with access to secrets; no secret isolation per PR |
| **Build Artifact Substitution** | Attacker substitutes build artifact in registry between build and deploy steps | No artifact signing; no content-hash verification between build and deployment |
| **GitHub Actions Injection** | Workflow uses `${{ github.event.issue.title }}` in a `run:` step; attacker injects shell commands via issue title | Untrusted event properties interpolated into shell commands without sanitization |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Cloud Credential Theft** | Application on cloud VM with SSRF vector | §1-1 + §1-2 (metadata SSRF) |
| **Account Takeover via Subdomain** | Multi-subdomain application with orphaned DNS | §3-3 (subdomain takeover) + §3-1 (CORS) + §7-1 (CSP) |
| **Cache Poisoning → Mass XSS** | CDN-fronted application with reflected unkeyed headers | §2-2 (Host header) + §6-1 (cache poisoning) |
| **Microservice Lateral Movement** | Kubernetes cluster with gateway-only auth | §9-1 (service auth trust) + §9-2 (context propagation) |
| **OAuth Token Theft** | OAuth implicit flow with lax redirect_uri | §4-2 (OAuth trust) + §3-3 (subdomain redirect) |
| **Supply Chain RCE** | npm-based application with CI/CD | §10-1 (registry trust) + §10-3 (build pipeline) |
| **DNS Rebinding → Internal Access** | Developer workstation with local services | §8-1 (DNS rebinding) + §1-2 (localhost trust) |
| **SAML SSO Bypass** | Enterprise SSO with SAML assertions | §4-3 (SAML trust) + XML signature processing |
| **Deserialization → RCE** | Java/PHP application accepting serialized input | §5-1 (deserialization trust) + §1-2 (internal network) |
| **WAF Bypass → Direct Exploitation** | WAF/CDN in front of origin server | §1-3 (proxy bypass) + §2-1 (header forgery) |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-1 (IMDS SSRF) | CVE-2025-53767 (Azure OpenAI) | CVSS 10.0. Managed identity token theft via URL validation bypass |
| §5-1 (Deserialization) | CVE-2025-55182 (React/Next.js) | RCE via Server Functions deserialization; Flight protocol trust boundary |
| §5-1 (ViewState) | CVE-2025-53690 (Sitecore) | RCE via ViewState deserialization zero-day |
| §5-1 (Deserialization) | CVE-2025-30382 (SharePoint) | RCE via SharePoint deserialization |
| §4-3 (SAML XSW) | CVE-2024-45409 (Ruby SAML) | Authentication bypass; log in as any user. Impacted GitLab and other Ruby SPs |
| §4-3 (SAML Bypass) | CVE-2024-6800 (GitHub Enterprise) | SAML SSO bypass on GitHub Enterprise Server |
| §4-3 (SAML) | CVE-2024-6202 (HaloITSM) | Critical SAML user impersonation |
| §5-3 (GraphQL) | CVE-2024-50312 (OpenShift) | GraphQL introspection information disclosure |
| §2-2 (Host Header) | CVE-2024-40686 (IBM SmartCloud) | Cache poisoning and session hijacking via Host Header Injection |
| §3-2 (postMessage) | CVE-2024-49038 (Copilot Studio) | CVSS 9.3. Origin validation bypass via postMessage |
| §1-1 (SSRF) | 2025 Campaign (F5 Labs report) | Mass campaign targeting EC2 metadata via SSRF |
| §8-1 (DNS Rebinding) | CVE-2024-28224 (Ollama) | AI model server access via DNS rebinding |
| §10-1 (Supply Chain) | September 2025 npm attack | 18 packages, 2.6B weekly downloads compromised; credential theft |
| §10-1 (Supply Chain) | November 2025 Shai-Hulud worm | Self-replicating npm worm; 796 packages, 132M monthly downloads |
| §1-3 + §3-3 (Subdomain) | 2025 Lovable Account Takeover | Full ATO via subdomain cookie injection + Firebase SDK hijacking |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Param Miner** (Burp Extension) | §6-1 Cache Poisoning | Brute-forces unkeyed header/cookie/parameter names; observes response differences |
| **Nuclei** (ProjectDiscovery) | §1-1, §1-3, §2-1, §5-3 | Template-based scanning for known trust boundary violations across protocols |
| **jwt_tool** (ticarpi) | §4-1 JWT Trust | Tests alg confusion, kid injection, jku manipulation, none algorithm, and claim tampering |
| **GraphQLmap** | §5-3 GraphQL Trust | Introspection enumeration, depth limit testing, batch query exploitation |
| **Subjack / Can I Take Over XYZ** | §3-3 Subdomain Takeover | Detects dangling CNAME records pointing to claimable cloud services |
| **CORStest / CORS Scanner** | §3-1 CORS Misconfiguration | Tests origin reflection, null origin trust, regex bypass patterns |
| **Singularity of Origin** | §8-1 DNS Rebinding | DNS rebinding attack framework; tests internal service accessibility |
| **SSRFmap** | §1-1, §1-2 SSRF Trust | Automates SSRF exploitation including cloud metadata access with encoding bypasses |
| **Semgrep** (SSTI rules) | §5-2 Template Trust | Static analysis for template concatenation patterns (taint tracking) |
| **Socket.dev** | §10-1 Supply Chain | Monitors npm/PyPI dependencies for suspicious behavior, typosquatting, and supply chain indicators |
| **Istio / Linkerd** (Service Mesh) | §9-1 Service Trust | Enforces mTLS between services; provides service-level identity and authorization |
| **truffleHog / GitLeaks** | §10-3 Build Pipeline | Scans repositories and CI logs for leaked secrets and credentials |

---

## Summary: Core Principles

### Why Implicit Trust Boundaries Persist

The root cause of implicit trust boundary vulnerabilities is **architectural composition under incomplete threat models**. Modern web applications are assembled from layers (browsers, CDNs, proxies, gateways, microservices, databases, cloud infrastructure) where each layer was designed with its own security assumptions. When these layers are composed, the *interfaces between them* inherit trust assumptions that were never explicitly stated or validated. A reverse proxy assumes it's the only path to the origin. An internal service assumes the gateway validated the token. A cache assumes unkeyed headers don't affect security. A package manager assumes the registry is trustworthy. None of these assumptions are documented as security requirements — they are implicit in the architecture.

### Why Incremental Fixes Fail

Each individual trust boundary violation can be patched (enforce IMDSv2, validate CORS origins, add mTLS). But the underlying pattern — *that systems trust their neighbors by default* — is never addressed. New architectural components (MCP servers, AI code generators, server components with novel serialization protocols) immediately inherit the same implicit trust patterns. The September 2025 npm supply chain attack demonstrated that even after years of awareness, the fundamental trust-by-default model of package registries remained exploitable at catastrophic scale. Similarly, CVE-2025-55182 showed that React Server Components introduced a new deserialization trust boundary that mirrored decades-old Java deserialization patterns.

### The Structural Solution

The structural answer is **Zero Trust Architecture** applied not just at the network layer but at every interface: every message, every token, every origin, every dependency, every DNS resolution must be independently verified. In practice, this means: treat every component boundary as a trust boundary, enumerate the assumptions at each boundary, and convert implicit assumptions into explicit verification. The cost is significant — mTLS everywhere, SRI for all scripts, SSRF-safe URL validation with DNS pinning, strict CSP with no wildcards, per-service authorization, signed artifacts, and reproducible builds. But the alternative is an ever-expanding taxonomy of the same fundamental mistake: trusting without verifying.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- CWE-501: Trust Boundary Violation — https://cwe.mitre.org/data/definitions/501.html
- OWASP Top 10:2025 A06 Insecure Design — https://owasp.org/Top10/2025/A06_2025-Insecure_Design/
- PortSwigger Web Security Academy — https://portswigger.net/web-security
- PortSwigger Top 10 Web Hacking Techniques 2024 — https://portswigger.net/research/top-10-web-hacking-techniques-of-2024
- HackTricks — https://book.hacktricks.xyz/
- Can I Take Your Subdomain? (Same-Site Attacks Research) — https://canitakeyoursubdomain.name/
- Cookie Tossing Research (Thomas Houhou) — https://www.thomashouhou.com/post/cookie-tossing-attacks/
- Doyensec Common OAuth Vulnerabilities — https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html
- SSO Protocol Security Vulnerabilities 2025 — https://guptadeepak.com/security-vulnerabilities-in-saml-oauth-2-0-openid-connect-and-jwt/
- Reverse Proxy Security Paradox — https://blog.devsecopsguides.com/p/secure-by-design-the-reverse-proxy
- Abusing Reverse Proxies (ProjectDiscovery) — https://projectdiscovery.io/blog/abusing-reverse-proxies-internal-access
- Resecurity SSRF to AWS Metadata — https://www.resecurity.com/blog/article/ssrf-to-aws-metadata-exposure-how-attackers-steal-cloud-credentials
- Akamai CVE-2025-55182 React/Next.js RCE — https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce
- CISA npm Supply Chain Alert — https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
- Straiker MCP DNS Rebinding — https://www.straiker.ai/blog/agentic-danger-dns-rebinding-exposing-your-internal-mcp-servers
- Microsoft postMessage Research — https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised
- PortSwigger CSP DOM Clobbering Bypass — https://portswigger.net/research/bypassing-csp-via-dom-clobbering
- PortSwigger Nonce-Based CSP Bypass Research — https://portswigger.net/research/hunting-nonce-based-csp-bypasses-with-dynamic-analysis
- Lovable Account Takeover (Vidoc Security) — https://blog.vidocsecurity.com/blog/how-we-secured-lovable
