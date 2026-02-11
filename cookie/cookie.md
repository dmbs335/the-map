# Cookie Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the full attack surface of HTTP cookie vulnerabilities along three orthogonal axes. **Axis 1 (Mutation Target)** classifies techniques by the structural component of the cookie system being attacked — attributes, parsing, scope, value content, jar state, transport layer, client-side storage, or session lifecycle. This is the primary organizational axis. **Axis 2 (Discrepancy/Bypass Type)** captures the nature of the mismatch or circumvention that makes each technique work — parsing differentials, flag bypasses, scope confusion, state manipulation, cryptographic weakness, or specification inconsistency. **Axis 3 (Attack Scenario)** maps techniques to their real-world weaponization context — session hijacking, CSRF, XSS amplification, denial of service, MFA bypass, cache poisoning, WAF bypass, or privilege escalation.

The cookie system's attack surface is fundamentally rooted in a historical design tension: cookies were introduced as a stateless-to-stateful bridge for HTTP, yet they carry implicit trust assumptions about origin, integrity, and confidentiality that the protocol never formally guaranteed. The cookie specification has evolved through RFC 2109 → RFC 2965 → RFC 6265 → RFC 6265bis, but browser and server implementations retain varying degrees of backward compatibility with deprecated behaviors. This specification drift is the meta-vulnerability that enables the majority of techniques cataloged below.

### Axis 2 Summary: Cross-Cutting Discrepancy Types

| Discrepancy Type | Description | Primary Sections |
|---|---|---|
| **Browser-Server Parsing Differential** | Browser and server interpret the same Cookie header bytes differently | §2, §1-3 |
| **Attribute/Flag Bypass** | Security attributes (HttpOnly, Secure, SameSite, Prefix) are circumvented | §1, §2-2, §2-3 |
| **Scope Confusion** | Cookie delivered to unintended origins due to domain/site/origin model mismatch | §3 |
| **State Manipulation** | Cookie jar state (creation, eviction, ordering) is externally controlled | §5 |
| **Cryptographic/Token Weakness** | Cookie value protection (encryption, signing, entropy) is broken | §4, §7 |
| **Specification Inconsistency** | Divergent RFC interpretations across implementations | §2-1, §2-3 |

---

## §1. Cookie Attribute & Flag Manipulation

Cookies carry security-relevant attributes (`Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`, cookie prefixes) that browsers are supposed to enforce. Attacks in this category subvert these enforcement mechanisms.

### §1-1. SameSite Bypass Techniques

The `SameSite` attribute restricts cross-site cookie transmission to mitigate CSRF. Multiple bypass vectors exist due to specification edge cases and browser implementation choices.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Lax+POST Two-Minute Window** | Chrome allows `SameSite=Lax` cookies on cross-site POST requests for 2 minutes after cookie creation, to avoid breaking OAuth flows. An attacker triggers a fresh login/OAuth flow, then exploits the grace window. | Cookie was set < 120 seconds ago; Chrome-specific behavior |
| **Top-Level GET Navigation** | `SameSite=Lax` permits cookies on top-level navigations using safe methods (GET). Attackers trigger state-changing GET endpoints via `<a>` clicks, `window.open()`, or redirects. | Application performs state-changing operations on GET requests |
| **HTTP Method Override** | Frameworks (Symfony, Rails, Laravel) support `_method` parameters that override the HTTP verb server-side. A GET request with `?_method=POST` is treated as POST by the server while the browser considers it a GET, sending Lax cookies. | Framework method override enabled; no server-side SameSite enforcement |
| **Same-Site Cross-Origin** | `SameSite` compares *sites* (eTLD+1), not *origins*. A compromised or attacker-controlled sibling subdomain (`evil.example.com`) can issue same-site requests to `app.example.com` with full cookie access. | Attacker controls any subdomain of the same registrable domain |
| **Client-Side Redirect Chain** | A server-side redirect from a cross-site context creates a same-site top-level navigation at the redirect destination. Chaining open redirects converts cross-site requests into same-site navigations. | Open redirect exists on the target site |

### §1-2. HttpOnly Bypass Techniques

The `HttpOnly` flag prevents JavaScript from reading cookies via `document.cookie`. Bypasses expose cookie values through alternative channels.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cookie Sandwich** | An attacker crafts cookies with strategically placed quotes that, under RFC 2109 legacy parsing (triggered by `$Version=1`), cause the server to merge multiple cookies into a single value — absorbing adjacent HttpOnly cookies into a readable, non-HttpOnly cookie. | Server supports RFC 2109 parsing (Tomcat, Jetty); attacker can set cookies (subdomain or XSS) |
| **TRACE Method Reflection** | HTTP TRACE reflects the full request, including `Cookie` headers, in the response body. If TRACE is enabled and XSS exists, JavaScript reads the reflected HttpOnly cookies. | TRACE method enabled; XSS present |
| **Error Page / Debug Reflection** | Server error pages, debug endpoints, or phpinfo() reflect cookie headers in HTML body, making them accessible to JavaScript. | Verbose error handling or debug mode enabled in production |
| **Server-Side Parsing Quirk Leak** | Differential parsing between browser and server causes HttpOnly cookie values to be concatenated with non-HttpOnly cookies in server responses (see §2-2 quoted-value parsing). | Jetty, Undertow, or similar servers with quoted-value parsing quirks |
| **CORS Credential Exfiltration** | If `Access-Control-Allow-Credentials: true` with a permissive origin, response body may contain reflected cookie values that JavaScript can read cross-origin. | Misconfigured CORS policy with credential reflection |

### §1-3. Cookie Prefix Bypass

`__Host-` and `__Secure-` prefixes enforce that cookies are set from secure origins and (for `__Host-`) cannot specify Domain/Path. Bypasses exploit encoding differentials.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **UTF-8 Normalization Bypass** | Attacker sets a cookie with a Unicode whitespace prefix (e.g., `\u2000__Host-session`). The browser treats it as a non-prefixed cookie (no restrictions), but server-side frameworks (Django, ASP.NET) normalize the Unicode, stripping the whitespace and interpreting it as `__Host-session`. | Server-side Unicode normalization; framework strips leading whitespace from cookie names |
| **Legacy $Version Parsing** | When `$Version=1` appears at the start of the Cookie header, Java servers (Tomcat, Jetty) switch to RFC 2109 parsing where quoted strings and comma separators alter cookie boundaries. An attacker injects a crafted value that the server interprets as a `__Host-` prefixed cookie. | Java-based server with legacy RFC 2109 support enabled |
| **Subdomain Cookie Shadowing** | While `__Host-` cookies cannot specify a Domain, an attacker on a sibling subdomain can set a *non-prefixed* cookie with the same name for the parent domain. Browser cookie ordering ambiguity may cause the server to read the attacker's cookie first. | Attacker controls a sibling subdomain; server reads first matching cookie name |

### §1-4. Secure Flag Bypass

The `Secure` attribute restricts cookie transmission to HTTPS. Bypasses deliver cookies over insecure channels.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Network MitM Cookie Setting** | An active network attacker intercepts an HTTP request to any subdomain and responds with `Set-Cookie` for the target domain. Browsers historically accept Secure-flagged cookies set over HTTP (though RFC 6265bis addresses this). | Victim makes any HTTP request; attacker controls network |
| **Mixed Content Leak** | HTTPS page loads HTTP subresources. Cookies without `Secure` flag are sent with HTTP requests, but even Secure cookies may leak through implementation bugs or browser inconsistencies. | Mixed content on HTTPS pages |
| **HSTS Stripping** | On first visit (before HSTS is cached), an active attacker downgrades HTTPS to HTTP, capturing cookies. Mitigated by HSTS preload, but not all domains are preloaded. | First visit without HSTS preload; active network attacker |

---

## §2. Cookie Parsing & Encoding Differentials

Cookies traverse multiple parsers (browser, CDN/proxy, WAF, server framework, application). When these parsers interpret the same byte sequence differently, security boundaries collapse.

### §2-1. Legacy RFC Parsing Exploitation

RFC 2109/2965 defined cookie features (quoted values, `$Version`, `$Path`, `$Domain`, comma separators) that modern browsers don't generate but many servers still accept.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **$Version Phantom Cookie** | A cookie named `$Version` (settable by JavaScript since browsers don't recognize it as special) triggers RFC 2109 parsing mode in Tomcat/Jetty. This changes how all subsequent cookies in the header are parsed — enabling cookie sandwich attacks (§1-2) and WAF bypasses (§2-3). | Java-based backend (Tomcat ≤10.0.x, Jetty); attacker can set cookies via JavaScript |
| **Comma-Separated Cookie Injection** | RFC 2109 permits commas as cookie separators. In legacy mode, a single cookie value containing a comma can be split into multiple cookies. `Cookie: $Version=1; a="x, injected=payload"` may yield cookies `a=x` and `injected=payload`. | Legacy parsing mode active; server splits on comma |
| **Quoted-String Escape Sequences** | RFC 2109 allows characters within quoted cookie values to be encoded as octal escape sequences (`\NNN`). WAFs and proxies typically don't decode these, enabling payload obfuscation: `Cookie: $Version=1; name="\074script\076"`. | Legacy parsing mode; WAF does not decode RFC 2109 quoted strings |

### §2-2. Quoted-Value Parsing Differentials

Even without explicit `$Version` triggering, servers differ in how they handle double-quoted cookie values.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Quote-Absorbing Semicolon** | When a parser encounters a `dquoted` cookie value, it reads past semicolons that would normally terminate the value. `Cookie: a="value; JSESSIONID=secret"; b=x` — Jetty/Undertow may parse this as `a = "value; JSESSIONID=secret"`, merging the HttpOnly JSESSIONID into `a`'s value. | Jetty, Undertow; attacker controls a non-HttpOnly cookie adjacent to HttpOnly cookie |
| **Unmatched Quote Propagation** | An opening quote without a matching close quote causes some parsers to absorb the rest of the Cookie header into one value. Different servers fail-open or fail-closed differently on unmatched quotes. | Server-specific; requires knowledge of target parser behavior |

### §2-3. Encoding & Character Set Exploitation

Differences in character set handling between browser and server create injection and bypass opportunities.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Out-of-Bounds Character Injection** | Cookie libraries (e.g., npm `cookie` < 0.7.0, CVE-2024-47764) accept characters in cookie name/path/domain that should be rejected. This permits control characters and delimiters in cookie attributes, enabling XSS and injection. | Vulnerable cookie parsing library |
| **Unicode Normalization Differential** | Browser stores cookie names as raw bytes; server framework applies Unicode normalization (NFC/NFKC). A cookie name with Unicode look-alikes (e.g., fullwidth characters) becomes a different name after normalization, potentially colliding with security-critical cookies. | Server applies Unicode normalization to cookie names (Django, ASP.NET) |
| **Percent-Encoding Mismatch** | Some servers percent-decode cookie values while browsers send them as-is. Payloads like `%3Cscript%3E` may pass through cookie validation but be decoded into `<script>` on the server. | Server percent-decodes cookie values; no post-decode validation |
| **Null Byte Truncation** | Null bytes (`%00`) in cookie values cause some C-based parsers to truncate the value, while other components process the full string. This creates differential interpretation of cookie content. | C-based server/library; null byte not stripped by proxy |

---

## §3. Cookie Scope & Domain Resolution

Cookies use a domain/path scoping model that is fundamentally misaligned with the web's origin model. This category covers attacks that exploit scoping ambiguity.

### §3-1. Domain Scope Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Parent Domain Cookie Injection** | A subdomain (`evil.example.com`) sets a cookie with `Domain=.example.com`, which is delivered to all sibling subdomains including `app.example.com`. The victim application cannot distinguish this cookie from one it set itself. | Attacker controls any subdomain under the same registrable domain |
| **Subdomain Takeover Cookie Hijacking** | An unclaimed subdomain (dangling DNS CNAME) is taken over by the attacker, who then sets cookies scoped to the parent domain. This combines with SameSite bypass (§1-1) since all subdomains are same-site. | Dangling DNS record for a subdomain; target uses domain-scoped cookies |
| **Public Suffix List (PSL) Bypass** | Browsers rely on the PSL to prevent cookies from being set on public suffixes (`.com`, `.co.uk`). Incorrect or outdated PSL entries, or case-sensitivity bugs (curl CVE-2023-46218), allow "super cookies" that span unrelated domains. | PSL implementation bug; case-insensitive matching flaw |
| **Path Scope Limitation** | The `Path` attribute is NOT a security boundary — JavaScript on any path within the same origin can read/set cookies for any path. Developers who rely on Path for isolation create a false security assumption. | Misunderstanding of Path attribute semantics |

### §3-2. Same-Site vs. Same-Origin Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cross-Origin Same-Site Request** | Two different origins (different ports or subdomains) under the same registrable domain are "same-site." `SameSite` cookies flow between them, enabling CSRF from compromised sibling subdomains even with `SameSite=Strict`. | Attacker controls same-site, cross-origin context |
| **Schemeful Same-Site Divergence** | Modern browsers implement "schemeful same-site" (HTTP ≠ HTTPS for SameSite purposes), but legacy browsers don't. An HTTP page on the same domain may or may not send SameSite cookies depending on browser version. | Mixed scheme deployment; legacy browser support |

---

## §4. Cookie Value & Content Manipulation

Attacks targeting the semantic content of cookie values rather than the cookie protocol itself.

### §4-1. Cookie Deserialization

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Serialized Object Injection** | Server stores serialized objects (PHP `serialize()`, Python `pickle`, Java `ObjectInputStream`) in cookie values. Attacker crafts a malicious serialized payload that executes arbitrary code upon deserialization. | Server deserializes cookie values; no integrity verification |
| **Framework-Specific Gadget Chains** | Frameworks (DotNetNuke `DNNPersonalization` cookie, WordPress serialized cookies) use known gadget chains. Attackers inject gadgets that chain method calls to achieve RCE. Multiple CVEs for DotNetNuke trace back to the same deserialization entry point. | Framework uses serialization-based cookies; available gadget chains |
| **Encrypted Cookie Forgery** | When cookie encryption uses ECB mode, CBC without authentication (MAC), or has key management flaws, attackers can forge, reorder blocks, or decrypt cookie content. Related: padding oracle attacks against encrypted cookies. | Weak cipher mode; missing MAC; key reuse |

### §4-2. Token & Session ID Weakness

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Insufficient Entropy / Predictable Tokens** | Session IDs generated with weak PRNGs, sequential counters, or predictable seeds. Attackers enumerate or predict valid session tokens. | Weak PRNG; time-based seed; short token length |
| **JWT Cookie Vulnerabilities** | JWTs stored in cookies inherit all JWT attack vectors: `alg: none` bypass, HMAC/RSA confusion (CVE-2022-23529), key brute-forcing, claim manipulation. Misconfigured `decode()` vs `verify()` calls skip signature verification entirely. | JWT in cookie; weak secret; algorithm confusion; missing verification |
| **Cookie Value Tampering** | Application stores plaintext state in cookies (user role, price, preferences) without integrity protection. Attacker modifies the value directly. | No HMAC/signature on cookie value; trust of client-supplied data |

### §4-3. Cookie Injection via Adjacent Vectors

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CRLF Injection → Set-Cookie** | CRLF characters injected into HTTP response headers allow insertion of arbitrary `Set-Cookie` headers. Attacker can set any cookie with any attributes on the victim's browser. | CRLF injection in any response header (Location, custom headers) |
| **HTML Meta Tag Cookie Setting** | `<meta http-equiv="Set-Cookie" content="...">` can set cookies in legacy browsers. If HTML injection is possible, cookies can be injected without JavaScript. | HTML injection; legacy browser support for meta Set-Cookie |
| **XSS → document.cookie** | Client-side script execution allows reading and writing non-HttpOnly cookies. This is the most direct cookie manipulation primitive — any XSS becomes a cookie manipulation vector. | XSS vulnerability; cookies lack HttpOnly flag |

---

## §5. Cookie Jar State Management

Browsers maintain a cookie jar with per-domain storage limits. Attacks manipulate the jar's state — creation, ordering, eviction — rather than individual cookie values.

### §5-1. Cookie Jar Overflow / Eviction

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cookie Jar Overflow** | Browsers enforce per-domain cookie limits (typically ~50-180 cookies). Setting many new cookies forces eviction of existing cookies (oldest-first or LRU). An attacker sets enough cookies to evict a legitimate cookie, then replaces it with a malicious one. | Attacker can set cookies (subdomain XSS, cookie tossing); target cookie is evictable |
| **HttpOnly Cookie Deletion via Overflow** | Since JavaScript-set cookies and server-set HttpOnly cookies share the same jar, flooding the jar with JavaScript cookies can evict HttpOnly cookies. The attacker then replaces the evicted cookie with a non-HttpOnly version they control. | JavaScript execution context; shared cookie jar limits |
| **Cookie Bomb (Denial of Service)** | Attacker sets maximum-size cookies (4KB each × multiple cookies) scoped to the target domain. The victim's browser sends oversized Cookie headers (>8KB) that the server rejects with "413 Request Entity Too Large." The victim is locked out until cookies are manually cleared — potentially for the cookie's lifetime (up to 1 year). | Attacker can set cookies for target domain; no server-side size mitigation |

### §5-2. Cookie Tossing

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Subdomain Cookie Tossing** | Attacker on `evil.example.com` sets a cookie with the same name as a cookie on `app.example.com` but scoped to `.example.com`. The browser sends both cookies; server behavior depends on which one it reads first (usually undefined/implementation-dependent). | Attacker controls subdomain; target uses unprotected cookie names (no `__Host-` prefix) |
| **OAuth Flow Hijacking via Tossing** | Cookie tossing replaces CSRF tokens, state parameters, or session cookies during OAuth flows. The attacker's session cookie is sent alongside the legitimate one, causing the application to bind the OAuth token to the attacker's session. | OAuth flow uses cookies for state management; no `__Host-` prefix |
| **Self-XSS Amplification** | Cookie tossing forces a victim to use the attacker's session cookie. If a self-XSS exists that triggers on the logged-in user's own content, the victim now executes the XSS payload the attacker placed in "their" account. | Self-XSS vulnerability; cookie tossing primitive |

### §5-3. Cookie Jar Desynchronization

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Browser Cookie Jar Inconsistency** | Firefox-specific: the in-memory cookie jar and persistent cookie storage can become desynchronized under certain race conditions, causing cookies to reappear after deletion or fail to update. | Firefox browser; specific timing conditions |
| **Cookie Ordering Ambiguity** | When multiple cookies with the same name exist (different Path/Domain), the order in which browsers send them is loosely specified. Servers that read only the first value may get the attacker's cookie instead of the legitimate one. | Multiple same-name cookies; server reads first occurrence |

---

## §6. Cookie Transport & Interception

Attacks targeting cookies in transit — on the network, through proxies, or via protocol manipulation.

### §6-1. Network-Level Cookie Theft

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Passive Network Sniffing** | Cookies without the `Secure` flag are transmitted in plaintext over HTTP. Attacker on the same network segment captures them via packet sniffing. | HTTP (non-HTTPS) requests; cookies lack Secure flag |
| **SSL Stripping / HSTS Bypass** | Active MitM attacker downgrades HTTPS to HTTP before HSTS policy is cached. First-visit vulnerability for non-preloaded domains. | First visit; domain not in HSTS preload list; active MitM |
| **Wi-Fi / Shared Network Interception** | On shared networks (public Wi-Fi), ARP spoofing or rogue access points enable cookie interception for unencrypted sessions. The Firesheep tool (2010) demonstrated this at scale; the attack remains viable for HTTP-only sites. | Shared network; unencrypted connections |

### §6-2. Header Injection for Cookie Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Response Splitting → Cookie Setting** | HTTP response splitting via CRLF injection in headers allows injecting complete `Set-Cookie` response headers, giving the attacker full control over cookie attributes. | CRLF vulnerability in response header generation |
| **Request Header Injection** | Injecting into the request `Cookie:` header via HTTP header injection (in proxies, intermediaries, or client-side) allows adding or overwriting cookies the server receives. | Header injection in upstream proxy or client |

### §6-3. Cache-Mediated Cookie Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Web Cache Poisoning via Unkeyed Cookies** | If a cache server doesn't include `Cookie` in the cache key but the origin server varies the response based on cookie values, an attacker can poison the cache with a response generated for their malicious cookie, served to all users. | Cache doesn't key on Cookie; origin varies response on cookie |
| **Cache Deception Cookie Exposure** | Tricking a cache into storing an authenticated page (containing cookie-derived data) under a cacheable URL, exposing user data to subsequent requestors. | Cache serves dynamic content as static; authenticated data in response body |

---

## §7. Cookie Storage & Client-Side Protection Bypass

Attacks targeting how browsers store and protect cookies at rest on the client machine.

### §7-1. Browser Cookie Storage Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SQLite Cookie Database Extraction** | Browsers store cookies in SQLite databases (e.g., Chrome's `Cookies` file, Firefox's `cookies.sqlite`). Malware or local access reads these files directly. | Local system access; file not locked or encryption bypassed |
| **Chrome AppBound Encryption Bypass (C4 Bomb)** | Chrome's AppBound Cookie Encryption (introduced July 2024) uses dual-layer DPAPI encryption. The C4 (Chrome Cookie Cipher Cracker) attack exploits a CBC padding oracle via Chrome's elevation service, allowing low-privileged attackers to decrypt cookie blobs. | Chrome on Windows; elevation service accessible; padding oracle in CBC mode |
| **DPAPI Credential Access** | Pre-AppBound Chrome encryption and other Chromium browsers use Windows DPAPI with user-scope keys. Any process running as the same user can decrypt cookies. | Same-user process access; Windows DPAPI |
| **macOS Keychain Extraction** | On macOS, Chrome's cookie encryption key is stored in the Keychain. Malware with user-level permissions can request it (with a UI prompt that can be socially engineered or suppressed). | macOS; user-level access |

### §7-2. Infostealer & Malware-Based Cookie Theft

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Infostealer Malware Harvesting** | Families like Lumma, StealC, RedLine, Raccoon systematically extract cookies from all installed browsers. 17+ billion cookies were stolen in 2024 alone. Stolen cookies are sold on dark markets or used directly for account takeover. | Endpoint compromised by infostealer; cookies not bound to device |
| **Cookie-Bite (Malicious Browser Extension)** | A Chrome extension monitors Microsoft login URLs and exfiltrates `ESTSAUTH` and `ESTSAUTHPERSISTENT` Azure Entra ID tokens. These tokens bypass MFA entirely and provide access to Microsoft 365, Teams, Outlook for up to 90 days. | Malicious extension installed; targets Azure Entra ID sessions |
| **Process Memory Extraction** | Reading browser process memory to extract decrypted cookies before they are written to encrypted storage. Bypasses all at-rest encryption protections. | Sufficient privileges to read browser process memory |

### §7-3. Cookie Replay & Session Abuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Session Cookie Replay** | Stolen session cookies are replayed from a different device/location. Since the cookie represents a completed authentication (including MFA), the server accepts it without re-authentication. | No device binding; no session fingerprinting; cookie not expired |
| **Pass-the-Cookie** | Enterprise variant of cookie replay: attackers use stolen cloud session tokens (Azure, AWS, GCP) to access cloud resources. Became the dominant post-compromise technique in 2024-2025, replacing password-based lateral movement. | Cloud session cookies; no token binding or continuous access evaluation |
| **Cookie Persistence Abuse** | "Remember me" tokens with long lifetimes (30-90 days) remain valid even after password changes. Attackers maintain access long after initial compromise is detected. | Long-lived persistent cookies; no invalidation on credential change |

---

## §8. Cookie Lifecycle & Session State Attacks

Attacks that exploit the temporal aspects of cookie creation, validation, and destruction.

### §8-1. Session Fixation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Pre-Authentication Fixation** | Attacker obtains a valid session ID from the server, forces it onto the victim (via URL, cookie injection, or meta tag), and waits for the victim to authenticate. The server does not regenerate the session ID on login, so the attacker's known ID is now authenticated. | Server does not regenerate session ID on authentication |
| **Cross-Subdomain Fixation** | Attacker on a sibling subdomain sets the session cookie for the parent domain before the victim visits the target application. Combines cookie tossing (§5-2) with session fixation. | Subdomain control; domain-scoped session cookies |
| **Cookie Injection via Network** | Active network attacker injects `Set-Cookie` responses for HTTP requests to any subdomain, fixing the session before the victim connects over HTTPS. | Active MitM; victim makes any HTTP request under the target domain |

### §8-2. Session Lifecycle Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Insufficient Session Invalidation** | Server fails to invalidate sessions on logout, password change, or privilege change. Old cookies remain valid indefinitely. | Server-side session not properly destroyed |
| **Concurrent Session Abuse** | No limit on concurrent sessions per user. Attacker's stolen session remains valid even after user creates a new one. | No concurrent session limits; no session listing/revocation UI |
| **Session Puzzle** | Application uses multiple independent cookie-based state parameters that can be mixed and matched. Attacker combines cookies from different sessions or users to construct an elevated-privilege state. | Multiple state cookies; no binding between them |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Condition | Primary Mutation Categories |
|---|---|---|
| **Session Hijacking** | Any cookie theft vector + session replay | §7-2 + §7-3 + §6-1 |
| **CSRF** | Cross-site request with victim's cookies | §1-1 (SameSite bypass) + §3-2 |
| **XSS Amplification** | XSS + cookie manipulation | §1-2 (HttpOnly bypass) + §5-2 (tossing for Self-XSS) |
| **MFA Bypass** | Stolen post-MFA session token replayed | §7-2 (Cookie-Bite) + §7-3 (Pass-the-Cookie) |
| **Denial of Service** | Cookie bomb locks out user | §5-1 (Cookie Bomb) |
| **WAF Bypass** | Payload hidden in legacy cookie encoding | §2-1 ($Version) + §2-3 (encoding) |
| **Cache Poisoning** | Cookie-varied response cached without cookie key | §6-3 |
| **Privilege Escalation** | Cookie value tampering or session puzzle | §4-2 + §8-2 |
| **Account Takeover** | Session fixation + victim login | §8-1 + §5-2 |
| **OAuth Hijacking** | Cookie tossing replaces OAuth state | §5-2 + §8-1 |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §2-3 (Out-of-bounds chars) | CVE-2024-47764 (npm `cookie`) | XSS via cookie name/path/domain injection |
| §3-1 (PSL bypass) | CVE-2023-46218 (curl) | Mixed-case PSL bypass enables super cookies across domains |
| §7-1 (AppBound bypass) | C4 Bomb (Chrome, reported Dec 2024) | Low-privilege decryption of all Chrome AppBound-encrypted cookies |
| §5-2 (Cookie tossing) | CVE-2024-21583 (Gitpod) | Session hijacking via cookie tossing in Gitpod protocol |
| §4-1 (Deserialization) | CVE-2017-9822 + 4 bypass CVEs (DotNetNuke) | RCE via DNNPersonalization cookie deserialization |
| §1-3 + §2-1 (Prefix bypass via $Version) | PortSwigger Cookie Chaos (2025) | __Host-/__Secure- prefix bypass on Java servers |
| §1-2 + §2-2 (Cookie sandwich) | PortSwigger Cookie Sandwich (Jan 2025) | HttpOnly flag bypass; session token theft |
| §2-1 + §2-3 (WAF bypass via phantom cookie) | PortSwigger $Version WAF Bypass (2025) | WAF rule evasion using legacy RFC 2109 encoding |
| §3-2 + §8 (Session integrity) | Cookie Crumbles — 12 CVEs (USENIX Sec 2023) | 27 vulnerability disclosures across 13 web frameworks; PHP (CVE-2022-31629), ReactPHP (CVE-2022-36032), Werkzeug (CVE-2023-23934) |
| §7-2 (Extension-based theft) | Cookie-Bite PoC (Varonis, Apr 2025) | Azure Entra ID MFA bypass; 90-day persistent access to M365 |
| §4-2 (JWT in cookie) | CVE-2025-34291 (Langflow) | Account takeover via JWT cookie + permissive CORS |
| §7-2 (Infostealer) | Lumma Stealer takedown (May 2025) | 394,000+ Windows systems infected; 1,300 domains seized |

---

## Detection & Testing Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Burp Suite Scanner** (Commercial) | Cookie attribute audit | Passive detection of missing Secure/HttpOnly/SameSite flags |
| **Burp Sequencer** (Commercial) | Session token entropy | Statistical randomness analysis of cookie values |
| **Cookie Reflection Extension** (Burp) | Cookie value reflection | Passive scan for cookie names/values reflected in response body |
| **Load Balancer Cookie Scanner** (Burp) | Infrastructure leak | Decodes BigIP/Netscaler cookies exposing internal IPs |
| **CookieCrumbles Test Suite** (Research) | Browser/framework inconsistency | Automated cross-browser evaluation of cookie integrity issues |
| **OWASP ZAP** (Open Source) | General cookie security | Passive/active scanning for cookie attribute misconfigurations |
| **testssl.sh** (Open Source) | Transport security | HSTS, Secure flag, and TLS configuration validation |
| **Nikto** (Open Source) | Server configuration | Detection of HttpOnly/Secure flag omissions, TRACE method |
| **Cookie-Editor** (Browser Extension) | Manual testing | View, edit, create, delete cookies with full attribute control |
| **jwt_tool** (Open Source) | JWT cookie attacks | Automated testing for alg:none, key confusion, brute force |

---

## Summary: Core Principles

The cookie vulnerability surface exists because the cookie mechanism was designed as a simple key-value state persistence layer but evolved to carry security-critical session state, authentication tokens, and authorization decisions. Three fundamental architectural tensions make this attack surface irreducible through incremental patching:

**1. Parsing Heterogeneity.** Every component in the request chain — browser, CDN, WAF, reverse proxy, application server, framework, and application code — implements its own cookie parser. The RFC lineage (2109 → 2965 → 6265 → 6265bis) left behind legacy behaviors that servers still support for compatibility. When any two parsers in the chain disagree on cookie boundaries, names, or values, the resulting differential is exploitable. The 2025 PortSwigger research series (cookie sandwich, phantom $Version, cookie chaos) demonstrates that even the newest browser-side protections (cookie prefixes) can be defeated by server-side parser quirks that date back to RFC 2109.

**2. Scope Model Mismatch.** Cookies scope to domains (registrable domain + subdomains), while security boundaries are drawn at origins (scheme + host + port). This mismatch means that controlling *any* subdomain — even through a dangling DNS record — grants the attacker full cookie manipulation capability for the entire domain. `SameSite` cookies compound the confusion by introducing a third boundary (site ≠ origin ≠ domain), leading practitioners to assume stronger isolation than actually exists.

**3. Stateless Token, Stateful Assumption.** A session cookie is a bearer token — possession equals authentication. No standard mechanism binds cookies to the device, network, or TLS session that created them. This makes cookie theft universally exploitable: infostealer malware stole 17+ billion cookies in 2024, each one a valid MFA-bypass credential. Browser-side encryption (Chrome AppBound) addresses storage-at-rest but was broken within months (C4 Bomb). The structural solution — token binding, device-bound session credentials, or continuous access evaluation — requires fundamental protocol changes that the web ecosystem has been slow to adopt.

The only comprehensive defense is defense-in-depth: `__Host-` prefixes for integrity, `SameSite=Strict` where feasible, `HttpOnly` always, server-side session regeneration on privilege changes, short-lived tokens with rotation, device-binding where supported, and continuous monitoring for anomalous session usage patterns.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- PortSwigger Research — [Cookie Chaos: How to bypass __Host and __Secure cookie prefixes](https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes)
- PortSwigger Research — [Stealing HttpOnly cookies with the cookie sandwich technique](https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique)
- PortSwigger Research — [Bypassing WAFs with the phantom $Version cookie](https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie)
- PortSwigger — [Bypassing SameSite cookie restrictions](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
- USENIX Security 2023 — [Cookie Crumbles: Breaking and Fixing Web Session Integrity](https://www.usenix.org/conference/usenixsecurity23/presentation/squarcina)
- Varonis — [Cookie-Bite: How Your Digital Crumbs Let Threat Actors Bypass MFA](https://www.varonis.com/blog/cookie-bite)
- CyberArk — [C4 Bomb: Blowing Up Chrome's AppBound Cookie Encryption](https://www.cyberark.com/resources/threat-research-blog/c4-bomb-blowing-up-chromes-appbound-cookie-encryption)
- Snyk Labs — [Hijacking OAuth flows via Cookie Tossing](https://labs.snyk.io/resources/hijacking-oauth-flows-via-cookie-tossing/)
- Thomas Houhou — [Cookie Tossing: Self-XSS Exploitation, Multi-Step Process Hijacking, and Targeted Action Poisoning](https://www.thomashouhou.com/post/cookie-tossing-attacks/)
- Ankur Sundara — [Cookie Bugs: Smuggling & Injection](https://blog.ankursundara.com/cookie-bugs/)
- HackTricks — [Cookies Hacking](https://book.hacktricks.wiki/en/pentesting-web/hacking-with-cookies/index.html)
- HackTricks — [Cookie Bomb](https://book.hacktricks.xyz/pentesting-web/hacking-with-cookies/cookie-bomb)
- HackTricks — [Cookie Jar Overflow](https://book.hacktricks.xyz/pentesting-web/hacking-with-cookies/cookie-jar-overflow)
- GitHub Advisory — [CVE-2024-47764: cookie package out-of-bounds characters](https://github.com/advisories/GHSA-pxg6-pf52-xh8x)
- Cobalt — [Got Cookies? Cookie Based Authentication Vulnerabilities in the Wild](https://www.cobalt.io/blog/got-cookies-cookie-based-authentication-vulnerabilities-in-wild)
- DeepStrike — [Stealer Log Statistics 2025](https://deepstrike.io/blog/stealer-log-statistics-2025)
- HP Wolf Security — [Tracing the Rise of Breaches Involving Session Cookie Theft](https://threatresearch.ext.hp.com/tracing-the-rise-of-breaches-involving-session-cookie-theft/)
- jub0bs.com — [The great SameSite confusion](https://jub0bs.com/posts/2021-01-29-great-samesite-confusion/)
- 0xn3va — [Cookie Tossing Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/web-application/cookie-security/cookie-tossing)
- OWASP — [Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
