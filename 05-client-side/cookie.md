# Cookie Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the full attack surface of HTTP cookie vulnerabilities along three orthogonal axes. **Axis 1 (Mutation Target)** classifies techniques by the structural component of the cookie system being attacked — attributes, parsing, scope, value content, jar state, transport layer, client-side storage, or session lifecycle. This is the primary organizational axis. **Axis 2 (Discrepancy/Bypass Type)** captures the nature of the mismatch or circumvention that makes each technique work — parsing differentials, flag bypasses, scope confusion, state manipulation, cryptographic weakness, or specification inconsistency. **Axis 3 (Attack Scenario)** maps techniques to their real-world weaponization context — session hijacking, CSRF, XSS amplification, denial of service, MFA bypass, cache poisoning, WAF bypass, or privilege escalation.

The cookie system's attack surface is fundamentally rooted in a historical design tension: cookies were introduced as a stateless-to-stateful bridge for HTTP, yet they carry implicit trust assumptions about origin, integrity, and confidentiality that the protocol never formally guaranteed. The cookie specification has evolved through RFC 2109 → RFC 2965 → RFC 6265, with RFC 6265bis currently progressing through the IETF standardization process (not yet published as an RFC). Browser and server implementations retain varying degrees of backward compatibility with deprecated behaviors, and many already implement draft 6265bis features (e.g., `SameSite` defaults). This specification drift — compounded by implementations racing ahead of finalized standards — is the meta-vulnerability that enables the majority of techniques cataloged below.

### Axis 2 Summary: Cross-Cutting Discrepancy Types

| Discrepancy Type | Description | Primary Sections |
|---|---|---|
| **Browser-Server Parsing Differential** | Browser and server interpret the same Cookie header bytes differently | §2, §1-3 |
| **Attribute/Flag/Prefix Bypass** | Security attributes (HttpOnly, Secure, SameSite), cookie name prefixes (`__Host-`, `__Secure-`), and scope attributes (Domain, Path) are circumvented | §1, §2-2, §2-3 |
| **Scope Confusion** | Cookie delivered to unintended origins due to domain/site/origin model mismatch | §3 |
| **State Manipulation** | Cookie jar state (creation, eviction, ordering) is externally controlled | §5 |
| **Cryptographic/Token Weakness** | Cookie value protection (encryption, signing, entropy) is broken | §4, §7 |
| **Specification Inconsistency** | Divergent RFC interpretations across implementations | §2-1, §2-3 |

---

## §1. Cookie Attribute, Flag & Prefix Manipulation

Cookies carry security-relevant attributes (`Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`) and cookie name prefixes (`__Host-`, `__Secure-`) that browsers are supposed to enforce. Note: prefixes are not Set-Cookie attributes — they are naming conventions enforced by browsers at cookie-setting time based on the cookie name's prefix. Attacks in this category subvert these enforcement mechanisms.

### §1-1. SameSite Bypass Techniques

The `SameSite` attribute restricts cross-site cookie transmission to mitigate CSRF. Multiple bypass vectors exist due to specification edge cases and browser implementation choices.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Lax+POST Two-Minute Window** | Chrome allows cross-site POST requests for **cookies without an explicit SameSite attribute** (implicitly treated as Lax-by-default) for 2 minutes after cookie creation. This grace window does not apply to cookies where the server explicitly sets `SameSite=Lax`. Attackers can exploit this window by triggering a new login/OAuth flow. | Cookie without explicit SameSite attribute (implicit Lax); within 120 seconds of creation; Chromium-based browsers (documented as a default-Lax relaxation behavior in some browsers) |
| **Top-Level GET Navigation** | `SameSite=Lax` permits cookies on top-level navigations using safe methods (GET). Attackers trigger state-changing GET endpoints via `<a>` clicks, `window.open()`, or redirects. | Application performs state-changing operations on GET requests |
| **HTTP Method Override** | Frameworks (Symfony, Rails, Laravel) support `_method` parameters that override the HTTP verb server-side. A GET request with `?_method=POST` is treated as POST by the server while the browser considers it a GET, sending Lax cookies. | Framework method override enabled; no server-side SameSite enforcement |
| **Same-Site Cross-Origin** | `SameSite` compares *sites* (eTLD+1), not *origins*. A compromised or attacker-controlled sibling subdomain (`evil.example.com`) can issue same-site requests to `app.example.com`, and the browser will transmit SameSite cookies with those requests. Note this grants *cookie transmission*, not the ability to read cross-origin responses (blocked by SOP) or access HttpOnly cookies via JavaScript. | Attacker controls any subdomain of the same registrable domain |
| **Client-Side Redirect Chain** | A server-side redirect from a cross-site context creates a same-site top-level navigation at the redirect destination. Chaining open redirects converts cross-site requests into same-site navigations. | Open redirect exists on the target site |

### §1-2. HttpOnly Bypass Techniques

The `HttpOnly` flag prevents JavaScript from reading cookies via `document.cookie`. Bypasses expose cookie values through alternative channels.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cookie Sandwich** | An attacker crafts cookies with strategically placed quotes that, under RFC 2109 legacy parsing (triggered by `$Version=1`), cause the server to merge multiple cookies into a single value — absorbing adjacent HttpOnly cookies into a readable, non-HttpOnly cookie. | Server supports RFC 2109 parsing (Tomcat, Jetty); attacker can set cookies (subdomain or XSS) |
| **TRACE Method Reflection (Legacy)** | HTTP TRACE reflects the full request, including `Cookie` headers, in the response body. Historically, if TRACE was enabled and XSS existed, JavaScript could read reflected HttpOnly cookies (Cross-Site Tracing / XST). Modern browsers block TRACE in `fetch()` and `XMLHttpRequest` (Fetch spec forbidden method), making this a legacy vector. Still relevant for non-browser HTTP clients or misconfigured custom request libraries. | TRACE method enabled on server; non-browser client or pre-2012 browser |
| **Error Page / Debug Reflection** | Server error pages, debug endpoints, or phpinfo() reflect cookie headers in HTML body, making them accessible to JavaScript. | Verbose error handling or debug mode enabled in production |
| **Server-Side Parsing Quirk Leak** | Differential parsing between browser and server causes HttpOnly cookie values to be concatenated with non-HttpOnly cookies in server responses (see §2-2 quoted-value parsing). | Jetty, Undertow, or similar servers with quoted-value parsing quirks |
| **CORS Credential Exfiltration** | If `Access-Control-Allow-Credentials: true` with a permissive origin, response body may contain reflected cookie values that JavaScript can read cross-origin. | Misconfigured CORS policy with credential reflection |

### §1-3. Cookie Prefix Bypass

`__Host-` and `__Secure-` prefixes enforce that cookies are set from secure origins. `__Host-` additionally requires that the cookie must omit the `Domain` attribute and must set `Path=/`. Bypasses exploit encoding differentials.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **UTF-8 Normalization Bypass** | Attacker sets a cookie with a Unicode whitespace prefix (e.g., `\u2000__Host-session`). The browser treats it as a non-prefixed cookie (no restrictions), but server-side frameworks (Django, ASP.NET) normalize the Unicode via Python's `str.strip()` / .NET's trimming, stripping the whitespace and interpreting it as `__Host-session`. Exploitable whitespace codepoints (all stripped by Django/ASP.NET): `\x85` (NEL), `\xA0` (NBSP), `\u1680` (Ogham Space), `\u2000`–`\u200A` (en/em/thin spaces), `\u2028` (Line Separator), `\u2029` (Paragraph Separator), `\u202F` (Narrow NBSP), `\u205F` (Medium Math Space), `\u3000` (Ideographic Space). **Browser constraint**: Safari rejects multibyte Unicode characters (`\u1680`, `\u2000`+) in cookie names but accepts single-byte characters `\x85` and `\xA0` — so Safari-targeted attacks must use one of these two codepoints. Chrome and Firefox accept all listed codepoints. | Server-side Unicode normalization (Django `str.strip()`, ASP.NET); Safari limited to `\x85`/`\xA0`; Chrome/Firefox accept all Unicode whitespace |
| **Legacy $Version Parsing** | When `$Version=1` appears at the start of the Cookie header, Java servers (Tomcat, Jetty) switch to RFC 2109 parsing where quoted strings and comma separators alter cookie boundaries. An attacker injects a crafted value that the server interprets as a `__Host-` prefixed cookie. | Java-based server with legacy RFC 2109 support enabled |
| **Subdomain Cookie Shadowing** | While `__Host-` cookies cannot specify a Domain, an attacker on a sibling subdomain can set a *non-prefixed* cookie with the same name for the parent domain. The browser sends both cookies, and the server's duplicate-name resolution determines which wins: **first-wins** (Tomcat, Express) vs **last-wins** (Django, PHP). Django and PHP use the last occurrence, so the attacker's later-created domain-scoped cookie (sent after the host-only cookie by Chrome/Firefox's creation-time ordering — older cookies first per RFC 6265bis) reliably overwrites the legitimate value. | Attacker controls a sibling subdomain; server duplicate-name resolution is implementation-dependent (first-wins: Tomcat, Express; last-wins: Django, PHP) |
| **Nameless Cookie Serialization Collision** | RFC 6265bis added support for nameless cookies (cookies set with empty name, e.g., `Set-Cookie: token`). A same-site attacker sets `Set-Cookie: =__Host-sid=evil; Domain=site.tld`, which the browser serializes as `Cookie: __Host-sid=evil` — indistinguishable from a legitimate `__Host-` cookie. The browser treats the nameless cookie as unrestricted (no Secure/Path=/ requirements), bypassing `__Host-` integrity guarantees. Chrome (CVE-2022-2860, v104) and Firefox (CVE-2022-40958, v105) patched by rejecting nameless cookies whose value starts with a case-insensitive match for `__Host-` or `__Secure-`. | Browser pre-patch (Chrome <104, Firefox <105); or proxy that re-serializes cookies bypassing browser-side mitigations (§2-2) |
| **PHP Cookie Name Character Normalization** | PHP's legacy `register_globals` design replaces spaces, dots (`.`), and opening brackets (`[`) with underscores (`_`) in `$_COOKIE` superglobal keys. An attacker sets `Set-Cookie: ..Host-sid=evil; Domain=site.tld` from a sibling subdomain; PHP normalizes `..Host-sid` to `__Host-sid`, bypassing prefix protections. The same transformation affects all cookie names containing these characters, extending integrity concerns beyond prefixed cookies (CVE-2022-31629, fixed in PHP 7.4.31, 8.0.24, 8.1.11). | PHP backend; attacker can set cookies via subdomain or network position |

### §1-4. Secure Flag Bypass

The `Secure` attribute restricts cookie transmission to HTTPS. Bypasses deliver cookies over insecure channels.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Network MitM Cookie Setting** | An active network attacker intercepts an HTTP request to any subdomain and responds with `Set-Cookie` for the target domain. Modern browsers (implementing draft RFC 6265bis) generally block setting `Secure`-flagged cookies from non-secure (HTTP) origins. Chrome and Firefox treat `http://localhost` as a "potentially trustworthy origin" and exempt it from this restriction; **Safari does not** — it strictly requires HTTPS for `Secure` cookies even on localhost (HTTPWG issue #2605). However, the attacker can still set *non-Secure* cookies that may shadow or interfere with legitimate cookies. Legacy browsers that predate this restriction remain fully vulnerable. | Victim makes any HTTP request; attacker controls network; legacy browser or non-Secure cookie targeting |
| **Mixed Content Leak** | HTTPS page loads HTTP subresources. Cookies without the `Secure` flag are transmitted in plaintext with those HTTP requests, exposing them to network interception. Note: modern browsers strictly enforce the `Secure` flag — Secure cookies are never sent over HTTP, so only non-Secure cookies are at risk in mixed-content scenarios. | Mixed content on HTTPS pages; cookies lack Secure flag |
| **HSTS Stripping** | On first visit (before HSTS is cached), an active attacker downgrades HTTPS to HTTP, capturing cookies. Mitigated by HSTS preload, but not all domains are preloaded. | First visit without HSTS preload; active network attacker |
| **Safari Insecure Cookie Tossing Against Secure Cookies** | Safari does not prevent cookie tossing of secure cookies from non-secure (HTTP) origins, violating RFC 6265bis §5.4 which mandates that browsers reject a cookie set from an insecure origin when a secure cookie with the same name and overlapping scope already exists. A network attacker can overwrite `Secure`-flagged cookies on Safari without needing HTTPS capability, lowering the preconditions for cookie tossing and session fixation attacks. | Safari browser; active network attacker; target uses Secure-flagged cookies without `__Host-` prefix |

---

## §2. Cookie Parsing & Encoding Differentials

Cookies traverse multiple parsers (browser, CDN/proxy, WAF, server framework, application). When these parsers interpret the same byte sequence differently, security boundaries collapse.

### §2-1. Legacy RFC Parsing Exploitation

RFC 2109/2965 defined cookie features (quoted values, `$Version`, `$Path`, `$Domain`, comma separators) that modern browsers don't generate but many servers still accept.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **$Version Phantom Cookie** | A cookie named `$Version` (settable by JavaScript since browsers don't recognize it as special) triggers RFC 2109 parsing mode in Tomcat/Jetty. This changes how all subsequent cookies in the header are parsed — enabling cookie sandwich attacks (§1-2) and WAF bypasses (§2-3). Trigger strings vary by server: Tomcat 8.5.x/9.0.x/10.0.x requires exactly `$Version=1`, while Eclipse Jetty < 9.4.3 enters legacy mode on **any cookie name starting with `$`** (e.g., `$anything`), greatly expanding the attack surface. | Java-based backend (Tomcat ≤10.0.x, Jetty < 9.4.3); attacker can set cookies via JavaScript |
| **Comma-Separated Cookie Injection** | RFC 2109 permits commas as cookie separators. In legacy mode, a single cookie value containing a comma can be split into multiple cookies. `Cookie: $Version=1; a="x, injected=payload"` may yield cookies `a=x` and `injected=payload`. | Legacy parsing mode active; server splits on comma |
| **Quoted-String Escape Sequences** | RFC 2109's `quoted-string` only defines `quoted-pair` (`\` + single character); octal escapes (`\NNN`) are not part of the RFC standard. However, some Java servers (Tomcat, Jetty) non-standardly interpret octal escapes, enabling WAF bypass: `Cookie: $Version=1; name="\074script\076"`. Python's standard library `http.cookies.SimpleCookie` also interprets octal escapes (inherited from RFC 2068's `cookies.py`), and does so **without requiring `$Version`** — any quoted-string value triggers octal decoding (e.g., `"\145\166\141\154\050\047\150\151\047\051"` → `eval('hi')`). Beyond WAF bypass, octal-decoded control characters enable **backend protocol injection**: when cookie values are used as Memcached/Redis keys, `\015\012` (octal for `\r\n`) injects CRLF into the protocol stream, allowing arbitrary command execution (e.g., `set EVIL 0 1 1\r\n1\r\nget EVIL`). Combined with Flask-Session's default pickle serialization (pylibmc 1.6.3 + Flask-Session 0.8.0), this yields a full RCE chain: octal encoding → CRLF → Memcached command injection → malicious pickle object insertion → deserialization RCE. | Non-standard parsing in Java servers and Python stdlib; WAF cannot handle server-specific quoted-string interpretation; Python: any quoted-string triggers octal decoding without `$Version` |
| **Python SimpleCookie Legacy Parsing** | Python's `http.cookies.SimpleCookie` (stdlib) implements RFC 2068/2109 quoted-string parsing **unconditionally** — no `$Version` trigger is needed. Any cookie value enclosed in double quotes activates legacy parsing including octal escape interpretation, backslash-quoting, and comma handling. This makes Python backends vulnerable to the same class of attacks as Java servers under `$Version=1`, but with a lower barrier: the attacker only needs to control a quoted cookie value. | Python backend using `SimpleCookie` or frameworks that delegate to it; any quoted cookie value |

### §2-2. Quoted-Value Parsing Differentials

Even without explicit `$Version` triggering, servers differ in how they handle double-quoted cookie values.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Quote-Absorbing Semicolon** | When a parser encounters a `dquoted` cookie value, it reads past semicolons that would normally terminate the value. `Cookie: a="value; JSESSIONID=secret"; b=x` — Jetty/Undertow may parse this as `a = "value; JSESSIONID=secret"`, merging the HttpOnly JSESSIONID into `a`'s value. | Jetty, Undertow; attacker controls a non-HttpOnly cookie adjacent to HttpOnly cookie |
| **Unmatched Quote Propagation** | An opening quote without a matching close quote causes some parsers to absorb the rest of the Cookie header into one value. Different servers fail-open or fail-closed differently on unmatched quotes. | Server-specific; requires knowledge of target parser behavior |
| **Leading-Equals Stripping** | Werkzeug (Flask's HTTP library) strips all leading `=` symbols when parsing the Cookie header. A nameless cookie set via `Set-Cookie: ==__Host-sid=evil; Domain=site.tld` is serialized by the browser as `Cookie: ==__Host-sid=evil`, which Werkzeug parses as the name-value pair `(__Host-sid, evil)`. This bypasses `__Host-` protections even after browser-side nameless cookie mitigations, since the cookie value starts with `=` (not matching the browser's rejection pattern). CVE-2023-23934, fixed in Werkzeug 2.2.3. | Werkzeug/Flask backend; attacker can set nameless cookies via subdomain or network |
| **Cookie Sandwich → Response Reflection Injection** | When a cookie sandwich (§1-2) absorbs adjacent cookies into a quoted-string value, and the server reflects that parsed value into a response body (JSON API, HTML, tracking pixel), the absorbed content becomes part of the output. Example: `Cookie: $Version=1, visitorId="Id; Inj"` → server reflects `{"visitorId":"\"Id; Inj\""}`, enabling JSON structure injection or XSS depending on the response context. This extends cookie sandwich from a cookie-theft primitive to a **response injection** primitive. | Server reflects parsed cookie values in response body (JSON, HTML); cookie sandwich absorbs attacker-controlled content adjacent to reflected cookie |
| **Browser Set-Cookie Quoted-String Divergence** | Safari respects RFC 2109 quoted-string semantics in `Set-Cookie` headers: `Set-Cookie: attr="anything; session=value"` is parsed as a single cookie with value `anything; session=value` (semicolons inside quotes are not treated as attribute separators). Chrome and Firefox ignore the quotes and split on the semicolon, creating separate attribute `session=value`. This divergence means cookie sandwich setups work differently per browser, and on Chrome/Firefox, a quoted `Set-Cookie` value can inadvertently create additional cookie attributes. | Safari vs Chrome/Firefox; Set-Cookie with quoted values containing semicolons |
| **Safari Set-Cookie Comma Splitting** | Safari splits `Set-Cookie` header values on commas, treating `Set-Cookie: cookie=a, injection=b;` as two separate cookies (`cookie=a` and `injection=b`). Chrome and Firefox do not split on commas in `Set-Cookie`. This enables phantom cookie injection on Safari: if any component in the response chain (proxy, CDN, application) concatenates multiple `Set-Cookie` headers with commas (as permitted for other HTTP headers), Safari creates attacker-controlled cookies that don't exist in other browsers. Safari's Network Inspector shows both cookies, confirming client-side creation. | Safari browser; `Set-Cookie` value contains comma (from header folding, proxy concatenation, or attacker-controlled value) |
| **Proxy Cookie-to-JSON Serialization** | Proxies that re-serialize cookies into different formats introduce additional parsing boundaries. AWS API Gateway's Lambda proxy integration converts Cookie headers into a JSON `cookies` array with comma separation. A nameless cookie `Cookie: =__Host-sid=evil` is serialized as `{"cookies": ["__Host-sid=evil"]}`, indistinguishable from a legitimate `__Host-sid` cookie in the Lambda function. This bypass evades browser-side mitigations because the cookie value starts with `=`. AWS deployed a fix in November 2022 discarding entries starting with `=` followed by `__Host-` or `__Secure-`. | Proxy/gateway re-serializes cookies into a different format (JSON, comma-separated); nameless cookie attack vector |

### §2-3. Encoding & Character Set Exploitation

Differences in character set handling between browser and server create injection and bypass opportunities.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Out-of-Bounds Character Injection** | Cookie libraries (e.g., npm `cookie` < 0.7.0, CVE-2024-47764) accept characters in cookie name/path/domain that should be rejected. This permits control characters and delimiters in cookie attributes, enabling cookie field tampering and unexpected values; XSS is a possible secondary impact depending on application context. | Vulnerable cookie parsing library |
| **Unicode Normalization Differential** | Browser stores cookie names as raw bytes; server framework applies Unicode normalization (NFC/NFKC). A cookie name with Unicode look-alikes (e.g., fullwidth characters) becomes a different name after normalization, potentially colliding with security-critical cookies. | Server applies Unicode normalization to cookie names (Django, ASP.NET) |
| **Percent-Encoding Mismatch** | Some servers percent-decode cookie values while browsers send them as-is. Payloads like `%3Cscript%3E` may pass through cookie validation but be decoded into `<script>` on the server. | Server percent-decodes cookie values; no post-decode validation |
| **Cookie Name Percent-Decoding** | Some server-side HTTP libraries url-decode cookie *names* (not just values). ReactPHP's HTTP server decodes `%5F%5FHost-sid=evil` to `__Host-sid=evil`, creating a `__Host-` prefix bypass from a cookie the browser treated as non-prefixed and unrestricted. CVE-2022-36032, fixed in ReactPHP HTTP v1.7.0. | ReactPHP HTTP server; attacker can set cookies from sibling subdomain or network position |
| **Set-Cookie Value Reflection Attribute Injection** | When a server reflects a user-controlled value into a `Set-Cookie` header (e.g., `Set-Cookie: id={user_input}; path=/; HttpOnly`), injecting attribute separators (`;`) inside the value causes the browser to parse the remainder as cookie attributes. Payload `id; path=/; \t` in Chrome causes the tab character to truncate parsing, allowing injection of fake attributes like `HttpOnly` or `Secure` into attacker-controlled cookies. Safari additionally treats RFC 2616 separator characters (`" { } , : < > ? @ [ ] ( ) \`) as special within cookie name contexts, broadening the injection surface. When the same reflected value appears in a JSON response body, the attacker achieves simultaneous cookie attribute manipulation and JSON injection (e.g., `id=", "foo":"bar"` → `{"id":"","foo":"bar"}`). | Server reflects user input into `Set-Cookie` header value or JSON response; no sanitization of `;`, `\t`, or quote characters |
| **Overlong UTF-8 Encoding** | UTF-8 forbids overlong encodings (e.g., `/` U+002F can be encoded as the valid single byte `2F`, or the invalid 2-byte `C0 AF`, or 3-byte `E0 80 AF`). Browsers transmit cookie names/values as raw octets per RFC 6265 ("a sequence of octets, not characters"). If a server-side parser performs UTF-8 decoding without rejecting overlong sequences, forbidden characters (`;`, `=`, `/`, `\r\n`) can be smuggled past byte-level validation. This is distinct from Unicode normalization (§2-3 NFC/NFKC): overlong encoding exploits invalid UTF-8 byte sequences rather than legitimate codepoint equivalences. Network analysis tools (Wireshark) may flag these as `[Malformed Packet: HTTP]`, creating blind spots for defenders. | Server accepts overlong UTF-8 without validation; byte-level security checks that don't decode UTF-8 |
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
| **Path Scope Limitation** | The `Path` attribute is NOT a security boundary. While `Path` restricts which requests *transmit* the cookie, it does not prevent same-origin JavaScript from setting cookies with arbitrary `Path` values. Additionally, techniques like `<iframe>` embedding of same-origin paths or `fetch()` requests can access responses from any path under the same origin, undermining path-based isolation. Developers who rely on Path for security create a false assumption. | Misunderstanding of Path attribute semantics |

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
| **JWT Cookie Vulnerabilities** | JWTs stored in cookies inherit all JWT attack vectors: `alg: none` bypass, HMAC/RSA algorithm confusion, key brute-forcing, claim manipulation. CVE-2022-23529 (retracted — Unit 42 and Auth0 jointly withdrew the CVE after determining the threat model requires the attacker to already control the secret key object, making exploitation circular) demonstrated key object injection in the `jsonwebtoken` library where a malicious object with a crafted `toString()` can be passed as the key. Separately, GHSA-qwph-4952-7xr6 addresses `jsonwebtoken`'s insecure `alg:none` / `verify()` default behavior. Misconfigured `decode()` vs `verify()` calls skip signature verification entirely. | JWT in cookie; weak secret; algorithm confusion; missing verification |
| **Cookie Value Tampering** | Application stores plaintext state in cookies (user role, price, preferences) without integrity protection. Attacker modifies the value directly. | No HMAC/signature on cookie value; trust of client-supplied data |

### §4-3. Cookie Injection via Adjacent Vectors

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CRLF Injection → Set-Cookie** | CRLF characters injected into HTTP response headers allow insertion of arbitrary `Set-Cookie` headers. Attacker can specify cookie name, value, and most attributes, though UA policies impose limits (e.g., non-secure context cannot set `Secure` flag, invalid `Domain` values are rejected). | CRLF injection in any response header (Location, custom headers) |
| **XSS → document.cookie** | Client-side script execution allows reading and writing non-HttpOnly cookies. This is the most direct cookie manipulation primitive — any XSS becomes a cookie manipulation vector. | XSS vulnerability; cookies lack HttpOnly flag |

---

## §5. Cookie Jar State Management

Browsers maintain a cookie jar with per-domain storage limits. Attacks manipulate the jar's state — creation, ordering, eviction — rather than individual cookie values.

### §5-1. Cookie Jar Overflow / Eviction

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cookie Jar Overflow** | Browsers enforce per-domain cookie limits (typically ~50-180 cookies per schemeful site in Chrome/Firefox; WebKit/Safari does not document a comparable strict per-site count limit, instead relying on overall jar caps and ITP-driven eviction — including the 7-day script-writable-storage purge and 30-day inactive-domain purge). Setting many new cookies forces eviction of existing cookies (oldest-first or LRU). An attacker sets enough cookies to evict a legitimate cookie, then replaces it with a malicious one. Safari's different eviction model changes the timing and reliability of count-based overflow but does not categorically prevent eviction-based attacks. | Attacker can set cookies (subdomain XSS, cookie tossing); target cookie is evictable; per-browser eviction model differs |
| **HttpOnly Cookie Deletion via Overflow** | Since JavaScript-set cookies and server-set HttpOnly cookies share the same jar, flooding the jar with JavaScript cookies can evict HttpOnly cookies. The attacker then replaces the evicted cookie with a non-HttpOnly version they control. | JavaScript execution context; shared cookie jar limits |
| **Cookie Bomb (Denial of Service)** | Attacker sets maximum-size cookies (4KB each × multiple cookies) scoped to the target domain. The victim's browser sends oversized Cookie headers (>8KB) that the server rejects — the RFC-appropriate status code is 431 Request Header Fields Too Large (RFC 6585), though real-world servers vary: Nginx returns 400, Apache/IIS may use 431, and some servers drop the connection entirely (RFC 6585 §5 explicitly permits this). The victim is locked out until cookies are manually cleared — potentially for the cookie's max lifetime (Chrome caps expiry at 400 days since v104). | Attacker can set cookies for target domain; no server-side size mitigation |

### §5-2. Cookie Tossing

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Subdomain Cookie Tossing** | Attacker on `evil.example.com` sets a cookie with the same name as a cookie on `app.example.com` but scoped to `.example.com`. The browser sends both cookies; server behavior on duplicate names is implementation-dependent: first-wins (Tomcat, Express) vs last-wins (Django, PHP). The attacker must tailor the attack to the target's resolution strategy. | Attacker controls subdomain; target uses unprotected cookie names (no `__Host-` prefix); server duplicate-name resolution varies |
| **OAuth Flow Hijacking via Tossing** | Cookie tossing replaces CSRF tokens, state parameters, or session cookies during OAuth flows. The attacker's session cookie is sent alongside the legitimate one, causing the application to bind the OAuth token to the attacker's session. | OAuth flow uses cookies for state management; no `__Host-` prefix |
| **Self-XSS Amplification** | Cookie tossing forces a victim to use the attacker's session cookie. If a self-XSS exists that triggers on the logged-in user's own content, the victim now executes the XSS payload the attacker placed in "their" account. | Self-XSS vulnerability; cookie tossing primitive |
| **DOM-Based Open Redirect via Cookie Value** | Application JavaScript reads a cookie value and uses it in a navigation sink (e.g., `document.location=\`/${lang}/reissue?cid=${id}\``). An attacker tosses `lang=/evil.com` via subdomain cookie injection; the template literal produces `//evil.com/reissue?cid=...` — a protocol-relative URL that redirects to `evil.com`. The cookie becomes a DOM source feeding an open redirect sink, converting cookie tossing into a navigation hijack without any server-side vulnerability. | Application reads cookie value in client-side JavaScript and uses it in `location`, `window.open()`, or similar navigation sink; attacker can toss cookies via subdomain |

### §5-3. Cookie Jar Desynchronization

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Browser Cookie Jar Inconsistency** | Firefox-specific: the in-memory cookie jar and persistent cookie storage can become desynchronized under certain conditions (e.g., CVE-2023-4055, where cookie jar overflow caused the cookie jar state to become inconsistent — requests could be sent with some cookies missing entirely). The exact manifestation varies by trigger condition, rather than a single predictable pattern. A distinct variant: when Firefox's jar overflows beyond the 180-per-site limit via `document.cookie`, excess cookies become "ghost" entries — visible through the `Document.cookie` API but NOT attached to HTTP requests. These ghost cookies survive page reloads, same-site navigations, and new windows (removable only by setting past expiration via JavaScript or closing the tab). Applications whose frontends read state from `Document.cookie` (e.g., ASP.NET and Angular set custom headers from cookie values for CSRF) may operate on stale or attacker-controlled data that the server never receives, creating a client-server state mismatch. Root cause traced to Site Isolation (Project Fission) composition with cookie storage. | Firefox browser; cookie jar overflow or edge-case storage conditions |
| **Cookie Ordering Ambiguity** | When multiple cookies with the same name exist (different Path/Domain), the order in which browsers send them is loosely specified. RFC 6265bis §5.5 specifies the sort as longer-path-first (primary) with earlier-creation-time as the tiebreaker; Chrome and Firefox follow this, while Safari historically diverges (creation-time-descending observed in some builds). Servers that read only the first value may get the attacker's cookie instead of the legitimate one, and cookie shadowing attacks must be tailored to the target browser's ordering behavior. | Multiple same-name cookies; server reads first occurrence; browser-specific ordering |

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
| **Response Splitting → Cookie Setting** | HTTP response splitting via CRLF injection in headers allows injecting complete `Set-Cookie` response headers, giving the attacker control over most cookie attributes (subject to UA policy constraints such as `Domain` validation and `Secure` context requirements). | CRLF vulnerability in response header generation |
| **Request Header Injection** | Injecting into the request `Cookie:` header via HTTP header injection (in proxies, intermediaries, or client-side) allows adding or overwriting cookies the server receives. | Header injection in upstream proxy or client |

### §6-3. Cache-Mediated Cookie Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Web Cache Poisoning via Unkeyed Cookies** | If a cache server doesn't include `Cookie` in the cache key but the origin server varies the response based on cookie values, an attacker can poison the cache with a response generated for their malicious cookie, served to all users. | Cache doesn't key on Cookie; origin varies response on cookie |
| **Cache Deception → Authenticated Data Exposure** | Tricking a cache into storing an authenticated response (whose content was determined by the victim's session cookie) under a publicly cacheable URL. Subsequent requestors access the victim's private data. Note: the cookie itself is not cached — the cookie-authenticated *response content* is what gets exposed. | Cache serves dynamic content as static; authenticated data in response body |

---

## §7. Cookie Storage & Client-Side Protection Bypass

Attacks targeting how browsers store and protect cookies at rest on the client machine.

### §7-1. Browser Cookie Storage Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SQLite Cookie Database Extraction** | Browsers store cookies in SQLite databases (e.g., Chrome's `Cookies` file, Firefox's `cookies.sqlite`). Malware or local access reads these files directly. | Local system access; file not locked or encryption bypassed |
| **Chrome AppBound Encryption Bypass (C4 Bomb)** | Chrome's AppBound Cookie Encryption (introduced July 2024) uses dual-layer DPAPI encryption. The C4 (Chrome Cookie Cipher Cracker) attack exploits a CBC padding oracle via Chrome's elevation service, allowing low-privileged attackers to decrypt cookie blobs. Public PoC notes speed and environment constraints; Chrome has issued partial mitigations. | Chrome on Windows; elevation service accessible; padding oracle in CBC mode |
| **DPAPI Credential Access** | Pre-AppBound Chrome encryption and other Chromium browsers use Windows DPAPI with user-scope keys. Any process running as the same user can decrypt cookies. | Same-user process access; Windows DPAPI |
| **macOS Keychain Extraction** | On macOS, Chrome's cookie encryption key is stored in the Keychain. Malware with user-level permissions can request it (with a UI prompt that can be socially engineered or suppressed). | macOS; user-level access |

### §7-2. Infostealer & Malware-Based Cookie Theft

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Infostealer Malware Harvesting** | Families like Lumma, StealC, RedLine, Raccoon systematically extract cookies from all installed browsers. Vendor telemetry reports estimated 17+ billion cookies exposed in 2024 stealer logs (note: this figure from aggregated dark web monitoring likely includes duplicates and re-collected entries across multiple datasets). Stolen cookies are sold on dark markets or used directly for account takeover. | Endpoint compromised by infostealer; cookies not bound to device |
| **Cookie-Bite (Malicious Browser Extension)** | A Chrome extension monitors Microsoft login URLs and exfiltrates `ESTSAUTH` and `ESTSAUTHPERSISTENT` Azure Entra ID tokens. These tokens bypass MFA and can provide access to Microsoft 365, Teams, Outlook for up to 90 days (per Varonis PoC; actual persistence depends on target organization's session policies, Continuous Access Evaluation, and conditional access configuration). | Malicious extension installed; targets Azure Entra ID sessions |
| **Process Memory Extraction** | Reading browser process memory to extract decrypted cookies before they are written to encrypted storage. Bypasses all at-rest encryption protections. | Sufficient privileges to read browser process memory |

### §7-3. Cookie Replay & Session Abuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Session Cookie Replay** | Stolen session cookies are replayed from a different device/location. Since the cookie represents a completed authentication (including MFA), the server accepts it without re-authentication. | No device binding; no session fingerprinting; cookie not expired |
| **Pass-the-Cookie** | Enterprise variant of cookie replay: attackers use stolen cloud session tokens (Azure, AWS, GCP) to access cloud resources. Increasingly observed as a major post-compromise technique in 2024-2025 incident reports, often preferred over password-based lateral movement due to MFA bypass capability. | Cloud session cookies; no token binding or continuous access evaluation |
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
| **CORF Token Fixation** | Cross-Origin Request Forgery (CORF) token fixation exploits the composition of cookie tossing (§5-2) with CSRF synchronizer token pattern implementations. **Pre-login variant**: the attacker obtains a pre-session cookie and its CSRF token, then fixates the victim's pre-session cookie via cookie tossing; when the victim logs in, the CSRF secret persists into the authenticated session (most frameworks do not refresh it), allowing the attacker to forge CSRF-protected requests. **Post-login variant**: against the Double Submit Pattern, the attacker overwrites the CSRF cookie via tossing and submits a matching token value. 7 of 13 major frameworks were vulnerable to pre-login CORF; all 6 frameworks implementing DSP were vulnerable to post-login CORF (Cookie Crumbles, USENIX Security 2023). | Framework uses synchronizer token pattern without refreshing CSRF secret on login; or uses Double Submit Pattern without `__Host-` prefix on CSRF cookie |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Condition | Primary Mutation Categories |
|---|---|---|
| **Session Hijacking** | Any cookie theft vector + session replay | §7-2 + §7-3 + §6-1 |
| **CSRF** | Cross-site request with victim's cookies; Double Submit Pattern defeated by cookie tossing | §1-1 (SameSite bypass) + §3-2 + §5-2 (cookie tossing defeats DSP) + §8-2 (CORF token fixation) |
| **XSS Amplification** | XSS + cookie manipulation | §1-2 (HttpOnly bypass) + §5-2 (tossing for Self-XSS) |
| **MFA Bypass** | Stolen post-MFA session token replayed | §7-2 (Cookie-Bite) + §7-3 (Pass-the-Cookie) |
| **Denial of Service** | Cookie bomb locks out user | §5-1 (Cookie Bomb) |
| **WAF Bypass** | Payload hidden in legacy cookie encoding | §2-1 ($Version) + §2-3 (encoding) |
| **Cache Poisoning** | Cookie-varied response cached without cookie key | §6-3 |
| **Privilege Escalation** | Cookie value tampering or session puzzle | §4-2 + §8-2 |
| **Account Takeover** | Session fixation + victim login | §8-1 + §5-2 |
| **OAuth Hijacking** | Cookie tossing replaces OAuth state | §5-2 + §8-1 |
| **Cookie Sandwich Chain** | XSS (even limited: `<meta>`/`<link>` reflection) → inject `$Version=1,session="` + `a=b"` cookies → cookie sandwich absorbs HttpOnly session token → CORS request to tracking/API subdomain exfiltrates absorbed value in JSON response | §1-2 + §2-1 + §2-2 + §1-2 (CORS) |
| **Backend Protocol Injection** | Cookie octal encoding → CRLF injection into Memcached/Redis protocol → arbitrary cache commands → pickle/serialized object insertion → deserialization RCE | §2-1 (octal) + §4-1 (deserialization) |
| **DOM Navigation Hijack** | Cookie tossing overwrites navigation-relevant cookie → DOM-based open redirect → phishing or token theft via controlled landing page | §5-2 (DOM-based redirect) |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §2-3 (Out-of-bounds chars) | CVE-2024-47764 (npm `cookie`) | Cookie field tampering via name/path/domain injection (XSS as possible secondary impact) |
| §3-1 (PSL bypass) | CVE-2023-46218 (curl) | Mixed-case domain comparison flaw allows cookies to be sent to unintended domains in curl-based clients |
| §7-1 (AppBound bypass) | C4 Bomb (Chrome, reported Dec 2024) | Low-privilege decryption of all Chrome AppBound-encrypted cookies |
| §5-2 (Cookie tossing) | CVE-2024-21583 (Gitpod) | Session hijacking via cookie tossing in Gitpod protocol |
| §4-1 (Deserialization) | CVE-2017-9822 + 4 bypass CVEs (DotNetNuke) | RCE via DNNPersonalization cookie deserialization |
| §1-3 + §2-1 (Prefix bypass via $Version) | PortSwigger Cookie Chaos (2025) | __Host-/__Secure- prefix bypass on Java servers |
| §1-2 + §2-2 (Cookie sandwich) | PortSwigger Cookie Sandwich (Jan 2025) | HttpOnly flag bypass; session token theft |
| §2-1 + §2-3 (WAF bypass via phantom cookie) | PortSwigger $Version WAF Bypass (Dec 2024, updated Jun 2025) | WAF rule evasion using legacy RFC 2109 encoding |
| §1-3 (Nameless cookie collision) | CVE-2022-2860 (Chrome v104), CVE-2022-40958 (Firefox v105) | __Host- prefix bypass via nameless cookie serialization collision (Cookie Crumbles, USENIX Sec 2023) |
| §1-3 (PHP name normalization) | CVE-2022-31629 (PHP 7.4.31/8.0.24/8.1.11) | __Host- bypass via `$_COOKIE` key character normalization (Cookie Crumbles, 2023) |
| §2-3 (Cookie name percent-decoding) | CVE-2022-36032 (ReactPHP HTTP v1.7.0) | __Host- bypass via url-decoded cookie names (Cookie Crumbles, 2023) |
| §2-2 (Leading-equals stripping) | CVE-2023-23934 (Werkzeug 2.2.3) | __Host- bypass via nameless cookie + leading `=` stripping (Cookie Crumbles, 2023) |
| §8-2 (CORF token fixation) | CVE-2022-24895 (Symfony), CVE-2022-25896 (Passport), CVE-2023-29020 (Fastify), CVE-2022-35943 (Shield/CI4), CVE-2023-27495 (CI4 Shield) | CSRF bypass via pre-login CORF in synchronizer token pattern (7 of 12 STP frameworks vulnerable) and post-login CORF in double-submit pattern (all 6 DSP frameworks vulnerable) (Cookie Crumbles, USENIX Sec 2023). Note: CVE-2023-29019 is a separate @fastify/passport session fixation issue. |
| §7-2 (Extension-based theft) | Cookie-Bite PoC (Varonis, Apr 2025) | Azure Entra ID MFA bypass; up to 90-day M365 access (session policy dependent) |
| §4-2 + §8-1 (CORS + cookie misconfiguration) | CVE-2025-34291 (Langflow) | Account takeover via permissive CORS (`Access-Control-Allow-Credentials: true` + reflected origin) combined with `SameSite=None` refresh-token cookie and missing CSRF protection on the refresh endpoint; JWT is the token format but the core flaw is cross-origin cookie relay |
| §7-2 (Infostealer) | Lumma Stealer takedown (May 2025) | Large Windows infection footprint; many domains taken down or redirected to Microsoft sinkhole |

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
| **PortSwigger Bambdas** ([GitHub](https://github.com/PortSwigger/bambdas)) | Cookie prefix bypass + injection | Two Custom Actions: **Cookies Prefix Bypass** (detects RFC 6265bis prefix bypass via Unicode/legacy parsing) and **Cookie Injection** (detects if user-controlled parameters can override server-set cookies) |

### Cookie Parser Discrepancy Discovery Methodology

Systematic approach for identifying exploitable cookie parsing differentials (per Zack, Cookie Chaos / Cookie Crumbles research):

1. **Observe** — Identify cookie values that are reflected (variable) vs static (constant) in server responses. Reflected values indicate the server parses and re-emits cookie content, creating potential injection sinks.
2. **Encode** — Inject legacy RFC markers: set `$Version=1` cookie, wrap values in quotes (`name="value"`), insert comma separators. Test octal escapes (`\NNN`) and Unicode whitespace prefixes.
3. **Observe** — Check if the injected value **disappears** (server parsed and stripped it — confirms legacy parsing is active) or is **reflected as-is** (server doesn't parse legacy syntax — this path is not exploitable via this vector).
4. **Exploit** — If legacy parsing is confirmed, chain with cookie sandwich, prefix bypass, WAF evasion, or backend protocol injection depending on the target architecture. Automate via Burp's `handleHttpRequestToBeSent` extension point.

---

## References

- [PortSwigger Research — Cookie Chaos: How to bypass __Host and __Secure cookie prefixes](https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes)
- [PortSwigger Research — Stealing HttpOnly cookies with the cookie sandwich technique](https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique)
- [PortSwigger Research — Bypassing WAFs with the phantom $Version cookie](https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie)
- [PortSwigger — Bypassing SameSite cookie restrictions](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
- [USENIX Security 2023 — Cookie Crumbles: Breaking and Fixing Web Session Integrity](https://www.usenix.org/conference/usenixsecurity23/presentation/squarcina)
- [Varonis — Cookie-Bite: How Your Digital Crumbs Let Threat Actors Bypass MFA](https://www.varonis.com/blog/cookie-bite)
- [CyberArk — C4 Bomb: Blowing Up Chrome's AppBound Cookie Encryption](https://www.cyberark.com/resources/threat-research-blog/c4-bomb-blowing-up-chromes-appbound-cookie-encryption)
- [Snyk Labs — Hijacking OAuth flows via Cookie Tossing](https://labs.snyk.io/resources/hijacking-oauth-flows-via-cookie-tossing/)
- [Thomas Houhou — Cookie Tossing: Self-XSS Exploitation, Multi-Step Process Hijacking, and Targeted Action Poisoning](https://www.thomashouhou.com/post/cookie-tossing-attacks/)
- [Ankur Sundara — Cookie Bugs: Smuggling & Injection](https://blog.ankursundara.com/cookie-bugs/)
- [HackTricks — Cookies Hacking](https://book.hacktricks.wiki/en/pentesting-web/hacking-with-cookies/index.html)
- [HackTricks — Cookie Bomb](https://book.hacktricks.xyz/pentesting-web/hacking-with-cookies/cookie-bomb)
- [HackTricks — Cookie Jar Overflow](https://book.hacktricks.xyz/pentesting-web/hacking-with-cookies/cookie-jar-overflow)
- [GitHub Advisory — CVE-2024-47764: cookie package out-of-bounds characters](https://github.com/advisories/GHSA-pxg6-pf52-xh8x)
- [Cobalt — Got Cookies? Cookie Based Authentication Vulnerabilities in the Wild](https://www.cobalt.io/blog/got-cookies-cookie-based-authentication-vulnerabilities-in-wild)
- [DeepStrike — Stealer Log Statistics 2025](https://deepstrike.io/blog/stealer-log-statistics-2025)
- [HP Wolf Security — Tracing the Rise of Breaches Involving Session Cookie Theft](https://threatresearch.ext.hp.com/tracing-the-rise-of-breaches-involving-session-cookie-theft/)
- [jub0bs.com — The great SameSite confusion](https://jub0bs.com/posts/2021-01-29-great-samesite-confusion/)
- [0xn3va — Cookie Tossing Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/web-application/cookie-security/cookie-tossing)
- [OWASP — Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
- Zack — Cookie Chaos: Exploiting Cookie Parser Discrepancies (conference talk, 2025) — Octal encoding → Memcached injection, Safari Set-Cookie comma splitting, browser attribute injection, Pylibmc RCE chain, Observe→Encode→Observe→Exploit methodology
