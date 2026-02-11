# URL Confusion Mutation/Variation Taxonomy

> A comprehensive, generalized taxonomy of URL Confusion attack primitives — organized by structural mutation target, discrepancy type, and weaponization scenario.

---

## Classification Structure

URL Confusion encompasses all attacks that exploit **discrepancies in how different components parse, interpret, or normalize URLs**. The fundamental insight is that there is no single "URL parser" — browsers, proxies, caches, WAFs, application frameworks, and standard libraries each implement their own parsing logic, often referencing different specifications (RFC 3986, WHATWG URL Standard, or ad-hoc behavior). When two components in a request pipeline disagree about the meaning of a URL, a security boundary is violated.

This taxonomy is organized along three axes:

**Axis 1 — Mutation Target (Primary Structure):** The structural component of the URL being manipulated. This is the main organizing principle — each top-level section (§1–§9) targets a different URL component.

**Axis 2 — Discrepancy Type (Cross-Cutting):** The nature of the parsing disagreement that makes the mutation exploitable:

| Discrepancy Type | Description |
|---|---|
| **Standard Differential** | RFC 3986 vs. WHATWG URL Standard vs. ad-hoc behavior |
| **Parser-to-Parser** | Validation parser vs. fetch/request parser (same application) |
| **Hop-to-Hop** | Proxy vs. origin, cache vs. origin, WAF vs. backend |
| **Client-to-Server** | Browser interpretation vs. server interpretation |
| **Encoding/Normalization** | Disagreement on when/how to decode or normalize |
| **Temporal (TOCTOU)** | Resolution changes between check time and use time |

**Axis 3 — Attack Scenario (Mapping):** Where the mutation is weaponized — SSRF, Open Redirect, Cache Poisoning/Deception, WAF Bypass, ACL/Auth Bypass, XSS, CORS Bypass, or Phishing.

### URL Structure Reference

```
  scheme://userinfo@host:port/path?query#fragment
  \______/ \______/ \__/ \__/\___/ \___/ \______/
     |        |      |    |    |     |      |
   §1       §3     §4   §4  §5    §6     §7
                    §2 (Authority as a whole)
```

Additional cross-cutting categories: §8 (Encoding Differentials), §9 (DNS Resolution / TOCTOU).

---

## §1. Scheme Confusion

Mutations targeting the URL scheme component to bypass validation or trigger unintended protocol handling.

### §1-1. Scheme Case and Whitespace Injection

URL schemes are case-insensitive per RFC 3986, but some validators perform case-sensitive comparison. Additionally, certain parsers tolerate leading/trailing whitespace or control characters around the scheme.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Case Variation** | Validator checks `http://` literally; parser normalizes `HTTP://` or `hTtP://` | `HTTP://evil.com`, `hTtP://evil.com` | Case-sensitive scheme allowlist |
| **Leading Whitespace** | Some parsers strip leading spaces/tabs/newlines before scheme extraction | `\t\nhttp://evil.com` | Parser tolerates whitespace prefix |
| **Null Byte Injection** | Null byte terminates scheme matching in one parser but not another | `http\x00s://evil.com` | C-based string termination vs. length-based parsing |

### §1-2. Scheme Substitution and Protocol Confusion

Replacing `http(s)` with alternative schemes to escape protocol-specific validation or trigger unexpected handlers.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **file:// Protocol** | Bypass HTTP-only validation to read local files via `file://` | `file:///etc/passwd`, `file://localhost/c:/windows/` | Server-side URL fetcher accepts `file://` |
| **gopher:// Protocol** | Craft arbitrary TCP payloads to internal services | `gopher://127.0.0.1:6379/_*1%0d%0a...` | Fetcher library supports `gopher://` (e.g., older curl/libcurl) |
| **dict:// Protocol** | Interact with dict protocol to probe ports or send commands | `dict://127.0.0.1:6379/INFO` | Fetcher supports `dict://` |
| **data: URI** | Embed inline content, bypassing same-origin checks or exfiltrating data | `data:text/html,<script>...</script>` | Data URIs accepted where only HTTP expected |
| **blob: URI** | Browser-local object URL that bypasses network-based security filters | `blob:https://target.com/uuid` | Client-side context; content generated in-browser |
| **javascript: URI** | Execute script via scheme in contexts expecting navigable URL | `javascript:alert(1)` | Input rendered as href/src without scheme validation |

### §1-3. Schemeless and Relative URL Confusion

Omitting the scheme to cause parser disagreement about whether the URL is absolute or relative, and which component is the authority.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Protocol-Relative URL** | `//evil.com` parsed as authority by browser, potentially as path by server | `//evil.com/path` | Server-side validation treats `//` as path |
| **Scheme Omission** | Missing scheme causes fallback behavior: some parsers prepend `http://`, others treat entire URL as path | `evil.com/path` | Different default scheme assumptions |
| **Colon-Scheme Confusion** | Colon in unusual positions tricks parser about scheme boundary | `http:evil.com`, `localhost:@evil.com` | Parser treats pre-colon text as scheme incorrectly |

---

## §2. Authority Component Confusion

Attacks exploiting ambiguity in the authority section (`userinfo@host:port`) as a whole, particularly the boundaries between subcomponents.

### §2-1. Userinfo (@) Exploitation

The `@` character separates optional userinfo from the host. Most modern systems ignore userinfo, but validators may not parse it correctly.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Basic @ Trick** | Validator sees `trusted.com` in URL prefix; browser/fetcher navigates to `evil.com` | `https://trusted.com@evil.com/path` | startsWith/contains-based validation |
| **Encoded @ Bypass** | URL-encoding the `@` (`%40`) confuses validators that check for literal `@` | `https://trusted.com%40evil.com/path` | Validator doesn't decode before parsing |
| **Multi-@ Ambiguity** | Multiple `@` signs create disagreement about which marks the host boundary | `https://a@b@evil.com/` | Parsers differ on first-@ vs. last-@ rule |
| **Userinfo with Credentials** | Stuffing credentials into userinfo to bypass length or content checks | `https://user:password@evil.com/` | Validator doesn't strip userinfo |
| **Colon-@ Combination** | `localhost:\@evil.com` — colon interpreted as port separator by validator, but `:\` treated as path or ignored by fetcher | `http://localhost:\@evil.com/` | Parser differential on colon placement (CVE-2025-0454) |

### §2-2. Authority Boundary Confusion

Attacks that confuse where the authority ends and the path begins.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Triple+ Slash** | Extra slashes after scheme confuse authority extraction | `http:///evil.com/path` | Parser disagrees on empty authority vs. path start |
| **Backslash as Authority Terminator** | WHATWG treats `\` as equivalent to `/` for ending authority; RFC 3986 does not | `http://evil.com\@trusted.com/` | Validation uses RFC 3986, fetcher uses WHATWG (§8-1) |
| **Tab/Newline in Authority** | WHATWG strips tabs and newlines from URLs; RFC 3986 does not | `http://evil\t.com/` | WHATWG-compliant parser vs. strict RFC parser |

---

## §3. Host Confusion

Mutations targeting the hostname/IP portion to bypass allowlist/blocklist validation while still resolving to the attacker's desired target.

### §3-1. IP Address Representation Obfuscation

IP addresses can be represented in numerous equivalent forms. Validators checking for `127.0.0.1` or `169.254.169.254` as literal strings miss alternative representations.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Decimal (DWORD)** | Single 32-bit integer representation of IPv4 | `http://2130706433` (= 127.0.0.1) | String-matching blocklist |
| **Octal** | Octets expressed in base-8 with leading zero | `http://0177.0.0.01` (= 127.0.0.1) | Blocklist doesn't handle octal |
| **Hexadecimal** | Octets expressed in base-16 | `http://0x7f.0x0.0x0.0x1`, `http://0x7f000001` | Blocklist doesn't handle hex |
| **Mixed Notation** | Combining decimal, octal, and hex in same address | `http://0x7f.0.0.01` | Parser normalizes; validator doesn't |
| **Overflow/Truncation** | Using values > 255 that wrap around (e.g., `256` → `0` in some parsers) | `http://127.0.0.256` → parsed as `127.0.0.0` in some implementations | Implementation-specific overflow behavior |
| **IPv6 Full Form** | Uncompressed IPv6 with leading zeros | `http://[0:0:0:0:0:0:0:1]` (= ::1 = localhost) | IPv6 blocklist incomplete |
| **IPv6 Compressed** | `::` zero compression creates multiple equivalent representations | `http://[::1]`, `http://[0::1]` | Strict string matching on IPv6 |
| **IPv4-Mapped IPv6** | IPv4 embedded within IPv6 notation | `http://[::ffff:127.0.0.1]` | Only IPv4 blocklist; no IPv6 mapping check |
| **IPv6 Zone ID** | Zone identifier (`%25`) appended to IPv6 address per RFC 6874 | `http://[fe80::1%25eth0]` | Parser accepts zone ID; validator can't parse it |
| **Dotless Decimal** | Certain parsers accept IP without dots as single integer | `http://2130706433/` | Browser-specific behavior |

### §3-2. Hostname Equivalence Bypass

Techniques that make a hostname resolve to the target while appearing different to string-based validators.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **localhost Aliases** | OS-level aliases for loopback that bypass string checks | `http://127.1`, `http://127.0.1`, `http://0`, `http://0.0.0.0` | Incomplete localhost blocklist |
| **Subdomain on Attacker Domain** | DNS A record pointing to internal IP via attacker-controlled subdomain | `http://169.254.169.254.evil.com` → points to 169.254.169.254 | Validator checks suffix/contains, not resolution |
| **Wildcard DNS Services** | Services like `nip.io`, `sslip.io` that resolve embedded IP addresses | `http://127.0.0.1.nip.io` | No DNS resolution during validation |
| **Unicode/IDN Homograph** | Visually identical Unicode characters in hostname (Punycode conversion) | `https://аpple.com` (Cyrillic 'а') → `xn--pple-43d.com` | Human trust; email/document phishing |
| **Case Sensitivity** | Hostnames are case-insensitive but some validators compare case-sensitively | `HTTP://LOCALHOST/` | Case-sensitive string matching |
| **Trailing Dot** | FQDN trailing dot (`example.com.`) is equivalent but distinct as string | `http://127.0.0.1./` | Validator uses exact string match |

### §3-3. Bracket and Special Character Confusion

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Square Bracket in Hostname** | Python's `urllib` (CVE-2025-0938) accepts brackets in non-IPv6 contexts, causing parser differential | `http://[evil.com]/` | Python urllib vs. spec-compliant parsers |
| **Enclosed Alphanumerics** | Unicode enclosed characters (e.g., `①②③`) that visually resemble digits | Hostname with enclosed numerics | Implementation-specific Unicode handling |

---

## §4. Port Confusion

Manipulating the port component to bypass validation or redirect traffic.

### §4-1. Port Parsing Differential

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Non-Standard Port Delimiter** | Some parsers accept port after hostname even without colon in edge cases | `http://evil.com 80/` | Whitespace-tolerant parser |
| **Port Overflow** | Port numbers exceeding 65535 may wrap or be truncated | `http://evil.com:65537/` → port 1 | Integer overflow in port parsing |
| **Port with Leading Zeros** | Octal interpretation of port number | `http://evil.com:080/` | Parser interprets leading-zero port as octal |
| **Empty Port** | Explicit colon with no port number (`http://host:/path`) resolves to default port but may confuse validators | `http://evil.com:/path` | Validator expects port number after colon |
| **Port-as-Userinfo** | Port position used to inject userinfo boundary | `http://trusted.com:80@evil.com/` | Validator extracts host:port before parsing `@` |

---

## §5. Path Confusion

The richest mutation space — discrepancies in how paths are parsed, normalized, and matched between proxies, caches, WAFs, and application servers.

### §5-1. Dot-Segment Traversal Differential

Path traversal via `..` and `.` segments, where different components apply normalization at different times.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Classic Dot-Segment** | `../` traversal resolved by server but not by proxy/cache for key computation | `/static/../admin/secret` | Proxy caches pre-normalization key; origin normalizes |
| **Encoded Dot-Segment** | `%2e%2e/%2e%2e/` bypasses literal `../` checks but is decoded by the origin | `/%2e%2e/admin/secret` | WAF/proxy doesn't decode; origin does |
| **Double-Encoded Dot-Segment** | `%252e%252e/` decoded once by proxy (→ `%2e%2e/`) and again by origin (→ `../`) | `/%252e%252e/etc/passwd` | Multi-layer decoding |
| **Overlong UTF-8 Dot** | Non-shortest UTF-8 encoding of `.` (e.g., `%c0%ae`) decoded by some parsers | `%c0%ae%c0%ae/etc/passwd` | Legacy parser decodes overlong sequences |
| **Mixed Separator Traversal** | Combining `/` and `\` in traversal on Windows systems | `/..\/..\/windows/` | Windows path handling + URL parsing |

### §5-2. Path Delimiter Confusion

Different HTTP servers and frameworks use different characters as path delimiters, creating discrepancies between cache/proxy and origin.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Semicolon Delimiter (Java/Spring)** | Semicolons denote matrix parameters in Java frameworks; stripped by framework but included in cache key | `/admin/panel;.css` | Cache sees `.css` extension → caches; origin sees `/admin/panel` |
| **Question Mark in Path** | `?` terminates the path component; but mod_proxy may forward it as part of filename | `/cgi-bin%3f.php` | Apache mod_proxy filename confusion (CVE-2024-38475) |
| **Hash/Fragment in Server Path** | Server-side parsers may interpret `#` differently from clients (clients never send fragment) | URL validated with `#` to truncate the visible host | Validation parser processes fragment; fetcher ignores it |
| **Null Byte Truncation** | `%00` terminates path in C-based parsers but not in higher-level languages | `/admin/secret%00.jpg` | C-based server truncates; app framework doesn't |
| **Newline/CR Injection** | `%0a` or `%0d` in path causes header injection or path truncation | `/path%0d%0aHeader: injected` | Incomplete input sanitization |

### §5-3. Path Normalization Differential

Discrepancies in how servers normalize equivalent path representations.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Trailing Slash Semantics** | `/admin` vs. `/admin/` treated differently by proxy and origin | `/admin` → 301 redirect vs. direct serve | Cache key includes/excludes trailing slash |
| **Double Slash Collapsing** | `//admin` normalized to `/admin` by some servers but not others | `//admin/secret` | Proxy preserves `//`; origin collapses |
| **Case Sensitivity** | Linux paths are case-sensitive; Windows/macOS are not; CDN keys may normalize case | `/Admin` vs. `/admin` | Cross-OS deployment or case-normalizing CDN |
| **URL Encoding of Path Characters** | `/path` vs. `/%70%61%74%68` — semantically identical but different as cache keys | `/%61%64%6d%69%6e` (= `/admin`) | Cache doesn't decode key; origin does |
| **Backslash in Path** | `\` treated as `/` by WHATWG but as literal character by RFC 3986 | `http://target.com/admin\..\secret` | Windows IIS + WHATWG-aware client |

### §5-4. Framework-Specific Path Interpretation

Application frameworks impose their own path parsing rules, creating discrepancies with upstream proxies and caches.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Spring Matrix Variable (;)** | Spring strips everything after `;` in path segments as matrix parameters | `/admin;jsessionid=x` → routes to `/admin` | Proxy/cache includes `;...` in key |
| **Rails Format Extension (.)** | Rails interprets `.json`, `.xml` etc. as format specifiers | `/users/1.json` → same controller, JSON response | Cache keys on full path; Rails routes differently |
| **Express.js Path Regex** | Express uses path-to-regexp with parameter patterns | `/users/:id` matching `//users/1` differently | Double-slash handling in route matching |
| **Apache mod_rewrite Confusion** | `r->filename` treated as URL by mod_proxy but as filesystem path by other modules | Crafted path that's valid URL and filesystem path | Apache Confusion Attacks: filename vs. URL interpretation |
| **DocumentRoot Escape** | Apache's DocumentRoot resolution allows path confusion to escape to system root | `/cgi-bin` + traversal → system-level path | Apache DocumentRoot Confusion (CVE-2024-38475) |
| **Handler Confusion** | Overwriting Apache handlers via AddType/AddHandler interaction | `.php.jpg` handled as PHP despite extension | Apache Handler Confusion |

### §5-5. Cache Key vs. Origin Path Discrepancy

The cache computes a key from the URL that differs from how the origin interprets the same URL, enabling cache poisoning or deception.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Static Extension Append** | Appending `.css`, `.js`, `.jpg` to dynamic endpoint tricks cache into storing response | `/account/settings.css` → origin serves `/account/settings`; cache stores as static | Path delimiter confusion (§5-2) between cache and origin |
| **Path Parameter Pollution** | Adding cache-friendly suffix via path parameters | `/api/me;x=1.js` → cache keys on `.js`; origin ignores `;x=1.js` | Java framework + CDN |
| **Dot-Segment Cache Key Mismatch** | Cache doesn't normalize dot-segments in key but origin does | `/static/../secret` → cache key includes `../`; origin serves `/secret` | CDN preserves dot-segments in key |
| **Encoded Path Cache Mismatch** | Cache key includes URL-encoded characters; origin decodes | `/%61dmin` cached separately from `/admin` but origin treats identically | CDN doesn't normalize encoding |

---

## §6. Query String Confusion

Mutations targeting the query component to alter request routing, bypass validation, or poison caches.

### §6-1. Query Delimiter Differential

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Semicolon vs. Ampersand** | Some frameworks accept `;` as query parameter delimiter; others only `&` | `?admin=false;admin=true` | WAF parses with `&` only; framework accepts `;` |
| **Duplicate Parameter (HPP)** | Multiple identical parameter names resolved differently (first/last/all) | `?role=user&role=admin` | Proxy uses first value; app uses last value |
| **Query String Presence in Cache Key** | Cache excludes query from key; origin uses query for routing | `/api/data?user=victim` cached for all users | CDN strips query from cache key |
| **Encoded Delimiters** | Encoding `&` as `%26` or `=` as `%3d` creates parameter injection | `?param=value%26admin%3dtrue` | Decoded after initial parameter parsing |

### §6-2. Query-Path Boundary Confusion

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Encoded Question Mark in Path** | `%3f` in path decoded to `?` shifts boundary between path and query | `/search%3fq=injection/file.js` | Cache sees path `/search?q=injection/file.js`; origin may differ |
| **Fragment Masquerading as Query** | Hash `#` inserted before query to truncate query in certain parser contexts | `http://target.com/path#?admin=true` | Parser treats `#` as fragment start; downstream doesn't |

---

## §7. Fragment Confusion

The fragment (`#`) component is client-side only per HTTP specification — servers should never see it. But URL parsers that process full URLs may disagree.

### §7-1. Fragment-Authority Interaction

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Fragment Truncation for Authority Swap** | Fragment `#` in validation URL hides the real authority from one parser | `http://evil.com#@trusted.com/` → parser A sees host `trusted.com`, parser B sees host `evil.com` | Validation parser extracts authority after `#@`; fetcher ignores fragment |
| **Fragment in Server-Side URL** | Server-side URL parser includes fragment in routing decision, unlike HTTP spec | `http://internal.host/api#.evil.com` | JNDI/LDAP URL parsing vs. HTTP URL parsing |
| **Encoded Fragment** | `%23` decoded to `#` at different pipeline stages | `/path%23fragment/rest` → decoded to `/path#fragment/rest` | Decoder runs before vs. after routing |

---

## §8. Encoding Differentials

Cross-cutting mutations exploiting disagreements about when and how URL encoding/decoding occurs. These combine with all other categories.

### §8-1. Backslash vs. Forward Slash (WHATWG vs. RFC 3986)

The most fundamental standard differential in URL parsing. WHATWG treats `\` as equivalent to `/` (ending authority, starting path). RFC 3986 treats `\` as a literal character.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Backslash Authority Termination** | `\` ends hostname in WHATWG; treated as path character in RFC 3986 | `http://evil.com\@trusted.com/` → WHATWG: host=`evil.com`; RFC: host=`evil.com\@trusted.com` | Validator uses RFC 3986; HTTP library uses WHATWG |
| **Backslash Path Confusion** | Backslash in path interpreted as directory separator on Windows but literal on Linux | `http://target.com/admin\..\..\secret` | IIS/Windows origin; Linux-based proxy |
| **Encoded Backslash** | `%5c` decoded to `\` at different stages | `http://target.com/%5c@evil.com/` | Proxy doesn't decode; origin does |

### §8-2. Double and Triple Encoding

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Double URL Encoding** | `%252f` → decoded once to `%2f` (by proxy), then to `/` (by origin) | `%252e%252e%252f` → traversal after double decode | Two decoding layers in pipeline |
| **Triple URL Encoding** | Three layers of encoding for deeply layered architectures | `%25252e` → three decode stages | Three decoding layers |
| **Mixed Encoding** | Combining URL encoding with other schemes (Unicode, HTML entities) | `%u002e%u002e/` (IIS-specific Unicode encoding) | IIS legacy Unicode URL decoding |

### §8-3. Unicode and UTF-8 Anomalies

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Overlong UTF-8 Sequences** | Non-shortest form UTF-8 encoding of ASCII characters | `%c0%af` = `/`, `%c0%ae` = `.` | Parser accepts non-shortest UTF-8 |
| **Unicode Normalization** | Different Unicode normalization forms (NFC, NFD, NFKC, NFKD) produce different byte sequences for same visual character | Admin vs. Аdmin (Cyrillic А) after normalization | Normalization applied inconsistently |
| **Width Characters** | Fullwidth characters (e.g., `Ａ` = U+FF21) that normalize to ASCII | `ｈｔｔｐ://evil.com` | Parser normalizes fullwidth to ASCII |
| **Right-to-Left Override** | Unicode RTL characters reverse visual display of URL | `http://evil.com/‮moc.detsurt` | Visual display manipulation for phishing |

### §8-4. Content-Type / Body Encoding Confusion (WAF Context)

While not strictly URL parsing, WAF bypass via request body encoding confusion is closely related.

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Multipart Boundary Mutation** | WAF and application disagree on multipart boundary parsing | Modified boundary characters or duplicate headers | WAF parses boundary differently than framework |
| **JSON Content-Type Confusion** | Body sent as JSON but Content-Type header suggests form data, or vice versa | `Content-Type: application/x-www-form-urlencoded` with JSON body | WAF parses as form; framework detects and parses as JSON |
| **Charset Confusion** | Different charset declarations cause different decoding of the same bytes | `charset=ibm037` vs. default UTF-8 | WAF doesn't handle charset; app does |

---

## §9. DNS Resolution and Temporal Confusion

Attacks exploiting the gap between URL validation time and URL fetch time, particularly through DNS resolution changes.

### §9-1. DNS Rebinding

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **Classic DNS Rebinding** | Attacker DNS server returns public IP for validation, private IP for fetch | First resolve: `1.2.3.4`; second resolve: `127.0.0.1` | Application resolves hostname twice (check + fetch) |
| **TTL-0 Rebinding** | DNS TTL set to 0 to force re-resolution between check and use | `evil.com` with TTL=0 → alternating responses | No DNS caching at resolver level |
| **Dual-A-Record** | DNS returns both public and private IP in same response; OS/library picks different one | `evil.com` → `[1.2.3.4, 127.0.0.1]` | Race condition in IP selection |
| **DNS Rebinding Service** | Services like `rbndr.us`, `1u.ms` that automate rebinding | `a]127.0.0.1.b]1.2.3.4.rbndr.us` | Convenient rebinding without custom DNS server |

### §9-2. Redirect-Based Resolution Bypass

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **HTTP Redirect to Internal** | External URL passes validation; responds with 302 to `http://127.0.0.1/` | `http://evil.com/redirect` → 302 → `http://169.254.169.254/` | Application follows redirects after validation |
| **Chained Redirects** | Multiple redirects gradually shift from external to internal | `evil.com` → `evil2.com` → `http://internal/` | Redirect limit not enforced or validation not re-applied |
| **Redirect Protocol Downgrade** | HTTPS redirect to HTTP to bypass TLS-only validation | `https://evil.com/` → 302 → `http://internal:80/` | Scheme not re-validated after redirect |
| **Redirect to Different Scheme** | HTTP redirect to `file://`, `gopher://`, etc. | `http://evil.com/` → 302 → `file:///etc/passwd` | Fetcher follows cross-scheme redirects |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Impact |
|---|---|---|---|
| **SSRF** | Server-side URL fetcher with validation | §1-2, §2-1, §3-1, §3-2, §8-1, §9-1, §9-2 | Internal network access, cloud metadata theft, RCE chain |
| **Open Redirect** | Server-side redirect with URL allowlist | §2-1, §3-2, §8-1, §1-3 | Phishing, OAuth token theft |
| **Web Cache Poisoning** | CDN/Proxy + Origin with different parsers | §5-2, §5-3, §5-4, §5-5, §6-1 | Arbitrary content injection for all users |
| **Web Cache Deception** | CDN/Proxy + Origin with path confusion | §5-2, §5-4, §5-5 | Stealing cached sensitive user data |
| **WAF Bypass** | WAF inline with different URL parser than backend | §5-1, §5-2, §8-2, §8-4, §6-1 | Bypassing SQLi/XSS/RCE protections |
| **ACL/Auth Bypass** | Reverse proxy ACL + backend with path normalization mismatch | §5-1, §5-2, §5-3, §5-4 | Accessing admin endpoints without credentials |
| **CORS Bypass** | Origin validation using URL parsing | §2-1, §3-2, §8-1 | Cross-origin data theft |
| **Phishing / IDN Spoofing** | Visual URL display in browser/email | §3-2 (IDN Homograph), §8-3 | Credential theft via spoofed domains |
| **XSS** | URL components reflected in HTML without proper encoding | §1-2 (javascript:), §5-2, §6-1 | Script execution in victim's browser |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Product | Impact / Bounty |
|---|---|---|---|
| §5-4 + §5-2 (Filename Confusion) | CVE-2024-38475 | Apache HTTP Server | `?` in r->filename allows ACL bypass + SSRF |
| §5-4 (DocumentRoot Confusion) | CVE-2024-38474 | Apache HTTP Server | Escape DocumentRoot to system root |
| §5-4 (Handler Confusion) | CVE-2024-38476 | Apache HTTP Server | Handler overwrite → code execution |
| §5-1 + §8-2 (Proxy Encoding) | CVE-2024-38473 | Apache HTTP Server | Proxy encoding problem enables SSRF |
| §5-4 + §5-2 (Confusion Attacks) | CVE-2024-38477 | Apache HTTP Server | mod_proxy crash via malicious request |
| §3-1 + §2-1 (Authority Confusion) | CVE-2024-22262 | Spring Framework UriComponentsBuilder | Open redirect + SSRF via URL parser bypass |
| §2-1 + §1-3 (Colon-@ Trick) | CVE-2025-0454 | AutoGPT | SSRF via `localhost:\@google.com` parser confusion |
| §3-3 (Bracket Confusion) | CVE-2025-0938 | Python urllib | Square brackets in hostname cause parser differential |
| §5-2 (URI Parser Bypass) | CVE-2025-29914 | Coraza WAF | URLs starting with `//` bypass WAF rules |
| §7-1 + §2-1 (Fragment+Authority) | CVE-2024-30043 | Microsoft SharePoint | URL parsing confusion → XXE |
| §8-4 (Content-Type Confusion) | WAFFLED (ACSAC 2025) | Cloudflare, AWS WAF, Azure WAF, ModSecurity | 1,207 bypasses across major WAFs via parsing discrepancy |
| §5-5 (Cache Key Confusion) | Gotta Cache 'em All (BH 2024) | Azure CDN, OpenAI, multiple CDNs | Full cache poisoning + DoS |
| §9-1 (DNS Rebinding) | CVE-2025-15104 | Nu Html Checker | SSRF via DNS rebinding bypass |

---

## Detection & Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **PortSwigger URL Validation Bypass Cheat Sheet** (Web App) | SSRF/CORS/Redirect filter bypass | Interactive payload generator for 6 wordlist types across multiple parsers |
| **WAFFLED** (Fuzzer) | WAF bypass via parsing discrepancy | Grammar-based HTTP request mutation + differential testing against WAFs and frameworks |
| **ipobf** (CLI) | IP address representation obfuscation | Generates all equivalent IP representations (octal, hex, decimal, IPv6-mapped) |
| **Burp Suite Intruder** (Scanner) | URL validation bypass testing | Automated payload injection from cheat sheet wordlists |
| **rbndr.us** (DNS Service) | DNS rebinding testing | Alternating DNS responses for TOCTOU exploitation |
| **1u.ms** (DNS Service) | DNS rebinding with fine-grained control | Configurable rebinding responses with HTTP logging |
| **r3dir** (Redirect Service) | Redirect-based SSRF bypass | On-demand redirect server for SSRF testing |
| **PayloadsAllTheThings SSRF** (Payload List) | Comprehensive SSRF payload reference | Curated list of URL confusion payloads organized by technique |
| **HackTricks URL Format Bypass** (Reference) | SSRF URL format bypass | Categorized bypass payloads with language-specific notes |

---

## Summary: Core Principles

### Why URL Confusion Exists

The fundamental root cause is **specification fragmentation**. There is no single, universally-adopted URL specification. RFC 3986 (2005) defines URI syntax but leaves many edge cases implementation-defined. The WHATWG URL Standard (living document, browser-focused) deliberately deviates from RFC 3986 in ways designed for browser compatibility but that create security-relevant discrepancies with server-side parsers. Meanwhile, each programming language, framework, and HTTP server implements its own parser with its own quirks, bugs, and legacy behavior. The result: for any non-trivial URL, different components in a request pipeline will disagree about its meaning.

### Why Incremental Patches Fail

Each CVE patching a specific parsing quirk addresses one leaf of the mutation tree while leaving the structural problem intact. There are at least **5 layers where parsing can differ** (client, CDN/cache, WAF, reverse proxy, application framework), each with multiple implementations, and the combinatorial space of discrepancies grows multiplicatively. Furthermore, new frameworks and parsers are continuously introduced, and existing parsers update their behavior, creating new differentials. The attack surface is not a fixed set of bugs — it is an emergent property of compositional systems.

### Structural Solutions

True mitigation requires: (1) **parsing canonicalization** — using a single URL parser at the outermost edge and passing only the parsed, canonicalized components downstream; (2) **resolution-based validation** — validating the resolved IP address after DNS lookup, immediately before the connection, not the hostname string; (3) **architectural alignment** — ensuring that cache/proxy/WAF/origin all use the same URL normalization rules, or explicitly accepting that they don't and restricting cached content accordingly; and (4) **defense in depth at the network layer** — blocking private IP ranges at the network/firewall level rather than relying on application-level URL validation.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

### Specifications

| # | Title | URL |
|---|-------|-----|
| [1] | RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax | https://datatracker.ietf.org/doc/html/rfc3986 |
| [2] | WHATWG URL Standard (Living Standard) | https://url.spec.whatwg.org/ |
| [3] | RFC 6874 — Representing IPv6 Zone Identifiers in URIs | https://datatracker.ietf.org/doc/html/rfc6874 |

### CVE / Vulnerability Advisories

| # | CVE | Title | URL |
|---|-----|-------|-----|
| [4] | CVE-2024-38475 | Apache HTTP Server mod_rewrite Filename Confusion | https://nvd.nist.gov/vuln/detail/cve-2024-38475 |
| [5] | CVE-2024-38474 | Apache HTTP Server DocumentRoot Confusion | https://httpd.apache.org/security/vulnerabilities_24.html |
| [6] | CVE-2024-38476 | Apache HTTP Server Handler Confusion (CVSS 9.8) | https://nvd.nist.gov/vuln/detail/cve-2024-38476 |
| [7] | CVE-2024-38473 | Apache HTTP Server mod_proxy Encoding Problem | https://nvd.nist.gov/vuln/detail/cve-2024-38473 |
| [8] | CVE-2024-38477 | Apache HTTP Server mod_proxy Null Pointer DoS | https://nvd.nist.gov/vuln/detail/cve-2024-38477 |
| [9] | CVE-2024-22262 | Spring Framework UriComponentsBuilder Open Redirect / SSRF | https://www.cvedetails.com/cve/CVE-2024-22262/ |
| [10] | CVE-2025-0454 | AutoGPT SSRF via Hostname Parser Confusion | https://github.com/advisories/GHSA-jg5r-v2h9-wfxx |
| [11] | CVE-2025-0938 | Python urllib Square Bracket Hostname Confusion | https://github.com/advisories/GHSA-5qjr-cj9f-phrx |
| [12] | CVE-2025-29914 | Coraza WAF URI Parser Bypass via `//` Prefix | https://nvd.nist.gov/vuln/detail/cve-2025-29914 |
| [13] | CVE-2024-30043 | Microsoft SharePoint XXE via URL Parsing Confusion | https://www.thezdi.com/blog/2024/5/29/cve-2024-30043-abusing-url-parsing-confusion-to-exploit-xxe-on-sharepoint-server-and-cloud |

### Research & Conference Talks

| # | Title | Author/Source | URL |
|---|-------|--------------|-----|
| [14] | Confusion Attacks: Exploiting Hidden Semantic Ambiguity in Apache HTTP Server | Orange Tsai, Black Hat USA 2024 | https://blog.orange.tw/posts/2024-08-confusion-attacks-en/ |
| [15] | Gotta Cache 'em All: Bending the Rules of Web Cache Exploitation | PortSwigger Research, Black Hat USA 2024 | https://portswigger.net/research/gotta-cache-em-all |
| [16] | WAFFLED: Automated Discovery of WAF Parsing Discrepancy Bypasses | ACSAC 2025 | https://arxiv.org/abs/2503.10846 |
| [17] | URL Validation Bypass Cheat Sheet | PortSwigger | https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet |
| [18] | Web Cache Deception | PortSwigger Web Security Academy | https://portswigger.net/web-security/web-cache-deception |

### Tools

| # | Tool | URL |
|---|------|-----|
| [19] | ipobf — IP Address Obfuscation for SSRF Filter Bypass | https://github.com/JorianWoltjer/ipobf |
| [20] | rbndr — DNS Rebinding Service | https://github.com/taviso/rbndr |
| [21] | 1u.ms — Zero-Configuration DNS Rebinding Utility | https://github.com/neex/1u.ms |
| [22] | r3dir — HTTP Redirection Service for SSRF Filter Bypass | https://github.com/Horlad/r3dir |
| [23] | PayloadsAllTheThings — Server Side Request Forgery | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery |
| [24] | HackTricks — URL Format Bypass | https://book.hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass.html |
| [25] | WAFFLED Fuzzer | https://github.com/sa-akhavani/waffled |
| [26] | PortSwigger URL Cheatsheet Data | https://github.com/PortSwigger/url-cheatsheet-data |
