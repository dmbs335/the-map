# File Upload Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

File upload vulnerabilities arise from a fundamental architectural tension: web applications must accept external data in its most complex form — arbitrary binary files — while ensuring that this data never subverts the execution model, storage semantics, or trust boundaries of the server. Unlike simple text inputs where sanitization can strip dangerous characters, uploaded files carry structure at multiple layers simultaneously: filename, extension, MIME type, magic bytes, metadata, embedded objects, archive structure, and the binary content itself. Each layer may be interpreted by a different component (browser, WAF, application framework, web server, OS filesystem, image processing library), and discrepancies between these interpretations constitute the fundamental attack surface.

This taxonomy organizes file upload mutations along three axes:

**Axis 1 — Mutation Target (Primary, §1–§10):** The structural component of the upload being manipulated. This axis structures the main body of the document. Categories include filename/extension manipulation, Content-Type spoofing, file content forgery, metadata exploitation, configuration file injection, archive abuse, multipart structure manipulation, storage path attacks, processing pipeline exploitation, and temporal race conditions.

**Axis 2 — Discrepancy Type (Cross-cutting):** The nature of the mismatch that makes the mutation effective. These types recur across multiple categories:

| Discrepancy Type | Description |
|---|---|
| **Validation Bypass** | Circumventing blacklist, whitelist, or regex-based checks |
| **Parser Differential** | Different components interpret the same data differently |
| **TOCTOU** | Time gap between validation and use is exploited |
| **Content-Type Confusion** | Browser MIME sniffing contradicts declared type |
| **Filesystem Semantics** | OS-level naming quirks alter file identity post-upload |
| **Processing-Triggered Execution** | Code runs as a side-effect of server-side file processing |

**Axis 3 — Attack Scenario (Mapping):** The weaponized outcome — RCE (webshell), client-side attacks (stored XSS), SSRF, denial of service, information disclosure, access control bypass, or chained exploitation. These are mapped in §11.

---

## §1. Extension & Filename Manipulation

The filename and its extension are the first and most commonly targeted validation surface. Servers, frameworks, and web servers all interpret extensions to determine how a file should be handled — but their parsing logic frequently diverges.

### §1-1. Blacklist Bypass via Alternative Extensions

When servers blacklist known dangerous extensions (e.g., `.php`, `.jsp`, `.asp`), attackers substitute lesser-known but functionally equivalent extensions that the server still maps to executable handlers.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PHP alternative extensions** | `.php3`, `.php4`, `.php5`, `.php6`, `.php7`, `.pht`, `.phpt`, `.phtml`, `.phar` are all mapped to the PHP handler by default Apache configurations | Apache with `mod_php` or PHP-FPM configured to handle multiple extensions |
| **JSP alternative extensions** | `.jspx`, `.jspf`, `.jsw`, `.jsv`, `.jtml` may be processed as JSP by servlet containers | Tomcat, JBoss, or other Java EE containers with default servlet mappings |
| **ASP/ASPX alternatives** | `.asa`, `.asax`, `.ascx`, `.ashx`, `.asmx`, `.axd`, `.config`, `.cshtml`, `.vbhtml` | IIS with ASP.NET handler mappings |
| **SSI extensions** | `.shtml`, `.stm`, `.shtm` enable Server-Side Includes that can execute commands | Apache/IIS with SSI module enabled |
| **CGI extensions** | `.cgi`, `.pl`, `.py`, `.rb` invoke CGI/scripting handlers | Servers with CGI configured for the upload directory |

### §1-2. Double Extension Abuse

Apache's `mod_mime` evaluates extensions right-to-left and will apply handlers for any recognized extension, not just the last one. This enables files that pass extension-based filters while remaining executable.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Right-to-left parsing** | `shell.php.jpg` — the `.jpg` passes the whitelist filter, but Apache recognizes `.php` and routes to the PHP handler | Apache with `mod_mime` and `AddHandler` for PHP |
| **Unknown last extension** | `shell.php.xyz` — if `.xyz` is unrecognized, some servers fall back to the previous known extension (`.php`) | Apache with `mod_mime` default behavior |
| **Reverse double extension** | `shell.jpg.php` — straightforward but defeats filters that only check the string after the *first* dot | Applications using naive first-dot extraction |

### §1-3. Case Sensitivity Exploitation

Extension validation is case-sensitive in the application but case-insensitive in the server or OS, creating a parser differential.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Mixed-case extension** | `shell.pHp`, `shell.PhP`, `shell.PHP` bypass lowercase-only blacklists while Windows/IIS and Apache (on Windows) treat them identically | Case-insensitive filesystem (Windows, macOS) or case-insensitive server handler mapping |
| **Case-folded double extension** | `shell.PhP.JpG` combines case tricks with double extension abuse | Combined parser differential |

### §1-4. Null Byte & Truncation Injection

Null bytes and special characters can terminate filename parsing at the OS or language runtime level while the application sees the full string.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Null byte injection** | `shell.php%00.jpg` or `shell.php\x00.jpg` — the application validates `.jpg`, but the C-level filesystem call truncates at the null byte, writing `shell.php` | PHP < 5.3.4, older Java, languages using C-level file APIs without null byte checks |
| **URL-encoded null byte** | `shell.php%00.jpg` in URL-encoded form data | Backend that URL-decodes filenames before filesystem operations |
| **Unicode truncation** | Multibyte Unicode characters (e.g., `%c0%ae`) may be normalized or collapsed, truncating the extension | Applications performing Unicode normalization after validation |

### §1-5. Trailing Characters & Whitespace

Filesystem behaviors around trailing dots, spaces, and special characters create divergence between validation and actual file creation.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Trailing dot** | `shell.php.` — Windows NTFS silently strips trailing dots, so the file is stored as `shell.php` | Windows filesystem |
| **Trailing space** | `shell.php ` (with trailing space) — NTFS strips trailing spaces | Windows filesystem |
| **Semicolon truncation** | `shell.php;.jpg` — some server parsers (notably older IIS) truncate at the semicolon | IIS 6.0 and some older versions |
| **Colon truncation** | `shell.php:.jpg` — NTFS ADS syntax; the `:` may cause truncation or alternate interpretation | Windows NTFS, IIS |

### §1-6. Special Filename Injection

Certain filenames have special meaning to the server or OS, enabling execution or configuration changes even when extensions are properly validated.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Dot-prefixed files** | `.htaccess`, `.user.ini`, `.htpasswd` — these control server behavior regardless of extension | §5 covers this in detail |
| **Windows reserved names** | `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9` — uploading these can cause errors, hangs, or DoS | Windows filesystem |
| **Command injection via filename** | Filenames like ``; sleep 10; .jpg`` or `$(whoami).jpg` — if the filename is passed unsanitized to a shell command (e.g., for image conversion), command injection results | Server-side processing that shells out with user-controlled filenames (§9) |

---

## §2. Content-Type & MIME Manipulation

The `Content-Type` header in multipart uploads is client-controlled and trivially spoofable. Applications relying on it for security decisions are fundamentally flawed, yet this pattern remains widespread.

### §2-1. Content-Type Header Spoofing

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct MIME spoofing** | Upload `shell.php` with `Content-Type: image/jpeg` — the application checks only the MIME type and accepts the file | Application validates Content-Type but not extension or content |
| **Permissive MIME mapping** | Using `Content-Type: application/octet-stream` to bypass type-specific restrictions, as most servers accept generic binary types | Whitelist that includes `application/octet-stream` |
| **Charset injection** | `Content-Type: image/jpeg; charset=php` — some parsers extract and use the charset parameter, potentially altering processing | Edge case in framework-specific MIME parsing |

### §2-2. MIME Sniffing Exploitation

Browsers may ignore the declared `Content-Type` and "sniff" the actual content to determine type, enabling client-side attacks.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JavaScript-in-image sniffing** | Upload a file containing valid JavaScript with an image extension; if served without `X-Content-Type-Options: nosniff`, browsers may sniff and execute it as JavaScript | Missing `X-Content-Type-Options: nosniff` header |
| **HTML sniffing** | Upload a file with HTML content and an innocuous extension; browser sniffs it as `text/html`, executing embedded scripts | Files served inline (not as attachment) without XCTO |
| **CSP bypass via upload** | Upload JavaScript disguised as an allowed content type (e.g., `.zip`, `.txt`), reference it via `<script src="/uploads/file.zip">` — browser MIME-sniffs and executes | CSP allows `script-src 'self'`, uploaded files served from same origin |

### §2-3. Content-Type Juggling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Multiple Content-Types** | Sending conflicting Content-Type headers or values; different components may pick different ones | Proxy/WAF reads first value, application reads last value |
| **Case-variant MIME** | `Content-Type: IMAGE/JPEG` or `content-type: Image/Jpeg` — inconsistent case handling between validation and processing | Case-sensitive MIME validation against case-insensitive handlers |

---

## §3. File Content & Magic Byte Manipulation

Server-side validation often checks the first few bytes of a file (magic bytes/file signatures) to verify file type. This check can be subverted while maintaining executable content.

### §3-1. Magic Byte Prepending

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JPEG header injection** | Prepend `FF D8 FF E0` (JPEG magic bytes) to a PHP file: `\xFF\xD8\xFF\xE0<?php system($_GET['cmd']); ?>` | Server validates magic bytes but executes the file as PHP based on extension |
| **GIF header injection** | Prepend `GIF89a` (ASCII) followed by PHP code — `GIF89a` is a valid text string that also serves as GIF magic bytes | PHP engine ignores non-PHP content before `<?php` tags |
| **PNG header injection** | Prepend `\x89PNG\r\n\x1a\n` followed by executable code | Same parser differential between content validator and execution engine |
| **PDF header injection** | Prepend `%PDF-1.4` followed by embedded code or JavaScript | PDF parsers in browsers execute embedded JavaScript |

### §3-2. Polyglot Files

Files that are simultaneously valid in two or more formats, enabling them to pass validation for one format while being executable as another.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **GIFAR (GIF + JAR)** | A file that is both a valid GIF image and a valid Java Archive — the GIF structure ignores trailing data, while the JAR format reads from the end of the file | Java applet loading context (historically significant, largely mitigated) |
| **PHAR/JPEG polyglot** | A file that is both a valid JPEG and a valid PHP Archive (PHAR). The PHAR stub section has no restrictions except ending with `__HALT_COMPILER();`, so JPEG data can precede it. When accessed via `phar://` wrapper, the metadata is deserialized | PHP application that uses `phar://` wrapper or filesystem functions on user-controlled paths |
| **JavaScript/JPEG polyglot** | A JPEG that also parses as valid JavaScript — crafted by manipulating JPEG comment fields to contain JS code. When loaded as `<script>`, the browser executes it | File served from same origin, loaded in a `<script>` tag |
| **PDF/JavaScript polyglot** | A PDF containing embedded JavaScript in its structure, valid as both PDF and executable script | Browser PDF rendering, or file served with sniffable type |
| **HTML/image polyglot** | A file with valid image headers followed by HTML/JavaScript content that browser MIME-sniffing interprets as HTML | Missing `X-Content-Type-Options: nosniff` |

### §3-3. PHP Tag Variants

PHP supports multiple opening tag syntaxes, some of which survive content stripping or format-specific encoding.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Short open tag** | `<?` instead of `<?php` — more concise, easier to embed in binary data | `short_open_tag=On` in php.ini (default on in many configurations) |
| **ASP-style tag** | `<%` as PHP opening tag | `asp_tags=On` in php.ini (removed in PHP 7.0) |
| **Script tag** | `<script language="php">code</script>` | PHP < 7.0 |
| **Echo shorthand** | `<?= expression ?>` — always available since PHP 5.4, useful for minimal payloads | PHP >= 5.4 |

---

## §4. Metadata & Embedded Object Exploitation

Files carry metadata in structured fields (EXIF, XMP, IPTC for images; XML for office documents; headers in PDFs) that are processed server-side, creating injection surfaces invisible to simple content validation.

### §4-1. EXIF/IPTC Metadata Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PHP in EXIF Comment** | Embed `<?php system($_GET['c']); ?>` in the EXIF Comment, Artist, or Copyright field of a valid JPEG. When the image file is included via LFI or processed by a script that reads and outputs metadata, the PHP code executes | PHP include/require on the uploaded image path, or metadata displayed unsanitized |
| **XSS via EXIF** | Embed `<script>` tags in EXIF fields (UserComment, ImageDescription). When the application renders metadata on a page without sanitization, stored XSS results | Application displays EXIF data without HTML encoding |
| **SQL injection via metadata** | Inject SQL payloads into EXIF fields that are stored in a database | Application parses and stores EXIF data in SQL without parameterization |
| **ExifTool RCE** | Craft a malicious DjVu file with Perl code injection in the ANT annotation, wrapped in a JPEG container. ExifTool's DjVu parser evaluates the Perl code during metadata extraction (CVE-2021-22204) | Server uses ExifTool (versions < 12.24) to process uploaded images |

### §4-2. XXE via XML-Based File Formats

Many common file formats use XML internally, enabling XML External Entity (XXE) injection through file upload.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SVG XXE** | SVG files are XML documents. An SVG with a malicious DOCTYPE declaring an external entity can read local files or trigger SSRF when the server parses the SVG (e.g., for thumbnail generation or rendering) | Server-side SVG parsing (librsvg, Batik, headless browsers) with external entity processing enabled |
| **DOCX/XLSX/PPTX XXE** | Office Open XML formats are ZIP archives containing XML files. Replacing `[Content_Types].xml` or embedded XML parts with XXE payloads triggers entity expansion when the server parses the document | Server-side document processing (Apache POI, python-docx, LibreOffice) |
| **XML upload XXE** | Direct upload of `.xml` files with external entity declarations | Application accepts XML uploads and parses them server-side |
| **XMP metadata XXE** | XMP metadata (embedded in images, PDFs) uses XML. Crafting XMP blocks with XXE payloads can trigger entity expansion during metadata processing | Libraries that parse XMP without disabling external entities |

### §4-3. Embedded Executable Content

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Office VBA macros** | Word/Excel documents with embedded VBA macros that execute on open. While primarily a client-side threat, server-side document preview/conversion systems may trigger macro execution | Server-side Office automation or preview without macro disabling |
| **Office DDE injection** | Dynamic Data Exchange (DDE) fields in Office documents execute commands without macros — `{DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"}` | Document opened by user or processed by server-side Office |
| **PDF JavaScript** | PDFs can contain embedded JavaScript that executes in PDF readers. Can be combined with file upload to deliver exploits | PDF rendering on client or server (phantomjs, browser preview) |
| **OLE embedded objects** | Office documents embed OLE objects (Package objects) that drop files to the Windows temp directory when opened | Server-side document processing or user opening uploaded documents |
| **Embedded Flash (SWF)** | Flash objects embedded in PDFs or Office documents can execute ActionScript | Legacy PDF readers with Flash support (largely deprecated) |

### §4-4. SVG-Specific Attacks

SVG's XML foundation combined with its script execution capabilities make it a uniquely dangerous upload format.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SVG JavaScript execution** | `<svg onload="alert(document.cookie)">` or `<svg><script>alert(1)</script></svg>` — when served inline, the browser executes embedded JavaScript | Executes when SVG is directly navigated, embedded via `<object>`, `<embed>`, `<iframe>`, or included as inline `<svg>` in the HTML DOM. **JavaScript execution is blocked in all modern browsers** when SVG is embedded via `<img>` tags |
| **SVG foreignObject** | `<foreignObject>` element can embed arbitrary HTML within SVG, including forms, scripts, and iframes | Browser rendering of SVG served inline |
| **SVG SSRF** | `<image xlink:href="http://internal-server/admin">` in SVG triggers server-side requests during rendering | Server-side SVG rendering (headless browsers, image conversion) |
| **SVG CSS injection** | SVG `<style>` elements can import external stylesheets or use CSS expressions for code execution | Older browsers or server-side renderers processing SVG CSS |

---

## §5. Server Configuration File Upload

Uploading server configuration files allows attackers to redefine how the web server handles files in the upload directory, effectively granting execution capabilities to otherwise inert files.

### §5-1. Apache Configuration Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **.htaccess handler override** | Upload `.htaccess` containing `AddType application/x-httpd-php .jpg` — all `.jpg` files in the directory are now executed as PHP | Apache with `AllowOverride` enabled for the upload directory |
| **.htaccess custom extension** | `AddType application/x-httpd-php .l33t` — creates a new executable extension not in any blacklist | Same as above |
| **.htaccess PHP config override** | Override `php_value auto_prepend_file` to inject code that runs before every PHP file in the directory | Apache with `AllowOverride Options` or `AllowOverride All` |
| **.htaccess self-executing** | `.htaccess` file containing `AddType application/x-httpd-php .htaccess` with PHP code at the end — the `.htaccess` file itself becomes executable | Apache processes the directive, then the file is also served as PHP |

### §5-2. IIS Configuration Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **web.config ASP handler** | Upload `web.config` defining a custom handler that maps an innocuous extension to the ASP.NET script processor: `<handlers><add name="asp" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory" /></handlers>` | IIS 7+ with delegated configuration |
| **web.config inline code** | `web.config` with embedded ASP.NET code in `<system.webServer>` sections that executes on parse | IIS configuration delegation enabled |
| **web.config MIME mapping** | Override MIME mappings to serve uploaded files as executable content types | IIS with per-directory configuration |

### §5-3. PHP Configuration Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **.user.ini auto_prepend** | Upload `.user.ini` with `auto_prepend_file=shell.jpg` — the shell code in `shell.jpg` executes before every PHP request in the directory | PHP running as CGI/FastCGI (not mod_php), `user_ini.filename` not disabled |
| **.user.ini engine override** | Override PHP engine settings to enable dangerous functions or modify execution behavior | PHP CGI/FastCGI mode |

---

## §6. Archive & Container File Exploitation

When applications accept archive files (ZIP, TAR, JAR, etc.) and extract them server-side, the archive structure itself becomes an attack vector.

### §6-1. Zip Slip (Path Traversal via Archive Entries)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Directory traversal in entry name** | Archive contains entries with names like `../../../var/www/html/shell.php`. During extraction, the file is written outside the intended directory to an attacker-controlled path | Extraction library does not sanitize entry names; affects ZIP, TAR, JAR, WAR, APK, RAR, 7z |
| **Absolute path entries** | Archive entries with absolute paths (e.g., `/etc/cron.d/malicious`) that override intended extraction directory | Extraction without path normalization |
| **Symlink-first extraction** | Archive contains: (1) a symlink entry pointing to a sensitive directory (e.g., `link → /etc/`), then (2) a file entry `link/cron.d/payload`. The symlink is created first, then the file is written through it to the actual filesystem path | Extraction preserves symlinks and processes entries sequentially |

### §6-2. Symlink Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Symlink file read** | Upload a ZIP containing a symlink to `/etc/passwd` or other sensitive files. After extraction, accessing the symlink through the web server reads the target file | Server extracts and serves symlinks; no symlink resolution checks |
| **Symlink directory escape** | Symlink pointing to the web root or other writable directories, enabling subsequent file writes via additional uploads | Chained with another upload or write operation |

### §6-3. Decompression Bombs

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Zip bomb** | A small ZIP file (e.g., 42KB) that decompresses to petabytes of data through nested compression layers (e.g., `42.zip`). Server exhausts disk space, memory, or CPU during extraction | Server extracts archives without recursion depth or size limits |
| **Recursive zip bomb** | Non-recursive variant using overlapping ZIP entries that reference the same compressed data block, achieving extreme compression ratios without nesting | Modern ZIP parsers that handle overlapping entries |
| **Gzip bomb** | A tiny gzip file that expands to gigabytes, targeting HTTP decompression or server-side gzip handling | Server automatically decompresses gzip uploads |

### §6-4. Archive Format Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JAR/WAR deployment** | Uploading a `.jar` or `.war` file to a Java application server's deployment directory triggers automatic deployment and code execution | Upload path coincides with or can traverse to the auto-deploy directory |
| **PKG/APK/IPA masquerading** | Mobile or OS package formats that are essentially ZIP files with specific structure — can bypass filters expecting only "ZIP" | Application accepts archives but doesn't verify internal structure |

---

## §7. Multipart Request Structure Manipulation

The HTTP `multipart/form-data` encoding used for file uploads has its own parsing complexity that can be exploited.

### §7-1. Boundary Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Boundary injection in Content-Type** | Manipulating the boundary string in the Content-Type header to create ambiguity about where parts begin and end — WAF sees one file, application sees another | WAF and application parse multipart boundaries differently |
| **Duplicate boundaries** | Sending content with multiple valid boundary definitions; different parsers may select different boundaries | Parser differential between proxy/WAF and backend |
| **Malformed boundary** | Using boundary strings with special characters, excessive length, or missing closing boundaries to confuse parsers | Lenient backend parser with strict WAF |

### §7-2. Content-Disposition Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Duplicate filename parameters** | `Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename="shell.php"` — WAF reads first filename, application reads last | Parser differential in duplicate parameter handling |
| **Filename encoding tricks** | `filename*=UTF-8''shell.php` (RFC 5987 encoding), `filename="=?UTF-8?B?c2hlbGwucGhw?="` (MIME encoded-word) — bypass filters that only match literal filename strings | Backend supports RFC 5987 or MIME encoded-word; WAF does not decode |
| **Quoted/unquoted differential** | `filename=shell.php` vs `filename="shell.php"` — some parsers require quotes, others don't, and behavior differs with special characters | Parser inconsistency |
| **Name field overwrite** | Injecting newlines or additional Content-Disposition headers within a part to redefine the `name` field, causing the backend to map the file to a different form parameter | Lenient multipart parser that doesn't reject malformed headers |

### §7-3. Multipart Smuggling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Part injection** | Injecting additional multipart parts by including boundary strings within the file content itself | Backend uses different boundary detection than WAF |
| **Header injection in part** | Including CRLF sequences in filename or other parameters to inject additional headers within a multipart part | Insufficient CRLF sanitization in part headers |

---

## §8. Storage & Path Handling Attacks

After a file passes validation, how and where it's stored can be exploited through filesystem-level tricks.

### §8-1. Path Traversal via Filename

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Directory traversal sequences** | `../../../var/www/html/shell.php` or `..\..\..\..\inetpub\wwwroot\shell.asp` in the filename | Application concatenates filename to upload directory without sanitization |
| **URL-encoded traversal** | `%2e%2e%2f` (../) or double-encoding `%252e%252e%252f` to bypass filters | Application URL-decodes filename after validation |
| **Unicode/UTF-8 traversal** | `%c0%ae%c0%ae/` — overlong UTF-8 encoding of `../` that bypasses ASCII-based filters | IIS, older Java, or applications with inconsistent Unicode handling |
| **Backslash variant** | `..\..\..\shell.php` — on Windows, backslashes are valid path separators but may not be filtered | Windows servers with Linux-style filter rules |

### §8-2. NTFS-Specific Tricks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Alternate Data Streams (ADS)** | `shell.php::$DATA` — the `::$DATA` suffix references the default data stream; Windows NTFS strips it, resulting in `shell.php`. Historically used to retrieve source code (`shell.asp::$DATA` returned raw ASP source instead of executing) | Windows NTFS filesystem; IIS |
| **ADS directory creation** | `folder.asp::$Index_Allocation` or `:$I30:$Index_Allocation` — NTFS creates a directory instead of a file, enabling directory creation in unexpected locations | Windows NTFS |
| **8.3 short name collision** | Windows generates 8.3 short names (e.g., `LONGFI~1.PHP` for `longfilename.php`). Attackers can reference files via short names to bypass validation that only checks long names | Windows NTFS with 8.3 name generation enabled (default) |
| **Reserved device names** | `shell.php.` (trailing dot stripped), `shell.php ` (trailing space stripped), `shell.php::$DATA` — all resolve to `shell.php` on NTFS | Windows NTFS automatic name normalization |

### §8-3. Cloud Storage & Object Storage

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Presigned URL abuse** | S3/GCS presigned URLs for upload may not enforce content-type or file size constraints; anyone with the URL can upload arbitrary content | Presigned URL generated without `Content-Type` condition or expiration |
| **Bucket policy bypass** | Uploading files that exploit overly permissive bucket policies — e.g., uploading HTML files to a bucket served as a static website, enabling XSS | S3 static website hosting with broad upload permissions |
| **Object key manipulation** | Cloud storage treats the full key as a flat string; `.` and `..` have no traversal meaning, but applications that generate filesystem paths from object keys may be vulnerable | Application downloads from S3 and saves to local filesystem using the object key |
| **Lambda /tmp persistence** | In serverless environments, uploaded files processed in `/tmp` persist across warm invocations. An attacker can upload a file that persists and is loaded by subsequent invocations | Lambda/Cloud Functions reusing warm containers without /tmp cleanup |

---

## §9. Processing Pipeline Exploitation

Server-side processing of uploaded files — image resizing, metadata extraction, document conversion, format validation — introduces execution surfaces beyond simple file storage.

### §9-1. Image Processing Library Exploits

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ImageMagick delegate RCE (ImageTragick)** | ImageMagick processes MVG/SVG files by invoking delegate commands via `system()`. Specially crafted images trigger command injection through the delegate mechanism: `push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://example.com/image.jpg"\|ls "-la)'` (CVE-2016-3714) | ImageMagick with default `delegates.xml` and `policy.xml` |
| **ImageMagick SSRF** | Using `url()` references in MVG/SVG to trigger server-side requests to internal services | ImageMagick processing user-uploaded images without URL policy restrictions |
| **ImageMagick file read** | `label:@/etc/passwd` or `text:@/etc/passwd` reads local files and renders content into the output image | ImageMagick with `@` file reading not restricted by policy |
| **Pillow/PIL overflow** | Integer overflow in BMP encoder or other format handlers leading to buffer overflow and potential code execution on 32-bit builds | Vulnerable Pillow versions on 32-bit systems |
| **LibreOffice conversion** | Uploading ODF/DOCX files for server-side conversion via LibreOffice can trigger macro execution, XXE, or SSRF through embedded content | Server uses LibreOffice in headless mode without disabling macros/external resources |

### §9-2. Metadata Processing Exploits

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ExifTool Perl injection** | CVE-2021-22204: a malicious DjVu annotation triggers arbitrary Perl code execution during metadata extraction by ExifTool. The payload is embedded in a JPEG wrapper file | ExifTool < 12.24 used for metadata processing |
| **PDF metadata parsing** | PDF files with crafted XRef tables or stream objects that exploit vulnerabilities in PDF parsing libraries (Ghostscript, Poppler, MuPDF) | Server-side PDF processing or thumbnail generation |

### §9-3. Deserialization via File Upload

When uploaded files are deserialized rather than simply stored, the deserialization mechanism itself becomes the vulnerability.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Python pickle upload** | Uploading a serialized Python object (pickle file) that, when deserialized via `pickle.loads()`, executes arbitrary code through `__reduce__` method | Application deserializes uploaded files using `pickle`, `shelve`, or `marshal` |
| **YAML unsafe load** | Uploading a YAML file containing `!!python/object/apply:os.system ['command']` that executes during parsing | Application uses `yaml.load()` instead of `yaml.safe_load()` (PyYAML < 6.0 default) |
| **Java deserialization** | Uploading serialized Java objects that leverage gadget chains (Commons Collections, etc.) for RCE when deserialized by `ObjectInputStream` | Application deserializes uploaded data using Java serialization |
| **PHP PHAR deserialization** | Uploading a PHAR archive (possibly disguised as an image via polyglot, §3-2). When any filesystem function (e.g., `file_exists()`, `is_dir()`) is called with a `phar://` wrapper pointing to the uploaded file, the PHAR metadata is unserialized, triggering POP chain exploitation | PHP application using filesystem functions with attacker-controlled paths; `phar://` wrapper enabled |
| **.NET ViewState** | Uploading or injecting crafted ViewState data containing serialized .NET objects that exploit `ObjectStateFormatter` deserialization | ASP.NET application with ViewState MAC disabled or known machine key |

### §9-4. Template Injection via File Upload

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SSTI in filename** | If the uploaded filename is rendered through a template engine (e.g., displayed on a page via Jinja2/Twig), payloads like `{{7*7}}` or `${7*7}` in the filename trigger SSTI | Application renders filenames through a template engine without escaping |
| **SSTI in file content** | Uploading template files (`.html`, `.tpl`, `.j2`) that are processed by the template engine, enabling `{{ config.items() }}` or RCE payloads | Application processes uploaded files as templates |
| **SSTI in metadata** | Embedding template syntax in EXIF/metadata fields that are extracted and rendered through a template engine | Metadata values passed to template rendering |

---

## §10. Temporal & Race Condition Attacks

The time gap between file upload, validation, and final storage/use creates exploitable windows.

### §10-1. Upload-Validate-Delete Race (TOCTOU)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Execution before deletion** | Application uploads file to web-accessible directory, then validates, then deletes if invalid. During the validation window, the attacker sends rapid requests to execute the file | File is accessible at a predictable URL between upload and deletion |
| **Apache Tomcat JSP race** | CVE-2024-50379 / CVE-2024-56337: On case-insensitive filesystems, concurrent upload and read of the same file path exploits TOCTOU in Tomcat's JSP compilation — a `.txt` file is swapped to `.jsp` between Tomcat's extension check and compilation, achieving RCE | Apache Tomcat on Windows/macOS (case-insensitive FS); `readonly=false` for default servlet |

### §10-2. Rename/Symlink Race

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Symlink swap** | Between the time the server validates the upload path and writes the file, an attacker creates a symlink at the upload path pointing to a sensitive location. The file is written through the symlink to an arbitrary destination (CVE-2025-67124) | Attacker has concurrent write access to the upload directory; server doesn't use `O_NOFOLLOW` |
| **Rename race** | Using `renameat2()` or rapid `rename()` calls to swap a file between validation and use | Multi-threaded or multi-process server with non-atomic file operations |

### §10-3. Parallel Upload Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Filename collision** | Simultaneously uploading multiple files with the same target name to exploit race conditions in name-collision handling | Server generates predictable filenames or allows user-controlled names |
| **Partial upload exploitation** | Sending chunked uploads and manipulating the reassembly process — a partially uploaded file may be temporarily accessible | Chunked upload implementation with early visibility |

---

## §11. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|---|---|---|
| **Remote Code Execution (Webshell)** | File executed by web server/application engine | §1 + §3 + §5 + §9 + §10 |
| **Stored XSS** | Uploaded file served to other users in browser context | §2-2 + §3-2 + §4-4 + §4-1 |
| **Server-Side Request Forgery (SSRF)** | Server processes file containing URL references | §4-2 (SVG XXE) + §9-1 (ImageMagick) + §4-4 |
| **Denial of Service** | Resource exhaustion during processing or storage | §6-3 (decompression bombs) + §9-1 (pixel flood) + §1-6 (reserved names) |
| **Local File Read / Information Disclosure** | XXE, SSRF, path traversal to read server files | §4-2 + §8-1 + §6-2 + §9-1 |
| **Access Control / Configuration Bypass** | Overwrite server configuration or escape upload directory | §5 + §8-1 + §6-1 + §8-2 |
| **Chained LFI + Upload → RCE** | Upload places code in accessible location; LFI includes it | §4-1 (EXIF PHP) + §3-1 (magic byte prepend) + §8-3 |
| **Client-Side Exploitation** | Uploaded documents/files exploit client applications | §4-3 (macros, DDE) + §4-2 (XXE) + §3-2 (polyglot) |
| **CSP Bypass** | Uploaded file serves as script source bypassing Content Security Policy | §2-2 + §3-2 + §8-3 |
| **Deserialization → RCE** | Uploaded serialized data triggers code execution during processing | §9-3 (pickle, YAML, PHAR, Java) |
| **Cloud Infrastructure Compromise** | Upload exploits cloud-specific storage or compute semantics | §8-3 (presigned URLs, /tmp persistence) + §6-1 (Zip Slip to deployment dir) |

---

## §12. CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §10-1 (TOCTOU) + §1-3 (case insensitivity) | CVE-2024-50379 / CVE-2024-56337 (Apache Tomcat) | CVSS 9.8. RCE via JSP compilation race condition on case-insensitive filesystems. Incomplete initial fix led to second CVE |
| §8-1 (path traversal) + §1 (extension bypass) | CVE-2025-31324 (SAP NetWeaver Visual Composer) | CVSS 10.0. Unauthenticated file upload to `/developmentserver/metadatauploader` with no file type validation; JSP webshell upload → RCE. Actively exploited in the wild |
| §2-1 (MIME spoofing) + §1 (extension bypass) | CVE-2024-5084 (Hash Form WordPress Plugin) | Unauthenticated RCE via `file_upload_action` function lacking file type validation; PHP webshell upload |
| §2-1 + §8-1 | CVE-2024-8060 (Open WebUI) | Authenticated RCE via `/audio/api/v1/transcriptions` endpoint; insufficient validation on `content_type` and user-controlled filenames; arbitrary file overwrite as root |
| §6-1 (Zip Slip) + §3 (content bypass) | CVE-2024-31280 (WordPress church-admin plugin) | Arbitrary file upload via unsafe Zip extraction; ZIP archive containing PHP files without extension validation; patched twice due to bypass |
| §3-2 (PHAR polyglot) + §9-3 (deserialization) | CVE-2024-33438 (CubeCart ≤ 6.5.4) | RCE via `.phar` file upload containing malicious serialized objects |
| §9-1 (ImageMagick overflow) | CVE-2025-57803 (ImageMagick 32-bit) | CVSS 9.8. Integer overflow in BMP encoder on 32-bit builds; heap overflow → potential RCE |
| §9-2 (ExifTool) | CVE-2021-22204 (ExifTool < 12.24) | RCE via Perl injection in DjVu ANT parsing; payload embeddable in JPEG wrapper. Widely exploited |
| §10-2 (symlink race) | CVE-2025-67124 (miniserve 0.32.0) | TOCTOU + symlink race in upload finalization; arbitrary file overwrite outside upload root |
| §6-1 (Zip Slip) | CVE-2025-3445 (archiver/v3 Go library) | Arbitrary file write via path traversal in archive extraction |
| §8-3 (presigned URL) | CVE-2025-65073 (OpenStack Keystone) | Authorization bypass in S3/EC2 token endpoints; presigned URL signature replay → full-scope token |
| §2-1 + §1 | CVE-2025-52078 (Writebot SaaS Template) | Unauthenticated file upload; no MIME validation, no extension checks, no authentication |
| §1 (extension bypass) + §6 (ZIP bypass) | CubeWP Framework ≤ 1.1.12 (WordPress) | Arbitrary file types inside ZIP archives bypass extension validation; PHP files in ZIP → RCE |
| §4-4 (SVG XSS) | Multiple HackerOne reports (H1:148853, H1:845832, H1:897244) | Stored XSS via SVG file upload; session cookie exfiltration. SVG XXE to SSRF in Zivver |

---

## §13. Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Upload Scanner** (Burp Suite Extension) | Comprehensive upload testing | Resizes images, injects PHP/JSP/ASP/XXE/SSRF/XSS/SSI payloads into EXIF metadata, tests multiple extension/content-type combinations; includes ReDownloader for server-side validation |
| **Burp File Fuzzer** (Burp Extension) | File type/MIME/filename fuzzing | Generates synthetic files of different types with three payload generators (file content, MIME type, filename); Pitchfork mode for correlated fuzzing |
| **Fuxploider** (Python tool) | Automated upload bypass | Automates file upload vulnerability detection and exploitation; tests extension bypass, MIME spoofing, magic byte injection |
| **ExifTool** (CLI utility) | Metadata injection for testing | Reads/writes metadata in 400+ formats; used offensively to inject payloads into EXIF fields and defensively to strip metadata |
| **PayloadsAllTheThings** (Repository) | Reference payload collection | Comprehensive collection of file upload payloads organized by server type (Apache, IIS, Nginx), technique (polyglot, config overwrite, EICAR), and format |
| **OPSWAT MetaDefender** (CDR/Scanning) | File sanitization & threat detection | Content Disarm & Reconstruct (CDR) — strips active content from uploaded files while preserving usability; detects polyglots |
| **ClamAV** (Antivirus engine) | Malware detection in uploads | Open-source AV scanner for server-side upload scanning; detects known malware signatures |
| **YARA** (Pattern matching) | Custom file content rules | Rule-based binary pattern matching for detecting webshells, polyglots, and malicious file patterns in uploaded content |
| **Semgrep** (SAST) | Source code analysis | Static analysis rules for detecting insecure file upload handling patterns: missing extension validation, unsafe deserialization, path traversal |
| **Snyk** (SCA) | Dependency vulnerability scanning | Identifies vulnerable file processing libraries (ImageMagick, ExifTool, archive extraction libraries) in project dependencies |

---

## §14. Summary: Core Principles

The entire file upload attack surface emerges from a single architectural reality: **files are multi-layered data structures interpreted by multiple independent components, and no single validation point can account for all interpretations.** A filename is read by the application, the web server, the operating system, and potentially a proxy or WAF — each with different parsing rules. File content is interpreted by magic-byte validators, image processing libraries, template engines, deserialization frameworks, and browsers. The Content-Type is declared by the client, interpreted by the server, and potentially re-sniffed by the browser. Every boundary between these interpretation layers is a potential discrepancy, and every discrepancy is a potential exploit.

**Incremental fixes fail because the attack surface is combinatorial.** Blacklisting `.php` invites `.phtml`. Checking magic bytes invites polyglots. Validating Content-Type invites multipart smuggling. Moving files to non-executable directories invites configuration file upload. Stripping metadata invites race conditions. Each defensive layer creates a new boundary, and each boundary creates a new differential to exploit. The defensive history of file uploads is a history of discovering that the previous fix created a new category of bypass.

**A structural solution requires defense-in-depth across all layers simultaneously:** (1) Generate random filenames server-side, discarding user-provided names entirely. (2) Store files outside the web root on non-executable storage (object storage, dedicated NAS) with no direct URL mapping. (3) Serve files through a proxy that sets `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and a correct, server-determined Content-Type. (4) Process files in isolated, ephemeral sandboxes (containers, Lambda) with no network access and strict resource limits. (5) Apply Content Disarm & Reconstruct (CDR) to strip active content from document formats. (6) Validate file content against the expected format using format-aware parsers (not just magic bytes) after — not instead of — all other checks. No single measure is sufficient; the combinatorial nature of the attack surface demands combinatorial defense.

---

## References

- OWASP Unrestricted File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- CWE-434: Unrestricted Upload of File with Dangerous Type: https://cwe.mitre.org/data/definitions/434.html
- PortSwigger Web Security Academy — File Upload: https://portswigger.net/web-security/file-upload
- PayloadsAllTheThings — Upload Insecure Files: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- Snyk Zip Slip Vulnerability: https://github.com/snyk/zip-slip-vulnerability
- HackTricks — File Upload: https://book.hacktricks.xyz/pentesting-web/file-upload
- The Hacker Recipes — Unrestricted File Upload: https://www.thehacker.recipes/web/inputs/unrestricted-file-upload
- Intigriti Advanced File Upload Guide: https://www.intigriti.com/researchers/blog/hacking-tools/insecure-file-uploads-a-complete-guide-to-finding-advanced-file-upload-vulnerabilities
- YesWeHack File Upload Attacks Parts 1 & 2: https://www.yeswehack.com/learn-bug-bounty/file-upload-attacks-part-1
- SEC Consult — Pentester's Windows NTFS Tricks: https://sec-consult.com/blog/detail/pentesters-windows-ntfs-tricks-collection/
- OPSWAT — Polyglot Image Attacks: https://www.opswat.com/blog/how-metadefender-prevents-sophisticated-polyglot-image-attacks
- Polyglot Files Research (arXiv): https://arxiv.org/html/2407.01529v1
- ImageTragick: https://imagetragick.com/
- Detectify — Bypassing Bucket Upload Policies: https://labs.detectify.com/writeups/bypassing-and-exploiting-bucket-upload-policies-and-signed-urls/

---

*This document was created for defensive security research and vulnerability understanding purposes.*
