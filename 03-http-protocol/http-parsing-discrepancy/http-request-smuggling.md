# HTTP Request Smuggling & Desync — Mutation Taxonomy



---



## Classification Structure



HTTP Request Smuggling (HRS) exploits parsing discrepancies between two or more HTTP agents (proxy, CDN, WAF, origin server) to inject hidden requests into a shared connection. This taxonomy classifies the entire mutation space along three axes.

- **Axis 1 — Mutation Target** (primary): *What structural component of the HTTP message is mutated?* This axis organizes the main body of the document (§1–§8).
- **Axis 2 — Discrepancy Type** (cross-cutting): *What kind of interpretation mismatch does the mutation create?* Every mutation must produce at least one discrepancy type.
- **Axis 3 — Attack Scenario** (mapping): *Under what architectural conditions is the mutation weaponized?*

A real-world exploit almost always chains mutations from multiple §-categories: a framing mutation from §1, enabled by header obfuscation from §2 or §3, exploiting a parser divergence from §7, and weaponized under a scenario from Axis 3.



### Discrepancy Types (Axis 2)



| Discrepancy Type | Definition |
|---|---|
| **Framing mismatch** | Two agents disagree on *where a request body ends* — the root cause of all smuggling |
| **Connection semantics mismatch** | Disagreement on connection state, protocol version, upgrade behavior, or keep-alive scope |
| **Parser leniency mismatch** | One agent accepts malformed input the other rejects, or both accept but derive different semantic values |
| **Timing mismatch** | Disagreement on when to read, respond, or timeout — exploited in pause-based and race-based desync |



### The Four Length Interpretation Methods



In mixed HTTP/1.1 + HTTP/2 environments, exactly four mechanisms determine where a message body ends. All framing mutations are notated as Front-End.Back-End pairs of these.

| Abbreviation | Interpretation |
|---|---|
| **CL** | Byte count from the `Content-Length` header |
| **TE** | Chunk boundaries from `Transfer-Encoding: chunked` |
| **0** | No length-specifying header present → implicitly zero body |
| **H2** | Built-in length field of the HTTP/2 DATA frame |



---



## §1. Message Framing Mutations



Mutations that cause two agents to disagree on *"how many bytes belong to this request's body."* This is the necessary condition for all HTTP Request Smuggling — every exploit ultimately produces a framing mismatch, whether directly or through enabling mutations from other categories.



### §1-1. CL ↔ TE Priority Conflict



RFC 7230 §3.3.3 mandates that when both Content-Length and Transfer-Encoding are present, Transfer-Encoding takes precedence and Content-Length must be ignored. Implementations diverge on this rule — and a single server that prioritizes CL over TE (or vice versa) creates an exploitable pair with any server that follows the opposite policy.

| Notation | Front-End Interpretation | Back-End Interpretation | Exploitation Pattern |
|---|---|---|---|
| **CL.TE** | Content-Length | Transfer-Encoding | Front-End reads CL bytes as body (including the smuggled request); Back-End parses TE chunked, hits `0\r\n\r\n` terminator, treats remaining bytes as next request |
| **TE.CL** | Transfer-Encoding | Content-Length | Front-End processes all chunks; Back-End reads only CL bytes, leaves the rest on the socket |
| **TE.TE** | TE (parsed normally) | TE (obfuscated → ignored → CL fallback) | Requires TE header obfuscation (§2-1) to make one side fail to recognize TE. Functionally reduces to CL.TE or TE.CL depending on which side's TE parsing is disrupted |

CL.TE and TE.CL are the oldest smuggling types, first documented in 2005 and demonstrated at scale against major infrastructure in 2019 (PayPal, Red Hat, and others, netting $70K+ in bounties). They remain the most common class. TE.TE is a variant that requires a prerequisite obfuscation mutation from §2-1.

**Payload — CL.TE:**

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

Front-End reads 35 bytes of body → forwards as one request. Back-End parses `0\r\n\r\n` as chunked terminator → `GET /admin` becomes the next request.

**Payload — TE.CL:**

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

Front-End processes chunk size `5c` (92 bytes) → forwards entire message. Back-End reads 4 bytes via CL (`5c\r\nG`) → treats `POST / HTTP/1.1...` as a new request.



### §1-2. Zero-Length Family



Asymmetries where one agent sees a body and the other sees none, without both CL and TE being simultaneously present.

| Notation | Mechanism | Key Condition |
|---|---|---|
| **CL.0** | Front-End parses CL and reads the body; Back-End ignores CL and treats the body as the start of the next request | Manifests primarily on endpoints that don't expect POST bodies — static files, redirects, error pages. Amazon, Akamai, and Varnish confirmed vulnerable |
| **0.CL** | Front-End sees no body (implicit zero) and forwards immediately; Back-End reads CL bytes → **deadlock** | Requires an **Early Response Gadget** to break the deadlock (see below) |
| **TE.0** | Front-End parses TE; Back-End doesn't support TE and treats body as zero | Demonstrated against Google Cloud Load Balancer ($8,500 bounty) |

**0.CL Deep Dive.** 0.CL was historically dismissed as "unexploitable due to deadlock": the Front-End forwards the request immediately (no body), but the Back-End reads CL bytes and blocks waiting for them — neither side advances. The breakthrough was the discovery of **Early Response Gadgets** — endpoints that respond before consuming the full request body, breaking the deadlock:

| Early Response Gadget Type | Mechanism | Example |
|---|---|---|
| **Static file requests** | Server responds from file cache without reading body | `GET /static/logo.png` |
| **Windows reserved filenames** | IIS responds immediately with 400 for reserved names | `GET /con`, `GET /prn`, `GET /aux`, `GET /nul` |
| **Server-level redirects** | 301/302 issued before body consumption | `GET /dir` → `GET /dir/` |
| **Expect: 100-continue** | RFC-specified early response mechanism | `Expect: 100-continue` header |
| **Error pages** | 404/405 responses returned before body read | Various non-existent paths |

0.CL typically combines with CL header whitespace obfuscation (`Content-Length : 76` with a space before the colon, see §3) to prevent the Front-End from recognizing the CL header. As of 2025, 0.CL has been confirmed at scale against Akamai (CVE-2025-32094, 74 bounties totaling ~$221K across 65 days), Cloudflare (H2.0 variant exposing 24M websites, $7K bounty), and Netlify.

**Double-Desync.** A 0.CL attack can be converted into a more powerful CL.0 by poisoning the connection twice: the initial 0.CL cuts the header block mid-stream, and the resulting leftover bytes form a CL.0 prefix that is concatenated to the next legitimate user's request. This two-stage "double-desync" enables full response queue poisoning from an attack vector that initially appears limited.

**Payload — CL.0:**

```
POST /static/image.png HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length: 30\r\n
Connection: keep-alive\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-Pad: x
```

Front-End reads 30 bytes via CL → forwards as one request. Back-End serves `/static/image.png`, ignores the body → `GET /admin` left on socket as next request.

**Payload — 0.CL with Early Response Gadget:**

```
GET /redirect HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length : 30\r\n
\r\n
GET /admin HTTP/1.1\r\n
X-Pad: x
```

`Content-Length : 30` (space before colon) — Front-End doesn't recognize it → forwards immediately with no body. Back-End recognizes it → waits for 30 bytes → but `/redirect` returns 301 early (gadget) → 30 bytes become the next request.



### §1-3. HTTP/2 Downgrade Framing



Mismatches between the H2 binary frame length and the CL/TE headers that survive (or are injected during) HTTP/2 → HTTP/1.1 translation. H2 downgrading is inherently more dangerous than HTTP/1.1-only chains because the H2 binary framing introduces a fourth length interpretation, expanding mismatch combinatorics.

| Notation | Mechanism | Notable Target |
|---|---|---|
| **H2.CL** | H2 DATA frame length disagrees with the CL header value retained after downgrade | Netflix ($20K bounty) — Netty Java library failed to validate CL against frame length |
| **H2.TE** | TE header that should be stripped per H2 spec survives the downgrade | Netlify CDN — every hosted site (including Firefox's start page `start.mozilla.org`) was vulnerable |
| **H2.0** | H2 request sent without CL → after downgrade, Back-End misjudges body presence | AWS ALB — patched within 5 days of report; Cloudflare — internal H2→H1 downgrade exposed 24M websites ($7K bounty) |

**H2 Frame Sequence Attacks.** Beyond header-level mismatches, the H2 frame *sequence grammar* itself produces additional attack classes when subjected to systematic fuzzing. Grammar-based H2 frame fuzzing across 12 reverse proxy technologies and CDNs (including Apache, Nginx, HAProxy, Envoy, Varnish, Cloudflare, Fastly, AWS CloudFront) revealed:

| Attack Class | Mechanism |
|---|---|
| **Request Blackholing** | Malformed H2 frame sequences cause the proxy to silently drop requests during conversion — the origin never receives them. Produces a targeted denial-of-service |
| **Query-of-Death** | Specific H2 frame patterns trigger fatal errors in the conversion layer, crashing the proxy process |
| **Conversion-induced Smuggling** | Inserting syntactically valid but unexpected frame types, or reordering DATA/HEADERS/CONTINUATION frames, produces HTTP/1.1 output that disagrees with the original H2 semantics |

These attacks exploit the H2 *frame sequence grammar* rather than individual header values carried within frames (cf. §4 for header-level H2 mutations).

**Payload — H2.CL:**

```
:method: POST
:path: /
:authority: vulnerable.com
content-length: 0

GET /admin HTTP/1.1\r\n
Host: vulnerable.com\r\n
\r\n
```

H2 DATA frame contains the full body. After downgrade, proxy writes `Content-Length: 0` but includes the body → Back-End reads zero bytes → `GET /admin` becomes the next request.

**Payload — H2.TE (forbidden header survives):**

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

H2 spec forbids `transfer-encoding`, but proxy fails to strip it during downgrade → Back-End parses TE:chunked → `0\r\n\r\n` ends body → `GET /admin` is next.



### §1-4. Timing-Based Desync



Exploiting *temporal* behavior rather than protocol grammar to create framing mismatches.

| Type | Mechanism | Confirmed Target |
|---|---|---|
| **Pause-based CL.0** | Send headers with CL, then deliberately pause for ~30 seconds → Back-End times out and responds → body arriving afterward is interpreted as a new request | Apache HTTP Server with server-level redirects |
| **Client-side pause-based desync** | MitM intercepts client TLS connection and introduces a delay for a specific packet size → causes the server to time out and respond prematurely → body becomes next request | Apache (demonstrated via TLS MitM) |
| **Expect-based 0.CL** | Use `Expect: 100-continue` to manipulate the Back-End's body-read timing, bypassing the 0.CL deadlock | T-Mobile ($12K bounty) — vanilla Expect; obfuscated Expect variants (`Expect: y 100-continue`) bypass WAF detection |

**Payload — Pause-Based CL.0:**

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



---



## §2. Transfer-Encoding Header Obfuscation



Mutations that subtly deform the `Transfer-Encoding` header so that only a subset of servers in the chain recognize it. This category is the **primary enabling mechanism** for §1-1 TE.TE attacks and amplifies many other framing mismatches. The mutation space is effectively infinite — each obfuscation variant creates a new server pair whose parsers may differ.



### §2-1. Value-Level Obfuscation



| Technique | Mutation Example | Parser Difference |
|---|---|---|
| **Value pollution** | `Transfer-Encoding: xchunked` | One side ignores the invalid value and falls back to CL; the other leniently accepts it as "chunked" |
| **Comma-prefixed value** | `Transfer-Encoding: ,chunked` | Some implementations treat `,chunked` identically to `chunked`; others reject or ignore it |
| **Identity encoding** | `Transfer-Encoding: identity` | Squid and ATS ignore the message body when TE is set to `identity`; most others process it normally |
| **Case variation** | `transfer-ENCODING: chunked` | RFC mandates case-insensitive header names, but implementations differ on value-level case sensitivity |
| **Header duplication** | `Transfer-Encoding: chunked\r\nTransfer-Encoding: x` | First-wins vs last-wins policy — one side sees "chunked", the other sees "x" (unknown → CL fallback) |



### §2-2. Structural Obfuscation



| Technique | Mutation Example | Parser Difference |
|---|---|---|
| **Colon whitespace** | `Transfer-Encoding : chunked` | Some parsers include the space in the header name, treating it as an unknown header. Also a core enabler for 0.CL attacks (§1-2) when applied to Content-Length (§3) |
| **Tab injection** | `Transfer-Encoding:\tchunked` | Implementations that don't equate tab with space fail to parse the value |
| **Obsolete line folding** | `Transfer-Encoding:\r\n chunked` | Deprecated in RFC 7230 §3.2.4 but still accepted by some servers. Exploited in CVE-2025-32094 (Akamai) where an OPTIONS-specific parser path failed to strip folded lines |
| **Leading whitespace** | `·Transfer-Encoding: chunked` | Space or non-printable character before header name causes some parsers to fail recognition |
| **Non-printable characters** | `Transfer-Encoding[\x0b]: chunked` | Vertical tab or other control characters in header name |

**Payload — TE.TE with obfuscation variants:**

```
POST / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Content-Length: 4\r\n
Transfer-Encoding: chunked\r\n
Transfer-Encoding: x\r\n
\r\n
5c\r\n
GPOST / HTTP/1.1\r\n
...
```

Other TE obfuscation patterns (any one may flip a parser's decision):

```
Transfer-Encoding : chunked          ← space before colon
Transfer-Encoding: xchunked          ← value pollution
Transfer-Encoding:\tchunked          ← tab instead of space
Transfer-Encoding:\r\n chunked       ← obsolete line folding
Transfer-Encoding: chunked\r\n
Transfer-Encoding: x                 ← duplicate header (first/last wins)
```

WAFs tend to block these with regex patterns — a **fingerprint-based defense** that catches only known mutations and is trivially bypassable with minor variations. The structural solution is parser-primitive-level normalization rather than pattern matching.



---



## §3. Content-Length Header Obfuscation



Mutations to the `Content-Length` header that cause differential interpretation of body length. While TE obfuscation (§2) is the classic enabling mechanism for CL.TE/TE.CL, CL obfuscation is the **primary enabler for 0.CL attacks** (§1-2) and creates independent framing mismatches when duplicate or malformed CL values are present.

| Technique | Mutation Example | Parser Difference |
|---|---|---|
| **Colon whitespace** | `Content-Length : 42` | Core enabler for 0.CL attacks: Front-End fails to recognize the CL header → treats body as zero; Back-End recognizes it → reads 42 bytes. This single mutation was the foundation for CVE-2025-32094 (Akamai, ~$221K in bounties) |
| **Header duplication** | `Content-Length: 0\r\nContent-Length: 42` | First-wins vs last-wins policy. RFC 7230 requires rejection of conflicting CL values, but most implementations silently pick one |
| **Signs and prefixes** | `Content-Length: +42`, `Content-Length: 042` | Octal vs decimal interpretation: LiteSpeed interprets `010` as octal 8; most others as decimal 10. This two-byte discrepancy is sufficient for smuggling |
| **Non-numeric characters** | `Content-Length: 42abc` | Extract-leading-digits vs reject-entirely policies diverge across implementations |
| **Negative / overflow** | `Content-Length: -1`, extremely large values | Integer parsing underflow (wrapping to large positive) or overflow (wrapping to small positive) in 32-bit vs 64-bit implementations |
| **Digit separators** | `Content-Length: 4_2` | Python servers accept digit-separating underscores; all other implementations reject |
| **Hex prefix** | `Content-Length: 0x2a` | Some implementations parse hex values; others reject or extract leading `0` |



---



## §4. HTTP/2 Binary-Level Header Mutations



Exploiting H2's binary framing to inject or preserve headers that produce different interpretations after downgrade to HTTP/1.1. H2's binary design, combined with HPACK header compression, allows arbitrary characters in arbitrary places — the proxy's downgrade layer is expected to re-impose HTTP/1.1 restrictions, but this validation is frequently skipped.

| Technique | Mechanism | Impact |
|---|---|---|
| **CRLF injection in H2 header values** | `\r\n` is meaningless in H2 but becomes a header delimiter after downgrade → arbitrary header injection | Can inject TE, CL, or any header into the downgraded HTTP/1.1 request. Affects numerous H2→1.1 proxies (python-hyper/h2 GHSA) |
| **Pseudo-header manipulation** | Tampering with `:method`, `:path`, `:authority` pseudo-headers → request-line / Host mismatch after downgrade | Enables path confusion and host mismatch in the downgraded request |
| **Forbidden header passthrough** | `transfer-encoding`, `connection`, `keep-alive`, `upgrade` — headers that H2 spec requires to be stripped — survive the translation | Direct enabler for H2.TE and H2.CL attacks (§1-3) |
| **Special characters in header names** | Characters illegal in HTTP/1.1 header names (null bytes, spaces, colons) inserted via H2 → downgrade parser misidentifies header boundaries | Creates phantom headers or merges adjacent headers |
| **H2C tunneling** | `Upgrade: h2c` initiates clear-text HTTP/2 → bypasses Edge's HTTP/1.1 validation and tunnels raw H2 frames | All subsequent H2 frames bypass the Edge's HTTP/1.1-level inspection entirely |

**Payload — H2 CRLF Injection:**

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

In H2, `\r\n` is just bytes in a header value — no structural meaning. After downgrade to HTTP/1.1: `\r\n` becomes a header delimiter → `Transfer-Encoding: chunked` is injected as a separate header.

**Payload — H2C Tunneling:**

```
GET / HTTP/1.1\r\n
Host: vulnerable.com\r\n
Upgrade: h2c\r\n
Connection: Upgrade, HTTP2-Settings\r\n
HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n
\r\n
```

If the front-end proxy blindly forwards `Upgrade: h2c`, the connection upgrades to clear-text HTTP/2. Subsequent H2 frames bypass all Edge HTTP/1.1-level inspection.



---



## §5. Chunk Encoding Structure Mutations



Mutations to the chunked Transfer-Encoding's internal structure — chunk extensions, chunk-size line terminators, chunk body terminators, and trailer sections. This attack surface emerged as a major independent smuggling vector in 2025, enabling desync **without any CL-vs-TE confusion** — a fundamental shift from the classic CL.TE/TE.CL paradigm.

The root cause: RFC 7230 §4.1 defines chunk extensions as a feature that "nobody uses," leading parsers to discard them without strict validation. The resulting implementation divergence creates exploitable gaps.



### §5-1. Chunk Extension Line Terminator Mutations



These mutations exploit how different parsers treat line-ending characters within or after chunk extensions. The RFC requires strict `\r\n` (CRLF) as line terminators, but implementations vary on accepting bare `\n` (LF), bare `\r` (CR), or treating ambiguous bytes differently.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **TERM.EXT** | `\n` inside a chunk extension: proxy treats it as a line terminator (ending the chunk-size line); Back-End treats it as part of the extension value → the two disagree on where the chunk body starts | Proxy: ATS (CVE-2024-53868), Google Classic ALB ($15K bounty). Server: AIOHTTP (CVE-2024-52304), fasthttp, Gunicorn |
| **EXT.TERM** | Reverse: only the Back-End treats `\n` as a line terminator within a chunk extension, while the proxy processes it as extension content → chunk boundaries shift | Proxy: Imperva CDN ($600 bounty). Server: nginx (won't fix), Jetty, Grizzly, netty, H2O, Go net/http (CVE-2025-22871, $5K bounty) |
| **TERM.SPILL** | Oversized chunk body (body larger than declared chunk-size): proxy ignores the excess bytes ("spill"); Back-End interprets a sequence within the spill as a line terminator + new chunk header | Proxy: Google Classic ALB (CVE-2025-4600, $15K bounty), pound. Server: h11/uvicorn/hypercorn (CVE-2025-43859), Ktor (CVE-2025-29904, $300 bounty), Jetty |
| **SPILL.TERM** | Reverse: Back-End ignores the spill; proxy recognizes a line terminator within it → chunk boundary divergence | Complementary to TERM.SPILL |

**Payload — TERM.EXT:**

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

Proxy: `\n` terminates chunk-size line → chunk size = 2 → reads `GE` → parsing continues. Back-End: `\n` is part of extension → chunk size = 2 → reads `AB` → `GET /admin` is hidden from proxy but visible after desync.

**Payload — TERM.SPILL:**

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

Proxy: reads 5 bytes (`HELLO`), ignores excess bytes until next chunk delimiter. Back-End: reads 5 bytes, treats the excess `GET /admin...` as line terminator + new request.



### §5-2. Chunk Body Terminator Mutations



| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Two-byte terminator overread** | One parser accepts any two bytes as the chunk body line terminator (CRLF); the other accepts a single byte (`\n`) → one-byte boundary shift between chunk bodies | Affects h11, uHTTPd, older llhttp versions. Both "front-end overread" and "back-end overread" variants exist |
| **Incorrect chunk terminators** | Non-standard characters used as chunk body terminators (e.g., `\r\r`, `\n\r`, single `\r`) accepted by lenient parsers, rejected by strict ones | Parser-specific; triggers framing mismatch when paired with a strict counterpart |



### §5-3. Trailer Section Mutations



The chunked encoding trailer section — an optional header section following the last chunk (`0\r\n`) — presents additional attack vectors through parsing inconsistencies.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **TERM.TRAIL** | Proxy ignores lone newlines in trailers; server interprets them as line terminators → pipelined request injected within trailer | Requires an **early-response gadget** (§1-2): AIOHTTP, Koa, Actix Web, and nginx/IIS under specific conditions. Google Classic ALB ($13,337 bounty) |
| **TRAIL.TERM** | Reverse: server ignores lone newlines in trailers; proxy treats them as terminators → "request joining" where two legitimate requests are conflated into one | Bypasses Content-Length validation through trailer ambiguity |
| **Forbidden headers in trailers** | Injecting `Content-Length`, `Transfer-Encoding`, `Host`, or other forbidden headers in chunked trailers → some servers process them, overriding earlier header values | Parser-specific; RFC explicitly forbids these headers in trailers but enforcement varies |



---



## §6. Connection & Protocol Mechanism Mutations



Mutations that exploit **protocol behaviors outside message grammar** — TCP connection reuse, protocol upgrades, TLS layer interactions, and inter-process communication semantics.

| Technique | Mechanism | Key Condition |
|---|---|---|
| **Connection reuse** | Residual bytes on a keep-alive connection concatenated with the next request — the foundational condition for all server-side HRS | Requires `Connection: keep-alive` (default in HTTP/1.1) and the proxy's failure to drain or close the connection after forwarding |
| **Pipelining confusion** | Parsing boundary differences when multiple requests are serialized on a single connection | Distinguishing smuggling from legitimate pipelining is a key detection challenge. CVE-2023-25950 (HAProxy 2.6/2.7): HTX parser incorrectly merges pipelined requests |
| **Connection header stripping** | `Connection: Transfer-Encoding` induces a proxy to strip TE as a hop-by-hop header → Back-End falls back to CL | Creates TE.CL without any TE obfuscation — the proxy itself removes the TE header |
| **Upgrade header abuse** | `Upgrade: h2c` for clear-text H2 (§4); `Upgrade: websocket` for protocol switch → bypasses Edge HTTP/1.1 validation | Some proxies blindly forward Upgrade headers without understanding the protocol switch implications |
| **Expect: 100-continue** | Manipulating the server's `100 Continue` response timing to desynchronize body reading | Vanilla Expect causes 0.CL desync (§1-4). Obfuscated variants (`Expect: y 100-continue`) bypass WAF detection. A second header block in the 100 Continue response can remove security headers |
| **Cross-protocol H2 smuggling** | Residual body bytes reinterpreted as HTTP/2 frames after a protocol switch | CVE-2022-41721 (Go `MaxBytesHandler`): leftover bytes from an HTTP/1.1 request body are parsed as H2 frame data |
| **Service mesh sidecar bypass** | Envoy and similar sidecar proxies failing to sanitize headers before forwarding to upstream services | CVE-2024-23326 (Envoy Proxy): request tunneling via unsanitized header forwarding |
| **Inter-runtime leniency divergence** | Within the same cluster, heterogeneous runtimes (Go, Node.js, Python) apply different parser leniency → intra-cluster desync | Go accepts bare LF (CVE-2025-22871); Node.js accepts bare CR as chunk terminator; Python accepts bare CR as header delimiter; strict proxies reject all of these |



### §6-1. TLS-Layer Desync



| Technique | Mechanism | Key Condition |
|---|---|---|
| **TLS Upgrade Desync** | HTTP desync during TLS upgrade process → session hijacking even over encrypted connections | CVE-2025-49812 (Apache ≤2.4.63): only configurations using `SSLEngine optional` |
| **Opossum Attack (Cross-Protocol TLS Desync)** | MitM intercepts victim's implicit TLS connection (port 443) and redirects to server's opportunistic TLS port (port 80 with `Upgrade: TLS/1.0`) → TLS handshake succeeds, but the application-layer protocol state diverges between client and server → **permanent** response stream desync | Requires: (1) server supporting both implicit and opportunistic TLS, (2) MitM position. Affects HTTP, SMTP, FTP, POP3, LMTP, NNTP. 3M+ hosts potentially vulnerable. Bypasses all ALPACA (2021) countermeasures because the vulnerability is in the application-layer protocol design (implicit + opportunistic TLS coexistence), not in TLS certificate validation |

**Opossum Attack Classes (HTTP context):**

| Class | Impact |
|---|---|
| **Resource confusion** | Server delivers incorrect content to the client |
| **Session fixation** | Attacker forces victim into an attacker-controlled session |
| **Reflected XSS escalation** | Converts self-XSS into full cross-origin exploitation |
| **Cookie leakage** | Implementation-specific flaws leak authentication cookies |

Detection: `curl -H "Upgrade: TLS/1.0" -i http://target.com` → a `101 Switching Protocols` response indicates vulnerability. Mitigation: disable opportunistic TLS entirely; migrate to implicit-only configurations.



---



## §7. Request-Line & Method Divergence



Mutations in the request line (method, URI, HTTP version) and method-body association semantics. Systematic differential fuzzing demonstrated that mutations in **all parts of a request** — not just CL/TE headers — can cause body parsing discrepancies leading to smuggling, overturning the assumption that only the `Content-Length` and `Transfer-Encoding` headers were relevant.

| Technique | Description | Confirmed Exploitable |
|---|---|---|
| **Unknown method handling** | How servers determine body presence for non-standard methods (e.g., `CATS`, `PURGE`). Some assume body-present, others assume body-absent → framing mismatch without any CL/TE manipulation | Multiple proxy-origin pairs via grammar-based fuzzing |
| **Method-body association** | Certain methods (GET, HEAD, DELETE) have ambiguous body semantics per RFC. A proxy may forward a GET body; the origin may ignore it → CL.0 variant | Akamai ignores the request body for certain methods while Tomcat/HAProxy/ATS parse and forward it |
| **HTTP version string** | Acceptance/rejection and behavioral changes for `HTTP/1.2`, `HTTP/0.9`, `HTTP/2.0` in HTTP/1.1 request lines — some servers downgrade behavior, others reject entirely | Parser-specific behavioral changes |
| **Request-line whitespace** | Extra spaces or tabs in `GET /path HTTP/1.1` — some parsers accept arbitrary whitespace between method, URI, and version; others reject | Multiple pairs: request-line mutations causing body parsing discrepancies |
| **Request-line field mutations** | Manipulating SP/CRLF placement within the request line, URI-encoding of method or version string | Multiple proxy-origin pairs where these mutations alone triggered smuggling |
| **Terminated request-line manipulation** | Inserting a space or tab after the header-terminating CRLF → certain servers treat it differently | ATS ignores the request body in these cases while NGINX, Cloudflare, and CloudFront do not |



---



## §8. Low-Level Parser Implementation Divergence



Micro-level differences in how individual servers and proxies implement HTTP parsing relative to the RFC. These underlie all mutations in §1–§7 and are systematically discoverable via differential fuzzing. Six major research efforts have collectively mapped this divergence surface across 50+ server/proxy implementations, revealing that RFC language ambiguity (SHOULD vs MUST, undefined edge cases) is itself a *systematic source* of parser divergence — not just individual implementation bugs.



### §8-1. Line Termination and Whitespace Divergence



| Technique | Description | Confirmed Exploitable Pairs |
|---|---|---|
| **Bare LF (`\n` without `\r`)** | Using LF-only line endings — acceptance/rejection varies per server | Go net/http accepts bare LF (CVE-2025-22871, $5K bounty) → strict proxies reject it; Node.js → ATS/Akamai/Google Cloud |
| **Bare CR (`\r` without `\n`)** | Python's `http.server` and Google Cloud load balancer accept bare CR as header delimiters → enables header injection when paired with strict proxies | Python/Google Cloud → strict origin servers |
| **Request-line whitespace** | Extra spaces or tabs in `GET /path HTTP/1.1` — some parsers accept arbitrary whitespace; others reject | Multiple proxy-origin pairs (see §7) |
| **Empty header values** | `Header-Name:` (no value) — some implementations merge with previous header, creating phantom combined headers | Parser-specific |
| **Special characters in header names** | Underscores (`_`), dots (`.`), spaces — Nginx defaults to `underscores_in_headers off`, silently dropping headers containing underscores | Nginx → origins that accept underscore headers |
| **Null bytes in headers** | `\x00` in header name or value — some proxies truncate, others pass through, some concatenate with adjacent headers | OpenBSD relayd concatenates headers containing null bytes |
| **Header-terminating CRLF mutations** | Space or tab inserted after the `\r\n\r\n` header terminator — some servers treat the extra whitespace as part of the body, others ignore it | ATS ignores body; NGINX/Cloudflare/CloudFront process it |
| **Line without colon** | A line in the headers block that lacks a `:` separator — some servers reject (400), others silently drop the line | Apache, H2O, HAProxy, Envoy reject; ATS drops and forwards |



### §8-2. Integer and Length Parsing Divergence



| Technique | Description | Confirmed Exploitable Pairs |
|---|---|---|
| **Leading zeros / Octal interpretation** | `Content-Length: 010` — LiteSpeed interprets as octal (8), most others as decimal (10). This two-byte discrepancy is sufficient for smuggling | LiteSpeed → non-normalizing proxies |
| **Hex prefix and signs** | `0x` prefix, `+42`, `-1` in CL and chunk sizes — extract-leading-digits vs reject-entirely policies diverge | Multiple pairs via grammar-based fuzzing |
| **Integer overflow** | Extremely large CL values wrapping around in 32-bit vs 64-bit implementations — `Content-Length: 4294967396` wraps to 100 in 32-bit | Architecture-dependent |
| **Chunk size parsing** | Non-standard characters after hex digits in chunk-size field — semicolon (extension), space, other characters handled inconsistently | ATS mishandles invalid chunk sizes like `0_ff` |
| **Digit-separating underscores** | `Content-Length: 4_2` — Python servers accept; all others reject | Python origins → non-Python proxies |



### §8-3. Semantic Gap Attacks



A specification-driven approach: using NLP to extract MUST/SHOULD/MAY rules from RFC documents, then generating test cases targeting rule boundaries. This revealed three systematic categories of semantic gap across 10 HTTP implementations (Apache, Nginx, Tomcat, Weblogic, IIS, Squid, ATS, HAProxy, Caddy, Lighttpd), resulting in 14 vulnerabilities, 29 affected server pairs, and **7 CVEs**:

| Gap Type | Description | Example |
|---|---|---|
| **Interpretation gap** | Same header/field parsed to different semantic values by two implementations | CL with leading zeros: octal vs decimal; `,chunked` treated as `chunked` vs rejected |
| **Prioritization gap** | When conflicting information exists (duplicate headers, CL+TE), implementations apply different priority rules | First-wins vs last-wins for duplicate CL; TE-takes-precedence vs CL-takes-precedence |
| **Tolerance gap** | Implementations differ on whether to accept, normalize, or reject malformed input | Obsolete line folding accepted by some, rejected by others; bare LF/CR handling; empty CL header values |

The key insight: RFC language ambiguity (SHOULD vs MUST, undefined edge cases, silent on certain malformation behaviors) is itself a *systematic source* of parser divergence. Every SHOULD that lacks a clear fallback behavior, and every edge case the RFC is silent on, creates a potential divergence point across implementations.



### §8-4. Response & CGI Parsing Divergence



Parsing discrepancies in *response* processing — not just requests — enable an additional class of desync. When a proxy and origin disagree on where a *response* body ends, the proxy misaligns the response queue, causing subsequent responses to be paired with the wrong requests.

| Subtype | Description | Impact |
|---|---|---|
| **Response framing mismatch** | Proxy and origin disagree on response body length → response queue misalignment | Enables response forgery (attacker-controlled response delivered to victim) and response stealing (victim's response delivered to attacker) |
| **Response ordering issues** | Disagreement on which response corresponds to which request in pipelined/multiplexed connections | Enables cross-user response leakage |
| **CGI response parsing divergence** | HTTP servers and CGI/FastCGI backends parse CGI response headers differently — disagreements on header termination, status line format, and content-length semantics in CGI output | Creates a secondary desync surface between the web server and its CGI processor |

Gray-box coverage-directed differential testing extending desync discovery to HTTP responses and CGI responses systematically identified these classes, resulting in 9 CVEs across multiple vendors (including response smuggling, response forgery, and response stealing vulnerabilities).



---



## Attack Scenario Mapping (Axis 3)



How the mutations above are **weaponized** under specific architectural conditions.

| Scenario | Architecture | Primary Mutation Categories | Key Example |
|---|---|---|---|
| **Server-Side HRS** | Front-End (proxy/CDN/WAF) ↔ Back-End with persistent connection | §1 + §2/§3 + §7/§8 | Classic CL.TE/TE.CL against PayPal ($20K+$18.9K bounties, 2019) |
| **Client-Side Desync (CSD)** | Single server possible; victim's browser desyncs its own HTTP/1.1 connection | §1-2 (CL.0) + §1-4 (Pause) + §6 | Attacker-controlled JS triggers CL.0 on victim's browser connection pool → backdoor installation |
| **Browser-Powered Desync** | Attacker JS → victim's browser → target server | §1-2 + §6; requires target lacking HTTP/2 | Cache poisoning via browser connection pool desync, desync worms |
| **Response Queue Poisoning (RQP)** | Post-desync response queue corruption → stealing other users' responses | §1 (all framing) + §2/§3 | HEAD request CL + response concatenation: HEAD response declares `Content-Length: 54321` but has no body → next response's first 54K bytes consumed as "body" → entire queue shifts |
| **Response Smuggling / Splitting** | Two complete requests smuggled → response queue desync → attacker-controlled response delivered to victim | §1 + §2/§3 + §6 | Requires timing differential (sleepy request). Enables HttpOnly cookie theft |
| **Cache Poisoning via Desync** | CL.0 desync poisons CDN's 3xx redirect into global cache | §1-2 (CL.0) + CDN cache | Akamai/Azure/Oracle CDN global cache poisoned via CL.0 + redirect endpoint |
| **Cache Poisoning → C2** | CL.0 global cache poisoning weaponized: Location header of 3xx redirects repurposed as covert C2 channel | §1-2 (CL.0) + CDN cache + operational tradecraft | GET-based gadgets avoid POST logging; Base64/AES payloads in Location header; bidirectional C2 via CDN cache poll/inject. Targets include `.mil`, `.gov` domains |
| **Microservice Internal Desync** | Service mesh (Envoy/Istio) + heterogeneous runtimes (Go/Node/Python) with differing parser leniency | §6 + §8; manifests even on internal networks | Go (bare LF) ↔ Node.js (bare CR) ↔ Python (underscores, bare CR) — no external attacker required if any microservice processes untrusted input |
| **Cross-Protocol TLS Desync (Opossum)** | MitM + server supporting both implicit and opportunistic TLS → permanent response stream desync | §6-1 (TLS / Opossum) | Affects HTTP, SMTP, FTP, POP3 beyond HTTP; 3M+ hosts. CVE-2025-49812 |
| **Response Desync / CGI Desync** | Proxy and origin disagree on response body boundaries or CGI output parsing → response queue misalignment | §8-4 (response/CGI divergence) | Response forgery, response stealing. 9 CVEs |

**Composite Payload — CL.TE → Response Queue Poisoning:**

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

1. Attacker sends CL.TE smuggle.
2. `GET /private/dashboard` is queued as the next request on the same connection.
3. Victim's request arrives on the same connection → Back-End pairs it with attacker's response slot.
4. Attacker receives `/private/dashboard` response (victim's data).

**Composite Payload — CL.TE + HEAD → Cache Poisoning:**

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

`HEAD /large-page` returns headers with `Content-Length: 54321` but no body → the next response on the connection has its first 54,321 bytes consumed as the HEAD's "body" → entire response queue shifts → cache stores wrong response for wrong URL.



---



## CVE / Bounty Mapping (2022–2025)



| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §1-2 (0.CL) + §3 (CL whitespace) + Early Response Gadget + §2-2 (line folding) | CVE-2025-32094 (Akamai) | ~$221,000 across 74 bounties. Tens of millions of sites affected; 65-day patch cycle. Obfuscated Expect variants and OPTIONS-specific parser paths exploited |
| §1-2 (0.CL) + §1-4 (Expect) + double-desync | 2025 Cloudflare/Netlify campaign | $350K+ total bounties (Akamai+Cloudflare+Netlify combined). Cloudflare: H2.0 variant, 24M websites, $7K. Donated to charity |
| §5-1 (TERM.EXT / chunk extension) | CVE-2025-55315 (ASP.NET Core Kestrel) | CVSS 9.9 — Microsoft's highest-ever for ASP.NET Core. $10K bounty. Bare `\n` handling divergence in chunk extensions → request + response smuggling. Affects .NET 8.0.0–8.0.20, 9.0.0–9.0.9, 10.0.0-rc1 |
| §5-1 (TERM.EXT) | CVE-2024-53868 (Apache Traffic Server) | Chunk extension line terminator divergence → proxy-side smuggling |
| §5-1 (TERM.EXT) | Google Classic ALB | $15,000. Chunk extension bare `\n` treated as line terminator by ALB |
| §5-1 (EXT.TERM) | Imperva CDN disclosure (2025.08) | $600. Proxy ignores malformed extension; Back-End treats `\n` as chunk header end |
| §5-1 (SPILL.TERM) | CVE-2025-4600 (Google Classic ALB) | $15,000. Oversized chunk body spill interpreted differently |
| §5-1 (SPILL.TERM) | CVE-2025-43859 (h11/uvicorn/hypercorn) | Python ASGI server chunk body spill vulnerability |
| §5-1 (SPILL.TERM) | CVE-2025-29904 (Ktor) | $300. Kotlin server chunk handling |
| §5-3 (TERM.TRAIL) | Google Classic ALB | $13,337. Trailer section lone newline divergence |
| §1-2 (TE.0) | Google Cloud Load Balancer | $8,500 (Google VRP). TE not supported by back-end |
| §1-3 (H2.CL) | Netflix (Netty library) | $20,000. Netty failed to validate CL against H2 frame length |
| §1-3 (H2.TE) | Netlify CDN | Every hosted site vulnerable including Firefox start page |
| §1-3 (H2.0) | AWS ALB | Patched within 5 days of report |
| §1-3 (H2.0) | Cloudflare internal downgrade | $7,000. Internal H2→H1 downgrade, 24M websites |
| §1-4 (Expect-based 0.CL) | T-Mobile | $12,000. Vanilla `Expect: 100-continue` causing 0.CL desync on staging environment |
| §4 (H2 CRLF injection) | python-hyper/h2 GHSA | Affects numerous H2→1.1 proxies |
| §6-1 (Opossum / cross-protocol TLS desync) | CVE-2025-49812 (Apache ≤2.4.63) | Permanent desync when implicit + opportunistic TLS coexist. 3M+ hosts potentially vulnerable. Apache deprecated opportunistic HTTP |
| §8-1 (bare LF acceptance) | CVE-2025-22871 (Go net/http) | $5,000. Go runtime accepts bare LF as line terminator → microservice desync via EXT.TERM chunk extension exploitation |
| §6 (sidecar bypass) | CVE-2024-23326 (Envoy Proxy) | Service mesh sidecar request tunneling via unsanitized header forwarding |
| §1-2 (CL.0) + global cache poisoning + C2 | 2025 research | CL.0 desync poisons 3xx redirects in Akamai/Azure/Oracle CDN global cache; Location header used as covert C2 channel. Targets include `.mil`, `.gov`, `.cn` domains |
| §6 (pipelining) | CVE-2023-25950 (HAProxy 2.6/2.7) | HTX parser incorrectly merges pipelined requests |
| §8 (request-line + header divergence) | CVE-2023-25725 (HAProxy) | Critical. Empty header name (line without colon) parsing discrepancy; graybox fuzzing discovery |
| §8 (header parsing divergence) | CVE-2023-33934 (Apache Traffic Server) | Critical. Proxy-origin parsing discrepancy enabling access control bypass and cache poisoning; graybox fuzzing discovery |
| §8-3 (semantic gap) | 7 CVEs (Apache, Tomcat, Weblogic, IIS) | Specification-driven testing: interpretation, prioritization, and tolerance gaps across 29 server pairs |
| §8-4 (request + response + CGI parsing) | 9 CVEs (multiple vendors) | Gray-box testing: request desync, response forgery, response stealing, response ordering issues |
| §6 (cross-protocol H2) | CVE-2022-41721 (Go net/http MaxBytesHandler) | Residual bytes reinterpreted as H2 frames after protocol switch |
| §1-1 (CL.TE/TE.CL) | PayPal (2019) | $20,000 + $18,900 (bypass fix bounty). Classic CL.TE against Akamai-fronted PayPal |
| §5-1 (TERM.EXT) | CVE-2024-52304 (AIOHTTP) | Server-side chunk extension vulnerability |
| §1-4 (Expect obfuscated) | LastPass via Akamai | $5,000. `Expect: 100-continue Content-Length` configuration abuse → authentication domain compromise |
| §1-4 (Expect obfuscated) | EXNESS | $7,500. Obfuscated Expect-based desync |
| §1-4 (Expect obfuscated) | GitLab (h1.sec.gitlab.net) | $7,000. Response Queue Poisoning accessing vulnerability report attachments via obfuscated Expect; required 27,000 requests to trigger race condition |



---



## Detection Tools



### Research Fuzzers (Systematic Discovery)

| Tool | Target Scope | Core Technique | Venue / Year |
|---|---|---|---|
| **T-Reqs** | Proxy-origin pairs (HTTP/1.1). Tested 10 server technologies in pairwise combinations | Grammar-based differential fuzzer. First to demonstrate that mutations in *all* request components (request line, headers, body) — not just CL/TE — can cause body parsing discrepancies leading to smuggling | CCS 2021 |
| **FRAMESHIFTER** | H2→H1 conversion in 12 reverse proxy technologies and CDNs (Apache, Nginx, HAProxy, Envoy, Varnish, Cloudflare, Fastly, AWS CloudFront, others) | Grammar-based HTTP/2 frame sequence fuzzer with content and sequence mutations. First systematic exploration of H2→H1 conversion anomalies. Discovers Request Blackholing, Query-of-Death, conversion-induced smuggling | USENIX Security 2022 |
| **HDiff** | 10 HTTP implementations (Apache, Nginx, Tomcat, Weblogic, IIS, Squid, ATS, HAProxy, Caddy, Lighttpd) | Semi-automatic: NLP extracts MUST/SHOULD rules from RFC documents → generates targeted test cases → differential testing. Specification-driven rather than grammar-driven. DSN 2022 Best Paper Runner-Up | DSN 2022 |
| **HTTP Garden** | 27 origin servers + 12 proxies (39 total: Aiohttp, Apache, Bun, CherryPy, Daphne, Deno, fasthttp, Go, Gunicorn, H2O, Hyper, Hypercorn, Jetty, libevent, libsoup, Lighttpd, Mongoose, Nginx, Node.js, OpenLiteSpeed, OpenBSD httpd, Passenger, Puma, Tomcat, Tornado, uhttpd, Unicorn, Uvicorn, Waitress, WEBrick, Werkzeug + proxies) | Coverage-guided differential fuzzing of HTTP/1.1 *request streams* (not individual requests). Fine path δ-diversity metric for parent selection. Interactive REPL for discrepancy exploration. Found 122 discrepancies, 39 exploitable, 68 patches | DEF CON 31 / 2024 |
| **Gudifu** | 6 reverse proxies (Apache httpd, NGINX, H2O, ATS, HAProxy, Envoy) with graybox instrumentation | Graybox differential fuzzing — uses coverage feedback from proxy internals to guide mutation across full HTTP request space. Discovers significantly more discrepancies than blackbox approaches. CVE-2023-33934 (ATS), CVE-2023-25725 (HAProxy) | RAID 2024 |
| **HDHunter** | Multiple servers (request + response + CGI response parsing) | Gray-box coverage-directed differential testing. First tool to systematically discover *response* and *CGI response* parsing discrepancies alongside request desync. 9 CVEs | USENIX Security 2025 |

### Offensive / Exploitation Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **HTTP Request Smuggler v3.0** (Burp extension) | Server-side + H2 + CSD + 0.CL + Expect-based | Primitive-level parser discrepancy detection via V-H (visible to front-end, hidden from back-end) and H-V (hidden from front-end, visible to back-end) probes. Bypasses fingerprint-based defenses |
| **smuggler.py** | Server-side HRS | CL.TE, TE.CL, TE.TE + mutation mode |
| **smugchunks** | Chunk extension HRS | Automated TERM.EXT, EXT.TERM, TERM.SPILL, SPILL.TERM, TERM.TRAIL detection via timeout-based probing |
| **h2cSmuggler** | H2C tunneling | Clear-text HTTP/2 upgrade automation |
| **http2smugl** | HTTP/2 request smuggling | H2→H1 downgrade desync detection |
| **Turbo Intruder** (Burp extension) | Timing / race-based | Pause-based desync, 0.CL exploit scripts (`0cl-find-offset`, `0cl-poc`, `0cl-exploit`), single-packet race conditions |
| **DesyncCL0** | Client-side desync (CSD) | CL.0 browser-powered desync detection |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **HTTP Desync Guardian** (AWS) | Inbound request classification | Risk-grades requests by analyzing CL/TE combination anomalies and blocks suspicious patterns |
| **YARP** (Azure) | Reverse proxy normalization | Azure App Services protected via YARP proxy that normalizes requests before forwarding to Kestrel |
| **RFC-strict normalizers** | Inbound request normalization | Enforce strict RFC compliance: strip obsolete line folding, reject conflicting CL/TE, reject bare LF/CR, canonicalize chunk extensions, reject non-CRLF terminators |



---



## Summary: Core Principles



All HTTP Request Smuggling mutations ultimately stem from **one fact**: HTTP/1.1 is a text-based protocol that offers multiple methods for specifying message boundaries, and thousands of independent implementations interpret the specification with varying degrees of leniency. HTTP/2 downgrading adds a fourth length interpretation method, expanding the mismatch combinatorics. The protocol's fundamental design — conveying structured data through text that must be parsed identically by every agent in the chain — guarantees divergence when the specification uses SHOULD instead of MUST, is silent on edge cases, or deprecates features (like obsolete line folding) without mandating rejection.

**The 2025 turning point.** Three developments defined this year. First, **chunk extensions emerged as a major independent attack surface** (§5). A feature "nobody uses" enables TERM.EXT / EXT.TERM / SPILL mutations that achieve smuggling *without any CL-vs-TE confusion* — a fundamental shift from the 20-year-old CL.TE/TE.CL paradigm. CVE-2025-55315 (CVSS 9.9, Microsoft's highest-ever for ASP.NET Core) demonstrated the severity. Second, **the attack surface expanded into the TLS layer** (§6-1). The Opossum Attack exploits a protocol design weakness — the coexistence of implicit and opportunistic TLS — to achieve *permanent* desync without any implementation bug, affecting 3M+ hosts across HTTP, SMTP, FTP, and POP3. Third, **desync began to be repurposed as attack infrastructure**: CL.0 global cache poisoning weaponized the Location header of 3xx redirects as a covert C2 side channel, turning CDN infrastructure into bidirectional command-and-control channels against `.mil` and `.gov` targets.

**Evolution of discovery methodology.** The vulnerability discovery approach has undergone a paradigm shift from manual payload crafting to systematic automated fuzzing, with each generation uncovering classes invisible to its predecessors:

| Generation | Approach | Key Innovation |
|---|---|---|
| Manual (2005–2019) | Hand-crafted CL.TE/TE.CL payloads | Proved the concept; worked on ~1/3 of the internet |
| Grammar-based blackbox (2021) | Full-request grammar mutations, pairwise testing | Showed request-line and header mutations beyond CL/TE cause smuggling |
| H2 frame fuzzing (2022) | H2 frame sequence grammar mutations | Discovered Request Blackholing, Query-of-Death, conversion-induced smuggling |
| Specification-driven (2022) | NLP on RFCs → targeted test generation | Revealed semantic gap attacks (interpretation, prioritization, tolerance) |
| Coverage-guided stream-level (2023–2024) | Coverage feedback on origin servers, request *streams* not individual requests | 122 discrepancies across 39 implementations; 39 exploitable |
| Graybox proxy (2024) | Coverage feedback from proxy *internals* | Critical CVEs in HAProxy and ATS invisible to blackbox approaches |
| Response + CGI (2025) | Gray-box testing of response and CGI output parsing | Extended desync beyond requests; 9 CVEs in response handling |
| 0.CL at scale + chunk extensions (2025) | Early response gadgets, double-desync, chunk extension mutations | $350K+ bounties, CVSS 9.9, C2 infrastructure weaponization |

Six years of individual patches and regex-based defenses block only **known mutation fingerprints** without resolving the fundamental parser divergence. The structural solution requires three concurrent efforts: (1) **upstream HTTP/2 adoption** — eliminating framing mismatch by removing text-based length interpretation entirely (but as of 2025, Cloudflare downgrades H2→H1 internally, and Nginx/Akamai/CloudFront/Fastly lack upstream H2 support); (2) **opportunistic TLS deprecation** — eliminating TLS-layer desync; and (3) **RFC-strict normalization proxies** — enforcing a single interpretation at the network edge before requests reach heterogeneous backends. From a detection perspective, the necessary shift is from exploit-pattern matching to identifying **parser-primitive-level discrepancies themselves** — the approach embodied in HTTP Request Smuggler v3.0's V-H/H-V probing methodology.



---



*This document was created for defensive security research and vulnerability understanding purposes.*



## References

### Foundational Research

- Linhart, Klein, Heled, Orrin — *HTTP Request Smuggling* (2005). The original whitepaper defining CL.TE and TE.CL attack classes.
- James Kettle — *HTTP Desync Attacks: Smashing into the Cell Next Door* (DEF CON 27 / Black Hat USA 2019). Revived HRS research; demonstrated at scale against PayPal ($20K+$18.9K bounties), Red Hat, and others ($70K+ total); introduced HTTP Request Smuggler Burp extension. Worked on ~1/3 of the internet.
- James Kettle — *HTTP/2: The Sequel is Always Scarier* (Black Hat USA 2021 / DEF CON 29). H2.CL, H2.TE, H2.0 downgrade attacks; H2 CRLF injection; pseudo-header manipulation. Netflix ($20K), Netlify (every hosted site), AWS ALB.
- James Kettle — *Browser-Powered Desync Attacks: A New Frontier in HTTP Request Smuggling* (Black Hat USA 2022 / DEF CON 30). Client-Side Desync (CSD), Pause-based desync, CL.0. Compromised Amazon, Apache, Akamai, Varnish, web VPNs. Introduced browser connection pool poisoning and desync worms.
- James Kettle — *HTTP/1.1 Must Die: The Desync Endgame* (Black Hat USA 2025 / DEF CON 33). 0.CL with Early Response Gadgets, double-desync (0.CL→CL.0 conversion), Expect-based desync (vanilla and obfuscated), V-H/H-V discrepancy detection methodology, HTTP Request Smuggler v3.0. $350K+ bounties across Akamai (CVE-2025-32094, ~$221K / 74 bounties / 65-day patch), Cloudflare (24M websites, $7K), Netlify, T-Mobile ($12K), GitLab ($7K), LastPass ($5K), EXNESS ($7.5K). All bounties donated to charity. Published `http1mustdie.com`.

### Systematic Fuzzing Research

- Bahruz Jabiyev, Steven Sprecher, Kaan Onarlioglu, Engin Kirda — *T-Reqs: HTTP Request Smuggling with Differential Fuzzing* (ACM CCS 2021). First systematic HRS exploration; grammar-based fuzzer demonstrating that request-line and header mutations beyond CL/TE cause smuggling. Tested 10 server technologies in pairwise combinations. Found that Akamai ignores body for certain methods, ATS/Squid ignore body with `identity` TE, Apache ignores body with `Expect: 100-continue`. GitHub: `bahruzjabiyev/t-reqs`.
- Bahruz Jabiyev, Steven Sprecher, Anthony Gavazzi, Tommaso Innocenti, Kaan Onarlioglu, Engin Kirda — *FRAMESHIFTER: Security Implications of HTTP/2-to-HTTP/1 Conversion Anomalies* (USENIX Security 2022). Grammar-based H2 frame sequence fuzzer; first systematic exploration of H2→H1 conversion anomalies across 12 proxy/CDN technologies. Discovered Request Blackholing, Query-of-Death, and conversion-induced smuggling. GitHub: `bahruzjabiyev/frameshifter`.
- Kaiwen Shen, Jianjun Chen et al. — *HDiff: A Semi-automatic Framework for Discovering Semantic Gap Attack in HTTP Implementations* (IEEE DSN 2022, Best Paper Runner-Up). NLP-driven specification rule extraction from RFCs + differential testing across 10 implementations; 14 vulnerabilities, 29 affected server pairs, 7 CVEs across Apache, Tomcat, Weblogic, IIS. Three semantic gap types: interpretation, prioritization, tolerance. GitHub: `mo-xiaoxi/HDiff`.
- Ben Kallus, Prashant Anantharaman, Michael E. Locasto, Sean W. Smith — *The HTTP Garden: Discovering Parsing Vulnerabilities in HTTP/1.1 Implementations by Differential Fuzzing of Request Streams* (DEF CON 31 / 2024). Coverage-guided stream-level differential fuzzing across 27 origin servers and 12 proxies (39 total); 122 discrepancies, 39 exploitable, 68 patches. Key findings: LiteSpeed octal CL, Python digit separators, Node.js bare CR, Puma two-byte terminator, ATS `0_ff` chunk parsing. Interactive REPL for discrepancy development. GitHub: `narfindustries/http-garden`.
- Bahruz Jabiyev, Anthony Gavazzi, Kaan Onarlioglu, Engin Kirda — *Gudifu: Guided Differential Fuzzing for HTTP Request Parsing Discrepancies* (RAID 2024). Graybox coverage-directed fuzzing of 6 proxy internals (Apache httpd, NGINX, H2O, ATS, HAProxy, Envoy); significantly more discrepancies than blackbox approaches. CVE-2023-33934 (ATS, critical), CVE-2023-25725 (HAProxy, critical — empty header name parsing). GitHub: `bahruzjabiyev/gudifu-fuzzer`.
- Keran Mu, Jianjun Chen, Jianwei Zhuge, Qi Li, Haixin Duan, Nick Feamster — *The Silent Danger in HTTP: Identifying HTTP Desync Vulnerabilities with Gray-box Testing* (USENIX Security 2025). Gray-box coverage-directed differential testing; first to extend desync discovery to HTTP responses and CGI responses. 9 CVEs across request desync, response forgery, response stealing, response ordering.
- James Kettle — *Smashing the State Machine: The True Potential of Web Race Conditions* (Black Hat USA 2023). Timing-based desync and single-packet attacks; foundational work for pause-based and race-based desync exploits.

### 2025 Research
- Jeppe Bonde Weikop — *Funky Chunks: Abusing Ambiguous Chunk Line Terminators for Request Smuggling* (2025). Novel chunk extension smuggling class: TERM.EXT, EXT.TERM, TERM.SPILL, SPILL.TERM. Smuggling without CL-vs-TE confusion. Google ALB ($15K×2), Imperva ($600). `smugchunks` scanner tool. *Funky Chunks Addendum* (2025.10): TERM.TRAIL, TRAIL.TERM, two-byte terminator overread. Google ALB ($13,337). Blog: `w4ke.info`.
- Robert Merget, Nurullah Erinola, Marcel Maehren, Lukas Knittel, Sven Hebrok, Marcus Brinkmann, Juraj Somorovsky, Jörg Schwenk — *Opossum Attack: Cross-Protocol TLS Desync* (2025). Permanent desync via implicit + opportunistic TLS coexistence. 3M+ hosts affected. CVE-2025-49812 (Apache ≤2.4.63). Affects HTTP, SMTP, FTP, POP3, LMTP, NNTP. Bypasses ALPACA countermeasures. Site: `opossum-attack.com`.
- Cache Poisoning → C2 Side Channel research (2025). CL.0 desync weaponized for covert C2 via CDN global cache Location header poisoning. Targets: Akamai, Azure, Oracle CDN; `.mil`, `.gov`, `.cn` domains. Blog: `malicious.group`.

### CVEs

| CVE | Component | Description |
|---|---|---|
| CVE-2025-55315 | ASP.NET Core Kestrel | CVSS 9.9. Chunk extension bare `\n` handling divergence → request + response smuggling. $10K bounty. Affects .NET 8/9/10 |
| CVE-2025-49812 | Apache HTTP Server ≤2.4.63 | TLS Upgrade Desync / Opossum. Permanent desync when `SSLEngine optional` enables opportunistic TLS. Apache deprecated opportunistic HTTP |
| CVE-2025-32094 | Akamai CDN | 0.CL + CL whitespace obfuscation + obsolete line folding + Expect variants. ~$221K / 74 bounties / 65-day patch. Tens of millions of sites |
| CVE-2025-22871 | Go net/http | Bare LF acceptance as line terminator → microservice desync + EXT.TERM chunk extension exploitation. $5K bounty |
| CVE-2025-43859 | h11 (uvicorn/hypercorn) | SPILL.TERM chunk body terminator divergence |
| CVE-2025-29904 | Ktor | Chunk body spill handling divergence. $300 bounty |
| CVE-2025-4600 | Google Classic ALB | SPILL.TERM chunk extension smuggling. $15K bounty |
| CVE-2024-53868 | Apache Traffic Server | TERM.EXT chunk extension line terminator divergence |
| CVE-2024-52304 | AIOHTTP | TERM.EXT chunk extension vulnerability |
| CVE-2024-23326 | Envoy Proxy | Service mesh sidecar request tunneling |
| CVE-2023-33934 | Apache Traffic Server | Critical. Proxy-origin parsing discrepancy enabling access control bypass and cache poisoning (Gudifu graybox discovery) |
| CVE-2023-25950 | HAProxy 2.6/2.7 | HTX parser incorrectly merges pipelined requests |
| CVE-2023-25725 | HAProxy | Critical. Empty header name (line without colon) parsing discrepancy (Gudifu graybox discovery) |
| CVE-2022-41721 | Go net/http (MaxBytesHandler) | Cross-protocol smuggling: residual bytes reinterpreted as H2 frames |

### Tools

| Tool | URL / Source |
|---|---|
| T-Reqs | `https://github.com/bahruzjabiyev/t-reqs` |
| FRAMESHIFTER | `https://github.com/bahruzjabiyev/frameshifter` |
| HDiff | `https://github.com/mo-xiaoxi/HDiff` |
| HTTP Garden | `https://github.com/narfindustries/http-garden` |
| Gudifu | `https://github.com/bahruzjabiyev/gudifu-fuzzer` |
| HTTP Request Smuggler v3.0 | Burp Suite BApp Store (PortSwigger) |
| smuggler.py | `https://github.com/defparam/smuggler` |
| smugchunks | Chunk extension smuggling scanner (w4ke.info) |
| h2cSmuggler | `https://github.com/BishopFox/h2csmuggler` |
| http2smugl | `https://github.com/neex/http2smugl` |
| Turbo Intruder | Burp Suite BApp Store (PortSwigger) |
| DesyncCL0 | `https://github.com/riramar/DesyncCL0` |
| HTTP Desync Guardian | AWS — request risk classification |

### Specifications

- RFC 7230 — *HTTP/1.1 Message Syntax and Routing* (obsoleted by RFC 9110/9112). §3.3.3 (Message Body Length), §3.2.4 (Field Parsing — obsolete line folding), §4.1 (Chunked Transfer Coding — chunk extensions).
- RFC 9110 — *HTTP Semantics* (2022). Successor to RFC 7231 (semantics). Note: RFC 7230 (message syntax) is succeeded by RFC 9112.
- RFC 9112 — *HTTP/1.1* (2022). Updated message framing rules.
- RFC 9113 — *HTTP/2* (2022). Binary framing, pseudo-headers, forbidden connection-specific headers.
- RFC 2817 — *Upgrading to TLS Within HTTP/1.1* (2000). Defines opportunistic TLS upgrade mechanism exploited by Opossum attack.
