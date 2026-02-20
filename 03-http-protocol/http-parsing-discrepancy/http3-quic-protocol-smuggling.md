# HTTP/3 & QUIC Protocol-Level Smuggling — Mutation Taxonomy



---



## Classification Structure



HTTP/3 (RFC 9114) replaces HTTP/2's TCP+TLS transport with QUIC (RFC 9000), a UDP-based multiplexed transport with built-in encryption. While HTTP/3 inherits the binary framing model of HTTP/2, the QUIC transport layer introduces entirely new attack surfaces absent from both HTTP/1.1 and HTTP/2: UDP-based connection semantics, QPACK header compression, 0-RTT early data, connection migration, and QUIC-native stream multiplexing. This taxonomy classifies the mutation space specific to HTTP/3 and QUIC that extends beyond the HTTP/1.1 and HTTP/2 smuggling techniques documented in the companion HTTP Request Smuggling taxonomy.

- **Axis 1 — Mutation Target** (primary): *What structural component of the HTTP/3 or QUIC message is mutated?* This axis organizes the main body of the document (§1–§5).
- **Axis 2 — Discrepancy Type** (cross-cutting): *What kind of interpretation mismatch does the mutation create?* Every mutation must produce at least one discrepancy type.
- **Axis 3 — Attack Scenario** (mapping): *Under what architectural conditions is the mutation weaponized?*

**Relationship to the HTTP Request Smuggling taxonomy.** HTTP/2 downgrade smuggling (H2.CL, H2.TE, H2.0), H2 frame sequence attacks, and H2 binary-level header mutations are documented in the companion HTTP Request Smuggling & Desync taxonomy (§1-3, §4). This document focuses exclusively on what HTTP/3 and QUIC add to the attack surface: H3-specific downgrade differentials, QPACK compression attacks, QUIC transport-layer mutations, 0-RTT replay vectors, and connection coalescing contamination.



### Discrepancy Types (Axis 2)



| Discrepancy Type | Definition |
|---|---|
| **Downgrade translation mismatch** | H3 edge and H1/H2 backend disagree on request semantics due to lossy protocol translation — analogous to H2 downgrade mismatch but with QPACK and QUIC-specific differentials |
| **Compression state mismatch** | QPACK encoder and decoder disagree on header field values due to dynamic table manipulation, decompression bombs, or integer encoding divergence |
| **Connection scope mismatch** | Two agents disagree on which origins a QUIC connection may serve, or which backend should handle requests on a coalesced connection |
| **Cryptographic state mismatch** | Disagreement on whether a request has been authenticated — 0-RTT early data arrives before handshake completion, enabling replay and spoofing |
| **Resource boundary mismatch** | QUIC transport-level disagreements on stream, flow control, or packet boundaries that cause differential processing or resource exhaustion |



### QUIC Transport Fundamentals



HTTP/3 eliminates TCP and operates over QUIC, which provides its own framing at the transport layer. The key structural differences from HTTP/2:

| Property | HTTP/2 (TCP) | HTTP/3 (QUIC) |
|---|---|---|
| **Transport** | TCP + TLS 1.2/1.3 | UDP + QUIC (TLS 1.3 integrated) |
| **Stream multiplexing** | TCP-level HOL blocking | Per-stream loss recovery, no HOL blocking |
| **Header compression** | HPACK (synchronized, in-order) | QPACK (out-of-order capable, encoder/decoder streams) |
| **Connection establishment** | TCP 3-way + TLS handshake | 1-RTT (or 0-RTT with session resumption) |
| **Connection migration** | Not supported (IP change = new connection) | Supported via Connection ID |
| **Framing** | HTTP/2 frames over TCP byte stream | HTTP/3 frames over QUIC streams |



---



## §1. H3→H1/H2 Downgrade Translation Mutations



Mutations that exploit the translation boundary when an HTTP/3-speaking edge proxy downgrades requests to HTTP/1.1 or HTTP/2 for backend communication. This is the HTTP/3 analog of H2 downgrade attacks (companion taxonomy §1-3, §4), but introduces additional differentials due to QPACK semantics and the absence of TCP-level ordering guarantees.



### §1-1. H3 Framing Downgrade

HTTP/3 DATA frames carry a length field within the QUIC stream. When the edge proxy translates to HTTP/1.1, it must emit Content-Length or Transfer-Encoding headers that faithfully represent the original H3 frame boundaries. The same mismatch combinatorics that produced H2.CL, H2.TE, and H2.0 apply:

| Notation | Mechanism | Key Condition |
|---|---|---|
| **H3.CL** | H3 DATA frame length disagrees with the Content-Length header value emitted during H3→H1 downgrade | Proxy preserves or injects CL from QPACK-decoded headers without validating against actual DATA frame length |
| **H3.TE** | Transfer-Encoding header that should not exist in HTTP/3 survives the downgrade and reaches the HTTP/1.1 backend | Proxy fails to strip connection-specific headers during H3→H1 translation (cf. companion taxonomy §4 for H2 analog) |
| **H3.0** | H3 request sent without Content-Length → after downgrade, backend misjudges body presence | Same deadlock/early-response-gadget dynamics as H2.0 (companion taxonomy §1-2) but via QUIC transport |

The fundamental risk is identical to H2 downgrade: the H3 binary framing introduces a length interpretation method that is independent of the CL/TE headers carried within QPACK-compressed header blocks. Any proxy that trusts header values over frame boundaries (or vice versa) during translation creates an exploitable pair.

**Current state.** As of 2025, H3→H1 downgrade smuggling has not been demonstrated at scale in public research to the degree that H2→H1 has. This is primarily because most CDN/proxy infrastructure that accepts HTTP/3 from clients performs the H3→H2 or H3→H1 translation at the same edge node that already handles H2→H1 translation — meaning the H2 downgrade mitigations often cover H3 as well. However, as HTTP/3 backend adoption increases and independent H3-only proxy stacks emerge, the translation surface will diverge from H2 and require independent security analysis.



### §1-2. QPACK-to-HTTP/1.1 Header Injection

QPACK (RFC 9204) replaces HPACK for header compression in HTTP/3. Unlike HPACK's strictly in-order processing, QPACK supports out-of-order decoding via separate encoder and decoder streams. During H3→H1 downgrade, QPACK-decoded headers are serialized into HTTP/1.1 text format. Characters that are structurally meaningless in QPACK-compressed binary form become delimiters in HTTP/1.1:

| Technique | Mechanism | Impact |
|---|---|---|
| **CRLF in QPACK header values** | `\r\n` bytes in QPACK-compressed header values are transparent to H3 but become header delimiters after serialization to HTTP/1.1 | Arbitrary header injection in downgraded request (cf. companion taxonomy §4 for H2 CRLF injection analog) |
| **Pseudo-header translation differential** | `:method`, `:path`, `:authority`, `:scheme` pseudo-headers decoded from QPACK may contain characters that produce request-line or Host header anomalies after translation | Path confusion, host mismatch in the downgraded request |
| **Forbidden header survival** | `transfer-encoding`, `connection`, `keep-alive` — headers that RFC 9114 §4.2 forbids in HTTP/3 — may survive QPACK decoding and downgrade if the proxy does not explicitly strip them | Direct enabler for H3.TE and H3.CL attacks |

The attack surface is structurally parallel to H2 binary-level header mutations (companion taxonomy §4), but the QPACK encoding adds an additional layer: the dynamic table and encoder/decoder stream synchronization create opportunities for state manipulation that HPACK's strictly ordered model does not.



---



## §2. QPACK Header Compression Mutations



Mutations targeting the QPACK compression layer itself — independent of downgrade translation. QPACK's architecture of separate encoder and decoder streams, dynamic table management, and integer encoding creates attack surfaces absent from HPACK.



### §2-1. Decompression Bomb (Memory Exhaustion)

QPACK compression can achieve high ratios — a small compressed HEADERS frame can decompose into a massive decoded header field section. If the implementation enforces size limits only on the compressed frame (as required by QUIC flow control) but not on the decoded output, an attacker can trigger unbounded memory allocation.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Decoded header expansion** | HEADERS frame within QUIC flow control limits decompresses to headers exceeding available memory | Implementation checks compressed size but not decoded size. Patched in quic-go (GHSA-g754-hx8w-x2g6) via enforcing `SETTINGS_MAX_FIELD_SECTION_SIZE` and incremental QPACK decoding with early abort |
| **Dynamic table amplification** | Attacker populates the dynamic table with entries that maximize compression ratio, then references them repeatedly to amplify decoded output | Requires multiple requests on the same connection to build up the dynamic table |

**Mitigation.** RFC 9114 §4.2.2 specifies `SETTINGS_MAX_FIELD_SECTION_SIZE` to limit the decoded header field section. Compliant implementations must enforce this limit during decoding, not just on wire size.



### §2-2. Integer Encoding Overflow

QPACK (and HPACK) use a variable-length integer encoding scheme (RFC 7541 §5.1) for header field indices and string lengths. Integer overflow in the decoding logic can produce incorrect lengths, leading to buffer overflows or incorrect header parsing.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **QPACK/HPACK integer overflow** | Crafted variable-length integer exceeds implementation's integer width → wraps to small value → buffer under-read or over-read | Affects implementations using fixed-width integers (32-bit) for QPACK integer decoding. Jetty CVE (GHSA-wgh7-54f2-x98r): HTTP/2 HPACK and HTTP/3 QPACK integer overflow and buffer allocation vulnerability |
| **String length mismatch** | Huffman-encoded string length field overflows → decoded string length disagrees with actual content | Creates header field value truncation or extension |



### §2-3. Compression Side-Channel (CRIME Analog)

QPACK's compression reveals information about header contents through response size. While QPACK mitigates the original CRIME attack by compressing entire field lines (name + value) rather than individual characters, partial leakage remains possible.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Field-line oracle** | Attacker injects headers with guessed values; QPACK compresses matching entries more efficiently → response size difference reveals whether guess is correct | Viable against low-entropy values (e.g., CSRF tokens with limited character sets, boolean flags). High-entropy values (session tokens) are practically immune |
| **Dynamic table probing** | Attacker probes whether a specific header entry exists in the dynamic table by observing compression ratio changes | Requires shared connection and control over at least one header value |

QPACK's design (RFC 9204 §7.1) explicitly acknowledges this residual risk: "An attacker can only learn whether a guess is correct or not, so the attacker is reduced to a brute-force guess for the field values associated with a given field name."



---



## §3. Connection Coalescing & Routing Mutations



HTTP/3's connection coalescing rules differ from HTTP/2's in a critical way: the proposed relaxation of the IP address match requirement significantly expands the attack surface for cross-origin connection contamination.



### §3-1. Connection Coalescing Contamination

HTTP/2 allows a browser to reuse a single connection for requests to different hostnames if: (a) the hostnames resolve to the same IP address, and (b) the TLS certificate covers both hostnames. HTTP/3 proposes **removing requirement (a)** — the IP address match — because QUIC connections are identified by Connection IDs rather than IP 4-tuples.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **First-request routing abuse** | Reverse proxy determines backend routing based on the first request's Host header, then routes all subsequent requests on the same connection to that backend — regardless of their actual Host header | Proxy uses first-request routing (a common optimization). Combined with wildcard/multi-domain TLS certificate and connection coalescing, attacker can route victim requests to attacker-controlled backend |
| **Cross-origin coalescing without IP match** | HTTP/3 connection coalescing without IP address verification allows connection reuse across origins that share a TLS certificate but have different IP addresses | HTTP/3 client implements relaxed coalescing rules. Wildcard certificate (e.g., `*.example.com`) covers both attacker and target subdomains |
| **Alt-Svc redirection** | `Alt-Svc` header directs the client to establish an HTTP/3 connection to a different host/port, potentially controlled by the attacker | Client follows Alt-Svc without sufficient origin validation; can redirect HTTP/3 traffic through attacker-controlled QUIC endpoints |

**Attack scenario.** An attacker with XSS on `wordpress.example.com` injects JavaScript that forces the victim's browser to make requests to `secure.example.com`. With HTTP/3 connection coalescing and first-request routing, the browser reuses the existing connection (originally established to WordPress), and the reverse proxy routes the `secure.example.com` request to the WordPress backend — exposing credentials and cookies intended for the secure subdomain.

**HTTP/3 amplification.** In HTTP/2, this attack requires the target domains to resolve to the same IP address, significantly limiting scope. HTTP/3's proposed removal of this requirement means an attacker only needs a shared TLS certificate (e.g., any two subdomains under a wildcard cert) — no IP address co-location required. This transforms connection contamination from a niche misconfiguration into a broadly applicable attack against multi-tenant infrastructure.



---



## §4. 0-RTT Early Data Mutations



QUIC's 0-RTT (Zero Round-Trip Time) connection resumption allows a client to send application data before the cryptographic handshake completes, using a Pre-Shared Key (PSK) from a previous session. This performance optimization introduces cryptographic state mismatches that are fundamentally absent from TCP-based HTTP/1.1 and HTTP/2.



### §4-1. Replay Attacks

0-RTT data is not protected against replay because the server has not yet established a unique session context. An attacker who captures 0-RTT packets can retransmit them to the server, which may process them again.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Non-idempotent request replay** | Attacker captures 0-RTT packet containing a state-changing request (POST, PUT, DELETE) and replays it → server processes the operation multiple times | Server accepts 0-RTT data for non-idempotent methods. RFC 9001 §9.2 recommends restricting 0-RTT to safe methods, but enforcement is implementation-dependent |
| **Cross-connection replay** | 0-RTT data replayed on a different connection or to a different server in a load-balanced cluster → server processes a request it never originally received on that connection | Distributed session ticket validation is imperfect; each unique ticket should be used only once, but this is "difficult and costly in a highly distributed environment" |

**Mitigation.** Servers can respond with HTTP 425 (Too Early) to instruct the client to retry after full handshake completion. Additionally, restricting 0-RTT to GET requests without query parameters limits the replay surface.



### §4-2. IP Spoofing via UDP + 0-RTT

Because QUIC runs over UDP (which does not validate source addresses at the transport layer), and 0-RTT data is processed before the handshake validates the client's address, an attacker can send 0-RTT requests with a spoofed source IP address.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **IP allowlist bypass** | Attacker obtains a valid session ticket from a legitimate connection, then crafts a UDP datagram with spoofed source IP containing a QUIC Initial packet (with TLS ClientHello + session ticket) and a 0-RTT packet with early data. The server processes the HTTP request as originating from the spoofed IP | HTTP/3 server has 0-RTT enabled; IP-based access controls applied before handshake completion. CVE-2024-39321 (Traefik, CVSS 7.5): demonstrated IP allowlist bypass where server logs show "Accepting IP 1.3.3.7" from a spoofed source |
| **Blind request injection** | Attacker cannot receive responses (spoofed IP) but can inject state-changing requests that bypass IP-based authentication | Request must fit within a single UDP datagram (MTU-limited, typically ~1472 bytes). Attack is blind — no response received |

**Constraints.** The entire 0-RTT request must fit in a single UDP datagram (limited by network path MTU). The attacker must first obtain a valid session ticket through a legitimate connection. The attack is blind — the attacker cannot receive responses. Despite these constraints, CVE-2024-39321 demonstrated practical exploitation against Traefik's IP allowlist middleware.



---



## §5. QUIC Transport-Level Mutations



Mutations at the QUIC transport layer — below HTTP/3 semantics — that cause resource exhaustion, memory corruption, or differential processing. These attack the QUIC implementation itself rather than the HTTP/3 application layer.



### §5-1. Packet Processing Vulnerabilities

QUIC's packet structure (Initial, Handshake, 0-RTT, 1-RTT packets that can be coalesced into a single UDP datagram) creates parsing complexity that HTTP/1.1 and HTTP/2 over TCP do not face.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Coalesced packet memory leak** | Multiple QUIC Initial packets with invalid Destination Connection IDs (DCIDs) coalesced into a single UDP datagram → first packet freed correctly, subsequent packets leak memory (~96 bytes each) | CVE-2025-54939 (QUIC-LEAK, LSQUIC). Pre-handshake vulnerability — bypasses all QUIC connection-level protections (stream controls, flow regulation). Memory growth rate ~70% of attack bandwidth. Affects all LiteSpeed/OpenLiteSpeed installations (34% of HTTP/3 sites, 14% of all websites) |
| **Buffer overwrite in H3 processing** | Undisclosed HTTP/3 requests cause NGINX worker process memory corruption | CVE-2024-32760 (NGINX). Requires NGINX configured with HTTP/3 QUIC module |
| **Stack overflow and use-after-free** | Malformed HTTP/3 requests trigger stack overflow or use-after-free in NGINX QUIC processing | CVE-2024-31079 (NGINX). Worker process termination or potential code execution |
| **NULL pointer dereference** | Specific HTTP/3 request patterns trigger NULL pointer dereference in NGINX | CVE-2024-35200 (NGINX). Worker process crash → denial of service |
| **Memory disclosure** | HTTP/3 processing flaw leaks NGINX worker process memory contents | CVE-2024-34161 (NGINX). Information leakage via HTTP/3 responses. Affected versions 1.25.0–1.25.3 |
| **Use-after-free in connection handling** | HTTP/3 connection teardown race condition causes use-after-free | CVE-2024-24990 (NGINX). Affected versions 1.25.0–1.25.3 |



### §5-2. Stream Multiplexing Exhaustion

HTTP/3 multiplexes requests as independent QUIC streams within a single connection. Unlike HTTP/2 (where stream multiplexing shares TCP congestion control), QUIC streams have per-stream flow control — an attacker can open thousands of streams with minimal overhead.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Stream state exhaustion** | Opening many streams and never closing them forces the server to maintain per-stream state (data buffers, flow control windows, unique IDs) → memory exhaustion | Server does not aggressively enforce `MAX_STREAMS` or idle stream timeout |
| **Rapid stream creation/reset** | Opening and immediately resetting streams at high rate consumes CPU for stream creation/teardown without useful work | Analogous to HTTP/2 Rapid Reset (CVE-2023-44487) but via QUIC transport |
| **Single-connection amplification** | QUIC multiplexing allows generating massive server load from a single connection — no need for thousands of TCP connections | Significantly reduces attacker cost compared to HTTP/1.1 or HTTP/2 DoS |

**Relationship to race conditions.** QUIC stream multiplexing enables the Quic-Fin-Sync race technique: buffer near-complete requests across many QUIC streams, then release all final bytes simultaneously via coordinated FIN flags — achieving >110 concurrent requests in a single UDP packet. This is documented in the companion Web Race Condition taxonomy.



### §5-3. DPI Evasion via Frame Mutation

QUIC's encryption of both payload and most header fields makes Deep Packet Inspection (DPI) significantly harder than for TCP-based HTTP. Stateful DPI systems that attempt to track QUIC connections can be evaded through transport-layer mutations.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Frame reordering** | QUIC frames within a packet reordered to confuse DPI state machines while remaining valid for the endpoint | DPI system assumes specific frame ordering not required by RFC 9000 |
| **Connection ID manipulation** | QUIC connection migration with new Connection IDs causes DPI to lose connection tracking state | DPI binds tracking to initial Connection ID; QUIC allows migration via `NEW_CONNECTION_ID` frames |
| **Version negotiation confusion** | Sending QUIC packets with unexpected version fields triggers differential handling between DPI and endpoint | DPI applies version-specific parsing rules that may not match endpoint's version negotiation behavior |

Differential fuzzing of QUIC implementations against DPI systems (DPIFuzz) has demonstrated systematic strategies to elicit divergent behavior between QUIC endpoints and middleboxes.



---



## Attack Scenario Mapping (Axis 3)



| Scenario | Architecture | Primary Mutation Categories | Key Example |
|---|---|---|---|
| **H3 Downgrade Smuggling** | H3-speaking edge proxy → H1/H2 backend with persistent connection | §1 (H3.CL, H3.TE, H3.0) + §1-2 (QPACK header injection) | Analogous to H2 downgrade smuggling but via QUIC transport; currently limited by shared H2/H3 translation codepaths at most CDNs |
| **Connection Contamination** | Multi-tenant reverse proxy with first-request routing + wildcard TLS certificate | §3-1 (coalescing abuse + first-request routing) | XSS on one subdomain → cross-origin request routing via HTTP/3 connection coalescing without IP match requirement |
| **0-RTT IP Spoofing** | HTTP/3 server with 0-RTT enabled + IP-based access controls | §4-2 (UDP source spoofing + 0-RTT early data) | CVE-2024-39321 (Traefik): session ticket + spoofed UDP source → IP allowlist bypass |
| **0-RTT Replay** | HTTP/3 server accepting 0-RTT for state-changing operations | §4-1 (replay of non-idempotent requests) | Double-spend, duplicate transaction, rate limit bypass via captured 0-RTT packet retransmission |
| **QUIC Transport DoS** | Any HTTP/3 endpoint | §5-1 (packet processing) + §5-2 (stream exhaustion) | CVE-2025-54939 (QUIC-LEAK): pre-handshake memory exhaustion via coalesced Initial packets; NGINX CVE cluster (2024) |
| **QPACK Resource Exhaustion** | HTTP/3 client or server with insufficient decoded header limits | §2-1 (decompression bomb) + §2-2 (integer overflow) | quic-go GHSA-g754-hx8w-x2g6: QPACK-encoded HEADERS frame triggers unbounded memory allocation |
| **DPI / Censorship Evasion** | QUIC traffic through stateful DPI middlebox | §5-3 (frame mutation, Connection ID manipulation) | DPIFuzz-discovered elusion strategies against QUIC-aware DPI systems |
| **Race Condition Amplification** | HTTP/3 server with race-sensitive endpoints | §5-2 (stream multiplexing) | Quic-Fin-Sync: >110 synchronized requests in a single UDP packet via QUIC stream FIN coordination (see companion Web Race Condition taxonomy) |



---



## CVE / Bounty Mapping (2022–2025)



| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §5-1 (coalesced packet memory leak) | CVE-2025-54939 (LSQUIC / QUIC-LEAK) | CVSS 7.5. Pre-handshake DoS via memory exhaustion. Affects 34% of HTTP/3 sites (LiteSpeed/OpenLiteSpeed). ~96 bytes leaked per invalid DCID packet, linear memory growth. Fixed in LSQUIC 4.3.1 / OpenLiteSpeed 1.8.4 / LiteSpeed Web Server 6.3.4 |
| §5-1 (buffer overwrite) | CVE-2024-32760 (NGINX HTTP/3) | NGINX worker process memory corruption via HTTP/3 QUIC module. Affects 1.25.0+ |
| §5-1 (stack overflow + UAF) | CVE-2024-31079 (NGINX HTTP/3) | Stack overflow and use-after-free in HTTP/3 processing. Worker process crash or potential RCE |
| §5-1 (NULL pointer deref) | CVE-2024-35200 (NGINX HTTP/3) | NULL pointer dereference → worker process termination. Affects QUIC-enabled NGINX |
| §5-1 (memory disclosure) | CVE-2024-34161 (NGINX HTTP/3) | Memory content leakage via HTTP/3 response processing |
| §5-1 (UAF in connection handling) | CVE-2024-24990 (NGINX HTTP/3) | Use-after-free in HTTP/3 connection handling. Affects 1.25.0–1.25.3 |
| §4-2 (0-RTT IP spoofing) | CVE-2024-39321 (Traefik) | CVSS 7.5. IP allowlist bypass via 0-RTT early data with spoofed UDP source. Demonstrated blind request injection to restricted backends. Fixed in v2.11.6 / v3.0.4 |
| §2-1 (QPACK decoded header expansion) | GHSA-g754-hx8w-x2g6 (quic-go) | Memory exhaustion via QPACK-encoded HEADERS frame. Implementation enforced compressed size but not decoded size. Fixed via `SETTINGS_MAX_FIELD_SECTION_SIZE` enforcement |
| §2-2 (integer overflow) | GHSA-wgh7-54f2-x98r (Jetty) | HTTP/2 HPACK and HTTP/3 QPACK integer overflow and buffer allocation vulnerability |
| §5-2 (stream exhaustion, H2 analog) | CVE-2023-44487 (HTTP/2 Rapid Reset) | Applicable pattern to HTTP/3: rapid stream creation/reset as DoS amplification. Original H2 CVE affected every major HTTP/2 implementation |
| §3-1 (connection contamination) | PortSwigger research (2022) | HTTP/3 connection coalescing without IP match → cross-origin request misrouting. No CVE assigned; architectural weakness in proposed HTTP/3 coalescing rules |



---



## Detection Tools



### Offensive / Research Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **QuicDraw** (CyberArk, 2025) | HTTP/3 race conditions and fuzzing | Quic-Fin-Sync: last-byte-sync adapted to QUIC streams; >110 concurrent requests in single UDP packet. First HTTP/3-native security testing tool. GitHub: `CyberArk/QuicDraw` |
| **DPIFuzz** (CISPA, ACSAC 2020) | QUIC DPI evasion detection | Differential fuzzing framework: generates and mutates QUIC streams to detect DPI elusion strategies. Compares server-side interpretation across QUIC implementations |
| **fuzi_q** (private-octopus) | QUIC implementation fuzzing | Over-the-network QUIC fuzzer; hooks into Picoquic stack to modify QUIC frames pre-encryption. Inserts randomly chosen frames and tests implementation robustness. GitHub: `private-octopus/fuzi_q` |
| **quicmap** (bojanisc, 2024) | QUIC service discovery | Fast QUIC protocol scanner; identifies QUIC services, protocol versions, and supported ALPNs via binary search. GitHub: `bojanisc/quicmap` |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **QUIC+H3 Scanner** (pqcrypta) | HTTP/3 configuration assessment | ML-powered 4-tier grading: detects HTTP/3 support, 0-RTT risks, Alt-Svc configuration, and misconfigurations |
| **SETTINGS_MAX_FIELD_SECTION_SIZE enforcement** | QPACK decompression bomb prevention | RFC 9114 §4.2.2 — incremental QPACK decoding with early abort on decoded size exceeding declared limit |
| **0-RTT restriction policies** | 0-RTT replay prevention | Restrict 0-RTT to safe (idempotent) methods without query parameters; respond with HTTP 425 (Too Early) for restricted requests; enforce single-use session tickets |



---



## Summary: Core Principles



HTTP/3 and QUIC fundamentally restructure the transport layer beneath HTTP semantics, but this restructuring introduces attack surfaces that **do not exist** in TCP-based HTTP/1.1 or HTTP/2. The three most significant structural shifts are:

**1. UDP as transport eliminates source address validation.** TCP's three-way handshake inherently verifies the client's IP address before any application data is exchanged. QUIC's 0-RTT mechanism intentionally bypasses this verification for performance, creating a window where requests are processed from unverified sources. CVE-2024-39321 demonstrated that this is not theoretical — IP-based access controls can be bypassed with a single spoofed UDP datagram containing a replayed session ticket.

**2. Connection coalescing rules expand cross-origin attack surface.** HTTP/2's connection coalescing already created the risk of cross-origin contamination, but the IP address match requirement significantly limited scope. HTTP/3's proposed relaxation of this requirement — because QUIC uses Connection IDs rather than IP 4-tuples — removes the most significant natural barrier. Any two origins sharing a TLS certificate (including all subdomains under a wildcard cert) become potential contamination targets.

**3. QUIC's pre-handshake packet processing creates unauthenticated attack surface.** Unlike TCP+TLS where the transport handshake completes before any application data is processed, QUIC processes Initial and 0-RTT packets before establishing a fully authenticated connection. CVE-2025-54939 (QUIC-LEAK) demonstrated that vulnerabilities in this pre-handshake processing bypass all standard QUIC protections — connection limits, stream controls, and flow regulation are ineffective against attacks that exploit the packet parsing layer itself.

**The maturity gap.** HTTP/3 and QUIC security tooling lags significantly behind HTTP/1.1 and HTTP/2. As of 2025, major interception proxies (Burp Suite, mitmproxy, ZAP) lack HTTP/3 client support, making testing dependent on specialized tools like QuicDraw. The absence of mature H3-specific differential fuzzers (comparable to HTTP Garden, FRAMESHIFTER, or Gudifu for H1/H2) means the implementation-level parsing discrepancy surface across QUIC libraries (quic-go, LSQUIC, Quiche, ngtcp2, MsQuic) remains largely unexplored. Given that H1/H2 fuzzing has consistently revealed exploitable discrepancies at scale (122 discrepancies across 39 implementations in HTTP Garden alone), the HTTP/3 implementation landscape likely harbors comparable — or greater — divergence.

With HTTP/3 adoption reaching ~40% of websites as of 2025, and browser support exceeding 95%, the protocol-level attack surface documented here will only grow. The fundamental tension is the same as in HTTP/1.1 and HTTP/2 smuggling: **performance optimizations (0-RTT, connection coalescing, connection migration) create security gaps that incremental patches cannot structurally resolve**.



---



*This document was created for defensive security research and vulnerability understanding purposes.*



## References

### Specifications

- RFC 9000 — *QUIC: A UDP-Based Multiplexed and Secure Transport* (2021). Core QUIC transport protocol. §7.2 (connection ID validation), §9 (connection migration), §19 (frame types).
- RFC 9001 — *Using TLS to Secure QUIC* (2021). TLS 1.3 integration; 0-RTT early data security considerations (§9.2).
- RFC 9114 — *HTTP/3* (2022). HTTP semantics over QUIC; §4.2 (HTTP fields, forbidden headers), §4.2.2 (SETTINGS_MAX_FIELD_SECTION_SIZE).
- RFC 7541 — *HPACK: Header Compression for HTTP/2* (2015). Variable-length integer encoding scheme (§5.1) shared with QPACK; integer overflow attack surface.
- RFC 9204 — *QPACK: Field Compression for HTTP/3* (2022). Header compression; §7 (security considerations, CRIME mitigation, memory exhaustion).

### Research

- James Kettle — *HTTP/3 Connection Contamination: An Upcoming Threat?* (PortSwigger Research, 2022). First-request routing + connection coalescing contamination; demonstrated how HTTP/3's relaxed IP match requirement amplifies cross-origin attacks.
- Sven Hebrok, Robert Merget et al. — *QUIC and HTTP/3 Security* (USENIX Security 2025). Systematic security analysis of QUIC implementations.
- Matteo Varvello, Iñigo Querejeta-Azurmendi — *A Hands-on Gaze on HTTP/3 Security through the Lens of HTTP/2 and a Public Dataset* (Computers & Security, 2023 / arXiv:2208.06722). Comparative security analysis of HTTP/2 and HTTP/3 implementations using public dataset methodology.
- Robin Marx, Joris Herbots, Peter Quax, Wim Lamotte — *How Resilient is QUIC to Security and Privacy Attacks?* (arXiv:2401.06657, 2024). Comprehensive survey of QUIC security and privacy attack resilience.
- Aly Moustafa et al. — *Revisiting QUIC Attacks: A Comprehensive Review on QUIC Security and a Hands-on Study* (International Journal of Information Security, Springer, 2022). Systematic QUIC vulnerability categorization.
- Florian Tschorsch et al. — *Security and Service Vulnerabilities with HTTP/3* (IEEE Conference, 2024). HTTP/3 service-level vulnerability analysis.
- CyberArk — *Racing and Fuzzing HTTP/3: Open-sourcing QuicDraw* (2025). Quic-Fin-Sync race technique for HTTP/3; first HTTP/3-native security testing tool.
- Imperva Offensive Team — *QUIC-LEAK (CVE-2025-54939)* (2025). Pre-handshake memory exhaustion in LSQUIC via coalesced Initial packet DCID validation failure.
- Florian Tschorsch, Nguyen Phong Hoang — *DPIFuzz: A Differential Fuzzing Framework to Detect DPI Elusion Strategies for QUIC* (ACSAC 2020). Systematic QUIC DPI evasion discovery.
- Traefik Security Advisory GHSA-gxrv-wf35-62w9 — *Bypassing IP Allow-lists via HTTP/3 Early Data Requests in QUIC 0-RTT Handshakes* (CVE-2024-39321, 2024). Demonstrated 0-RTT IP spoofing against Traefik's IP allowlist middleware. https://github.com/traefik/traefik/security/advisories/GHSA-gxrv-wf35-62w9

### Security Advisories

- NGINX HTTP/3 QUIC Security Advisories (2024). CVE-2024-32760 (buffer overwrite), CVE-2024-31079 (stack overflow / use-after-free), CVE-2024-35200 (NULL pointer dereference), CVE-2024-34161 (memory disclosure), CVE-2024-24990 (use-after-free in connection handling). Affects NGINX 1.25.0–1.25.5 with HTTP/3 QUIC module. Fixed in 1.26.1+ / 1.27.0+. https://nginx.org/en/security_advisories.html
- quic-go GHSA-g754-hx8w-x2g6 — *HTTP/3 QPACK Header Expansion Memory Exhaustion*. QPACK-encoded HEADERS frame decompresses to unbounded header section; implementation enforced compressed size but not decoded size. Fixed via `SETTINGS_MAX_FIELD_SECTION_SIZE` enforcement with incremental decoding. https://github.com/quic-go/quic-go/security/advisories/GHSA-g754-hx8w-x2g6
- Jetty GHSA-wgh7-54f2-x98r — *HTTP/2 HPACK, and HTTP/3 QPACK Integer Overflow and Buffer Allocation*. Variable-length integer encoding overflow in HPACK/QPACK decoding logic. https://github.com/jetty/jetty.project/security/advisories/GHSA-wgh7-54f2-x98r
