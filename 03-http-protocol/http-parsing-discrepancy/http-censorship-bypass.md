# HTTP Censorship Bypass — Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy classifies censorship bypass techniques along three orthogonal axes, derived from systematic analysis of academic literature (USENIX Security, NDSS, CCS, FOCI/PETS), practitioner tools, and real-world deployment data across China, Russia, Iran, and Kazakhstan.

### Axis 1 — Mutation Target (Primary Axis)

The **protocol layer or structural component** being manipulated to evade the censor. This axis structures the main body of this document into eight top-level categories:

| § | Mutation Target | Layer | Core Idea |
|---|----------------|-------|-----------|
| §1 | TCP/IP Packet Structure | L3–L4 | Fragment, reorder, or inject packets to desynchronize the DPI's TCP state machine |
| §2 | TLS Handshake Fields | L5 | Mutate SNI, fragment ClientHello, encrypt metadata, or spoof fingerprints |
| §3 | HTTP Semantics | L7 | Exploit parsing differentials in HTTP headers, methods, and request structure |
| §4 | DNS Resolution | L7 | Encrypt, tunnel, or relocate DNS queries outside the censor's reach |
| §5 | QUIC/UDP Framing | L4–L7 | Exploit QUIC-specific parsing gaps and UDP's different handling by middleboxes |
| §6 | Protocol Mimicry & Tunneling | L5–L7 | Disguise circumvention traffic as legitimate protocol flows |
| §7 | Routing & Infrastructure | Network | Exploit CDN/cloud topology to make blocking create unacceptable collateral damage |
| §8 | Traffic Analysis Countermeasures | Statistical | Defeat ML classifiers and timing/volume fingerprinting |

### Axis 2 — Discrepancy Type (Cross-Cutting)

The **fundamental mechanism** that makes each evasion work. Every technique in §1–§8 exploits one or more of these discrepancies:

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D1** | Parser Differential | DPI reassembles/interprets bytes differently than the endpoint |
| **D2** | State Machine Desync | DPI's TCP/TLS state diverges from the real connection state |
| **D3** | Signature Evasion | The censored pattern (keyword, SNI, domain) is altered to avoid matching |
| **D4** | Visibility Gap | The censored identifier is encrypted, omitted, or tunneled beyond DPI's view |
| **D5** | Collateral Damage | Blocking the evasion vector would break critical legitimate services |
| **D6** | Protocol Confusion | DPI misidentifies the protocol or misinterprets its semantics |
| **D7** | Active Probe Resistance | The circumvention server is indistinguishable from a legitimate server under probing |

### Axis 3 — Censor Architecture Target (Mapping Axis)

The **type of censorship infrastructure** each technique is effective against:

| Target | Description | Countries |
|--------|-------------|-----------|
| **Passive DPI** | Inline/tap-based keyword and pattern matching | CN, RU, IR, KZ |
| **Stateful DPI** | Connection-tracking DPI maintaining TCP/TLS state | CN, RU, IR |
| **DNS Poisoning** | Forged DNS responses or DNS query interception | CN, IR, RU |
| **SNI Filtering** | TLS ClientHello SNI field inspection | CN, RU, IR |
| **IP/Port Blocking** | Network-layer blocklists of IPs and ports | All |
| **Protocol Whitelist** | Only approved protocols (DNS, HTTP, HTTPS) allowed | IR |
| **Active Probing** | Censor initiates connections to suspected servers | CN, IR |
| **Traffic Analysis** | ML/statistical fingerprinting of traffic patterns | CN, RU |

---

## §1. TCP/IP Packet Structure Manipulation

TCP/IP-layer evasion exploits the fundamental architectural constraint of DPI systems: they run **incomplete TCP/IP stacks** that differ from endpoint implementations. These differences — in reassembly logic, state tracking, timeout handling, and edge-case processing — create exploitable gaps between what the DPI "sees" and what the server receives.

### §1-1. TCP Segmentation / Fragmentation

The most widely deployed category of censorship evasion. DPI systems typically inspect packets individually or perform limited reassembly; splitting a censored keyword (e.g., a hostname in an HTTP Host header or TLS SNI) across multiple TCP segments causes the DPI to fail pattern matching while the endpoint reassembles correctly.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **First-byte split** | Send only the first 1 byte of a request, then the remainder in a second segment | DPI examines only the first segment for pattern matching | D1 |
| **Mid-keyword split** | Fragment the TCP stream such that the censored string (e.g., `exampl` / `e.com`) straddles two segments | DPI lacks cross-segment reassembly | D1 |
| **Multi-split** | Divide a single request into 3+ small segments, each below the DPI's minimum inspection threshold | DPI drops very small segments or has limited reassembly buffers | D1 |
| **Out-of-order segments (disorder)** | Send TCP segments out of sequence number order; the endpoint reorders, but the DPI may not | DPI performs in-order-only inspection | D1, D2 |
| **Overlapping segments** | Send overlapping TCP segments with different data; endpoint and DPI may resolve overlaps differently (RFC 793 vs. implementation) | Platform-specific overlap resolution (first-wins vs. last-wins) | D1 |

**Example (first-byte split):**
```
Segment 1: [TCP seq=0, len=1]  → "G"
Segment 2: [TCP seq=1, len=...]  → "ET / HTTP/1.1\r\nHost: blocked.com\r\n..."
```
The DPI sees "G" in isolation and cannot match the Host header pattern.

### §1-2. Fake Packet Injection

Inject TCP packets that the DPI processes but the destination server discards. This poisons the DPI's view of the connection while leaving the real data stream intact.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Bad-checksum fake** | Inject a packet with an incorrect TCP checksum; the server drops it (checksum validation), but many DPI systems skip checksum verification for performance | DPI does not validate TCP checksums | D2 |
| **Low-TTL fake** | Inject a packet with a TTL value calculated to expire before reaching the server but after passing through the DPI | DPI is topologically closer to the client than the server | D2 |
| **Bad-sequence fake** | Inject a packet with a TCP sequence number outside the server's receive window; the server ignores it, but the DPI may update its state | DPI has a looser receive-window check | D2 |
| **Fake RST/FIN** | Inject a fake RST or FIN packet to make the DPI believe the connection is closed, then continue the real connection | DPI tears down connection state on RST/FIN; server ignores the fake | D2 |
| **Fake data injection** | Inject a packet containing a decoy Host header or SNI, followed by the real request; the DPI inspects the decoy | DPI processes the first matching pattern without full reassembly | D2, D3 |

**Example (low-TTL fake):**
```
Real packet: [TTL=64] GET / HTTP/1.1\r\nHost: blocked.com  → reaches server
Fake packet: [TTL=3]  GET / HTTP/1.1\r\nHost: allowed.com  → DPI sees this, packet dies en route
```

### §1-3. IP-Layer Fragmentation

Exploit differences in IP fragment reassembly between the DPI and endpoint.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **IP fragment splitting** | Fragment IP datagrams so that the censored payload spans two fragments; many DPI systems do not reassemble IP fragments | DPI inspects individual fragments without reassembly | D1 |
| **Overlapping IP fragments** | Send overlapping IP fragments with conflicting data; the endpoint and DPI may resolve overlaps differently | OS-specific fragment reassembly policy | D1 |
| **Tiny fragment attack** | Create IP fragments small enough that the TCP header spans two fragments, preventing the DPI from identifying the port/protocol | DPI requires complete TCP header in first fragment | D1 |
| **MTU/PMTUD manipulation** | Send forged ICMP "Fragmentation Needed" messages to force smaller MTU, causing natural fragmentation that the DPI may not handle | DPI doesn't track PMTUD state | D1, D6 |

### §1-4. TCP State Machine Exploitation

Systematically discover and exploit differences between the DPI's TCP state machine and the endpoint's real TCP implementation.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Urgent pointer abuse** | Set the TCP urgent pointer to cause the DPI and server to interpret data boundaries differently | DPI handles URG flag differently from the server's TCP stack | D1, D2 |
| **Window-size manipulation** | Advertise a TCP window size that influences the DPI's reassembly behavior differently from the server's | DPI respects advertised window for reassembly; server implementation differs | D2 |
| **SYN data injection** | Include data in the SYN packet (TCP Fast Open style); some DPI systems ignore SYN data | DPI does not process data in SYN packets | D2 |
| **RST tolerance differential** | Server ignores RST packets with incorrect sequence numbers; DPI tears down state on any RST | DPI has looser RST acceptance criteria | D2 |
| **Retransmission divergence** | Send different data in retransmitted segments; the DPI may accept either the original or retransmission differently from the server | DPI retransmission handling differs from endpoint | D1, D2 |

These subtypes are systematically discoverable via symbolic execution of the server's TCP stack (as in SymTCP) or genetic algorithm-driven fuzzing against live censors (as in Geneva).

---

## §2. TLS Handshake Manipulation

TLS-layer censorship primarily targets the **Server Name Indication (SNI)** field in the ClientHello message — the last major plaintext metadata leak in HTTPS connections. This category covers mutations to the TLS handshake that hide, alter, or obscure the SNI and other fingerprintable fields.

### §2-1. TLS Record Fragmentation

Analogous to TCP segmentation (§1-1) but operating at the TLS record layer. A single TLS handshake message (e.g., ClientHello) can be split across multiple TLS records. Many DPI systems only inspect the first TLS record.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **ClientHello record split** | Fragment the ClientHello across 2+ TLS records so that the SNI extension spans a record boundary | DPI inspects only the first TLS record for SNI | D1 |
| **Multi-record handshake** | Split all handshake messages (ClientHello, Certificate, etc.) across records | DPI lacks TLS record reassembly for handshake messages | D1 |
| **Combined TCP + TLS fragmentation** | Apply TCP segmentation (§1-1) AND TLS record fragmentation simultaneously; the DPI must reassemble at both layers | DPI can reassemble at one layer but not both | D1 |

Over 90% of TLS servers correctly process fragmented ClientHello messages. This technique successfully circumvents the GFW's TLS inspection.

### §2-2. SNI Field Mutation

Directly modify the SNI extension in the ClientHello to evade pattern matching while ensuring the server still accepts the connection.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **SNI omission** | Send a ClientHello without the SNI extension entirely; some servers accept this and serve a default certificate | Server has a default/fallback certificate configured | D3, D4 |
| **SNI padding** | Insert null bytes, spaces, or other padding around the SNI value that the DPI includes in matching but the TLS stack strips | DPI performs literal string match without normalization | D3 |
| **SNI case variation** | Alter the case of the hostname in SNI (e.g., `Blocked.COM`); DNS and TLS are case-insensitive but the DPI's blocklist may be case-sensitive | DPI performs case-sensitive comparison | D3 |
| **Encrypted SNI (ESNI)** | Encrypt the SNI field using a key published in DNS (deprecated predecessor to ECH) | Server supports ESNI; DNS query for key is not censored | D4 |
| **Encrypted Client Hello (ECH)** | Encrypt the entire ClientHello (including SNI) inside an outer ClientHello with a benign SNI | Server supports ECH; ECH config is retrievable (via DNS) | D4 |
| **SNI removal via version field** | Manipulate the TLS version field in the outer record layer to values the DPI does not expect, causing it to skip SNI extraction | DPI only parses specific TLS version numbers | D6 |

**ECH status (2025):** ECH is nearing IETF standardization but deployment remains limited primarily to Cloudflare. Russia began blocking ECH connections to Cloudflare in November 2024. China and Iran prevent ECH usage by blocking encrypted DNS required to retrieve ECH configs.

### §2-3. TLS Fingerprint Manipulation

DPI systems increasingly use TLS fingerprinting (JA3, JA4) to identify circumvention tools by their unique ClientHello patterns. This subcategory covers techniques to make circumvention traffic's TLS fingerprint indistinguishable from legitimate browsers.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Browser fingerprint mimicry** | Construct a ClientHello that exactly replicates a popular browser's cipher suites, extensions, and ordering (via libraries like uTLS) | The mimicked fingerprint matches an allowed browser | D3, D6 |
| **Extension order randomization** | Randomize the order of TLS extensions in each connection, matching the behavior of modern Chrome/Firefox which began randomizing in 2023 | DPI uses order-dependent fingerprinting (JA3); broken by JA4 | D3 |
| **Cipher suite shuffling** | Randomize cipher suite ordering to defeat fingerprint-based blocklists | DPI matches on exact cipher suite order | D3 |
| **GREASE injection** | Include Generate Random Extensions And Sustain Extensibility (GREASE) values in the ClientHello to disrupt static fingerprints | DPI does not handle unknown extension codes gracefully | D3, D6 |
| **Fingerprint rotation** | Rotate between multiple pre-computed fingerprints across connections to avoid statistical profiling | DPI uses single-fingerprint matching per client | D3 |

### §2-4. TLS Certificate Borrowing / Impersonation

Make the circumvention server's TLS handshake indistinguishable from a legitimate server's by borrowing or replaying real TLS certificates.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **REALITY handshake proxy** | The proxy forwards the initial TLS handshake to a legitimate "front" server (e.g., apple.com), obtaining a genuine ServerHello and certificate chain; subsequent data is decrypted with a pre-shared key | Client and proxy share a PSK; censor sees a valid handshake to a reputable domain | D4, D7 |
| **ShadowTLS relay** | The relay completes a genuine TLS handshake with a trusted server, then switches to proxying encrypted circumvention data; the censor sees only the legitimate handshake | Relay has access to a legitimate TLS server; post-handshake traffic must be indistinguishable | D4, D7 |
| **Certificate chain replay** | Cache and replay legitimate certificate chains from popular websites, presenting them during the handshake without actual connectivity to the front server | Censor does not perform online certificate validation (OCSP stapling check) | D7 |

**Detection risk:** Active probing tools (e.g., Aparecium) can detect REALITY and ShadowTLS by sending unexpected TLS application data and observing whether the server behaves like the claimed front domain. ShadowTLS v3 has been assessed as potentially detectable via timing analysis and response behavior discrepancies.

---

## §3. HTTP Semantics Manipulation

HTTP-layer evasion targets censors that inspect HTTP request/response content for censored keywords — typically in the `Host` header, URL path, or response body. These techniques exploit the gap between how a DPI system parses HTTP and how the destination web server interprets the same bytes.

### §3-1. Host Header Mutation

The HTTP `Host` header is the primary target for HTTP-layer censors. Mutations aim to prevent the DPI from extracting the censored hostname while ensuring the server still routes the request correctly.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Case variation** | Alter hostname casing: `Host: BLOCKED.com` or `Host: bLoCkEd.CoM`; HTTP hostnames are case-insensitive per RFC 9110 (and DNS per RFC 4343) | DPI performs case-sensitive matching | D3 |
| **Whitespace injection** | Insert spaces or tabs: `Host:  blocked.com` or `Host:\tblocked.com`; many servers strip leading/trailing whitespace | DPI includes whitespace in the extracted hostname | D1, D3 |
| **Header name casing** | Alter the header name: `host:` or `HOST:` or `hOsT:`; HTTP/1.1 header names are case-insensitive | DPI expects exact case for header names | D1, D3 |
| **Line folding (obs-fold)** | Split the Host header value across multiple lines using obsolete line folding (`\r\n ` or `\r\n\t`); some servers still support this per HTTP/1.1's legacy syntax | DPI does not handle line folding; server unFolds | D1 |
| **Duplicate Host headers** | Include two `Host` headers with different values; the DPI and server may choose differently (first vs. last) | Server and DPI have different duplicate-header resolution logic | D1 |
| **Null byte injection** | Insert `\x00` within the hostname: `Host: blocked\x00.com`; some servers truncate at null while DPI reads the full string | Server truncates at null byte; DPI does not | D1, D3 |
| **Tab/space before colon** | Add whitespace before the colon: `Host : blocked.com`; technically invalid but accepted by some servers | DPI rejects or misparses the malformed header; server is tolerant | D1 |

### §3-2. HTTP Request Smuggling for Censorship Evasion

Repurposing the web security vulnerability of HTTP Request Smuggling (HRS) as a censorship circumvention technique. The key insight: construct ambiguously defined HTTP requests that split differently between the censor's parser and the endpoint.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **CL-TE smuggling** | Set both `Content-Length` and `Transfer-Encoding: chunked`; the DPI uses one to delimit requests while the server uses the other, causing a smuggled second request with the censored Host to be invisible to the DPI | DPI and server prioritize CL vs. TE differently | D1 |
| **TE-CL smuggling** | Reverse of CL-TE: the DPI processes Transfer-Encoding while the server uses Content-Length | Same differential, reversed roles | D1 |
| **TE obfuscation** | Obfuscate the `Transfer-Encoding` header (e.g., `Transfer-Encoding: \tchunked` or `Transfer-Encoding: chunked, identity`) so one parser recognizes it and the other does not | DPI and server have different TE parsing tolerance | D1, D3 |
| **Pipelined smuggling** | Send multiple HTTP requests in a pipeline where the boundary between requests is ambiguous; the censored domain appears in a request the DPI attributes to a different connection context | DPI does not correctly track pipelined request boundaries | D1 |

This technique was demonstrated effective against censors in China, Russia, and Iran (FOCI 2024), with the censored domain placed in a smuggled second request's Host header.

### §3-3. HTTP Method and Version Tricks

Exploit DPI assumptions about HTTP method types and protocol versions.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Unusual HTTP methods** | Use methods like `OPTIONS`, `HEAD`, `CONNECT`, or custom methods; some DPI systems only inspect `GET` and `POST` | DPI filters only common methods | D6 |
| **HTTP/0.9 downgrade** | Send a bare request line without headers (`GET /path\r\n`); the DPI may not recognize this as HTTP | DPI expects HTTP/1.0+ format | D6 |
| **HTTP version manipulation** | Use non-standard version strings (e.g., `HTTP/1.2`, `HTTP/2.0` in plaintext); the DPI may skip inspection for unrecognized versions | DPI has version-specific parsing logic | D6 |
| **Absolute-form vs. origin-form** | Use `GET http://blocked.com/ HTTP/1.1` (absolute form) when the DPI only inspects the Host header, or vice versa | DPI extracts the hostname from only one location | D1, D3 |

### §3-4. URL and Path Obfuscation

Modify the URL/path component to evade keyword-based filtering of specific URLs.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Percent-encoding** | Encode characters in the URL path: `/p%61th` → `/path`; the server decodes but the DPI may match the encoded form | DPI does not URL-decode before matching | D3 |
| **Double encoding** | Apply percent-encoding twice: `%2561` → `%61` → `a`; the DPI decodes once, the server/application decodes twice | DPI performs single-pass decoding; application decodes again | D3 |
| **Unicode/UTF-8 encoding** | Use multi-byte UTF-8 sequences for ASCII characters: overlong encoding of `/` as `%c0%af` | DPI does not normalize Unicode; server does | D3 |
| **Path traversal normalization** | Insert traversal sequences: `/allowed/../blocked/page`; the server normalizes to `/blocked/page` | DPI matches the pre-normalized path | D3 |
| **Query string obfuscation** | Move censored keywords into query parameters, fragments, or POST body where the DPI does not inspect | DPI only inspects URL path, not query/body | D4 |

---

## §4. DNS Resolution Manipulation

DNS-based censorship (poisoning, injection, blocking) is the most widely deployed and often the first layer of censorship encountered. Evasion at this layer prevents the censor from learning which domain the user is resolving.

### §4-1. Encrypted DNS Protocols

Encrypt DNS queries to prevent the censor from reading the queried domain name.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **DNS over HTTPS (DoH)** | Tunnel DNS queries inside HTTPS connections to a resolver (port 443); indistinguishable from regular HTTPS traffic | DoH resolver is reachable and not blocked by IP; shares port 443 with regular HTTPS | D4, D5 |
| **DNS over TLS (DoT)** | Encrypt DNS queries via TLS to a resolver on port 853 | Port 853 is not blocked (easily identifiable and blockable) | D4 |
| **DNS over QUIC (DoQ)** | Encrypt DNS queries via QUIC to a resolver on port 853 | Port 853 UDP is not blocked; QUIC is not blanket-blocked | D4 |
| **DNS over Tor** | Route DNS queries through the Tor network, anonymizing both the query and the resolver selection | Tor is accessible (or accessed via bridges) | D4 |
| **DNS over HTTP/3 (DoH3)** | DoH over QUIC, sharing port 443 with regular QUIC/HTTP3 traffic | QUIC is not blanket-blocked | D4, D5 |

**Effectiveness (2025):** DoH provides the strongest censorship resistance because it shares port 443 with all HTTPS traffic, making selective blocking create massive collateral damage. DoT and DoQ use dedicated port 853, which censors can trivially block. China and Iran block encrypted DNS to prevent ECH config retrieval.

### §4-2. DNS Infrastructure Evasion

Bypass DNS censorship without protocol-level encryption, by using alternative resolution paths.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Third-party resolver** | Configure a non-censored resolver (e.g., 8.8.8.8, 1.1.1.1) instead of the ISP's DNS | The resolver's IP is not blocked; DNS traffic to it is not intercepted | D4 |
| **DNS tunneling** | Encode arbitrary data (including censored DNS queries) within legitimate-looking DNS queries to a controlled authoritative server (e.g., via `iodine`, `dnscat2`) | Outbound DNS to arbitrary domains is allowed | D4, D6 |
| **Happy Eyeballs / dual-stack** | Resolve via IPv6 when IPv4 DNS is poisoned, or vice versa; censors may not poison both A and AAAA records | Censor does not poison both address families | D4 |
| **Moving-target resolvers** | Use resolvers that dynamically change IP addresses and are discovered via side channels (e.g., IPNS-based resolution) to evade IP-based blocking | Client can discover new resolver IPs faster than the censor blocks them | D4 |
| **DNS cache exploitation** | Leverage cached DNS responses from before censorship was applied, or poison the censor's cache with correct responses | Timing-dependent; limited window | D4 |

### §4-3. DNS Response Manipulation Countermeasures

Detect and discard forged DNS responses injected by the censor.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **TTL-based filtering** | Forged DNS responses often arrive faster (lower TTL / shorter path) than legitimate ones; the client waits for and accepts only the later, authentic response | Censor injects rather than blocks (e.g., China's DNS injection) | D2 |
| **Source-IP validation** | Verify that DNS responses come from the expected resolver IP; drop responses from unexpected sources | Censor injects from different IPs than the real resolver | D2 |
| **DNSSEC validation** | Validate DNSSEC signatures on responses; forged responses will fail signature verification | Domain has DNSSEC enabled; resolver supports validation | D2 |
| **Multiple-resolver cross-check** | Query multiple resolvers and compare results; discard outliers consistent with censorship | At least one resolver returns uncensored results | D2 |

---

## §5. QUIC/UDP Layer Manipulation

QUIC presents unique challenges and opportunities for censorship evasion. QUIC Initial packets are encrypted (though decryptable with publicly derived keys), and the protocol's structure over UDP creates different DPI handling compared to TCP.

### §5-1. QUIC Frame Splitting

Exploit the GFW's inability to reassemble QUIC Initial packets that span multiple UDP datagrams.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **CRYPTO frame splitting** | Split the TLS ClientHello (carried in QUIC CRYPTO frames) across multiple QUIC Initial packets in separate UDP datagrams; the SNI extension spans a datagram boundary | DPI does not reassemble QUIC packets across UDP datagrams | D1 |
| **Natural oversized Initials** | Leverage browser changes (e.g., Chrome's September 2024 update) that naturally produce QUIC Initial packets too large for a single UDP datagram | DPI can only inspect the first datagram; SNI may appear in the second | D1 |
| **Padding-induced splitting** | Add QUIC PADDING frames to push the SNI extension into a subsequent datagram | DPI inspects a fixed number of bytes per datagram | D1 |

This is the primary circumvention strategy against China's QUIC censorship, which began in April 2024.

### §5-2. QUIC Protocol-Level Evasion

Exploit QUIC-specific protocol features for evasion.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Connection migration** | QUIC supports migrating connections to new IP/port pairs; initiate a connection through an uncensored path, then migrate to the censored destination | DPI does not track QUIC connection migration | D2, D6 |
| **Version negotiation abuse** | Use QUIC version numbers that the DPI does not recognize, causing it to skip inspection | DPI only decrypts known QUIC versions | D6 |
| **0-RTT data exploitation** | Place the censored request in 0-RTT data, which is encrypted with a PSK; the DPI cannot decrypt without the PSK | Server supports 0-RTT resumption; DPI cannot derive the PSK | D4 |
| **Connection ID manipulation** | Use long or randomized Connection IDs to disrupt DPI's connection-tracking heuristics | DPI relies on Connection ID length/format for protocol identification | D6 |

### §5-3. UDP-Level Evasion

Exploit differences in how middleboxes handle UDP versus TCP traffic.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **UDP fragmentation** | Fragment UDP datagrams at the IP layer; DPI may not reassemble UDP fragments | DPI performs limited IP reassembly for UDP traffic | D1 |
| **QUIC masquerade** | Tunnel non-QUIC protocols (e.g., WireGuard) inside QUIC/HTTP3, making them appear as standard web traffic (e.g., via MASQUE) | DPI treats QUIC port-443 traffic as web browsing | D4, D5 |
| **UDP port hopping** | Rapidly change the UDP source/destination ports across packets; stateless DPI cannot maintain a connection context | DPI requires fixed port pairs for flow tracking | D2 |

---

## §6. Protocol Mimicry & Tunneling

Rather than mutating individual fields, this category encompasses techniques that disguise entire circumvention flows as legitimate protocol traffic, or tunnel circumvention data inside approved protocols.

### §6-1. HTTPS Mimicry

Make circumvention traffic indistinguishable from regular HTTPS web browsing.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **WebTunnel (HTTPT-based)** | Wrap circumvention traffic inside a WebSocket-like HTTPS connection; coexists on the same endpoint as a real website, sharing domain, IP, and port | Bridge operator runs a real website alongside the tunnel; traffic is indistinguishable | D4, D7 |
| **VLESS + REALITY** | Proxy traffic via the VLESS protocol, with the REALITY transport layer borrowing legitimate TLS certificates from real servers during handshake (§2-4); post-handshake traffic is encrypted with a PSK | Client has PSK; the "front" domain's TLS configuration is compatible | D4, D7 |
| **Trojan protocol** | Mimic a standard TLS handshake (with valid certificate) followed by password-authenticated proxy data; indistinguishable from legitimate HTTPS at the handshake level | Valid TLS certificate for the proxy domain; password authentication | D4, D7 |
| **Meek (CDN fronting)** | Tunnel circumvention data inside HTTPS requests to a CDN, using domain fronting (§7-1) or CDN-native routing to reach the circumvention relay | CDN does not enforce domain fronting restrictions | D4, D5 |

### §6-2. Look-Like-Nothing Protocols

Design the circumvention traffic to have no identifiable protocol signature — appearing as random bytes.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **obfs4** | Randomize the wire image so traffic appears as uniformly distributed random bytes with no identifiable header, magic bytes, or structure | Censor does not block all unclassifiable traffic; entropy-based blocking is not deployed | D3, D6 |
| **Fully encrypted protocols** | Use symmetric encryption from the first byte with no plaintext handshake (e.g., Shadowsocks, Outline); the censor cannot identify the protocol | Censor has not deployed entropy/randomness detection (China has since ~2023) | D4, D6 |
| **Printable ASCII prefix** | Prepend customizable plaintext bytes (printable ASCII) to the first packet to evade the GFW's "fully encrypted traffic" heuristic, which exempts connections whose first bytes match known protocol patterns | The GFW's exemption rules check only the first several bytes | D3, D6 |

**Detection risk (2025):** China's GFW now detects fully encrypted traffic via entropy analysis — connections whose first data packet has high entropy and doesn't match any known protocol fingerprint are flagged and blocked. The "printable ASCII prefix" countermeasure exploits the exemption rules in this heuristic.

### §6-3. Protocol Repurposing

Tunnel circumvention data through protocols the censor is unlikely to block.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **HTTP CONNECT tunneling** | Use the HTTP CONNECT method to establish a proxy tunnel through an allowed HTTP proxy | An accessible HTTP proxy that permits CONNECT to arbitrary destinations | D4 |
| **WebSocket tunneling** | Upgrade an HTTP connection to WebSocket and tunnel arbitrary data; WebSocket frames are not typically inspected by DPI | DPI does not inspect post-upgrade WebSocket traffic | D4 |
| **SSH tunneling** | Tunnel traffic through SSH connections; SSH is encrypted end-to-end | SSH is not protocol-blocked (Iran blocks SSH by default) | D4 |
| **ICMP/DNS tunneling** | Encode circumvention data inside ICMP echo requests or DNS queries; these protocols are rarely blocked entirely | ICMP/DNS outbound is allowed; throughput is severely limited | D4, D6 |
| **Pub/Sub cloud services** | Tunnel circumvention traffic through cloud pub/sub messaging services (e.g., AWS IoT, Google Cloud Pub/Sub) that the censor cannot block without disrupting major cloud services | Cloud service API is reachable; sufficient bandwidth | D4, D5 |

### §6-4. Pluggable Transport Framework

A standardized architecture for deploying multiple obfuscation layers as interchangeable modules (originally developed for Tor).

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **obfs4** | Look-like-nothing with per-bridge key-based authentication to resist active probing | Bridge address is not discovered by the censor | D3, D7 |
| **Snowflake** | Leverage ephemeral WebRTC proxies run by volunteers; each proxy has a short lifespan, preventing IP-based blocking | Volunteer proxies are available; WebRTC is not blocked | D4, D5 |
| **meek** | CDN-fronted HTTPS tunnel using domain fronting (§7-1) | CDN does not block fronting; CDN IP ranges are not blocked | D4, D5 |
| **WebTunnel** | HTTPS-mimicking tunnel (§6-1) deployed as a Tor pluggable transport | Bridge operator runs a real website | D4, D7 |
| **Traffic splitting** | Split circumvention traffic across multiple independent connections/paths to evade flow-based analysis | Multiple paths available; reassembly at exit | D3, D7 |

**Status (April 2025):** Reports from China indicate obfs4, meek, and Snowflake are unusable; WebTunnel connects but is quickly detected and blocked. In Russia, increasing censorship impacts obfs4 and Snowflake. Iran's protocol whitelist blocks most pluggable transports.

---

## §7. Routing & Infrastructure Exploitation

Rather than modifying the traffic itself, these techniques exploit the topology and economic structure of the internet to make censorship create unacceptable collateral damage.

### §7-1. Domain Fronting and CDN Exploitation

Leverage the gap between the network-visible destination (SNI/DNS) and the actual destination (HTTP Host header) when traffic passes through a CDN or cloud provider.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Classic domain fronting** | Set the TLS SNI to an allowed domain hosted on the same CDN as the circumvention relay, while the encrypted HTTP Host header targets the relay; the CDN routes based on the Host header | CDN hosts both the front domain and the relay; CDN does not enforce SNI-Host matching | D4, D5 |
| **Domainless fronting** | Omit the SNI entirely (or use the CDN's default domain); the CDN routes based on the Host header, which the censor cannot see | CDN accepts SNI-less connections with a default routing | D4, D5 |
| **Cloud function fronting** | Route through serverless functions (AWS Lambda, Google Cloud Functions, Azure Functions) that the censor cannot selectively block | Cloud function endpoints share IPs with thousands of other services | D5 |
| **CDN WebSocket upgrade** | Establish a WebSocket connection through a CDN to a circumvention backend; the CDN proxies WebSocket frames transparently | CDN supports WebSocket passthrough; initial HTTPS handshake uses fronting | D4, D5 |

**Status (2025):** Traditional domain fronting is deprecated by most major CDN providers — AWS (2018), Google Cloud (2018), Azure (2022), Fastly (~2024). Cloudflare also disabled domain fronting support. However, research in 2024 identified that many smaller CDN providers still permit domain fronting.

### §7-2. Refraction Networking / Decoy Routing

Embed circumvention functionality directly into the internet's core routing infrastructure, at cooperating ISPs or autonomous systems outside the censored country.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **TapDance** | Client sends a specially tagged TLS connection to a real "decoy" website; a cooperating ISP at an intermediate hop recognizes the tag and redirects traffic to a proxy | A cooperating ISP's network is on the path; the tag is steganographically hidden | D4 |
| **Conjure** | Instead of using real decoy websites, connects to "phantom" IP addresses where no real server exists; cooperating ISPs recognize tagged connections to phantom addresses and route them to proxies | Cooperating ISPs can identify phantom-addressed connections; phantom IPs are plausible | D4, D7 |
| **REDACT** | Implement refraction networking from the data center side rather than requiring ISP cooperation; operates at content providers rather than transit networks | Content provider cooperation; sufficient routing coverage | D4, D5 |

**Strategic advantage:** Refraction networking cannot be defeated by blocking individual IPs or servers — the censor would need to block all traffic passing through cooperating networks, which may carry essential commercial traffic.

### §7-3. Collateral Freedom Exploitation

Deliberately host circumvention infrastructure on platforms the censor cannot afford to block.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Cloud storage fronting** | Host circumvention relays or mirrors on AWS S3, Azure Blob, Google Cloud Storage; blocking requires blocking the entire cloud platform | Cloud platform is economically essential to the country | D5 |
| **Shared-IP hosting** | Host circumvention servers on IP addresses shared with thousands of legitimate websites (shared hosting, CDN anycast IPs) | Censor uses IP-based blocking; blocking the IP disrupts all co-hosted sites | D5 |
| **App store distribution** | Distribute circumvention apps through Google Play Store or Apple App Store; blocking the app requires blocking the store | App stores are high-collateral targets | D5 |
| **Ephemeral infrastructure** | Use rapidly rotating cloud instances, serverless functions, or volunteer proxies; the censor cannot build blocklists faster than new endpoints appear | Automation for rapid deployment; discovery mechanism for clients | D5 |

---

## §8. Traffic Analysis Countermeasures

Even when the content and destination of traffic are fully encrypted, censors can use statistical analysis of traffic patterns — timing, volume, packet sizes, directionality — to identify circumvention flows. This category covers techniques to defeat such analysis.

### §8-1. Traffic Shaping and Padding

Modify traffic patterns to match legitimate protocol profiles.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Random padding** | Add random-length padding to each packet/message to obscure the true payload size distribution | Padding is applied consistently; overhead is acceptable | D3 |
| **Constant-rate padding** | Transmit at a fixed rate regardless of actual data volume, inserting dummy packets during idle periods | Bandwidth overhead is acceptable; bidirectional padding | D3 |
| **Protocol-profile padding** | Shape packet sizes and timing to match the statistical profile of a specific legitimate application (e.g., video streaming, web browsing) | Accurate target profile; real-time traffic shaping | D6 |
| **TLS record padding** | Use TLS 1.3's record padding feature to normalize record sizes, preventing size-based content inference | Both endpoints support TLS 1.3 record padding | D3 |

### §8-2. Timing and Flow Analysis Countermeasures

Defeat timing-based fingerprinting that exploits round-trip time (RTT) discrepancies and inter-packet timing patterns.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Timing jitter injection** | Add random delays to packets to disrupt timing-based fingerprinting | Latency increase is acceptable for the application | D3 |
| **Cross-layer RTT equalization** | Pad transport-layer and application-layer responses to equalize RTT measurements across protocol layers, defeating cross-layer RTT fingerprinting | Proxy architecture supports per-layer timing control | D3 |
| **Request coalescing** | Batch multiple small requests into single transmissions to obscure request-response timing patterns | Application tolerates increased latency from batching | D3 |
| **Stream multiplexing** | Multiplex multiple independent streams over a single connection to obscure per-stream timing and volume patterns (reduces detection rates by >70%) | Multiple concurrent streams are available or can be generated | D3 |

### §8-3. Anti-Fingerprinting Defenses

Counter protocol-level and behavior-level fingerprinting used by ML classifiers.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Encapsulated TLS handshake elimination** | Avoid nested TLS handshakes within tunnels (the "TLS-in-TLS" fingerprint); use non-TLS inner protocols or XTLS Vision's direct encryption to eliminate the telltale encapsulated handshake pattern | Proxy supports XTLS Vision or equivalent; CDN usage is sacrificed | D3 |
| **Initial packet entropy masking** | Ensure the first data packet's byte distribution matches known protocol patterns (low entropy for HTTP, medium for TLS) rather than high-entropy random data | Customizable first-packet format | D3, D6 |
| **Connection behavior normalization** | Ensure connection setup timing, keepalive intervals, and teardown patterns match the mimicked protocol's behavior under load | Behavioral model of the target protocol is accurate | D6, D7 |
| **Active probe response correctness** | Ensure the circumvention server responds correctly to unexpected inputs (e.g., HTTP requests, TLS alerts) exactly as the claimed front server would | Complete protocol implementation for the front service; or transparent relay to a real server (as in REALITY §2-4) | D7 |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Censor Architecture | Primary Mutation Categories | Real-World Example |
|----------|-------------------|---------------------------|-------------------|
| **Keyword-based HTTP blocking** | Passive DPI inspecting Host header and URL | §1-1 (TCP split) + §3-1 (Host mutation) + §3-4 (URL obfuscation) | GFW HTTP keyword filter; Russia's TSPU HTTP filter |
| **SNI-based HTTPS blocking** | Stateful DPI inspecting TLS ClientHello | §2-1 (TLS fragmentation) + §2-2 (SNI mutation) + §1-1 (TCP split) | GFW SNI blocking; Russia ECH blocking |
| **SNI-based QUIC blocking** | QUIC-aware DPI decrypting Initial packets | §5-1 (CRYPTO frame split) + §2-2 (SNI mutation) | GFW QUIC censorship (April 2024–) |
| **DNS poisoning / injection** | Inline DNS interceptor injecting forged responses | §4-1 (DoH/DoT) + §4-2 (third-party resolver) + §4-3 (response filtering) | GFW DNS injection; Iran DNS manipulation |
| **Protocol whitelist enforcement** | DPI allowing only DNS, HTTP, HTTPS; blocking all else | §6-1 (HTTPS mimicry) + §6-3 (WebSocket tunnel) + §7-1 (CDN fronting) | Iran's national protocol whitelist |
| **Fully encrypted traffic detection** | ML-based entropy analysis of first packet | §6-2 (ASCII prefix) + §6-1 (TLS mimicry) + §8-3 (entropy masking) | GFW's fully-encrypted-traffic blocking (~2023) |
| **Active probing of circumvention servers** | Censor sends probe connections to suspected servers | §2-4 (REALITY) + §6-1 (WebTunnel) + §8-3 (probe response correctness) | GFW active probing of Shadowsocks/Tor |
| **IP/endpoint blocking** | Network-layer blocklisting of known circumvention IPs | §7-2 (refraction networking) + §7-3 (ephemeral infra) + §6-4 (Snowflake) | All censoring countries |
| **Traffic fingerprinting (ML)** | Statistical classifier on traffic patterns | §8-1 (padding) + §8-2 (timing) + §8-3 (anti-fingerprinting) | Cross-layer RTT detection; TLS-in-TLS detection |
| **SNI whitelist enforcement** | Only connections to explicitly approved SNIs are allowed | §2-4 (REALITY with whitelisted front) + §7-1 (CDN fronting to whitelisted CDN) | Regional deployment in parts of China (2024) |

---

## Notable Incidents and Vulnerability Disclosures (2023–2025)

| Mutation Category | Incident / Disclosure | Impact | Year |
|------------------|----------------------|--------|------|
| §1-4 (TCP state exploitation) | SymTCP discovers novel evasion strategies via symbolic execution, including urgent pointer abuse | Bypasses Zeek, Snort, and the GFW; tens of thousands of candidate evasion packets generated | 2020 |
| §1 (TCP manipulation, multiple) | Geneva genetic algorithm discovers 100+ evasion strategies against censors in CN, IN, IR, KZ | Previously unknown censor bugs discovered; deployed client-side without proxy | 2019–2025 |
| GFW internal | Wallbleed: memory disclosure vulnerability in GFW's DNS injector reveals internal architecture | Unprecedented view of GFW internals; 6+ months of data leakage before patch | 2023–2024 |
| §3-2 (HTTP smuggling) | HTTP Request Smuggling demonstrated as censorship evasion against CN, RU, IR censors | Novel application-layer evasion; effective against Host-header-based blocking | 2024 (FOCI) |
| §5-1 (QUIC frame splitting) | GFW begins QUIC SNI-based censorship; circumvented by CRYPTO frame splitting | First country-level QUIC censorship; Chrome changes naturally break GFW's single-datagram parser | 2024–2025 |
| §2-2 (ECH) | Russia blocks ECH connections to Cloudflare within one month of Cloudflare's ECH rollout | Rapid censor adaptation; ECH's limited server support undermines its circumvention potential | 2024 |
| §6-2 (fully encrypted detection) | GFW deploys entropy-based detection of fully encrypted traffic, blocking Shadowsocks and similar | Paradigm shift: "look-like-nothing" no longer viable in China | 2023 |
| §2-4 (REALITY/ShadowTLS) | Aparecium PoC demonstrates detection of ShadowTLS v3 and REALITY TLS camouflage via active probing | Questions viability of certificate-borrowing approaches | 2024–2025 |
| §6-4 (pluggable transports) | China blocks obfs4, meek, Snowflake; WebTunnel connects but is quickly blocked | All major Tor pluggable transports defeated in China | 2025 |
| §4-1 (DNS encryption) | China, Iran block ECH by censoring encrypted DNS (both DoH and DoT); Russia blocks ECH at TLS layer | Multi-layer censorship: blocking DNS encryption prevents ECH negotiation | 2024–2025 |
| §6-1 (VLESS + REALITY) | VLESS + REALITY remains functional in China and partially in Russia; blocked in Iran when IP is graylisted | Last remaining viable protocol-level evasion in China | 2024–2025 |
| §7-2 (refraction networking) | Conjure deployed in production at ISP scale; 18+ months of operational experience | Demonstrated viability of network-level circumvention | 2019–2025 |

---

## Detection and Circumvention Tools

### Evasion Tools (Client-Side / Autonomous)

| Tool | Platform | Primary Techniques | Target |
|------|----------|-------------------|--------|
| **GoodbyeDPI** | Windows | TCP fragmentation (§1-1), fake packet injection (§1-2), SNI split | Passive DPI, SNI filtering |
| **SpoofDPI** | Cross-platform (Go) | First-byte TCP split (§1-1), HTTP header fragmentation | Passive DPI |
| **ByeDPI** | Linux, Android | TCP fragmentation, fake packets, desynchronization (§1) | Passive DPI |
| **zapret** | Linux, OpenWrt | Multi-split, fake packets, disorder, desync, combined L3-L7 (§1, §2, §3) | Passive and stateful DPI |
| **Geneva** | Linux (client/server) | Genetically evolved packet manipulation strategies (§1, §2) | Any DPI; discovers novel strategies automatically |
| **SymTCP** | Linux (research) | Symbolic execution-driven TCP state discrepancy discovery (§1-4) | Stateful DPI (Zeek, Snort, GFW) |
| **DPYProxy** | Cross-platform | TLS record fragmentation (§2-1) + TCP fragmentation (§1-1) | SNI-based filtering |
| **TLSFragmenter** | Android, desktop | TLS record fragmentation of ClientHello (§2-1) | SNI-based filtering |

### Proxy/Tunnel Tools

| Tool | Protocol | Primary Techniques | Target |
|------|----------|-------------------|--------|
| **Xray-core (VLESS+REALITY)** | VLESS | TLS certificate borrowing (§2-4), XTLS Vision (§8-3) | SNI filtering, active probing, TLS-in-TLS detection |
| **Shadowsocks (2022+)** | Custom encrypted | Fully encrypted stream (§6-2), ASCII prefix countermeasure (§6-2) | Passive DPI (weakened against CN entropy detection) |
| **Tor + WebTunnel** | HTTPT/WebSocket | HTTPS mimicry (§6-1), real website cohosting | Protocol whitelist, active probing |
| **Tor + Snowflake** | WebRTC | Ephemeral volunteer proxies (§6-4, §7-3) | IP blocking |
| **Tor + obfs4** | Custom | Look-like-nothing (§6-2), bridge authentication (§6-4) | Passive DPI (defeated by entropy analysis in CN) |
| **Tor + meek** | HTTPS (CDN-fronted) | Domain fronting (§7-1), CDN collateral (§7-3) | SNI filtering, IP blocking |
| **Psiphon** | Multiple | Domain fronting, SSH tunnel, CDN fronting, protocol rotation | Multi-layered censorship |
| **Lantern** | Multiple | CDN fronting (§7-1), traffic obfuscation, cloud infrastructure | Multi-layered censorship |

### Measurement and Detection Tools

| Tool | Purpose | Technique |
|------|---------|-----------|
| **OONI Probe** | Measure censorship (DNS, HTTP, TLS, QUIC) | Controlled queries from censored vantage points; open data publication |
| **Aparecium** | Detect ShadowTLS v3 and REALITY | Active probing for TLS camouflage protocol fingerprints |
| **Censored Planet** | Remote censorship measurement | Distributed measurement using echo servers, satellite, augur |
| **GFW Report** | Document GFW behavior and vulnerabilities | Active measurement, reverse engineering, community reporting |

---

## Summary: Core Principles

### The Fundamental Property

Internet censorship bypass is possible because **censorship middleboxes operate under fundamentally different constraints than endpoints**. DPI systems must process traffic at line speed for millions of concurrent connections, forcing them to implement simplified, incomplete protocol stacks. Every simplification — skipping reassembly, ignoring edge cases, accepting invalid packets, omitting state tracking — creates an exploitable gap between the DPI's interpretation of traffic and the endpoint's interpretation. This is the same "parser differential" that underlies web security vulnerabilities like HTTP Request Smuggling, but elevated to a nation-state-vs-protocol-complexity scale.

### Why Incremental Fixes Fail

The arms race is structurally asymmetric, but not always in the same direction:

1. **At the packet/protocol level**, defenders (circumvention tools) have the advantage: the space of valid-but-unusual TCP, TLS, and HTTP constructions is vast, and each new mutation requires the censor to update its parser. Tools like Geneva can automatically discover new evasion strategies faster than censors can patch them.

2. **At the traffic analysis level**, censors are gaining ground: ML-based classifiers, cross-layer RTT fingerprinting, and TLS-in-TLS detection threaten protocol mimicry approaches. The GFW's 2023 deployment of entropy-based fully-encrypted-traffic detection invalidated an entire generation of "look-like-nothing" tools.

3. **At the infrastructure level**, the "collateral freedom" strategy remains powerful but is eroding: major CDN providers have disabled domain fronting, and censors have shown willingness to accept significant collateral damage (Russia blocking OONI Explorer; Iran's protocol whitelist).

### The Structural Solution

No single technique provides durable censorship resistance. The most resilient approaches combine multiple layers:

- **Short-term**: TCP/TLS fragmentation (§1-1, §2-1) provides immediate, low-overhead evasion against passive DPI
- **Medium-term**: Protocol mimicry with active-probe resistance (§6-1, §2-4) defeats stateful DPI and active probing
- **Long-term**: Infrastructure-level approaches (§7-2 refraction networking, §7-3 collateral freedom) change the economics of censorship

The ultimate structural solution is **raising the cost of censorship above the censor's willingness to pay** — whether through collateral damage (blocking essential services), computational cost (requiring full protocol implementation at line speed), or architectural impossibility (traffic indistinguishable from essential communication at every layer of analysis).

---

## References

The following sources informed this taxonomy. Consistent with the document's methodology, findings have been dissolved into generalized categories rather than organized by source.

### Academic Papers and Conference Proceedings
- "Geneva: Evolving Censorship Evasion Strategies" — CCS 2019
- "SymTCP: Eluding Stateful Deep Packet Inspection with Automated Discrepancy Discovery" — NDSS 2020
- "How China Detects and Blocks Shadowsocks" — IMC 2020
- "Conjure: Summoning Proxies from Unused Address Space" — CCS 2020
- "Running Refraction Networking for Real" — PETS 2020
- "How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic" — USENIX Security 2023
- "Circumventing the GFW with TLS Record Fragmentation" — CCS 2023 Poster / FOCI 2024
- "Turning Attacks into Advantages: Evading HTTP Censorship with HTTP Request Smuggling" — FOCI 2024
- "Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes" — USENIX Security 2024
- "On Precisely Detecting Censorship Circumvention in Real-World Networks" — NDSS 2024
- "The Discriminative Power of Cross-layer RTTs in Fingerprinting Proxy Traffic" — NDSS 2025
- "Wallbleed: A Memory Disclosure Vulnerability in the Great Firewall of China" — NDSS 2025
- "Encrypted Client Hello (ECH) in Censorship Circumvention" — FOCI 2025
- "Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China" — USENIX Security 2025
- "A Wall Behind A Wall: Emerging Regional Censorship in China" — IEEE S&P 2025
- "Transport Layer Obscurity: Circumventing SNI Censorship on the TLS-Layer" — 2025
- "Advancing Obfuscation Strategies to Counter China's Great Firewall" — arXiv 2025
- "A Survey of Internet Censorship and its Measurement: Methodology, Trends, and Challenges" — 2025

### Tools and Projects
- Geneva: https://geneva.cs.umd.edu/
- GoodbyeDPI: https://github.com/ValdikSS/GoodbyeDPI
- zapret: https://github.com/bol-van/zapret
- Xray-core (XTLS/REALITY): https://github.com/XTLS/Xray-core
- ShadowTLS: https://github.com/ihciah/shadow-tls
- uTLS: https://github.com/refraction-networking/utls
- OONI Probe: https://ooni.org
- GFW Report: https://gfw.report/
- Tor Project Pluggable Transports: https://www.torproject.org
- Refraction Networking: https://refraction.network/
- Censored Planet: https://censoredplanet.org/

### Community and Reporting
- net4people/bbs: https://github.com/net4people/bbs
- Tor Project Forum — Censorship Circumvention: https://forum.torproject.org
- Open Technology Fund: https://www.opentech.fund/

---

*This document was created for defensive security research, censorship measurement, and internet freedom purposes. The techniques described are documented to support the development of censorship-resistant communication tools and to inform policy discussions about internet freedom.*
