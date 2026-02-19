# WebSocket Security Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy classifies the entire WebSocket attack surface along three orthogonal axes. **Axis 1 (Mutation Target)** identifies the structural component of the WebSocket lifecycle being exploited — from the initial HTTP Upgrade handshake, through protocol framing, message payloads, connection state, proxy intermediaries, transport security, higher-level sub-protocols, and concurrent state management. This axis structures the main body of the document. **Axis 2 (Discrepancy Type)** captures the nature of the security violation each mutation creates: origin bypass, authentication bypass, parser differential, input validation failure, state desynchronization, or resource exhaustion. **Axis 3 (Attack Scenario)** maps each technique to the real-world impact context in which it becomes weaponizable.

WebSocket's fundamental security characteristic is its **protocol duality**: it begins as HTTP (the handshake) and then transitions into a persistent, full-duplex, message-oriented TCP channel. This transition point — and the assumptions each layer makes about the other — is the root cause of the entire mutation space. HTTP security mechanisms (CORS, CSRF tokens, Content-Type enforcement) do not carry over to post-handshake WebSocket communication, while the WebSocket protocol itself (RFC 6455) delegates authentication and authorization entirely to the application layer. Every category in this taxonomy exploits some consequence of this fundamental design.

### Axis 2: Cross-Cutting Discrepancy Types

| Discrepancy Type | Description |
|---|---|
| **Origin/CSRF Bypass** | Exploiting absent or weak origin validation to initiate cross-site WebSocket connections |
| **Authentication Bypass** | Circumventing authentication via alternate paths, missing token validation, or handshake-only auth |
| **Authorization Bypass** | Accessing resources or performing actions beyond granted privileges via WebSocket messages |
| **Parser Differential** | Exploiting interpretation mismatches between proxy and backend on handshake/framing semantics |
| **Protocol Confusion** | Leveraging ambiguity in protocol upgrade mechanics to create unintended tunnel states |
| **Input Validation Failure** | Injecting malicious content through insufficiently sanitized WebSocket message payloads |
| **State Desynchronization** | Creating inconsistent state between client, server, or intermediaries through timing or ordering attacks |
| **Resource Exhaustion** | Consuming excessive memory, CPU, connections, or bandwidth via protocol-specific mechanisms |

---

## §1. Handshake Manipulation

The WebSocket handshake is an HTTP/1.1 Upgrade request that transitions the connection from HTTP to the WebSocket protocol. Attacks in this category target the handshake phase itself — the Origin header, cookie transmission, upgrade headers, and server validation logic — to establish unauthorized or hijacked WebSocket connections.

### §1-1. Cross-Site WebSocket Hijacking (CSWSH)

Cross-Site WebSocket Hijacking is the WebSocket analog of Cross-Site Request Forgery (CSRF). Because the WebSocket handshake is an HTTP request, browsers automatically attach cookies to it. If the server relies solely on cookies for authentication and does not validate the `Origin` header, a malicious website can initiate a WebSocket connection to the target on behalf of an authenticated victim.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Classic CSWSH** | Malicious page opens `new WebSocket('wss://target.com/ws')` which sends victim's cookies automatically; attacker receives all server messages on their controlled endpoint | `SameSite=None` on auth cookies + no Origin validation |
| **GraphQL-over-WebSocket CSWSH** | Target exposes GraphQL API via WebSocket (e.g., `graphql-ws` protocol); CSWSH enables arbitrary query/mutation/subscription execution including destructive operations (account deletion, data exfiltration) | GraphQL endpoint accessible via WS + cookie auth without CSRF token enforcement on WS |
| **Subdomain Trust CSWSH** | When SameSite=Lax is set, CSWSH is blocked cross-site — but subdomains of the same registrable domain are considered "same-site"; an XSS on any subdomain enables CSWSH against the main domain | Multi-tenant subdomain architecture (e.g., `*.example.com`) |
| **Private Network CSWSH** | WebSocket connections from public web pages to private/localhost IPs (`127.0.0.1`, `192.168.x.x`); Chrome's Private Network Access preflight does NOT apply to WebSocket connections | Locally-bound WebSocket server without origin/auth checks |
| **SameSite Lax 2-Minute Grace Period** | Chrome temporarily allows cross-site cookie transmission for POST navigations within 2 minutes of cookie creation; however, this does NOT apply to CSWSH because WebSocket handshakes are not top-level POST navigations | Not directly exploitable for CSWSH; included for disambiguation |

**Browser Mitigation Landscape (2025):**

| Browser | SameSite Default | Third-Party Cookie Policy | CSWSH Status |
|---|---|---|---|
| Chrome 130+ | Lax | Restricted (but exceptions exist) | Blocked for `SameSite=Lax/Strict`; exploitable if `SameSite=None` |
| Firefox (ETP) | None (but Total Cookie Protection active) | Partitioned per-site | Effectively blocked by Total Cookie Protection |
| Safari | Lax | ITP blocks third-party cookies | Blocked for most scenarios |

Despite browser-level mitigations, CSWSH remains exploitable in 2025 when: (a) auth cookies explicitly set `SameSite=None` (common for cross-origin auth services), (b) targets are on private/localhost networks, or (c) XSS exists on a sibling subdomain.

### §1-2. Origin Header Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Missing Origin Validation** | Server does not check `Origin` header at all during handshake; any website can connect | Server-side configuration gap (extremely common; e.g., `ws` library for Node.js does not enforce Origin by default) |
| **Regex Bypass** | Server validates Origin using a permissive regex (e.g., `/example\.com/` matches `evil-example.com` or `example.com.attacker.com`) | Improperly anchored regex pattern |
| **Null Origin** | Sandboxed iframes (`<iframe sandbox>`) or `data:` URI pages send `Origin: null`; servers with allowlists that include `null` are bypassed | Server allows `null` as a valid origin |
| **Non-Browser Client Spoofing** | Scripts outside browsers (Python, curl, etc.) can set arbitrary `Origin` headers; Origin validation only protects against browser-initiated cross-origin attacks, not direct API abuse | Origin used as sole authentication mechanism |

### §1-3. Handshake Header Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Sec-WebSocket-Version Downgrade** | Client requests an unsupported protocol version; some servers fall back to weaker behaviors or error-handling paths that expose information or bypass validation | Server does not strictly reject unsupported versions |
| **Sec-WebSocket-Protocol Injection** | Manipulating the subprotocol negotiation header to request access to privileged protocol channels (e.g., `graphql-ws`, `stomp`) | Server grants access to any requested subprotocol without authorization checks |
| **Sec-WebSocket-Extensions Abuse** | Requesting extensions (e.g., `permessage-deflate` with extreme parameters) to influence server resource allocation or compression behavior | Server accepts extension parameters without bounds checking |
| **Custom Header Injection via Handshake** | Injecting CRLF sequences or additional headers during the upgrade request to manipulate proxy/server behavior | HTTP/1.1 header parsing vulnerabilities in proxy or server |

---

## §2. Authentication & Session Management

WebSocket has no built-in authentication mechanism. RFC 6455 explicitly delegates this to the application layer, creating a class of vulnerabilities where developers either forget to authenticate WebSocket connections entirely or authenticate only at handshake time without per-message validation.

### §2-1. Missing or Handshake-Only Authentication

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unauthenticated WebSocket Endpoint** | Server exposes WebSocket endpoint with no authentication at all; any client can connect and interact | Common in development tools, IoT devices, local services (CVE-2025-52882: Claude Code MCP server) |
| **Handshake-Only Auth** | Authentication verified during HTTP Upgrade handshake (via cookies or tokens), but no per-message authentication applied; once connected, any message is trusted | Server assumes handshake auth persists for entire connection lifetime |
| **Token in URL Query Parameter** | Authentication token passed as `?token=xxx` in the WebSocket URL; visible in server logs, proxy logs, Referer headers, browser history | Token exposure through logging and caching |
| **Port Brute-Force for Local Services** | Localhost-bound WebSocket servers on dynamic ports are discovered by systematically scanning the port range from a malicious web page via JavaScript `new WebSocket()` attempts | Dynamic port allocation + no auth (CVE-2025-52882) |

### §2-2. Session Binding Weaknesses

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Session Fixation via WebSocket** | Attacker establishes WebSocket connection, obtains session identifier, then tricks victim into using that session | Session ID generated before authentication completes |
| **Session Non-Revocation** | User logs out or session is invalidated, but existing WebSocket connections continue operating with stale credentials | No mechanism to push session invalidation to active WS connections |
| **Cross-Connection Session Confusion** | In multiplexed environments (HTTP/2 + RFC 8441), WebSocket streams may incorrectly inherit or share session state with other streams on the same connection | Shared connection state in HTTP/2 multiplexed WebSockets |

### §2-3. Authorization Bypass via Messages

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **IDOR in WebSocket Messages** | Manipulating resource identifiers in WebSocket message payloads (e.g., changing `{"userId": 123}` to `{"userId": 456}`) to access other users' data or perform actions on their behalf | Missing per-message authorization checks on resource identifiers |
| **Privilege Escalation via Message Type** | Sending administrative or privileged message types through a standard user connection (e.g., `{"action": "admin_delete_user"}`) | Authorization checked at handshake but not per-message-type |
| **Channel/Room Escape** | Subscribing to or sending messages in channels/rooms the user should not have access to, bypassing subscription-level access controls | Channel authorization only checked at subscription time, or subscription requests not validated |

---

## §3. Protocol Framing Attacks

RFC 6455 defines a binary framing layer with opcodes, masking, fragmentation, and payload length encoding. Attacks in this category exploit the framing layer itself — targeting implementation bugs in frame parsers, mask handling, and fragmentation reassembly.

### §3-1. Frame Structure Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Oversized Payload Length Declaration** | Sending a frame with the 64-bit extended payload length set to an extremely large value (near `2^63`); vulnerable servers pre-allocate a buffer of that size, causing Out-of-Memory crashes | Server trusts declared payload length for buffer pre-allocation without bounds checking |
| **Payload Length Mismatch** | Declaring a payload length that differs from the actual data sent; causes parser confusion, buffer over/under-reads, or protocol state corruption | Implementation does not validate actual vs. declared length |
| **Reserved Bit Manipulation** | Setting RSV1/RSV2/RSV3 bits without negotiating the corresponding extension; spec-compliant servers should fail the connection, but non-compliant ones may exhibit undefined behavior | Server ignores reserved bit validation |
| **Invalid Opcode Injection** | Sending frames with undefined opcodes (0x3-0x7 for data, 0xB-0xF for control); some implementations process these as valid, creating protocol confusion | Server does not reject undefined opcodes |

### §3-2. Masking Vulnerabilities

Client-to-server frames MUST be masked (RFC 6455 §5.1) to prevent cache poisoning of intermediary proxies. The 32-bit masking key should be unpredictable for each frame.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Predictable Mask Pattern** | Client uses a static or predictable masking key across frames; an intermediary proxy can be tricked into interpreting masked WebSocket data as valid HTTP, enabling cache poisoning | Fixed/reused masking key (CVE-2025-10148: curl used a persistent mask for entire connections) |
| **Missing Client Masking** | Client sends unmasked frames; spec-compliant servers should reject these, but proxies that see the unmasked payload may interpret it as HTTP traffic | Non-browser client + non-compliant server that accepts unmasked frames |
| **Server-to-Client Masking** | Server erroneously masks server-to-client frames; while not a direct attack, this violates the protocol and can confuse client parsers | Server implementation bug |

### §3-3. Fragmentation Attacks

WebSocket allows a single logical message to be split across multiple frames using the FIN bit and continuation opcodes.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Infinite Fragmentation DoS** | Sending an endless stream of continuation frames (FIN=0) with small payloads, forcing the server to buffer an ever-growing incomplete message | Server has no limit on reassembly buffer size or maximum message size |
| **Interleaved Control Frame Injection** | RFC 6455 allows control frames (ping/pong/close) to be interleaved between fragments of a data message; sending unexpected control frames during reassembly may disrupt server state machines | Server's fragment reassembly logic doesn't correctly handle interleaved control frames |
| **Fragment Boundary Injection** | Splitting a malicious payload across fragment boundaries to bypass content-inspection middleware that only examines complete frames | WAF/IDS inspects individual frames rather than reassembled messages |
| **Opcode Continuation Confusion** | Sending continuation frames (opcode 0x0) without a preceding initial frame; some implementations may enter undefined states or read from uninitialized buffers | Server does not validate fragmentation state machine |

---

## §4. Message Payload Injection

Once a WebSocket connection is established, message payloads flow bidirectionally without the HTTP request/response framing. This bypasses many traditional web security mechanisms (Content-Type restrictions, CORS, WAF rules designed for HTTP). All conventional injection attacks transfer to WebSocket messages but are often overlooked because security tooling has historically focused on HTTP.

### §4-1. Server-Side Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SQL Injection via WebSocket** | WebSocket message parameters (typically JSON fields) are concatenated into SQL queries without parameterization; e.g., `{"search": "' OR 1=1--"}` | Server-side code constructs SQL from WS message data without prepared statements |
| **Command Injection via WebSocket** | Message fields are passed to system shell commands; e.g., `{"filename": "; rm -rf /"}` | Server passes WS message data to `exec()`, `system()`, or similar functions |
| **Server-Side Template Injection (SSTI)** | Template expressions injected via WebSocket messages are evaluated server-side; e.g., `{"name": "{{7*7}}"}` | Server renders WS message content through template engines |
| **XXE via WebSocket** | XML payloads sent over WebSocket with external entity declarations; e.g., `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` | Server parses XML from WS messages with external entity processing enabled |
| **SSRF via WebSocket** | WebSocket message contains a URL that the server fetches; e.g., `{"imageUrl": "http://169.254.169.254/latest/meta-data/"}` | Server-side URL fetching triggered by WS message content |
| **NoSQL Injection** | JSON operator injection in WebSocket messages targeting MongoDB or similar; e.g., `{"username": {"$gt": ""}, "password": {"$gt": ""}}` | Server passes WS JSON directly to NoSQL query engine |

### §4-2. Client-Side Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Stored XSS via WebSocket** | Server broadcasts a malicious WebSocket message containing JavaScript to connected clients; client renders it as HTML without sanitization; e.g., chat message: `<img src=x onerror=alert(1)>` | Client-side code uses `innerHTML` or equivalent to render WS message content |
| **DOM Manipulation via WebSocket** | WebSocket messages control DOM operations (element creation, attribute setting); malicious messages inject event handlers or modify page structure | Client uses WS data to dynamically construct DOM elements without sanitization |
| **WebSocket-to-HTTP Injection** | Client takes data from a WebSocket message and includes it in subsequent HTTP requests (e.g., as a URL parameter or header value) without sanitization | Client code bridges WS messages to HTTP requests |

### §4-3. Protocol-Layer Payload Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Compression Bomb (Zip Bomb)** | When `permessage-deflate` extension is negotiated, sending a small compressed payload that expands to gigabytes upon decompression | Server uses `permessage-deflate` without decompressed size limits |
| **Binary Frame Type Confusion** | Sending binary frames (opcode 0x2) when the application expects text frames (opcode 0x1) or vice versa; may cause encoding errors, parser crashes, or bypass text-based input validation | Application does not validate frame type before processing |
| **JSON/MessagePack Deserialization** | Exploiting deserialization vulnerabilities in the message serialization format used over WebSocket (JSON prototype pollution, MessagePack type confusion, etc.) | Server deserializes WS messages using vulnerable libraries |

---

## §5. Proxy and Intermediary Exploitation

WebSocket connections frequently traverse reverse proxies, load balancers, CDNs, and WAFs. The protocol upgrade mechanism creates a unique attack surface where intermediaries must correctly interpret both the HTTP handshake and the subsequent binary framing. Mismatches between proxy and backend interpretation enable smuggling, tunneling, and security control bypass.

### §5-1. WebSocket Smuggling

WebSocket smuggling exploits discrepancies in how a front-end proxy and a back-end server interpret the Upgrade handshake. If they disagree on whether the handshake succeeded, an attacker can tunnel raw HTTP requests through the "phantom" WebSocket connection.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Status Code Ignorance** | Client sends Upgrade request with invalid `Sec-WebSocket-Version`; backend responds with 426 (Upgrade Required) but proxy doesn't check response status and assumes the upgrade succeeded, opening a TCP tunnel to the backend | Proxy (e.g., Varnish, older Envoy) does not validate backend's response code |
| **SSRF-Triggered 101 Response** | Attacker sends POST request to a public endpoint with `Upgrade: websocket` header; backend follows an SSRF to attacker-controlled server that returns HTTP 101; proxy (e.g., NGINX) sees 101 and establishes a raw tunnel | Backend has SSRF vulnerability + proxy trusts any 101 response |
| **h2c Smuggling via WebSocket** | Abusing HTTP/2 cleartext (h2c) upgrade mechanism in conjunction with WebSocket upgrade headers to bypass proxy access controls and reach internal endpoints | Proxy supports both h2c and WebSocket upgrades without proper isolation |
| **Upgrade Header Injection** | Injecting `Upgrade: websocket` and `Connection: Upgrade` headers into unrelated HTTP requests to trick proxies into establishing tunnel connections | Proxy processes Upgrade headers without context validation |

### §5-2. Proxy Bypass and Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **WAF Bypass via WebSocket** | After upgrade, traffic flows as binary WebSocket frames rather than HTTP; most WAFs only inspect HTTP traffic and are blind to WebSocket message content | WAF lacks WebSocket-aware deep packet inspection |
| **ACL Bypass via Tunnel** | Once a WebSocket tunnel is established (legitimately or via smuggling), internal-only HTTP endpoints become accessible through the tunnel | Internal APIs accessible from the backend host that serves WebSocket |
| **IP-Based ACL Evasion** | WebSocket connections proxied through a load balancer inherit the proxy's internal IP; backend ACLs that trust internal IPs are bypassed | Backend uses source IP for access control + WebSocket goes through trusted proxy |
| **Rate Limit Bypass** | Rate limiting applied per-HTTP-request does not account for WebSocket messages; a single WebSocket connection can send unlimited messages without triggering HTTP rate limits | Rate limiting operates at HTTP layer only |

### §5-3. Cache Poisoning via WebSocket

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unmasked Frame Cache Poisoning** | Client sends unmasked WebSocket frames crafted to resemble HTTP responses; intermediary proxy caches the "response" and serves it to other users | Client doesn't mask + proxy doesn't distinguish WS frames from HTTP (original motivation for RFC 6455 masking requirement) |
| **Predictable Mask Cache Poisoning** | Known masking key allows attacker to craft frames whose masked content, when XOR'd by the predictable key, produces valid HTTP responses that poison proxy caches | Predictable or static masking key (CVE-2025-10148) |
| **Post-Upgrade Response Confusion** | After WebSocket upgrade, server sends data that is misinterpreted by the proxy as HTTP responses for subsequent requests on the same connection | Proxy doesn't fully isolate WebSocket traffic from HTTP connection pool |

---

## §6. Transport Layer Attacks

WebSocket supports both unencrypted (`ws://`) and TLS-encrypted (`wss://`) connections. Transport-layer attacks target the confidentiality and integrity of WebSocket communication.

### §6-1. Encryption and MITM

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Plaintext WebSocket Interception** | Passive eavesdropping or active modification of `ws://` traffic by any network intermediary | Application uses `ws://` instead of `wss://` |
| **TLS Downgrade** | Attacker strips or interferes with the TLS upgrade process, forcing the client to fall back to `ws://` | Application does not enforce `wss://`-only; no HSTS for WebSocket |
| **Mixed Content Exploitation** | HTTPS page establishes `ws://` WebSocket connection; while modern browsers block this, older browsers or non-browser clients may allow it | Legacy browser or misconfigured client |
| **Certificate Validation Bypass** | Non-browser WebSocket clients (IoT devices, mobile apps) skip or improperly implement TLS certificate validation | Custom TLS implementation without proper chain validation |

### §6-2. Connection Hijacking

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **TCP Session Hijacking** | On unencrypted connections, attacker injects frames into the TCP stream to take over the WebSocket conversation | `ws://` connection on a network where attacker can inject packets |
| **DNS Rebinding** | Attacker's domain initially resolves to their server (passing Origin checks), then re-resolves to the target's internal IP, enabling WebSocket connections to internal services | Target validates Origin against DNS name (not IP) + short DNS TTL |

---

## §7. Higher-Level Protocol Attacks

Many applications use WebSocket as a transport for higher-level protocols (STOMP, Socket.IO, GraphQL subscriptions, JSON-RPC). These protocols introduce their own message framing, routing, and state management — and their own vulnerability classes.

### §7-1. STOMP over WebSocket

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **STOMP Frame Smuggling (Pre-CONNECT Injection)** | Sending a WebSocket message containing multiple STOMP frames where a SEND or SUBSCRIBE frame precedes the CONNECT frame; server processes them before authentication completes | Spring Framework STOMP implementation (CVE-2025-41254) |
| **STOMP Destination Injection** | Subscribing to or sending messages to unauthorized STOMP destinations (e.g., `/topic/admin`) by manipulating the destination header in STOMP frames | Missing per-destination authorization in STOMP broker |
| **STOMP Header Injection** | Injecting STOMP protocol headers (e.g., `receipt`, `transaction`) to manipulate server-side transaction handling or trigger unexpected behavior | Server processes all STOMP headers without validation |

### §7-2. Socket.IO Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Event Name Type Confusion** | Sending Socket.IO packets where the event name is an object instead of a string; server calls `eventName.toString()` on the object, which throws an uncaught exception and crashes the Node.js process | Socket.IO < 4.6.2 (CVE-2023-32695) |
| **Object Event Name DoS** | Crafted packets override the `toString()` method on the event name object, causing a crash when the EventEmitter resolves the handler | Socket.IO < 4.6.2 |
| **Namespace Injection** | Connecting to unauthorized Socket.IO namespaces that expose privileged event handlers or data streams | Missing per-namespace authentication/authorization |
| **Binary Attachment Manipulation** | Socket.IO's binary attachment mechanism can be abused to inject unexpected binary data or trigger deserialization vulnerabilities | Server processes binary attachments without type validation |
| **Engine.IO Polling Fallback Exploitation** | When WebSocket is unavailable, Socket.IO falls back to HTTP long polling; this fallback may have different security characteristics (vulnerable to standard HTTP CSRF, different auth handling) | Inconsistent security policy between WS and polling transports |

### §7-3. GraphQL over WebSocket

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Subscription Hijacking via CSWSH** | Combining CSWSH (§1-1) with GraphQL subscriptions to receive real-time data streams from the victim's account | GraphQL WS endpoint + cookie auth + no Origin validation |
| **Introspection via WebSocket** | Querying the GraphQL introspection system (`__schema`) over a hijacked WebSocket connection to map the entire API surface | Introspection enabled + CSWSH vulnerability |
| **Mutation via Hijacked Connection** | Executing destructive GraphQL mutations (delete account, modify data) through a CSWSH-hijacked WebSocket connection | CSWSH + no per-operation authorization |
| **Batched Query DoS** | Sending deeply nested or batched GraphQL queries through WebSocket to exhaust server resources | No query depth/complexity limits on WS-delivered GraphQL |

### §7-4. JSON-RPC over WebSocket

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Method Enumeration** | Sending JSON-RPC `system.listMethods` or systematically calling methods to discover the API surface | No method-level access control |
| **Unauthorized Method Invocation** | Calling administrative or privileged JSON-RPC methods over WebSocket without proper authorization | Authorization checked only at connection, not per-method (CVE-2025-52882: MCP server exposed `tools/list` and tool execution) |
| **Notification Abuse** | JSON-RPC notifications (requests without `id`) do not receive responses; attackers flood with notifications to trigger server-side effects without receiving error feedback | No rate limiting on notification messages |

---

## §8. Denial of Service

WebSocket's persistent, full-duplex nature creates unique DoS attack surfaces that differ significantly from HTTP-based DoS. A single connection can consume server resources indefinitely.

### §8-1. Connection-Level DoS

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Connection Exhaustion (Slowloris-WS)** | Opening the maximum number of WebSocket connections and keeping them alive with periodic ping/pong frames while performing no useful work; exhausts the server's connection pool | No per-IP or per-user connection limits |
| **Half-Open Connection Flood** | Initiating WebSocket handshakes but not completing the protocol negotiation, tying up server resources in pending-upgrade state | Server pre-allocates resources before handshake completion |
| **Zombie Connection Accumulation** | Connections that appear alive due to TCP keepalive but have no application-layer activity; accumulate over time consuming file descriptors and memory | No application-layer heartbeat timeout |

### §8-2. Message-Level DoS

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Message Flooding** | Sending a high volume of messages through a single connection to overwhelm server-side message processing | No per-connection message rate limit |
| **Large Message Attack** | Sending individual messages that are extremely large (multiple MB/GB), exhausting server memory during processing | No maximum message size limit |
| **Compression Bomb** | As described in §4-3: small compressed payload expands to massive size upon decompression when `permessage-deflate` is active | `permessage-deflate` enabled without decompressed size limit |
| **Computational DoS** | Sending messages that trigger expensive server-side operations (complex regex evaluation, heavy database queries, cryptographic operations) | Server-side processing cost not bounded per message |

### §8-3. Protocol-Level DoS

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Ping Flood** | Sending continuous ping frames; server MUST respond with pong for each, consuming CPU and bandwidth | No ping rate limit |
| **Close Frame Loop** | Repeatedly sending close frames to trigger connection teardown/re-establishment overhead | No close frame rate limit |
| **Fragmentation Bomb** | As described in §3-3: endless continuation frames force server to maintain and grow reassembly buffer | No maximum fragment count or reassembly timeout |
| **Malformed Frame Crash (Ping-of-Death)** | Sending WebSocket frames with invalid structure (e.g., manipulated payload length headers without full data) to trigger parser crashes, null pointer dereferences, or buffer overflows | Implementation bugs in frame parser |

---

## §9. Concurrency and State Attacks

WebSocket's persistent, asynchronous nature creates timing-sensitive state management challenges. Unlike HTTP's stateless request-response model, WebSocket servers must maintain per-connection state across an arbitrary number of concurrent messages.

### §9-1. Race Conditions

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Multi-Connection Race** | Spawning multiple independent WebSocket connections and sending conflicting state-changing messages simultaneously to bypass business logic checks (e.g., double-spend, duplicate redemption) | Server-side state check and state update are not atomic |
| **Single-Connection Parallel Messages** | Sending multiple messages in rapid succession on a single connection; server may process them concurrently if using async handlers, creating race windows | Async message handlers without proper synchronization |
| **Token Reuse Race** | Simultaneously using a single-use token (OTP, nonce) across multiple WebSocket connections before the server can invalidate it | Token validation and invalidation are not atomic |
| **Subscription Race** | Subscribing and unsubscribing rapidly to exploit race windows in channel membership management, potentially receiving messages from channels after unsubscription | Non-atomic subscription state management |

### §9-2. State Desynchronization

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Client-Server State Drift** | Client and server disagree on the current state of the session (e.g., user permissions, game state, transaction status) due to out-of-order message delivery or lost messages | No state synchronization mechanism |
| **Broadcast State Confusion** | In pub/sub systems, messages delivered to multiple subscribers may create inconsistent state if any subscriber's processing fails or is delayed | No transactional guarantee on broadcast delivery |
| **Reconnection State Reset Exploit** | After disconnect/reconnect, the server re-initializes state but the client retains stale state or vice versa; this delta can be exploited to gain unauthorized access or bypass restrictions | No state reconciliation protocol on reconnection |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Cross-Site Data Theft** | Browser → target WebSocket with cookie auth | §1-1, §1-2, §7-3 |
| **Internal Network Pivoting** | Public web → private network WebSocket | §1-1 (Private Network CSWSH), §5-1, §6-2 |
| **Remote Code Execution** | WS message → server-side command execution | §2-1, §4-1, §7-4 |
| **Account Takeover** | CSWSH + privileged API operations | §1-1, §2-3, §7-3 |
| **Denial of Service** | Connection/message/protocol level exhaustion | §3-1, §3-3, §4-3, §8 |
| **Cache Poisoning** | Proxy misinterprets WS frames as HTTP | §3-2, §5-3 |
| **WAF/ACL Bypass** | Tunneled HTTP through WS upgrade | §5-1, §5-2 |
| **Session Hijacking** | Steal or reuse WebSocket session credentials | §2-2, §6-1 |
| **Privilege Escalation** | Access admin functions via WS messages | §2-3, §7-1, §7-4 |
| **Data Manipulation** | Modify in-transit data or server state | §4-1, §6-1, §9 |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §2-1 + §1-1 (Unauthenticated local WS + port brute-force) | CVE-2025-52882 (Claude Code MCP Server) | CVSS 8.8 — Arbitrary file read, code execution via unauthenticated localhost WebSocket |
| §7-1 (STOMP frame smuggling, pre-CONNECT injection) | CVE-2025-41254 (Spring Framework) | Medium — Unauthorized STOMP messages bypass CSRF protection; affects Spring 4.3–6.2 |
| §3-2 (Predictable masking key) | CVE-2025-10148 (curl) | Proxy cache poisoning via static WebSocket masking key reused across entire connection |
| §2-1 + §1-2 (Auth bypass via Node.js WS module) | CVE-2024-55591 (FortiOS/FortiProxy) | CVSS 9.6 — Super-admin privilege gain via crafted WebSocket requests; actively exploited in the wild |
| §1-1 (CSWSH, missing Origin validation) | CVE-2024-26135 (MeshCentral) | Cross-site WebSocket hijacking enables unauthorized management operations |
| §1-1 + §1-2 (CSWSH, subdomain trust) | CVE-2024-11045 (various) | CSWSH via subdomain trust boundaries |
| §7-2 (Socket.IO event name type confusion) | CVE-2023-32695 (Socket.IO) | DoS — Server crash via crafted event name object that overrides `toString()` |
| §1-1 + §6-2 (CSWSH + subdomain XSS chain) | CVE-2023-0957 (Gitpod) | Full account compromise — CSWSH + SameSite bypass + VS Code server exploitation |
| §8-1 (Connection resource exhaustion) | Apache Tomcat WebSocket DoS (2024) | DoS — WebSocket client keeps connection open, exhausting server resources |
| §1-1 (CSWSH with GraphQL mutations) | Include Security 2025 Research | Account deletion via GraphQL-over-WebSocket CSWSH; `SameSite=None` cookies; blocked in Firefox |
| §1-1 (Private Network CSWSH) | Include Security 2025 Research | Camera device exploitation — video streaming and configuration via localhost CSWSH; works in all browsers |
| §5-1 (WebSocket smuggling via status code ignorance) | @0ang3el Research | Internal API access via phantom WebSocket tunnel through Varnish, Envoy reverse proxies |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **WebSocket Turbo Intruder** (Burp Extension) | Message fuzzing, race conditions, protocol-level attacks | Custom Python scripts; high-performance WS engine sending thousands of messages/sec; THREADED engine for concurrent connections; malformed frame support |
| **STEWS** (Security Tool for Enumerating WebSockets) | Discovery + vulnerability detection | Modified ZGrab2 for WS endpoint discovery; tests known WS vulnerabilities; enumerates subprotocols and extensions |
| **WSSiP** (WebSocket/Socket.IO Proxy) | Traffic interception + modification | Man-in-the-middle proxy for WS and Socket.IO; capture, intercept, and send custom messages |
| **websocket-fuzzer** (Python) | Message fuzzing | JSON-focused WebSocket fuzzer; payload mutation for injection testing |
| **Burp Suite** (native WS support) | Traffic analysis + interception | WebSocket message history; message interception and modification; repeater support |
| **websocket-smuggle** (@0ang3el) | Smuggling PoC | Automated WebSocket smuggling exploitation against reverse proxies |
| **PayloadsAllTheThings** (WebSocket section) | Payload reference | Curated payloads for CSWSH, injection, and manipulation attacks |
| **ZAP** (OWASP) | WebSocket scanning | WebSocket breakpoints, fuzzing, and message analysis |
| **WS_RaceCondition_PoC** | Race condition testing | Proof-of-concept for demonstrating race conditions over WebSocket connections |
| **SQLMap** (via WS harness) | SQL injection over WebSocket | HTTP-to-WebSocket harness enables SQLMap to target WS-backed databases |

---

## Summary: Core Principles

### The Root Cause: Protocol Duality Without Security Continuity

WebSocket's entire mutation space stems from a single architectural reality: the protocol is born as HTTP and reborn as a raw TCP channel, yet no security context automatically crosses this boundary. HTTP's decades of security tooling — CORS, CSRF tokens, Content-Type enforcement, WAF signatures, cookie policies — are designed for stateless request-response exchanges and largely cease to function once the connection upgrades to WebSocket. Simultaneously, RFC 6455 provides no authentication, no authorization, and no input validation at the protocol level, explicitly delegating all security to the application.

This creates a fundamental mismatch: developers and security tools assume HTTP-level protections apply, while the WebSocket runtime operates in a security vacuum. Cross-Site WebSocket Hijacking exists because CSRF tokens don't carry over. Injection attacks succeed because WAFs don't inspect WebSocket frames. Authorization bypass works because per-request access controls become meaningless in a persistent connection. The handshake is HTTP; everything after is not. This discontinuity is the genesis of every category in this taxonomy.

### Why Incremental Fixes Fail

Patching individual WebSocket vulnerabilities produces a perpetual game of catch-up for three reasons. First, the attack surface multiplies with every higher-level protocol layered on top: STOMP, Socket.IO, GraphQL, and JSON-RPC each introduce their own framing, routing, and state management — and their own security gaps. Second, the intermediary ecosystem (proxies, load balancers, CDNs) was designed for HTTP and bolted on WebSocket support as an afterthought, creating parser differentials that smuggling attacks exploit. Third, browser-level mitigations (SameSite cookies, Total Cookie Protection, Private Network Access) each address a narrow slice of the problem while leaving other vectors open — SameSite doesn't protect `SameSite=None` cookies required by cross-origin auth; Private Network Access doesn't cover WebSocket connections; Firefox blocks CSWSH via cookie partitioning but Chrome doesn't.

### The Structural Solution

A comprehensive defense requires treating WebSocket as a first-class security boundary with its own defense stack: (1) per-message authentication and authorization that is independent of the HTTP handshake; (2) server-side Origin validation as a mandatory configuration, not opt-in; (3) input validation and output encoding on every message as if it were an untrusted HTTP request; (4) WebSocket-aware WAFs and monitoring that inspect post-upgrade traffic; (5) strict proxy validation of the complete upgrade lifecycle (request headers, response status, response headers); and (6) rate limiting, message size limits, and connection limits applied at the WebSocket protocol layer, not the HTTP layer. Until the ecosystem treats the WebSocket channel with the same security rigor as HTTP, the mutation space documented here will continue to expand.

---

## References

- RFC 6455: The WebSocket Protocol — https://www.rfc-editor.org/rfc/rfc6455
- RFC 8441: Bootstrapping WebSockets with HTTP/2 — https://www.rfc-editor.org/rfc/rfc8441
- OWASP WebSocket Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html
- Include Security: Cross-Site WebSocket Hijacking Exploitation in 2025 — https://blog.includesecurity.com/2025/04/cross-site-websocket-hijacking-exploitation-in-2025/
- PortSwigger Research: WebSocket Turbo Intruder — https://portswigger.net/research/websocket-turbo-intruder-unearthing-the-websocket-goldmine
- PortSwigger Web Security Academy: WebSockets — https://portswigger.net/web-security/websockets
- Datadog Security Labs: CVE-2025-52882 — https://securitylabs.datadoghq.com/articles/claude-mcp-cve-2025-52882/
- HeroDevs: CVE-2025-41254 Spring WebSocket CSRF — https://www.herodevs.com/blog-posts/cve-2025-41254-spring-websocket-csrf-bypass-vulnerability-explained
- curl: CVE-2025-10148 Predictable WebSocket Mask — https://curl.se/docs/CVE-2025-10148.html
- @0ang3el: WebSocket Smuggling — https://github.com/0ang3el/websocket-smuggle
- PalindromeLabs: awesome-websocket-security — https://github.com/PalindromeLabs/awesome-websocket-security
- PalindromeLabs: STEWS — https://github.com/PalindromeLabs/STEWS
- Praetorian: MeshCentral CVE-2024-26135 — https://www.praetorian.com/blog/meshcentral-cross-site-websocket-hijacking-vulnerability/
- Snyk Labs: Gitpod CVE-2023-0957 — https://labs.snyk.io/resources/gitpod-remote-code-execution-vulnerability-websockets/
- Integrity360: CVE-2024-55591 FortiOS — https://insights.integrity360.com/cve-2024-55591-being-exploited-in-the-wild-critical-authentication-bypass-in-node.js-websocket-module
- PayloadsAllTheThings: Web Sockets — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Web%20Sockets/README.md
- HackTricks: WebSocket Attacks — https://book.hacktricks.xyz/pentesting-web/websocket-attacks
- Black Hills InfoSec: CSWSH Analysis — https://www.blackhillsinfosec.com/cant-stop-wont-stop-hijacking-websockets/
- DeepStrike: Mastering WebSockets Vulnerabilities — https://deepstrike.io/blog/mastering-websockets-vulnerabilities

---

*This document was created for defensive security research and vulnerability understanding purposes.*
