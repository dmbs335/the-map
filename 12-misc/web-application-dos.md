# Web Application Denial of Service (DoS) — Mutation/Variation Taxonomy

*Comprehensive classification of application-layer Denial of Service attack surfaces targeting web applications, APIs, and web infrastructure. This document focuses on DoS vectors that exploit application logic, protocol design, parsing behavior, and algorithmic complexity — not volumetric/network-layer DDoS. XXE entity expansion (Billion Laughs, Quadratic Blowup) and archive decompression bombs (zip bombs) are covered in dedicated the-map taxonomy documents (`xxe.md` §7-1 and `zip-archive.md` §4 respectively) and intentionally excluded here.*

---

## Classification Structure

Application-layer Denial of Service is fundamentally an asymmetry problem: the attacker invests minimal resources to force the server into disproportionately expensive computation, memory allocation, connection holding, or I/O. Unlike volumetric DDoS that overwhelms network bandwidth, application-layer DoS exploits the inherent cost asymmetry in parsing, computation, protocol handling, and caching — often requiring only a single malicious request to render a service unavailable.

This taxonomy organizes application-layer DoS vectors along three axes:

**Axis 1 — DoS Vector Class (Primary, §1–§9):** The structural category of the system component whose cost asymmetry is exploited. This axis structures the main body of the document.

**Axis 2 — Exhaustion Primitive (Cross-cutting):** The server resource being depleted. These primitives recur across multiple vector classes:

| Primitive | Description | Primary Sections |
|---|---|---|
| **CPU Exhaustion** | Computation cycles consumed by backtracking, hash collisions, cryptographic operations, or complex query evaluation | §1, §3, §5, §9 |
| **Memory Exhaustion** | Heap/stack consumption via deeply nested structures, entity expansion, large allocations, or unbounded buffering | §2, §4, §6, §7 |
| **Connection/Thread Pool Exhaustion** | Server connection slots or worker threads held open by slow or incomplete requests, preventing legitimate clients | §2, §6, §8 |
| **Stack Exhaustion** | Call stack overflow through recursive parsing of deeply nested input structures | §4 |
| **Bandwidth Exhaustion** | Upstream/downstream bandwidth consumed through amplification, large response generation, or CDN-origin saturation | §7 |
| **Disk/Storage Exhaustion** | Persistent storage consumed through log flooding, upload abuse, or cache storage inflation | §8 |

**Axis 3 — Attack Scenario (Mapping, §10):** The real-world deployment context — single-origin DoS, CDN/edge amplification, microservice cascade, API gateway overwhelm, and client-side rendering DoS.

---

## §1. Regular Expression Denial of Service (ReDoS)

Regular expression engines using backtracking algorithms (NFA-based) are vulnerable to catastrophic performance degradation when processing crafted input against vulnerable patterns. A single malicious string can cause a regex evaluation to consume CPU for minutes or hours, blocking the thread and denying service to all concurrent requests on that worker.

### §1-1. Catastrophic Backtracking

The core ReDoS mechanism: regex patterns with ambiguous quantifiers create exponential branching in the NFA's backtracking tree when the engine fails to find a match.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Exponential backtracking (nested quantifiers)** | Patterns like `^(a+)+$` create 2^n backtracking paths when applied to input `"a"*n + "!"`. Each additional character doubles the execution time. The engine exhaustively explores all paths before concluding no match exists | Any NFA-based regex engine (PCRE, Python `re`, Java `java.util.regex`, JavaScript RegExp) processing user input against vulnerable patterns |
| **Polynomial backtracking (overlapping alternatives)** | Patterns like `(a|a)*$` or `(.*a){n}` create polynomial-time backtracking (O(n^k)) rather than exponential, but still achieve DoS with sufficiently long input | Same engines; patterns with overlapping character class alternatives |
| **Super-linear backtracking** | Patterns with quantified groups containing optional elements — e.g., `(\w+\s?)*$` — exhibit super-linear (O(n^2) or higher) behavior on non-matching suffixes. Less dramatic than exponential but sufficient for DoS with inputs of ~10,000+ characters | Ubiquitous in validation patterns for names, addresses, and free-text fields |
| **Repetition with lazy quantifiers** | Lazy quantifiers (`*?`, `+?`) in certain patterns cause the engine to attempt the minimum match first, then progressively increase, creating different but equally catastrophic backtracking paths | Patterns mixing lazy and greedy quantifiers in nested groups |

### §1-2. ReDoS in Validation & Sanitization Libraries

Real-world ReDoS vulnerabilities concentrate in input validation code where user-controlled strings are matched against developer-defined patterns.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Email validation ReDoS** | Email regex patterns are notoriously complex. Patterns like `^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})*$` contain nested quantifiers exploitable with crafted email-like strings | Server-side email validation using regex rather than dedicated parsers |
| **URL validation ReDoS** | URL parsing patterns with protocol/domain/path groups create backtracking when matching strings that partially resemble URLs but fail at the end | URL validation in WAFs, input sanitizers, and framework validators |
| **JSON schema pattern keyword abuse** | JSON Schema validators that compile the `pattern` keyword into regex and execute it against input data. When combined with `$data` references, attackers control both the pattern and the input | CVE-2025-69873 (ajv); JSON Schema validation with `$data` references |
| **Glob pattern ReDoS** | Glob-to-regex conversion in file matching libraries introduces nested quantifiers not present in the original glob syntax | CVE-2024-4067 (micromatch < 4.0.8); any library converting globs to regex |
| **Cross-spawn argument parsing** | Command argument parsing libraries using regex for shell metacharacter detection contain vulnerable patterns exploitable through crafted command arguments | CVE-2024-21538 (cross-spawn < 7.0.5) |
| **Content formatting ReDoS** | Code formatters and linters using regex for syntax detection contain patterns that catastrophically backtrack on adversarial input | CVE-2024-21503 (black Python formatter); CVE-2024-22363 (SheetJS) |

### §1-3. ReDoS Amplification Contexts

The severity of a ReDoS vulnerability depends on where the regex evaluation occurs in the request processing pipeline.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **WAF rule ReDoS** | Web Application Firewalls evaluate regex rules against every request. A vulnerable WAF rule blocks the entire request pipeline during backtracking, affecting all proxied traffic | WAF with regex-based rules containing vulnerable patterns; affects all traffic through the WAF |
| **Rate limiter key extraction** | Rate limiters using regex to extract client identifiers (API keys, tokens) from requests. Crafted requests cause the extraction regex to backtrack, paradoxically disabling the rate limiter itself | Rate limiting middleware with regex-based key extraction |
| **Log processing ReDoS** | Log aggregation systems parsing log entries with regex. A single log line containing a ReDoS payload blocks the entire log processing pipeline | ELK stack, Splunk, custom log parsers with vulnerable patterns |
| **Per-route middleware ReDoS** | Framework middleware that applies regex-based path matching before route handling. Crafted URL paths trigger backtracking before the request reaches application code | Express.js path-to-regexp, Django URL patterns, Spring path matchers |
| **ReDoS timing side-channel for data exfiltration** | ReDoS execution time varies based on which input character triggers backtracking failure. By crafting inputs that conditionally backtrack depending on a secret character's value, the attacker infers secret data one character at a time via response timing differentials. Cross-site variants exploit client-side JavaScript regex to leak cross-origin data through `performance.now()` timing | Server or client-side regex evaluation where input and secret interact; timing measurable by attacker (lmt_swallow, 2020) |

---

## §2. Protocol-Level Resource Exhaustion

HTTP and related protocols contain design features that create cost asymmetry between client and server. Slow HTTP attacks exploit this by holding connections open at minimal client cost, while HTTP/2 and HTTP/3 protocol features introduce new classes of multiplexing-based DoS.

### §2-1. Slow HTTP Attacks

Slow HTTP attacks maintain connections in an incomplete state, consuming server connection slots indefinitely while the client sends data at the minimum rate to avoid timeouts.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Slowloris (slow headers)** | The client opens a connection and sends HTTP headers extremely slowly — one byte at a time or one header per timeout interval — never completing the request. The server holds the connection open waiting for the final `\r\n\r\n`, consuming a connection slot | Thread-per-connection servers (Apache prefork/worker); servers without header timeout enforcement |
| **Slow POST / R.U.D.Y. (slow body)** | The client sends a legitimate POST request with a large `Content-Length` header, then transmits the body one byte at a time. The server allocates resources for the declared body size and waits for the complete body | Servers without body receive timeout; applications accepting large POST bodies |
| **Slow Read** | The client sends a legitimate request but advertises a tiny TCP receive window (e.g., 10 bytes), forcing the server to hold the response in memory and transmit it extremely slowly. The server maintains the connection and response buffer for the duration | Servers without send timeout; responses that cannot be discarded once generation begins |
| **Apache Range Header** | The client sends a `Range: bytes=0-,5-0,5-1,...` header with hundreds of overlapping byte ranges, causing the server to generate a multipart response with each range as a separate MIME part, consuming CPU and memory for a tiny file | Apache HTTP Server with default range handling; other servers processing overlapping ranges |
| **HTTP incomplete request flooding** | Rapidly opening connections and sending partial requests (just the request line, no headers), filling the connection pool with incomplete requests faster than timeout mechanisms can reclaim them | Servers with high connection limits but slow timeout enforcement |

### §2-2. HTTP/2 Stream Multiplexing Abuse

HTTP/2's stream multiplexing — designed for performance — creates new DoS surfaces because the server maintains state for each stream, and protocol features allow clients to create and manipulate streams at high rates.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Rapid Reset (stream create-cancel)** | The client opens streams at maximum rate and immediately cancels each with `RST_STREAM`. The server allocates resources for each stream (memory, goroutines, threads) before processing the reset. At 398 million requests/second observed rates, server-side resource allocation vastly exceeds reclamation speed | Any HTTP/2 implementation; CVE-2023-44487, CVSS 7.5; Google mitigated 398M rps, Cloudflare 201M rps, AWS 155M rps |
| **MadeYouReset (server-reset bypass)** | The client triggers server-initiated `RST_STREAM` via protocol errors — `WINDOW_UPDATE` with increment=0, `PRIORITY` with self-dependency, or frames sent after `END_STREAM` — causing the server to reset the stream after backend processing has started. Because the reset is server-initiated (not client-initiated), client-RST rate counters deployed after Rapid Reset are bypassed, and the stream falls out of `MAX_CONCURRENT_STREAMS` accounting while backend work continues | CVE-2025-8671; bypasses Rapid Reset mitigations; affects Apache Tomcat, Netty, Varnish, Fastly, F5 |
| **CONTINUATION frame flood** | HTTP/2 allows splitting large header blocks across multiple `CONTINUATION` frames. The client sends an initial `HEADERS` frame followed by thousands of `CONTINUATION` frames that the server must buffer and decode. Without limits, this causes out-of-memory crashes | CVE-2024-27316 (Apache httpd), CVE-2024-24549 (Tomcat), CVE-2024-27983 (Node.js), CVE-2023-45288 (Go), CVE-2024-28182 (nghttp2), CVE-2024-27919 (Envoy) |
| **SETTINGS flood** | Rapid `SETTINGS` frames require the server to acknowledge each, consuming processing resources and memory for pending acknowledgments | HTTP/2 implementations without SETTINGS frame rate limiting |
| **PING flood** | High-rate `PING` frames force the server to generate and send `PING` ACK responses, consuming both CPU and bandwidth | HTTP/2 implementations without PING rate limiting |
| **Empty frames flood** | Sending streams of empty `DATA` or `HEADERS` frames that are syntactically valid but carry no payload, forcing the server to process each frame through the HTTP/2 state machine | HTTP/2 implementations that process empty frames without throttling |
| **Priority tree manipulation** | Crafting complex priority dependency trees that force the server to perform expensive tree restructuring operations during stream scheduling | HTTP/2 implementations with unbounded priority tree depth |

### §2-3. HTTP/3 (QUIC) DoS Vectors

QUIC's UDP-based transport and built-in encryption introduce protocol-specific DoS surfaces.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **QUIC connection ID hash collision** | QUIC servers use hash tables to map connection IDs to connection state. Crafted connection IDs that collide in the hash table degrade lookup performance from O(1) to O(n), exhausting CPU | CVE-2025-29908 (Netty QUIC); any QUIC implementation using non-randomized hashing for connection ID lookup |
| **Initial packet amplification** | QUIC's handshake involves the server sending more data than the client (ServerHello, certificates), creating a ~3-4x amplification factor exploitable for reflection attacks against third parties | QUIC implementations without address validation tokens |
| **0-RTT replay amplification** | QUIC 0-RTT allows clients to send data before handshake completion. Replayed 0-RTT requests trigger server-side processing (database queries, API calls) without the cost of a full handshake | QUIC servers accepting 0-RTT without anti-replay mechanisms |

---

## §3. Algorithmic Complexity Attacks

Algorithmic complexity attacks exploit the gap between a data structure's average-case and worst-case performance. When an attacker can control input to data structures using algorithms with poor worst-case bounds, a small malicious input forces disproportionate computation.

### §3-1. Hash Table Collision Attacks (HashDoS)

Hash tables are the foundational data structure of web applications — HTTP headers, query parameters, JSON objects, form data, and session stores all use hash-table-backed structures. When an attacker can force hash collisions, every operation degrades from O(1) to O(n).

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **HTTP parameter hash collision** | Web frameworks parse query strings and POST bodies into hash tables. Crafted parameter names that collide in the framework's hash function force O(n) lookup per parameter, turning a typical O(n) request parsing into O(n²). The original 2011 HashDoS research demonstrated PHP, Java, Python, Ruby, and ASP.NET were all vulnerable | Frameworks using non-randomized hash functions; mitigated by hash randomization (Python 3.3+, Ruby 2.0+, PHP 8.0+) but reimplementable against any deterministic hash |
| **V8 rapidhash collision (Node.js)** | Node.js v24.0.0 adopted V8's `rapidhash` for string hashing, which is deterministic and does not sufficiently randomize input. Attackers can craft collision strings for HTTP headers, query parameters, or JSON keys, degrading JavaScript object/Map operations from O(1) to O(n) per operation | CVE-2025-27209; Node.js v24.0.0–v24.4.0; fixed in v24.4.1 with revised hashing |
| **JSON key hash collision** | JSON payloads containing thousands of keys that collide in the server-side JSON parser's internal hash table. A ~1MB JSON body with 65,536 colliding keys can consume >60 seconds of CPU time | JSON-accepting API endpoints; server-side language with predictable string hashing |
| **Cookie/header hash collision** | HTTP cookies and headers are typically stored in hash maps. Crafted cookie names or header names that collide degrade server-side request parsing | Servers parsing many cookies/headers into hash structures |
| **QUIC connection ID hash collision** | QUIC server hash tables mapping connection IDs to state become O(n) per lookup when connection IDs are crafted to collide | CVE-2025-29908 (Netty QUIC); §2-3 cross-reference |
| **IIS output cache hash table collision** | IIS stores cached HTTP responses in a hash table keyed on the request URL. Crafted URLs that produce hash collisions in the output cache destabilize lookup, causing the server to return incorrect cached responses for unrelated URLs — converting a HashDoS primitive into a **cache poisoning** vector where attacker-controlled content is served to victims requesting legitimate pages | Microsoft IIS with output caching enabled (Black Hat USA 2022, Orange Tsai) |

### §3-2. Sorting & Search Algorithm Exploitation

Algorithms with O(n²) worst-case complexity (quicksort, certain binary tree operations) become DoS vectors when attacker-controlled input triggers the worst case.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Quicksort worst-case triggering** | If a web application sorts user-provided data using a quicksort variant without randomized pivot selection, pre-sorted or reverse-sorted input triggers O(n²) behavior | Applications using naive quicksort on user-controlled arrays; rare in modern standard libraries but possible in custom implementations |
| **Binary search tree degradation** | Inserting sorted keys into an unbalanced BST creates a degenerate linked list, degrading all operations from O(log n) to O(n) | Custom data structures using unbalanced BSTs; less common due to prevalence of balanced trees |
| **Probabilistic data structure attacks** | Redis and similar systems use probabilistic data structures (HyperLogLog, Bloom filters, Count-Min Sketch). Research has identified 10 novel attacks exploiting implementation deviations that cause severe performance degradation | Redis PDS implementations; exposed Redis instances |
| **Floating-point / number parser DoS** | Certain floating-point string representations (e.g., extremely long decimal expansions, subnormal numbers near `2.2250738585072012e-308`, or deeply nested scientific notation) trigger worst-case behavior in number parsing algorithms (`strtod`, `parseFloat`, `Double.parseDouble`), consuming disproportionate CPU per value. A single carefully crafted numeric string in a JSON field, query parameter, or form input can block a worker thread for seconds | Application parses user-supplied numeric strings without input length limiting before parse; language-specific parser implementations with worst-case edge cases |

---

## §4. Parser & Serialization Bomb Attacks

Parsers for structured data formats (JSON, YAML, XML attributes, Protobuf, MessagePack) are vulnerable to input that triggers recursive descent without depth limits, exponential expansion via references, or allocation of disproportionate memory relative to input size.

> **Cross-reference:** XXE entity expansion (Billion Laughs, Quadratic Blowup) is covered in `01-injection/xxe.md` §7-1. Zip/archive decompression bombs are covered in `06-encoding-parser/zip-archive.md` §4. This section covers non-XXE parser bombs.

### §4-1. JSON Deep Nesting DoS

JSON parsers using recursive descent encounter stack overflow or extreme CPU consumption when processing deeply nested structures.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Recursive descent stack overflow** | A JSON document with thousands of nested objects `{"a":{"a":{"a":...}}}` or arrays `[[[[...]]]` causes recursive descent parsers to overflow the call stack, crashing the process with a `StackOverflowError` | CVE-2024-21907 (Newtonsoft.Json); CVE-2025-52999 (jackson-core); CVE-2025-53864 (Nimbus JOSE+JWT); any parser without configurable depth limits |
| **JWT claim set nesting** | JWTs containing deeply nested JSON claim sets trigger stack overflow during claim parsing/validation, causing authentication services to crash | CVE-2025-53864 (Nimbus JOSE+JWT < 10.0.2); JWT validation libraries without depth limits |
| **JSON serialization recursion** | Serialization libraries crashing when serializing deeply nested Python/JavaScript objects back to JSON, triggered when an attacker controls the data structure being serialized | CVE-2025-67221 (orjson); libraries without recursion limits during serialization |
| **JSON-JAVA uncapped recursion** | The JSON-Java (org.json) library allocates excessive memory when parsing crafted JSON strings with extremely deep nesting or very long strings, enabling DoS with a ~2MB payload consuming ~1GB of heap | CVE-2023-5072 (JSON-Java); any Java application using org.json for parsing untrusted input |

### §4-2. YAML Anchor & Alias Bomb

YAML's anchor (`&`) and alias (`*`) feature enables references between nodes. Exponential expansion occurs when aliases reference anchors that themselves contain aliases, creating a "Billion Laughs" equivalent.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Exponential alias expansion** | A YAML document uses chained anchors: `a: &a [x] / b: &b [*a,*a] / c: &c [*b,*b] / ...`. Each level doubles the expansion, producing 2^n elements from n anchor levels. A 1KB YAML document can expand to gigabytes | SnakeYAML (CVE-2022-1471); PyYAML; Ruby YAML; any parser that eagerly resolves aliases without expansion limits |
| **Kubernetes API YAML bomb** | The Kubernetes API server accepts YAML manifests. Crafted manifests with recursive anchor aliases cause the API server to consume excessive CPU and memory during parsing, potentially crashing the control plane | CVE-2019-11253; kube-apiserver parsing untrusted YAML |
| **YAML merge key abuse** | The `<<` merge key in YAML allows merging mappings. Chained merge keys referencing large anchors create multiplicative expansion | YAML parsers supporting merge keys without expansion limits |

### §4-3. Protocol Buffer Recursive Nesting

Protobuf's binary wire format allows nesting messages to arbitrary depth. When parsers recursively descend without depth limits, crafted messages cause stack overflow.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unknown group recursive nesting** | Protobuf messages with deeply nested unknown groups (SGROUP/EGROUP tags) cause the parser to recursively call itself for each nesting level, overflowing the stack | CVE-2024-7254; CVSS 8.7; affects protobuf-java, protobuf-javalite, protobuf-kotlin, JRuby protobuf; all versions before fix |
| **MessagePack hash collision + stack overflow** | MessagePack deserialization of deeply nested structures combined with hash collisions in the internal data structures causes both stack overflow and performance degradation | CVE-2024-48924 (MessagePack) |

### §4-4. Other Format Bombs

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **XML attribute blowup (non-XXE)** | XML documents with elements containing thousands of attributes. Even without entity expansion, attribute parsing and namespace resolution consume O(n²) time in some parsers due to uniqueness checking | XML parsers without attribute count limits; distinct from XXE-based DoS |
| **CSV formula injection → spreadsheet DoS** | CSV cells containing deeply nested formula expressions (e.g., `=SUM(SUM(SUM(...)))`) cause spreadsheet applications to consume excessive CPU during formula evaluation | Server-generated CSV opened in Excel/Google Sheets; indirect DoS against end users |
| **TOML deep nesting** | TOML parsers vulnerable to deeply nested inline tables/arrays causing stack overflow similar to JSON nesting attacks | TOML parsing libraries without depth limits |

---

## §5. GraphQL & API Query Abuse

GraphQL's flexibility — query depth, field selection, aliases, batching, and introspection — creates multiple DoS vectors because the client controls query complexity while the server bears the execution cost. REST APIs are also vulnerable to specific query abuse patterns.

### §5-1. Query Depth & Complexity Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Deeply nested query** | Recursive relationships in the schema (e.g., `User → friends → User → friends → ...`) allow queries nested to arbitrary depth, causing the resolver to perform exponential database lookups: `{ user { friends { friends { friends { ... } } } } }` | GraphQL API without query depth limits; recursive type relationships |
| **Field duplication** | Repeating the same field hundreds of times in a query forces the server to resolve and serialize each duplicate: `{ user { name name name name ... } }`. While each field is cheap individually, thousands of duplications exhaust serialization resources | GraphQL API without field count limits |
| **Alias overloading** | GraphQL aliases allow requesting the same field multiple times with different names: `{ a1: user(id:1) { name } a2: user(id:2) { name } ... a10000: user(id:10000) { name } }`. Each alias triggers a separate resolver invocation, enabling N+1 query amplification | GraphQL API without alias count limits or query cost analysis |
| **Fragment spread abuse** | Deeply nested fragment spreads create recursive expansion: `fragment A on User { ...B } fragment B on User { ...A }`. While most servers detect direct cycles, indirect cycles through multiple fragments can bypass detection | GraphQL servers with incomplete cycle detection |

### §5-2. Batching & Introspection Abuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Query batching flood** | GraphQL supports sending multiple queries in a single HTTP request as a JSON array. An attacker sends a batch of thousands of expensive queries, bypassing per-request rate limiting since all queries share one HTTP request | GraphQL API supporting batching without batch size limits; per-request (not per-query) rate limiting |
| **Introspection query resource exhaustion** | The `__schema` introspection query returns the entire schema definition. For large schemas with hundreds of types and thousands of fields, the introspection response can be megabytes, and repeated introspection requests consume significant serialization resources | GraphQL API with introspection enabled in production |
| **Mutation batching for write amplification** | Batching mutations (e.g., thousands of `createComment` mutations in one request) bypasses per-request rate limits and triggers massive database write operations | GraphQL API with mutation batching; insufficient per-operation rate limiting |

### §5-3. REST API Query Abuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Expensive filter/sort combinations** | API endpoints accepting complex filter and sort parameters (e.g., `?sort=field1,-field2,field3&filter[nested][deep]=value`) that translate to expensive database queries with multiple JOINs, full table scans, or unindexed sorts | REST APIs with flexible query parameters; ORMs generating unoptimized queries from filter params |
| **Pagination abuse** | Requesting extremely large page sizes (`?page_size=999999`) or deep offsets (`?page=999999&page_size=100`) that force the database to scan and discard massive result sets | APIs without maximum page size enforcement; offset-based pagination on large tables |
| **Expansion/include parameter abuse** | APIs supporting response expansion (e.g., `?include=author,comments,comments.author,tags`) that trigger deep object graph loading with N+1 queries | REST APIs with eager loading of related resources; ORM-backed APIs without join depth limits |

---

## §6. WebSocket & Persistent Connection Exhaustion

WebSocket connections are long-lived, bidirectional, and typically allocated a dedicated thread or event loop slot. This makes them attractive DoS targets because a single connection consumes resources indefinitely.

### §6-1. WebSocket Connection Exhaustion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Connection slot saturation** | The attacker opens the maximum allowed WebSocket connections from distributed clients, filling the server's connection pool and preventing legitimate users from connecting. Unlike HTTP requests, WebSocket connections persist indefinitely | Servers without per-IP connection limits; absence of authentication before connection establishment |
| **Header count overflow** | WebSocket upgrade requests with excessive HTTP headers exceeding `server.maxHeadersCount` cause the server to crash or reject all subsequent connections | CVE-2024-37890 (ws library); Node.js WebSocket servers |
| **Incomplete upgrade holding** | Initiating WebSocket handshakes but never completing the upgrade, holding HTTP connections in the upgrade-pending state and consuming connection slots | Servers without handshake timeout enforcement |
| **HTTP/1.1 browser connection limit saturation** | When not using HTTP/2, browsers limit connections to 6 per origin. WebSocket connections count toward this limit. A page opening 6 SSE/WebSocket connections blocks all subsequent HTTP requests to the same origin, effectively DoS-ing the client | Client-side DoS; applications using multiple SSE/WebSocket connections without HTTP/2 |

### §6-2. WebSocket Frame Abuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Message flooding** | Sending WebSocket messages at maximum rate, overwhelming the server's message processing queue and consuming CPU for deserialization, validation, and routing | Servers without per-connection message rate limits |
| **Large frame memory exhaustion** | WebSocket frames declaring extremely large payload lengths (close to `Integer.MAX_VALUE`) cause servers to pre-allocate buffers of that size, triggering `OutOfMemoryError` and crashing the process | Servers that allocate buffers based on frame header length without validation |
| **Ping/pong flooding** | WebSocket ping frames require pong responses. Rapid ping flooding forces the server to generate and send pong frames, consuming CPU and bandwidth | Servers without ping rate limiting |
| **Compression bombing (permessage-deflate)** | The `permessage-deflate` WebSocket extension enables per-message compression. A small compressed frame can expand to gigabytes after decompression, similar to zip bombs | WebSocket servers with compression enabled; no decompression size limits |
| **Fragmentation abuse** | WebSocket protocol allows fragmenting messages across multiple frames. Sending millions of tiny fragments forces the server to reassemble them, consuming CPU and memory for fragment management | Servers without fragment count limits or reassembly timeouts |

### §6-3. Server-Sent Events (SSE) & Long Polling Exhaustion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SSE connection saturation** | Each SSE connection holds an HTTP connection open indefinitely. Exhausting the server's SSE connection pool prevents new subscribers from receiving real-time updates | SSE servers without connection limits; event-driven architectures |
| **Long polling connection holding** | Long polling clients maintain requests that the server holds open until data is available. Attackers open maximum concurrent long-poll requests, exhausting the server's thread/connection pool | Servers using thread-per-request model for long polling; no per-client request limits |
| **EventSource reconnection storm** | When an SSE connection drops, the `EventSource` API automatically reconnects. A server-induced disconnect on many clients simultaneously creates a reconnection thundering herd that can overwhelm the server | SSE servers under load; mass disconnect events (deployment, network blip) |

---

## §7. Cache-Poisoned Denial of Service (CPDoS)

Cache-Poisoned DoS exploits differences in how caching proxies (CDNs, reverse proxies) and origin servers handle HTTP requests. The attacker causes the origin to generate an error response for a valid URL, and the cache stores this error response — serving it to all subsequent legitimate users requesting that URL. A single malicious request can render a cached page globally unavailable.

### §7-1. CPDoS Attack Variants

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **HTTP Header Oversize (HHO)** | The attacker adds oversized headers (e.g., `X-Padding: AAAA...` at 16KB+) to a request for a cacheable URL. The CDN forwards the request (its header limit is higher), but the origin server rejects it with `400 Bad Request`. The CDN caches this 400 response and serves it to all subsequent visitors | CDN with higher header size limit than origin (e.g., CloudFront 20KB vs. Apache 8KB); cacheable resource; CVE-2019-0941 (IIS) |
| **HTTP Meta Character (HMC)** | The attacker injects control characters (e.g., `\n`, `\r`, `\x00`) into request headers. The CDN passes them through, but the origin rejects the malformed request. The error response is cached | CDN that doesn't sanitize control characters in headers; origin server that rejects them |
| **HTTP Method Override (HMO)** | The attacker sends a GET request with `X-HTTP-Method-Override: POST` or `X-HTTP-Method: DELETE`. The CDN caches based on the actual GET method, but the origin processes it as POST/DELETE and returns an error response | Origin framework supporting method override headers; CDN caching GET responses regardless of override headers |
| **Next.js ISR/SSR cache poisoning** | Next.js applications using Incremental Static Regeneration or Server-Side Rendering, when deployed behind a CDN that caches HTTP 204 responses, can have their routes poisoned with empty 204 responses that replace valid content | CVE-2025-49826 (Next.js 15.1.0–15.1.8); CDN configured to cache 204 responses |
| **Host header cache poisoning for DoS** | Injecting a nonexistent `Host` header value causes the origin to generate an error. If the cache uses the URL path (without Host) as the cache key, the error response is served for the legitimate Host | Cache key not including Host header; origin returning different responses for different Host values |
| **Response Filter DoS (RFDoS)** | The attacker crafts requests that cause the origin server to include WAF-triggering patterns in its legitimate response body (e.g., injecting SQL-like syntax into reflected search results, user-generated content, or error messages). The WAF's response body inspection rules match these patterns as false positives and block or strip the legitimate response, denying content delivery to the requesting user. Unlike CPDoS, the response is not cached — each individual request triggers fresh WAF-mediated content blocking | WAF performs response body inspection with pattern-matching rules; attacker can influence response content via reflected input, stored user content, or manipulated query results |

### §7-2. CDN & Cache-Level DoS

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CDN-origin bandwidth saturation** | Abusing HTTP/2 request conversion behavior and cache-busting query parameters to generate high volumes of requests that bypass the CDN cache and hit the origin directly, saturating the CDN-origin link | CDN with cache bypass via query parameters; HTTP/2 multiplexing for request amplification |
| **Cache storage exhaustion** | Generating requests with unique cache-busting parameters (e.g., random query strings) that force the cache to store a unique entry for each request, eventually filling cache storage and evicting legitimate entries | Caches without storage quotas per origin; no rate limiting on cache-miss requests |
| **Stale-while-revalidate exploitation** | CDNs using `stale-while-revalidate` serve stale content while revalidating in the background. By triggering revalidation at high rates, attackers force the CDN to make excessive origin requests | CDNs with aggressive stale-while-revalidate policies; cache poisoning combined with forced revalidation |

---

## §8. Application Logic Resource Exhaustion

Application-level DoS exploits business logic, configuration, or implementation patterns that allow attackers to consume disproportionate resources through legitimate-looking requests.

### §8-1. Compute-Intensive Operation Abuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Expensive database query triggering** | Crafting API requests that trigger expensive database operations — full table scans, unindexed JOINs, cartesian products, or recursive CTEs — that block database connections and starve other requests | ORM-generated queries without complexity limits; user-controlled WHERE/ORDER BY clauses; APIs translating filter parameters to SQL |
| **Image/document processing amplification** | Uploading files that trigger expensive server-side processing (image resizing of a 100MP image, PDF rendering of a 1000-page document, video transcoding) that consumes CPU and memory disproportionate to request size | Upload endpoints without processing limits; headless browser/LibreOffice rendering pipelines |
| **Cryptographic operation abuse** | Triggering expensive cryptographic operations: bcrypt/scrypt/Argon2 password hashing at registration/login endpoints, TLS certificate generation, or JWT verification with large key sizes. Each operation is intentionally expensive, making them attractive DoS targets | Login/registration endpoints without rate limiting; password hashing cost factor tuned for security but exploitable at scale |
| **Search query complexity** | Search endpoints that support regex, fuzzy matching, or full-text search with complex operators. Crafted queries trigger catastrophic regex evaluation, expensive Levenshtein distance calculations, or massive result set generation | Elasticsearch/Solr/Lucene backends exposed via search API; regex search enabled |
| **Export/report generation** | Endpoints that generate PDF reports, CSV exports, or Excel files from large datasets. Requesting export of all records without pagination triggers in-memory generation of massive files | Export endpoints without row count limits; in-memory report generation |

### §8-2. Storage & Logging Exhaustion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Upload storage exhaustion** | Repeatedly uploading maximum-size files to consume disk space until the server's filesystem is full, causing all services to fail | Upload endpoints without per-user quotas; shared filesystem |
| **Log flooding** | Triggering verbose error logging through crafted requests — invalid URLs, malformed headers, authentication failures — that generate large log entries. At sufficient rate, log files fill disk space or overwhelm log aggregation pipelines | Applications with verbose error logging; log rotation not configured; unlimited log storage |
| **Temporary file exhaustion** | Triggering operations that create temporary files (multipart upload parsing, document conversion, thumbnail generation) without proper cleanup. Accumulated temp files exhaust disk space or inode limits | Applications without temp file cleanup; no disk quota per operation |
| **Race condition → file storage DoS** | Exploiting race conditions in upload handlers to bypass file count or size limits, allowing an attacker to upload far more data than intended | Upload handlers with TOCTOU vulnerabilities in quota checking |

### §8-3. Thread/Worker Starvation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Synchronous blocking chain** | Triggering requests that make synchronous calls to slow external services (payment gateways, email sending, third-party APIs). Each request blocks a worker thread, and a burst of such requests exhausts the thread pool | Synchronous request handlers calling external services without timeouts; thread-per-request model |
| **Deadlock induction** | Crafting concurrent requests that acquire locks in conflicting order, inducing deadlock in the application's thread pool. Once deadlocked, no further requests can be processed | Applications with lock-based concurrency; user-triggerable conflicting lock acquisition |
| **Infinite redirect loop** | Triggering redirect chains where URL A redirects to B, B redirects to C, and C redirects to A. Clients following redirects consume server resources for each hop, and server-side request following (e.g., URL preview fetching) enters infinite loops | Applications following redirects without hop limits; circular redirect configurations |
| **Recursive function triggering** | Input that triggers deeply recursive application logic — recursive template rendering, recursive tree traversal for nested comments, recursive permission checking in hierarchical ACLs | Applications with unbounded recursion in business logic |

---

## §9. TLS/SSL Cryptographic Exhaustion

TLS handshakes and cryptographic operations are deliberately expensive. Attackers exploit this cost asymmetry — the server performs more computation than the client during handshakes — to exhaust CPU resources.

### §9-1. TLS Handshake Abuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Client-initiated renegotiation flood** | The client initiates TLS renegotiation repeatedly on an established connection. Each renegotiation requires the server to perform a full handshake (RSA key exchange, certificate chain validation) — consuming ~15x more CPU than the client. Tool: thc-ssl-dos | Servers with client-initiated renegotiation enabled; no renegotiation rate limiting |
| **TLS handshake flood** | Rapidly initiating TLS handshakes without completing them, or completing them and immediately closing, forcing the server to perform expensive asymmetric cryptographic operations for each attempt | Servers without TLS handshake rate limiting; no connection throttling |
| **Large certificate chain validation** | Sending client certificates with extremely long certificate chains or chains referencing CRLs/OCSP endpoints that are slow or unreachable, causing the server to spend excessive time on validation | mTLS endpoints; servers performing synchronous certificate chain validation |
| **Session ticket exhaustion** | Requesting massive numbers of TLS session tickets (via `NewSessionTicket` in TLS 1.3), forcing the server to generate and store ticket encryption keys | TLS 1.3 servers without session ticket issuance limits |

---

## §10. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Chain Example |
|---|---|---|---|
| **Single-Origin Service DoS** | Monolithic web application | §1 + §3 + §8-1 | ReDoS in email validation regex → blocks all request threads → service unavailable |
| **CDN/Edge DoS Amplification** | CDN-fronted application | §7-1 + §7-2 | HHO CPDoS poisons cached homepage → all CDN edge nodes serve 400 error → global outage |
| **Microservice Cascade Failure** | Microservice architecture | §8-3 + §2-1 | Slowloris exhausts API gateway connections → gateway times out → upstream services cascade fail |
| **API Gateway Overwhelm** | GraphQL/REST API | §5-1 + §5-2 + §3-1 | Batched deeply-nested GraphQL queries with alias overloading → N+1 query explosion → database connection pool exhausted |
| **Authentication Service DoS** | Auth/SSO infrastructure | §8-1 + §9-1 + §4-1 | bcrypt flood on login endpoint + JWT claim nesting on token validation → auth service CPU-bound → all dependent services lose authentication |
| **Client-Side Rendering DoS** | SPA with WebSocket | §6-1 + §6-2 | WebSocket connection saturation in browser → SSE connections consume all 6 HTTP/1.1 slots → page becomes unresponsive |
| **Container/Cluster DoS** | Kubernetes infrastructure | §4-2 + §2-2 | YAML anchor bomb in K8s manifest → API server OOM → cluster control plane crash |
| **Protocol-Level Infrastructure DoS** | Load balancer / reverse proxy | §2-2 + §2-3 | HTTP/2 MadeYouReset bypasses Rapid Reset mitigations → unbounded backend concurrency → origin server crash |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §1-2 (cross-spawn ReDoS) | CVE-2024-21538 (cross-spawn < 7.0.5) | ReDoS via improper input sanitization; affects 100M+ weekly npm downloads |
| §1-2 (micromatch ReDoS) | CVE-2024-4067 (micromatch < 4.0.8) | ReDoS in glob matching library; widespread dependency |
| §1-2 (ajv ReDoS) | CVE-2025-69873 (ajv) | ReDoS via pattern keyword with $data references in JSON Schema validator |
| §1-2 (black ReDoS) | CVE-2024-21503 (black formatter) | ReDoS in Python code formatter |
| §1-2 (SheetJS ReDoS) | CVE-2024-22363 (SheetJS < 0.20.2) | ReDoS in spreadsheet parsing library |
| §2-2 (HTTP/2 Rapid Reset) | CVE-2023-44487 | **CVSS 7.5.** Record-breaking DDoS: 398M rps (Google), 201M rps (Cloudflare). CISA KEV. Affects every HTTP/2 implementation |
| §2-2 (HTTP/2 MadeYouReset) | CVE-2025-8671 | Bypasses Rapid Reset mitigations via server-initiated RST_STREAM. Affects Tomcat, Netty, Varnish, Fastly, F5 |
| §2-2 (CONTINUATION flood, Apache) | CVE-2024-27316 (Apache httpd) | OOM crash via unbounded CONTINUATION frame buffering |
| §2-2 (CONTINUATION flood, Tomcat) | CVE-2024-24549 (Apache Tomcat) | DoS via improper CONTINUATION frame validation |
| §2-2 (CONTINUATION flood, Node.js) | CVE-2024-27983 (Node.js) | HTTP/2 server crash via CONTINUATION flood |
| §2-2 (CONTINUATION flood, Go) | CVE-2023-45288 (Go net/http2) | Unbounded CONTINUATION frame processing |
| §2-2 (CONTINUATION flood, Envoy) | CVE-2024-27919, CVE-2024-30255 (Envoy) | CONTINUATION frame DoS in popular service mesh proxy |
| §2-3 (QUIC hash collision) | CVE-2025-29908 (Netty QUIC) | Connection ID hash collision DoS |
| §3-1 (Node.js HashDoS) | CVE-2025-27209 (Node.js v24) | V8 rapidhash deterministic hashing enables HashDoS; O(1) → O(n) degradation |
| §3-2 (Redis PDS attacks) | Multiple (2024 research) | 10 novel attacks against probabilistic data structures in Redis |
| §4-1 (Newtonsoft.Json nesting) | CVE-2024-21907 (Newtonsoft.Json) | StackOverflow via deeply nested JSON; no default depth limit |
| §4-1 (jackson-core nesting) | CVE-2025-52999 (jackson-core) | Stack exhaustion via deeply nested JSON |
| §4-1 (Nimbus JWT nesting) | CVE-2025-53864 (Nimbus JOSE+JWT < 10.0.2) | DoS via deeply nested JSON in JWT claims |
| §4-1 (orjson recursion) | CVE-2025-67221 (orjson) | Crash during serialization of deeply nested structures |
| §4-1 (JSON-Java) | CVE-2023-5072 (org.json) | ~2MB payload → ~1GB heap via deep nesting and long strings |
| §4-3 (Protobuf recursion) | CVE-2024-7254 (protobuf-java) | **CVSS 8.7.** Stack overflow via recursive unknown group nesting; affects all protobuf-java versions |
| §4-3 (MessagePack) | CVE-2024-48924 (MessagePack) | Hash collision + stack overflow in deserialization |
| §4-2 (K8s YAML bomb) | CVE-2019-11253 (Kubernetes) | kube-apiserver DoS via YAML anchor alias expansion |
| §6-1 (ws header overflow) | CVE-2024-37890 (ws library) | DoS when headers exceed maxHeadersCount threshold |
| §7-1 (Next.js cache poisoning DoS) | CVE-2025-49826 (Next.js 15.1.0–15.1.8) | Cache poisoning via ISR/SSR route returning cached 204 |
| §7-1 (IIS CPDoS) | CVE-2019-0941 (Microsoft IIS) | IIS DoS via cache-poisoned error responses |
| §8-1 (Tomcat upload DoS) | Multiple (Apache Tomcat) | OutOfMemoryError via examples app upload without limits |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **slowhttptest** (C, Kali Linux) | §2-1 Slow HTTP | Simulates Slowloris, Slow POST, Slow Read, and Apache Range attacks; generates CSV/HTML statistics |
| **SlowLoris.py** (Python) | §2-1 Slowloris | Lightweight Slowloris attack simulator for testing connection exhaustion resilience |
| **h2spec** (Go, open-source) | §2-2 HTTP/2 | HTTP/2 conformance testing tool; validates stream handling, CONTINUATION processing, and flow control |
| **nghttp2** (C, open-source) | §2-2 HTTP/2 | HTTP/2 library with debugging tools for frame-level protocol analysis |
| **recheck** (Scala, open-source) | §1 ReDoS | Static analysis of regex patterns for catastrophic backtracking; generates attack strings |
| **safe-regex** (JavaScript) | §1 ReDoS | Detects potentially vulnerable regex patterns in JavaScript code |
| **RegexScalpel** (Python, USENIX) | §1 ReDoS | Automatic ReDoS-vulnerable regex repair using localize-and-fix strategy |
| **ReDoSHunter** (Research tool) | §1 ReDoS | Vetting regular expressions for ReDoS vulnerability with exploit string generation |
| **graphql-cop** (Python) | §5 GraphQL DoS | GraphQL security auditing: detects missing depth limits, batching abuse, introspection exposure |
| **InQL** (Burp extension) | §5 GraphQL | GraphQL introspection and query complexity analysis for Burp Suite |
| **clairvoyance** (Python) | §5 GraphQL | GraphQL schema enumeration even when introspection is disabled |
| **nuclei** (Go, ProjectDiscovery) | §7 CPDoS, §2-2 HTTP/2 | YAML template scanner with CPDoS, CONTINUATION flood, and protocol-level DoS templates |
| **Grype / Trivy** (SCA) | §1, §4 Library DoS | Identifies vulnerable library versions (protobuf, JSON parsers, regex libs) in dependencies |
| **thc-ssl-dos** (C) | §9-1 TLS renegotiation | TLS renegotiation flood tool demonstrating client-initiated renegotiation DoS |
| **testssl.sh** (Bash) | §9 TLS | Tests TLS configuration including renegotiation support, cipher suite strength |
| **wrk / bombardier** (Go/C) | §8 General load | HTTP benchmarking tools useful for testing application-level resource exhaustion thresholds |
| **vegeta** (Go) | §8 General load | HTTP load testing tool with support for constant rate, configurable connections, and reporting |

---

## Summary: Core Principles

### Why Application-Layer DoS Persists

Application-layer DoS is rooted in a fundamental asymmetry inherent to web architecture: **servers must perform work before they can determine whether a request is legitimate**. A regex must be evaluated before it can be determined to backtrack catastrophically. A JSON document must be parsed before its depth is known. An HTTP/2 stream must be allocated before the client cancels it. A hash table must insert elements before discovering they all collide. This *process-before-validate* pattern is not a bug in any individual system — it is a structural consequence of accepting arbitrary input from untrusted clients.

This asymmetry is amplified by three design tensions:

1. **Flexibility versus safety.** GraphQL exists because clients need flexible queries. WebSockets exist because applications need real-time communication. Regex exists because applications need pattern matching. Each of these features gives the client control over server-side computation cost, and each creates a DoS surface proportional to the flexibility granted.

2. **Caching as a single point of failure.** CDN caching transforms a single malicious request into a global outage. Cache-Poisoned DoS demonstrates that the same infrastructure designed to absorb volumetric attacks becomes the amplification vector when poisoned — one request at one edge location propagates error responses worldwide.

3. **Protocol complexity creates implementation divergence.** HTTP/2's CONTINUATION frames, SETTINGS handling, and stream lifecycle were designed for performance but create DoS surfaces when implementations handle edge cases differently. The progression from Rapid Reset (2023) to CONTINUATION Flood (2024) to MadeYouReset (2025) shows that each protocol feature is a potential DoS vector, and mitigations for one attack create new surfaces for the next.

### Why Incremental Fixes Are Insufficient

The patch-bypass cycle in application DoS follows a predictable pattern: limit → bypass → deeper limit → deeper bypass. HTTP/2 `MAX_CONCURRENT_STREAMS` was added to prevent stream exhaustion → Rapid Reset bypassed it via create-cancel → rate limiting on client RST_STREAM was added → MadeYouReset bypassed it via server-initiated resets. Hash randomization was added to prevent HashDoS → V8's rapidhash accidentally reintroduced deterministic hashing. JSON depth limits were added → attackers switched to width attacks (thousands of keys). Each fix addresses one exploitation path while leaving the fundamental asymmetry intact.

### What Structural Solutions Require

Lasting DoS defenses share a common architecture: **cost accounting before execution**:

- **Query cost analysis** before GraphQL resolution — reject queries exceeding a complexity budget before any resolver runs
- **Input budget enforcement** at the parser level — depth limits, breadth limits, total allocation limits, and expansion limits before parsing begins
- **Protocol-level resource accounting** — track resources consumed per-stream (not just per-connection) and enforce hard limits on total server-side work per client
- **Regex engine replacement** — RE2, Rust regex, and other Thompson NFA engines guarantee linear-time matching, eliminating the entire ReDoS vector class at the engine level
- **Adaptive rate limiting** — cost-aware rate limiting that charges clients based on actual server-side resource consumption (CPU time, memory, I/O) rather than request count

The fundamental challenge is that cost estimation must be cheaper than the operation being estimated. Measuring regex complexity is itself an NP-hard problem. Estimating GraphQL query cost requires schema analysis. Predicting JSON parse depth requires parsing the JSON. The art of DoS defense is finding approximations good enough to reject catastrophic inputs without adding prohibitive overhead to legitimate requests.

---

## References

- Cloudflare: "HTTP/2 Rapid Reset: Deconstructing the Record-Breaking Attack" — https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/
- CISA: "HTTP/2 Rapid Reset Vulnerability, CVE-2023-44487" — https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487
- MINE2: "MadeYouReset (CVE-2025-8671): HTTP/2 DoS Attack Bypasses Rapid Reset Mitigations" — https://www.mine2.io/blog/2025-08-18-http2-madeyoureset-dos-cve-2025-8671/
- Cloudflare: "MadeYouReset: An HTTP/2 Vulnerability Thwarted by Rapid Reset Mitigations" — https://blog.cloudflare.com/madeyoureset-an-http-2-vulnerability-thwarted-by-rapid-reset-mitigations/
- Snyk: "Exploiting HTTP/2 CONTINUATION Frames for DoS Attacks" — https://snyk.io/blog/exploiting-http-2-continuation-frames-dos-attacks/
- Phoenix Security: "The Rising Threat of HTTP/2 Vulnerabilities: From Rapid Reset to Continuation Flood" — https://phoenix.security/http2cve-2024-27316/
- ZeroPath: "Node.js v24 HashDoS (CVE-2025-27209): How a V8 Hashing Change Reopened a Classic DoS Attack" — https://zeropath.com/blog/cve-2025-27209-nodejs-v8-hashdos
- NCC Group: "Technical Advisory – Hash Denial-of-Service Attack in Multiple QUIC Implementations" — https://www.nccgroup.com/research-blog/technical-advisory-hash-denial-of-service-attack-in-multiple-quic-implementations/
- Snyk: "ReDoS and Catastrophic Backtracking" — https://snyk.io/blog/redos-and-catastrophic-backtracking/
- OWASP: "Regular Expression Denial of Service - ReDoS" — https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- Siddiq et al.: "Understanding Regular Expression Denial of Service (ReDoS)" (ICPC '24) — https://s2e-lab.github.io/preprints/icpc24-preprint.pdf
- Hooimeijer & Weimer: "Analyzing Catastrophic Backtracking Behavior in Practical Regular Expression Matching" — https://www.semanticscholar.org/paper/Analyzing-Catastrophic-Backtracking-Behavior-in-Berglund-Drewes/2acb87fa3aed6f09773c53c9b34db221941e3627
- Crosby & Wallach: "Denial of Service via Algorithmic Complexity Attacks" (USENIX Security '03) — https://www.usenix.org/conference/12th-usenix-security-symposium/denial-service-algorithmic-complexity-attacks
- ACM CCS '24: "The Harder You Try, The Harder You Fail: The KeyTrap Denial-of-Service Algorithmic Complexity Attacks on DNSSEC" — https://dl.acm.org/doi/10.1145/3658644.3670389
- CPDoS.org: "Cache-Poisoned Denial of Service" — https://cpdos.org/
- Escape.tech: "Avoid GraphQL Denial of Service Attacks Through Batching and Aliasing" — https://escape.tech/blog/graphql-batch-attacks-cause-dos/
- GraphQL Foundation: "Security" — https://graphql.org/learn/security/
- PortSwigger: "GraphQL API Vulnerabilities" — https://portswigger.net/web-security/graphql
- OWASP: "WebSocket Security Cheat Sheet" — https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html
- Qualys: "TLS Renegotiation and Denial of Service Attacks" — https://blog.qualys.com/product-tech/2011/10/31/tls-renegotiation-and-denial-of-service-attacks
- Vaadata: "What is a Slow HTTP Attack? Types & Security Best Practices" — https://www.vaadata.com/blog/what-is-a-slow-http-attack-types-and-security-best-practices/
- PortSwigger: "Top 10 Web Hacking Techniques of 2025" — https://portswigger.net/research/top-10-web-hacking-techniques-of-2025
- Akamai: "DDoS Attack Trends in 2024 Signify That Sophistication Overshadows Size" — https://www.akamai.com/blog/security/ddos-attack-trends-2024-signify-sophistication-overshadows-size
- Orange Tsai: "Let's Dance in the Cache — Destabilizing Hash Table on Microsoft IIS" (Black Hat USA 2022) — Hash table collision attacks weaponized against IIS output cache for cache poisoning

---

*This document was created for defensive security research and vulnerability understanding purposes.*
