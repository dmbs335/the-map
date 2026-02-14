# Web Timing Attack Mutation/Variation Taxonomy

---

## Classification Structure

Web timing attacks exploit measurable differences in how long a system takes to process, transport, or render requests and responses. Unlike traditional vulnerabilities that rely on direct data leakage, timing attacks extract information through a **temporal side-channel** — the attacker never reads the secret directly but infers it from microsecond-to-millisecond variations in system behavior.

This taxonomy organizes the attack surface along three axes:

- **Axis 1 — Timing Signal Source (Primary):** The structural component generating the measurable timing difference. This is the main organizational axis, ranging from server-side processing logic to browser execution internals to hardware cache hierarchies.
- **Axis 2 — Measurement Technique (Cross-cutting):** How the attacker observes and quantifies the timing difference. This axis captures the evolution from naive sequential measurement to sophisticated concurrent-comparison and order-based inference methods.
- **Axis 3 — Attack Scenario (Mapping):** The real-world exploitation context — what information is ultimately leaked and under what architectural conditions.

### Axis 2 Summary: Measurement Techniques

| Technique | Mechanism | Precision | Network Dependency |
|-----------|-----------|-----------|-------------------|
| **Sequential Measurement** | Send request, measure `performance.now()` delta | ~1ms+ | High (network jitter dominates) |
| **Concurrent Comparison (Single-Packet)** | Pack two requests into one TCP packet, compare response order | ~100ns | None (jitter eliminated) |
| **Dual-Packet Synchronization** | Fragment requests across exactly two packets with ping-frame coalescing | ~200ns | Minimal |
| **Timeless Timing (HTTP/2)** | Multiplex requests in single HTTP/2 stream, infer from arrival order | ~100ns | None (protocol-level jitter cancellation) |
| **Event-Based Detection** | Use browser events (`onload`, `onerror`, `unload`) as implicit clocks | ~1-10ms | Medium |
| **AbortController Probing** | Abort fetch at precise intervals; success/failure reveals completion speed | ~3-9ms | Medium |
| **Event Loop Blocking** | Measure main-thread blocking duration from cross-origin execution | ~μs-ms | Low (same-process) |
| **Service Worker Interception** | Intercept navigation, measure JS blocking via 204 abort cycles | ~μs-ms | Low |
| **Statistical Aggregation** | Collect thousands of samples, apply bottom-quartile filtering | Varies | Reduces to signal |

### Fundamental Equation

All web timing attacks obey one relationship:

```
Exploitability = Signal / Noise
```

Where **Signal** is the timing difference caused by the secret-dependent code path, and **Noise** is the sum of network jitter, server processing variance, and measurement imprecision. The entire history of this attack class is a progression of techniques to **maximize signal** (amplification) and **minimize noise** (concurrent measurement, statistical filtering).

---

## §1. Server-Side Processing Differentials

Server-side timing attacks exploit code paths on the backend that take measurably different amounts of time depending on secret state. These are the oldest and most intuitive form of web timing attack.

### §1-1. Authentication and Credential Verification

The most classic server-side timing oracle: authentication systems that process valid vs. invalid credentials through different code paths with different execution times.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Username Enumeration** | Server checks username existence before password verification; valid usernames trigger additional hashing/DB operations, producing longer response times | Sequential auth logic without constant-time equalization |
| **Password Length Oracle** | Password hashing functions (bcrypt, scrypt, argon2) take time proportional to input characteristics; long passwords fed to real hash vs. short-circuited invalid-user path | Hashing only triggered for valid users |
| **MFA State Leakage** | Different response times when MFA is enabled vs. disabled for an account, revealing account security configuration | MFA check occurs in timing-observable path |
| **Account Lockout Detection** | Locked accounts processed through different (often faster) code paths, allowing lockout state enumeration | Early-return on locked accounts |
| **Password Amplification** | Sending extremely long passwords (200+ characters) to amplify the timing difference between hash-executed and short-circuited paths | No input length normalization before hash |

**Example — Username Enumeration:**
```
POST /login  {"user": "valid_user", "pass": "wrong"}    → 342ms (bcrypt executed)
POST /login  {"user": "no_such_user", "pass": "wrong"}  → 118ms (early return)
```

### §1-2. String and Token Comparison

Timing differences in byte-by-byte comparison of secrets, tokens, HMAC signatures, and session identifiers.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Non-Constant-Time `strcmp`** | Standard string comparison functions (`strcmp`, `==`, `===`) return early on first mismatched byte; each correct prefix byte adds measurable delay | Use of language-default comparison for secrets |
| **HMAC Signature Oracle** | HMAC verification using non-constant-time comparison leaks correct HMAC bytes iteratively; attacker recovers full signature byte-by-byte | `hmac == computed_hmac` instead of `hmac.equals()` |
| **API Key Verification** | API key validation that compares against stored keys using early-exit logic | Key comparison in application code rather than DB query |
| **CSRF Token Leakage** | Anti-CSRF token validation with byte-by-byte timing signal | Direct comparison rather than `hash_equals()` |
| **Double-HMAC Blinding Bypass** | Even with constant-time comparison, computing the HMAC itself may leak through input-dependent processing time if the underlying hash implementation is non-constant-time | Rare; requires vulnerable hash implementation |

**Example — HMAC Byte Recovery:**
```
# Iterative recovery: test each byte value, measure response time
GET /api?sig=00000000...  → 12ms  (first byte wrong)
GET /api?sig=a0000000...  → 12ms  (first byte wrong)
GET /api?sig=7f000000...  → 14ms  (first byte correct, second byte checked)
# Continue for each position...
```

### §1-3. Database Query Differentials

Backend database queries that execute different operations or scan different amounts of data depending on input, producing timing signals observable through HTTP response times.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Time-Based Blind SQL Injection** | Injected `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`, or `BENCHMARK()` functions create attacker-controlled delays conditional on data | SQL injection point exists |
| **Query Complexity Differential** | Queries against valid vs. invalid records produce different execution plans; index hits vs. full table scans create timing differences | No response-time normalization |
| **ORM Search Leakage** | ORM-generated queries with search/filter parameters produce response times proportional to result set size, leaking data existence | Search endpoints with cross-origin accessibility |
| **N+1 Query Amplification** | GraphQL or ORM endpoints that resolve nested relationships produce timing proportional to relationship depth/count | Unbounded query depth |
| **Conditional Index Behavior** | Queries that hit indexes for some inputs but trigger scans for others create measurable timing differentials | Schema knowledge + injectable parameters |

**Database-Specific Delay Primitives:**

| Database | Function | Example |
|----------|----------|---------|
| MySQL | `SLEEP(n)`, `BENCHMARK(count, expr)` | `IF(1=1, SLEEP(5), 0)` |
| PostgreSQL | `pg_sleep(n)` | `; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--` |
| SQL Server | `WAITFOR DELAY 'HH:MM:SS'` | `IF (1=1) WAITFOR DELAY '0:0:5'` |
| Oracle | `DBMS_LOCK.SLEEP(n)` | `BEGIN IF (1=1) THEN DBMS_LOCK.SLEEP(5); END IF; END;` |
| SQLite | `randomblob(n)` (CPU-bound) | `CASE WHEN (1=1) THEN randomblob(500000000) ELSE 0 END` |

### §1-4. Business Logic Differentials

Application-specific processing paths that produce timing signals based on business state.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Search Result Volume** | Endpoints returning more results take longer to serialize/render; timing reveals whether search query matches exist | Observable response time correlation |
| **Feature Flag Detection** | Enabled vs. disabled features trigger different code paths with measurable timing differences | Feature flags in request-processing path |
| **Permission Check Chains** | Authorization checks that short-circuit on first denial vs. evaluating full permission chains | Complex RBAC with observable timing |
| **File Existence Probing** | File-serving endpoints that check filesystem existence before reading produce different timing for existing vs. non-existing paths | No constant-time response for missing files |
| **Payment Processing State** | Payment verification endpoints that contact external services for valid transactions but return immediately for invalid ones | External service call only on valid input |

### §1-5. Server-Side Parameter and Injection Discovery

Using timing differentials to discover hidden parameters, internal routing, and injection points that produce no visible output difference.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hidden Parameter Discovery** | Sending candidate parameter names and measuring response time; recognized parameters trigger additional processing | Backend processes recognized params differently |
| **Blind SSTI Detection** | Server-Side Template Injection payloads that cause computation but produce identical output; timing reveals successful injection | Template engine processes injected expressions |
| **Server-Side Parameter Pollution** | Encoded URI characters (`#`, `?`, `%00`) injected into parameters produce different backend processing times depending on how the server parses them | Multi-tier parameter parsing |
| **Blind JSON/XML Injection** | Malformed JSON escape sequences or XML entities produce different processing times; 200μs differences can reveal injection points | Parser processes injected content |
| **Reverse Proxy Route Discovery** | Timing differences when requests are routed through different backend paths via manipulated Host/path headers reveal internal infrastructure | Reverse proxy with timing-visible routing |

---

## §2. Network and Transport Layer Timing

Timing signals generated by network-level behavior — connection establishment, DNS resolution, TLS handshakes, and transport protocol mechanics.

### §2-1. DNS Resolution Timing

DNS lookup timing reveals whether hostnames resolve, whether they hit cache, and whether the server performs server-side DNS resolution.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SSRF Detection via DNS Timing** | Server-side requests to attacker-controlled hostnames produce measurable DNS resolution delays; cached vs. uncached DNS reveals whether the server attempted resolution | SSRF-capable endpoint |
| **DNS Rebinding Window** | Timing the gap between DNS cache expiry and re-resolution to inject malicious IP bindings | Short TTL + timing-sensitive application |
| **Overlong DNS Label Probing** | Sending 64+ octet DNS labels causes DNS client refusal without network lookup, distinguishing scoped SSRF from open proxies | DNS label validation differences |
| **Internal Hostname Probing** | Measuring resolution time for internal vs. external hostnames reveals network topology | Server-side DNS resolution of user input |

### §2-2. Connection and TLS Timing

TCP and TLS handshake timing reveals server identity, certificate processing, and connection reuse behavior.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **TLS Certificate Processing** | Different certificate chain lengths and validation complexity produce measurable handshake timing differences | Observable TLS handshake duration |
| **Connection Reuse Detection** | Reused vs. new connections have different latency profiles; detecting connection pooling reveals same-origin relationships | Browser connection pool behavior |
| **TCP Handshake Fingerprinting** | SYN-ACK timing reveals server OS, load state, and geographic location | Network-level timing measurement |
| **HTTP/2 Stream Priority Leakage** | Server stream scheduling priority reveals internal request processing order | HTTP/2 multiplexing with priority |

### §2-3. Response Size Inference

Network timing that correlates with response size, allowing attackers to infer content length without reading the response body.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Transfer Time Differential** | Larger responses take longer to transmit; timing reveals approximate response size | No constant-size padding |
| **Chunked Encoding Timing** | Chunked transfer encoding produces timing patterns that reveal chunk boundaries and total content size | Server uses chunked encoding |
| **Compression Ratio Oracle (BREACH/CRIME)** | Compressed responses containing attacker-controlled and secret content produce size variations detectable through timing; matching content compresses smaller | TLS compression or HTTP compression + reflected input |
| **ETag Length Leakage** | Cross-site ETag header length differences (even 1 byte) can be used as an XS-Leak oracle through conditional request timing | Server generates ETags with length correlated to content |

---

## §3. Browser-Side Timing (Cross-Site Leaks / XS-Leaks)

Timing attacks executed from the victim's browser that extract cross-origin information by exploiting browser behavior, same-origin policy gaps, and side-channel APIs.

### §3-1. Network Timing via Browser APIs

Direct measurement of cross-origin request timing using browser-available APIs and events.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`performance.now()` Measurement** | Wrap cross-origin fetch/XHR in `performance.now()` calls to measure completion time; precision reduced by browser mitigations but still ~5μs in some contexts | Cross-origin request permitted (no CORS block on the request itself) |
| **Resource Timing API** | `PerformanceResourceTiming` entries expose `duration`, `transferSize` (same-origin only), and timing milestones for cross-origin resources | Resource loaded as subresource |
| **Element Onload Timing** | `<img>`, `<script>`, `<link>`, `<iframe>` elements fire `onload`/`onerror` events; time between element creation and event firing reveals load duration | Cross-origin resource loadable via HTML element |
| **Cross-Window Timing** | `window.open()` + polling `window.origin` property to detect when navigation completes and origin changes | Pop-up not blocked; target doesn't set COOP |
| **Unload/Beforeunload Gap** | Time difference between `beforeunload` (navigation request) and `unload` (actual navigation) reveals response latency; bypasses `X-Frame-Options` | Navigation-based measurement |
| **Sandboxed Frame Timing** | `<iframe sandbox>` blocks JS execution, providing nearly pure network measurement without script execution noise | Target frameable without CSP/X-Frame-Options |

### §3-2. Execution Timing via Browser Internals

Timing differences caused by browser-internal processing of cross-origin content — not network timing but CPU/rendering timing.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Event Loop Blocking** | JavaScript's single-threaded event loop is blocked by cross-origin script execution; attacker measures blocking duration to infer script complexity/content | Shared event loop (no Site Isolation) or same-site context |
| **Busy Event Loop (Same-Site)** | Open target in separate window, create same-site iframe, measure `onload` blocking duration; bypasses Site Isolation since same-site resources share event loops | Same-site (not same-origin) relationship |
| **Service Worker Timer** | Service Worker intercepts navigation, starts timer, returns 204 to abort, measures JS blocking through repeated navigation cycles | Attacker-controlled Service Worker on same-site origin |
| **CSS Selector Short-Circuit** | jQuery's right-to-left CSS selector evaluation produces timing differences based on whether selectors match; injected via URL hash `jQuery(location.hash)` | Target page uses jQuery with `location.hash` in selector |
| **ReDoS Amplification** | Regular expression injection on target page causes exponential backtracking; runtime proportional to page data creates measurable timing variance | Regex injection point on target |
| **Rendering Time Differential** | Pages with more DOM elements or complex CSS take longer to render; `requestAnimationFrame` timing reveals rendering complexity | Cross-origin page renderable in context |

### §3-3. Cache State Probing

Detecting whether a resource exists in browser cache reveals whether the user previously visited a page or loaded a resource.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cache Timing Differential** | Cached resources load in ~0-2ms vs. 50-500ms for network fetches; timing measurement reveals cache state | Target resource cacheable + non-partitioned cache |
| **AbortController Cache Probe** | Issue `fetch()` with very short `AbortController` timeout (3-9ms); request succeeds only if resource is cached | Precise timeout calibration |
| **Error-Event Cache Detection** | Force server rejection (overlong Referer, incompatible headers); error event fires differently for cached vs. uncached resources | Server produces different errors for manipulated requests |
| **CORS Origin Mismatch** | Cached resources retain original `Access-Control-Allow-Origin`; accessing from different origin produces detectable mismatch | Resource was previously fetched with CORS |
| **Web Worker Parallel Probing** | Parallelize cache probing across many URLs using Web Workers; very short fetch timeouts succeed only for cached resources | Web Worker available |
| **Cache Capacity Eviction** | Fill browser cache to capacity, then check if target resource was evicted; eviction reveals cache was full vs. had room | Knowledge of cache size limits |

**Defense — Partitioned HTTP Cache:**
Modern browsers (Chrome 86+) implement cache partitioning by top-level origin, preventing cross-site cache probing. However, partitioning is ineffective for same-site (subdomain) requests and direct navigations.

### §3-4. Connection Pool and Resource Limit Oracles

Browser-level resource limits (connection pools, socket limits) create observable side-channels.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Connection Pool Exhaustion** | Exhaust browser's per-origin connection limit (typically 6 for HTTP/1.1); timing of subsequent requests reveals whether the target origin has open connections | Shared connection pool per origin |
| **Connection Pool Prioritization** | Chrome's connection-pool prioritization algorithm leaks redirect hostnames cross-domain; priority ordering reveals where redirects point | Chrome-specific implementation detail |
| **Socket Limit Timing** | Global browser socket limits (256 in Firefox) create timing differences when many connections are active | High-connection-count scenario |
| **Prefetch/Preconnect Detection** | Detecting whether `<link rel="preconnect">` hints have been processed reveals navigation intent | Prefetch behavior observable |

### §3-5. XS-Search (Cross-Site Search)

A compound attack class that uses any of the above timing oracles to iteratively brute-force search queries against cross-origin search endpoints.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Response-Size XS-Search** | Search results with matches produce larger responses than empty results; timing reveals response size differential | Search endpoint accessible cross-origin |
| **Result-Count XS-Search** | Backend computation time scales with result count; timing directly reveals whether query matched | No constant-time search processing |
| **Character-by-Character Recovery** | Iteratively brute-force search prefixes; each correct character produces a "hit" timing profile different from "miss" | Prefix-matching search with observable timing |
| **Boolean XS-Search** | Binary oracle (exists/doesn't exist) combined with search operators to extract structured data bit-by-bit | Search supports boolean/filter operators |
| **Frame Count Amplification** | Target page renders different numbers of iframes based on search results; `window.length` reveals frame count cross-origin without timing | `window.length` readable cross-origin |

---

## §4. Cryptographic Timing Oracles

Timing differences in cryptographic operations that leak key material, plaintext, or algorithm state.

### §4-1. Asymmetric Key Operation Timing

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **RSA Decryption Timing** | Modular exponentiation timing varies with key bits; Bleichenbacher-style attacks use padding oracle timing to recover plaintext | Non-constant-time RSA implementation |
| **ECDSA Nonce Leakage** | ECDSA signing time varies based on nonce value (e.g., top word of inverted nonce being zero creates ~300ns signal on P-521) | Non-constant-time modular inversion (CVE-2024-13176) |
| **Lattice-Based (Post-Quantum) Timing** | KyberSlash: timing in Kyber KEM decapsulation leaks secret key information through division operations that are not constant-time | Post-quantum implementations with variable-time arithmetic |

### §4-2. Symmetric and Hash Operation Timing

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **AES Cache Timing** | Table-lookup AES implementations produce cache-line access patterns dependent on key bytes; measurable through Flush+Reload or Prime+Probe | Shared cache with victim process |
| **HMAC Comparison Timing** | Non-constant-time HMAC comparison leaks correct bytes iteratively (§1-2); remote exploitation demonstrated at ~20μs precision over internet | `==` instead of `constant_time_compare()` |
| **Hash Length Extension** | Hash computation time proportional to message length reveals information about internal hash state | Non-standard hash construction |
| **PBKDF2/bcrypt Iteration Timing** | Password hashing time reveals iteration count configuration, allowing targeted brute-force optimization | Observable hash computation latency |

### §4-3. JWT and Token Timing

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JWT Signature Timing** | JWT validation libraries using `strcmp` for signature comparison leak correct signature bytes (CVE-2024-25191: php-jwt 1.0.0) | Non-constant-time signature comparison |
| **Algorithm Confusion Timing** | Different JWT algorithms (`HS256` vs. `RS256`) produce measurably different validation times, confirming which algorithm the server accepts | Multiple algorithms accepted |
| **Token Expiration Timing** | Expired vs. valid tokens processed through different code paths with different timing; reveals token validity window | Timing-observable expiration check |
| **Key ID (`kid`) Timing** | JWT `kid` header lookup produces timing dependent on key existence in keystore | Non-constant-time key lookup |

---

## §5. Hardware and Low-Level Side Channels (Web-Exploitable)

Hardware-level timing differences exploitable through web browser APIs — not requiring local code execution.

### §5-1. CPU Cache Timing via JavaScript

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Shared Cache Probing** | SharedArrayBuffer or `performance.now()` used to detect cache-line evictions caused by cross-origin activity; reveals memory access patterns | SharedArrayBuffer available (requires COOP/COEP) |
| **Spectre v1 (Bounds Check Bypass)** | Speculative execution reads cross-origin data into cache; timing measurement reveals cached values | Browser JS engine vulnerable to speculative execution |
| **Cache Occupancy Measurement** | Measuring time to fill and probe cache sets reveals cache utilization by other processes | High-resolution timer available |
| **Contention-Based History Sniffing** | CPU cache contention from visited-link styling creates timing differences detectable through JavaScript micro-benchmarks | Shared CPU cache + high-resolution timing |

### §5-2. GPU Cache Timing via WebGPU

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WebGPU Cache Side-Channel** | GPU compute shaders measure cache hit/miss timing on GPU cache lines, detecting rendering activity from other browser tabs (cross-origin) | WebGPU API available; shared GPU cache |
| **GPU Fingerprinting** | Timing of specific WebGPU operations reveals GPU model, driver version, and hardware configuration; achieves 90%+ website fingerprinting accuracy | WebGPU feature support varies by GPU |
| **Render Timing Correlation** | GPU rendering time for cross-origin content reveals page complexity and content characteristics | GPU rendering pipeline shared between origins |

### §5-3. Memory and Microarchitectural Channels

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DRAM Row Buffer Timing** | Memory access timing reveals whether target data is in same DRAM row (row hit vs. row conflict); exploitable through JavaScript typed arrays | Physical memory co-location |
| **Branch Prediction Side-Channel** | Training branch predictor with controlled patterns, then measuring cross-origin code execution timing that follows different branch patterns | Shared branch predictor state |
| **TLB Timing** | Translation Lookaside Buffer hits/misses reveal memory access patterns of cross-origin processes | Shared TLB + high-resolution timer |

---

## §6. Timing Signal Amplification Techniques

Techniques that increase the magnitude of timing signals, making otherwise-undetectable differences exploitable. These apply across all categories (§1-§5).

### §6-1. Computational Amplification

| Subtype | Mechanism | Amplification Factor |
|---------|-----------|---------------------|
| **Repeated Header/Parameter Injection** | Sending the same parameter hundreds of times forces the server to process each one, multiplying the per-instance timing difference | 10x-1000x |
| **GraphQL Batching** | Batching many queries into a single GraphQL request multiplies the processing time differential | Proportional to batch size |
| **ReDoS Injection** | Injecting catastrophic-backtracking regex patterns that amplify timing exponentially with input length | Exponential |
| **XML Entity Expansion (Billion Laughs)** | Nested XML entity references create exponential processing time | Exponential |
| **ORM Relationship Traversal** | Deep nested includes/joins in ORM queries multiply processing time with relationship depth | O(n^k) for k-depth |
| **Password Length Amplification** | Sending 200+ character passwords to amplify bcrypt/scrypt timing differences between valid-user (hash executed) and invalid-user (short-circuit) paths | Linear with password length |
| **Database `BENCHMARK()` Multiplication** | `BENCHMARK(10000000, SHA1('test'))` multiplies a single operation into millions | Arbitrary |

### §6-2. Measurement Noise Reduction

| Technique | Mechanism | Effect |
|-----------|-----------|--------|
| **Single-Packet Attack (HTTP/2)** | Two requests in one TCP packet; compare response arrival order instead of absolute time | Eliminates network jitter entirely |
| **Dual-Packet Synchronization** | Fragment across exactly two packets with ping-frame coalescing to solve sticky request-order problem | Eliminates first-request bias |
| **Connection Warming** | Send initial "warm-up" requests to establish TCP connections, populate caches, and stabilize server processing before measurement | Reduces connection-setup noise |
| **Bottom-Quartile Filtering** | Use only the fastest 25% of measurements, which reflect minimal noise | Reduces outlier impact |
| **Response-Order Comparison** | Instead of measuring absolute time, compare which of two responses arrives first across 50+ trials; report if >80% biased | Converts continuous signal to robust binary |
| **DNS Caching Pre-warming** | Pre-resolve DNS before timing measurement to eliminate DNS lookup variance | Removes DNS jitter |

### §6-3. Temporal Alignment Techniques

| Technique | Mechanism | Use Case |
|-----------|-----------|----------|
| **Last-Byte Synchronization** | Withhold final data frame of both requests, then send simultaneously | Race conditions + timing attacks |
| **TCP_NODELAY Manipulation** | Disable Nagle's algorithm to control packet boundaries precisely | Single-packet attack prerequisite |
| **Sacrificial Ping Frames** | Send HTTP/2 PING frames as padding to coalesce header frames into desired packet boundaries | Dual-packet synchronization |
| **IP Fragmentation Extension** | Split single TCP packet across multiple IP fragments to exceed 1,500-byte MTU limit for single-packet attacks | >10,000 simultaneous requests needed |

---

## §7. Race Condition Timing (Timing-Adjacent)

Race conditions are timing-adjacent — they exploit the same concurrent-request primitives (§6-2, §6-3) but target state mutation rather than information leakage. Included here because the measurement infrastructure is shared.

### §7-1. Limit Overrun Races

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Coupon/Discount Double-Spend** | Simultaneously apply same coupon code before deduction is committed; both requests see valid coupon | Non-atomic check-and-apply |
| **Rate Limit Bypass** | Concurrent requests arrive before rate counter increments; all pass the limit check | Counter increment not atomic |
| **Balance Double-Spend** | Simultaneous withdrawal requests both read same balance before deduction | Non-serialized transactions |
| **Gift Card Redemption Race** | Multiple redemption requests for same gift card processed concurrently (CVE-2024-58248: nopCommerce) | No distributed locking |

### §7-2. State Mutation Races

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **TOCTOU (Time-of-Check-to-Time-of-Use)** | Permission/validation check occurs in different transaction than the action; concurrent request changes state between check and use | Non-atomic check-then-act |
| **Session Fixation Race** | Concurrent login + session-read requests exploit gap between session creation and binding | Session management not serialized |
| **Email Verification Bypass** | Request email change + verification simultaneously; verification applies to old email before change propagates | Non-atomic email update flow |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Precision Required |
|----------|-------------|---------------------------|---------------------------|
| **Username/Account Enumeration** | Any authentication system | §1-1, §1-2 | ~1-10ms |
| **Cross-Origin Data Exfiltration** | Victim browser + target site | §3-1, §3-2, §3-5 | ~5-100ms (browser) |
| **Cryptographic Key Recovery** | TLS/JWT/API endpoints | §4-1, §4-2, §4-3 | ~100ns-20μs |
| **Hidden Infrastructure Mapping** | Reverse proxy chains | §1-5, §2-1, §2-2 | ~1-50ms |
| **Browser History/Activity Sniffing** | Victim browser | §3-3, §5-1, §5-2 | ~μs-ms |
| **Blind Injection Discovery** | Any backend with injection points | §1-3, §1-5 | ~200μs-10ms |
| **Search Data Extraction** | Cross-origin search endpoints | §3-5 | ~5-50ms |
| **WAF/Security Control Bypass** | WAF-protected applications | §1-5 + §6-1 | ~1-10ms |
| **User Fingerprinting/Tracking** | Any web context | §5-2, §3-3 | Varies |
| **Financial Limit Bypass** | E-commerce/banking | §7-1 | Single-packet precision |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §4-1 (ECDSA nonce timing) | CVE-2024-13176 (OpenSSL) | Private key recovery via ~300ns timing signal on P-521 curve; requires low-latency network |
| §4-3 (JWT `strcmp` timing) | CVE-2024-25191 (php-jwt 1.0.0) | Authentication bypass via non-constant-time signature comparison |
| §7-1 (Gift card race) | CVE-2024-58248 (nopCommerce <4.80.0) | Double-spend on gift card redemption; no order placement locking |
| §1-5 + §2-1 (Reverse proxy + DNS timing) | Kettle 2024 (375 domains) | IP spoofing header discovery via Param Miner timing; 206 domains with DNS pingback |
| §1-5 (Scoped SSRF via timing) | Kettle 2024 (hundreds of reverse proxies) | Internal infrastructure mapping; alternative routes to tens of thousands of domains |
| §3-4 (Connection pool priority oracle) | XS-Leak 2025 (Chrome) | Cross-domain redirect hostname leakage via Chrome connection-pool prioritization |
| §3-3 + §5-1 (Cache + contention) | Browsing History Sniffing 2025 | Faster and stealthier history sniffing via CPU contention side-channels |
| §5-2 (WebGPU cache side-channel) | WebGPU-SPY 2024 | 90% accuracy website fingerprinting of top 100 sites via GPU cache attacks |
| §3-5 (XS-Search) | Google Issue Tracker XS-Search | Source code URL extraction from Google's bug tracker via timing-based search |
| §2-3 (ETag length leak) | Cross-Site ETag Length Leak 2025 | Cross-origin response size inference through 1-byte ETag length differences |

---

## Detection and Exploitation Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **Burp Suite (Single-Packet Attack)** | Exploitation | Server-side timing (§1, §6) | HTTP/2 single-packet concurrent request delivery; built into Burp Repeater |
| **Param Miner** | Discovery | Hidden parameters (§1-5) | Timing-augmented parameter brute-forcing with single-packet measurement |
| **Turbo Intruder** | Exploitation | Race conditions (§7), timing (§1) | Custom Python-scripted high-concurrency request engine |
| **timing_attack (Ruby gem)** | Exploitation | String comparison (§1-2) | Statistical analysis of HTTP response times for byte-by-byte recovery |
| **Nanown** | Research | General server-side timing | Statistical timing analysis with ~100,000 sample profiling |
| **XSinator** | Research | XS-Leaks (§3) | Automated cross-browser XS-Leak testing framework |
| **xsleaks.dev** | Reference | XS-Leaks (§3) | Comprehensive wiki of browser-side timing techniques and defenses |
| **nowafpls** | Exploitation | WAF bypass via timing (§1-5) | Timing-discovered WAF bypass techniques |
| **SQLMap (time-based)** | Exploitation | Blind SQL injection (§1-3) | Automated time-based blind SQL injection with adaptive delay detection |
| **Raccoon Attack Tool** | Research | TLS timing (§4) | Timing attack against DH key exchange in TLS |

---

## Defenses Matrix

| Defense | Scope | Effective Against | Limitations |
|---------|-------|-------------------|-------------|
| **Constant-Time Comparison** (`hash_equals`, `hmac.compare_digest`, `crypto.timingSafeEqual`) | §1-2, §4-2, §4-3 | String/token/HMAC comparison timing | Does not protect against processing-path differentials |
| **Response Time Normalization** (sleep padding to fixed duration) | §1-1, §1-3, §1-4 | Server-side processing differentials | Increases latency; hard to calibrate; amplification may exceed padding |
| **Rate Limiting (per-IP, 1-5ms interval)** | §6-2 (single-packet) | Single-packet attack prerequisite | Legitimate users affected; bypassable with distributed IPs |
| **Partitioned HTTP Cache** | §3-3 | Cross-site cache probing | Ineffective for same-site (subdomain) and navigation requests |
| **SameSite Cookies (Lax/Strict)** | §3-1, §3-5 | Cross-origin authenticated timing | Does not prevent unauthenticated timing; Lax allows top-level navigation |
| **Cross-Origin-Opener-Policy (COOP)** | §3-1, §3-4 | Cross-window timing, connection pool oracle | Must be deployed on target; breaks legitimate popup interactions |
| **Cross-Origin-Resource-Policy (CORP)** | §3-1 | Cross-origin resource loading | Must be deployed on every sensitive endpoint |
| **Fetch Metadata (`Sec-Fetch-*`)** | §3-1, §3-3, §3-5 | Browser-initiated cross-origin requests | Requires server-side enforcement; older browsers unsupported |
| **`Vary: Sec-Fetch-Site`** | §3-3 | Cache probing via fetch | Segregates cache by request context |
| **WAF Packet Splitting** (split multi-request packets with delay) | §6-2 | Single-packet attack at edge level | Adds latency; not universally deployed |
| **`timer_resolution` Reduction** (browser) | §3-1, §3-2, §5-1 | High-precision browser timing | Adaptive attacks still work; harms legitimate performance APIs |
| **Site Isolation / Process Isolation** | §3-2, §5-1 | Event loop blocking, Spectre | Same-site bypass exists (§3-2 Busy Event Loop) |

---

## Summary: Core Principles

Web timing attacks exploit a **fundamental tension in computing**: performance optimization creates observable timing variations, and those variations correlate with secret state. Every cache hit, every early-return optimization, every conditional branch that skips unnecessary work creates a potential timing oracle. The attack surface is not a bug to be patched but a **structural property of how computers process information**.

The 2020 introduction of **Timeless Timing Attacks** and the 2024 refinement into the **single-packet attack** represent an inflection point. By eliminating network jitter through protocol-level request synchronization (HTTP/2 multiplexing, TCP packet coalescing), these techniques converted web timing attacks from a theoretical curiosity requiring lab conditions into a **portable, reliable exploitation primitive** effective against remote targets over commodity internet connections. The minimum detectable timing difference dropped from ~30ms (2015) to ~200μs (2024) — a 150x improvement — and no prior configuration or target-specific calibration is required.

Incremental defenses fail because timing leakage emerges at every layer of the stack simultaneously. Constant-time comparison (§1-2) does not protect against processing-path differentials (§1-1). Response-time padding (§1) does not address browser-side cache probing (§3-3). Cache partitioning (§3-3) does not prevent same-site attacks (§3-2). Each defense addresses one signal source while leaving others exposed, and **amplification techniques (§6) can escalate sub-threshold signals past any fixed defense threshold**. A structural solution would require either fully constant-time processing across the entire application stack (impractical) or **architectural isolation** where no timing signal from secret-dependent processing is ever observable by an untrusted party — which is precisely what browser features like Site Isolation, Cache Partitioning, COOP, and CORP attempt, but with significant gaps remaining at same-site boundaries, connection pools, and hardware cache hierarchies.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- PortSwigger Research, "Listen to the whispers: web timing attacks that actually work" (Black Hat USA 2024) — https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work
- Van Goethem et al., "Timeless Timing Attacks: Exploiting Concurrency to Leak Secrets over Remote Connections" (USENIX Security 2020) — https://www.usenix.org/conference/usenixsecurity20/presentation/van-goethem
- XS-Leaks Wiki — https://xsleaks.dev/
- PortSwigger, "Top 10 Web Hacking Techniques of 2025" — https://portswigger.net/research/top-10-web-hacking-techniques-of-2025
- Ferguson & Wilson, "WebGPU-SPY: Finding Fingerprints in the Sandbox through GPU Cache Attacks" (ACM AsiaCCS 2024) — https://arxiv.org/abs/2401.04349
- Ark, "Cross-Site ETag Length Leak" (2025) — https://blog.arkark.dev/2025/12/26/etag-length-leak
- Morgan & Morgan, "Web Timing Attacks Made Practical" (Black Hat USA 2015) — https://blackhat.com/docs/us-15/materials/us-15-Morgan-Web-Timing-Attacks-Made-Practical.pdf
- Gelernter & Herzberg, "Timing Attacks Have Never Been So Practical: Advanced Cross-Site Search Attacks" (Black Hat USA 2016) — https://blackhat.com/docs/us-16/materials/us-16-Gelernter-Timing-Attacks-Have-Never-Been-So-Practical-Advanced-Cross-Site-Search-Attacks.pdf
- Vila & Köpf, "Loophole: Timing Attacks on Shared Event Loops in Chrome" (USENIX Security 2017) — https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-vila.pdf
- Van Goethem et al., "Request and Conquer: Exposing Cross-Origin Resource Size" (USENIX Security 2020) — https://www.usenix.org/system/files/sec20-van_goethem.pdf
- Bortz et al., "Exposing Private Information by Timing Web Applications" (WWW 2007) — https://crypto.stanford.edu/~dabo/papers/webtiming.pdf
- Flatt Security, "Beyond the Limit: Expanding Single-Packet Race Condition" (2024) — https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/
- CVE-2024-13176 (OpenSSL ECDSA timing) — https://www.sentinelone.com/vulnerability-database/cve-2024-13176/
- CVE-2024-25191 (php-jwt timing) — https://www.cvedetails.com/cve/CVE-2024-25191/
