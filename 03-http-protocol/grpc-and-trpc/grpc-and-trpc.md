# gRPC / tRPC Security Mutation & Variation Taxonomy

**Version:** 2025.1
**Scope:** gRPC (Google Remote Procedure Call) and tRPC (TypeScript RPC) security vulnerabilities
**Coverage:** Protocol layer, serialization, authentication, service mesh, and type system attacks

---

## Classification Structure

This taxonomy organizes gRPC and tRPC attack vectors across three axes:

**Axis 1 (Mutation Target)** — The structural component being modified: HTTP/2 protocol layer, Protobuf serialization, metadata/headers, service discovery, authentication/authorization, transport/connection, type system/validation, and gateway/service mesh layer. This axis structures the main body of the document (§1-§8).

**Axis 2 (Discrepancy Type)** — The nature of the exploit mechanism created by the mutation. These cross-cutting types apply across all categories:

| Discrepancy Type | Definition | Common Manifestation |
|-----------------|------------|---------------------|
| **Protocol Violation** | Intentional violation of HTTP/2 or gRPC spec | Rapid reset, malformed frames, invalid settings |
| **Parsing Differential** | Different interpretation by components | Proxy vs backend, client vs server discrepancies |
| **Validation Bypass** | Circumventing input/output/metadata checks | Authentication bypass, input sanitization evasion |
| **Resource Exhaustion** | Triggering excessive resource consumption | Memory exhaustion, CPU saturation, stream flooding |
| **State Confusion** | Exploiting stateful protocol handling | Connection state mismatch, session confusion |
| **Type Confusion** | Exploiting type system weaknesses | Protobuf type manipulation, TypeScript type bypass |
| **Information Disclosure** | Unauthorized data or metadata exposure | Service enumeration, credential leakage, metadata exposure |
| **Auth/Authz Bypass** | Circumventing access controls | Hardcoded credentials, policy bypass, token manipulation |

**Axis 3 (Attack Scenario)** — The deployment context and ultimate impact. Mapped at the end of this document showing which mutation categories combine to enable specific attack scenarios.

### Fundamental Mechanism: RPC Over HTTP/2

Both gRPC and tRPC leverage HTTP/2 as transport (gRPC uses HTTP/2 framing directly; tRPC typically uses HTTP/2 features via modern web servers). This creates multiple interpretation boundaries:

1. **Binary Serialization Boundary** — Protobuf (gRPC) vs JSON (tRPC)
2. **HTTP/2 Framing Boundary** — Stream multiplexing, flow control, frame types
3. **Metadata Boundary** — gRPC metadata as HTTP/2 headers
4. **Type System Boundary** — Protobuf schema (gRPC) vs TypeScript types (tRPC)
5. **Gateway Boundary** — gRPC-Web, reverse proxies, service meshes

Each boundary represents an opportunity for differential interpretation, making the entire RPC stack vulnerable to mutations that create discrepancies between components.

---

## §1. HTTP/2 Protocol Layer Mutations

HTTP/2 provides the transport foundation for gRPC and (commonly) tRPC. Mutations at this layer exploit stream management, frame handling, and flow control mechanisms.

### §1-1. Stream & Connection Management Attacks

These attacks manipulate HTTP/2's stream lifecycle to create resource exhaustion or state confusion.

| Subtype | Mechanism | Key Condition | CVE/Reference |
|---------|-----------|---------------|---------------|
| **HTTP/2 Rapid Reset** | Client opens stream, sends request, immediately sends RST_STREAM to cancel, repeats at high rate. Server allocates resources before cancellation, causing DoS. | Target doesn't enforce stream creation rate limits independent of cancellation rate. | CVE-2023-44487 (record: 398M rps) |
| **MadeYouReset (Max Streams Bypass)** | Attacker sends GOAWAY frame followed by SETTINGS frame with SETTINGS_MAX_CONCURRENT_STREAMS=0. This breaks the max concurrent streams limit through protocol-compliant frame ordering. | Server processes SETTINGS after GOAWAY without proper validation. | CVE-2025-55163 |
| **gRPC-Go Stream Exhaustion** | Send requests and immediately cancel them. Valid per HTTP/2 spec, but gRPC-Go launches concurrent method handlers exceeding configured max stream limit. | Affects gRPC-Go < 1.56.3, < 1.57.1, < 1.58.3. Fixed in 1.59.0. | GMS-2023-3788 |
| **GOAWAY + SETTINGS Frame Attack** | Send GOAWAY frame immediately followed by SETTINGS frame with SETTINGS_MAX_CONCURRENT_STREAMS=0. Causes Envoy (Istio sidecar) to terminate abnormally. | Affects Istio 1.10.0-1.10.3, 1.11.0 with Envoy sidecar. | ISTIO-SECURITY-2021-008 |

**Cross-reference**: Stream exhaustion often combines with metadata attacks (§3-1) for amplification.

### §1-2. HTTP/2 Frame Manipulation

Attackers craft malformed or unexpected frame sequences to trigger vulnerabilities in HTTP/2 implementations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SETTINGS Frame Flood** | Send excessive SETTINGS frames without SETTINGS acknowledgment (SETTINGS_ACK). Each frame requires processing, causing CPU exhaustion. | Target doesn't rate-limit SETTINGS frame processing. |
| **HTTP/2 Smuggling (CL/TE Variants)** | Use headers like `transfer-encoding : chunked` (space before colon). Proxy forwards as-is; backend interprets it. Per spec, transfer-encoding takes precedence over content-length (CL.TE smuggling). | Frontend (Cloudflare, nginx) and backend interpret transfer-encoding differently. |
| **gRPC-Web Frame Tampering** | gRPC-Web uses `application/grpc-web-text` (base64-wrapped gRPC frames). Attacker intercepts, base64 decodes, modifies fields/flags, re-encodes, forwards. | gRPC-Web endpoints without integrity checks on frame payload. |

---

## §2. Protobuf Serialization Mutations

Protobuf is the serialization format for gRPC. Mutations target message structure, field encoding, and parser implementations.

### §2-1. Message Structure & Encoding Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Recursive Protobuf Parsing (CVE-2025-4565)** | Send protobuf message with deeply nested or cyclic recursive elements. Pure-Python protobuf backend doesn't limit recursion depth, causing stack exhaustion. | Target uses protobuf Pure-Python backend. Disclosed June 16, 2025. |
| **Varint Integer Overflow** | Exploit varint encoding (variable-length integers in protobuf). Send extremely large varint causing integer overflow in length calculations. Can lead to buffer overflows or memory corruption. | Protobuf implementation doesn't validate varint size before conversion. |
| **Unknown Field Injection** | Protobuf allows unknown fields (forward compatibility). Inject fields not in .proto schema but processed by backend logic. Can bypass validation or trigger hidden functionality. | Application processes protobuf messages without strict schema enforcement. |
| **Default Value Confusion** | Omit required fields relying on default values. In proto3, all fields are optional with defaults (0, "", false). Can cause logic errors if backend assumes presence. | Backend logic doesn't distinguish between explicitly set vs default values. |

### §2-2. Compression & Size Validation Bypass

| Subtype | Mechanism | Key Condition | CVE/Reference |
|---------|-----------|---------------|---------------|
| **Compression Bomb (Zip Bomb for gRPC)** | Send HTTP request with compressed payload to gRPC endpoint. Service verifies compressed size but not uncompressed size. "Compressed bomb" (highly compressible malicious payload) causes memory exhaustion when decompressed. | Service validates only compressed payload size. | CVE-2024-36129 (OpenTelemetry Collector) |
| **Message Size Limit Bypass** | Exploit discrepancy between advertised max message size and actual enforcement. Send message just under limit but with expansion gadgets (e.g., repeated fields with large strings). | Implementation checks serialized size but not in-memory size after parsing. | - |

---

## §3. gRPC Metadata & Header Mutations

gRPC metadata is implemented as HTTP/2 headers. Mutations exploit metadata handling, validation, and propagation.

### §3-1. Metadata Injection & Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Authentication Header Injection** | Inject or manipulate authentication metadata (e.g., `authorization`, custom token headers). If service doesn't validate metadata source, attacker can forge credentials. | Service trusts metadata without cryptographic validation or origin verification. |
| **Hardcoded Token Exploitation** | Target uses hardcoded static authentication token in metadata. RustFS example: token "rustfs rpc" hardcoded in source, accepted by all deployments. Single grpcurl command grants full access. | Hardcoded credentials in code, non-rotatable tokens. | CVE-2025-68926 (CVSS 9.8, RustFS) |
| **Metadata Timeout Manipulation** | Set excessive timeout values in `grpc-timeout` metadata header. Can cause resource holding attacks where server holds connections/resources for extended periods. | Service honors client-specified timeouts without upper bound. |
| **Binary Metadata Encoding Bypass** | Binary metadata values must end with `-bin` suffix and are base64-encoded. Craft metadata keys without `-bin` but containing binary data, or vice versa. Can trigger parser errors or bypass validation. | Implementation doesn't strictly enforce `-bin` suffix convention. |

### §3-2. HPACK & Header Compression Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HPACK Table Poisoning** | gRPC clients communicating through HTTP/2 proxies can poison the HPACK dynamic table (header compression state) between proxy and backend. Errors not cleared between header reads cause header key leakage to other clients. | HTTP/2 proxy shares HPACK state across clients without isolation. |
| **Header Bombing** | Send headers with extremely long values (close to max header size). HPACK compression is ineffective for random data, causing memory exhaustion on decompression. | Target doesn't enforce practical limits on uncompressed header size. |

---

## §4. Service Definition & Discovery Mutations

gRPC and tRPC expose service definitions for client code generation and documentation. Mutations exploit these discovery mechanisms.

### §4-1. gRPC Reflection Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unauthenticated Service Enumeration** | gRPC reflection API (`grpc.reflection.v1alpha.ServerReflection`) broadcasts all available services, methods, and message types. Attacker uses `grpcurl` or `grpcui` to list all endpoints without authentication. | Reflection enabled in production without access controls. |
| **Proto Schema Extraction** | Via reflection, attacker retrieves complete `.proto` file definitions. Reveals internal service structure, parameter names, types, potentially exposing business logic or attack surface. | Reflection API exposed; `.proto` files contain sensitive naming or structure. |
| **Hidden Service Discovery** | Reflection reveals services not documented or intended for public access. Can discover admin panels, debugging endpoints, internal APIs. | Service exposure not aligned with reflection configuration. |

### §4-2. tRPC Panel & Documentation Exposure

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **tRPC Panel Unauthenticated Access** | Developer exposes `trpc-panel` documentation tool (typically at `/panel` or `/trpc-panel`). Provides full list of procedures, input/output schemas, interactive testing interface. Simplifies vulnerability hunting. | Production deployment includes tRPC panel without authentication. |
| **Type Definition Leakage** | tRPC panel exposes TypeScript type definitions, revealing data models, validation rules, optional vs required fields. Can identify input validation bypasses. | Panel exposed; TypeScript types contain security-relevant information. |

---

## §5. Authentication & Authorization Mutations

Attacks targeting access control mechanisms in gRPC/tRPC applications.

### §5-1. Authentication Bypass

| Subtype | Mechanism | Key Condition | CVE/Reference |
|---------|-----------|---------------|---------------|
| **Hardcoded Credential Exploitation** | Static credentials embedded in source code or configuration. RustFS example: token "rustfs rpc" hardcoded client and server-side, non-configurable, no rotation mechanism. | Credentials in version control, publicly accessible source code. | CVE-2025-68926 (RustFS, CVSS 9.8) |
| **Metadata Authentication Bypass** | Service validates authentication token in wrong metadata key, or doesn't validate metadata origin. Attacker sends forged metadata with valid-looking but unverified credentials. | Weak metadata validation, reliance on client-provided metadata. |
| **JWT/Token Replay** | Capture valid authentication token (JWT in metadata) and replay. Effective if tokens lack expiration, nonce, or binding to connection/session. | Tokens without expiration, no replay protection, no session binding. |

### §5-2. Authorization Policy Bypass

| Subtype | Mechanism | Key Condition | CVE/Reference |
|---------|-----------|---------------|---------------|
| **URI Fragment Bypass (Istio)** | HTTP request with fragment in URI path (e.g., `/admin#.user/data`). Istio's URI path-based authorization compares paths but may ignore or process fragments incorrectly. | Istio authorization rules based on paths; fragment handling inconsistent. | Istio security advisory |
| **Host Header Case Sensitivity Bypass (Istio)** | Istio authorization policy compares `Host` or `:authority` headers case-sensitively. Send `Host: API.example.com` when policy expects `api.example.com`. | Authorization rules use `hosts` or `notHosts` with case-sensitive matching. | Istio security advisory |
| **tRPC Middleware Chain Bypass** | tRPC uses middleware for authentication/authorization. If middleware chain has gaps or middleware doesn't throw errors on failure, attacker can bypass by triggering edge cases. | Incomplete middleware coverage, missing error handling in middleware. |
| **Prototype Pollution in tRPC Context** | If tRPC procedures use `experimental_caller` / `experimental_nextAppDirCaller`, prototype pollution vulnerability can inject properties into context object, potentially bypassing authorization checks. | Use of experimental tRPC functions without sanitization. | GHSA-43p4-m455-4f4j |

---

## §6. Transport & Connection Layer Mutations

Attacks exploiting transport security, connection state, and WebSocket (for tRPC).

### §6-1. Transport Security Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Plaintext Communication Exploitation** | gRPC servers default to allowing plaintext communication. Developers use `usePlaintext()` during testing, forget to disable in production. All data (credentials, business data) transmitted unencrypted. | Production deployment without TLS enforcement. |
| **TLS Downgrade via Connection Reuse** | Exploit mTLS session reuse in Envoy/Istio. After mTLS validation settings change (e.g., stricter CA), old sessions can be reused without re-validation. | Envoy/Istio doesn't invalidate cached mTLS sessions on policy change. | CVE-2022-21654 |
| **Certificate Validation Bypass** | Client-side gRPC implementations with disabled or weak certificate validation. Attacker performs MITM with self-signed or invalid certificates. | Client configured with `grpc.ssl_target_name_override` or similar insecure options. |

### §6-2. Connection State & WebSocket Attacks (tRPC)

| Subtype | Mechanism | Key Condition | CVE/Reference |
|---------|-----------|---------------|---------------|
| **tRPC WebSocket connectionParams DoS** | Send invalid `connectionParams` object over WebSocket to tRPC 11 server. `parseConnectionParams` function throws error during validation. Error not caught, triggers uncaught exception, crashes entire server process. | tRPC 11 WebSocket enabled with `createContext` method. Any client can crash server. | CVE-2025-43855 (CVSS 8.7) |
| **WebSocket Frame Injection** | Inject malformed WebSocket frames to tRPC WebSocket handler. Can cause parser errors, state confusion, or trigger edge cases in frame processing logic. | WebSocket implementation doesn't validate all frame fields. |

---

## §7. Type System & Input Validation Mutations

Attacks exploiting type system weaknesses and input validation gaps.

### §7-1. gRPC Protobuf Type Confusion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Type Mismatch Injection** | Send protobuf message where field type differs from schema. Some parsers silently coerce types (e.g., int64 to int32 with truncation), others accept unknown wire types. Can bypass business logic checks. | Backend doesn't enforce strict type matching; relies on parser defaults. |
| **Oneof Field Confusion** | Protobuf `oneof` allows one of several fields to be set. Send message with multiple `oneof` fields set (invalid per spec). Some parsers accept last field, others first, causing differential interpretation. | Multiple components process same message with different `oneof` precedence. |

### §7-2. tRPC TypeScript Type Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Runtime Type Bypass** | tRPC provides compile-time type safety. At runtime, if input validation (e.g., Zod) is missing or incomplete, attacker sends data that doesn't match TypeScript types. Runtime doesn't enforce types; only validation libraries do. | tRPC procedures without Zod or other runtime validation. |
| **Type Coercion Exploitation** | JavaScript/TypeScript type coercion rules can be exploited. Send string `"123"` where number expected; JS coerces to number. Or send array `[1]` coerced to string `"1"`. Can bypass validation logic. | Weak equality checks (`==` vs `===`), missing type assertions. |
| **Prototype Pollution via Procedure Input** | Inject `__proto__` or `constructor.prototype` fields in input objects. If tRPC procedures merge or assign user input to objects without sanitization, can pollute prototypes. | Object.assign, spread operator, or merge utilities without prototype checks. |

### §7-3. Injection Attacks via Insufficient Validation

gRPC and tRPC are vulnerable to classic injection attacks when input validation is missing.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SQL Injection** | gRPC/tRPC procedure accepts user input and concatenates into SQL query without parameterization. Protobuf/JSON encoding doesn't prevent SQL injection; only parameterized queries or ORMs do. | Backend constructs SQL from user input without sanitization. |
| **Command Injection** | Procedure accepts filename, path, or command argument and passes to shell without sanitization. Example: `grpcurl` with user-controlled flags. | Backend executes shell commands with user-controlled input. |
| **XSS (tRPC with SSR/Browser Rendering)** | tRPC procedure returns data rendered in browser without escaping. Attacker injects HTML/JavaScript in input fields; returned to other users via tRPC response and rendered. | Server-side rendering or client renders tRPC responses as HTML without escaping. |

---

## §8. Gateway & Service Mesh Layer Mutations

Attacks exploiting reverse proxies, API gateways, gRPC-Web gateways, and service meshes (Envoy, Istio, nginx).

### §8-1. gRPC-Web Gateway Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Content-Type Confusion** | gRPC-Web uses `application/grpc-web-text` or `application/grpc-web+proto`. Gateway routes based on Content-Type. Send ambiguous or alternate Content-Type to bypass gateway-level controls but still be processed by backend. | Gateway and backend disagree on Content-Type interpretation. |
| **Base64 Encoding Bypass** | gRPC-Web encodes protobuf in base64 for browser compatibility. Gateway may validate base64 layer but not decoded protobuf. Attacker crafts valid base64 containing malicious protobuf payload. | Gateway only validates encoding, not decoded content. |

### §8-2. Service Mesh Exploitation (Istio/Envoy)

| Subtype | Mechanism | Key Condition | CVE/Reference |
|---------|-----------|---------------|---------------|
| **Envoy HTTP/2 SETTINGS DoS** | Send HTTP/2 SETTINGS frames with excessive parameters or malformed values. Envoy processes each frame, consuming CPU. CVE-2020-11080 relates to excessive CPU when processing SETTINGS frames. | Envoy version without rate limiting on SETTINGS frames. | CVE-2020-11080 (HIGH severity) |
| **Istio Authorization Policy Bypass (Fragment)** | Send HTTP request with URI fragment to bypass path-based authorization. Istio compares paths without normalizing fragments. | URI path authorization rules without fragment handling. | Istio advisory |
| **Istio Authorization Policy Bypass (Host Case)** | Exploit case-sensitive host matching. Policy expects `api.example.com`; send `API.example.com` or `Api.Example.Com`. | Host-based authorization rules with case-sensitive matching. | Istio advisory |
| **mTLS Session Reuse Bypass** | After mTLS validation settings change, Envoy reuses old cached sessions without re-validation. Attacker with previously valid cert can continue access after revocation or CA change. | Envoy doesn't flush mTLS session cache on policy update. | CVE-2022-21654 |

### §8-3. Proxy & Gateway Parsing Differentials

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Nginx gRPC Pass Misconfig** | Nginx `grpc_pass` directive with improper upstream configuration. Can cause routing errors, expose internal endpoints, or create path traversal opportunities. | Nginx configuration without trailing slashes or path normalization. |
| **Gateway Timeout Bypass** | Configure client-side gRPC timeout (via metadata) to be extremely high. If gateway enforces timeout but backend honors client timeout, can bypass gateway limits. | Gateway and backend timeout precedence differs. |

---

## Attack Scenario Mapping (Axis 3)

This table maps attack scenarios to the primary mutation categories that enable them.

| Attack Scenario | Architectural Context | Primary Mutation Categories | Notable CVEs |
|----------------|----------------------|---------------------------|--------------|
| **Denial of Service (DoS/DDoS)** | Internet-facing gRPC/tRPC endpoints, service meshes | §1 (HTTP/2 layer), §2-2 (compression), §6-2 (WebSocket), §8-2 (service mesh) | CVE-2023-44487 (Rapid Reset), CVE-2025-43855 (tRPC WS), CVE-2024-36129 (compression) |
| **Authentication Bypass** | Services relying on token/credential-based auth | §3-1 (metadata injection), §5-1 (auth bypass), §6-1 (plaintext) | CVE-2025-68926 (RustFS hardcoded token) |
| **Authorization Bypass & Privilege Escalation** | Service mesh policies, RBAC systems, tRPC middleware | §5-2 (authz policy), §7-2 (type bypass), §8-2 (Istio) | Istio fragment/host bypass, tRPC prototype pollution |
| **Information Disclosure & Enumeration** | Production services with debug features, public APIs | §4 (service discovery), §3-2 (HPACK poisoning), §6-1 (plaintext) | - |
| **Injection Attacks (SQL/Command/XSS)** | Backend services with database/shell/rendering | §7-3 (insufficient validation), §2-1 (unknown field injection) | - |
| **Man-in-the-Middle & Interception** | Unencrypted or weak TLS deployments | §6-1 (transport security), §3-2 (HPACK), §8-1 (gRPC-Web gateway) | CVE-2022-21654 (mTLS reuse) |
| **Service Mesh Exploitation** | Kubernetes, Istio, Envoy deployments | §8-2 (service mesh), §1-1 (stream management), §6-1 (TLS downgrade) | ISTIO-SECURITY-2021-008, CVE-2020-11080 |
| **API Misconfiguration Exploitation** | Development artifacts in production, over-permissive configs | §4-2 (tRPC panel), §4-1 (gRPC reflection), §6-1 (plaintext) | - |

---

## CVE / Bounty Mapping (2023-2025)

| Mutation Combination | CVE / Case | Impact / Bounty | CVSS Score |
|---------------------|-----------|----------------|------------|
| §6-2 (WebSocket) + §7 (validation) | CVE-2025-43855 (tRPC 11 WebSocket) | Unauthenticated DoS, crash entire tRPC server via invalid connectionParams | 8.7 (HIGH) |
| §5-1 (auth bypass) + §3-1 (metadata) | CVE-2025-68926 (RustFS gRPC) | Complete data disclosure, modification, cluster control via hardcoded token "rustfs rpc" | 9.8 (CRITICAL) |
| §1-1 (stream mgmt) + §8-2 (service mesh) | CVE-2025-55163 (MadeYouReset) | DDoS via HTTP/2 max streams bypass using GOAWAY+SETTINGS frames | HIGH |
| §2-2 (compression) | CVE-2024-36129 (OpenTelemetry Collector) | DoS via compression bomb (validates compressed but not uncompressed size) | - |
| §1-1 (stream mgmt) | CVE-2024-37168 (gRPC Node.js) | DoS via memory allocation with excessive size value | - |
| §1-1 (stream mgmt) | CVE-2023-44487 (HTTP/2 Rapid Reset) | Record-breaking DDoS: 398M rps (Google), 201M rps (Cloudflare), 155M rps (Amazon) | - |
| §8-2 (service mesh) + §1-1 (stream) | ISTIO-SECURITY-2021-008 | Envoy termination via GOAWAY+SETTINGS(STREAMS=0) | - |
| §8-2 (service mesh) | CVE-2022-21654 (Istio/Envoy) | mTLS session reuse without re-validation after policy change | - |
| §8-2 (service mesh) | CVE-2020-11080 (Envoy) | DoS via excessive CPU processing HTTP/2 SETTINGS frames | HIGH |
| §2-1 (protobuf) | CVE-2025-4565 (Protobuf Pure-Python) | DoS via recursive protobuf elements causing stack exhaustion | - |
| §5-2 (authz) + §8-2 (service mesh) | Istio Fragment/Host Bypass | Authorization policy bypass via URI fragment or case-insensitive host matching | - |
| §5-2 (authz) + §7-2 (type) | GHSA-43p4-m455-4f4j (tRPC) | Prototype pollution in experimental_caller/experimental_nextAppDirCaller | - |

---

## Detection & Testing Tools

### Offensive Tools (Reconnaissance & Exploitation)

| Tool | Type | Target | Core Technique |
|------|------|--------|---------------|
| **grpcurl** | CLI | gRPC | Interact with gRPC services, call methods, invoke reflection API |
| **grpcui** | Web UI | gRPC | Browser-based gRPC client with proxy support for Burp Suite integration |
| **ProtoFuzz** | Fuzzer | Protobuf | Generic protobuf message fuzzer; auto-generates fuzzers from .proto definitions |
| **Defensics** | Fuzzer | gRPC | Commercial black-box fuzzer with gRPC test suite; imports .proto files, generates malformed messages |
| **gRPC-Web Coder** | Burp Extension | gRPC-Web | Decodes/encodes application/grpc-web-text and application/grpc-web+proto for manual testing |
| **grpc-pentest-suite** | Burp Extension | gRPC-Web | Comprehensive gRPC-Web pentesting suite by nxenon |
| **h2load** | CLI | HTTP/2 | HTTP/2 flood attack tool for DoS testing |
| **grpc-dump** | CLI | gRPC | Capture and decode gRPC traffic for analysis |

### Defensive Tools (Scanning & Monitoring)

| Tool | Type | Target | Core Technique |
|------|------|--------|---------------|
| **StackHawk** | DAST Scanner | gRPC | Native gRPC scanner; understands binary protocol and streaming; CI/CD integration |
| **Levo** | API Security | gRPC/tRPC | Schema-valid attack payloads from real traffic; auto-detects roles, tokens, IDs for privilege abuse testing |
| **Escape** | DAST | gRPC | AI-enhanced business logic testing; detects gRPC-specific vulnerabilities |
| **Akto** | Scanner | gRPC | gRPC-specific vulnerability templates; captures gRPC over HTTP/2 traffic |
| **Tetragon** | Runtime Monitor | gRPC | eBPF-based observability; monitors processes, syscalls, network activity; gRPC integration |
| **OWASP ZAP** | DAST | gRPC | gRPC fuzzing support via plugins; injection, auth bypass, misconfiguration checks |

### Validation & Security Libraries

| Tool | Type | Target | Core Technique |
|------|------|--------|---------------|
| **Zod** | Library | tRPC | Runtime input/output validation for TypeScript; schema definition and validation |
| **trpc-shield** | Library | tRPC | Permission layer for tRPC; flexible rule-based authorization |
| **grpc-gateway** | Library | gRPC | Reverse-proxy server translating RESTful JSON API into gRPC (adds HTTP/gRPC boundary) |

---

## Summary: Core Principles

### What Makes gRPC/tRPC Mutation Space Possible?

The vulnerability surface stems from **four fundamental properties**:

1. **Multiple Interpretation Boundaries** — gRPC/tRPC stacks involve 5+ components (client, proxy, gateway, service mesh, backend) each parsing HTTP/2, protobuf/JSON, metadata, and types. Any discrepancy in parsing creates exploit opportunities.

2. **Protocol Complexity** — HTTP/2's stream multiplexing, flow control, and frame types (10+ frame types with interdependencies) create state management challenges. Combined with gRPC's metadata-as-headers and protobuf's wire format flexibility, attack surface is vast.

3. **Type System Duality** — gRPC relies on protobuf schemas (enforced at serialization), but backend logic operates on deserialized objects (runtime). tRPC uses TypeScript (compile-time) but JavaScript runtime has no type enforcement. This compile-vs-runtime gap enables type confusion attacks.

4. **Implicit Trust Assumptions** — Many implementations trust client-provided metadata (timeouts, authentication tokens), trust HTTP/2 spec compliance (stream limits, frame ordering), or trust upstream components (service mesh policies). These trust boundaries are systematically violated by mutations.

### Why Incremental Patches Fail

Each CVE fix addresses a specific mutation instance but doesn't close the structural gaps:

- **CVE-2023-44487 (Rapid Reset)** → Vendors added stream creation rate limits. But this doesn't address §1-1 MadeYouReset (SETTINGS manipulation) or §1-1 gRPC-Go exhaustion (cancellation vs handler launching).
- **CVE-2025-68926 (Hardcoded Token)** → RustFS removed hardcoded token. But this doesn't prevent §3-1 metadata injection or §5-1 weak JWT replay in other services.
- **CVE-2025-43855 (tRPC WebSocket)** → tRPC fixed specific validation error handling. But this doesn't address §7-2 type bypass or §5-2 middleware chain gaps.

Incremental fixes play "whack-a-mole" because they address symptoms (specific parser bugs, specific validation gaps) rather than root causes (interpretation boundaries, trust assumptions).

### Structural Solution

A comprehensive defense requires addressing the **five boundaries** simultaneously:

1. **HTTP/2 Framing Boundary** → Strict stream/frame limits independent of protocol operations; rate limit SETTINGS/RST_STREAM frames; enforce frame ordering validation.

2. **Serialization Boundary** → Schema-enforced validation at both serialization (protobuf/JSON) and deserialization; reject unknown fields; limit recursion depth; validate uncompressed sizes.

3. **Metadata Boundary** → Cryptographically verify all authentication/authorization metadata (JWTs with signatures); enforce origin validation; reject client-specified security-relevant metadata (timeouts, permissions).

4. **Type System Boundary** → Runtime validation at RPC entry points (Zod for tRPC, validator libraries for gRPC); treat TypeScript types as documentation, not security; fail closed on type mismatches.

5. **Gateway/Mesh Boundary** → Normalize all paths/headers before authorization checks (case, fragments, encoding); enforce consistent TLS validation; flush session caches on policy updates; parsing differential testing between components.

Additionally:

- **Defense in Depth** — Never rely on a single component (gateway, mesh, application). Each layer must validate independently.
- **Fail Closed** — On parsing errors, validation failures, or unexpected states, reject the request (don't silently coerce or accept).
- **Differential Testing** — Continuously test for interpretation differences between client/proxy/gateway/backend using fuzzing tools (ProtoFuzz, Defensics) and property-based testing.

The fundamental insight: **RPC security is a distributed systems problem, not an application security problem**. Every component in the call chain (HTTP/2 implementation, serialization library, service mesh, application code) must enforce the same security invariants. Discrepancies between any two components create exploitable mutations.

---

## References

### CVE Sources
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [GitHub Advisory Database](https://github.com/advisories)
- [Snyk Vulnerability Database](https://security.snyk.io/)
- [GitLab Advisory Database](https://advisories.gitlab.com/)

### Research Publications
- [gRPC Security Series - IBM PTC Security](https://medium.com/@ibm_ptc_security/grpc-security-series-part-3-c92f3b687dd9)
- [HTTP/2 Rapid Reset - Cloudflare](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/)
- [HTTP/2 Rapid Reset - Google Cloud](https://cloud.google.com/blog/products/identity-security/how-it-works-the-novel-http2-rapid-reset-ddos-attack)
- [ProtoFuzz: A Protobuf Fuzzer - Trail of Bits](https://blog.trailofbits.com/2016/05/18/protofuzz-a-protobuf-fuzzer/)
- [Breaking Protocol Buffers - IOActive Labs](https://labs.ioactive.com/2021/07/breaking-protocol-buffers-reverse.html)
- [tRPC Security Research - Borna Nematzadeh](https://medium.com/@LogicalHunter/trpc-security-research-hunting-for-vulnerabilities-in-modern-apis-b0d38e06fa71)

### Conference Proceedings
- [PortSwigger Top 10 Web Hacking Techniques 2024](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024)
- [Black Hat USA 2024 - Akto gRPC Security Capabilities](https://www.prnewswire.com/news-releases/akto-launches-industry-leading-grpc-api-security-capabilities-at-black-hat-usa-2024-302208072.html)

### Security Advisories
- [Istio Security Advisories](https://istio.io/latest/news/security/)
- [gRPC Security Audit](https://grpc.github.io/grpc/core/md_doc_security_audit.html)
- [tRPC Security Advisories](https://github.com/trpc/trpc/security)
- [Envoy Security Advisories - Palo Alto Networks](https://www.paloaltonetworks.com/blog/2019/12/cloud-envoy-vulnerabilities/)

### Tool Documentation
- [HackTricks - gRPC-Web Pentest](https://book.hacktricks.xyz/pentesting-web/grpc-web-pentest)
- [StackHawk gRPC Security](https://www.stackhawk.com/blog/best-practices-for-grpc-security/)
- [Defensics gRPC Support](https://www.blackduck.com/blog/defensics-grpc-support-for-web-mobile-app-testing.html)

### Vendor Security Bulletins
- [Trend Micro - Unsecure gRPC Implementations](https://www.trendmicro.com/en_us/research/20/h/how-unsecure-grpc-implementations-can-compromise-apis.html)
- [Cisco HTTP/2 Rapid Reset Advisory](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-http2-reset-d8Kf32vZ.html)
- [Qualys CVE-2023-44487 Analysis](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/10/cve-2023-44487-http-2-rapid-reset-attack)

### Standards & Specifications
- [gRPC Official Documentation](https://grpc.io/docs/)
- [Protocol Buffers Documentation](https://protobuf.dev/)
- [tRPC Documentation](https://trpc.io/docs/)
- [HTTP/2 Specification - RFC 7540](https://httpwg.org/specs/rfc7540.html)

---

*This document was created for defensive security research and vulnerability understanding purposes. Version 2025.1 — Last updated: February 2025.*
