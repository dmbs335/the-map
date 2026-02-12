# JWT (JSON Web Token) Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire JWT attack surface along three orthogonal axes derived from systematic analysis of CVEs, academic research, bug bounty reports, and practitioner writeups through 2025.

**Axis 1 — Mutation Target (Primary):** The structural component of the JWT being manipulated. JWT consists of three segments (Header, Payload, Signature) plus the ecosystem of key management, transport, and lifecycle mechanisms. Each top-level category targets a distinct structural component — the algorithm field, header parameters for key resolution, the cryptographic signature itself, payload claims, the key management infrastructure, token transport/storage, or the protocol-level lifecycle.

**Axis 2 — Discrepancy Type (Cross-cutting):** The nature of the security violation each mutation creates. These discrepancy types cut across all categories and explain *why* each mutation works:

| Discrepancy Type | Description |
|---|---|
| **Signature Bypass** | The token's integrity check is completely circumvented |
| **Key Confusion** | The verifier uses a different key or key type than intended |
| **Validation Gap** | A required check (claim, parameter, constraint) is missing or incomplete |
| **Injection** | Attacker-controlled data reaches an unintended interpreter (SQL, filesystem, URL) |
| **Cryptographic Flaw** | Mathematical or implementation weakness in the signing/verification algorithm |
| **Lifecycle Abuse** | Exploiting the stateless nature of JWTs or time-based assumptions |

**Axis 3 — Attack Scenario (Mapping):** The real-world impact context — authentication bypass, privilege escalation, account takeover, cross-service relay, SSRF, RCE, DoS, or data exfiltration. These are mapped in the Attack Scenario Mapping section (§8).

### Foundational Mechanism

A JWT is a compact, URL-safe token format defined in RFC 7519, consisting of three Base64URL-encoded segments separated by dots: `Header.Payload.Signature`. The Header declares the signing algorithm (`alg`) and optional key-resolution parameters (`kid`, `jku`, `jwk`, `x5u`, `x5c`). The Payload contains claims (issuer, subject, audience, expiration, custom data). The Signature is computed over `Base64URL(Header).Base64URL(Payload)` using the algorithm and key specified. Verification requires the receiver to: (1) parse the header, (2) resolve the correct key, (3) verify the signature, and (4) validate claims. Every mutation in this taxonomy exploits a failure in one or more of these four steps.

---

## §1. Algorithm Manipulation

Attacks that modify or exploit the `alg` header field to subvert signature verification. This is the most historically significant JWT attack surface.

### §1-1. None Algorithm Bypass

The `alg` field is set to `"none"` (or case variants), instructing the verifier to skip signature checking entirely.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Canonical none** | Set `alg` to `"none"` and remove the signature segment | Server accepts unregistered/unrestricted algorithms |
| **Case variation** | Use `"None"`, `"NONE"`, `"nOnE"` to bypass case-sensitive blocklists | Blocklist checks `alg` case-sensitively but the parser normalizes |
| **Empty signature preservation** | Set `alg` to `"none"` but retain the trailing dot (e.g., `header.payload.`) | Parser requires three segments but doesn't enforce signature presence |
| **Whitespace/encoding tricks** | Insert whitespace, null bytes, or alternate Base64 padding around `"none"` | Parser normalizes before comparison but blocklist checks the raw value |

**Example payload:**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.
```

### §1-2. Algorithm Confusion (Key Confusion)

The attacker switches the algorithm from asymmetric (RSA/ECDSA) to symmetric (HMAC), causing the verifier to treat the public key as an HMAC secret.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **RS256→HS256 confusion** | Change `alg` from `RS256` to `HS256`; sign with the RSA public key as the HMAC secret | Server selects algorithm from the token header; public key is obtainable |
| **ES256→HS256 confusion** | Same principle applied to ECDSA-to-HMAC downgrade | Public key exposed via JWKS endpoint or certificate |
| **PS256→HS256 confusion** | RSA-PSS to HMAC downgrade | Same conditions as RS256 variant |
| **Public key derivation** | When the public key is not directly exposed, derive it from two or more existing signed tokens using mathematical recovery | Server has signed ≥2 tokens with the same RSA key; attacker obtains both |

The attack works because HMAC verification uses a single shared secret, and if the library accepts the algorithm from the token header, it will use the RSA public key (a known value) as the HMAC secret — a value the attacker also knows.

### §1-3. Algorithm Downgrade

Forcing the use of a weaker algorithm variant within the same algorithm family.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **RS512→RS256 downgrade** | Switch to a weaker RSA variant with shorter signature requirements | Server allows algorithm flexibility within the RSA family |
| **ES512→ES256 downgrade** | Switch to a weaker ECDSA curve | Server doesn't pin the specific curve/key size |
| **EdDSA→ECDSA confusion** | Switch between Edwards-curve and Weierstrass-curve algorithms | Library handles multiple EC algorithm families |

---

## §2. Header Parameter Injection

Attacks exploiting JWT header parameters that control key resolution. The JWT specification defines several optional header parameters (`kid`, `jku`, `jwk`, `x5u`, `x5c`, `cty`) that, when improperly validated, become injection vectors.

### §2-1. Key ID (`kid`) Injection

The `kid` parameter identifies which key should be used for verification. If the server uses this value in database queries or filesystem operations without sanitization, it becomes an injection vector.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SQL injection via `kid`** | `kid` value contains SQL payload (e.g., `' UNION SELECT 'known-secret' --`) that returns an attacker-controlled key from the database | Server uses `kid` in raw SQL queries to look up signing keys |
| **Path traversal via `kid`** | `kid` points to a predictable file (e.g., `../../../dev/null` or `../../../proc/self/environ`) | Server reads key material from the filesystem using `kid` as a path |
| **Null key via `/dev/null`** | Point `kid` to `/dev/null` (empty file); sign token with empty string | Linux/Unix system; server reads file path from `kid` |
| **Known file key** | Point `kid` to a file with known content (e.g., `../../../etc/hostname`, a public CSS file) and use that content as the signing key | Any predictable file accessible to the server process |
| **LDAP injection via `kid`** | `kid` value contains LDAP filter injection | Server resolves keys from LDAP directory |
| **Command injection via `kid`** | `kid` value triggers OS command execution (e.g., via backtick interpolation) | Server passes `kid` to a shell command or eval-like function |

### §2-2. JWK Set URL (`jku`) Injection

The `jku` header specifies a URL from which the server fetches the JSON Web Key Set for verification.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unvalidated `jku` URL** | Set `jku` to an attacker-controlled server hosting a crafted JWKS; sign with the corresponding private key | Server fetches JWKS from any URL specified in the header |
| **URL allowlist bypass** | Use open redirects, DNS rebinding, or URL parser differentials to bypass domain allowlists (e.g., `https://trusted.com@evil.com`, `https://trusted.com#@evil.com/jwks`) | Server validates `jku` domain but is vulnerable to URL parsing tricks |
| **Same-origin `jku` abuse** | Host the crafted JWKS on a user-controllable path within the trusted domain (e.g., file upload, profile page, API endpoint that reflects JSON) | Server restricts `jku` to same-origin but user content can be hosted on the same domain |
| **SSRF via `jku`** | Point `jku` to internal services (`http://169.254.169.254/...`) to trigger server-side requests | Server follows `jku` without restricting to external hosts |

### §2-3. Embedded JWK (`jwk`) Injection

The `jwk` header embeds a public key directly within the token.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Self-signed token** | Generate attacker's own RSA/EC key pair; embed the public key in `jwk` header; sign with the private key | Server uses the embedded `jwk` for verification without checking against trusted key store |
| **Key ID matching** | Set the `kid` in the embedded `jwk` to match a known `kid` in the server's trusted key store, but supply different key material | Server matches `kid` but doesn't verify key material matches the trusted key (CVE-2025-24976) |

### §2-4. X.509 Certificate Parameters (`x5u`, `x5c`) Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unvalidated `x5u` URL** | Set `x5u` to an attacker-controlled URL serving a crafted X.509 certificate | Server fetches certificate from any URL |
| **Self-signed `x5c` chain** | Embed a self-signed certificate chain in the `x5c` header | Server doesn't validate the certificate chain against a trusted CA |
| **Certificate chain confusion** | Provide a valid leaf certificate signed by an untrusted root, hoping the server only validates the leaf | Incomplete chain validation logic |

### §2-5. Content Type (`cty`) Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Nested JWT confusion** | Set `cty` to `"JWT"` to trigger nested token processing on a non-nested token | Server follows `cty` blindly, enabling double-decoding or processing changes |
| **Deserialization via `cty`** | Set `cty` to `"application/x-java-serialized-object"` or `"text/xml"` to trigger unsafe deserialization or XXE processing of the payload | Server uses `cty` to determine payload deserialization strategy |

---

## §3. Cryptographic Implementation Flaws

Attacks targeting weaknesses in the cryptographic algorithms or their implementations, independent of header manipulation.

### §3-1. Weak Symmetric Key Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Dictionary-based brute force** | Use hashcat (`-m 16500`) or jwt_tool with known wordlists (e.g., `jwt.secrets.list`) to crack HMAC secrets offline | HMAC secret is a short, guessable, or common string |
| **Default/hardcoded secrets** | Use known default secrets (`"secret"`, `"password"`, `"changeme"`, `"your-256-bit-secret"`) | Developers left placeholder secrets in production |
| **Rule-based cracking** | Apply hashcat rules (e.g., `best64.rule`) to permute wordlist entries and discover password-derived secrets | Secret was derived from a human-chosen password |
| **Brute force (short key)** | Character-by-character brute force for keys shorter than the recommended 256 bits | Key length significantly below RFC 7518's MUST requirement |

Over 340 known weak JWT secrets have been cataloged. The attack is entirely offline — no server interaction required after obtaining a single valid token.

### §3-2. Elliptic Curve Implementation Flaws

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Psychic Signatures (zero-value r,s)** | Submit an ECDSA signature where both `r` and `s` are zero (or specific degenerate values); the verification equation `0 = 0` becomes trivially true | Java 15–18 with built-in JCA provider (CVE-2022-21449) |
| **ECDSA nonce reuse** | If the server signs two different tokens with the same ECDSA nonce (`k`), the private key can be recovered mathematically | Server-side ECDSA implementation with broken RNG or deterministic nonce failure |
| **Invalid curve attack** | Supply a public key point on a different (weaker) curve; the server performs operations on the weak curve, allowing key recovery | Library doesn't validate that the public key point lies on the expected curve |
| **Degenerate point injection** | Use curve points of small order to leak bits of the private key through multiple interactions | Library doesn't check point order |

### §3-3. RSA Implementation Flaws

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Short RSA key** | Factor the RSA modulus when a weak/short key (< 2048 bits) is used | Server uses undersized RSA keys |
| **Bleichenbacher padding oracle** | Exploit PKCS#1 v1.5 padding validation differences in RSA decryption (relevant for JWE) | Server uses RSA with PKCS#1 v1.5 and leaks padding validity |
| **e=1 or degenerate exponent** | Use an RSA key with public exponent `e=1`, making any message its own signature | Library doesn't validate RSA key parameters |

---

## §4. Payload Claim Manipulation

Attacks that modify JWT payload claims to alter authorization decisions, escalate privileges, or bypass validation logic. These require either a signature bypass (§1–§3) or exploit applications that check claims before or without full signature verification.

### §4-1. Identity Claims Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`sub` (Subject) swap** | Change the `sub` claim to another user's identifier | Application uses `sub` for authorization without additional verification |
| **`email` claim swap** | Change the `email` claim to a target user's email | Application trusts the email claim for user identity lookup |
| **Numeric ID substitution** | Change numeric user IDs in claims (e.g., `user_id`, `uid`) to target another user | BOLA/IDOR via JWT claim |
| **Issuer confusion (`iss`)** | Change `iss` to a different trusted issuer that the application also accepts | Multi-IdP environment where issuers share signing keys or validation is loose |
| **Array injection in `iss`** | Provide `iss` as an array containing both legitimate and malicious values (CVE-2025-30144) | Library incorrectly accepts arrays for string-type claims |

### §4-2. Authorization Claims Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Role escalation** | Change `role` from `"user"` to `"admin"` or inject `["admin", "user"]` | Application relies on JWT claims for role-based access control |
| **Scope expansion** | Add additional OAuth scopes (e.g., `"read write admin"`) to the `scope` claim | API gateway trusts JWT scopes without cross-referencing the authorization server |
| **Permission injection** | Add new permission claims or modify existing boolean flags (e.g., `"is_admin": true`) | Application uses custom JWT claims for fine-grained authorization |
| **Tenant ID manipulation** | Change `tenant_id` or `org_id` to access another tenant's resources | Multi-tenant application with tenant isolation based on JWT claims |

### §4-3. Temporal Claims Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Expiration removal** | Remove the `exp` claim entirely, creating a token that never expires | Server doesn't enforce mandatory `exp` presence |
| **Expiration extension** | Set `exp` to a far-future timestamp | Signature bypass is available; server trusts the `exp` in the token |
| **`nbf` (Not Before) bypass** | Set `nbf` to a past time or manipulate client-side time used for `nbf` generation | Application relies on client-provided time for `nbf` |
| **`iat` (Issued At) manipulation** | Pre-date or post-date the `iat` claim to circumvent age-based checks | Server uses `iat` for token freshness validation |
| **Back to the Future attack** | During device manufacturing (IoT), manipulate the device's perceived time to generate tokens with far-future `iat` claims; use them later when the timestamp arrives | Physical access during manufacturing; system lacks nonce/replay protection (RFC 7519 protocol flaw) |

### §4-4. Audience Claims Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Audience bypass (missing validation)** | Token has no `aud` claim or server doesn't validate it, allowing cross-service token use | Audience validation not enforced |
| **Audience confusion** | Use a token issued for Service A on Service B when both accept the same issuer | Services share trust but don't validate `aud` distinctly (CVE-2024-5798) |
| **ALBEAST attack** | Configure a token for the attacker's own AWS tenant with audience claims that victim applications accept | AWS multi-tenant environment without strict `aud`+signer validation |

---

## §5. Key Management Infrastructure Attacks

Attacks targeting the infrastructure that stores, distributes, and rotates signing keys, rather than the tokens themselves.

### §5-1. JWKS Endpoint Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JWKS endpoint takeover** | Gain control of the domain or path hosting the JWKS endpoint (e.g., expired domain, dangling DNS) | JWKS URL points to a domain the attacker can register or control |
| **JWKS poisoning** | Inject an attacker's public key into the JWKS endpoint through an application vulnerability | Write access to the JWKS endpoint or its backing store |
| **JWKS caching exploitation** | Exploit cache TTL windows — replace keys during the window when the server still trusts cached keys | Server caches JWKS responses; attacker can modify the endpoint between cache refreshes |
| **OIDC discovery manipulation** | Modify the `.well-known/openid-configuration` to point to a different JWKS endpoint | Attacker controls the OIDC discovery endpoint or can intercept/modify it |

### §5-2. Key Rotation Failures

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Stale key acceptance** | Exploit servers that continue accepting tokens signed with revoked/rotated keys indefinitely | No key expiration enforcement |
| **Key rollback** | Trick the server into reverting to an older (potentially compromised) key | Key selection based on `kid` without validating key freshness |
| **Parallel key confusion** | During rotation, exploit the window when both old and new keys are valid to bypass controls that assume single-key operation | Application logic assumes one active key |

### §5-3. Key Material Exposure

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Key in source code** | Extract HMAC secrets from public repositories, Docker images, or client-side JavaScript | Developers committed secrets to version control |
| **Key in configuration** | Extract keys from misconfigured cloud storage (S3 buckets), environment variable dumps, or error messages | Insecure deployment practices |
| **Key via side-channel** | Recover key material through timing attacks on HMAC comparison or power analysis on embedded devices | Unprotected comparison functions or physical access |

---

## §6. Token Transport and Storage Attacks

Attacks targeting how JWTs are transmitted, stored, and managed in the client-server communication channel.

### §6-1. Token Leakage Vectors

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **URL parameter leakage** | JWT passed as a URL query parameter, logged in server logs, browser history, and Referer headers | Application uses JWT in URL rather than Authorization header |
| **Referer header leakage** | Token in URL leaks to third-party domains via the HTTP Referer header | External resources loaded on the page receiving the token |
| **Server log exposure** | JWTs logged in access logs, error logs, or debug output in plaintext | Verbose logging configuration |
| **Cross-origin leakage** | Token accessible to third-party scripts via DOM (localStorage/sessionStorage) | XSS vulnerability + client-side token storage |
| **Proxy/CDN logging** | Intermediate proxies or CDNs log Authorization headers containing JWTs | Proxy/CDN misconfiguration |

### §6-2. Client-Side Storage Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **XSS + localStorage theft** | JavaScript injection reads the JWT from `localStorage` or `sessionStorage` | Token stored in browser storage; XSS vulnerability exists |
| **XSS + cookie theft** | Steal JWT from cookies without `HttpOnly` flag | Cookie lacks `HttpOnly`; XSS vulnerability exists |
| **CSRF with cookie-based JWT** | If JWT is in a cookie without CSRF protection, trigger authenticated requests from victim's browser | JWT stored in cookie; no CSRF token; `SameSite` not set |

### §6-3. Token Replay

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Simple replay** | Intercept and reuse a valid JWT before it expires | No replay protection; token intercepted via MITM, logs, or leakage |
| **Cross-context replay** | Use a token obtained from one context (e.g., password reset email) in another context (e.g., API authentication) | Token not bound to specific action or context |
| **Long-lived token abuse** | Exploit tokens with excessively long expiration (hours/days) after the user has logged out | No server-side revocation mechanism; long `exp` window |

---

## §7. Protocol-Level and Structural Attacks

Attacks exploiting fundamental properties of the JWT/JOSE specification or its interaction with broader protocols.

### §7-1. JWS/JWE Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Encrypted↔signed confusion** | Submit a JWS token where the server expects JWE, or vice versa, exploiting different parsing paths | Server doesn't enforce the expected token type |
| **Nested JWT abuse** | Exploit double-encoding or double-processing when the server handles nested JWTs (JWS inside JWE) | Server processes nested tokens without proper depth/type checking |

### §7-2. Base64 Encoding Exploits

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Non-canonical Base64URL** | Use alternate Base64 representations (different padding, whitespace, line breaks) that decode to the same value but bypass signature checks or WAF rules | Parser and verifier handle Base64 differently |
| **Unicode/encoding injection** | Inject Unicode characters or alternate encodings in claim values that normalize differently across components | Multi-component architecture with different JSON/string parsers |

### §7-3. Parser Differential Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JSON parser differential** | Exploit differences between JSON parsers (duplicate keys, trailing commas, comments, number precision) across components that process the same JWT | Different JSON parsing libraries between token issuer, gateway, and application |
| **Duplicate claim handling** | Include the same claim twice with different values; different parsers take the first vs. last occurrence | Parser inconsistency between validation and consumption layers |
| **Memory exhaustion via malformed tokens** | Send tokens with excessive numbers of dot separators, deeply nested JSON, or extremely long Base64 segments (CVE-2025-27144) | Library allocates memory proportional to input without bounds checking |

### §7-4. Statelessness Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Irrevocable token** | Exploit the fundamental inability to revoke a stateless JWT before its natural expiration | No server-side token blacklist or revocation list |
| **Session fixation via JWT** | Fix a victim's session by injecting a known JWT, maintaining access even after the victim's actions | Application doesn't bind JWTs to additional session state |
| **Missing `jti` uniqueness** | Replay tokens when the `jti` (JWT ID) claim is absent or the server doesn't track used `jti` values | No `jti` enforcement; no server-side tracking |

---

## §8. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|---|---|---|
| **Authentication Bypass** | Any JWT-protected endpoint | §1 (alg manipulation) + §2 (header injection) + §3 (crypto flaws) |
| **Privilege Escalation** | Role/permission stored in JWT claims | §4-2 (authz claims) + any signature bypass (§1–§3) |
| **Account Takeover** | Identity derived from JWT claims | §4-1 (identity claims) + §6 (token leakage/replay) |
| **Cross-Service Token Relay** | Microservices / multi-API architecture | §4-4 (audience bypass) + §5-1 (JWKS confusion) |
| **Cross-Tenant Access** | Multi-tenant SaaS / cloud platform | §4-2 (tenant ID manipulation) + §4-4 (ALBEAST) |
| **SSRF** | Server fetches remote resources from JWT headers | §2-2 (`jku` injection) + §2-4 (`x5u` injection) |
| **Remote Code Execution** | Unsafe deserialization or command injection | §2-1 (`kid` command injection) + §2-5 (`cty` deserialization) |
| **Denial of Service** | Resource-constrained server | §3-2 (invalid curve) + §7-3 (memory exhaustion) |
| **Persistent Impersonation (IoT)** | IoT devices with factory-stage physical access | §4-3 (Back to the Future) |
| **WAF/Gateway Bypass** | Security appliance in front of application | §7-2 (encoding tricks) + §1-1 (case variants) |

---

## §9. CVE / Bounty Mapping (2022–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §3-2 (Psychic Signatures) | CVE-2022-21449 (Java 15–18) | CVSS 7.5. Complete ECDSA signature bypass with zero-value r,s. Affects all Java JWT libraries using built-in JCA. |
| §1-1 (None algorithm) | CVE-2024-48916 (Ceph RadosGW) | Authentication bypass. `alg=none` accepted, allowing arbitrary claim forgery. |
| §4-4 (Audience bypass) | CVE-2024-5798 (HashiCorp Vault) | Auth bypass. JWT audience claim not properly validated; invalid logins succeed. |
| §1-2 (Algorithm confusion) | CVE-2024-54150 | RS256→HS256 confusion allowing token forgery with public key. |
| §4-1 (Issuer array injection) | CVE-2025-30144 (fast-jwt) | Issuer validation bypass. Arrays accepted for `iss` claim, mixing legitimate and malicious issuers. |
| §7-3 (Memory exhaustion) | CVE-2025-27144 (Go JOSE) | DoS. Malformed JWTs with excessive periods cause exponential memory consumption. |
| §2-3 (Key ID matching) | CVE-2025-24976 (Distribution registry) | Key injection. `kid` matched but actual key material not verified against trusted store. |
| §5-1 / §6-3 (Token leakage) | Grafana Bug Bounty | JWT tokens in query parameters leaked to backend data sources via proxied requests. |
| §6-3 (Replay / revocation) | HackerOne #3120790 (WakaTime) | Session replay. Logged-out tokens remain valid, enabling persistent access. |
| §1-2 (Algorithm confusion) | CVE-2025-4692 (cloud platform) | Authentication bypass via algorithm confusion in cloud service. |

---

## §10. Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **jwt_tool** (Python) | Comprehensive JWT testing | 16+ attack modules: none alg, algorithm confusion, `kid` injection, claim tampering, brute force, JWKS injection |
| **jwtXploiter** | Known CVE exploitation | Tests against all known JWT CVEs; exploits `kid`, `jku`, `x5u` header claims |
| **JWT Security Analyzer** | Payload generation for 20+ attack vectors | Generates attack payloads for CVE-2024-54150, CVE-2025-30144, CVE-2025-4692, and others |
| **hashcat** (`-m 16500`) | HMAC secret cracking | Offline brute force / dictionary / rule-based attacks against HS256/HS384/HS512 secrets |
| **jwtfuzz** (Rust) | Fuzzing and malformation | Generates malformed tokens: null signatures, swapped algorithms, psychic signatures, encoding edge cases |
| **JWTForge** | OAuth2/OIDC testing | JWT vending service generating customizable tokens for fuzzing authentication systems |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Burp JWT Scanner** (Extension) | Automated vulnerability detection | Scans for none algorithm, algorithm confusion, weak secrets, header injection in intercepted traffic |
| **JWTLens** | Token analysis and visualization | Decodes, analyzes, and highlights security issues in JWT structure and claims |
| **OWASP WSTG JWT Tests** | Penetration testing methodology | Structured checklist covering all JWT attack vectors for manual security assessment |

### Research Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **jwt.io** | Token inspection | Online decoder/encoder for rapid JWT structure analysis |
| **PentesterLab JWT Exercises** | Training and skill development | Hands-on labs for each JWT vulnerability class including CVE-specific exercises |
| **hakaioffsec/jwt-vulnerabilities-lab** | Practice environment | Docker-based vulnerable lab implementing major JWT vulnerability types |

---

## §11. Summary: Core Principles

**The fundamental property that makes the JWT attack surface so expansive is the dual nature of the token as both a carrier of data and an instruction set for its own verification.** The JWT header is attacker-controlled yet dictates critical security decisions — which algorithm to use, where to find the verification key, how to interpret the payload. This inversion of control (the message instructing the verifier how to verify it) is the root cause of the entire §1 (algorithm manipulation) and §2 (header parameter injection) attack families. No other common authentication mechanism gives the client this level of influence over the verification process.

**Incremental fixes fail because the attack surface is combinatorial.** Fixing `alg: none` doesn't prevent algorithm confusion. Fixing algorithm confusion doesn't prevent `kid` injection. Fixing `kid` injection doesn't prevent `jku` SSRF. Each mutation target (§1–§7) is independently exploitable, and combinations create novel attack chains (e.g., `jku` bypass + algorithm confusion + claim manipulation). Libraries must implement a "deny-by-default" posture across *all* header parameters simultaneously, which many fail to do — evidenced by recurring CVEs across different libraries year after year (2015 through 2025).

**The structural solution requires three architectural principles:** (1) **Server-side algorithm pinning** — never read the algorithm from the token; configure it at the application level. (2) **Closed key resolution** — never fetch, embed, or dynamically resolve keys from token headers; use a pre-configured, immutable key store. (3) **Stateful lifecycle management** — accept that purely stateless JWTs cannot support revocation, replay prevention, or session binding; augment with server-side state (token blacklists, refresh token rotation, `jti` tracking) for any use case requiring these properties. The 2025 "Back to the Future" attack on IoT underscores that even the RFC 7519 specification itself has protocol-level gaps (missing nonce requirements) that no library can fix without deviating from the standard.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- RFC 7519: JSON Web Token (JWT) — https://datatracker.ietf.org/doc/html/rfc7519
- RFC 7518: JSON Web Algorithms (JWA) — https://datatracker.ietf.org/doc/html/rfc7518
- PortSwigger Web Security Academy: JWT Attacks — https://portswigger.net/web-security/jwt
- Auth0: Critical Vulnerabilities in JSON Web Token Libraries — https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- PentesterLab: The Ultimate Guide to JWT Vulnerabilities and Attacks — https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide
- SecurityPattern: "Back to the Future" Attack — https://www.securitypattern.com/post/introducing-the-back-to-the-future-attack
- HackTricks: JWT Vulnerabilities — https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens
- OWASP WSTG: Testing JSON Web Tokens — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens
- Red Sentry: JWT Vulnerabilities List 2026 — https://redsentry.com/resources/blog/jwt-vulnerabilities-list-2026-security-risks-mitigation-guide
- TrustedSec: Keys to JWT Assessments — https://trustedsec.com/blog/keys-to-jwt-assessments-from-a-cheat-sheet-to-a-deep-dive
- Wallarm: 340 Weak JWT Secrets — https://lab.wallarm.com/340-weak-jwt-secrets-you-should-check-in-your-code/
- Intigriti: Exploiting JWT Vulnerabilities — https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-jwt-vulnerabilities
- Akamai: Analyzing Broken User Authentication Threats to JWT — https://www.akamai.com/blog/security-research/owasp-authentication-threats-for-json-web-token
- JFrog: CVE-2022-21449 "Psychic Signatures" Analysis — https://jfrog.com/blog/cve-2022-21449-psychic-signatures-analyzing-the-new-java-crypto-vulnerability/
- Traceable AI: JWTs Under the Microscope — https://www.traceable.ai/blog-post/jwts-under-the-microscope-how-attackers-exploit-authentication-and-authorization-weaknesses
