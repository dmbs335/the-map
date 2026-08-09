# JWT (JSON Web Token) Mutation/Variation Taxonomy

---

## Classification Structure


**Axis 1 — Mutation Target (Primary):** The structural component of the JWT being manipulated. JWT consists of three segments (Header, Payload, Signature) plus the ecosystem of key management, transport, and lifecycle mechanisms. Each top-level category targets a distinct structural component — the algorithm field, header parameters for key resolution, the cryptographic signature itself, payload claims, the key management infrastructure, token transport/storage, or the protocol-level lifecycle.

**Axis 2 — Discrepancy Type (Cross-cutting):** The nature of the security violation each mutation creates. These discrepancy types cut across all categories and explain *why* each mutation works:

| Discrepancy Type | Description |
|---|---|
| **Signature Bypass** | The token's integrity check is completely circumvented |
| **Key Confusion** | The verifier uses a different key or key type than intended |
| **Validation Gap** | A required check (claim, parameter, constraint) is missing or incomplete |
| **Injection** | Attacker-controlled data reaches an unintended interpreter (SQL, filesystem, URL) |
| **Cryptographic Flaw** | Mathematical or implementation weakness in the signing/verification algorithm |
| **Type Confusion** | The verifier processes the token as a different type (JWS vs. JWE) than intended |
| **Resource Exhaustion** | Attacker-controlled parameters force excessive computation before authentication |
| **Lifecycle Abuse** | Exploiting the stateless nature of JWTs or time-based assumptions |

**Axis 3 — Attack Scenario (Mapping):** The real-world impact context — authentication bypass, privilege escalation, account takeover, cross-service relay, SSRF, RCE, DoS, or data exfiltration. These are mapped in the Attack Scenario Mapping section (§8).

### Foundational Mechanism

A JWT is a compact, URL-safe token format defined in RFC 7519. A JWS compact serialization has three Base64URL-encoded segments: `Header.Payload.Signature`; a JWE compact serialization has five: `Header.EncryptedKey.IV.Ciphertext.AuthenticationTag`. Processing includes parsing the header, selecting an allowed algorithm and key, verifying or decrypting the token, and validating claims such as issuer, audience, and expiration.

---

## §1. Algorithm Manipulation

Attacks that modify or exploit the `alg` header field to subvert signature verification. This is the most historically significant JWT attack surface.

### §1-1. None Algorithm Bypass

The `alg` field is set to `"none"` (or case variants), instructing the verifier to skip signature checking entirely.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Canonical none** | Set `alg` to `"none"` and remove the signature segment | Server accepts unregistered/unrestricted algorithms |
| **Case variation** | Use `"None"`, `"NONE"`, `"nOnE"` to bypass case-sensitive blocklists. Note: per RFC 7515, `alg` values are case-sensitive ASCII strings — a spec-compliant library should reject these outright. This only works against implementations with case-insensitive algorithm lookup or naive blocklists that check case but the underlying parser normalizes | Non-spec-compliant parser with case-insensitive algorithm matching, or blocklist that checks case while parser normalizes |
| **Empty signature preservation** | Set `alg` to `"none"` but retain the trailing dot (e.g., `header.payload.`) | Parser requires three segments but doesn't enforce signature presence |
| **Whitespace/encoding tricks** | Insert whitespace, null bytes, or alternate Base64 padding around `"none"`. As with case variation, RFC 7515 does not permit these — this exploits implementation-specific leniency in JSON/Base64 parsing, not a protocol-level weakness | Parser normalizes whitespace/encoding before comparison but blocklist checks raw value; non-compliant JSON/Base64 handling |
| **Unknown algorithm empty-signature bypass** | Set `alg` to an arbitrary unsupported value (e.g., `"zzz"`, `"foo"`). The library's signature computation function returns an empty string for unrecognized algorithms instead of raising an error. The attacker supplies an empty signature segment (trailing dot). Verification compares `"" == ""` and passes — a different code path from the `none` handler, which explicitly skips verification. PentesterLab reports this for HarbourJwt, but the claimed CVE-2026-23993 was not present in the CVE Program API when checked on 2026-04-29 | Library returns empty/default from signature computation for unknown algorithms; signature comparison does not reject empty values |

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
| **RS512→RS256 downgrade** | Switch to a weaker RSA hash variant (SHA-256 vs. SHA-512). Primarily a **policy-bypass** issue rather than a practical cryptographic attack — SHA-256 still provides 128-bit collision resistance, which is not realistically exploitable. The practical impact is limited to environments where security policy mandates RS384/RS512 and the server fails to enforce it | Server allows algorithm flexibility within the RSA family; impact requires policy-specific context |
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

### §2-6. Token Type (`typ`) Confusion

The `typ` header parameter declares the media type of the JWT. RFC 7519 defines `"JWT"` as the standard value, while OAuth 2.0 and OIDC specifications introduce differentiated types (`"at+jwt"` for access tokens per RFC 9068, `"dpop+jwt"` for DPoP proof tokens per RFC 9449). When receivers do not validate the `typ` header, tokens issued for one purpose can be substituted for another.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ID Token / Access Token confusion** | Use an OIDC ID Token (`typ` absent or `"JWT"`) where an OAuth 2.0 Access Token (`"at+jwt"`) is expected, or vice versa. Both are signed by the same issuer with the same key, but carry different claims and authorization semantics. An ID Token presented as an access token grants the attacker the identity claims as authorization claims, bypassing scope restrictions. | Same issuer/key for ID Tokens and Access Tokens; receiver does not validate `typ` to distinguish token purpose; no audience cross-check between token types |
| **DPoP proof substitution** | Present a standard JWT where a DPoP proof (`"dpop+jwt"`) is expected. RFC 9449 requires DPoP proofs to include `typ: "dpop+jwt"`, `jwk`, `jti`, `htm`, `htu`, `iat` (and `ath` for resource access). Missing `typ` validation is one failure point — it allows a standard JWT to pass the type check, but the proof must still satisfy the remaining required claims to be accepted. The attack succeeds when the server validates `typ` as the *only* (or primary) distinguishing check, or when multiple validation gaps combine | Server does not validate `typ: "dpop+jwt"` in the proof JWT, combined with incomplete enforcement of other required DPoP claims (`jwk`, `jti`, `htm`, `htu`, `iat`); or server fails to reject non-DPoP tokens at DPoP-protected endpoints |
| **Missing `typ` validation** | Omit the `typ` header entirely or set it to an unexpected value (e.g., `"JWT"` instead of `"at+jwt"`). Many libraries and frameworks do not check `typ` at all, treating all structurally valid JWTs identically regardless of their intended purpose | Library/framework default configuration does not enforce `typ` checking; application does not add custom `typ` validation logic |

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
| **Invalid curve attack** | Supply a public key point on a different (weaker) curve; the server performs operations on the weak curve, allowing key recovery. Note: this primarily affects JWE ECDH-ES key agreement (recipient's static EC private key recovery) rather than ECDSA signature verification — see `cryptographic-implementation-vulnerabilities.md` for the generalized treatment | Library doesn't validate that the public key point lies on the expected curve |
| **Degenerate point injection** | Use curve points of small order to leak bits of the private key through multiple interactions | Library doesn't check point order |

### §3-3. RSA Implementation Flaws

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Short RSA key** | Factor the RSA modulus when a weak/short key (< 2048 bits) is used | Server uses undersized RSA keys |
| **Bleichenbacher padding oracle** | Exploit PKCS#1 v1.5 padding validation differences in RSA decryption (relevant for JWE) | Server uses RSA with PKCS#1 v1.5 and leaks padding validity |
| **e=1 or degenerate exponent** | Use an RSA key with public exponent `e=1`, making any message its own signature | Library doesn't validate RSA key parameters |

### §3-4. PBES2 Key Derivation Abuse (Billion Hashes Attack)

JWE supports password-based encryption via PBES2 (RFC 7518 §4.8), where a Content Encryption Key (CEK) is derived from a password using PBKDF2 iterations. The iteration count is specified in the `p2c` (PBES2 Count) header parameter — which is attacker-controlled and processed *before* any authentication or validity check.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Excessive iteration count** | Set `p2c` to the maximum 32-bit integer value (2,147,483,647); the server must complete all PBKDF2 iterations to derive the CEK before it can determine whether the token is valid. A single malicious token can consume minutes to hours of CPU time. The attack is entirely unauthenticated — no valid credentials or prior tokens are required. | Library supports PBES2 key encryption algorithms (`PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`) and does not enforce a maximum `p2c` value (CVE-2023-51775, CVE-2023-49290) |
| **Amplified batch DoS** | Send multiple JWE tokens with high `p2c` values in parallel, multiplying the CPU exhaustion across worker threads/processes | Server processes JWE tokens from unauthenticated sources; no rate limiting on token validation |

**Affected libraries and fixes:**
- **jose4j** (Java): vulnerable before 0.9.4 (CVE-2023-51775)
- **lestrrat-go/jwx** (Go): fixed in v1.2.27 / v2.0.18 (CVE-2023-49290)
- **jose2go** (Go): fixed in v1.6.0
- **josekit-rs** (Rust): fixed in v0.8.5
- **jwcrypto** (Python): vulnerable before 1.5.1 (CVE-2023-6681)
- **latchset/jose** (C): vulnerable (CVE-2023-50967)
- **jjwt** (Java): reported vulnerable by the NDSS 2026 *Token Time Bomb* paper (paper-listed CVE-2024-39960; no public CVE Program record found as of 2026-08-09)
- **nimbus-jose-jwt** (Java): vulnerable (CVE-2023-52428)

### §3-5. Compression Decompression Abuse (Compression DoS)

JWE supports payload compression via the `zip` header parameter (RFC 7516 §4.1.3). When set to `"DEF"` (Deflate), the library may decompress plaintext after successful JWE decryption and before returning it. Since `zip` is attacker-controlled and decompression can occur *before* application-level size validation, a crafted JWE containing a highly compressed payload that expands to gigabytes triggers excessive memory allocation — a classic decompression bomb. Unlike PBES2 billion hashes (§3-4), which targets CPU before token validity can be established, this attack targets memory during the decrypt/decompress path. JWTeemo found this class across multiple JWE-supporting implementations and CVEs.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Decompression bomb via `zip`** | Craft a JWE with `zip: "DEF"` and a payload that compresses to a small token but expands to gigabytes upon Deflate decompression. The library decompresses after decryption but before returning the payload, consuming server memory proportional to the decompressed size. Describe this as unauthenticated only when the deployment accepts attacker-supplied encrypted tokens that reach the JWE decryption path; unlike PBES2 `p2c` abuse, the decompression step normally depends on successful processing of the JWE ciphertext. | Library supports `zip` parameter and does not enforce a maximum decompressed payload size (CVE-2024-28176, CVE-2024-28180, CVE-2024-29370, CVE-2024-28102, CVE-2024-29371, paper-listed CVE-2024-27663, CVE-2025-63811, CVE-2024-28122) |
| **`zip` in JWS (RFC violation)** | The `zip` parameter is defined only for JWE (RFC 7516 §4.1.3), not JWS. However, some libraries accept `zip` in JWS headers and decompress the payload after signature verification. An attacker crafts a JWS with `zip: "DEF"` to trigger decompression in contexts where only JWS is expected — bypassing defenses that restrict JWE-specific attack surface. This is an RFC-violating behavior: the JWT specification (RFC 7515) does not define `zip` for JWS. | Library processes `zip` in JWS despite RFC restriction; no explicit rejection of compression in signed-only tokens |

**Affected libraries and fixes:**
- **jose** (JavaScript): fixed with decompression size limits (CVE-2024-28176)
- **go-jose** (Go): fixed in v3.0.3 / v4.0.1 (CVE-2024-28180)
- **python-jose** (Python): vulnerable (CVE-2024-29370)
- **jwcrypto** (Python): fixed in v1.5.6 (CVE-2024-28102)
- **jose4j** (Java): fixed (CVE-2024-29371)
- **jose-jwt** (C#): reported fixed by the NDSS 2026 *Token Time Bomb* paper (paper-listed CVE-2024-27663; no public CVE Program record found as of 2026-08-09)
- **jose2go** (Go): vulnerable (CVE-2025-63811)
- **lestrrat-go/jwx** (Go): fixed (CVE-2024-28122)

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

### §4-4. Audience Claims Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Audience bypass (missing validation)** | Token has no `aud` claim or server doesn't validate it, allowing cross-service token use | Audience validation not enforced |
| **Audience confusion** | Use a token issued for Service A on Service B when both accept the same issuer | Services share trust but don't validate `aud` distinctly |
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

JWS and JWE both use compact dot-separated Base64URL forms. A unified `decode()` interface that does not require the expected token type can confuse signing and encryption flows.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Sign/Encrypt confusion (public key forgery)** | Attacker acquires the public RSA/EC key (e.g., via OIDC `/.well-known/jwks.json`), then crafts a JWE token encrypted with that public key. When the server's unified `decode()` processes this JWE, it decrypts using its private key and accepts the attacker-controlled payload as a valid JWT — the attacker sets arbitrary claims without needing the signing private key. The attack fundamentally subverts the security model: JWS verification proves authenticity (only the private key holder can sign), but JWE decryption only proves confidentiality (anyone with the public key can encrypt). By submitting a JWE where a JWS is expected, the attacker converts a "proof of identity" check into a "can you read this?" check — which anyone with the public key can pass. | Library accepts both JWS and JWE via a single decode path; application uses asymmetric signing (RS*/PS*/ES*); attacker can obtain the public key; no explicit token type (JWS vs. JWE) enforcement (CVE-2022-39174, CVE-2022-3102, CVE-2023-51774) |
| **Polyglot token** | A single token is constructed to be valid under multiple parsing interpretations across different JWT libraries. Since JWS (3 dot-separated segments) and JWE (5 dot-separated segments) share similar compact serialization, and libraries differ in how they detect and route token types, a carefully crafted token can cause one library to validate it as a legitimate JWS while another processes it as a JWE — allowing complete token forgery in multi-library architectures (e.g., gateway validates JWS, backend processes JWE). The JWE payload, encrypted key, IV, and authentication tag fields can be set to arbitrary byte sequences of appropriate length, giving the attacker freedom to construct such ambiguous tokens. | Multi-component architecture using different JWT libraries for validation vs. consumption; libraries auto-detect token type from structure rather than enforcing it explicitly |
| **Encrypted↔signed type confusion** | Submit a JWS token where the server expects JWE, or vice versa, exploiting different parsing paths and validation logic applied to each type | Server doesn't enforce the expected token type via explicit type check or `typ` header validation |
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
| **Memory exhaustion via malformed tokens** | Send tokens with excessive numbers of dot separators so the library splits the token into a huge number of segments and over-allocates memory (CVE-2025-27144) | Library eagerly splits on every `.` without reasonable bounds checking |

### §7-4. Statelessness Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Irrevocable token** | Exploit the fundamental inability to revoke a stateless JWT before its natural expiration | No server-side token blacklist or revocation list |
| **Session fixation via JWT** | Fix a victim's session by injecting a known JWT, maintaining access even after the victim's actions | Application doesn't bind JWTs to additional session state |
| **Missing `jti` uniqueness** | Replay tokens when the `jti` (JWT ID) claim is absent or the server doesn't track used `jti` values | No `jti` enforcement; no server-side tracking |

### §7-5. Serialization Format Confusion

RFC 7515 defines two serialization formats for JWS: Compact (three dot-separated Base64URL segments) and JSON (a JSON object with `protected`, `payload`, `signature` fields, plus an optional Flattened variant). While the JWT specification (RFC 7519) mandates Compact serialization, some libraries accept JSON-serialized JWS through the same parse interface. When the application layer assumes Compact format for claim extraction but the library validates a JSON-format token, the resulting mismatch between claim extraction logic and signature verification creates an authentication bypass.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Compact↔JSON format mismatch** | Attacker crafts a JWS in JSON serialization format with a spoofed claim field (e.g., a `fakeiss` field containing a base64url-encoded `{"iss":"fakeissuer"}`). The JWT library (e.g., go-jose) validates the signature against the legitimate `protected` header — which is intact and correctly signed. However, the application extracts claims by assuming Compact format: splitting on dots and base64-decoding the middle segment. In the JSON-format token, this splitting operation hits the spoofed field instead of the real payload, causing the application to accept the attacker's forged claims while the library reports a valid signature. The attack splits signature verification from claim extraction across two different serialization assumptions. | Library accepts both Compact and JSON JWS serialization via unified parse; application assumes Compact format for claim extraction (e.g., splitting on `.` and decoding the second segment); no explicit format enforcement (CVE-2024-5037, Kubernetes bug bounty) |
| **Cross-system format confusion** | In multi-component architectures, one component (e.g., API gateway) validates the token as JSON-format JWS, while another component (e.g., application server) re-parses it as Compact. The fields validated differ between the two parsing modes, allowing attacker-controlled claims to pass through the gateway validation but be interpreted differently by the backend. | Multi-component architecture where JWT is validated and consumed by different systems; each system uses a different serialization assumption |

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
| **Denial of Service** | Resource-constrained server | §3-2 (invalid curve) + §3-4 (PBES2 billion hashes) + §3-5 (compression DoS) + §7-3 (memory exhaustion) |
| **Token Forgery via Type Confusion** | Asymmetric signing with public key exposure (OIDC) | §7-1 (sign/encrypt confusion, polyglot token) + §2-6 (`typ` confusion) + §7-5 (format confusion) |
| **WAF/Gateway Bypass** | Security appliance in front of application | §7-2 (encoding tricks) + §1-1 (case variants) |

---

## §9. CVE / Bounty Mapping (2022–2026)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §3-2 (Psychic Signatures) | CVE-2022-21449 (Java 15–18) | CVSS 7.5. Complete ECDSA signature bypass with zero-value r,s. Affects Java JWT libraries using built-in JCA ECDSA provider on vulnerable JDK versions (15–18 prior to patch). |
| §1-1 (None algorithm) | CVE-2024-48916 (Ceph RadosGW) | Authentication bypass. `alg=none` accepted, allowing arbitrary claim forgery. |
| §4-4 (Audience bypass — missing validation) | CVE-2024-5798 (HashiCorp Vault) | Auth bypass. JWT `aud` claim not properly validated; logins with invalid or missing audience succeed. |
| §1-2 (Algorithm confusion) | CVE-2024-54150 (cjwt, Comcast C JWT library) | RS256→HS256 confusion allowing token forgery with public key. |
| §4-1 (Issuer array injection) | CVE-2025-30144 (fast-jwt) | Issuer validation bypass. Arrays accepted for `iss` claim, mixing legitimate and malicious issuers. |
| §7-3 (Memory exhaustion) | CVE-2025-27144 (Go JOSE) | DoS. Malformed JWTs with excessive periods trigger excessive memory allocation during token splitting/parsing. |
| §2-3 (Key ID matching) | CVE-2025-24976 (Distribution registry) | Key injection. `kid` matched but actual key material not verified against trusted store. |
| §7-1 (Sign/encrypt confusion) | Project-documented CVE-2022-39174 (authlib/Python) | Authentication bypass. Public key used for JWS verification exploited to forge JWE tokens via unified decode() interface. Authlib documents the identifier, but no public CVE Program API record was found as of 2026-08-09. |
| §7-1 (Sign/encrypt confusion) | Project-documented CVE-2022-3102 (jwcrypto/Python) | Authentication bypass. Same sign/encrypt confusion vector as CVE-2022-39174. JWCrypto documents the identifier, but no public CVE Program API record was found as of 2026-08-09. |
| §7-1 (Sign/encrypt confusion) | CVE-2023-51774 (json-jwt/Ruby) | Identity check bypass. NVD describes sign/encrypt confusion in json-jwt gem 1.16.3. Broader version ranges (1.15.x, 1.16.x) may be affected per gem changelog but are not explicitly stated in the NVD entry. |
| §3-4 (PBES2 billion hashes) | CVE-2023-51775 (jose4j/Java) | DoS. Unbounded `p2c` parameter allows CPU exhaustion via 2^31 PBKDF2 iterations. Fixed in jose4j 0.9.4. |
| §3-4 (PBES2 billion hashes) | CVE-2023-49290 (lestrrat-go/jwx) | DoS. Same PBES2 `p2c` exploitation. Fixed in lestrrat-go/jwx v1.2.27 / v2.0.18. |
| §1-1 (Unknown algorithm empty-signature) | PentesterLab HarbourJwt report (claimed CVE-2026-23993, not present in CVE Program API as of 2026-04-29) | Authentication bypass. `GetSignature()` returns empty string for unrecognized `alg` values; empty-vs-empty comparison passes verification. Requires independent verification before citing as confirmed. |
| §5-1 / §6-3 (Token leakage) | Grafana Bug Bounty | JWT tokens in query parameters leaked to backend data sources via proxied requests. |
| §6-3 (Replay / revocation) | HackerOne #3120790 (WakaTime) | Session replay. Logged-out tokens remain valid, enabling persistent access. |
| §1-2 (Algorithm confusion) | Paper-listed CVE-2024-57453 (libjwt/C) | Authentication bypass. RS256→HS256 confusion allowing token forgery with public key. Listed by the NDSS 2026 paper, but no public CVE Program record was found as of 2026-08-09. |
| §1-2 (Algorithm confusion) | Paper-listed CVE-2024-57454 (cpp-jwt/C++) | Authentication bypass. RS256→HS256 confusion allowing token forgery with public key. Listed by the NDSS 2026 paper, but no public CVE Program record was found as of 2026-08-09. |
| §3-4 (PBES2 billion hashes) | CVE-2023-6681 (jwcrypto/Python) | DoS. Unbounded `p2c` parameter allows CPU exhaustion. |
| §3-4 (PBES2 billion hashes) | CVE-2023-50967 (latchset/jose/C) | DoS. Unbounded `p2c` parameter allows CPU exhaustion. |
| §3-4 (PBES2 billion hashes) | Paper-listed CVE-2024-39960 (jjwt/Java) | DoS. Unbounded `p2c` parameter allows CPU exhaustion. Listed by the NDSS 2026 paper, but no public CVE Program record was found as of 2026-08-09. |
| §3-4 (PBES2 billion hashes) | CVE-2023-52428 (nimbus-jose-jwt/Java) | DoS. Unbounded `p2c` parameter allows CPU exhaustion. |
| §3-4 (PBES2 billion hashes) | CVE-2023-50658 (jose2go/Go) | DoS. Unbounded `p2c` parameter allows CPU exhaustion. |
| §3-5 (Compression DoS) | CVE-2024-29370 (python-jose/Python) | DoS. Decompression bomb via `zip` parameter causes memory exhaustion. |
| §3-5 (Compression DoS) | CVE-2024-28102 (jwcrypto/Python) | DoS. Decompression bomb via `zip` parameter causes memory exhaustion. |
| §3-5 (Compression DoS) | CVE-2024-29371 (jose4j/Java) | DoS. Decompression bomb via `zip` parameter causes memory exhaustion. |
| §3-5 (Compression DoS) | CVE-2024-28176 (jose/JavaScript) | DoS. Decompression bomb via `zip` parameter causes memory exhaustion. |
| §3-5 (Compression DoS) | Paper-listed CVE-2024-27663 (jose-jwt/C#) | DoS. Decompression bomb via `zip` parameter causes memory exhaustion. Listed by the NDSS 2026 paper, but no public CVE Program record was found as of 2026-08-09. |
| §3-5 (Compression DoS) | CVE-2025-63811 (jose2go/Go) | DoS. Decompression bomb via `zip` parameter causes memory exhaustion. |
| §3-5 (Compression DoS) | CVE-2024-28180 (go-jose/Go) | DoS. Decompression bomb via `zip` parameter causes memory exhaustion. Fixed in v3.0.3 / v4.0.1. |
| §3-5 (Compression DoS) | CVE-2024-28122 (lestrrat-go/jwx) | DoS. Decompression bomb via `zip` parameter causes memory exhaustion. |
| §7-1 (Sign/encrypt confusion) | Paper-listed CVE-2024-24238 (jose-jwt/C#) | Authentication bypass. JWS public key used to forge JWE tokens via unified decode interface. Listed by the NDSS 2026 paper, but no public CVE Program record was found as of 2026-08-09. |
| §7-5 (Format confusion) | CVE-2024-5037 (OpenShift Telemeter) | CVSS 7.5. Authentication bypass via JSON-serialized JWS with spoofed issuer field. go-jose validates signature on real header while application extracts claims from spoofed JSON field. |
| §7-5 (Format confusion) | Kubernetes bug bounty | Authentication bypass. Same JSON vs. Compact serialization format confusion as CVE-2024-5037; forged issuer accepted by Kubernetes API server. |

---

## §10. Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **jwt_tool** (Python) | Comprehensive JWT testing | 16+ attack modules: none alg, algorithm confusion, `kid` injection, claim tampering, brute force, JWKS injection |
| **jwtXploiter** | Known CVE exploitation | Tests against all known JWT CVEs; exploits `kid`, `jku`, `x5u` header claims |
| **JWT Security Analyzer** | Payload generation for 20+ attack vectors | Generates attack payloads for algorithm confusion, issuer/audience validation flaws, header-parameter abuse, and other JWT attack classes; keep CVE mapping in supporting notes rather than treating tool coverage as a canonical CVE list |
| **hashcat** (`-m 16500`) | HMAC secret cracking | Offline brute force / dictionary / rule-based attacks against HS256/HS384/HS512 secrets |
| **jwtfuzz** (Rust) | Fuzzing and malformation | Generates malformed tokens: null signatures, swapped algorithms, psychic signatures, encoding edge cases |
| **JWTForge** | OAuth2/OIDC testing | JWT vending service generating customizable tokens for fuzzing authentication systems |
| **Burp JWT Scanner** (Extension) | Automated vulnerability detection | Scans for none algorithm, algorithm confusion, weak secrets, header injection in intercepted traffic |
| **JWTeemo** | Systematic JWT implementation fuzzing | Grammar-based fuzzer using FBNF (Function-extended BNF) + UCT-Rand feedback-driven generation; differential analyzer detects cross-library parsing discrepancies and resource exhaustion via Chebyshev-based anomaly detection. Evaluated 43 libraries across 10 languages, discovered 31 vulnerabilities (20 CVEs). Findings incorporated into IETF RFC 8725bis draft |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **JWTLens** | Token analysis and visualization | Decodes, analyzes, and highlights security issues in JWT structure and claims |
| **OWASP WSTG JWT Tests** | Penetration testing methodology | Structured checklist covering all JWT attack vectors for manual security assessment |

### Research Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **jwt.io** | Token inspection | Online decoder/encoder for rapid JWT structure analysis |
| **PentesterLab JWT Exercises** | Training and skill development | Hands-on labs for each JWT vulnerability class including CVE-specific exercises |
| **hakaioffsec/jwt-vulnerabilities-lab** | Practice environment | Docker-based vulnerable lab implementing major JWT vulnerability types |

---

## §11. BaaS (Backend-as-a-Service) JWT Exposure

Backend-as-a-Service platforms (Supabase, Firebase, Appwrite) expose database access via client-side JWT tokens. Unlike traditional architectures where server-side code enforces access control, BaaS platforms shift the security boundary to database-level policies — Row Level Security (RLS) in Supabase/PostgreSQL, Security Rules in Firebase. When these policies are misconfigured or absent, the publicly embedded JWT grants unrestricted access.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Missing Row Level Security (RLS)** | BaaS platforms embed an "anon" JWT in client-side JavaScript (intentionally public). Security depends on per-table RLS policies. When RLS is **not enabled** on a table, the anon key's access is governed by PostgreSQL grants — Supabase's default grants to the `anon` role allow read/write on `public` schema tables, so disabling RLS typically exposes the table. When RLS **is enabled but no policies are defined**, the default behavior is deny-all (no rows visible via API). The dangerous case is RLS disabled (relying on grants) or RLS enabled with overly permissive policies | Supabase/PostgreSQL-based BaaS; one or more tables without `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` (exposed via default grants), or with RLS enabled but overly broad policies |
| **Service Role Key Exposure** | The `service_role` JWT (which bypasses all RLS) leaked via client-side code, `.env` files in public repositories, error messages, or build artifacts grants full RLS-bypassing database access — not PostgreSQL superuser, but sufficient to read/write all tables without any row-level policy enforcement | Service role key accessible to attacker; no network-level restriction on direct Supabase API access |
| **Firebase Security Rules Misconfiguration** | Firebase Realtime Database and Firestore default to **Locked mode** (deny-all), but the Firebase Console also offers a **Test mode** option during project creation that sets fully open rules with a 30-day expiry. During the expiry window, any authenticated (or anonymous) user can read/write the entire database. After expiry, rules revert to deny-all — the risk window is the pre-expiry period when developers build and ship to production without restricting rules, not after expiry. Developers who manually set permissive rules (`".read": true, ".write": true`) without an expiry face permanent exposure | Firebase project with permissive security rules during test mode window or manually set `".read": true, ".write": true`; anonymous authentication enabled |

---

## §12. Summary: Core Principles

**The fundamental property that makes the JWT attack surface so expansive is the dual nature of the token as both a carrier of data and an instruction set for its own verification.** The JWT header is attacker-controlled yet dictates critical security decisions — which algorithm to use, where to find the verification key, how to interpret the payload. This inversion of control (the message instructing the verifier how to verify it) is the root cause of the entire §1 (algorithm manipulation) and §2 (header parameter injection) attack families. Few other common authentication mechanisms give the client this level of influence over the verification process (though SAML's XML-based structure creates a comparable attacker-influenced verification surface — see `saml.md`).

**Incremental fixes fail because the attack surface is combinatorial.** Fixing `alg: none` doesn't prevent algorithm confusion. Fixing algorithm confusion doesn't prevent `kid` injection. Fixing `kid` injection doesn't prevent `jku` SSRF. Each mutation target (§1–§7) is independently exploitable, and combinations create novel attack chains (e.g., `jku` bypass + algorithm confusion + claim manipulation). Libraries must implement a "deny-by-default" posture across *all* header parameters simultaneously, which many fail to do — evidenced by recurring CVEs across different libraries year after year (2015 through 2026).

**The structural solution requires four architectural principles:** (1) **Server-side algorithm pinning** — never read the algorithm from the token; configure it at the application level. (2) **Closed key resolution** — never fetch, embed, or dynamically resolve keys from token headers; use a pre-configured, immutable key store. (3) **Explicit token type enforcement** — always enforce whether JWS or JWE is expected; never use a unified decode() interface that auto-detects token type. The sign/encrypt confusion and polyglot token attacks (§7-1) demonstrate that collapsing signing and encryption into a single code path converts a proof-of-authenticity check into a mere decryption check, which anyone with the public key can pass. (4) **Stateful lifecycle management** — accept that purely stateless JWTs cannot support revocation, replay prevention, or session binding; augment with server-side state (token blacklists, refresh token rotation, `jti` tracking) for any use case requiring these properties. The PBES2 billion hashes DoS (§3-4) and compression decompression abuse (§3-5) underscore protocol-level gaps: RFC 7518 defines `p2c` as a positive integer and recommends a minimum of 1000 but sets no upper bound, leaving the door open for attacker-controlled iteration counts; similarly, the `zip` parameter enables decompression bombs with no specified size limit, and some implementations incorrectly accept `zip` in JWS despite it being defined only for JWE. The serialization format confusion (§7-5) adds another dimension: libraries that accept JSON-serialized JWS alongside Compact format enable claim extraction/verification mismatches exploited in real-world systems like Kubernetes. However, adding an upper-bound check on `p2c` and decompressed payload size is fully standards-compliant — the RFCs do not prohibit it — and affected libraries have in fact shipped such fixes without deviating from the specification.

---


---

## References

- [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7518: JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [PortSwigger Web Security Academy: JWT Attacks](https://portswigger.net/web-security/jwt)
- [Auth0: Critical Vulnerabilities in JSON Web Token Libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [PentesterLab: The Ultimate Guide to JWT Vulnerabilities and Attacks](https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide)
- [HackTricks: JWT Vulnerabilities](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
- [OWASP WSTG: Testing JSON Web Tokens](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)
- [Red Sentry: JWT Vulnerabilities List 2026](https://redsentry.com/resources/blog/jwt-vulnerabilities-list-2026-security-risks-mitigation-guide)
- [TrustedSec: Keys to JWT Assessments](https://trustedsec.com/blog/keys-to-jwt-assessments-from-a-cheat-sheet-to-a-deep-dive)
- [Wallarm: 340 Weak JWT Secrets](https://lab.wallarm.com/340-weak-jwt-secrets-you-should-check-in-your-code/)
- [Intigriti: Exploiting JWT Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-jwt-vulnerabilities)
- [Akamai: Analyzing Broken User Authentication Threats to JWT](https://www.akamai.com/blog/security-research/owasp-authentication-threats-for-json-web-token)
- [PentesterLab: claimed CVE-2026-23993 HarbourJwt Unknown Algorithm JWT Bypass](https://pentesterlab.com/blog/cve-2026-23993-harbourjwt-unknown-alg-jwt-bypass)
- [JFrog: CVE-2022-21449 "Psychic Signatures" Analysis](https://jfrog.com/blog/cve-2022-21449-psychic-signatures-analyzing-the-new-java-crypto-vulnerability/)
- [Traceable AI: JWTs Under the Microscope](https://www.traceable.ai/blog-post/jwts-under-the-microscope-how-attackers-exploit-authentication-and-authorization-weaknesses)
- [Tom Tervoort (Secura): Three New Attacks Against JSON Web Tokens (BlackHat US 2023)](https://i.blackhat.com/BH-US-23/Presentations/US-23-Tervoort-Three-New-Attacks-Against-JSON-Web-Tokens.pdf)
- [Authlib security documentation listing CVE-2022-39174](https://docs.authlib.org/en/v1.3.0/community/security.html)
- [JWCrypto documentation for the expected-token-type fix associated with CVE-2022-3102](https://jwcrypto.readthedocs.io/en/v1.4.0/jwt.html)
- [Trail of Bits: Out of the kernel, into the tokens](https://blog.trailofbits.com/2024/03/08/out-of-the-kernel-into-the-tokens/)
- [Yang et al. (Tsinghua): Token Time Bomb: Evaluating JWT Implementations for Vulnerability Discovery (NDSS 2026)](https://dx.doi.org/10.14722/ndss.2026.240697)
