# JSON Web Token (JWT) Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire JWT attack surface under three orthogonal axes. **Axis 1 (Mutation Target)** is the primary structural axis — it defines *what component of the JWT mechanism is being mutated*. **Axis 2 (Discrepancy Type)** is the cross-cutting axis — it explains *what kind of mismatch or bypass the mutation creates*. **Axis 3 (Attack Scenario)** is the mapping axis — it connects mutations to *real-world impact*.

JWT (RFC 7519) is a compact, URL-safe token format consisting of three Base64url-encoded segments: **Header** (algorithm and token metadata), **Payload** (claims), and **Signature** (cryptographic proof of integrity). The security model depends entirely on the verifier correctly enforcing algorithm selection, key binding, signature validation, and claim semantics. Every mutation in this taxonomy exploits a failure in one or more of these trust links — the gap between what the token *declares* about itself and what the verifier *enforces*.

### Axis 2: Discrepancy Types (Cross-Cutting)

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D1** | Algorithm Confusion | Verifier uses a different algorithm or key type than intended by the issuer |
| **D2** | Signature Bypass | Token is accepted without valid cryptographic proof of integrity |
| **D3** | Validation Omission | A required verification step (claim check, key binding, expiration) is missing or incomplete |
| **D4** | Key Trust Confusion | Verifier trusts a key from an unverified or attacker-controlled source |
| **D5** | Claim Semantic Mismatch | Claim values are interpreted differently by issuer, verifier, or downstream consumers |
| **D6** | Injection / Escalation | Attacker-controlled input in header or payload triggers unintended server-side behavior |
| **D7** | Cryptographic Weakness | Weak key material, flawed curve validation, or exploitable mathematical properties |
| **D8** | Protocol-Level Gap | Structural omission in the JWT/JOSE specification itself enables attack |
| **D9** | Transport / Binding Gap | Token leaks or is reusable due to missing transport-layer protection or sender constraint |

---

## §1. Signature Algorithm Manipulation

JWT's most distinctive (and dangerous) design property is that the token itself declares which algorithm the verifier should use via the `alg` header parameter. When verifiers trust this declaration without server-side enforcement, the entire signature model collapses.

### §1-1. Algorithm Switching (Asymmetric → Symmetric)

The foundational JWT attack. When a server is configured to verify tokens with an RSA or ECDSA public key, an attacker changes the `alg` header from an asymmetric algorithm to a symmetric one and signs with the public key as the HMAC secret.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **RS256→HS256 downgrade** | Change `alg` from RS256 to HS256. Use the server's RSA public key (freely available) as the HMAC secret to compute a valid HS256 signature over attacker-modified claims | D1 | Library uses a single, algorithm-agnostic verification function that trusts the `alg` header; public key is accessible (e.g., via JWKS endpoint, `/jwks.json`, or certificate) |
| **ES256→HS256 downgrade** | Same principle applied to ECDSA-configured servers. The EC public key bytes are used as the HMAC secret | D1 | Library does not enforce algorithm-key type binding |
| **PS256→HS256 downgrade** | RSA-PSS to HMAC confusion, exploiting the same public key reuse vector | D1 | Library treats all algorithms interchangeably |
| **Unsafe default algorithm** | Library defaults to HS256 verification when the configured algorithm does not match the token's `alg` header, rather than rejecting the token. Attacker signs with any known or guessable HS256 secret | D1, D3 | Library falls back to a default algorithm instead of failing closed (CVE-2026-22817, Hono JWT middleware) |

### §1-2. `none` Algorithm Bypass

The JWT specification defines `alg: "none"` for unsecured tokens where integrity is verified by other means. When libraries accept this value in production, any token can be forged without any key material.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Direct `none`** | Set `alg` to `"none"` and remove the signature segment (or leave it empty). Library accepts the token as valid without signature verification | D2 | Library does not reject `alg: none` in production configuration |
| **Case variation bypass** | Use `"None"`, `"NONE"`, `"nOnE"`, or other case variants to bypass string-exact blocklists that only check for lowercase `"none"` | D2 | Blocklist uses case-sensitive comparison |
| **Whitespace / encoding bypass** | Inject whitespace, null bytes, or URL-encoded variants (`"none%20"`, `"none\x00"`) into the algorithm string to bypass filters while still being interpreted as `none` by the parser | D2 | Parser normalizes or trims the algorithm string after blocklist check |
| **Empty signature acceptance** | Provide a valid algorithm in the header (e.g., RS256) but submit an empty or truncated signature. Some libraries skip verification when the signature segment is empty rather than raising an error | D2, D3 | Library does not enforce that a non-empty signature exists for non-`none` algorithms |

### §1-3. ECDSA Signature Exploits

Elliptic Curve Digital Signature Algorithm (ECDSA) introduces mathematically specific vulnerabilities beyond algorithm confusion — particularly around signature format, curve validation, and degenerate values.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Psychic Signature (degenerate ECDSA)** | Submit an ECDSA signature where both `r` and `s` components are zero (or other degenerate values). Flawed implementations that do not validate these components accept the signature as valid for *any* payload | D7 | Implementation does not verify that `r` and `s` are in the valid range [1, n-1] (CVE-2022-21449, Java 15–18) |
| **Invalid curve attack** | Supply a public key on a weak elliptic curve (with a small subgroup order) instead of the expected curve. The verifier performs ECDH or ECDSA operations on the weak curve, allowing the attacker to recover the private key through repeated queries | D7 | Library does not validate that the supplied key lies on the expected curve |
| **Signature malleability** | ECDSA signatures have an inherent malleability: for any valid signature `(r, s)`, `(r, n-s)` is also valid. While not directly exploitable for forgery, it breaks systems that use JWT signatures as unique identifiers or cache keys | D7 | Application uses the raw signature value for deduplication or replay detection |

### §1-4. EdDSA-Specific Vulnerabilities

EdDSA (Ed25519, Ed448) is increasingly adopted for JWT signing via RFC 8037/8812. Its Edwards curve mathematics introduce unique attack surfaces distinct from ECDSA.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Cofactor confusion** | Ed25519 has a cofactor of 8, meaning the group order is not prime. Implementations that do not perform cofactor multiplication during verification may accept signatures from keys in small subgroups, analogous to the ECDSA invalid curve attack but specific to Edwards curve cofactor structure | D7 | Implementation does not perform cofactored verification |
| **EdDSA curve ambiguity (`alg: "EdDSA"`)** | The JWT `alg` value `"EdDSA"` does not specify which Edwards curve is used — the curve must be inferred from the key's `crv` parameter (`"Ed25519"` or `"Ed448"`). If a library does not validate that the key's curve matches what the verifier expects, a token signed with one curve may be verified against a key for a different curve | D1, D7 | Library does not enforce curve-algorithm binding; `crv` parameter not validated |
| **Non-canonical signature acceptance (S-malleability)** | Ed25519 signatures have a canonical form, but some implementations accept non-canonical signatures where the S component is not reduced modulo the group order. While not enabling forgery, this creates signature malleability — the same message has multiple valid signature representations | D7 | Application uses raw signature values for deduplication, replay detection, or audit (CVE-2024-34447, Bouncy Castle Ed448 validation) |
| **Batch verification inconsistency** | Some EdDSA implementations support batch verification (verifying multiple signatures simultaneously for performance). Certain batch verification algorithms have weaker security guarantees than individual verification, potentially accepting individually invalid signatures | D7 | Library uses batch verification with weaker guarantees |
| **Ed25519 infinite loop / DoS** | Crafted Ed25519 public keys or signatures can trigger infinite loops or excessive computation in certain implementations | D7 | Flawed point validation in EdDSA implementation (CVE-2024-30172, Bouncy Castle) |

---

## §2. Key Source & Trust Manipulation

JWT header parameters (`jwk`, `jku`, `x5c`, `x5u`, `kid`) instruct the verifier *where to find* or *which key to use* for signature verification. When the verifier trusts these attacker-controlled parameters without restriction, the attacker controls the verification key.

### §2-1. JWK / JKU Injection

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Embedded JWK injection** | Include an attacker's public key directly in the JWT's `jwk` header parameter. Sign the token with the corresponding private key. If the verifier extracts and trusts the embedded key, the attacker has self-signed a valid token | D4 | Library resolves the verification key from the `jwk` header without checking it against a trusted key store (CVE-2025-24976) |
| **JKU URL substitution** | Set the `jku` (JWK Set URL) header to an attacker-controlled server hosting a JWK Set containing the attacker's public key. The verifier fetches and trusts the key | D4 | Library fetches JWKS from the URL in the token header without URL allowlist enforcement |
| **JKU SSRF** | Point `jku` to an internal network address (e.g., `http://169.254.169.254/`, `http://localhost:8080/internal`). The verifier's server-side fetch becomes an SSRF vector, even if the key retrieval itself fails | D4, D6 | Library performs server-side HTTP fetch of the `jku` URL without SSRF protections |
| **JKU open redirect chain** | Point `jku` to a legitimate URL that has an open redirect, bouncing the fetch to the attacker's server. Bypasses domain-based allowlists | D4 | Allowlist checks the initial URL but follows redirects to untrusted destinations |
| **Key ID mismatch (JWK Set)** | Inject a JWK with a `kid` matching a trusted key ID but with different key material. If the verifier matches keys by `kid` without verifying the key material itself, the injected key is used | D4 | Verifier matches `kid` without validating that the key material matches the expected value (CVE-2025-24976) |

### §2-2. X.509 Certificate Chain Injection (x5c / x5u)

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Self-signed x5c injection** | Embed an attacker-generated self-signed X.509 certificate in the `x5c` header parameter. Sign the JWT with the corresponding private key. The verifier extracts the public key from the embedded certificate without validating the certificate chain against a trusted root | D4 | Library trusts any certificate in the `x5c` header without chain validation |
| **x5u URL substitution** | Set `x5u` to an attacker-controlled URL hosting a crafted certificate. The verifier fetches and trusts the certificate | D4 | Library fetches certificates from the `x5u` URL without URL restriction |
| **Intermediate CA injection** | Provide a certificate chain in `x5c` where the leaf certificate is signed by an attacker-controlled intermediate CA. If the verifier only checks that the chain is internally consistent (each cert signs the next) without verifying the root against a pinned trust anchor, the attacker's chain is accepted | D4 | Certificate chain validation does not verify the root CA against a trusted store |

### §2-3. Key ID (`kid`) Exploitation

The `kid` (Key ID) header parameter identifies which key to use for verification. When its value is used unsafely in server-side operations (database queries, file system lookups), it becomes an injection vector.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Path traversal via `kid`** | Set `kid` to a path traversal payload (e.g., `../../../dev/null`, `../../etc/hostname`). The server reads the target file's contents as the verification key. Sign the JWT with that known content (e.g., empty string for `/dev/null`) | D6 | Server uses `kid` value in a filesystem path without sanitization |
| **SQL injection via `kid`** | Inject SQL into the `kid` parameter when it is used in a database query to look up the signing key (e.g., `' UNION SELECT 'attacker-controlled-secret' --`). The query returns the attacker's chosen key | D6 | Server interpolates `kid` into SQL without parameterization |
| **Command injection via `kid`** | Inject OS commands into `kid` when it is passed to a shell command (e.g., for key retrieval via external process) | D6 | Server passes `kid` to a shell command without sanitization |
| **LDAP injection via `kid`** | Inject LDAP filter syntax into `kid` when keys are stored in a directory service | D6 | Server uses `kid` in LDAP queries without escaping |
| **Null/empty `kid`** | Set `kid` to an empty string or null. Some implementations fall back to a default key or skip key lookup entirely, potentially using a weaker key or no key | D3 | Implementation has an insecure fallback for missing/empty `kid` |

### §2-4. JWKS Infrastructure Attacks

Distinct from header-based key injection (§2-1–§2-3), these attacks target the key distribution infrastructure that verifiers rely on — even when token-level key source parameters (`jwk`, `jku`, `x5c`, `x5u`) are correctly ignored.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **DNS poisoning of JWKS endpoint** | Poison DNS resolution for the JWKS endpoint hostname (e.g., `login.example.com/.well-known/jwks.json`). The verifier's background JWKS fetch resolves to an attacker-controlled IP serving a malicious JWKS containing attacker's public key | D4, D9 | DNS cache is poisonable (no DNSSEC, vulnerable resolver); JWKS endpoint domain lacks DNSSEC |
| **HTTP response cache poisoning** | Inject a malicious JWKS response into an intermediate HTTP cache (CDN, reverse proxy) by exploiting cache key normalization differences (Host header variations, query parameter ordering, HTTP method confusion). All verifiers behind the cache receive attacker-controlled keys | D4 | JWKS endpoint served through a caching layer with exploitable cache key logic |
| **TOCTOU key substitution** | Between the moment the JWKS is fetched and the moment it is used for verification, the legitimate JWKS endpoint is compromised or DNS is poisoned. Tokens verified against the poisoned cache appear valid for the full cache TTL | D4 | Long JWKS cache TTL; no integrity verification beyond HTTPS |
| **Unknown `kid` flooding** | Submit tokens with random, non-existent `kid` values. If the verifier's JWKS refresh logic fetches from the remote endpoint whenever a `kid` is not found in cache, each unique `kid` triggers a new HTTP request to the JWKS endpoint, potentially overwhelming it or the verifier itself | D4, D6 | Verifier refreshes JWKS on every cache miss without rate limiting |
| **JWKS endpoint availability attack** | DDoS the JWKS endpoint so verifiers cannot refresh their key cache. Combined with an expiring cache entry, this forces verifiers into either rejecting all tokens (DoS) or continuing to use stale cached keys (which may be compromised) | D4 | No fallback mechanism for JWKS unavailability; no local key pinning |
| **Unsigned JWKS exploitation** | JWKS endpoints serve plain JSON over HTTPS. If TLS is terminated at a load balancer and the internal fetch is over HTTP, or if certificate validation is disabled in development and not re-enabled in production, the JWKS response can be modified in transit | D4 | Insecure internal JWKS fetch configuration; missing TLS certificate validation |

### §2-5. JWK Thumbprint Attacks

RFC 7638 defines a method for computing a deterministic hash of a JWK's essential members. Thumbprints are used for key identification and proof-of-possession binding (DPoP, mTLS).

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Thumbprint algorithm weakness** | If SHA-1 is used for thumbprint computation (some implementations default to it), collision attacks become feasible. Two different JWKs with the same SHA-1 thumbprint enable key substitution | D7 | Thumbprint uses SHA-1 instead of SHA-256 |
| **Partial member inclusion** | RFC 7638 specifies that only the "required" members of the JWK are included in thumbprint computation (e.g., for RSA: `e`, `kty`, `n`). An attacker creates a JWK with identical required members but different optional members (like `kid`, `key_ops`, or `use`), producing the same thumbprint but different operational behavior | D4, D5 | Verifier matches by thumbprint without checking all key properties |
| **DPoP `cnf` thumbprint bypass** | In DPoP (RFC 9449), the access token's `cnf` claim contains a JWK thumbprint (`jkt`). If the thumbprint comparison is vulnerable (truncation, algorithm confusion, or collision), an attacker can create a different key pair that produces the same thumbprint, bypassing sender constraint | D4, D9 | Weak or truncated thumbprint comparison in DPoP validation |
| **JSON serialization differential** | JWK thumbprint computation requires deterministic JSON serialization (sorted keys, no whitespace). If issuer and verifier serialize differently (key member ordering, Unicode escaping), the same logical key produces different thumbprints, causing lookup failures or mismatches | D5 | Inconsistent JSON canonicalization between components |

---

## §3. Weak Key Material & Brute Force

Even when algorithm enforcement and key source validation are correct, weak key material undermines the entire cryptographic guarantee.

### §3-1. HMAC Secret Weakness

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Dictionary brute force** | Capture a valid JWT and use offline tools (hashcat mode 16500, jwt_tool) to test candidate secrets against the signature. Common secrets (`secret`, `password`, `123456`, application names) are cracked in seconds | D7 | HMAC secret is a short, predictable, or dictionary-derivable string |
| **Short key brute force** | Exhaustively enumerate all possible keys up to a given length. HS256 with a 4-character secret requires testing only ~4 billion candidates | D7 | Secret is shorter than the recommended minimum (256 bits for HS256) |
| **Default/hardcoded secret** | Application ships with or falls back to a hardcoded secret (`changeme`, `jwt-secret`, framework defaults). Attacker reads the secret from source code, documentation, or default configuration | D7 | Secret is not changed from the default value |
| **Shared secret across environments** | Same HMAC secret used across development, staging, and production. A compromise in any lower environment reveals the production secret | D7 | No per-environment key rotation |
| **Public key derivation from signatures** | Given two or more JWTs signed with the same RSA key, it is mathematically possible to derive the public key from the signatures alone. This enables algorithm confusion attacks (§1-1) even when the public key is not explicitly published | D7, D1 | Attacker has two or more tokens signed with the same RSA key |

### §3-2. Asymmetric Key Weakness

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Short RSA key** | RSA keys shorter than 2048 bits can be factored with modern resources, allowing private key recovery and token forgery | D7 | RSA key is ≤1024 bits |
| **Leaked private key** | Private key exposed via source code repository, misconfigured server, debug endpoint, or backup file | D7 | Operational security failure in key management |
| **Key confusion across formats** | Libraries that accept multiple key formats (PEM, JWK, OpenSSH) may misinterpret key material. An OpenSSH ECDSA public key interpreted as a different format can lead to algorithm confusion or verification bypass | D1, D7 | Library auto-detects key format without strict type checking (python-jose issue #346) |
| **Non-rotation of compromised keys** | After a key compromise, the old key remains trusted during an excessively long rotation window, allowing continued forgery | D3 | No mechanism for rapid key revocation; long JWKS cache TTLs |

---

## §4. Claim Validation Bypass

JWT claims (`iss`, `aud`, `exp`, `nbf`, `sub`, `jti`, and custom claims) define the token's authorization context. Failures in how these claims are validated — or whether they are validated at all — create impersonation and escalation vectors.

### §4-1. Temporal Claim Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Expiration bypass (`exp`)** | Modify the `exp` claim to a far-future timestamp, extending token validity indefinitely. Effective when combined with any signature bypass (§1, §2) | D5 | Signature is bypassed; or verifier does not check `exp` |
| **Not-before bypass (`nbf`)** | Set `nbf` to a past timestamp or remove it entirely. Combined with pre-signed future-dated tokens, enables immediate use of tokens intended for later activation | D5, D3 | Verifier does not enforce `nbf` |
| **"Back to the Future" attack** | RFC 7519 does not mandate freshness mechanisms (nonces). An attacker with temporary access to a signing key can pre-generate tokens with future `exp`/`nbf` values. These tokens become valid when the future timestamp arrives, enabling persistent access long after the key compromise is remediated | D8 | No nonce or jti-based freshness enforcement; tokens are self-contained with no server-side revocation check |
| **Clock skew exploitation** | Exploit generous clock skew tolerances (sometimes 5+ minutes) configured to handle distributed system time differences. Submit tokens that are technically expired but within the skew window | D5 | Excessive clock skew tolerance configured |

### §4-2. Identity & Authorization Claim Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Audience confusion (`aud`)** | Token issued for Service A is presented to Service B. If Service B does not verify that its own identifier appears in the `aud` claim, the token is accepted. Particularly dangerous in multi-service SSO ecosystems sharing the same IdP | D3, D5 | Service does not validate `aud` matches its own identifier (CVE-2025-27371) |
| **Issuer confusion (`iss`)** | Submit a token from a different (attacker-controlled) issuer. If the verifier does not check `iss` against an allowlist, or if the `iss` validation is flawed (partial matching, array confusion), tokens from rogue issuers are accepted | D3, D5 | Verifier does not validate `iss`; or uses partial string matching (CVE-2024-53861, CVE-2025-30144) |
| **Issuer array confusion** | Provide `iss` as an array (`["https://attacker.com", "https://legit.com"]`) instead of a string. Libraries that check if the expected issuer is *contained in* the claim (rather than *equal to*) accept the token because the legitimate issuer appears in the array | D5 | Library treats `iss` as an array and uses `includes()` logic (CVE-2025-30144, fast-jwt) |
| **Subject (`sub`) substitution** | Modify the `sub` claim to impersonate a different user. Trivial when signature verification is bypassed, but also effective when `sub` is not validated against the authentication context | D5, D6 | Combined with any signature bypass; or `sub` is not cross-checked with the authenticated session |
| **Nested claim manipulation** | Modify deeply nested JSON objects within custom claims (e.g., `{"user": {"role": "admin", "permissions": ["*"]}}`) when signature verification is bypassed or absent | D5, D6 | Custom claims carry authorization data; combined with signature bypass |
| **Role / group claim injection** | Inject or elevate role/group claims (`role`, `groups`, `scope`, `authorities`) to gain administrative privileges | D6 | Application derives authorization directly from JWT claims without cross-referencing an authoritative source |
| **Scope escalation** | Modify the `scope` claim in an OAuth access token JWT to include additional permissions not originally granted (e.g., `openid profile` → `openid profile admin:write`) | D5, D6 | Resource server reads scope from the JWT payload without cross-referencing the authorization grant |

### §4-3. Subject Identifier & Claim Semantic Confusion

In federated identity systems (OpenID Connect, SAML-to-OIDC bridges), claim values — particularly `sub` — frequently contain URIs, emails, or structured identifiers. Parsing and comparison inconsistencies create identity confusion.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **`sub` URL normalization mismatch** | Two URLs that are semantically equivalent but syntactically different are treated as different identities (or vice versa): `https://idp.example/users/123` vs `https://idp.example/users/123/` vs `https://IDP.EXAMPLE/users/123` | D5 | Application compares `sub` values with inconsistent URL normalization |
| **`sub` userinfo authority confusion** | The URL authority component `user@host` can confuse parsers: `https://legitimate-idp.com@attacker.com/users/123` — some parsers treat `attacker.com` as the host | D5, D6 | `sub` URL parsed without proper authority validation |
| **Cross-IdP `sub` collision** | When a service accepts tokens from multiple identity providers, different IdPs may issue tokens with identical `sub` values (both using `"sub": "user123"`). Without pairing `sub` with `iss`, cross-IdP impersonation occurs | D3, D5 | Service does not pair `sub` with `iss` for identity uniqueness |
| **Email claim homoglyph confusion** | `email` claim containing Unicode homoglyphs (e.g., `аdmin@example.com` using Cyrillic 'а') treated as identical to `admin@example.com` by some systems and different by others | D5 | No Unicode normalization applied consistently across identity chain |
| **`sub` percent-encoding differential** | `https://idp.example/users/John%20Doe` vs `https://idp.example/users/John Doe` — decoded vs encoded forms compared differently by different components | D5 | Inconsistent URL decoding in claim comparison |

### §4-4. Token Replay & Lifecycle Abuse

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Missing `jti` replay** | Capture a valid JWT and replay it within its validity window. Without a `jti` (JWT ID) claim and server-side tracking of consumed tokens, the same token can be used unlimited times | D3, D8 | No `jti` claim; no server-side token consumption tracking |
| **Refresh token abuse** | Steal a long-lived refresh token (often a JWT itself) and continuously generate new access tokens, maintaining persistent access even after password changes | D3 | Refresh tokens are not bound to client/device; not revoked on credential change |
| **Token after logout** | JWT remains valid after user logout because JWTs are stateless — there is no server-side session to invalidate. Unless the application maintains a token blocklist or uses short-lived tokens with rotation, the logged-out user's token continues to work | D3 | No token revocation mechanism; long-lived tokens without blocklist |
| **Cross-context token reuse** | Token issued for one API endpoint, service, or client is reused against a different one that shares the same verification key but does not validate `aud` or `azp` claims | D3, D5 | Shared signing keys across services without audience restriction |

---

## §5. Header Parameter Abuse & Content Type Confusion

Beyond the `alg` parameter (§1) and key source parameters (§2), JWT headers contain additional fields that, when mishandled, enable injection and processing confusion.

### §5-1. Content Type (`cty`) Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Deserialization via `cty`** | Inject `cty: "application/x-java-serialized-object"` into the JWT header. If the underlying processing library respects this content type and attempts to deserialize the payload accordingly, it triggers Java deserialization vulnerabilities | D6 | Library uses `cty` header to determine payload deserialization strategy; combined with signature bypass |
| **XXE via `cty`** | Set `cty: "text/xml"` or `cty: "application/xml"`. If the library processes the payload as XML based on this header, an XXE payload in the token body can trigger external entity expansion | D6 | Library respects `cty` for payload parsing; XML parsing with external entities enabled |
| **Nested JWT confusion** | Set `cty: "JWT"` to indicate nested JWT processing. Craft an inner JWT with different (weaker) security properties. The verifier may apply signature checks only to the outer JWT, processing the inner JWT's claims without independent verification | D3, D5 | Library recursively processes nested JWTs without enforcing consistent security properties at each level |

### §5-2. Type (`typ`) Header Confusion

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Missing `typ` validation** | RFC 8725 recommends explicit `typ` checking to prevent cross-token confusion (e.g., using an access token JWT as an ID token). Without this check, tokens intended for one purpose are accepted in a different context | D3, D5 | Application does not validate the `typ` header parameter |
| **`typ` spoofing** | Modify the `typ` header to match the expected value of a different token consumer, enabling cross-context token acceptance | D5 | Multiple systems share keys but expect different `typ` values |

### §5-3. Critical (`crit`) Header Bypass

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Ignoring `crit` extensions** | The `crit` header parameter lists header fields that the verifier MUST understand and process. If a verifier ignores `crit`, it may skip mandatory security checks defined by custom extensions | D3 | Library does not implement `crit` header processing per RFC 7515 §4.1.11 |

### §5-4. JWS JSON Serialization Attacks

The existing taxonomy implicitly assumes JWS Compact Serialization (`header.payload.signature`). RFC 7515 also defines a JSON Serialization format — a JSON object with `payload`, `signatures` (array), each containing `protected`, `header`, and `signature` fields. This format introduces distinct attack surfaces.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Format confusion** | A library that accepts both serialization formats may apply different validation logic to each. The JSON Serialization path may be less tested and contain bypasses not present in the Compact Serialization path | D3 | Library accepts both formats without consistent validation |
| **Unprotected header injection** | The JSON Serialization distinguishes between "protected" headers (Base64url-encoded, covered by signature) and "unprotected" headers (plain JSON, NOT covered by signature). An attacker can inject or modify unprotected header parameters (including `kid`, `jku`, `jwk`) without invalidating the signature | D2, D6 | Verifier reads key selection parameters from unprotected headers |
| **Multiple signatures exploitation** | JSON Serialization supports multiple signatures over the same payload. An attacker includes both a legitimate signature (copied from a valid token) and a forged signature with a different protected header (e.g., `alg: none` or attacker-controlled key). If the verifier checks any-of rather than all-of, the forged path is used | D2, D3 | Verifier accepts token if *any* signature is valid rather than requiring *all* |
| **Flattened vs. general confusion** | JSON Serialization has two sub-forms: "General" (array of signatures) and "Flattened" (single signature as direct fields). Parsing differences between these forms can lead to bypasses when one form is validated differently than the other | D3 | Inconsistent handling of general vs. flattened JSON serialization |

---

## §6. JWE (Encrypted JWT) Exploitation

JSON Web Encryption (JWE, RFC 7516) provides confidentiality for JWT payloads. Its additional complexity introduces encryption-specific attack surfaces beyond those of JWS (signed-only) tokens.

### §6-1. JWE Algorithm & Encryption Attacks

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Key agreement invalid curve attack** | When JWE uses ECDH-ES key agreement, supply a public key on a weak elliptic curve with small subgroup order. The server performs ECDH on the weak curve, leaking partial information about its private key. Repeated queries recover the full key | D7 | Library does not validate that the ephemeral public key in the JWE header lies on the expected curve |
| **AEAD oracle (CBC/PKCS5 padding)** | When JWE uses AES-CBC with PKCS5 padding (`A128CBC-HS256`), error messages distinguishing padding errors from decryption errors become a Bleichenbacher-style oracle, enabling plaintext recovery | D7 | Server returns distinguishable errors for different decryption failure modes |
| **Compression bomb (JWE DEF)** | Craft a JWE payload with extreme compression ratio using the "DEF" (DEFLATE) compression algorithm. Upon decryption and decompression, the payload expands to gigabytes, causing denial of service via memory exhaustion | D6 | Library processes `zip: "DEF"` without limiting decompressed output size |
| **Encryption algorithm downgrade** | Modify the JWE `enc` header to specify a weaker encryption algorithm. If the verifier does not enforce the expected encryption algorithm, the weakened encryption may be breakable | D1, D3 | Verifier trusts the `enc` header value rather than enforcing server-side configuration |

### §6-2. Encrypted-then-Signed vs. Signed-then-Encrypted Confusion

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Sign/encrypt order confusion** | Application expects sign-then-encrypt (the secure order for most use cases) but accepts encrypt-then-sign tokens. An attacker who can decrypt (e.g., because the encryption key is a public key in RSA-OAEP) can modify claims before re-encrypting, and the outer signature covers the modified ciphertext | D3 | Application does not enforce the expected nesting order |
| **Encrypted assertion bypass** | Server expects encrypted JWTs but falls back to processing unencrypted JWTs when decryption fails, allowing an attacker to submit plaintext tokens | D3 | Server does not enforce mandatory encryption (cf. CVE-2024-4985 in SSO context) |

---

## §7. Library & Implementation-Specific Vulnerabilities

Beyond protocol-level design issues, individual JWT library implementations introduce their own vulnerability classes through parsing quirks, type handling, and API design.

### §7-1. API Design Flaws

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Algorithm-agnostic verify function** | Library provides a single `verify(token, key)` function that auto-detects the algorithm from the token header. This is the root cause of algorithm confusion (§1-1): the function accepts any algorithm the token specifies | D1 | Library API does not require explicit algorithm specification at the call site |
| **Permissive default configuration** | Library ships with insecure defaults: `alg: none` accepted, no algorithm whitelist, no claim validation enabled by default | D3 | Developer uses library defaults without hardening |
| **Decode vs. Verify confusion** | Library offers both `decode()` (no signature check) and `verify()` (with signature check) functions. Developers use `decode()` for accessing claims, inadvertently trusting unverified tokens | D2, D3 | Developer calls `decode()` instead of `verify()` for security-sensitive operations |
| **Prototype pollution via `secretOrPublicKey`** | In Node.js JWT libraries, if the `secretOrPublicKey` parameter is derived from user-controlled input and the prototype chain is polluted (e.g., `Object.prototype.algorithm = "none"`), the verification function may inherit attacker-controlled configuration | D6, D2 | Library reads options from prototype chain; `secretOrPublicKey` object is pollutable (CVE-2022-23529, jsonwebtoken) |

### §7-2. Parser & Type Handling Quirks

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **JSON type confusion** | JWT claims are JSON — integers, strings, arrays, and objects are all valid claim values. A library expecting `"iss": "string"` may behave unexpectedly when given `"iss": ["array"]`, `"iss": 12345`, or `"iss": {"nested": "object"}` | D5 | Library does not enforce JSON schema on claims (CVE-2025-30144) |
| **Base64 padding tolerance** | JWT segments should be Base64url-encoded without padding. Some libraries accept standard Base64 (with `+`, `/`, `=`) or tolerate extra padding, enabling differential parsing between components | D5 | Different parsing behaviors between signature verification and claim extraction |
| **Unicode normalization differential** | Claim values containing Unicode (e.g., email addresses with homoglyphs) may be normalized differently by the JWT library and the downstream application, enabling identity confusion | D5 | No Unicode normalization applied consistently |
| **Large number handling** | JSON numeric claims (like `exp`) may overflow or lose precision in languages with limited integer types (JavaScript's 53-bit integer limit), potentially causing tokens to be treated as never-expiring | D5 | `exp` value exceeds the language's safe integer range |

### §7-3. Prototype Pollution via JWT Claims

JWT payloads are JSON objects. In JavaScript/Node.js environments, when decoded JWT claims are merged into application objects, keys like `__proto__`, `constructor.prototype`, or `prototype` pollute the global Object prototype.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Direct `__proto__` pollution** | JWT payload contains `{"__proto__": {"isAdmin": true}}`. When merged via `Object.assign()`, spread operators, or deep-merge utilities into application context, every object in the runtime inherits `isAdmin: true` | D6 | Application merges decoded JWT claims into objects without sanitizing prototype-polluting keys |
| **`constructor.prototype` pollution** | JWT contains `{"constructor": {"prototype": {"role": "admin"}}}`. Bypasses `__proto__`-specific sanitization by using the `constructor` chain | D6 | Sanitizer only blocks `__proto__` but not `constructor.prototype` |
| **Deep-merge library exploitation** | JWT claims processed through vulnerable deep-merge libraries (lodash `_.merge`, jQuery `$.extend`, hoek `merge`) enable prototype pollution even when the JWT library itself is safe | D6 | Application uses a deep-merge utility on decoded claims (CVE-2018-3721 lodash, CVE-2018-16487 lodash) |
| **Claim-to-template injection** | Polluted prototype values (`__proto__.template`, `__proto__.sourceURL`) are picked up by template engines (Pug, Handlebars, EJS), converting prototype pollution into server-side template injection (SSTI) and RCE | D6 | Template engine reads from prototype chain; combined with claim pollution |

### §7-4. Timing Side-Channel Attacks

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Non-constant-time HMAC comparison** | Signature comparison for HMAC-signed JWTs uses standard string comparison (`==`, `===`, `strcmp`) rather than a constant-time comparison function. The comparison short-circuits on the first differing byte. By measuring response times across many requests, an attacker can determine the correct signature byte-by-byte | D7 | Library uses non-constant-time comparison for HMAC signatures |
| **RSA verification timing (Bleichenbacher)** | Variable-time modular exponentiation during RSA signature verification or JWE RSA key unwrapping can leak information about the private key through timing measurements | D7 | Library uses non-constant-time RSA operations (CVE-2024-30171, Bouncy Castle RSA timing; CVE-2023-50782, Python cryptography RSA PKCS#1 v1.5) |
| **Claim validation timing** | If the verifier checks claims sequentially and returns as soon as one fails, timing differences reveal which claim caused rejection, leaking information about expected `iss`, `aud`, or other claim values | D3 | Verifier returns early on first claim validation failure |
| **Key lookup timing** | When the verifier looks up the signing key by `kid`, timing differences between "kid found" and "kid not found" reveal valid key identifiers | D3 | Key lookup does not use constant-time comparison or uniform response timing |

### §7-5. Denial of Service via JWT Parsing

Beyond the JWE compression bomb (§6-1), JWT parsing itself introduces multiple DoS vectors.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Deeply nested JSON payload** | JWT payload with extreme JSON nesting depth (e.g., 10,000+ levels of `{"a":{"a":{"a":...}}}`) causes stack overflow in recursive JSON parsers | D6 | No JSON nesting depth limit in parser |
| **Hash collision DoS on JSON parser** | Craft JWT claim keys that produce hash collisions in the JSON parser's internal hash table. Degrades hash table lookup from O(1) to O(n), turning JSON parsing into a quadratic-time operation | D6 | Language/parser does not use randomized hashing (e.g., older Python, PHP, certain Java versions) |
| **Recursive nested JWT** | `cty: "JWT"` with a payload that is itself a JWT with `cty: "JWT"`, creating arbitrarily deep nested JWT recursion until stack exhaustion | D6, D3 | Library recursively processes nested JWTs without depth limit |
| **JWKS refresh flooding** | Submit tokens with random `kid` values to trigger repeated JWKS endpoint fetches, causing DoS on both the verifier (HTTP request overhead) and the JWKS endpoint (request flooding) | D6 | No rate limiting on JWKS refresh triggered by unknown `kid` |
| **Large Base64url segment** | JWT with an extremely large header or payload segment (megabytes of Base64url data) consumes excessive memory during decoding | D6 | No size limit on JWT segment decoding |
| **ReDoS via claim validation** | If claim validation uses regular expressions (e.g., validating `iss` format, email format), crafted claim values trigger catastrophic backtracking in vulnerable regex patterns | D6 | Claim validation uses non-linear-time regex patterns (CVE-2024-45296, path-to-regexp) |

---

## §8. Transport, Binding & Deployment Vulnerabilities

JWT's security model assumes secure transport and proper token handling, but the specification itself does not enforce these properties. This section covers vulnerabilities arising from how tokens are transmitted, stored, and bound (or not bound) to their intended context.

### §8-1. Token Binding Absence (Bearer Token Problem)

JWTs are bearer tokens — possession alone is sufficient to use them. There is no built-in mechanism to verify that the presenter is the intended recipient. This is an architectural gap distinct from replay (§4-4).

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Stolen token reuse from any context** | An attacker who obtains a JWT via any exfiltration method (XSS, log access, Referer leak, MITM) can use it from any device, any network, any client with no additional proof required | D9, D8 | No sender constraint mechanism (DPoP, mTLS binding) deployed |
| **Missing DPoP enforcement** | Server issues DPoP-bound access tokens (RFC 9449) but does not enforce the DPoP proof on every request, or accepts both bound and unbound tokens | D9, D3 | DPoP proof validation is optional or inconsistently enforced |
| **mTLS binding bypass** | Token bound to client certificate via `cnf.x5t#S256` (RFC 8705) but the resource server does not verify the client certificate matches the token's `cnf` claim | D9, D3 | mTLS certificate-token binding not validated at resource server |
| **Missing token exchange in delegation** | Service A forwards the user's JWT directly to Service B instead of performing OAuth 2.0 Token Exchange (RFC 8693) to obtain a constrained delegated token | D8, D9 | No token exchange infrastructure; direct JWT forwarding between services |

### §8-2. JWT Leakage via Transport & Storage

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Referer header leakage** | JWT passed as URL query parameter (`?token=eyJ...`). When the user navigates to an external link, the full URL including the token is sent in the `Referer` header to the third-party site | D9 | Token transported in URL query parameter; no `Referrer-Policy` header |
| **Browser history / bookmark persistence** | URL-embedded JWTs stored in browser history, autocomplete databases, and browser sync services (Chrome Sync, Firefox Sync), persisting long after the token should have expired | D9 | Token in URL; no mechanism to clear browser history entries |
| **Server/proxy log exposure** | Web server access logs, reverse proxy logs, CDN logs, and WAF logs record the full URL including query-string JWTs | D9 | Token in URL; log retention exceeds token lifetime |
| **WebSocket upgrade URL leakage** | JWTs sent in the WebSocket upgrade request URL (browser WebSocket API does not support custom headers) are logged like any HTTP request | D9 | JWT passed in WebSocket URL due to browser API limitation |
| **localStorage / sessionStorage XSS exposure** | JWTs stored in `localStorage` or `sessionStorage` are accessible to any JavaScript running in the same origin, including XSS payloads | D9 | Token stored in Web Storage; no HttpOnly protection possible |
| **CDN cache key inclusion** | CDN uses the full URL (including JWT query parameter) as a cache key, potentially serving authenticated responses to different users or caching user-specific content | D9, D5 | CDN caching layer does not strip JWT from cache key |

### §8-3. JWT Session Fixation

Analogous to traditional session fixation but applied to JWT-based session management.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Pre-authentication fixation** | Attacker obtains a pre-authentication JWT (e.g., by hitting an anonymous endpoint). Attacker injects this JWT into the victim's browser (via subdomain cookie injection or URL parameter). When the victim authenticates, the application upgrades the existing JWT with authentication claims rather than issuing a new token. The attacker's copy becomes authenticated | D3, D9 | Application upgrades existing JWTs on authentication rather than issuing new tokens |
| **Cross-subdomain cookie injection** | Attacker controls `evil.example.com` and sets a JWT cookie for `.example.com`. The victim's browser sends this attacker-controlled JWT to `app.example.com`. If the application uses this JWT to establish a session, the attacker has fixed the session | D9 | Cookie scoped to parent domain; no cookie prefix (`__Host-`) enforcement |
| **Token upgrade without re-issuance** | Application adds claims to an existing JWT (e.g., after MFA verification) by decoding, modifying, and re-signing, rather than issuing a completely new token. If the attacker obtained the pre-upgrade token, race conditions or caching may allow the old token to remain valid | D3 | Token identity (e.g., `jti`) is preserved across security context changes |

---

## §9. Confused Deputy & Cross-Service Token Misuse

In microservice architectures, JWT tokens cross service boundaries in ways that create confused deputy attacks distinct from simple audience confusion (§4-2). The fundamental problem is that JWT has no built-in mechanism to express delegation chains or constrain forwarding.

### §9-1. Cross-Service Confused Deputy

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Direct forwarding** | Service A forwards the user's JWT as-is to Service B, gaining the user's full permissions at Service B. Service B cannot distinguish "user is directly calling me" from "Service A is calling me on behalf of the user" | D8 | Same signing key / trust domain across services; no delegation token mechanism |
| **Token scope widening** | A JWT with narrow scope (`scope: "read:profile"`) is forwarded to an internal service that only checks the signature, not the scope, effectively granting full access | D3, D5 | Downstream services do not validate `scope` claims |
| **Internal-external token confusion** | Same JWT format and signing key used for external (user-facing) and internal (service-to-service) tokens. An external user's JWT is accepted by internal services that should only accept service-to-service tokens | D5, D3 | No `typ` or custom claim to distinguish token contexts; shared signing keys |
| **Transitive trust escalation** | Service A → Service B → Service C, each hop forwarding the original JWT. Each service may have different permission expectations, but the token carries the original user's full claim set through the entire chain | D8 | No token exchange (RFC 8693) or transaction tokens (draft-ietf-oauth-transaction-tokens) deployed |
| **Mix-up attack** | In OAuth flows with multiple authorization servers, the client is tricked into sending the authorization code or token to the wrong authorization server, which then obtains tokens on behalf of the user | D5, D8 | No issuer identification (RFC 9207) enforced |

---

## §10. SD-JWT (Selective Disclosure JWT) Attack Surface

SD-JWT (draft-ietf-oauth-selective-disclosure-jwt) is a JWT extension where claims are hidden behind salted hashes. The holder selectively discloses individual claims by providing corresponding disclosures (salt + claim name + value). Rapidly gaining adoption in the EU Digital Identity Wallet (EUDI) ecosystem.

### §10-1. SD-JWT Disclosure Attacks

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Missing disclosure hash validation** | Verifier accepts disclosures without checking that their hashes appear in the JWT's `_sd` array. Attacker can inject arbitrary claims as "disclosures" | D3 | Verifier does not validate disclosure-to-hash binding |
| **Disclosure substitution (hash collision)** | Replace a legitimate disclosure with a different one that produces the same hash. Computationally infeasible with SHA-256 but possible with truncated hashes or weak hash algorithms | D7 | SD-JWT uses truncated or weak hash for disclosure binding |
| **Salt reuse across claims** | If the same salt is reused for multiple claims, observing one disclosure reveals the salt, making it possible to brute-force other claim values by computing hashes with the known salt | D7 | Non-random or reused salt generation |
| **Decoy digest manipulation** | SD-JWT allows "decoy" digests (hashes not corresponding to any real claim) to hide the number of claims. If decoy generation is predictable, it leaks information about the actual claim structure | D7 | Decoy digest generation uses weak randomness |

### §10-2. SD-JWT Key Binding Attacks

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Key Binding JWT (KB-JWT) bypass** | SD-JWT includes a Key Binding JWT to prove holder identity. If the verifier does not validate the KB-JWT or does not check that it binds to the correct SD-JWT, an attacker can present stolen disclosures with their own KB-JWT | D3, D9 | Verifier does not validate KB-JWT or its binding to the SD-JWT hash |
| **Missing `sd_hash` verification** | The KB-JWT must contain an `sd_hash` claim binding it to the specific SD-JWT presentation. If this claim is not verified, the KB-JWT can be replayed with different SD-JWT presentations | D3 | `sd_hash` claim in KB-JWT not validated |
| **KB-JWT replay** | A valid KB-JWT is captured and replayed with the same SD-JWT presentation to a different verifier or at a later time. Without nonce or audience binding in the KB-JWT, the replay succeeds | D3 | No `nonce` or `aud` enforcement in KB-JWT |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **Authentication Bypass** | Any service using JWT for authn | §1 + §2 | Forge tokens to authenticate as arbitrary user |
| **Privilege Escalation** | Services deriving authz from claims | §4-2 + §1 | Elevate role/scope claims to admin |
| **Persistent Backdoor** | IoT / long-lived token ecosystems | §4-1 ("Back to the Future") + §3-1 | Pre-generated tokens valid months/years later |
| **Account Takeover** | Applications with JWT session tokens | §3-1 (brute force) + §4-3 (replay) | Full account compromise |
| **SSRF / Server-Side Exploitation** | Services fetching JKU/x5u URLs | §2-1 (JKU SSRF) + §2-2 | Internal network scanning, metadata theft |
| **Injection Chains** | Services with dynamic `kid` lookup | §2-3 (SQLi/path traversal) | RCE, database compromise, file read |
| **Cross-Service Impersonation** | Multi-tenant / multi-service SSO | §4-2 (aud/iss confusion) + §4-3 | Access to unauthorized services |
| **Denial of Service** | JWE-accepting endpoints | §6-1 (compression bomb) + §7-5 (parsing DoS) | Service unavailability |
| **Token Theft & Reuse** | Any bearer-token architecture | §8-1 (binding absence) + §8-2 (transport leakage) | Persistent unauthorized access from any device |
| **Prototype Pollution → RCE** | Node.js microservices | §7-3 (prototype pollution) + SSTI chain | Remote code execution via claim injection |
| **Confused Deputy Escalation** | Microservice architectures | §9-1 (confused deputy) + §4-2 (aud confusion) | Privilege escalation across service boundaries |
| **Identity Wallet Forgery** | EU Digital Identity (EUDI) | §10-1 (SD-JWT disclosure) + §10-2 (KB-JWT bypass) | Forged verifiable credentials |

---

## CVE / Bounty Mapping (2024–2026)

| Mutation Combination | CVE / Case | Product | Impact |
|---------------------|-----------|---------|--------|
| §1-1 (algorithm confusion) | CVE-2024-54150 | cjwt (xmidt-org) | Algorithm confusion allows token forgery |
| §1-1 (unsafe default algorithm) | CVE-2026-22817 | Hono JWT Middleware | HS256 default fallback enables token forgery and auth bypass |
| §1-1 (algorithm confusion) | CVE-2024-37568 | Authlib | Algorithm confusion in JWT validation |
| §1-3 (psychic signature) | CVE-2022-21449 | Java 15–18 (ECDSA) | ECDSA signatures with zero-value `r`/`s` accepted as valid; complete signature bypass |
| §2-1 (JWK key injection) | CVE-2025-24976 | Distribution (container registry) | Key ID match without key material verification enables signing key injection |
| §4-2 (audience confusion) | CVE-2025-27371 | OAuth implementations | JWT audience value ambiguity across services |
| §4-2 (issuer array confusion) | CVE-2025-30144 | fast-jwt ≤5.0.5 | Array `iss` claim bypasses issuer validation |
| §4-2 (issuer partial match) | CVE-2024-53861 | PyJWT | Partial string matching on `iss` claim enables issuer spoofing; DoS via crafted values |
| §3-2 (key format confusion) | python-jose #346 | python-jose | OpenSSH ECDSA key format enables algorithm confusion |
| §6-1 (compression bomb) | GHSA-hj3v-m684-v259 | lestrrat-go/jwx | JWE compression bomb causes DoS via memory exhaustion |
| §6-1 (JWE decompression DoS) | CVE-2024-28176 | jose (npm, panva/jose) | JWE decompression bomb causes memory exhaustion in Node.js |
| §6-1 (JWE decompression DoS) | CVE-2024-28180 | go-jose (Go) | Improper handling of highly compressed JWE data causing DoS |
| §7-3 (prototype pollution) | CVE-2022-23529 | jsonwebtoken (Node.js) < 9.0.0 | Prototype pollution via `secretOrPublicKey` leads to RCE |
| §7-1 (insecure defaults) | CVE-2022-23539 | jsonwebtoken (Node.js) < 9.0.0 | Insecure default algorithm handling allowing weak key types |
| §7-1 (loose validation) | CVE-2022-23540 | jsonwebtoken (Node.js) < 9.0.0 | Loose validation enabling signature bypass |
| §7-1 (kid handling) | CVE-2022-23541 | jsonwebtoken (Node.js) < 9.0.0 | Insecure `kid` header handling |
| §1-4 (EdDSA DoS) | CVE-2024-30172 | Bouncy Castle (Java) | Infinite loop in Ed25519 verification with crafted signatures |
| §1-4 (EdDSA validation) | CVE-2024-34447 | Bouncy Castle (Java) | Improper validation of Ed448 public keys |
| §7-4 (RSA timing) | CVE-2024-30171 | Bouncy Castle (Java) | Timing side-channel in RSA decryption (Bleichenbacher variant) |
| §7-4 (RSA timing) | CVE-2023-50782 | Python cryptography | Bleichenbacher timing side-channel in RSA PKCS#1 v1.5 |
| §7-5 (parsing DoS) | CVE-2024-21319 | Microsoft.IdentityModel (.NET) | DoS via crafted JWT causing excessive CPU consumption |
| §7-1 (validation bypass) | CVE-2024-21643 | Microsoft.IdentityModel (.NET) | JWT validation bypass allowing authentication bypass |
| §9-1 (claim injection) | CVE-2024-47616 | Pomerium | JWT claim injection in authorization context |
| §7-1 (validation bypass) | CVE-2024-52592 | jose2go (.NET) | JWT validation bypass allowing authentication bypass |
| §1-1 (algorithm confusion) | CVE-2025-21535 | Oracle WebLogic Server | Authentication bypass via JWT token manipulation |
| §1-3 (ECDSA malleability) | CVE-2023-46234 | browserify-sign | ECDSA signature validation bypass due to malleability |
| §1-2 (missing signature) | CVE-2020-28042 | jwt-go (Go) | Library accepted tokens with absent signatures |
| §2-1 (JWK trust) | CVE-2018-0114 | node-jose (Cisco) | Embedded JWK key trusted without verification against key store |
| §1-1 + §1-2 (foundational) | CVE-2015-9235 | Multiple JWT libraries | `alg:none` signature bypass across languages |
| §1-1 (key confusion) | CVE-2016-10555 | jsonwebtoken (Node.js) < 4.2.2 | RS256-to-HS256 algorithm confusion |

---

## Detection Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **jwt_tool** | CLI Tool (Python) | Comprehensive JWT attack suite | Algorithm confusion, claim tampering, key brute-force, JWK injection, `kid` injection, signature bypass testing |
| **SignSaboteur** | Burp Extension | JWS/JWE editing and attacks | Automatic token detection, in-line editing, signing/verifying/encrypting, automated attack workflows |
| **JWT Editor** | Burp Extension | JWT manipulation | Automatic JWT detection in HTTP/WebSocket, key management, signing/verifying, common attack payloads |
| **JWT-scanner** | Burp Extension | Automated JWT vulnerability detection | Auto-detects JWTs from Proxy/Repeater/Target; tests for common misconfigurations |
| **jwtfuzz** | CLI Tool (Rust) | JWT fuzzing | Generates malformed JWTs: null signatures, swapped algorithms, psychic signatures, header mutations |
| **jwt-fuzzer** | CLI Tool (Python) | JWT mutation testing | Creates multiple invalid JWT strings from an initial valid token |
| **hashcat** (mode 16500) | CLI Tool | HMAC secret cracking | Offline brute force of JWT HS256/HS384/HS512 signatures against wordlists |
| **jwt-security-analyzer** | CLI Tool (Python) | Comprehensive JWT security testing | CVE-specific attack implementations (2024–2025 CVEs), psychic signatures, prototype pollution |
| **OWASP ZAP JWT Add-on** | ZAP Extension | Active scanning + fuzzing | Automated JWT vulnerability scanning rules |
| **jwtXploiter** | CLI Tool (Python) | Automated JWT exploitation | `alg:none`, key confusion, `kid` injection, `jku`/`x5u` spoofing, HMAC brute-force |
| **John the Ripper** | CLI Tool (C) | HMAC secret cracking | CPU-based JWT HMAC cracking as alternative to hashcat |
| **jwt-cracker** | CLI Tool (Node.js) | HS256 brute force | Simple brute-force for JWTs with short HMAC secrets |
| **jwt.io** | Web Tool | JWT debugging & library matrix | Online decoder/encoder; comprehensive library compatibility matrix across languages |

---

## Summary: Core Principles

**The fundamental property that makes the JWT mutation space so expansive is the trust inversion inherent in self-describing tokens.** JWT places critical security metadata — algorithm selection, key source, claim semantics — inside the token itself, which is controlled by the bearer. This inverts the normal trust model where the verifier dictates security parameters. Every mutation in this taxonomy exploits the gap between what the token *declares* and what the verifier *enforces*: the `alg` header declares the algorithm, but the verifier must enforce its own algorithm; the `jwk` header declares the verification key, but the verifier must use only trusted keys; the `exp` claim declares validity, but the verifier must independently check freshness.

**The attack surface extends beyond the token into infrastructure, transport, and architecture.** This taxonomy demonstrates that JWT vulnerabilities exist at every layer: the cryptographic layer (§1, §3), the key management infrastructure (§2), the claim semantics layer (§4), the header processing layer (§5), the encryption layer (§6), the library implementation layer (§7), the transport and deployment layer (§8), the cross-service architecture layer (§9), and now the selective disclosure extension layer (§10). Securing any single layer is insufficient — JWKS cache poisoning (§2-4) bypasses perfect token-level validation, prototype pollution (§7-3) bypasses perfect signature verification, and confused deputy attacks (§9) bypass perfect claim validation.

**Incremental fixes fail because the attack surface is inherent to the specification design.** RFC 7519 and the JOSE family (RFC 7515–7518) were designed for maximum flexibility — supporting arbitrary algorithms, multiple key formats, extensible headers, and self-contained validation. This flexibility means that every parser quirk, every type confusion in claim values, every library API that defaults to trusting the token's self-description becomes a potential authentication bypass. The steady stream of algorithm confusion CVEs across languages and frameworks (from Java's psychic signatures to Hono's HS256 default in 2026) demonstrates that developers consistently struggle to use JWT libraries safely, because safe usage requires understanding and countering the specification's own design.

**Structural solutions require eliminating the trust inversion and adding sender constraint.** RFC 8725 (JWT Best Current Practices) addresses many symptoms — mandating algorithm allowlists, `typ` checking, and short-lived tokens — but the root cause remains. The long-term trajectory points toward: (1) opinionated token formats like PASETO (Platform-Agnostic Security Tokens), which eliminate algorithm negotiation entirely; (2) sender-constrained tokens via DPoP (RFC 9449) or mTLS binding (RFC 8705), which eliminate the bearer-token problem; (3) proper token exchange (RFC 8693) and transaction tokens for cross-service delegation; and (4) SD-JWT for privacy-preserving credential presentation with holder binding. For organizations that must use JWT, the minimum safe configuration requires: server-side algorithm enforcement (never trust `alg`), key source pinning (never resolve `jwk`/`jku`/`x5c`/`x5u` from the token), explicit claim validation (`iss`, `aud`, `exp`, `nbf`), short token lifetimes with server-side revocation capability, sender constraint (DPoP or mTLS), and prototype-pollution-safe claim processing.

---

## References

### RFC Documents — Core JOSE/JWT

| RFC | Title | Date |
|-----|-------|------|
| RFC 7515 | JSON Web Signature (JWS) | May 2015 |
| RFC 7516 | JSON Web Encryption (JWE) | May 2015 |
| RFC 7517 | JSON Web Key (JWK) | May 2015 |
| RFC 7518 | JSON Web Algorithms (JWA) | May 2015 |
| RFC 7519 | JSON Web Token (JWT) | May 2015 |
| RFC 7520 | Examples of Protecting Content Using JOSE | May 2015 |
| RFC 7638 | JSON Web Key (JWK) Thumbprint | September 2015 |
| RFC 7797 | JWS Unencoded Payload Option | February 2016 |
| RFC 8037 | CFRG Elliptic Curve Signatures in JOSE (EdDSA) | January 2017 |
| RFC 8725 | JSON Web Token Best Current Practices (BCP 225) | February 2020 |
| RFC 8812 | JOSE CFRG Algorithms Registration (EdDSA, Ed25519, Ed448) | August 2020 |
| RFC 9278 | JWK Thumbprint URI | August 2022 |

### RFC Documents — JWT in Protocol Contexts

| RFC | Title | Date |
|-----|-------|------|
| RFC 6749 | The OAuth 2.0 Authorization Framework | October 2012 |
| RFC 6750 | OAuth 2.0 Bearer Token Usage | October 2012 |
| RFC 7523 | JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants | May 2015 |
| RFC 7800 | Proof-of-Possession Key Semantics for JWTs (`cnf` claim) | April 2016 |
| RFC 8693 | OAuth 2.0 Token Exchange | January 2020 |
| RFC 8705 | OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens | February 2020 |
| RFC 9068 | JWT Profile for OAuth 2.0 Access Tokens | October 2021 |
| RFC 9207 | OAuth 2.0 Authorization Server Issuer Identification | March 2022 |
| RFC 9396 | OAuth 2.0 Rich Authorization Requests | May 2023 |
| RFC 9449 | OAuth 2.0 Demonstrating Proof of Possession (DPoP) | September 2023 |
| OpenID Connect Core 1.0 | ID Token as signed/encrypted JWT | November 2014 |

### Active IETF Drafts

| Draft | Topic | Relevance |
|-------|-------|-----------|
| draft-ietf-oauth-selective-disclosure-jwt | SD-JWT | Selective disclosure JWT with new attack surface (§10) |
| draft-ietf-oauth-sd-jwt-vc | SD-JWT Verifiable Credentials | Credential-specific attack vectors extending SD-JWT |
| draft-ietf-oauth-status-list | Token Status Lists | JWT revocation mechanism addressing stateless revocation gap |
| draft-ietf-oauth-transaction-tokens | Transaction Tokens | Cross-service identity propagation addressing confused deputy (§9) |
| draft-ietf-wimse-s2s-protocol | Workload Identity (WIMSE) | JWT-based workload identity for microservice-to-microservice auth |

### Foundational Vulnerability Research

| Source | Author(s) | Year | Contribution |
|--------|-----------|------|-------------|
| "Critical vulnerabilities in JSON Web Token libraries" | Tim McLean | 2015 | Original `alg:none` and RS256→HS256 algorithm confusion disclosure |
| "Practical Cryptanalysis of JWE — Invalid Curve Attacks" (ESORICS 2017) | Detering, Somorovsky, Mainka, Mladenov, Schwenk (Ruhr-Universität Bochum) | 2017 | Invalid elliptic curve attacks against ECDH-ES key agreement in JWE |
| "Revisiting the JOSE/JWT Standard: A Comprehensive Security Analysis" | Mainka, Mladenov, Schwenk (Ruhr-Universität Bochum) | 2017 | Systematic analysis of structural JOSE specification weaknesses |
| "Psychic Signatures in Java" (CVE-2022-21449) | Neil Madden (ForgeRock) | 2022 | Java 15-18 ECDSA blank-signature bypass discovery |
| "Three New Attacks Against JSON Web Tokens" | Tom Tervoort (Deloitte) | 2020 | Novel ECDH key confusion and JWE attacks |
| "A Comprehensive Formal Security Analysis of OAuth 2.0" | Fett, Küsters, Schmitz | ACM CCS | Formal model identifying cross-service token confusion |
| "An Extensive Formal Security Analysis of the OpenID Financial-Grade API" | Fett et al. | IEEE S&P 2019 | Formal FAPI verification identifying JWT-specific attack vectors |

### Conference Presentations

| Talk | Venue | Year |
|------|-------|------|
| "Friday the 13th: JSON Attacks" — Alvaro Muñoz, Oleksandr Mirosh | Black Hat USA | 2017 |
| "Living with JSON Web Tokens: Practical Attacks and Defenses" — Sven Morgenroth | DEF CON 28 / Black Hat EU | 2020 |
| "Hacking JWT Tokens" — Dejan Zelic | Red Team Village, DEF CON 29 | 2021 |
| "JWT Parkour — Practical JWT Exploitation" — Louis Nyffenegger (PentesterLab) | Various workshops | 2019-2022 |

### Technical Writeups & Guides

| Source | Description |
|--------|-------------|
| PortSwigger Web Security Academy — JWT Attacks | Interactive lab suite: `alg:none`, HMAC brute-force, algorithm confusion, `jwk`/`jku` injection, `kid` traversal |
| OWASP JWT Cheat Sheet / JSON Web Token for Java Cheat Sheet | Defensive guidance for JWT implementations |
| HackTricks — Hacking JSON Web Tokens | Community-maintained attack reference aggregating techniques |
| jwt_tool Wiki (ticarpi) — JWT Attack Playbook | Detailed walkthrough for every jwt_tool attack mode |
| Auth0 Blog — "Brute Forcing HS256 Is Possible" | Practical HMAC brute-force feasibility demonstration |
| Auth0 — JWT Handbook (Sebastian Peyrott) | Comprehensive JWT reference (free ebook) |
| Neil Madden (Illuminated Security) — JOSE vulnerability blog series | Deep ECDSA/EdDSA, JWE oracle, key agreement vulnerability analysis |
| Scott Arciszewski — "JWT is a Bad Standard That Everyone Should Avoid" (Paragon IE) | Architectural critique; PASETO as alternative |
| Unit 42 (Palo Alto Networks) — "Prototype Pollution in jsonwebtoken (CVE-2022-23529)" | Prototype pollution → RCE chain in Node.js JWT library |

### CWE Classifications

| CWE | Title | JWT Relevance |
|-----|-------|---------------|
| CWE-345 | Insufficient Verification of Data Authenticity | `alg:none`, signature bypass |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | Algorithm confusion, weak algorithms |
| CWE-347 | Improper Verification of Cryptographic Signature | All signature verification bypasses |

---

*This document was created for defensive security research and vulnerability understanding purposes.*
