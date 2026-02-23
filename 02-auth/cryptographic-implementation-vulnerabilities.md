# Cryptographic Implementation Vulnerabilities (Web Context) — Mutation/Variation Taxonomy

---

## Scope & Boundary

This document covers **cryptographic primitive and protocol implementation flaws** as they manifest in web applications and infrastructure. The focus is on the underlying cryptographic mechanisms—cipher modes, asymmetric operations, hash functions, RNG, key lifecycle, data structure parsing, and side-channel leakage—rather than the higher-level protocols that consume them.

**Explicitly excluded** (covered in dedicated documents):
- TLS/SSL protocol-level attacks (version downgrade, cipher negotiation, session management, certificate validation, HSTS) → `tls-security.md`
- JWT-specific attacks (algorithm confusion, header injection, kid exploitation) → `jwt.md`
- SAML signature wrapping, canonicalization, Golden/Silver SAML → `saml.md`
- OAuth token handling, PKCE downgrade, client authentication → `oauth.md`
- Cookie encryption forgery (ECB/CBC without MAC at cookie level) → `cookie.md`
- Kerberos, NTLM, RADIUS, FIDO2/WebAuthn/Passkey attacks → `authentication-bypass-and-sso.md`
- MFA bypass, password reset token weakness → `account-takeover.md`
- Web timing attacks (general) → `web-timing-attack.md`

Where a protocol-specific document mentions a cryptographic primitive (e.g., ECDSA nonce reuse in JWT context), this document provides the **generalized treatment** of that primitive's failure modes across all web contexts.

---

## Classification Structure

The taxonomy is organized along three axes:

### Axis 1 — Mutation Target (Primary Structure)

The structural component of the cryptographic system being attacked or misused. This axis defines the nine top-level categories (§1–§9).

### Axis 2 — Discrepancy Type (Cross-Cutting)

The nature of the cryptographic guarantee that is violated:

| Discrepancy Type | Description |
|---|---|
| **Integrity Bypass** | Ciphertext or signed data manipulated without detection |
| **Key Recovery** | Secret or private key material extracted |
| **Plaintext Recovery** | Encrypted data decrypted without possessing the key |
| **Authentication Bypass** | Signatures or MACs forged without the signing key |
| **Information Leakage** | Metadata, timing, or length information reveals protected content |
| **Downgrade** | Stronger algorithm/mode forced to weaker alternative |
| **Denial of Service** | Cryptographic operations weaponized for resource exhaustion |

### Axis 3 — Attack Scenario (Mapping)

The deployment context in which the flaw becomes exploitable:

| Scenario | Architecture |
|---|---|
| **MitM / Session Interception** | Network-positioned attacker modifying or observing traffic |
| **Token / Credential Forgery** | Attacker generating valid authentication material |
| **Data Exfiltration** | Extracting protected data from encrypted stores or transit |
| **Retrospective Decryption** | Capturing traffic now for future decryption (HNDL) |
| **Supply Chain Compromise** | Attacking cryptographic libraries or key distribution |
| **Infrastructure Compromise** | Exploiting crypto processing for RCE, DoS, or pivoting |

---

## §1. Symmetric Cipher Mode & Parameter Misuse

Symmetric ciphers (AES, ChaCha20) are the workhorses of web encryption—session data, encrypted cookies, database field encryption, file storage. Their security depends entirely on correct mode selection, parameter handling, and integrity protection.

### §1-1. Unauthenticated CBC Mode Exploitation

AES-CBC provides confidentiality but **no integrity**. Without a separate MAC, ciphertext is malleable.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CBC Bit-Flipping** | In CBC decryption, `plaintext[n] = DECRYPT(ciphertext[n]) XOR ciphertext[n-1]`. Modifying byte `i` in block `n-1` directly XORs the same change into plaintext block `n`. Formula: `modified = original_byte XOR old_value XOR new_value`. | Attacker can intercept and modify ciphertext (cookies, URL params, API fields). No MAC/HMAC protects the ciphertext. |
| **CBC Padding Oracle** | When a server reveals whether PKCS#7 padding is valid after decryption (via error messages, timing, or HTTP status codes), an attacker iteratively decrypts each byte by manipulating the preceding ciphertext block and observing the oracle response. Requires ~128 × block_size (in bytes) queries per block (e.g., ~2,048 for AES-128). | Server returns distinguishable responses for padding errors vs. application errors. Applies to any system decrypting CBC ciphertext from untrusted input. |
| **IV Manipulation (First Block)** | The IV functions as `ciphertext[0]` for the first block. If the IV is transmitted alongside the ciphertext (common in cookies, encrypted URL parameters), the attacker controls the XOR applied to the first plaintext block: `fake_iv = DECRYPT(block_1) XOR desired_plaintext`. | IV is not integrity-protected or is user-controllable. |
| **IV Reuse / Predictable IV** | Reusing the same IV with the same key produces identical ciphertext for identical first plaintext blocks, leaking equality. Predictable IVs enable chosen-plaintext attacks (BEAST attack pattern). Note: the `C1 XOR C2 = P1 XOR P2` relation applies to CTR/stream ciphers, not CBC. | Static or predictable IV generation. Same key used across multiple encryptions. |

**Example — CBC Bit-Flipping on Encrypted Cookie:**
```
Original plaintext:  userid=12345&role=guest
Target plaintext:    userid=12345&role=admin
Attack: XOR bytes at positions corresponding to "guest" in the
        preceding ciphertext block with (ord('g')^ord('a')),
        (ord('u')^ord('d')), (ord('e')^ord('m')), (ord('s')^ord('i')),
        (ord('t')^ord('n')).
Side effect: The modified block decrypts to garbage, but the
             target block contains "role=admin".
```

### §1-2. ECB Mode Pattern Leakage

ECB encrypts each block independently with the same key, producing identical ciphertext for identical plaintext blocks. This deterministic property leaks structural information.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Block Boundary Alignment** | Attacker controls input adjacent to a secret value. By padding input to align the secret across block boundaries and observing ciphertext blocks, bytes of the secret are recovered one at a time (ECB byte-at-a-time / ECB oracle). | Application encrypts attacker-controlled input concatenated with secret data. ECB mode used for encryption. |
| **Ciphertext Block Reordering** | Since each block is independently encrypted, blocks can be swapped, duplicated, or removed. Role escalation by replacing one encrypted field with another. | Structured data (e.g., `role=user`, `role=admin`) encrypted in ECB. Attacker can collect blocks from different contexts. |
| **Pattern Recognition** | Repeated plaintext blocks produce repeated ciphertext blocks, revealing data structure, repetition frequency, and field boundaries even without decryption. | Any ECB encryption of structured or partially repetitive data. |

### §1-3. CTR/GCM Nonce Misuse

Counter (CTR) mode and its authenticated variant GCM depend on nonce uniqueness. Nonce reuse has catastrophic consequences.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CTR Nonce Reuse (Two-Time Pad)** | Reusing a nonce with the same key produces identical keystream blocks. XORing two ciphertexts eliminates the keystream: `C1 XOR C2 = P1 XOR P2`. Known or guessable portions of either plaintext enable full recovery of the other. | Same (key, nonce) pair used for two or more encryptions. Common in stateless servers or distributed systems without nonce coordination. |
| **GCM Nonce Reuse → Auth Key Recovery** | AES-GCM uses a polynomial MAC (GHASH) keyed by `H = AES_K(0^128)`. With two messages encrypted under the same nonce, the authentication key `H` is recoverable via polynomial GCD. The attacker can then forge authenticated ciphertexts. | Same (key, nonce) pair used for two GCM encryptions. This destroys both confidentiality AND authenticity. |
| **GCM Short Tag Truncation** | GCM tags can be truncated to reduce overhead. Each bit removed doubles the forgery probability. A 32-bit tag allows forgery with probability 2^-32 per attempt—feasible for online attacks with high request rates. | Application uses truncated GCM tags (< 96 bits). High request volume available. |

### §1-4. Stream Cipher Keystream Reuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **RC4 Bias Exploitation** | RC4's output bytes exhibit statistical biases. The second output byte has a 2/256 probability of being zero. With ~2^30 encryptions of the same plaintext (e.g., cookies sent in repeated HTTPS requests), biases allow recovery of plaintext bytes. | RC4 used in TLS (now deprecated). Same secret encrypted across many connections. |
| **ChaCha20 Nonce Reuse** | ChaCha20 (like CTR mode) produces a deterministic keystream from (key, nonce). Nonce reuse yields two-time pad. ChaCha20-Poly1305 nonce reuse also exposes the Poly1305 one-time key (derived from ChaCha20 block 0): authenticating two messages with the same key allows polynomial key recovery, compromising both confidentiality and authenticity — analogous to GCM nonce reuse exposing the GHASH key. | Same (key, nonce) pair reused. Relevant in custom implementations bypassing TLS. |

### §1-5. Encrypt-then-MAC Order Violations

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **MAC-then-Encrypt** | The MAC is computed over plaintext, then both are encrypted. The receiver must decrypt before verifying integrity, creating a window for padding oracles and processing-time differences (Lucky13). TLS ≤1.2 with CBC suites uses this order. | CBC cipher suites in TLS 1.0/1.1/1.2. Any custom protocol using MAC-then-Encrypt. |
| **Encrypt-and-MAC** | MAC is computed over plaintext; encryption is applied to plaintext only. The MAC (over plaintext) is sent in the clear, leaking information about the plaintext through the MAC tag. SSH's original design used this. | Custom protocols using Encrypt-and-MAC composition. |
| **No MAC at All** | Encryption applied without any integrity protection. All ciphertext manipulation attacks (§1-1, §1-2, §1-3) become trivially exploitable. | Disturbingly common in web application code using raw AES without AEAD. |

---

## §2. Asymmetric Cryptography Implementation Flaws

Asymmetric cryptography (RSA, ECDSA, Ed25519, ECDH) underpins digital signatures, key exchange, and authentication across the web. Implementation errors in these primitives compromise the mathematical guarantees they provide.

### §2-1. ECDSA Nonce Vulnerabilities

ECDSA's security depends entirely on the secrecy and uniqueness of the per-signature nonce `k`. Any leakage—even a few bits—enables private key recovery via lattice reduction.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Nonce Reuse (k-value Reuse)** | When the same `k` is used for two signatures on different messages, both signatures share the same `r` value. The private key is directly computable: `k = (hash(m1) - hash(m2)) / (s1 - s2) mod n`, then `privateKey = (s1*k - hash(m1)) / r mod n`. | PRNG failure, static seed, or insufficient entropy during signing. Detectable by comparing `r` values across signatures. |
| **Nonce Bias (Partial Leakage)** | If nonces are biased—e.g., top bits always zero due to hash output shorter than curve order—lattice-based attacks (HNP/LLL) recover the private key from multiple signatures. PuTTY's P-521 implementation leaked 9 bits per nonce via SHA-512 truncation (CVE-2024-31497), requiring ~60 signatures for full key recovery. | Hash output size < curve order (P-521: 521 bits vs SHA-512: 512 bits). Any systematic bias in nonce generation. |
| **Timing-Based Nonce Leakage** | Non-constant-time scalar multiplication during signing leaks nonce bit-length through execution timing. The Minerva attack class exploits nanosecond-level timing differences to extract partial nonce information, enabling lattice-based key recovery. OpenSSL's ECDSA had a ~300ns timing signal when the top word of the inverted nonce was zero (CVE-2024-13176). | Non-constant-time bignum operations in the signing path. Attacker can measure signing time (local process, co-located VM, or high-precision network timing). |
| **Invalid Curve Attack** | If the ECDSA implementation does not validate that the peer's public key lies on the expected curve, an attacker submits a point on a weak curve with small subgroup order. The resulting shared secret or signature leaks the private key modulo the subgroup order. Chinese Remainder Theorem combines multiple leaks for full recovery. | Missing point validation in ECDH key exchange or ECDSA verification. The implementation accepts arbitrary (x, y) coordinates. |

**Example — Nonce Bias Leading to Key Recovery (PuTTY CVE-2024-31497):**
```
Curve: NIST P-521 (order ≈ 2^521)
Hash: SHA-512 (output = 512 bits)
Bias: Top 9 bits of every nonce are zero
Signatures needed: ~60 (from public Git commits signed with SSH keys)
Attack: Construct lattice problem from (r, s, hash) tuples
        Apply LLL/BKZ reduction to recover private key
Impact: SSH private keys recoverable from public Git signing history
```

### §2-2. RSA Implementation Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PKCS#1 v1.5 Padding Oracle (Bleichenbacher)** | RSA with PKCS#1 v1.5 padding is vulnerable when a server reveals padding validity. The attacker iteratively crafts ciphertexts `c' = c * s^e mod n`, observes the server's response, and progressively narrows the plaintext range. Typically requires ~10,000–100,000 oracle queries for a 2048-bit key. | Server returns distinguishable responses for valid vs. invalid PKCS#1 v1.5 padding. RSA key exchange (not RSA signing) in TLS. |
| **ROBOT (Return of Bleichenbacher's Oracle Threat)** | Modern variant using subtle side-channels as oracles: TCP reset vs. timeout, duplicated TLS alerts, HTTP status code differences. Affected ~27% of Alexa Top 100 in 2017. Products from F5, Citrix, Palo Alto, IBM, and Cisco were vulnerable. | RSA key exchange enabled in TLS. Any observable behavioral difference on padding failure—even at the TCP level. |
| **Weak RSA Key Generation** | Keys generated with insufficient entropy, shared prime factors across devices (common in IoT/embedded), or degenerate parameters (e.g., `e=1`). Factorable.net found 0.2% of TLS RSA public keys shared prime factors. | Low-entropy PRNG at key generation time. Mass-produced devices with identical firmware generating keys at first boot. |
| **RSA Short Key Length** | RSA keys below 2048 bits are factorizable with moderate resources. 1024-bit keys are within reach of well-funded attackers. 512-bit keys (FREAK/export-grade) are trivially factorizable on consumer hardware. | Legacy systems or misconfigured servers offering short RSA keys. FREAK: forcing export-grade 512-bit RSA. |
| **Public Key Encryption as Token Authentication (Confidentiality ≠ Authenticity)**| OIDC/OAuth implementations that encrypt refresh tokens or session tokens using RSA public keys retrievable from public JWKS endpoints (`.well-known/jwks.json`). Since the public key is available to anyone, any party can encrypt arbitrary token payloads that the server will successfully decrypt and accept — the server confuses "I can decrypt this" with "this is authentic." The attacker extracts the public RSA key, constructs a token with forged claims (user identity, scopes, expiration), encrypts it with the public key, and submits it to the token endpoint. The server decrypts successfully, trusts the claims, and issues valid access tokens for the victim's account | RSA public key used for token encryption is publicly accessible (JWKS endpoint). Token integrity relies solely on encryption (no separate signature or MAC). Token structure/schema is predictable or documented. (See `oauth.md` for OAuth-specific context.) |

### §2-3. Ed25519 Implementation Flaws

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unvalidated Public Key Parameter (Chalkias Vulnerability)** | Over 45 Ed25519 libraries expose a signing API accepting a pre-computed public key as an optimization parameter. If the library does not validate that the public key matches the private key, an attacker can invoke signing with manipulated public keys and use lattice-based cryptanalysis on the resulting signatures to recover the private key. | Library exposes `sign(message, privateKey, publicKey)` API. No validation that `publicKey = privateKey * G`. Attacker can invoke signing with arbitrary public key values. |

### §2-4. Diffie-Hellman / ECDH Key Exchange Flaws

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Small Subgroup Attack (DH)** | Attacker sends a DH public value from a small subgroup of the multiplicative group. The shared secret is confined to a small set of values, recoverable by brute force. | DH group parameters lack safe-prime validation. Server does not validate that the peer's public value has full order. |
| **Logjam (DH Export Downgrade)** | Attacker forces a TLS handshake to use 512-bit "export-grade" DH parameters, then performs Number Field Sieve precomputation to break the key exchange in real time. A single 512-bit group was reused by ~8.4% of HTTPS domains. | TLS server supports DHE_EXPORT cipher suites. Client does not reject weak DH parameters. |
| **Cross-Protocol ECDH Key Reuse** | When the same ECDH key pair is used for both key exchange and signing (or across protocols), an attacker can exploit one protocol's interaction to extract information usable in another. | Same key pair reused across TLS, SSH, and application-layer protocols. |

---

## §3. Hash Function & MAC Exploitation

Hash functions and MACs provide integrity and authentication. Their misuse or the exploitation of their structural properties undermines these guarantees.

### §3-1. Length Extension Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Merkle-Damgård Length Extension** | Hash functions with Merkle-Damgård construction (MD5, SHA-1, SHA-256) permit an attacker who knows `H(secret || message)` and the length of `secret` to compute `H(secret || message || padding || attacker_suffix)` without knowing `secret`. This breaks MAC constructions of the form `MAC = H(key || data)`. | Application computes `hash(secret + user_data)` as an integrity check. SHA-256 or MD5 used (not HMAC, not SHA-3, not truncated SHA-512/256). |
| **API Signature Forgery via Length Extension** | Web APIs using `signature = SHA256(api_secret + request_params)` are vulnerable. The attacker appends additional parameters (e.g., `&admin=true`) and computes the valid extended hash. The server validates the signature and processes the appended parameters. | Common in custom API authentication schemes that avoid HMAC. Query string or POST body is concatenated with secret before hashing. |

**Example — API Signature Extension:**
```
Original: GET /api?user=alice&sig=abc123
          Server computes: SHA256(secret + "user=alice") == abc123 ✓

Attack:   GET /api?user=alice[padding]&admin=true&sig=def456
          Attacker computes: extend(abc123, len(secret), "&admin=true") → def456
          Server computes: SHA256(secret + "user=alice[padding]&admin=true") == def456 ✓
```

### §3-2. Hash Collision Exploitation in Web Context

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **MD5 Chosen-Prefix Collision** | Two different inputs sharing an arbitrary prefix can be made to produce the same MD5 hash with ~2^39 complexity (practical). Exploited in X.509 certificate forgery, RADIUS response forgery (BlastRADIUS, CVE-2024-3596), and software signing. | Any system using MD5 for integrity or authentication. MD5 in RADIUS Response-Authenticator is explicitly exploitable. |
| **SHA-1 Identical-Prefix Collision** | Two documents with the same prefix yield the same SHA-1 hash at ~2^63 cost (SHAttered, 2017). Practical for PDF forgery, Git commit collision, and certificate signing. | SHA-1 used for digital signatures, content addressing (Git), or certificate thumbprints. |
| **Hash-as-Deduplication Confusion** | Content-addressable systems (CDNs, caches, object stores) using weak hashes for deduplication allow an attacker to substitute content by providing a collision. The legitimate content is replaced or confused with malicious content. | Deduplication keyed on MD5 or SHA-1. Attacker can upload content to the same storage system. |
| **Birthday Attack on Short Hash Outputs** | For hash outputs of `n` bits, a collision is expected after ~2^(n/2) attempts. Truncated hashes (e.g., 64-bit identifiers derived from SHA-256) are vulnerable to birthday attacks with ~2^32 operations. | Truncated hash outputs used as unique identifiers. Session tokens, CSRF tokens, or cache keys derived from truncated hashes. |

### §3-3. HMAC and MAC Misuse

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Timing Attack on MAC Comparison** | Comparing MAC tags using standard string comparison (`==`) reveals the first differing byte through timing differences. An attacker iteratively brute-forces each byte by measuring comparison time, reducing the attack from 2^128 to 128×256 = 32,768 attempts for a 16-byte MAC. | Non-constant-time comparison function used for MAC verification. Measurable timing differences (local or network-adjacent). |
| **HMAC Key Length Interaction** | HMAC keys longer than the hash block size are first hashed, then used. If an attacker can influence key selection and the resulting hash is weak (collision), different keys produce the same HMAC output. Additionally, keys shorter than the hash output provide less security than expected. | Application allows user-influenced key material for HMAC. Very long keys passed without awareness of internal hashing. |
| **Poly1305 Key Reuse** | Poly1305 (used in ChaCha20-Poly1305) is a one-time MAC. Reusing the same Poly1305 key for two messages allows forgery of MACs for arbitrary messages. In ChaCha20-Poly1305, nonce reuse implies Poly1305 key reuse. | Nonce reuse in ChaCha20-Poly1305 (see §1-3). Custom protocols misusing Poly1305 as a general-purpose MAC. |

### §3-4. Password Hashing Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **bcrypt 72-Byte Truncation** | bcrypt silently truncates passwords to 72 bytes. Passwords longer than 72 bytes that share the same first 72 bytes produce identical hashes. Exploited in the Okta October 2024 incident where cache keys based on bcrypt hash allowed authentication with any password sharing the first 72 bytes. | Passwords or derived inputs exceeding 72 bytes passed to bcrypt. Cache key derived from bcrypt hash. |
| **Unsalted Hash / Global Salt** | Without per-user salts, identical passwords produce identical hashes, enabling rainbow table attacks and revealing password reuse across users. A single global salt (shared across all users) enables precomputation once the salt is known. | Legacy systems using MD5/SHA-1/SHA-256 without salts. Compromised global salt value. |
| **Insufficient Work Factor** | Password hashing functions (bcrypt, scrypt, Argon2) require calibrated cost parameters. Too low a cost factor enables GPU-based brute forcing. bcrypt cost < 10, scrypt N < 2^14, or Argon2 memory < 64MB are generally considered insufficient for 2025. | Default or low cost parameters used. No periodic recalibration as hardware improves. |
| **PBKDF2 Iteration Abuse (Denial of Service)** | When the iteration count is attacker-controlled (e.g., PBES2 in JWE/JWK), setting an extremely high value forces the server to perform billions of PBKDF2 iterations, causing CPU exhaustion. A single request can stall a server for minutes. | Iteration count parsed from untrusted input (see jwt.md §5 for JWT-specific treatment). PBES2 key wrapping in any non-JWT context. |

---

## §4. Random Number & Nonce Generation Failures

Cryptographic security fundamentally depends on the quality of random number generation. Insufficient entropy or predictable generators undermine every cryptographic operation built upon them.

### §4-1. Insufficient Entropy at Generation Time

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Boot-Time Entropy Starvation** | Systems generating cryptographic keys immediately after boot (VMs, containers, IoT devices) may have insufficient entropy. `/dev/urandom` on Linux will return data even with low entropy, potentially producing predictable keys. Factorable.net found 5.57% of TLS hosts and 9.58% of SSH hosts shared keys due to low-entropy key generation. | Key generation during early boot. VMs cloned from a single snapshot (identical initial PRNG state). Embedded devices with no entropy sources. |
| **VM Fork Entropy Duplication** | When a VM is forked/cloned, the forked instance inherits the parent's PRNG state. Both VMs generate identical "random" values until sufficient new entropy is mixed in. TLS session keys, ECDSA nonces, and CSRF tokens may collide. | VM live migration or snapshot-based cloning. No PRNG reseeding after fork. Cloud auto-scaling from snapshots. |
| **Embedded Device Entropy Failure** | Devices lacking hardware RNG (no RDRAND, no TPM, no timer jitter) generate keys from predictable sources (uptime, PID, MAC address). Multiple devices produce identical keys. | IoT devices, routers, network appliances. Headless systems with no user input entropy. |

### §4-2. Predictable PRNG in Web Frameworks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Math.random() for Security Tokens** | JavaScript's `Math.random()` uses xorshift128+ (V8) or similar non-cryptographic PRNGs. The internal state (128 bits in V8) is recoverable from ~5 consecutive outputs, enabling prediction of all future and past values—including session tokens, CSRF tokens, and password reset links. | Application uses `Math.random()` instead of `crypto.getRandomValues()` for security-sensitive values. |
| **Python random Module State Recovery** | Python's `random` module uses Mersenne Twister (MT19937). The 624×32-bit internal state is fully recoverable from 624 consecutive 32-bit outputs. All subsequent outputs (tokens, nonces, keys) are predictable. | Application uses `random.random()` instead of `secrets` module or `os.urandom()` for security tokens. |
| **PHP mt_rand() / rand() Prediction** | PHP's `mt_rand()` (Mersenne Twister) is seeded with a 32-bit value on first call. The seed is recoverable from a few outputs, making all subsequent values predictable. Pre-PHP 7.1, `rand()` used an even weaker LCG. | PHP applications using `mt_rand()` or `rand()` for tokens, CSRF values, or password reset codes. |
| **Ruby SecureRandom Pitfalls** | Ruby's `SecureRandom` typically uses `/dev/urandom`, but fallback to OpenSSL's PRNG can introduce issues in forked processes (pre-Ruby 2.5 did not reseed after fork). | Ruby applications using `SecureRandom` in forked worker processes (Unicorn, Puma prefork). |
| **Java java.util.Random State Recovery** | Java's `java.util.Random` uses a 48-bit LCG. The full seed is recoverable from two consecutive outputs. `ThreadLocalRandom` shares this weakness. Only `java.security.SecureRandom` is cryptographically secure. | Java applications using `Random` or `ThreadLocalRandom` for security-critical values. |

### §4-3. Nonce/IV Generation Flaws

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Sequential Nonce in Distributed Systems** | Multiple servers using sequential counters for nonces (e.g., `server_id || counter`) can collide if server IDs are reused, counters wrap, or configuration is inconsistent. | Distributed encryption without centralized nonce coordination. Counter rollover not handled. |
| **Timestamp-Based Nonce Collision** | Using timestamp as nonce (e.g., Unix epoch seconds) produces collisions when two operations occur in the same second. Microsecond or nanosecond timestamps reduce but do not eliminate the risk under high throughput. | High-throughput encryption using time-based nonces. Clock synchronization issues in distributed systems. |
| **Deterministic Nonce with Predictable Input** | RFC 6979 deterministic ECDSA nonces are safe when implemented correctly, but if the hash function or private key is compromised, all nonces become predictable. Custom "deterministic" nonce schemes using weak inputs (e.g., `HMAC(key, counter)` with a leaked key) are directly exploitable. | Custom deterministic nonce schemes. Leaked key material in RFC 6979 implementations. |

---

## §5. Key Material Lifecycle & Management

Key material exposure, from generation through storage, rotation, and destruction, represents the most direct path to cryptographic system compromise.

### §5-1. Key Material Exposure

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Source Code Repository Leakage** | Private keys, API secrets, and encryption keys committed to Git repositories (including in commit history even after deletion). GitHub's secret scanning detected >40 million secrets in public repos in 2024. | `.pem`, `.key`, `.pfx` files in repositories. Hardcoded key strings in source code. `.env` files committed. |
| **Error Message Key Disclosure** | Stack traces, debug pages, and verbose error messages exposing key material, PRNG state, or intermediate cryptographic values. Django debug pages, PHP `phpinfo()`, and Java stack traces have all leaked secrets. | Debug mode enabled in production. Verbose error handling for cryptographic operations. |
| **Memory Disclosure (Heartbleed Pattern)** | Buffer over-read vulnerabilities in TLS libraries expose server memory containing private keys, session keys, and user credentials. Heartbleed (CVE-2014-0160) leaked up to 64KB per request from OpenSSL's heap. The pattern recurs in any TLS library with buffer management bugs. (See `tls-security.md` §7-2 and `web-memory-disclosure.md` §1-1 for detailed treatment.) | TLS library with buffer over-read. Server memory contains key material (common due to long-lived processes). |
| **Backup and Log Exposure** | Key material included in database backups, application logs, cloud storage snapshots, or monitoring systems. Encrypted database backups that include the encryption key in the same backup. | Logging of request/response bodies containing keys. Backup systems without separate key management. |

### §5-2. Key Rotation and Revocation Failures

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **No Key Rotation** | Cryptographic keys used indefinitely. Long-lived keys accumulate risk: more data encrypted under the same key (increasing exposure from compromise), more time for cryptanalysis, and more opportunities for exfiltration. | No key rotation policy. Keys older than organizational lifecycle. |
| **Rotation Without Re-Encryption** | Key is rotated (new key generated) but existing data remains encrypted under the old key, which must be retained indefinitely. The "rotated" key provides no forward security for existing data. | Key rotation policy without data re-encryption strategy. Old keys stored alongside new keys with equal access. |
| **Certificate Revocation Failure** | Revoked certificates remain trusted because clients don't check CRL/OCSP, OCSP responders are unreachable, or soft-fail OCSP silently accepts the certificate. CRLite and short-lived certificates are emerging mitigations. (See `tls-security.md` §4-3 for TLS-specific revocation treatment.) | Soft-fail OCSP (default in most browsers). CRL distribution point unreachable. No OCSP Must-Staple. |
| **JWKS Endpoint Key Confusion** | When a JWKS endpoint serves multiple keys and the `kid` (Key ID) is not validated strictly, an attacker may be able to exploit key rollover windows where both old and new keys are valid, or inject additional keys if the JWKS endpoint is compromisable. | JWKS endpoint serves keys without strict `kid` binding. Key rollover window with permissive validation. (See jwt.md for JWT-specific treatment.) |

### §5-3. Key Derivation Function (KDF) Weaknesses

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct Use of Passwords as Keys** | Using a user password directly as an AES key (e.g., padding with zeros or truncating) without a KDF. Passwords have far less entropy than keys, enabling brute-force. | `AES.new(password.encode().ljust(32, b'\0'))` pattern. No PBKDF2, scrypt, or Argon2 applied. |
| **Low-Iteration KDF** | PBKDF2 with low iteration count (< 600,000 for SHA-256 as of 2025 OWASP recommendation). Each halving of iterations doubles the attacker's speed. GPU-accelerated cracking of PBKDF2-SHA256 at 10,000 iterations exceeds 1M guesses/second. | Default or legacy iteration counts. No periodic adjustment for hardware improvements. |
| **Salt Reuse in KDF** | Same salt used across multiple users or derivations. Enables parallel attack: crack one password and the same precomputed table applies to all users with that salt. | Global salt or no salt in KDF. Salt derived from username (predictable, low entropy). |
| **KDF Type Confusion** | Using a hash function (SHA-256) instead of a proper KDF (PBKDF2, scrypt, Argon2) for password-to-key derivation. Fast hashes enable billions of guesses per second on GPUs. | `key = SHA256(password + salt)` without iteration. Confusing message hashing with key derivation. |

---

## §6. Cryptographic Data Structure Parsing Vulnerabilities

Cryptographic systems consume complex data structures (ASN.1/DER, X.509 certificates, PKCS#7/CMS, PEM encoding). Parser vulnerabilities in these structures enable pre-authentication attacks.

### §6-1. ASN.1/DER Parsing Flaws

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Length Field Overflow** | ASN.1 length fields can specify multi-byte lengths. Parsers that trust the length field without bounds checking can be tricked into allocating excessive memory or reading past buffer boundaries. | Untrusted ASN.1 input (certificates, CMS messages, PKCS#12 files). C/C++ implementations without bounds checking. |
| **Indefinite Length Encoding Abuse** | BER (but not DER) allows indefinite-length encoding. Parsers accepting BER where DER is expected may handle nested indefinite-length structures incorrectly, causing stack overflows or infinite loops. | Parsers accepting BER-encoded input. Deeply nested structures with indefinite lengths. |
| **Type Confusion in ASN.1** | ASN.1 tags identify the type of each element. If a parser does not strictly validate expected tags, an attacker can substitute one type for another (e.g., an INTEGER where a BIT STRING is expected), leading to misinterpretation of cryptographic parameters. | Lax ASN.1 parsing that skips tag validation. Certificate or key structures with substituted types. |
| **Trailing Data / Non-Canonical Encoding** | DER requires canonical encoding (minimal length, no trailing data). Parsers that accept non-canonical input or ignore trailing bytes may process different data than what was signed, enabling signature bypass. | Certificate validation using lax DER parsers. Signed data with appended unsigned content. |

### §6-2. X.509 Certificate Parsing Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Null Byte in Common Name** | A certificate issued for `www.target.com\0.attacker.com` may pass CA validation (which sees the full string) while the application truncates at the null byte and matches `www.target.com`. | C-based string handling in certificate validation. CAs that issue certificates with null bytes in names (increasingly rare). |
| **Name Constraint Bypass** | X.509 Name Constraints extension restricts which domains a subordinate CA can issue for. Parsers that ignore or improperly evaluate name constraints allow unauthorized certificate issuance. | Intermediate CA certificates with name constraints. Clients that do not enforce name constraints (many TLS libraries historically). |
| **Critical Extension Handling** | X.509 extensions marked as `critical` MUST be understood by the client; unrecognized critical extensions MUST cause rejection. Libraries that ignore this requirement accept certificates with security-relevant extensions they don't understand. | TLS libraries that skip unknown critical extensions. Custom certificate validation code. |
| **Certificate Policy Confusion** | Extended Validation (EV), Organization Validation (OV), and Domain Validation (DV) certificates have different trust levels but are technically equivalent in TLS. Applications assuming certificate type implies security level can be misled. | Application logic that depends on certificate validation level. Phishing sites with DV certificates. |

### §6-3. CMS/PKCS#7/S/MIME Parsing

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CMS AuthEnvelopedData IV Overflow** | When parsing CMS structures using AEAD ciphers (AES-GCM), the IV from ASN.1 parameters is copied into a fixed-size stack buffer without length validation. An oversized IV overflows the buffer. This is **pre-authentication** — no valid key material is required. (CVE-2025-15467, OpenSSL 3.x) | Application processes untrusted CMS/PKCS#7/S/MIME content. OpenSSL 3.0–3.6 prior to patch. |
| **PKCS#12 Parsing Vulnerabilities** | PKCS#12 files (.pfx, .p12) contain nested, encrypted structures. Parser bugs in handling malformed PKCS#12 enable heap overflows, NULL pointer dereferences, and infinite loops. Multiple such bugs found in OpenSSL by AI-driven fuzzing (2026). | Application imports PKCS#12 files from untrusted sources. Certificate enrollment or key import workflows. |
| **PEM Encoding Confusion** | PEM is a base64 encoding of DER with header/footer lines. Multiple PEM objects in a single file, missing headers, or embedded non-base64 characters can cause parser disagreements. Different libraries may extract different certificates from the same PEM file. | PEM files containing multiple certificates or keys. Different parsers in certificate validation pipeline. |

---

## §7. Side-Channel Leakage in Web Context

Side-channel attacks exploit information leaked through implementation behavior (timing, size, power, electromagnetic emanation) rather than cryptographic weaknesses. In web contexts, network-observable side channels are the primary threat.

### §7-1. Timing Side-Channels

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Non-Constant-Time Comparison** | String comparison of MACs, tokens, or passwords that short-circuits on first mismatch. Each byte position leaks timing information. Network jitter requires statistical analysis over many requests, but high-precision attacks have demonstrated byte-by-byte recovery over the internet. | Standard string equality (`==`, `strcmp`) for MAC/token comparison. See §3-3 for HMAC-specific treatment. |
| **Scalar Multiplication Timing (ECDSA/ECDH)** | Variable-time point multiplication in elliptic curve operations leaks information about the scalar (nonce or private key) through execution time. Even ~300ns differences are exploitable with enough samples. | Non-constant-time elliptic curve implementation. See §2-1 for ECDSA-specific treatment. |
| **RSA Decryption Timing** | RSA private-key operations using Chinese Remainder Theorem (CRT) with non-constant-time modular exponentiation leak information about the private key factors through timing. | RSA implementations without blinding. Co-located attacker or network timing with statistical analysis. |
| **Key-Dependent Branch Timing** | Conditional branches based on key bits (e.g., square-and-multiply without Montgomery ladder) leak the bit pattern of the exponent/scalar through execution time. | Unprotected modular exponentiation. Private key operations without constant-time guarantees. |

### §7-2. Network Traffic Analysis

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Encrypted Traffic Classification** | TLS encrypts content but not metadata: packet sizes, timing, direction, and connection patterns. Machine learning classifiers identify visited pages, API endpoints, and user actions from encrypted traffic patterns with >90% accuracy in controlled settings. | HTTPS without traffic padding. Distinctive page sizes or API response patterns. |
| **Compression Ratio Oracle (BREACH)** | HTTP-level compression combined with attacker-controlled input creates a length oracle: when a guess matches existing content, the compressed output is shorter, and the encrypted packet is correspondingly smaller. Byte-by-byte recovery of secrets in compressed responses. | HTTP compression enabled. Reflected user input in responses containing secrets (CSRF tokens, API keys). See `tls-security.md` §3-3 for TLS-level treatment. |

---

## §8. Cryptographic Agility & Algorithm Migration Vulnerabilities

The transition between cryptographic algorithms—whether due to deprecation, standardization, or quantum threat—creates a distinct class of vulnerabilities.

### §8-1. Algorithm Downgrade Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cipher Suite / Algorithm Downgrade** | MitM attacker modifies protocol negotiation to remove strong options, forcing selection of a weak algorithm. Applies to S/MIME, PGP, JOSE, and any protocol with algorithm negotiation. If the receiver does not enforce minimum algorithm strength, the attacker succeeds. (For TLS-specific cipher suite downgrade, see `tls-security.md` §1-2.) | Protocol supports multiple algorithm options. No minimum algorithm strength policy enforced. |
| **Crypto Library Fallback Behavior** | Libraries that silently fall back to weaker algorithms when the preferred algorithm is unavailable (e.g., falling back from AES-256-GCM to AES-128-CBC, or from ECDSA to RSA) without application awareness. | Library with automatic fallback behavior. Application does not verify the actual algorithm used. |

### §8-2. Hardcoded Algorithm Inflexibility

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Non-Agile Algorithm Embedding** | Applications that hardcode `RS256`, `AES-256-CBC`, or specific cipher suites cannot migrate to new algorithms without code changes. When the hardcoded algorithm is deprecated or broken, the entire application requires redeployment. | Algorithm specified as string literals in code. No configuration-based algorithm selection. |
| **Protocol-Locked Algorithms** | Some protocols embed specific algorithms in their specification (e.g., RADIUS uses MD5 for Response-Authenticator). Upgrading requires protocol version changes, which require ecosystem-wide adoption. BlastRADIUS (CVE-2024-3596) exploited RADIUS's MD5 dependency. | Protocol standards mandating specific algorithms. Legacy protocol deployments. |
| **Data Format Algorithm Binding** | Encrypted data stored with algorithm metadata (e.g., JWE headers, CMS algorithm identifiers). When the algorithm is deprecated, all stored data must be re-encrypted—a massive operational undertaking for databases, backups, and archives. | Long-lived encrypted data stores. No re-encryption automation. |

### §8-3. Post-Quantum Migration Risks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Harvest Now, Decrypt Later (HNDL)** | Adversaries capture encrypted traffic today for future decryption by quantum computers. All sessions using RSA or ECDH key exchange are vulnerable to retrospective decryption once cryptographically relevant quantum computers exist. (See `tls-security.md` §10-1 for TLS-specific HNDL treatment.) | Any data with long-term confidentiality requirements encrypted with non-PQ algorithms. State-level adversaries with large-scale traffic capture capability. |
| **Hybrid Implementation Errors** | Combining classical and post-quantum algorithms (e.g., X25519 + ML-KEM) creates new attack surface: incorrect concatenation of shared secrets, missing validation of PQ public keys, or fallback to classical-only when PQ negotiation fails. | Hybrid key exchange implementations. Early PQ adoption without mature library support. |
| **PQ Signature Size Impact** | ML-DSA (Dilithium) signatures are ~2.5KB (vs. ~256B for ECDSA). In protocols like TLS, this increases handshake size, potentially causing fragmentation and middlebox incompatibility. (See `tls-security.md` §10-2 for TLS-specific PQ treatment.) | PQ signatures in latency-sensitive protocols. Network paths with small MTU or intolerant middleboxes. |
| **Cryptographic Inventory Gaps** | Organizations cannot migrate what they cannot inventory. Unknown cryptographic dependencies in third-party libraries, embedded systems, and legacy applications create blind spots. PCI DSS v4.0 requires documented cryptographic inventory after March 2025. | Large organizations with heterogeneous technology stacks. No automated crypto discovery tools deployed. |

---

## §9. End-to-End Encryption (E2EE) Implementation Flaws

E2EE in web applications (messaging, cloud storage, collaboration tools) introduces client-side cryptography that is notoriously difficult to implement correctly.

### §9-1. Key Management in E2EE

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unauthenticated Key Distribution** | The server distributes encryption keys to clients without cryptographic authentication. A malicious or compromised server substitutes its own keys, gaining access to all future encrypted content. Found in Sync and pCloud E2EE cloud storage (ETH Zurich, 2024). | Key distribution via server API without out-of-band verification. No key transparency or safety number comparison. |
| **Key Verification Ceremony Bypass** | E2EE systems that offer but don't require key verification (fingerprint comparison, safety numbers) allow the server to silently perform key substitution for the majority of users who never verify. | Optional key verification. No automatic cryptographic binding between key distribution and verification. |
| **Key Escrow / Recovery Backdoor** | E2EE systems with server-mediated key recovery (e.g., password-based key recovery) expose the encryption key to the server during recovery, breaking the E2EE guarantee. The server (or an attacker compromising the recovery flow) gains access to all encrypted data. | Key recovery mechanism that involves server access to plaintext key material. Password-based recovery without client-side key wrapping. |

### §9-2. Client-Side Crypto Implementation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Fixed IV / Nonce in File Encryption** | Seafile E2EE used a fixed initialization vector for AES encryption of all file chunks. Combined with CTR or CBC mode, this leaks information about file content (see §1-3, §1-1). | Static IV/nonce hardcoded or derived deterministically without message-specific input. |
| **Missing Integrity on Encrypted Chunks** | Encrypting file chunks without per-chunk authentication allows a server to reorder, duplicate, or substitute chunks. The client decrypts garbage or attacker-chosen content for individual chunks without detecting tampering. | Chunk-level encryption without chunk-level MAC. Server trusted for chunk ordering and integrity. |
| **Metadata Leakage** | E2EE protects file content but often exposes: file names, directory structure, file sizes, modification timestamps, sharing relationships, and access patterns. This metadata can reveal sensitive information even without decrypting content. | E2EE design that encrypts content but not metadata. Server-side indexing for search or deduplication. |
| **WebCrypto API Misuse** | The W3C WebCrypto API (`SubtleCrypto`) provides low-level cryptographic primitives in the browser. Its API design requires developers to make correct mode/parameter choices. Common misuses: using `AES-CBC` without separate HMAC, `RSA-OAEP` with default SHA-1, or `ECDSA` with `Math.random()` nonces instead of the internal RNG. | Browser-based E2EE implementation. Developers unfamiliar with cryptographic primitive selection. No high-level crypto library wrapper. |

### §9-3. Protocol-Level E2EE Weaknesses

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **File Injection / Tampering** | E2EE cloud storage services that don't authenticate file metadata allow the server to inject files into a user's account. The injected file appears legitimately encrypted to the client. Found in multiple E2EE providers (Tresorit, Sync, pCloud, Seafile). | File metadata (name, path, sharing info) not cryptographically bound to encryption key. Server controls file listing. |
| **Downgrade to Non-E2EE** | Applications supporting both E2EE and server-side encryption may silently downgrade to non-E2EE mode without user awareness. This can occur during protocol negotiation errors, fallback scenarios, or server-initiated mode changes. | Dual-mode encryption support. No client-side enforcement of E2EE-only mode. |
| **Group Key Management Scaling** | E2EE group messaging requires either O(n) encryptions per message (sender-side fan-out) or a shared group key with complex ratcheting. Group key update on member removal is often implemented as "create new key and hope old members don't have cached copies." | Large groups with frequent membership changes. Lazy group key rotation. |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **MitM / Session Interception** | Network-positioned attacker between client and server | `tls-security.md` + §2-4 (DH/ECDH) + §1-1 (CBC) + §8-1 (downgrade) |
| **Token / Credential Forgery** | Attacker generates valid authentication material | §2-1 (ECDSA) + §2-3 (Ed25519) + §3-1 (length extension) + §4 (PRNG) |
| **Data Exfiltration** | Extracting protected data from encrypted stores or transit | §1 (symmetric modes) + §7-2 (traffic analysis) + §9 (E2EE flaws) |
| **Retrospective Decryption** | Captured traffic decrypted later (quantum or key compromise) | §8-3 (PQC) + `tls-security.md` §1 (weak ciphers) + §5-1 (key exposure) |
| **Supply Chain Compromise** | Attacking crypto libraries or key distribution | §6 (parser vulns) + §5-1 (key leakage) + §9-1 (key distribution) |
| **Infrastructure Compromise** | Exploiting crypto processing for RCE, DoS, or pivoting | §6-3 (CMS parsing) + §3-4 (PBKDF2 DoS) |

---

## CVE / Bounty Mapping (2024–2026)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §2-1 (ECDSA nonce bias) | CVE-2024-31497 (PuTTY P-521) | SSH private key recovery from ~60 public Git signatures. Affected PuTTY, FileZilla, WinSCP, TortoiseGit. |
| §2-1 (ECDSA timing) | CVE-2024-13176 (OpenSSL) | ~300ns timing signal on ECDSA nonce inversion. All OpenSSL versions through 3.4. |
| §2-1 (ECDSA timing, Minerva) | CVE-2024-23342 (python-ecdsa) | Nonce bit-length leakage via signing time. Private key recoverable. |
| §2-1 (ECDSA timing, SM2) | CVE-2025-9231 (OpenSSL ARM64) | SM2 signing timing variations. All OpenSSL < 3.6 on ARM64. |
| §2-2 (RSA padding oracle) | ROBOT (2017, ongoing) | ~27% of Alexa Top 100 vulnerable. F5, Citrix, Palo Alto, IBM, Cisco products. (See `tls-security.md` §2-1 for TLS context.) |
| §6-3 (CMS IV overflow) | CVE-2025-15467 (OpenSSL 3.x) | Pre-auth stack buffer overflow in CMS parsing. RCE achieved by JFrog. |
| §6-3 (multiple parser vulns) | 12 CVEs (OpenSSL, AISLE 2026) | 12 zero-days including one present since 1998. QUIC, PKCS#12, CMS, TLS 1.3, BIO subsystems. |
| §3-2 (MD5 collision) | CVE-2024-3596 (BlastRADIUS) | RADIUS Response-Authenticator forgery via MD5 chosen-prefix collision. |
| §3-4 (bcrypt truncation) | Okta incident (Oct 2024) | Cache key collision via bcrypt 72-byte truncation. Authentication bypass for passwords >72 bytes. |
| §9-2 (E2EE implementation) | ETH Zurich (2024) | Sync, pCloud, Icedrive, Seafile: unauthenticated keys, fixed IVs, file injection. |
| §1-2 (CBC padding oracle) | CVE-2021-31196 (Microsoft Exchange) | ProxyOracle: AES-CBC padding oracle on Exchange FBA cookies. Chained with reflected XSS (CVE-2021-31195) to steal HttpOnly cookies via SSRF redirect, then offline decryption recovers plaintext credentials. First 12 bytes predictable (`Basic ` in UTF-16), eliminating IV recovery. |

---

## Detection Tools

### Offensive / Testing Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **PadBuster** | CBC padding oracle | Automated padding oracle exploitation for CBC-encrypted cookies/tokens |
| **jwt_tool** | JWT implementation | Algorithm confusion, none algorithm, header injection, key brute-force |
| **hashcat / John the Ripper** | Password hash cracking | GPU-accelerated brute-force for bcrypt, PBKDF2, scrypt, Argon2 |
| **nonce-disrespect** | GCM nonce reuse | Detection of GCM nonce reuse across connections |
| **ECDSA Nonce Analysis Scripts** | ECDSA nonce reuse/bias | Lattice-based key recovery from biased or reused nonces |

*For TLS-specific tools (testssl.sh, SSLyze, robot-detect, Raccoon Attack Tool), see `tls-security.md` Detection Tools section.*

### Defensive / Static Analysis Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **CryptoGuard** | Java crypto API misuse | Context-/field-sensitive backward/forward program slicing. 6 CWE categories. |
| **CogniCrypt / CrySL** | Java/Android crypto misuse | CrySL domain-specific language defining correct crypto API usage patterns. Eclipse plugin. |
| **Semgrep (crypto rules)** | Multi-language crypto misuse | Pattern-based detection of insecure crypto function calls (ECB mode, weak hashes, hardcoded keys) |
| **CRYLOGGER** | Android/Java runtime | Dynamic analysis: logs crypto API parameters during execution, validates offline |
| **Cryptosense Analyzer** | Enterprise crypto inventory | Maps all cryptographic operations across application portfolio. PCI DSS 4.0 compliance. |

---

## Summary: Core Principles

### The Fundamental Property

Web cryptographic implementation vulnerabilities arise from a **structural asymmetry**: cryptographic algorithms provide security guarantees only under precise mathematical conditions (unique nonces, constant-time operations, authenticated ciphertext, validated parameters), but the web development ecosystem systematically violates these conditions. The gap between "mathematically secure" and "securely implemented" is where this entire taxonomy lives.

### Why Incremental Fixes Fail

Each vulnerability in this taxonomy has a straightforward "fix" in isolation—use AEAD instead of CBC, use constant-time comparison, validate certificates properly. Yet the vulnerability classes persist because:

1. **Abstraction inversion**: High-level web frameworks expose low-level cryptographic primitives (AES-CBC, RSA-OAEP, ECDSA nonces) that require specialist knowledge to use correctly. The WebCrypto API is a canonical example of developer-hostile design.
2. **Default insecurity**: Libraries and APIs default to insecure options (no certificate validation, weak algorithms, non-constant-time operations) and require explicit opt-in to security.
3. **Composition failures**: Individual components may be secure, but their composition (MAC-then-Encrypt, encryption without integrity, key reuse across protocols) introduces vulnerabilities that neither component has in isolation.
4. **Migration debt**: Cryptographic agility requires infrastructure that most applications lack. When algorithms are deprecated (MD5, SHA-1, RC4, 3DES), the migration is slow, incomplete, and creates transitional vulnerabilities.

### The Structural Solution

The only durable approach is **raising the abstraction level**: developers should interact with goal-oriented APIs ("encrypt this message for this recipient with integrity and authentication") rather than primitive-oriented APIs ("encrypt with AES-256-GCM using this key and this nonce"). Libraries like libsodium, Tink, and age exemplify this approach. Combined with automated cryptographic inventory (§8-3), hardware-backed key management (§5), and protocol-level enforcement of minimum algorithm strength (§8-1), the attack surface can be reduced—though never eliminated—structurally.

---

## References

- Weiss, Y. et al. "What Was Your Prompt? A Remote Keylogging Attack on AI Assistants." USENIX Security 2024.
- Heftrig, E. et al. "KeyTrap: Denial-of-Service Attacks against DNSSEC." ACM CCS 2024. CVE-2023-50387.
- McDonald, G. et al. "Whisper Leak: Side-Channel Attack on Remote Language Models." 2025.
- JFrog Security Research. "CVE-2025-15467: OpenSSL CMS AuthEnvelopedData Buffer Overflow." 2025.
- AISLE. "AI-Discovered 12 OpenSSL Zero-Days." January 2026.
- OpenSSL Security Advisory. CVE-2024-13176 (ECDSA timing), CVE-2025-9231 (SM2 timing). (For TLS-specific OpenSSL CVEs, see `tls-security.md`.)
- PuTTY Advisory. CVE-2024-31497 (P-521 nonce bias).
- python-ecdsa Advisory. CVE-2024-23342 (Minerva timing attack).
- Böck, H. et al. "Return Of Bleichenbacher's Oracle Threat (ROBOT)." USENIX Security 2018.
- Albrecht, M. & Heninger, N. "On Boundedly Generated Subgroups of Finite Groups." Crypto 2024.
- ETH Zurich. "End-to-End Encrypted Cloud Storage: Security Analysis." 2024.
- NIST CSWP 39. "Considerations for Achieving Crypto Agility." December 2025.
- NIST IR 8547. "Transition to Post-Quantum Cryptography Standards." 2024.
- Miles, N. et al. "Methods and Benchmark for Detecting Cryptographic API Misuses in Python." IEEE TSE 2024.
- Cloudflare. "State of Post-Quantum Internet." 2025.
- PortSwigger Research. Top 10 Web Hacking Techniques, TLS Padding Oracle Prevalence, Ed25519 Library Analysis.
- HashiCorp Advisory. CVE-2024-5798 (Vault JWT audience bypass).
- cjwt Advisory. CVE-2024-54150 (Algorithm confusion).
- fast-jwt Advisory. CVE-2025-30144 (Issuer claim bypass).
- Proofpoint / IOActive. "Authentication Downgrade Attacks: MFA Bypass." 2025.
- MystenLabs. "ed25519-unsafe-libs: Vulnerable Ed25519 Implementations." GitHub.

---

*This document was created for defensive security research and vulnerability understanding purposes.*
