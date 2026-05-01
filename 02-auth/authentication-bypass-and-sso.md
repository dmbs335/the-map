# Authentication Bypass & SSO Vulnerability Mutation Taxonomy

**Scope**: Authentication bypass mechanisms at the credential validation, protocol, SSO trust, passwordless, and middleware/framework layers
**Exclusions**: OAuth, JWT, SAML (covered in separate taxonomies); MFA bypass, session management, password recovery, credential acquisition (covered in [account-takeover.md](account-takeover.md))
**Coverage**: Credential validation logic flaws, Kerberos, LDAP, mTLS, CAS, IdP trust architecture, FIDO2/WebAuthn/passkeys, middleware/framework authentication bypass
**Period**: Focused on 2024–2025 discoveries, with foundational techniques included

---

## Classification Structure

This taxonomy organizes authentication bypass and SSO vulnerabilities along three orthogonal axes:

**Axis 1 — Authentication Layer Targeted (Primary Axis):** The structural component of the authentication system being attacked. This document covers five layers: credential validation logic (§1), protocol-level mechanisms (§2), SSO trust architecture (§5), modern passwordless systems (§6), and framework/middleware enforcement (§7). MFA bypass (§3), session lifecycle (§4), password recovery (§8), and credential acquisition (§9) are cross-referenced to [account-takeover.md](account-takeover.md) to avoid duplication.

**Axis 2 — Exploitation Mechanism (Cross-Cutting Axis):** The nature of the flaw or mismatch that enables the bypass. Every technique in §1–§9 exploits one or more of these fundamental mechanism types. This axis explains *why* each mutation works, independent of where it occurs.

**Axis 3 — Impact Scenario (Mapping Axis):** The deployment context and operational outcome when the technique is weaponized. This axis connects individual techniques to real-world consequences.

### Axis 2: Exploitation Mechanism Summary

| Mechanism | Description |
|-----------|-------------|
| **Cryptographic Weakness** | Hash truncation, weak algorithms (MD5, bcrypt limits), predictable token generation |
| **Logic / State Machine Flaw** | Authentication steps that can be skipped, reordered, or applied to wrong sessions |
| **Input Boundary Violation** | Inputs exceeding expected limits causing truncation, overflow, or bypass |
| **Protocol Design Defect** | Inherent weaknesses in authentication protocol specifications |
| **Race Condition / TOCTOU** | Exploiting timing gaps between authentication check and resource access |
| **Trust Boundary Violation** | Abusing trust relationships between federated systems or internal components |
| **Relay / Reflection** | Forwarding or reflecting authentication material to unintended targets |
| **Downgrade / Fallback** | Forcing authentication to weaker methods that can be intercepted |
| **Injection** | Inserting attacker-controlled data into authentication queries or assertions |
| **Social Engineering Amplification** | Combining technical exploits with human factor manipulation |

### Axis 3: Impact Scenario Summary

| Scenario | Architecture | Typical Entry Vectors |
|----------|-------------|----------------------|
| **Full Domain Compromise** | Active Directory / Windows domain | §2 + [ATO §6](account-takeover.md) (ticket forging + credential acquisition) |
| **Cloud/SaaS Account Takeover** | Azure/Entra ID, Okta, Google Workspace | [ATO §4](account-takeover.md) + [ATO §3](account-takeover.md) (MFA bypass + session theft) |
| **Network Appliance Takeover** | Firewalls, VPN gateways, management interfaces | §7 (framework/middleware bypass) |
| **Web Application Access** | Custom web applications | §1 + §7 + [ATO §2](account-takeover.md) (logic flaws + middleware + recovery) |
| **Lateral Movement** | Post-initial-compromise expansion | §2 + §5 (ticket forging + SSO trust) |
| **Persistent Backdoor** | Long-term undetected access | §2 + §5 (ticket forging + Golden dMSA) |

---

## §1. Credential Validation Logic Flaws

Flaws in the fundamental mechanism that compares user-supplied credentials against stored references. These vulnerabilities bypass authentication not by attacking protocols or sessions, but by exploiting implementation defects in the credential verification itself.

### §1-1. Input Boundary Exploits

When credential validation functions have undocumented input limits, inputs exceeding those limits produce truncated or predictable comparison values, enabling bypass.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hash Function Truncation** | Hashing algorithms with fixed input limits (e.g., bcrypt's 72-byte limit) silently truncate excess input, causing the password portion to be excluded from the comparison when combined with long usernames or user IDs | Cache key composed of userId + username + password exceeds hash input limit; cache is used as fallback when primary auth is unavailable |
| **Cache Key Collision** | When authentication results are cached with truncated keys, different credentials produce identical cache entries, allowing authentication with any password that matches the truncated prefix | Authentication cache enabled as high-availability fallback; hash input exceeded by composite key |

The Okta bcrypt incident (October 2024) exemplifies this category: the cache key was a bcrypt hash of the concatenation (userId + username + password). When the username exceeded 52 characters, the combined input exceeded bcrypt's 72-byte limit, effectively truncating or excluding the password portion from the hash — allowing authentication with cached results regardless of the actual password supplied. The fix replaced bcrypt with PBKDF2 for cache key generation.

### §1-2. Injection-Based Authentication Bypass

When user-supplied credentials are incorporated into backend queries without proper sanitization, attackers can manipulate query logic to return valid authentication results for arbitrary credentials.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **LDAP Injection Auth Bypass** | Malicious payloads injected into LDAP bind or search queries modify the filter logic to always evaluate to true (e.g., `(&(uid=*)(userPassword=*))`) | Application constructs LDAP queries from unsanitized user input; LDAP directory used for authentication |
| **SQL Injection Auth Bypass** | Classic `' OR '1'='1` style injections in login queries cause the WHERE clause to return valid user records regardless of credentials | Raw SQL query construction without parameterized queries in authentication endpoints |
| **NoSQL Injection Auth Bypass** | Operator injection (e.g., `{"$gt": ""}`) in MongoDB/NoSQL authentication queries bypasses password comparison | JSON-based authentication APIs without input type validation |
| **LDAP Bind Confusion** | Exploiting LDAP servers that treat empty passwords as anonymous bind (successful authentication) when applications don't validate bind results properly | LDAP anonymous bind enabled; application checks only for bind success/failure without verifying identity |

Recent real-world instances include CVE-2024-37782 (Gladinet CentreStack) where LDAP injection through the username field enabled both unauthorized access and arbitrary command execution, and CVE-2025-29810 (Windows Active Directory Domain Services) where LDAP query manipulation allowed privilege escalation to SYSTEM level (CVSS 7.5).

### §1-3. Default and Hardcoded Credential Exploitation

Authentication systems shipped with known credentials or credential-generation algorithms that are deterministic and reversible.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Factory Default Credentials** | Vendor-shipped username/password pairs that are identical across all deployed units and documented in public manuals | Device not reconfigured after deployment; management interface exposed |
| **Deterministic Credential Generation** | Credentials generated algorithmically from device identifiers (serial number, MAC address) using known or reversible algorithms | Algorithm reverse-engineered or leaked; device identifiers obtainable |
| **Hardcoded Service Account** | Application contains embedded credentials for internal service communication that also grant external access | Service account credentials in source code, firmware, or configuration files |
| **Shared Secret Weakness** | Shared secrets (e.g., RADIUS shared secrets) that are too short, common, or reused across environments | Network path interception capability; weak shared secret |

### §1-4. Cryptographic Comparison Flaws

Defects in how credential-derived values are compared, leading to false positive authentication results.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Timing Side-Channel** | Non-constant-time comparison of password hashes or tokens leaks information about correct characters through response timing differences | High-precision timing measurement possible; comparison not using constant-time function |
| **Type Juggling / Loose Comparison** | Weakly-typed languages (PHP, JavaScript) evaluate pairwise comparisons unexpectedly: `"0" == 0` and `0 == false` both return true, enabling type confusion chains. PHP additionally treats `null == false` and `null == 0` as true, but JavaScript does not (`null` only loosely equals `undefined`). Exploitable for bypassing password checks when magic hashes or type-confused values are supplied. | Loose equality (`==`) instead of strict equality (`===`) in credential comparison |
| **Encoding Normalization Mismatch** | Different Unicode normalization forms for the same visual string produce different hash values, allowing pre-computed hashes to match unexpected inputs | Unicode normalization not applied consistently between registration and authentication |

---

## §2. Protocol-Level Authentication Attacks

Attacks exploiting design or implementation flaws in network authentication protocols. These target the protocol mechanisms themselves rather than application-level logic.

### §2-1. Kerberos Ticket Forging

Creating or manipulating Kerberos tickets without legitimate authority, enabling authentication as arbitrary principals.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Golden Ticket** | Forging Ticket-Granting Tickets (TGTs) using the compromised `krbtgt` account hash. Forged tickets are accepted unconditionally because the KDC's own key signed them, granting authentication as any user including Domain Admins | Attacker has obtained the `krbtgt` NTLM hash (typically via domain controller compromise) |
| **Silver Ticket** | Forging Ticket-Granting Service (TGS) tickets using a compromised service account hash. Unlike Golden Tickets, these target specific services but do not require communication with the KDC, making detection significantly harder | Attacker has obtained a service account NTLM hash (via credential theft or other means) |
| **Diamond Ticket** | Modifying legitimate TGTs obtained from the KDC rather than forging from scratch, blending into normal ticket lifecycle and evading detections that look for tickets with anomalous creation metadata | `krbtgt` hash compromised; attacker wants to evade Golden Ticket detection mechanisms |
| **Golden dMSA** | Exploiting a design flaw in Windows Server 2025's delegated Managed Service Accounts (dMSA) where the `ManagedPasswordId` structure contains only 1,024 possible time-based combinations, reducing password derivation to a trivial brute-force operation | Windows Server 2025 with dMSA deployed; attacker has KDS root key (Domain Admin, Enterprise Admin, or SYSTEM access) |

The Golden dMSA vulnerability, discovered in May 2025, is particularly notable because it attacks a feature explicitly designed to *improve* service account security. Microsoft acknowledged the finding but characterized it as by-design behavior for scenarios where domain controller secrets are already compromised.

### §2-2. LDAP Authentication Attacks

Targeting the LDAP protocol as an authentication backend, beyond the injection attacks covered in §1-2.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Anonymous Bind Exploitation** | LDAP servers configured to accept anonymous binds (empty DN + empty password) as valid authentication, where the application interprets any successful bind as authenticated | LDAP anonymous bind enabled; application doesn't distinguish anonymous from authenticated bind |
| **LDAP Referral Abuse** | Manipulating LDAP referrals to redirect authentication queries to attacker-controlled LDAP servers that return forged positive results | LDAP client follows referrals; no referral validation |
| **Pass-Back Attack** | Reconfiguring a device to point its LDAP authentication to an attacker-controlled server, capturing credentials in cleartext as users authenticate | Administrative access to device LDAP configuration; credentials sent in cleartext |
| **ACL Hierarchy Exploitation** | Leveraging LDAP group hierarchy resolution and ACL misconfigurations to escalate from limited access to SYSTEM level | Misconfigured Active Directory ACLs; LDAP query access to group objects (CVE-2025-29810, CVSS 7.5) |

### §2-3. Mutual TLS (mTLS) Authentication Bypass

Mutual TLS extends standard TLS by requiring the client to present a certificate during the handshake. Implementation flaws in certificate validation, identity extraction, and revocation checking create authentication bypass vectors.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Certificate Validation Without Identity Binding** | Application validates that the client certificate is signed by a trusted CA but does not verify the certificate's subject, SAN, or other identity fields against the expected user identity. Any certificate from the same CA authenticates as any user | mTLS enabled; CA-level trust without per-certificate identity binding |
| **Subject/SAN Extraction Differential** | Different components in the request chain (load balancer, reverse proxy, application) extract identity from different certificate fields (CN, SAN, OU). Attacker obtains a certificate with a permissive SAN or mismatched CN that passes one component's check while being interpreted differently by another | Multi-layer mTLS termination; inconsistent identity extraction logic across components |
| **Proxy Header Trust Without Connection Verification** | mTLS is terminated at the reverse proxy, which forwards the client certificate or its subject in an HTTP header (e.g., `X-Client-Cert`, `X-SSL-Client-DN`). The application trusts this header without verifying that the request actually traversed the proxy — allowing direct requests with injected headers to impersonate any certificate holder | mTLS terminated at proxy; backend trusts certificate headers without connection-level verification |
| **Certificate Revocation Check Bypass** | Application does not check CRL or OCSP for certificate revocation status, or the check fails open (treats OCSP timeout as valid). Revoked certificates continue to authenticate indefinitely | No CRL/OCSP check configured; or fail-open revocation policy |
| **Privilege Escalation via Certificate Attribute Injection** | CA or registration authority allows certificate attributes (OU, role, group) to be influenced by the requester. Attacker requests a certificate with elevated attributes that the application uses for authorization decisions | Self-service or weakly controlled certificate issuance; application derives authorization from certificate attributes (CVE-2025-9312) |

---

## §3. Multi-Factor Authentication Bypass

> **Cross-reference**: MFA bypass mutations are comprehensively covered in [account-takeover.md §4](account-takeover.md). That document includes OTP brute-force (including AuthQuake), MFA flow logic bypasses, channel compromise (AitM/PhaaS/Browser Extension), authentication downgrade attacks, and implementation logic flaws. This section is intentionally omitted here to avoid duplication.

---

## §4. Session & Token Lifecycle Attacks

> **Cross-reference**: Session management attacks (fixation, hijacking, token replay, infostealer cookie extraction, App-Bound Encryption bypass, login nonce leakage) are comprehensively covered in [account-takeover.md §3](account-takeover.md). This section is intentionally omitted here to avoid duplication.
>
> **Unique to this document (SSO Response Manipulation)**: Tampering with SSO authentication responses at the HTTP level — status code tampering (302→200) and SSO header injection (`X-Forwarded-User`, `Remote-User`) — is covered in §7-1 (Internal Header / Routing Exploitation) of this document.

---

## §5. SSO Trust Architecture Attacks

Exploiting trust relationships in federated authentication systems. These attacks target the *trust model* between Identity Providers (IdPs) and Service Providers (SPs), rather than specific protocol implementations. (SAML/OAuth-specific attacks excluded per scope.)

### §5-1. CAS (Central Authentication Service) Protocol Attacks

Vulnerabilities in the CAS SSO protocol and its implementations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Ticket Validation Bypass** | Exploiting flaws in how CAS service tickets are validated, allowing forged or replayed tickets to be accepted | CAS server implementation with incomplete ticket validation; service ticket structure predictable |
| **Service URL Manipulation** | Manipulating the `service` parameter in CAS authentication flows to redirect authenticated tickets to attacker-controlled services | CAS server does not validate service URLs against an allowlist; open redirect in service validation |
| **CAS Proxy Ticket Abuse** | Exploiting CAS proxy authentication where a backend service uses proxy tickets to access other services on behalf of users, escalating access beyond intended scope | CAS proxy authentication enabled; proxy ticket validation insufficient |
| **WebAuthn Integration Flaws** | Vulnerabilities in how CAS integrates with WebAuthn/FIDO2, allowing authentication bypass through flow manipulation | Apereo CAS with WebAuthn enabled (patched April 2025) |

### §5-2. IdP Compromise and Impersonation

Directly compromising or impersonating the Identity Provider to forge arbitrary authentication assertions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **IdP Signing Key Theft** | Stealing the private key used by the IdP to sign authentication assertions, enabling unlimited forging of valid tokens for any user | Access to IdP server, key management system, or backup (SolarWinds/Nobelium-style attack) |
| **AD Synchronization Exploitation** | Targeting organizations that synchronize on-premises AD with cloud IdP (Azure Entra ID), leveraging compromised synchronization credentials to gain unfettered access to cloud identity systems | Azure AD Connect or similar sync service deployed; sync service credentials compromised (Black Hat 2025) |
| **Rogue IdP Registration** | Registering a malicious IdP in a multi-tenant or federated environment that issues fabricated authentication assertions accepted by SPs | Federated trust allows dynamic IdP registration; SP does not validate IdP identity rigorously |

### §5-3. Cross-Domain Trust Exploitation

Abusing trust relationships between domains, forests, or organizational boundaries.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Forest Golden Ticket** | Using a compromised `krbtgt` hash from one forest to forge tickets accepted in trusted forests, leveraging inter-forest trust relationships | Forest trust configured; `krbtgt` hash obtained from one forest; SID filtering not enforced |
| **dMSA Cross-Domain Movement** | The Golden dMSA attack (§2-1) enabling lateral movement across domain boundaries by generating passwords for managed service accounts in trusted domains | Windows Server 2025 dMSA deployed across domains; KDS root key compromised |
| **Trust Account Password Exploitation** | Extracting or brute-forcing the passwords of inter-domain trust accounts to establish unauthorized cross-domain authentication | Trust account passwords not rotated; accessible via LDAP query or SAM database extraction |

### §5-4. SSO Session and FortiOS-Style Abuse

Attacks targeting SSO mechanisms in network appliances and security devices.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **FortiOS SSO Abuse** | Leveraging SSO trust mechanisms in FortiOS to bypass normal authentication flows, particularly through the RADIUS and FSSO (Fortinet Single Sign-On) agents | FortiOS with FSSO configured; attacker understands FSSO agent protocol |
| **Device Registration Bypass** | Bypassing device compliance checks in conditional access policies by manipulating device registration or attestation claims in SSO flows | Conditional access based on device claims; claims not cryptographically bound |

### §5-5. Multi-Backend Identity Collision

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **LDAP-Local DB Registration Collision** | Application supports both LDAP and local database authentication. Attacker registers a local account with the same username as an existing LDAP user — the application merges both identities, granting the attacker access to the LDAP user's resources via locally set credentials | Dual authentication backend (LDAP + local DB) without identity deduplication or backend-binding enforcement |

---

## §6. Passwordless & Modern Authentication Attacks

Targeting FIDO2, WebAuthn, passkeys, and other post-password authentication mechanisms. These represent the newest and least-studied attack surface.

### §6-1. WebAuthn API Manipulation

Exploiting the browser-level WebAuthn API that mediates passkey authentication.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **API Hijacking via Extension** | Malicious browser extension or XSS-injected JavaScript intercepts the WebAuthn `navigator.credentials.create()` and `navigator.credentials.get()` calls, forging both registration and login flows | Malicious extension with sufficient permissions; or XSS vulnerability in the authentication page |
| **Discoverable vs. Non-Discoverable Confusion** | FIDO server fails to distinguish between discoverable (resident) and non-discoverable credentials, allowing authentication with the wrong credential type and potentially as the wrong user | FIDO server implementation bug; credential type not validated during assertion (CVE-2025-26788, StrongKey FIDO Server) |

### §6-2. Passkey Synchronization Attacks

Targeting the cloud synchronization fabric that enables passkey portability across devices.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sync Provider Account Compromise** | If the attacker gains access to the account acting as passkey synchronization fabric (Google Password Manager, Apple iCloud Keychain, Microsoft account), they can replicate all synced passkeys to their own device | User's Google/Apple/Microsoft account compromised; passkeys synced through that provider |
| **Cross-Device Sync Exploitation** | Exploiting the BLE-based cross-device authentication protocol to authenticate from a nearby attacker device by initiating a WebAuthn request that the victim's phone responds to | Attacker within BLE range; cross-device authentication enabled; user not attentive to prompts |

### §6-3. Hardware Token Attacks

Physical and logical attacks against hardware security keys.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Credential Storage Filling** | Filling all credential storage slots on a hardware token, preventing registration of new credentials and forcing fallback to weaker methods | Attacker has brief physical or protocol-level access to the token |
| **Forced Lockout / Factory Reset** | Triggering lockout mechanisms or factory reset on hardware tokens, eliminating registered credentials and forcing recovery flows (which may be weaker) | Knowledge of token PIN exhaustion threshold; or USB/NFC access to trigger reset |
| **BLE Proximity Hijack** | Exploiting the Bluetooth Low Energy transport for CTAP2 to intercept or initiate authentication requests from nearby hardware tokens | Attacker within BLE range; Chrome Android WebAuthn vulnerability (CVE-2024-9956) |

### §6-4. Authentication Method Downgrade

Forcing fallback from phishing-resistant to phishable authentication. (Detailed mechanisms in [account-takeover.md §4-4](account-takeover.md); this section covers the broader architectural implications.)

The fundamental tension is that near-universal phishing-resistant authentication requires **all** fallback methods to be removed — but organizations maintain weaker alternatives for accessibility, compatibility, and disaster recovery. Every maintained fallback method becomes the *effective* security level, regardless of how strong the primary method is.

---

## §7. Middleware & Framework Authentication Bypass

Vulnerabilities in how application frameworks, reverse proxies, and middleware enforce authentication. These bypass authentication not at the credential level but at the *enforcement architecture* level.

### §7-1. Internal Header / Routing Exploitation

Abusing headers or routing mechanisms that frameworks use internally to manage authentication state.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Middleware Subrequest Header Injection** | Setting internal framework headers (e.g., Next.js `x-middleware-subrequest`) that signal to the framework that a request has already been authenticated/authorized by middleware, causing the middleware to be completely skipped | Framework uses internal headers for middleware flow control; external requests not stripped of these headers (CVE-2025-29927, CVSS 9.1) |
| **Trusted Proxy Header Spoofing** | Injecting headers like `X-Forwarded-For`, `X-Real-IP`, or `X-Original-URL` that the application uses to determine client identity or the requested resource, bypassing IP-based access controls or routing to different authentication paths | Application trusts proxy headers without verifying origin; no header stripping at ingress |
| **Internal IP Simulation** | Forging source IP headers to appear as internal/localhost traffic, bypassing authentication that is only required for external requests | Authentication exempted for internal IPs; IP determined from spoofable header |

The Next.js CVE-2025-29927 is paradigmatic: a single header value (`x-middleware-subrequest: middleware`) caused the *entire* authentication middleware to be bypassed. The vulnerability affected one of the most widely used web frameworks with a CVSS score of 9.1.

### §7-2. Alternate Path and Channel Bypass

Reaching authenticated functionality through alternative entry points that lack authentication enforcement.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WebSocket Channel Bypass** | Accessing functionality through WebSocket endpoints that have different (weaker) authentication than the corresponding HTTP endpoints. The authentication on the WebSocket channel may only check for token *presence* without validating authenticity | WebSocket endpoints exposed alongside HTTP; authentication logic not shared (CVE-2024-55591, FortiOS, CVSS 9.8) |
| **API Version Mismatch** | Older API versions still accessible that have weaker or no authentication, while newer versions have been hardened | Deprecated API versions not decommissioned; authentication added only to new versions |
| **Debug / Management Interface Exposure** | Administrative or diagnostic interfaces accessible without authentication when exposed to unintended networks | Management interface bound to all interfaces instead of localhost; no separate authentication for management (CVE-2024-0012, Palo Alto PAN-OS) |
| **Path Traversal to Unprotected Endpoints** | Using directory traversal sequences to navigate from an authenticated path to an unauthenticated one while maintaining the appearance of authorized access | Path normalization inconsistency between reverse proxy and application; encoded traversal sequences not decoded uniformly |

The FortiOS CVE-2024-55591 (CVSS 9.8) exemplifies WebSocket channel bypass: the Node.js WebSocket module only verified the *presence* of a `local_access_token` parameter without validating its authenticity or session binding, allowing unauthenticated attackers to obtain super-admin privileges. Nearly 50,000 vulnerable instances were exposed on the Internet.

### §7-3. HTTP Verb and Method Tampering

Exploiting inconsistent authentication enforcement across HTTP methods.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Method Override Bypass** | Using HTTP method override headers (`X-HTTP-Method-Override`, `X-Method-Override`) to convert a POST to a GET or HEAD, where the alternate method is not subject to the same authentication checks | Framework supports method override headers; authentication enforcement method-specific |
| **HEAD Request Bypass** | Sending HEAD requests to endpoints that only enforce authentication on GET/POST, where the HEAD response reveals information or triggers side effects | Authentication middleware checks method type; HEAD not included in enforcement |
| **CONNECT / TRACE Method Abuse** | Using uncommon HTTP methods that are not covered by authentication middleware rules, potentially reaching backend functionality | Web server forwards unusual methods to the application; authentication ACLs don't cover all methods |

### §7-4. Path Normalization Differential

Exploiting differences in how proxy/WAF and application normalize URL paths, allowing requests to reach authenticated endpoints while appearing to access unauthenticated ones.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Encoded Path Traversal** | Double-encoding, UTF-8 encoding, or other encoding tricks that the WAF/proxy normalizes differently than the application, bypassing path-based authentication rules | WAF normalizes once; application normalizes twice (or vice versa); encoded `/` or `..` sequences treated differently |
| **Trailing Dot/Slash Confusion** | Adding trailing dots, slashes, or other path suffixes that the proxy treats as different paths (bypassing auth rules) but the application treats as equivalent | Proxy path matching is exact; application path matching is fuzzy/normalized |
| **Null Byte Injection** | Inserting null bytes (`%00`) in URL paths where the proxy reads the full path but the application truncates at the null byte, reaching authenticated resources through apparently unauthenticated paths | Language/framework treats null byte as string terminator; proxy/WAF does not |

---

## §8. Password Recovery & Account Takeover

> **Cross-reference**: Password reset/recovery attacks (predictable tokens, token leakage, host header poisoning, recovery flow bypasses, MFA reset via recovery) are comprehensively covered in [account-takeover.md §2](account-takeover.md). This section is intentionally omitted here to avoid duplication.

---

## §9. Credential Acquisition at Scale

> **Cross-reference**: Credential acquisition techniques (credential stuffing, password spraying, variant stuffing, proxy-rotated stuffing, infostealer ecosystem) are comprehensively covered in [account-takeover.md §6](account-takeover.md). This section is intentionally omitted here to avoid duplication.

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Chain |
|----------|-------------|---------------------------|---------------|
| **Full AD Domain Compromise** | On-premises Active Directory | §2 + [ATO §6](account-takeover.md) | Credential stuffing → Golden Ticket (§2-1) |
| **Cloud/SaaS Account Takeover** | Azure/Entra, Okta, Google Workspace | [ATO §4](account-takeover.md) + [ATO §3](account-takeover.md) | Infostealer → Cookie replay → Lateral access via SSO |
| **Network Appliance Takeover** | Firewalls, VPN, management interfaces | §7 + §1 | WebSocket bypass (§7-2) or middleware injection (§7-1) → Admin access |
| **Web Application Access** | Custom applications | §1 + §7 + [ATO §2](account-takeover.md) | LDAP injection (§1-2) → Session fixation → Account takeover |
| **MFA-Protected Account Bypass** | Enterprise with MFA deployed | [ATO §4](account-takeover.md) + §6 | Downgrade attack → AitM interception → Session theft |
| **Persistent Domain Backdoor** | Windows Server 2025 | §2-1 + §5-3 | Golden dMSA (§2-1) → Cross-domain movement (§5-3) → Indefinite access |
| **AD Sync to Cloud Pivot** | Hybrid on-prem + cloud | §5-2 + §2 | AD sync credential compromise (§5-2) → Cloud IdP control → Full tenant |
| **Recovery Flow Exploitation** | Any web application | [ATO §2](account-takeover.md) + [ATO §3](account-takeover.md) | Reset poisoning → Password reset → MFA reset → Full access |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Product | Impact / CVSS |
|---------------------|-----------|---------|---------------|
| §1-1 (Hash Truncation) | Okta Advisory (Oct 2024) | Okta AD/LDAP DelAuth | Auth bypass via bcrypt 52-char truncation; no CVE assigned |
| §1-2 (LDAP Injection) | CVE-2024-37782 | Gladinet CentreStack v13.12 | Unauthorized access + RCE via username field injection |
| §1-2 (LDAP ACL Exploit) | CVE-2025-29810 | Windows AD Domain Services | Privilege escalation to SYSTEM; CVSS 7.5 |
| §2-1 (Golden dMSA) | Semperis Disclosure (May 2025) | Windows Server 2025 dMSA | Auth bypass for all managed service accounts; Microsoft: "by design" |
| MFA (TOTP Brute Force) → [ATO §4-1](account-takeover.md) | Oasis Security (Dec 2024) | Microsoft Azure MFA | AuthQuake: session-parallel TOTP brute-force; no CVE assigned |
| MFA (User Agent Bypass) → [ATO §4-2](account-takeover.md) | Okta Advisory (2024) | Okta SSO Policies | MFA bypass via unknown user agent classification |
| §5-1 (CAS WebAuthn) | Apereo Advisory (Apr 2025) | Apereo CAS 7.x | Authentication bypass in WebAuthn integration; CVSS ~7.5 |
| §5-1 (CAS Flow Mgmt) | Apereo Advisory (Sep 2025) | Apereo CAS 7.x | OAuth/OIDC flow manipulation → auth bypass; CVSS ~7.5 |
| §6-1 (FIDO Credential Confusion) | CVE-2025-26788 | StrongKey FIDO Server 4.10–4.15 | Account takeover via discoverable/non-discoverable credential confusion |
| §6-3 (BLE Proximity Hijack) | CVE-2024-9956 | Google Chrome Android | WebAuthn BLE proximity attack → credential capture |
| §7-1 (Middleware Header) | CVE-2025-29927 | Next.js 11.1.4–12.3.4, 13.0.0–13.5.8, 14.0.0–14.2.24, 15.0.0–15.2.2 | Complete auth middleware bypass; CVSS 9.1 |
| §7-2 (WebSocket Bypass) | CVE-2024-55591 | FortiOS 7.0.x / FortiProxy | Super-admin via WebSocket; CVSS 9.8; zero-day exploited since Nov 2024 |
| §7-2 (Mgmt Interface) | CVE-2024-0012 | Palo Alto PAN-OS | Unauthenticated admin access to management web interface |
| §7-2 (Mgmt Interface) | CVE-2025-0108 | Palo Alto PAN-OS | Auth bypass in management web interface |
| §2-1 (Kerberos Cert Auth) | CVE-2025-26647 | Windows Kerberos | Certificate-based auth bypass when cert issuer not in NTAuth store |
| §2-1 (Kerberos Storage) | CVE-2025-29809 | Windows Kerberos | Security feature bypass via insecure storage of Kerberos keys; CVSS 7.1 |
| §6-1 (WSO2 mTLS) | CVE-2025-9312 | WSO2 Products | mTLS auth bypass → admin privileges on REST/SOAP APIs |
| MFA startup ordering → [ATO §4-2](account-takeover.md) | CVE-2025-62004 | BullWall Server Intrusion Protection | SIP MFA service initializes after login services during startup; authenticated user can log in during the boot-time window before MFA is enforced |
| §5-4 (NTLM Relay) | CVE-2021-33768, CVE-2022-21979 | Microsoft Exchange (ProxyRelay) | NTLM relay between Exchange servers via PrinterBug coercion. Machine accounts in Exchange Servers group have `ms-Exch-EPI-Token-Serialization` right by default, enabling impersonation of any user. Architectural design flaw |
| §7-2 (Pre-auth File Read) | CVE-2018-13379 | Fortinet FortiGate SSL VPN | Pre-auth arbitrary file read via `snprintf` buffer overflow stripping `.json` suffix; leaks session files containing plaintext credentials |
| §7-2 (Hardcoded Backdoor) | CVE-2018-13382 | Fortinet FortiGate SSL VPN | Hardcoded "magic" parameter in login interface allows password reset for any user without authentication |
| §7-2 (Pre-auth File Read) | CVE-2019-11510 | Pulse Secure Connect | Pre-auth arbitrary file read via path traversal in HTML5 Access feature; leaks plaintext session tokens and cached credentials; CVSS 10.0 |

---

## Detection Tools

### Offensive / Testing Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Impacket** | Kerberos, LDAP, SMB | Python library for network protocol interaction; includes GetTGT, GetST, secretsdump |
| **Rubeus** | Kerberos (Windows) | C# Kerberos abuse toolkit: ticket forging, overpass-the-hash, ticket manipulation |
| **Evilginx** | AitM phishing / MFA bypass | Open-source reverse proxy phishing framework for real-time session cookie interception |
| **CrackMapExec / NetExec** | AD reconnaissance + credential testing | Network-wide credential spraying, Kerberos ticket operations |
| **Hashcat / John the Ripper** | Offline credential cracking | GPU-accelerated hash cracking for authentication tokens, TOTP seeds |
| **Burp Suite** | Web authentication testing | HTTP interception, authentication flow analysis, session management testing |
| **Nuclei** | CVE scanning | Template-based vulnerability scanner with auth bypass detection templates |
| **NextSploit** | CVE-2025-29927 | Dedicated scanner/exploiter for Next.js middleware auth bypass |

### Defensive / Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **CrowdStrike Identity Protection** | AD authentication attacks | Real-time identity threat detection; anomalous authentication monitoring |
| **Microsoft Defender for Identity** | AD authentication attacks | Golden Ticket, pass-the-hash detection via DC sensor |
| **Semperis Directory Services Protector** | AD persistence attacks | Golden Ticket, dMSA abuse, DCSync detection and response |
| **OWASP ZAP** | Web authentication testing | Open-source DAST with authentication flow fuzzing |
| **SSOScan** | SSO implementation testing | Automated SSO vulnerability detection (Facebook SSO focused) |
| **BloodHound / SharpHound** | AD attack path analysis | Graph-based analysis of AD trust relationships, delegation, and escalation paths |
| **PingCastle** | AD security assessment | Active Directory health scoring and attack surface analysis |

---

## Summary: Core Principles

### The Root Cause: Trust Materialization Gap

The entire authentication bypass attack surface exists because of a fundamental architectural problem: **authentication is a point-in-time event whose result must be materialized into a persistent, transferable artifact** (session token, Kerberos ticket, cookie, assertion) that subsequent systems trust without re-verifying. Every technique in this taxonomy ultimately exploits the gap between the authentication *event* and the ongoing *trust* in its materialized artifact.

Kerberos tickets can be forged because trust is materialized in a signed data structure, and the signing key is a recoverable secret. Session cookies can be replayed because trust is materialized in a portable browser artifact. MFA can be bypassed through AitM because the attacker intercepts the materialization point. Recovery flows create alternative materialization paths with weaker verification. Even the Golden dMSA attack exploits a flaw in how managed-service-account password *derivation* was materialized as a 1,024-possibility brute-force problem.

### Why Incremental Patches Fail

1. **Defense-in-depth layers are independently attackable**: Each authentication layer (credential verification, MFA, session management, SSO trust) can be bypassed independently. Strengthening one layer does not protect against bypass of another. The 2024–2025 trend of AitM + infostealer chains demonstrates that even "phishing-resistant" MFA is bypassed by attacking the session layer that sits *above* it.

2. **Protocol ossification**: Protocols like Kerberos (designed before modern threat models) and legacy authentication mechanisms cannot be fundamentally redesigned without breaking compatibility with millions of deployed systems.

3. **The fallback problem**: Every authentication system maintains weaker alternatives for disaster recovery, accessibility, or compatibility. The authentication downgrade attacks of 2025 prove that the *effective* security of any system is equal to its weakest maintained fallback method.

4. **Trust boundary proliferation**: The explosion of SSO, federation, cloud synchronization, and hybrid architectures means that authentication trust boundaries are multiplying faster than they can be secured. Each trust relationship (AD ↔ Azure, IdP ↔ SP, LDAP client ↔ server) is an independent attack surface.

### Structural Solutions

The only comprehensive mitigations are those that address the trust materialization gap directly:

- **Device-bound session credentials (DBSC)**: Cryptographically binding session tokens to specific devices prevents replay even if cookies are stolen, addressing §4 entirely.
- **Continuous authentication**: Re-verifying identity throughout a session rather than trusting a single point-in-time authentication event, addressing §4 and reducing the value of §3 bypasses.
- **Zero-fallback MFA policies**: Eliminating all phishable fallback methods, accepting the usability/accessibility trade-off, which is the only defense against §3-3 downgrade attacks.
- **Protocol modernization**: Enforcing AES encryption for all Kerberos operations, mandating modern authentication protocols over legacy mechanisms, and requiring cryptographic channel binding.
- **Credential-less architectures**: Moving toward systems where there is no extractable secret at rest (hardware-bound passkeys without synchronization, certificate-based auth with non-exportable keys), which structurally eliminates §9 credential acquisition attacks.

The trajectory is clear: authentication security must evolve from "verify once, trust forever" to "verify continuously, trust nothing." Until that transition is complete, the techniques documented in this taxonomy will continue to evolve faster than point defenses can contain them.

---

## References

- Semperis, "Golden dMSA: What Is dMSA Authentication Bypass?," July 2025
- Oasis Security, "Microsoft Azure MFA Bypass," December 2024
- IOActive, "Authentication Downgrade Attacks: Deep Dive into MFA Bypass," 2025
- Proofpoint, "Don't Phish-let Me Down: FIDO Authentication Downgrade," 2025
- JFrog, "CVE-2025-29927 - Authorization Bypass in Next.js," March 2025
- Watchtowr Labs, "FortiOS Authentication Bypass CVE-2024-55591," January 2025
- Sekoia, "Global Analysis of Adversary-in-the-Middle Phishing Threats," 2025
- Securing.pl, "CVE-2025-26788: Passkey Authentication Bypass in StrongKey FIDO Server," February 2025
- PortSwigger Research, "The Fragile Lock: Novel Bypasses for SAML Authentication," 2025
- Apereo Foundation, "CAS OAuth/OpenID Connect & WebAuthn Vulnerability Disclosure," April/September 2025
- Varonis, "Cookie-Bite: How Your Digital Crumbs Let Threat Actors Bypass MFA," 2025
- Microsoft Security Blog, "Defending Against Evolving Identity Attack Techniques," May 2025
- Okta Trust Center, "AD/LDAP Delegated Authentication Username Above 52 Characters Security Advisory," November 2024
- ZeroPath, "CVE-2025-9312: WSO2 mTLS Authentication Bypass," 2025
- DeepStrike, "Stealer Log Statistics 2025: Inside the Credential Theft Boom," 2025
- OWASP, "A07 Authentication Failures - OWASP Top 10:2025," 2025
- Hack The Box, "8 Powerful Kerberos Attacks," 2025
- PortSwigger Web Security Academy, "Authentication Vulnerabilities," 2025
- Datadog Security Labs, "Understanding CVE-2025-29927: The Next.js Middleware Authorization Bypass," 2025

---

*This document was created for defensive security research and vulnerability understanding purposes.*
