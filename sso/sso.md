# Single Sign-On (SSO) Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire SSO attack surface under three orthogonal axes. **Axis 1 (Mutation Target)** is the primary structural axis — it defines *what component of the SSO mechanism is being mutated*. **Axis 2 (Discrepancy Type)** is the cross-cutting axis — it explains *what kind of mismatch or bypass the mutation creates*. **Axis 3 (Attack Scenario)** is the mapping axis — it connects mutations to *real-world impact*.

SSO protocols (SAML, OAuth 2.0, OpenID Connect, Kerberos, CAS) share a common trust architecture: an **Identity Provider (IdP)** asserts identity to a **Service Provider (SP)** or **Relying Party (RP)** via cryptographically signed tokens transmitted through a user agent. Every mutation in this taxonomy exploits a failure in one or more links of this trust chain — signature verification, token binding, redirect validation, session state, claim interpretation, or federation trust.

### Axis 2: Discrepancy Types (Cross-Cutting)

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D1** | Parser Differential | Two parsers (or parser + canonicalizer) interpret the same document differently |
| **D2** | Signature/Digest Decoupling | Signature remains valid but covers different data than what is consumed |
| **D3** | Validation Omission | A required verification step is missing or incomplete |
| **D4** | Trust Boundary Confusion | IdP trust is extended beyond intended scope, or SP trusts unverified sources |
| **D5** | State/Binding Mismatch | Session, nonce, or CSRF state is not properly bound between request and response |
| **D6** | Scope/Claim Escalation | Token scope or identity claims are manipulated beyond authorized boundaries |
| **D7** | Protocol Flow Abuse | Legitimate protocol flow is weaponized via social engineering or redirection |
| **D8** | Cryptographic Weakness | Algorithm confusion, key material exposure, or weak key management |

---

## §1. SAML Authentication Bypass

> **Full taxonomy**: See [SAML Vulnerability Mutation Taxonomy](../saml/saml.md) for comprehensive coverage of XML Signature Wrapping (§1), parser differential attacks (§2), canonicalization exploitation (§3), attribute & element pollution (§4), cryptographic & certificate exploitation including Golden/Silver SAML (§5), XXE attacks (§6), protocol flow & session manipulation (§7), and federation trust & metadata exploitation (§8).

SAML represents the most actively exploited SSO vulnerability class in 2024–2025, driven by the inherent complexity of XML Digital Signatures. The dedicated SAML taxonomy covers the full attack surface: XSW Types 1–8, dual-parser divergence (REXML vs. Nokogiri), void canonicalization (Golden SAML Response), DigestValue comment injection (SAMLStorm), SignedInfo manipulation, namespace confusion, encrypted assertion bypass, Golden/Silver SAML persistence, and SP misconfiguration.

---

## §2. OAuth 2.0 / OpenID Connect Flow Exploitation

> **Full taxonomy**: See [OAuth 2.0 / OpenID Connect Vulnerability Mutation Taxonomy](../oauth/oauth.md) for comprehensive coverage of redirect URI manipulation (§1), authorization code & PKCE exploitation (§2), token lifecycle attacks (§3), state/nonce/CSRF exploitation (§4), scope & consent abuse (§5), client registration exploitation (§6), OIDC discovery & federation attacks (§7), and grant flow abuse including device code phishing (§8).

OAuth/OIDC-specific vulnerabilities — redirect URI validation bypass, PKCE downgrade, code interception, state/nonce manipulation, implicit flow token leakage, device code phishing, consent phishing, dynamic client registration SSRF, OIDC discovery endpoint manipulation, and CI/CD workload identity abuse — are documented in the dedicated OAuth taxonomy. In the SSO context, these mutations combine with SAML-specific attacks (§1) and Kerberos attacks (§7-3) to form the complete SSO attack surface.

---

## §3. Token Claims & Identity Binding Manipulation

SSO tokens (SAML assertions, JWTs, ID tokens) carry identity claims. Manipulating which claims are trusted, how they are interpreted, or their binding to specific contexts creates impersonation and escalation vectors.

### §3-1. Claim Value Manipulation

> SAML-specific claim injection (unsigned AttributeStatement, NameID manipulation, AudienceRestriction bypass) is covered in [SAML Taxonomy §4-2](../saml/saml.md#42-claim--identity-manipulation). JWT claim manipulation is covered in [JWT Taxonomy §4-2](../jwt/jwt.md#42-identity--authorization-claim-manipulation).

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Mutable claim identity binding** | SP/RP identifies users by mutable fields (email, username) instead of immutable `sub`/`NameID`. Attacker changes their email at the IdP to match the victim's identifier | D6, D4 | SP/RP uses email or other mutable claim as primary identifier |
| **Audience confusion** | Token issued for Service A is presented to Service B. If Service B does not verify the `aud` (audience) or `<AudienceRestriction>` matches its own identifier, the token is accepted | D3, D4 | SP does not validate audience; same IdP serves multiple SPs |
| **Issuer confusion / IdP mix-up** | Attacker tricks the client into sending the authorization request to one IdP but processing the response as if it came from another | D4 | Client does not verify issuer matches the intended IdP; multiple IdPs share redirect_uri |

### §3-2. Scope, Permission & Token Cross-Context Abuse

> OAuth-specific scope manipulation, consent bypass, token exchange abuse, and cross-context token reuse are covered in [OAuth Taxonomy §5](../oauth/oauth.md#5-scope-consent--permission-exploitation) and [§3](../oauth/oauth.md#3-token-lifecycle--binding-attacks). CI/CD workload identity token abuse is covered in [OAuth Taxonomy §7-3](../oauth/oauth.md#73-oidc-federation-in-cicd-environments).

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Role/group claim injection** | Modify group membership or role claims in SAML assertions or JWTs when signature verification is bypassed | D2, D6 | Combined with any signature bypass from §1 or §4 |

---

## §4. Cryptographic Mechanism & Algorithm Exploitation

SSO protocols depend on cryptographic operations for token integrity and confidentiality. Weaknesses in algorithm selection, key management, or verification logic undermine the entire trust model.

### §4-1. JWT Algorithm & Key Exploitation

> **Full taxonomy**: See [JWT Vulnerability Mutation Taxonomy](../jwt/jwt.md) for comprehensive coverage of algorithm confusion (§1), key source manipulation (§2), weak key material (§3), and JWE exploitation (§6).

JWT-specific vulnerabilities (algorithm confusion, `alg: none` bypass, JWK/JKU injection, `kid` parameter injection, ECDSA signature exploits, claim validation bypass, brute-force attacks) are documented in the dedicated JWT taxonomy. In the SSO context, these mutations are typically combined with protocol-level attacks (§2, §3, §5) to achieve authentication bypass or privilege escalation.

### §4-2. SAML Cryptographic & Certificate Exploitation

> **Full coverage**: See [SAML Taxonomy §5](../saml/saml.md#5-cryptographic--certificate-exploitation) for Golden SAML, Silver SAML, certificate validation failures, encrypted assertion bypass, and XML Encryption oracle attacks.

---

## §5. Session State & Binding Attacks

SSO introduces complex session relationships: IdP sessions, SP sessions, and the tokens that bind them. Weaknesses in session lifecycle management create opportunities for fixation, replay, and hijacking.

> SAML-specific session attacks (assertion replay, RelayState manipulation, session fixation, SLO failure) are covered in [SAML Taxonomy §7-2](../saml/saml.md#72-session--replay-attacks). OAuth state/nonce/CSRF attacks are covered in [OAuth Taxonomy §4](../oauth/oauth.md#4-state-nonce--csrf-exploitation). JWT token replay is covered in [JWT Taxonomy §4-3](../jwt/jwt.md#43-token-replay--lifecycle-abuse).

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **IdP session hijacking** | Compromise the IdP session cookie (via XSS, network sniffing, or malware). Since the IdP session grants access to all SPs, a single compromise cascades across the entire SSO ecosystem | D5, D4 | IdP session cookie is not adequately protected (missing HttpOnly, Secure, SameSite flags) |

---

## §6. Federation Trust & Metadata Exploitation

SSO federation relies on trust relationships established through metadata exchange between IdPs and SPs. Compromising or manipulating this trust layer affects the entire SSO ecosystem.

### §6-1. SAML Metadata & Federation Trust Exploitation

> **Full coverage**: See [SAML Taxonomy §8](../saml/saml.md#8-federation-trust--metadata-exploitation) for metadata injection/spoofing, metadata URL substitution, WS-Federation metadata repurposing, IdP trust chain manipulation, and SP misconfiguration attacks.

### §6-2. IdP Trust Escalation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Rogue IdP registration** | Register a new IdP in a multi-IdP federation. The rogue IdP asserts arbitrary identities that the SP trusts | D4 | Federation allows dynamic IdP registration without verification |
| **IdP tenant confusion** | In multi-tenant IdP deployments (e.g., Azure AD/Entra ID), attacker creates a tenant and configures it as a trusted IdP for target SPs that accept tokens from any tenant | D4 | SP trusts the IdP's common endpoint (`/common/`) rather than a tenant-specific endpoint |
| **Subdomain takeover → IdP impersonation** | If an IdP's subdomain (e.g., `auth.example.com`) has a dangling DNS record, attacker takes over the subdomain and operates a rogue IdP | D4 | DNS records for IdP subdomains are not properly maintained |

### §6-3. OIDC Federation & Trust Chain Attacks

> **Full coverage**: See [OAuth Taxonomy §7](../oauth/oauth.md#7-oidc-discovery--federation-exploitation) for OIDC discovery endpoint manipulation, IdP trust attacks, multi-tenant confusion, and CI/CD OIDC federation exploitation.

---

## §7. Protocol-Specific Grant Flow Abuse

Each SSO protocol defines specific flows for different client types and deployment scenarios. Abusing the intended semantics of these flows—especially through social engineering—represents a growing attack vector.

### §7-1. OAuth Grant Flow Abuse

> **Full coverage**: See [OAuth Taxonomy §8](../oauth/oauth.md#8-grant-flow-abuse) for device code flow exploitation (the dominant OAuth attack vector in 2024–2025), client credentials abuse, and ROPC grant abuse.

### §7-2. SAML Flow Manipulation

> **Full coverage**: See [SAML Taxonomy §7-1](../saml/saml.md#71-protocol-flow-exploitation) for IdP-initiated SSO injection, InResponseTo bypass, AuthnRequest manipulation, and [SAML Taxonomy §7-2](../saml/saml.md#72-session--replay-attacks) for assertion replay and session fixation attacks.

### §7-3. Kerberos Ticket Exploitation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Golden Ticket** | Forge a Ticket Granting Ticket (TGT) using the compromised `krbtgt` account's password hash. Provides domain-wide, persistent authentication as any user | D8 | Attacker has the krbtgt NTLM hash (post-domain-compromise persistence) |
| **Silver Ticket** | Forge a service ticket using a compromised service account's NTLM hash. Provides access to a specific service as any user without contacting the KDC | D8 | Attacker has a service account's NTLM hash |
| **Unconstrained delegation abuse** | Compromise a server with unconstrained delegation enabled. Any user who authenticates to this server has their TGT cached, allowing the attacker to impersonate them to any service | D4 | Unconstrained delegation configured; high-value user authenticates to the compromised server |
| **Constrained delegation abuse (S4U2Self/S4U2Proxy)** | Exploit Service-for-User (S4U) protocol extensions to obtain service tickets for arbitrary users to constrained services | D4, D6 | Attacker controls a service account with constrained delegation; protocol transition enabled |
| **Diamond Ticket** | Modify a legitimately issued TGT rather than forging one from scratch, making detection significantly harder than Golden Tickets | D8 | Attacker has the krbtgt hash and can intercept/request legitimate TGTs |

---

## §8. Registration & Configuration Exploitation

Vulnerabilities arising from the SSO setup, registration, and configuration process itself — targeting the administrative interface rather than the authentication flow.

### §8-1. Client Registration & Identity Abuse (OAuth/OIDC)

> **Full coverage**: See [OAuth Taxonomy §6](../oauth/oauth.md#6-client-identity--registration-exploitation) for client credential exploitation, dynamic client registration abuse (including SSRF via metadata URIs), and client impersonation.

### §8-2. SP/RP Misconfiguration

> SAML-specific SP misconfigurations (signature validation disabled, certificate validation bypass) are covered in [SAML Taxonomy §8-3](../saml/saml.md#83-sp-misconfiguration).

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Mixed authentication context** | SP accepts both SSO-authenticated and locally-authenticated sessions, with locally-authenticated sessions bypassing SSO security controls (MFA, conditional access) | D3, D4 | Alternative authentication paths exist alongside SSO |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **User Impersonation** | Any SP accepting forged tokens | §1 ([SAML](../saml/saml.md)) + §4-1 ([JWT](../jwt/jwt.md)) + §4-2 | Authenticate as arbitrary user |
| **Account Takeover** | Multi-SP SSO ecosystems | §3-1 + §5-1 + §7-1 | Full account compromise across services |
| **Privilege Escalation** | SPs with role-based access from claims | §3-2 + §1 + §4-1 | Admin access via claim manipulation |
| **Persistent Backdoor** | Enterprise AD/federation environments | §4-2 ([SAML §5](../saml/saml.md#5-cryptographic--certificate-exploitation)) + §7-3 (Golden Ticket) | Long-term undetected access |
| **Token Theft / Lateral Movement** | OAuth/OIDC ecosystems | §2 ([OAuth §3](../oauth/oauth.md#3-token-lifecycle--binding-attacks)) | Cross-service access from single compromise |
| **CI/CD Pipeline Compromise** | Cloud-native OIDC federation | §6-3 ([OAuth §7-3](../oauth/oauth.md#73-oidc-federation-in-cicd-environments)) | Cloud resource access via pipeline tokens |
| **Consent / Device Code Phishing** | OAuth device flow / consent screens | §7-1 ([OAuth §8-1](../oauth/oauth.md#81-device-authorization-grant-device-code-flow-exploitation)) | MFA-bypassing account compromise |
| **WAF/Gateway Bypass** | Network appliances using SSO | §1 ([SAML §1](../saml/saml.md#1-xml-signature-wrapping-xsw)) | Network perimeter bypass |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Product | Impact |
|---------------------|-----------|---------|--------|
| §1 (SAML-specific) | *Multiple CVEs* | *Multiple libraries* | See [SAML Taxonomy CVE table](../saml/saml.md#cve--bounty-mapping-20242026) for XSW, parser differential, SAMLStorm, Golden SAML Response, encrypted assertion bypass CVEs |
| §4-1 (JWT-specific) | *Multiple CVEs* | *Multiple libraries* | See [JWT Taxonomy CVE table](../jwt/jwt.md#cve--bounty-mapping-20242026) for algorithm confusion, JWK injection, claim validation CVEs |
| §2 / §7-1 (OAuth/OIDC-specific) | *Multiple CVEs* | *Multiple products* | See [OAuth Taxonomy CVE table](../oauth/oauth.md#cve--bounty-mapping-20242025) for redirect_uri bypass, PKCE downgrade, device code phishing, consent phishing, MCP OAuth CVEs |

---

## Detection Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **SAML tools** | Various | SAML analysis & attack | See [SAML Taxonomy Detection Tools](../saml/saml.md#detection-tools) for SAML Raider, SAMLReQuest, SAMLTool, and full SAML tooling matrix |
| **EsPReSSO** | Burp Extension | Multi-protocol SSO | Detect SAML, OAuth, OIDC, BrowserId, Facebook Connect; built-in WS-Attacker XSW library |
| **OAUTHScan** | Burp Extension | OAuth 2.0 / OIDC | See [OAuth Taxonomy Detection Tools](../oauth/oauth.md#detection-tools) for full OAuth/OIDC tooling matrix |
| **jwt_tool** | CLI Tool | JWT analysis & attack | See [JWT Taxonomy Detection Tools](../jwt/jwt.md#detection-tools) for full JWT tooling matrix |
| **vulnerable-sso** | Training Platform | Full SSO stack | Intentionally vulnerable SSO implementation for security testing practice |
| **Rubeus** | CLI Tool | Kerberos attacks | Kerberoasting, ticket forging (Golden/Silver), delegation abuse, S4U exploitation |
| **Impacket** | Python Library | Kerberos / NTLM | GetTGT, GetST, Golden/Silver ticket creation, delegation exploitation |
| **Mimikatz** | Post-exploitation | Kerberos / credential | TGT/TGS extraction, Golden/Silver Ticket forging, DCSync |
| **AADInternals** | PowerShell Module | Azure AD / Entra ID | Federation exploitation, Golden SAML, certificate manipulation |

---

## Summary: Core Principles

**The fundamental property that makes the SSO mutation space so expansive is the delegation of trust across protocol boundaries.** SSO systems, by design, require one party (the SP) to accept identity assertions from another party (the IdP) conveyed through an untrusted intermediary (the user agent). Every mutation in this taxonomy exploits a gap in how that trust is established, verified, or maintained — whether it's the gap between two XML parsers interpreting the same signature differently, the gap between an OAuth authorization request and its callback, or the gap between what a Kerberos ticket claims and what the KDC actually issued.

**Incremental fixes fail because the attack surface is inherent to the protocol architecture.** SAML's reliance on XML Signatures — a technology designed for general-purpose XML documents, not authentication tokens — means that every XML parser quirk, canonicalization edge case, and namespace ambiguity becomes a potential authentication bypass. The 2024–2025 wave of SAML vulnerabilities (ruby-saml, xml-crypto, samlify, PHP-SAML) demonstrates this: despite years of patches, researchers continue to find new parser differentials and canonicalization errors because the underlying XML processing stack is too complex to fully constrain (see [SAML Taxonomy](../saml/saml.md) for the full SAML attack surface). Similarly, OAuth's redirect-based architecture means that URL parsing discrepancies and open redirects will always threaten token security (see [OAuth Taxonomy](../oauth/oauth.md) for the full OAuth/OIDC attack surface).

**Structural solutions require reducing protocol complexity and eliminating parser differentials.** For SAML, this means strict XML schema enforcement with minimal extensibility, single-parser architectures, and validating that only signed elements influence authentication decisions (see [SAML Taxonomy Summary](../saml/saml.md#summary-core-principles) for detailed structural analysis). For OAuth/OIDC, OAuth 2.1's deprecation of Implicit Flow, mandatory PKCE, and exact redirect_uri matching address the most common flow-level mutations. For federation trust, zero-trust principles — pinned certificates, audience-restricted tokens, and continuous verification — must replace the implicit trust models that enable Golden SAML, metadata injection, and CI/CD token abuse. The long-term trajectory points toward simpler token formats (like PASETO over JWT — see [JWT Taxonomy](../jwt/jwt.md) for detailed analysis) and hardware-bound credentials (like WebAuthn/passkeys) that eliminate the parsing complexity at the root of most SSO vulnerabilities.

---

*This document was created for defensive security research and vulnerability understanding purposes.*
