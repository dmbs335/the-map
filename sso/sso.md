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

## §1. XML Signature & Digest Verification Bypass (SAML)

SAML authentication relies on XML Digital Signatures (XMLDSig) to bind IdP assertions to cryptographic proof. The complexity of XML parsing, canonicalization, and signature verification creates a uniquely rich mutation surface. This category represents the most actively exploited SSO vulnerability class in 2024–2025.

### §1-1. Classic XML Signature Wrapping (XSW)

The foundational SAML attack. An attacker relocates the signed assertion to a non-processed location in the document and inserts an unsigned, malicious assertion where the SP expects to find it. The signature validates against the original (relocated) assertion, but the SP consumes the attacker-crafted one.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **XSW Type 1–8** | Move signed `<Assertion>` into `<Extensions>`, `<Object>`, or duplicate wrapper; inject unsigned assertion at original location | D2 | SP locates assertion by position (first child) rather than by signature reference |
| **Response-level wrapping** | Wrap the entire `<Response>` and inject a second unsigned `<Response>` containing a forged assertion | D2 | SP does not enforce that exactly one Response exists |
| **Assertion duplication** | Insert a second `<Assertion>` with modified claims; SP processes the unsigned copy if it appears first | D2, D3 | SP does not verify that every processed assertion has a valid signature |

### §1-2. Parser Differential Attacks

When a SAML library uses two different XML parsers for different stages of processing (e.g., signature verification vs. assertion extraction), differences in how they handle edge cases create exploitable gaps.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Dual-parser divergence (REXML vs. Nokogiri)** | REXML and Nokogiri/libxml2 produce entirely different document structures from the same XML input due to differences in namespace handling, DOCTYPE processing, and entity expansion. Signature verifies against Parser A's interpretation; SP extracts identity from Parser B's interpretation | D1 | Library uses separate parsers for signature validation and assertion extraction (e.g., ruby-saml ≤1.17.0) |
| **Namespace confusion** | Redefine namespace prefixes so that `<saml:Assertion>` resolves to different URIs in different parsers. The signature covers the assertion under one namespace; the SP processes a different element under another | D1 | Parsers handle namespace prefix rebinding differently |
| **DOCTYPE/entity handling differential** | Inject DOCTYPE declarations that one parser processes (expanding entities, modifying document) while another ignores them | D1 | One parser supports DOCTYPE; the other strips or ignores it |
| **Round-trip mutation** | Document is parsed → serialized to string → re-parsed. XML comments, CDATA sections, or whitespace that survive the first parse are stripped or interpreted differently on re-parse, changing the effective document structure | D1 | Library performs parse-serialize-reparse cycle (common in ruby-saml) |

### §1-3. Canonicalization Exploitation

XML canonicalization (C14N) normalizes documents before hashing. Errors or edge cases in canonicalization can be weaponized to make signatures validate over unintended content.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Void canonicalization** | Inject a relative namespace URI (e.g., `xmlns:ns="1"`) that causes libxml2's canonicalization to silently return an empty string. The digest is then computed over empty content, producing a predictable hash (`47DEQpj8...` for SHA-256 of empty string) | D2, D8 | Library uses libxml2 for C14N; does not validate that canonical output is non-empty |
| **Golden SAML Response** | Combine void canonicalization with a precomputed signature over the empty string. This single signature validates for *any* modified assertion, since C14N always returns void regardless of content | D2, D8 | Extension of void canonicalization; requires one valid signature from the IdP |
| **Comment injection in DigestValue** | Insert an XML comment inside `<DigestValue>`: `<!-- forged_digest -->legitimate_digest`. Digest validation reads the first child node (the comment's adjacent text = forged value) while signature validation uses the canonicalized form (comments stripped = legitimate value) | D1, D2 | Library extracts DigestValue via first-child rather than text-content; canonicalization strips comments (SAMLStorm / xml-crypto ≤6.0.0) |
| **Exclusive C14N namespace manipulation** | Exploit differences between Exclusive and Inclusive canonicalization in namespace inheritance. Inject namespace declarations that are included in one mode but excluded in another, altering the signed content | D2 | Mismatch between specified and actual canonicalization algorithm |

### §1-4. Attribute & Element Pollution

Exploit how XML parsers handle duplicate or ambiguous attributes and elements to create divergent interpretations.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Attribute pollution** | Define duplicate attributes with different namespace prefixes (e.g., `ID="attack"` and `samlp:ID="legitimate"`). Different parsers select different values based on internal attribute ordering logic | D1 | Parsers disagree on which attribute takes precedence when duplicates exist in different namespaces |
| **Reserved namespace redeclaration** | Redefine reserved XML namespaces (`xml`, `xmlns`) as regular attributes, causing elements to become visible to one parser but hidden from another's XPath queries | D1 | REXML treats reserved namespaces as regular attributes (ruby-saml ≤1.12.4) |
| **Multiple SignedInfo injection** | Insert additional `<SignedInfo>` nodes inside `<Signature>`. If the library does not enforce exactly one SignedInfo, the attacker can provide a second SignedInfo referencing a forged assertion | D2, D3 | Library does not validate SignedInfo uniqueness (xml-crypto CVE-2025-29774) |

### §1-5. Reference & ID Manipulation

Exploit the binding between XML Signature `<Reference URI>` and the signed element's `ID` attribute.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **ID confusion** | Assign the same `ID` value to both a legitimate signed element and an attacker-injected element. The signature reference resolves to the legitimate one, but the SP processes the attacker's element (which appears first or in the expected location) | D2 | SP does not verify that the element it processes is the exact element covered by the reference |
| **Reference URI stripping** | Provide an empty or missing `URI` attribute in `<Reference>`, causing the library to sign the entire document or a default element instead of the specific assertion | D3 | Library does not enforce that Reference URI points to the specific assertion being consumed |
| **XPath injection in Reference** | Inject XPath transforms within the `<Reference>` element that alter which nodes are included in the digest calculation | D2 | Library processes arbitrary XPath transforms without restriction |

---

## §2. Redirect URI & Authorization Flow Manipulation (OAuth/OIDC)

OAuth 2.0 and OpenID Connect rely on redirect-based flows where the authorization server redirects the user agent back to the client application with authorization codes or tokens. The `redirect_uri` parameter is the critical trust anchor.

### §2-1. Redirect URI Validation Bypass

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Missing validation** | Authorization server does not validate `redirect_uri` at all, accepting any attacker-controlled URL | D3 | No redirect_uri validation implemented |
| **Subdomain matching** | Validation checks only the parent domain (e.g., `*.example.com`), allowing redirect to attacker-controlled subdomain (`evil.example.com`) | D3 | Wildcard or suffix-based domain validation |
| **Path traversal** | Validation checks domain + base path but allows path traversal (e.g., `https://legit.com/callback/../../../attacker/steal`) | D3 | Path normalization not applied before comparison |
| **Fragment injection** | Append `#` to redirect_uri causing the authorization code/token to be sent to a legitimate URL but readable via JavaScript at attacker-controlled origin | D7 | SP-side open redirect or XSS on the callback domain |
| **URL parser differential** | Exploit differences between how the authorization server and the client parse URLs (e.g., `https://legit.com@evil.com`, `https://legit.com%40evil.com`, `https://evil.com\@legit.com`) | D1 | Different URL parsing libraries between AS and client |
| **Open redirect chaining** | Use a legitimate open redirect on the whitelisted callback domain to bounce the token to an attacker-controlled destination | D7 | Open redirect exists on a domain within the allowed redirect_uri list |
| **Scheme downgrade** | Change `redirect_uri` from `https://` to `http://` to intercept tokens via network-level MitM | D3 | Authorization server does not enforce HTTPS for redirect_uri |

### §2-2. Authorization Code / Token Interception

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Code interception (no PKCE)** | Intercept the authorization code from the redirect URI before the legitimate client exchanges it. Without PKCE, any party with the code can exchange it for tokens | D3, D5 | Client does not use PKCE; code is transmitted via front channel |
| **PKCE downgrade** | Authorization server supports PKCE but does not enforce it. Attacker sends authorization request without `code_challenge`, then intercepts and exchanges the code without `code_verifier` | D3 | PKCE not mandatory; server accepts requests without code_challenge |
| **Implicit flow token exposure** | In Implicit Grant, access token is returned in URL fragment, exposable via Referer header leaks, browser history, or XSS on the callback page | D7 | Application uses Implicit Grant (deprecated in OAuth 2.1) |
| **Custom scheme hijacking (mobile)** | Multiple apps register the same custom URI scheme (e.g., `myapp://callback`). A malicious app intercepts the authorization code intended for the legitimate app | D4 | Mobile app uses custom URI scheme without platform-verified deep linking |

### §2-3. State & CSRF Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Missing state parameter** | No CSRF protection on the OAuth callback. Attacker initiates OAuth flow with their own account, forces victim's browser to complete it, linking attacker's identity to victim's session | D5 | `state` parameter not implemented or not validated |
| **State fixation** | Attacker obtains a valid state value and forces the victim to use it, allowing the attacker to complete the flow on behalf of the victim | D5 | State is predictable or reusable |
| **Nonce replay (OIDC)** | ID token nonce is not validated, allowing replay of a previously captured ID token to authenticate as the original user | D5 | Client does not verify `nonce` claim in ID token matches the value sent in the authorization request (CVE-2024-10318) |
| **Login CSRF** | Attacker forces victim to log into the attacker's account via SSO, then captures victim's subsequent actions (credentials, sensitive data entered into what the victim believes is their own account) | D5, D7 | Application allows SSO-initiated login without CSRF protection |

---

## §3. Token Claims & Identity Binding Manipulation

SSO tokens (SAML assertions, JWTs, ID tokens) carry identity claims. Manipulating which claims are trusted, how they are interpreted, or their binding to specific contexts creates impersonation and escalation vectors.

### §3-1. Claim Value Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Mutable claim identity binding** | SP identifies users by mutable fields (email, username) instead of immutable `sub`/`NameID`. Attacker changes their email at the IdP to match the victim's identifier at the SP | D6, D4 | SP uses email or other mutable claim as primary identifier |
| **Claim injection via unsigned assertion** | In SAML, inject additional `<AttributeStatement>` elements outside the signed assertion. If the SP extracts attributes from the entire response rather than only from the signed assertion, injected claims are trusted | D2, D3 | SP does not restrict attribute extraction to signed elements only |
| **Nested claim manipulation (JWT)** | Modify nested JSON objects within JWT claims (e.g., `{"user": {"role": "admin"}}`) when signature verification is bypassed or absent | D3, D6 | JWT signature not verified, or combined with algorithm confusion (§4-1) |
| **Audience confusion** | Token issued for Service A is presented to Service B. If Service B does not verify the `aud` (audience) claim matches its own identifier, the token is accepted | D3, D4 | SP does not validate `aud` claim; same IdP serves multiple SPs |
| **Issuer confusion / IdP mix-up** | Attacker tricks the client into sending the authorization request to one IdP but processing the response as if it came from another. Client accepts a token from an attacker-controlled IdP because it doesn't verify the `iss` claim against the intended provider | D4 | Client does not verify issuer matches the intended IdP; multiple IdPs use the same redirect_uri |

### §3-2. Scope & Permission Escalation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Scope upgrade in token request** | Send elevated `scope` parameter in the Access Token Request (not specified in the original authorization). If the AS trusts the scope in the token request without cross-referencing the authorization grant, elevated permissions are issued | D6 | AS does not verify scope in token request matches the authorized scope |
| **Scope manipulation via token reuse** | Steal an access token from Implicit Flow and replay it with manually appended scope parameters against the resource server | D6 | Resource server reads scope from the token request rather than from the token itself |
| **Consent bypass** | Manipulate the authorization request to skip user consent (e.g., `prompt=none` when the user has previously consented to a lesser scope) | D6, D7 | AS grants previously-consented scopes without re-prompting when additional scopes are requested |
| **Role/group claim injection** | Modify group membership or role claims in SAML assertions or JWTs when signature verification is bypassed | D2, D6 | Combined with any signature bypass from §1 or §4 |

### §3-3. Token Cross-Context Abuse

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Client confusion (token substitution)** | Attacker obtains an access token generated for Client A (via an attacker-controlled Implicit Flow app) and presents it to Client B. If Client B accepts tokens from user-controlled parameters without verifying `client_id`, the attacker gains access | D4, D3 | Client uses Implicit Flow; does not verify token's `client_id` matches its own |
| **Token chaining across services** | Steal a token from one service in an SSO ecosystem and use it to access other services that share the same IdP without service-specific authorization checks | D4 | Services within SSO ecosystem do not validate service-specific audience/scope |
| **Workload identity token abuse (CI/CD)** | OIDC tokens issued to CI/CD workflows (e.g., GitHub Actions) are accepted by cloud providers with overly permissive trust policies. Attacker triggers a workflow in a forked/public repo to obtain tokens accepted by the victim's cloud IAM role | D4 | Trust policy uses wildcard matching on repo/branch claims; does not restrict to specific repositories or branches |

---

## §4. Cryptographic Mechanism & Algorithm Exploitation

SSO protocols depend on cryptographic operations for token integrity and confidentiality. Weaknesses in algorithm selection, key management, or verification logic undermine the entire trust model.

### §4-1. JWT Algorithm Confusion

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **RS256→HS256 downgrade** | Change the JWT `alg` header from RS256 (asymmetric) to HS256 (symmetric). Use the IdP's public RSA key (intended only for verification) as the HMAC secret to forge tokens | D8 | Library trusts the `alg` field from the JWT header rather than enforcing a server-side algorithm |
| **`alg: none` bypass** | Set the JWT algorithm to `none` (no signature). Some libraries accept unsigned tokens if the algorithm field is set to none, None, NONE, or other case variants | D8, D3 | Library does not reject `alg: none` or does case-insensitive matching |
| **ECDSA key confusion** | Exploit differences in how ECDSA curve parameters are validated. Provide a crafted public key with a different curve that produces a valid signature for attacker-controlled content | D8 | Library does not validate that the key curve matches the expected algorithm parameters |
| **JWK injection** | Inject a JSON Web Key into the `jwk` or `jku` header parameter of the JWT, pointing to an attacker-controlled key. If the library fetches and trusts the embedded key, the attacker can self-sign tokens | D8, D4 | Library resolves JWK/JKU URLs from the token header without restriction (CVE-2025-24976) |

### §4-2. Key & Certificate Manipulation (SAML/Federation)

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Golden SAML** | Compromise the IdP's token-signing certificate private key (e.g., AD FS signing certificate). Forge arbitrary SAML assertions for any user without touching the IdP | D8 | Attacker has access to the IdP signing key (post-compromise persistence) |
| **Secondary certificate injection** | Federated IdP configurations (e.g., Microsoft Entra ID) accept multiple token-signing certificates. Attacker adds their own certificate as a secondary signer, then forges tokens signed with their key | D4, D8 | Federation configuration allows adding additional signing certificates without sufficient audit controls |
| **Certificate rollover exploitation** | During IdP certificate rollover, both old and new certificates are temporarily trusted. Attacker uses a stolen old certificate (or forces rollover) to sign forged assertions during the overlap window | D8 | SP trusts both old and new certificates during rollover period |
| **Self-signed certificate acceptance** | SP accepts SAML assertions signed with self-signed certificates that are not in the trusted certificate store | D3 | SP does not validate the signing certificate against a trusted root or pinned certificate |

### §4-3. Encrypted Assertion Exploitation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Encrypted assertion bypass** | When optional encrypted assertions are enabled, bypass encryption handling to process unencrypted assertions that the SP should reject | D3 | SP falls back to processing unencrypted assertions when decryption fails (CVE-2024-4985, GitHub Enterprise) |
| **XML Encryption oracle** | Use error messages during decryption as an oracle to recover plaintext assertion content byte-by-byte | D3 | SP returns distinguishable errors for padding vs. decryption failures |

---

## §5. Session State & Binding Attacks

SSO introduces complex session relationships: IdP sessions, SP sessions, and the tokens that bind them. Weaknesses in session lifecycle management create opportunities for fixation, replay, and hijacking.

### §5-1. Session Fixation & Hijacking

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Pre-authentication session fixation** | Attacker sets the victim's session ID before SSO authentication. After the victim authenticates, the session (now bound to the victim's identity) is known to the attacker | D5 | SP does not regenerate session ID after successful SSO authentication |
| **IdP session hijacking** | Compromise the IdP session cookie (via XSS, network sniffing, or malware). Since the IdP session grants access to all SPs, a single compromise cascades across the entire SSO ecosystem | D5, D4 | IdP session cookie is not adequately protected (missing HttpOnly, Secure, SameSite flags) |
| **Relay state manipulation** | In SAML, the `RelayState` parameter carries the post-authentication redirect URL. Attacker modifies RelayState to redirect the authenticated user to a phishing page or attacker-controlled endpoint | D7 | SP does not validate RelayState against an allowlist of permitted URLs |

### §5-2. Token Replay & Lifetime Abuse

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Assertion replay** | Capture a valid SAML assertion and replay it to the SP within its validity window. If the SP does not track consumed assertions, the replayed assertion grants access | D5 | SP does not maintain an assertion ID cache / replay detection |
| **Token lifetime extension** | Modify the `NotBefore`/`NotOnOrAfter` timestamps in a SAML assertion (when signature is bypassed) or `exp` claim in a JWT to extend token validity indefinitely | D6 | Combined with any signature bypass; SP relies solely on token-embedded timestamps |
| **Refresh token abuse** | Steal a long-lived OAuth refresh token and use it to continuously generate new access tokens, maintaining persistent access even after password changes | D5 | Refresh tokens are not bound to the original client/device; not revoked on password change |
| **Single Logout (SLO) failure** | After a user logs out of one SP, their sessions at other SPs remain active. Attacker exploits the orphaned sessions | D5 | SLO not implemented, or back-channel SLO messages fail silently |

---

## §6. Federation Trust & Metadata Exploitation

SSO federation relies on trust relationships established through metadata exchange between IdPs and SPs. Compromising or manipulating this trust layer affects the entire SSO ecosystem.

### §6-1. Metadata Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Metadata injection/spoofing** | Attacker provides malicious IdP metadata during SP configuration, pointing the SP to an attacker-controlled IdP | D4 | SP accepts metadata from untrusted sources; does not verify metadata signatures |
| **Metadata URL substitution** | Replace the IdP metadata URL with an attacker-controlled endpoint that serves crafted metadata containing the attacker's signing certificate | D4 | SP fetches metadata dynamically from a configurable URL without pinning |
| **WS-Federation metadata repurposing** | Extract signed metadata from a legitimate IdP's WS-Federation endpoint and repurpose it for SAML namespace confusion attacks, since the signed XML can provide valid signatures in unexpected contexts | D4, D2 | IdP exposes signed WS-Federation metadata publicly; SP processes metadata-derived signatures without context validation |

### §6-2. IdP Trust Escalation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Rogue IdP registration** | Register a new IdP in a multi-IdP federation. The rogue IdP asserts arbitrary identities that the SP trusts | D4 | Federation allows dynamic IdP registration without verification |
| **IdP tenant confusion** | In multi-tenant IdP deployments (e.g., Azure AD/Entra ID), attacker creates a tenant and configures it as a trusted IdP for target SPs that accept tokens from any tenant | D4 | SP trusts the IdP's common endpoint (`/common/`) rather than a tenant-specific endpoint |
| **Subdomain takeover → IdP impersonation** | If an IdP's subdomain (e.g., `auth.example.com`) has a dangling DNS record, attacker takes over the subdomain and operates a rogue IdP | D4 | DNS records for IdP subdomains are not properly maintained |

### §6-3. OIDC Federation & Trust Chain Attacks

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Overly permissive OIDC trust policy** | Cloud IAM roles trust OIDC tokens from a CI/CD provider with wildcarded conditions (e.g., `repo:*`, `branch:*`), allowing any repository or branch to assume the role | D4 | Trust policy does not restrict to specific repos/branches/environments |
| **Poisoned pipeline execution (PPE) + OIDC** | Attacker modifies a CI/CD pipeline definition (via PR or compromised dependency) to execute code that requests OIDC tokens, then uses those tokens to access cloud resources | D4, D7 | CI/CD platform issues OIDC tokens to any workflow execution, including from forked repos |
| **Issuer URL confusion** | OIDC discovery endpoint (`.well-known/openid-configuration`) serves different configurations based on path traversal or host header manipulation, allowing attacker to inject their own signing keys | D1, D4 | Discovery endpoint is vulnerable to path manipulation or host header injection |

---

## §7. Protocol-Specific Grant Flow Abuse

Each SSO protocol defines specific flows for different client types and deployment scenarios. Abusing the intended semantics of these flows—especially through social engineering—represents a growing attack vector.

### §7-1. OAuth Device Code Flow Exploitation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Device code phishing** | Attacker initiates a device authorization request, obtains a user code, and socially engineers the victim into entering it at the legitimate IdP's device login page. Victim authenticates, granting the attacker's polling client an access token | D7 | Device flow is enabled; no mechanism to verify that the person entering the code is the device operator |
| **Automated device code harvesting** | Scale device code phishing through automated phishing campaigns, generating unique device codes per target and polling for completion | D7 | No rate limiting on device code generation; long polling intervals allow extended attack windows |
| **Device code + MFA bypass** | Since the victim authenticates directly at the IdP (including completing MFA), the attacker's token inherits full MFA-authenticated privileges | D7 | Token does not distinguish between direct and device-code-mediated authentication |

### §7-2. SAML Flow Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **IdP-initiated SSO injection** | In IdP-initiated flows, there is no SP-generated `AuthnRequest` to bind the response to. Attacker crafts a SAML response and submits it directly to the SP's ACS endpoint | D5 | SP accepts unsolicited SAML responses (IdP-initiated SSO enabled) |
| **InResponseTo bypass** | Remove or modify the `InResponseTo` attribute in the SAML response. If the SP does not verify that the response corresponds to a pending authentication request, forged responses are accepted | D5, D3 | SP does not validate `InResponseTo` against outstanding request IDs |
| **AuthnRequest manipulation** | Modify the `AuthnRequest` to request a weaker authentication context (e.g., password-only instead of MFA), then use the resulting assertion at SPs that require stronger authentication | D6, D3 | IdP honors the requested authentication context without enforcing minimum security levels |

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

### §8-1. Client Registration Abuse (OAuth/OIDC)

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Malicious client registration** | Register a new OAuth client with attacker-controlled `redirect_uri`, `logo_uri`, `jwks_uri`, or `sector_identifier_uri`. These URLs may trigger SSRF when the AS fetches them | D4, D7 | Dynamic client registration enabled without authentication or approval |
| **Client impersonation** | Register a client with a name/logo resembling a trusted application to trick users into granting consent | D7 | No verification of client identity during registration |
| **SSRF via client metadata URIs** | Set `logo_uri`, `policy_uri`, `tos_uri`, or `jwks_uri` to internal network addresses. When the AS fetches these for display or validation, it performs server-side requests to internal services | D4 | AS fetches client metadata URIs without SSRF protection |

### §8-2. SP/RP Misconfiguration

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Signature validation disabled** | SP is configured to not require signed assertions (often during development/testing and never re-enabled) | D3 | SP accepts unsigned SAML assertions |
| **Certificate validation bypass** | SP validates the signature but does not verify the signing certificate against a trusted store, accepting any valid self-signed certificate | D3 | SP validates signature math but not certificate trust |
| **Mixed authentication context** | SP accepts both SSO-authenticated and locally-authenticated sessions, with locally-authenticated sessions bypassing SSO security controls (MFA, conditional access) | D3, D4 | Alternative authentication paths exist alongside SSO |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **User Impersonation** | Any SP accepting forged tokens | §1 + §4-1 + §4-2 | Authenticate as arbitrary user |
| **Account Takeover** | Multi-SP SSO ecosystems | §3-1 + §5-1 + §7-1 | Full account compromise across services |
| **Privilege Escalation** | SPs with role-based access from claims | §3-2 + §1 + §4-1 | Admin access via claim manipulation |
| **Persistent Backdoor** | Enterprise AD/federation environments | §4-2 (Golden SAML) + §7-3 (Golden Ticket) | Long-term undetected access |
| **Token Theft / Lateral Movement** | OAuth/OIDC ecosystems | §2 + §5-2 + §3-3 | Cross-service access from single compromise |
| **CI/CD Pipeline Compromise** | Cloud-native OIDC federation | §6-3 + §3-3 | Cloud resource access via pipeline tokens |
| **Consent Phishing** | OAuth device flow / consent screens | §7-1 + §8-1 | MFA-bypassing account compromise |
| **WAF/Gateway Bypass** | Network appliances using SSO | §1 (SAML bypass on FortiGate) | Network perimeter bypass |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Product | Impact |
|---------------------|-----------|---------|--------|
| §1-2 (parser differential) | CVE-2024-45409 | ruby-saml / GitLab | CVSS 10.0. Full auth bypass; sign in as any user |
| §1-2 (parser differential) + §1-4 | CVE-2025-25291, CVE-2025-25292 | ruby-saml ≤1.17.0 | CVSS 8.8. Auth bypass via DOCTYPE/namespace parser differential |
| §1-2 + §1-4 (namespace confusion + round-trip) | CVE-2025-66567 | ruby-saml | Auth bypass via namespace handling differential |
| §1-3 (comment injection in DigestValue) | CVE-2025-29775 | xml-crypto (Node.js) ≤6.0.0 | SAMLStorm. Complete auth bypass via XML comment in DigestValue |
| §1-4 (multiple SignedInfo) | CVE-2025-29774 | xml-crypto (Node.js) ≤6.0.0 | SAMLStorm. Auth bypass via duplicate SignedInfo |
| §1-1 (signature wrapping) | CVE-2025-47949 | samlify (Node.js) <2.10.0 | Critical auth bypass, arbitrary user impersonation |
| §1-1 + §1-3 (void canonicalization) | — (PortSwigger "Fragile Lock") | ruby-saml 1.12.4, PHP-SAML, xmlseclibs | Golden SAML Response — universal signature forgery |
| §1-2 (round-trip + namespace) | — (PortSwigger "SAML Roulette") | ruby-saml / GitLab Enterprise | Unauthenticated admin access on GitLab |
| §4-3 (encrypted assertion bypass) | CVE-2024-4985 | GitHub Enterprise Server | Full SAML SSO bypass via encrypted assertions |
| §4-3 + §1 | CVE-2024-9487 | GitHub Enterprise Server | SAML SSO bypass, unauthorized user provisioning |
| §1-5 + §1-1 | CVE-2024-8698 | Keycloak | SAML signature validation bypass, privilege escalation |
| §1-1 (assertion processing) | CVE-2025-54369 | @node-saml/node-saml | SAML authentication bypass |
| §5-2 (nonce replay) | CVE-2024-10318 | NGINX OIDC Reference Impl. | Session fixation via missing nonce validation |
| §1-1 (SAML bypass on appliance) | CVE-2025-59718, CVE-2025-59719 | Fortinet FortiGate/FortiWeb | CVSS 9.8. Unauthenticated SSO bypass, active exploitation Dec 2025 |
| §4-1 (algorithm confusion) | CVE-2024-54150 | — | JWT algorithm confusion |
| §4-1 (JWK injection) | CVE-2025-24976 | Distribution (container registry) | Signing key injection via JWK verification bypass |
| §3-1 (audience confusion) | CVE-2025-27371 | OAuth implementations | JWT audience value ambiguity |
| §7-1 (device code phishing) | — (ShinyHunters/UNC6040 campaign) | Microsoft 365, Google, Salesforce | Mass enterprise compromise, MFA bypass, data exfiltration (2024–2025) |

---

## Detection Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **SAML Raider** | Burp Extension | SAML message manipulation | Intercept, decode, and modify SAML requests/responses; X.509 cert management; automated XSW attacks |
| **SAMLReQuest** | Burp Extension | SAML AuthnRequest testing | Decode and manipulate SAML authentication requests |
| **EsPReSSO** | Burp Extension | Multi-protocol SSO | Detect SAML, OAuth, OIDC, BrowserId, Facebook Connect; built-in WS-Attacker XSW library |
| **OAUTHScan** | Burp Extension | OAuth 2.0 / OIDC | Automated security checks for OAuth and OIDC flows |
| **jwt_tool** | CLI Tool | JWT analysis & attack | Algorithm confusion, claim tampering, key brute-force, JWK injection |
| **SAMLTool** | PortSwigger Research | SAML parser differential | Identify parser differential and canonicalization vulnerabilities (released with "Fragile Lock" research) |
| **vulnerable-sso** | Training Platform | Full SSO stack | Intentionally vulnerable SSO implementation for security testing practice |
| **Rubeus** | CLI Tool | Kerberos attacks | Kerberoasting, ticket forging (Golden/Silver), delegation abuse, S4U exploitation |
| **Impacket** | Python Library | Kerberos / NTLM | GetTGT, GetST, Golden/Silver ticket creation, delegation exploitation |
| **Mimikatz** | Post-exploitation | Kerberos / credential | TGT/TGS extraction, Golden/Silver Ticket forging, DCSync |
| **AADInternals** | PowerShell Module | Azure AD / Entra ID | Federation exploitation, Golden SAML, certificate manipulation |

---

## Summary: Core Principles

**The fundamental property that makes the SSO mutation space so expansive is the delegation of trust across protocol boundaries.** SSO systems, by design, require one party (the SP) to accept identity assertions from another party (the IdP) conveyed through an untrusted intermediary (the user agent). Every mutation in this taxonomy exploits a gap in how that trust is established, verified, or maintained — whether it's the gap between two XML parsers interpreting the same signature differently, the gap between an OAuth authorization request and its callback, or the gap between what a Kerberos ticket claims and what the KDC actually issued.

**Incremental fixes fail because the attack surface is inherent to the protocol architecture.** SAML's reliance on XML Signatures — a technology designed for general-purpose XML documents, not authentication tokens — means that every XML parser quirk, canonicalization edge case, and namespace ambiguity becomes a potential authentication bypass. The 2024–2025 wave of SAML vulnerabilities (ruby-saml, xml-crypto, samlify, PHP-SAML) demonstrates this: despite years of patches, researchers continue to find new parser differentials and canonicalization errors because the underlying XML processing stack is too complex to fully constrain. Similarly, OAuth's redirect-based architecture means that URL parsing discrepancies and open redirects will always threaten token security.

**Structural solutions require reducing protocol complexity and eliminating parser differentials.** For SAML, this means strict XML schema enforcement with minimal extensibility, single-parser architectures, and validating that only signed elements influence authentication decisions. For OAuth/OIDC, OAuth 2.1's deprecation of Implicit Flow, mandatory PKCE, and exact redirect_uri matching address the most common flow-level mutations. For federation trust, zero-trust principles — pinned certificates, audience-restricted tokens, and continuous verification — must replace the implicit trust models that enable Golden SAML, metadata injection, and CI/CD token abuse. The long-term trajectory points toward simpler token formats (like PASETO over JWT) and hardware-bound credentials (like WebAuthn/passkeys) that eliminate the parsing complexity at the root of most SSO vulnerabilities.

---

*This document was created for defensive security research and vulnerability understanding purposes.*
