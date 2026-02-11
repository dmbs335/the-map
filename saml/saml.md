# SAML (Security Assertion Markup Language) Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire SAML attack surface under three orthogonal axes. **Axis 1 (Mutation Target)** is the primary structural axis — it defines *what component of the SAML mechanism is being mutated*. **Axis 2 (Discrepancy Type)** is the cross-cutting axis — it explains *what kind of mismatch or bypass the mutation creates*. **Axis 3 (Attack Scenario)** is the mapping axis — it connects mutations to *real-world impact*.

SAML 2.0 is an XML-based federation protocol where an **Identity Provider (IdP)** issues digitally signed XML assertions about a user's identity, which are consumed by a **Service Provider (SP)** to grant access. The security model depends on XML Digital Signatures (XMLDSig) to bind the IdP's cryptographic proof to the assertion content. The fundamental tension — and the root cause of SAML's expansive vulnerability surface — is that XMLDSig was designed for general-purpose XML documents, not for the constrained use case of authentication tokens. Every XML parser quirk, canonicalization edge case, namespace ambiguity, and signature verification shortcut becomes a potential authentication bypass.

### Axis 2: Discrepancy Types (Cross-Cutting)

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D1** | Parser Differential | Two parsers (or parser + canonicalizer) interpret the same XML document differently |
| **D2** | Signature/Digest Decoupling | Signature remains valid but covers different data than what the SP consumes |
| **D3** | Validation Omission | A required verification step (signature check, certificate validation, replay detection) is missing or incomplete |
| **D4** | Trust Boundary Confusion | IdP trust is extended beyond intended scope, or SP trusts unverified sources |
| **D5** | State/Binding Mismatch | Request-response binding, session state, or relay state is not properly enforced |
| **D6** | Claim/Scope Escalation | Identity claims or authorization attributes are manipulated beyond authorized boundaries |
| **D7** | Protocol Flow Abuse | Legitimate SAML flow semantics are weaponized via manipulation of request parameters |
| **D8** | Cryptographic Weakness | Key material exposure, weak algorithms, or certificate management failures |

---

## §1. XML Signature Wrapping (XSW)

The foundational SAML attack class. XML Signature Wrapping exploits the decoupling between *which elements the signature covers* (determined by the `<Reference URI>`) and *which elements the SP processes for authentication decisions* (determined by the SP's assertion extraction logic). By relocating signed elements and inserting unsigned replacements, the attacker maintains a valid signature while controlling the consumed identity.

### §1-1. Classic Assertion Wrapping

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **XSW Type 1–8** | Move the signed `<Assertion>` into a non-processed location (`<Extensions>`, `<Object>`, a duplicate wrapper, or as a sibling) and inject an unsigned assertion with attacker-controlled claims at the original location. The signature validates against the relocated original; the SP processes the injected copy | D2 | SP locates assertion by position (first child, XPath index) rather than by verifying the signature reference covers the exact element being processed |
| **Response-level wrapping** | Wrap the entire `<Response>` element and inject a second unsigned `<Response>` containing a forged assertion. The signature covers the original (wrapped) Response; the SP processes the outer forged one | D2 | SP does not enforce that exactly one Response exists; does not verify the processed Response is the signed one |
| **Assertion duplication** | Insert a second `<Assertion>` with modified claims into the Response. If the SP processes the first assertion it encounters (by document order) without verifying its signature, the unsigned attacker assertion is consumed | D2, D3 | SP does not verify that every processed assertion has a valid signature; processes assertions by order rather than by reference |
| **samlify-style wrapping** | Insert an unsigned assertion as a sibling or child node. The library validates the signature on the legitimate assertion but extracts identity from the attacker's assertion due to XPath/DOM traversal logic selecting the wrong element | D2, D3 | Library uses XPath queries that return the attacker's assertion instead of the signed one (CVE-2025-47949, samlify <2.10.0) |

### §1-2. SignedInfo & Reference Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Multiple SignedInfo injection** | Insert additional `<SignedInfo>` nodes inside `<Signature>`. If the library does not enforce exactly one SignedInfo, the attacker provides a second SignedInfo whose `<Reference>` points to a forged assertion | D2, D3 | Library does not validate SignedInfo uniqueness (CVE-2025-29774, xml-crypto) |
| **ID confusion** | Assign the same `ID` value to both the legitimate signed assertion and an attacker-injected assertion. The signature reference resolves to the legitimate one, but the SP's extraction logic finds and processes the attacker's element (which appears first or in the expected location) | D2 | SP does not verify that the element it processes is the exact element covered by the signature reference |
| **Reference URI stripping** | Provide an empty or missing `URI` attribute in `<Reference>`. The library signs the entire document or a default element instead of the specific assertion. Attacker injects content elsewhere in the document that is not covered by the signature | D3 | Library does not enforce that Reference URI points to the specific assertion being consumed |
| **XPath injection in Reference** | Inject XPath transforms within the `<Reference>` element that alter which nodes are included in the digest calculation, selectively excluding attacker-modified elements | D2 | Library processes arbitrary XPath transforms without restriction |

---

## §2. Parser Differential Attacks

When a SAML library uses two different XML parsers for different stages of processing (e.g., one for signature verification, another for assertion extraction), differences in how they handle edge cases create exploitable gaps. This category represents the most actively researched SAML vulnerability class in 2024–2025.

### §2-1. Dual-Parser Divergence

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **REXML vs. Nokogiri divergence** | ruby-saml uses REXML for some operations and Nokogiri (backed by libxml2) for others. These parsers produce entirely different document structures from the same XML input due to differences in namespace handling, DOCTYPE processing, entity expansion, and attribute ordering. The signature verifies against one parser's interpretation; the SP extracts identity from the other's | D1 | Library uses separate parsers for signature validation and assertion extraction (ruby-saml ≤1.17.0, CVE-2024-45409, CVE-2025-25291, CVE-2025-25292) |
| **Namespace confusion** | Redefine namespace prefixes so that `<saml:Assertion>` resolves to different namespace URIs in different parsers. The signature covers the assertion under one namespace; the SP processes a different element under another. Namespaces are ideal for XSW attacks because they directly influence how XML elements are identified by XPath queries | D1 | Parsers handle namespace prefix rebinding differently (CVE-2025-25292, CVE-2025-66567) |
| **DOCTYPE/entity handling differential** | Inject DOCTYPE declarations that one parser processes (expanding entities, modifying the document tree) while another ignores or strips them. Entity expansion can alter element content, attribute values, or namespace declarations | D1 | One parser supports DOCTYPE; the other strips or ignores it (CVE-2025-25291) |
| **Round-trip mutation** | Document is parsed → serialized to string → re-parsed. XML comments, CDATA sections, whitespace, or namespace declarations that survive the first parse are stripped, normalized, or interpreted differently on re-parse, changing the effective document structure and breaking the signature-to-content binding | D1 | Library performs parse-serialize-reparse cycle (common in ruby-saml; PortSwigger "SAML Roulette") |
| **libxml2 caching quirks** | Exploit libxml2's internal node caching behavior. When the library caches parsed nodes and reuses them across operations, attacker-injected modifications to the cached structure affect subsequent processing without invalidating the signature | D1 | Library uses libxml2 with internal caching enabled (CVE-2025-23369, GitHub Enterprise Server) |

### §2-2. Encoding & Serialization Differentials

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **CDATA section handling** | Wrap assertion content in CDATA sections. Some parsers include CDATA sections in text content; others strip the CDATA markers. Signature verification may operate on the CDATA-included version while the SP processes the stripped version | D1 | Parsers disagree on CDATA section handling |
| **XML comment stripping differential** | Insert XML comments within critical elements (e.g., `<NameID>admin<!-- -->@evil.com</NameID>`). One parser preserves comments in text extraction; another strips them, yielding different identity values | D1 | Parsers differ in whether comments affect text node extraction |
| **Whitespace normalization** | Inject significant whitespace within attribute values or between elements. Different normalization behaviors between parsers create divergent interpretations | D1 | Parsers apply different whitespace normalization rules |

---

## §3. Canonicalization Exploitation

XML canonicalization (C14N) normalizes documents before hashing for signature verification. Errors, edge cases, or unexpected behaviors in the canonicalization process can be weaponized to make signatures validate over unintended or empty content.

### §3-1. Void & Predictable Canonicalization

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Void canonicalization** | Inject a relative namespace URI (e.g., `xmlns:ns="1"`) that causes libxml2's canonicalization to silently return an empty string instead of the canonicalized XML. The digest is then computed over empty content, producing a predictable hash (`47DEQpj8HttFZJkD...` for SHA-256 of empty string). The attacker precomputes this digest and injects it into the `<DigestValue>` | D2, D8 | Library uses libxml2 for C14N; does not validate that canonical output is non-empty (PortSwigger "Fragile Lock") |
| **Golden SAML Response** | Combine void canonicalization with a precomputed signature over the empty string. This single, static signature validates for *any* modified assertion content, since C14N always returns void regardless of input. Effectively, one captured valid signature from the IdP can be reused indefinitely to forge any assertion | D2, D8 | Extension of void canonicalization; requires one valid signature captured from the IdP |
| **Exclusive vs. Inclusive C14N mismatch** | Exploit differences between Exclusive and Inclusive canonicalization in namespace inheritance. Inject namespace declarations that are included in one mode but excluded in another, altering the signed content while maintaining a valid signature under the declared algorithm | D2 | Mismatch between specified and actual canonicalization algorithm, or the library does not verify which C14N algorithm is used |

### §3-2. DigestValue & Transform Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Comment injection in DigestValue** | Insert an XML comment inside `<DigestValue>`: `<DigestValue><!-- forged_digest_base64 -->legitimate_digest_base64</DigestValue>`. Digest validation reads the first child text node (the comment's adjacent text = forged value) while signature validation uses the canonicalized form (comments stripped = legitimate value) | D1, D2 | Library extracts DigestValue via first-child text node rather than full text-content; canonicalization strips comments (CVE-2025-29775, SAMLStorm, xml-crypto ≤6.0.0) |
| **Transform chain manipulation** | Inject additional `<Transform>` elements into the `<Reference>` that modify which parts of the document are included in the digest. XPath filter transforms can selectively exclude attacker-modified elements | D2 | Library processes arbitrary transforms without restriction or validation |
| **Digest algorithm substitution** | Change the digest algorithm to a weaker one (e.g., SHA-1) that may be easier to collide, or to one that the library handles differently | D8 | Library accepts any declared digest algorithm without enforcement |

---

## §4. Attribute & Element Pollution

Exploit how XML parsers handle duplicate, ambiguous, or adversarial attributes and elements to create divergent interpretations between signature verification and assertion processing.

### §4-1. Attribute-Level Attacks

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Attribute pollution** | Define duplicate attributes with different namespace prefixes (e.g., `ID="attack"` and `samlp:ID="legitimate"`). Different parsers select different values based on internal attribute ordering logic, creating a split between which element the signature references and which the SP processes | D1 | Parsers disagree on attribute precedence when duplicates exist in different namespaces |
| **Reserved namespace redeclaration** | Redefine reserved XML namespaces (`xml`, `xmlns`) as regular attributes. This causes elements to become visible to one parser's XPath queries but hidden from another's, enabling assertion substitution | D1 | Parser treats reserved namespaces as regular attributes (REXML behavior, ruby-saml ≤1.12.4) |

### §4-2. Claim & Identity Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Attribute injection via unsigned elements** | Inject additional `<AttributeStatement>` or `<Attribute>` elements outside the signed assertion. If the SP extracts attributes from the entire Response rather than only from signed assertions, injected claims (roles, groups, email) are trusted | D2, D3 | SP does not restrict attribute extraction to signed elements only |
| **NameID manipulation** | Modify the `<NameID>` element value within a forged assertion (combined with any signature bypass from §1–§3) to impersonate an arbitrary user | D6 | Combined with any signature bypass; SP uses NameID as primary user identifier |
| **Mutable identifier binding** | SP identifies users by mutable fields (email from `<Attribute>`) instead of immutable NameID or persistent identifier. Attacker changes their email at the IdP to match the victim's identifier at the SP | D6, D4 | SP uses mutable claim as primary identifier |
| **Audience restriction bypass** | Modify or remove the `<AudienceRestriction>` element. If the SP does not validate that its own entity ID appears in the audience list, assertions intended for other SPs are accepted | D3, D4 | SP does not enforce AudienceRestriction validation |

---

## §5. Cryptographic & Certificate Exploitation

SAML's security depends on the integrity of signing keys, certificate chains, and the SP's ability to verify that assertions come from trusted IdPs. Compromising or manipulating the cryptographic layer provides the most powerful and persistent attack vectors.

### §5-1. Signing Key Compromise (Golden/Silver SAML)

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Golden SAML** | Compromise the IdP's token-signing certificate private key (e.g., AD FS signing certificate). Extract it using tools like ADFSDump, Mimikatz, or by accessing the Distributed Key Manager (DKM) key from Active Directory. Forge arbitrary SAML assertions for any user, any SP, with any claims — without touching the IdP. Provides persistent, stealthy access even after password resets | D8 | Attacker has admin access to AD FS server; can extract the token-signing private key (Solorigate/SolarWinds, 2020; ongoing technique) |
| **Silver SAML** | In cloud IdP environments (e.g., Microsoft Entra ID), if the organization uses externally generated SAML signing certificates (imported rather than Entra-generated), stealing the external certificate's private key enables response forgery without AD FS compromise. This evades Golden SAML defenses that focus on on-premises AD FS | D8 | Organization imports externally generated signing certificates into Entra ID; attacker compromises the external certificate storage (Semperis, 2024) |
| **Secondary certificate injection** | Federated IdP configurations accept multiple token-signing certificates. Attacker adds their own certificate as a secondary signer via admin API or compromised federation settings, then forges assertions signed with their key | D4, D8 | Federation configuration allows adding additional signing certificates without sufficient audit controls |
| **Certificate rollover exploitation** | During IdP certificate rollover, both old and new certificates are temporarily trusted. Attacker uses a stolen old certificate (or forces premature rollover via configuration manipulation) to sign forged assertions during the overlap window | D8 | SP trusts both old and new certificates during rollover period; overlap window is excessively long |

### §5-2. Certificate Validation Failures

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Self-signed certificate acceptance** | SP accepts SAML assertions signed with self-signed certificates that are not in the trusted certificate store. Attacker generates their own key pair, signs a forged assertion, and the SP accepts it | D3 | SP validates signature math but does not verify the signing certificate against a trusted root or pinned certificate |
| **Certificate trust chain bypass** | SP validates only the leaf certificate but does not verify the full chain up to a trusted root CA. Attacker uses a certificate signed by an untrusted CA | D3 | No complete certificate chain validation |
| **Expired certificate acceptance** | SP accepts assertions signed with expired certificates. Attacker uses a previously stolen certificate that has since expired | D3 | SP does not check certificate validity period |
| **Signature validation disabled** | SP is configured to not require signed assertions — often enabled during development/testing and never re-enabled for production | D3 | SP accepts unsigned SAML assertions |

### §5-3. Encrypted Assertion Exploitation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Encrypted assertion bypass** | SP expects encrypted assertions but falls back to processing unencrypted assertions when decryption fails. Attacker submits a plaintext forged assertion, and the SP processes it without encryption | D3 | SP does not enforce mandatory encryption; falls back to plaintext processing (CVE-2024-4985, GitHub Enterprise Server, CVSS 10.0) |
| **Signature-before-decryption bypass** | When a signature is found on the outer Response element before the encrypted assertion is decrypted, the SP may validate the outer signature and then trust the decrypted inner content without additional verification. Attacker manipulates the encrypted assertion content while the outer signature remains valid | D2, D3 | SP validates signature at the wrong processing stage (CVE-2024-4985) |
| **XML Encryption oracle** | Use distinguishable error messages during decryption (padding errors vs. schema errors vs. successful decryption) as a Bleichenbacher-style oracle to recover plaintext assertion content byte-by-byte | D3 | SP returns distinguishable errors for different decryption failure modes |

---

## §6. XXE & XML-Specific Attacks

SAML messages are XML documents, inheriting all XML-specific attack vectors. While not SAML-specific, these attacks are particularly impactful in SAML contexts because SAML endpoints accept attacker-controlled XML input.

### §6-1. XML External Entity (XXE) Injection

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Classic XXE in SAML Response** | Inject a DOCTYPE declaration with external entity references into the SAML Response. When the SP's XML parser processes the document, it resolves external entities, enabling file read (`file:///etc/passwd`), SSRF (`http://internal-server/`), or denial of service | D3 | SP's XML parser has external entity processing enabled; does not strip DOCTYPE declarations |
| **Blind XXE via out-of-band exfiltration** | Use external entity references to exfiltrate data to an attacker-controlled server via DNS or HTTP callbacks when direct output is not visible | D3 | Parser resolves external entities; network egress is possible |
| **Entity expansion DoS (Billion Laughs)** | Inject nested entity definitions that expand exponentially (e.g., 10 levels of entity references, each expanding 10x), consuming memory and CPU to denial-of-service the SP | D3 | Parser does not limit entity expansion depth or total expansion size |
| **XXE to key exfiltration** | Use XXE file read to access the SP's private key, SAML configuration, or other secrets stored on the filesystem, enabling further SAML attacks (e.g., decrypting encrypted assertions, impersonating the SP) | D3 | Private keys or configuration files are accessible to the web server process |

---

## §7. Protocol Flow & Session Manipulation

SAML defines specific request-response flows (SP-initiated, IdP-initiated) and session management mechanisms. Abusing flow semantics, request-response binding, and session state creates authentication bypass and fixation vectors.

### §7-1. Flow Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **IdP-initiated SSO injection** | In IdP-initiated flows, there is no SP-generated `AuthnRequest` to bind the response to. Attacker crafts a SAML Response and submits it directly to the SP's Assertion Consumer Service (ACS) endpoint. Without a pending request to match, the SP has no baseline to validate against | D5 | SP accepts unsolicited SAML Responses (IdP-initiated SSO enabled) |
| **InResponseTo bypass** | Remove or modify the `InResponseTo` attribute in the SAML Response. If the SP does not verify that the Response corresponds to a pending AuthnRequest (matching `InResponseTo` to a stored request ID), forged Responses are accepted | D5, D3 | SP does not validate `InResponseTo` against outstanding request IDs |
| **AuthnRequest manipulation** | Modify the `AuthnRequest` to request a weaker authentication context class (e.g., `urn:oasis:names:tc:SAML:2.0:ac:classes:Password` instead of `urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract`). The IdP authenticates the user with weaker assurance, and the resulting assertion is accepted by SPs requiring stronger authentication | D6, D3 | IdP honors the requested authentication context without enforcing minimum security levels per SP |
| **Destination mismatch** | Modify the `Destination` attribute in the SAML Response to a different SP's ACS URL. If the receiving SP does not verify that `Destination` matches its own ACS endpoint, cross-SP token replay is possible | D3, D5 | SP does not validate the Destination attribute |

### §7-2. Session & Replay Attacks

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Assertion replay** | Capture a valid SAML assertion (e.g., from network interception, browser history, or log files) and replay it to the SP within its validity window. Without assertion ID tracking, the same assertion grants access repeatedly | D5 | SP does not maintain an assertion ID cache / replay detection; no `OneTimeUse` enforcement |
| **Assertion lifetime extension** | Modify the `NotBefore`/`NotOnOrAfter` `<Conditions>` timestamps in a SAML assertion (when signature is bypassed) to extend token validity far beyond the intended window | D6 | Combined with any signature bypass; SP relies solely on assertion-embedded timestamps |
| **RelayState manipulation** | Modify the `RelayState` parameter (which carries the post-authentication redirect URL) to redirect the authenticated user to a phishing page or attacker-controlled endpoint after successful SSO | D7 | SP does not validate RelayState against an allowlist of permitted URLs |
| **Pre-authentication session fixation** | Set the victim's session ID before SSO authentication (e.g., via cookie injection). After the victim authenticates via SAML, the session — now bound to the victim's identity — is known to the attacker | D5 | SP does not regenerate session ID after successful SAML authentication |
| **Single Logout (SLO) failure** | After a user logs out of one SP, their sessions at other SPs remain active because SLO messages fail silently or are not implemented. Attacker exploits orphaned sessions at SPs that didn't receive the logout signal | D5 | SLO not implemented, or back-channel SLO messages fail silently |

---

## §8. Federation Trust & Metadata Exploitation

SAML federation relies on trust relationships established through metadata exchange between IdPs and SPs. Compromising or manipulating this trust layer affects the entire SSO ecosystem.

### §8-1. Metadata Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Metadata injection/spoofing** | Attacker provides malicious IdP metadata during SP configuration, pointing the SP to an attacker-controlled IdP with the attacker's signing certificate | D4 | SP accepts metadata from untrusted sources; does not verify metadata signatures |
| **Metadata URL substitution** | Replace the IdP metadata URL with an attacker-controlled endpoint that serves crafted metadata containing the attacker's signing certificate and SSO endpoints | D4 | SP fetches metadata dynamically from a configurable URL without pinning or integrity verification |
| **WS-Federation metadata repurposing** | Extract signed metadata from a legitimate IdP's WS-Federation endpoint and repurpose it for SAML namespace confusion attacks. The signed XML from WS-Federation can provide valid signatures in SAML contexts | D4, D2 | IdP exposes signed WS-Federation metadata publicly; SP processes metadata-derived signatures without context validation |
| **Metadata certificate injection** | Inject additional signing certificates into the IdP metadata. If the SP trusts all certificates listed in metadata without verifying them against an out-of-band trust anchor, the attacker's certificate is accepted | D4 | SP trusts all certificates in metadata without independent verification |

### §8-2. IdP Trust Escalation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Rogue IdP registration** | Register a new IdP in a multi-IdP federation. The rogue IdP asserts arbitrary identities that the SP trusts | D4 | Federation allows dynamic IdP registration without verification |
| **IdP tenant confusion** | In multi-tenant IdP deployments (e.g., Azure AD/Entra ID), attacker creates a tenant and configures it as a trusted IdP for target SPs that accept tokens from any tenant via common endpoints | D4 | SP trusts the IdP's common/multi-tenant endpoint rather than a tenant-specific one |
| **Subdomain takeover → IdP impersonation** | If an IdP's subdomain (e.g., `auth.example.com`) has a dangling DNS record, attacker takes over the subdomain and operates a rogue IdP that serves valid-looking metadata and assertions | D4 | DNS records for IdP subdomains are not properly maintained; dangling CNAME |

### §8-3. SP Misconfiguration

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Signature validation disabled** | SP is configured to not require signed assertions — often set during development/testing and accidentally left in production | D3 | SP accepts unsigned SAML assertions |
| **Certificate validation bypass** | SP validates the signature math (verifies the cryptographic signature) but does not verify the signing certificate against a trusted store. Any valid self-signed certificate is accepted | D3 | SP validates signature but not certificate trust |
| **Mixed authentication context** | SP accepts both SSO-authenticated and locally-authenticated sessions. Locally-authenticated sessions bypass SSO security controls (MFA, conditional access, IP restrictions) | D3, D4 | Alternative authentication paths exist alongside SAML SSO |
| **ACS endpoint exposed without rate limiting** | SP's Assertion Consumer Service endpoint accepts unlimited SAML Responses without rate limiting, enabling brute-force or automated attack attempts | D3 | No rate limiting on ACS endpoint |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **User Impersonation** | Any SP accepting forged assertions | §1 + §2 + §3 | Authenticate as arbitrary user including admin |
| **Universal Signature Forgery** | SPs using libxml2-based libraries | §3-1 (Golden SAML Response) | One captured signature → forge any assertion indefinitely |
| **Persistent Backdoor** | Enterprise AD/federation environments | §5-1 (Golden/Silver SAML) | Long-term undetected access surviving password changes |
| **WAF/Gateway Bypass** | Network appliances with SAML auth | §1 (XSW on FortiGate/FortiWeb) | Network perimeter bypass via forged SAML |
| **Privilege Escalation** | SPs with role-based access from claims | §4-2 + §1 | Admin access via claim injection |
| **Lateral Movement** | Multi-SP SSO ecosystems | §5-1 + §8-2 | Access all federated services from IdP compromise |
| **Data Exfiltration** | SPs with XXE-vulnerable parsers | §6-1 | Server-side file read, SSRF, secret exfiltration |
| **Cross-SP Token Replay** | Multi-SP environments | §7-1 + §7-2 | Reuse assertion across services |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Product | Impact |
|---------------------|-----------|---------|--------|
| §2-1 (parser differential) | CVE-2024-45409 | ruby-saml / GitLab | CVSS 10.0. Full auth bypass; sign in as any user |
| §2-1 (DOCTYPE differential) | CVE-2025-25291 | ruby-saml ≤1.17.0 | CVSS 8.8. Auth bypass via DOCTYPE parser differential |
| §2-1 (namespace differential) | CVE-2025-25292 | ruby-saml ≤1.17.0 | CVSS 8.8. Auth bypass via namespace parser differential |
| §2-1 (namespace handling) | CVE-2025-66567 | ruby-saml ≤1.12.4 | Auth bypass via incomplete namespace fix |
| §3-2 (DigestValue comment) | CVE-2025-29775 | xml-crypto (Node.js) ≤6.0.0 | SAMLStorm. Complete auth bypass via XML comment injection in DigestValue |
| §1-2 (multiple SignedInfo) | CVE-2025-29774 | xml-crypto (Node.js) ≤6.0.0 | SAMLStorm. Auth bypass via duplicate SignedInfo |
| §1-1 (signature wrapping) | CVE-2025-47949 | samlify (Node.js) <2.10.0 | Critical auth bypass, arbitrary user impersonation |
| §3-1 (void canonicalization) | — (PortSwigger "Fragile Lock") | ruby-saml 1.12.4, PHP-SAML, xmlseclibs | Golden SAML Response — universal signature forgery via void C14N |
| §2-1 (round-trip + namespace) | — (PortSwigger "SAML Roulette") | ruby-saml / GitLab Enterprise | Unauthenticated admin access on GitLab |
| §2-1 (libxml2 caching) | CVE-2025-23369 | GitHub Enterprise Server | Auth bypass via libxml2 caching quirk |
| §5-3 (encrypted assertion bypass) | CVE-2024-4985 | GitHub Enterprise Server | CVSS 10.0. Full SAML SSO bypass via encrypted assertion handling flaw |
| §5-3 + §1 | CVE-2024-9487 | GitHub Enterprise Server | SAML SSO bypass, unauthorized user provisioning |
| §1-2 (reference + wrapping) | CVE-2024-8698 | Keycloak | SAML signature validation bypass, privilege escalation |
| §1-1 (XSW on HaloITSM) | CVE-2024-6202 | HaloITSM | Critical SAML user impersonation |
| §1-1 (assertion processing) | CVE-2025-54369 | @node-saml/node-saml | SAML authentication bypass |
| §1-1 (SAML bypass on appliance) | CVE-2025-59718, CVE-2025-59719 | Fortinet FortiGate/FortiWeb | CVSS 9.8. Unauthenticated SSO bypass, active exploitation Dec 2025 |
| §5-1 (Silver SAML) | — (Semperis, 2024) | Microsoft Entra ID | SAML response forgery via externally generated certificates |
| §3-1 (simpleSAMLphp C14N) | — (Hackmanit, 2024) | simpleSAMLphp / xmlseclibs | Signature validation bypass via canonicalization flaw |

---

## Detection Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **SAML Raider** | Burp Extension | SAML message manipulation | Intercept, decode, and modify SAML requests/responses; X.509 certificate management; automated XSW Type 1–8 attacks. Major 2.0 release (July 2024) |
| **SAMLReQuest** | Burp Extension | SAML AuthnRequest testing | Decode and manipulate SAML authentication requests |
| **EsPReSSO** | Burp Extension | Multi-protocol SSO | Detect SAML, OAuth, OIDC flows; built-in WS-Attacker XSW library |
| **SAMLTool** | PortSwigger Research Tool | SAML parser differential | Identify parser differential and canonicalization vulnerabilities; released with "Fragile Lock" research (2025) |
| **WS-Attacker** | Research Framework | XML Signature attacks | XML Signature Wrapping, XML-based DoS, SOAPAction spoofing |
| **saml-decoder** | CLI Tool / Web | SAML message inspection | Decode, decompress, and inspect SAML Requests and Responses |
| **SAML Tracer** | Browser Extension | SAML flow debugging | Capture and display SAML messages in browser traffic |
| **ADFSDump** | Post-exploitation | AD FS key extraction | Extract AD FS token-signing certificate, DKM key, and configuration for Golden SAML |
| **AADInternals** | PowerShell Module | Azure AD / Entra ID | Federation exploitation, Golden SAML, Silver SAML, certificate manipulation |
| **shimit** | CLI Tool (Python) | Golden SAML forging | Forge SAML tokens using compromised IdP signing certificate |
| **vulnerable-sso** | Training Platform | Full SSO stack | Intentionally vulnerable SSO implementation for security testing practice |

---

## Summary: Core Principles

**The fundamental property that makes the SAML mutation space so expansive is the use of XML Digital Signatures — a general-purpose technology designed for arbitrary XML documents — to secure authentication tokens.** XML's inherent complexity (namespaces, canonicalization, DTDs, entities, multiple parsing strategies, extensible schemas) provides an enormous attack surface that authentication protocols were never meant to expose. Every XML parser quirk, every canonicalization edge case, every namespace ambiguity becomes a potential authentication bypass. SAML's architects chose XML for its flexibility and extensibility; attackers exploit that same flexibility to decouple what the signature covers from what the SP consumes.

**The 2024–2025 wave of SAML vulnerabilities demonstrates that this attack surface is irreducible without fundamental architectural change.** Despite over a decade of XSW awareness and patches, researchers continue to find new parser differentials (ruby-saml, xml-crypto), new canonicalization bypasses (void C14N, comment injection), and new wrapping techniques (samlify, node-saml). The PortSwigger "Fragile Lock" and "SAML Roulette" research showed that even mature, heavily-audited libraries remain vulnerable because the underlying problem — two-parser architectures, complex C14N algorithms, and flexible document structures — cannot be fully constrained within the XML ecosystem. The SAMLStorm vulnerabilities in xml-crypto demonstrated that even single-parser implementations are vulnerable when digest validation logic has subtle type confusion bugs.

**Structural solutions require eliminating the XML processing complexity at the root of the problem.** Within SAML: strict XML schema enforcement with minimal extensibility, mandatory single-parser architectures (verifying that the exact element covered by the signature is the exact element consumed for authentication), validation that canonical output is non-empty before computing digests, and enforcement of exactly-one constraints on all critical elements (SignedInfo, Assertion, Response). Beyond SAML: migration toward simpler token formats (OIDC with JWT/PASETO) that do not require XML parsing, canonicalization, or dual-parser architectures. For organizations that must continue using SAML, the minimum safe configuration requires: certificate pinning (not trust-on-first-use), mandatory encryption with strict enforcement (no plaintext fallback), AudienceRestriction validation, InResponseTo binding, assertion replay detection, and regular library updates. The emergence of Golden/Silver SAML as a persistence technique post-compromise underscores that SAML key material must be treated with the same criticality as domain admin credentials.

---

## References

- OASIS SAML 2.0 Core Specification
- W3C XML Signature Syntax and Processing (XMLDSig)
- W3C XML Encryption Syntax and Processing
- W3C Exclusive XML Canonicalization
- OWASP SAML Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- PortSwigger, "The Fragile Lock: Novel Bypasses For SAML Authentication" (2025): https://portswigger.net/research/the-fragile-lock
- PortSwigger, "SAML Roulette: The Hacker Always Wins" (2025): https://portswigger.net/research/saml-roulette-the-hacker-always-wins
- WorkOS, "SAMLStorm: Critical Authentication Bypass in xml-crypto" (2025): https://workos.com/blog/samlstorm
- GitHub Security Lab, "GHSL-2024-329/330: Auth Bypasses in ruby-saml" (2025): https://securitylab.github.com/advisories/GHSL-2024-329_GHSL-2024-330_ruby-saml/
- Endor Labs, "CVE-2025-47949: samlify SSO Bypass" (2025): https://www.endorlabs.com/learn/cve-2025-47949-reveals-flaw-in-samlify-that-opens-door-to-saml-single-sign-on-bypass
- ProjectDiscovery, "GitHub Enterprise SAML Auth Bypass (CVE-2024-4985)" (2024): https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass
- Semperis, "Meet Silver SAML: Golden SAML in the Cloud" (2024): https://www.semperis.com/blog/meet-silver-saml/
- Sygnia, "Detection and Hunting of Golden SAML Attack": https://www.sygnia.co/threat-reports-and-advisories/golden-saml-attack/
- Hackmanit, "XML Signature Validation Bypass in simpleSAMLphp and xmlseclibs" (2024): https://hackmanit.de/en/blog-en/82-xml-signature-validation-bypass-in-simplesamlphp-and-xmlseclibs/
- Juraj Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012): https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf

---

*This document was created for defensive security research and vulnerability understanding purposes.*
