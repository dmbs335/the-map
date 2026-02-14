# SAML Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

Security Assertion Markup Language (SAML) is an XML-based open standard for exchanging authentication and authorization data between identity providers (IdPs) and service providers (SPs). Its reliance on XML as a transport format — combined with a complex trust model involving cryptographic signatures, multi-party message passing, and diverse library ecosystems — creates an exceptionally broad mutation surface. Vulnerabilities in SAML do not stem from a single flaw but from the fundamental tension between XML's structural flexibility and the rigid guarantees that digital signatures are supposed to provide.

This taxonomy organizes the entire SAML attack surface along three axes. **Axis 1 (Mutation Target)** defines *what structural component* of the SAML protocol is being attacked — this is the primary organizational axis. **Axis 2 (Discrepancy Type)** describes *what kind of mismatch or gap* enables the attack — this cross-cutting axis explains why each mutation works. **Axis 3 (Attack Scenario)** maps *where and how* the mutation is weaponized in real-world deployments.

### Axis 2: Discrepancy Types (Cross-Cutting)

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D1** | Signature-Content Binding Gap | The signed portion of the document diverges from the portion the SP processes for business logic |
| **D2** | Parser Differential | Two XML parsers (or the same parser in different modes) produce different document trees from identical input |
| **D3** | Canonicalization Divergence | The C14N transform produces unexpected output (empty, truncated, or semantically altered), breaking digest assumptions |
| **D4** | Validation Omission | A required verification step (signature, recipient, timestamp, audience) is skipped entirely |
| **D5** | Trust Boundary Confusion | Assertions valid for one trust context are accepted in another (cross-SP, cross-tenant, cross-environment) |
| **D6** | Temporal Validation Failure | Time-based constraints (NotBefore, NotOnOrAfter, replay windows) are not enforced or are enforced with excessive tolerance |
| **D7** | Cryptographic Material Compromise | Signing keys or certificates are stolen, forged, or externally controllable, enabling assertion forgery at the source |

### Fundamental Root Cause

SAML's security model depends on a **fragile chain**: an XML document is constructed, canonicalized, digested, signed, transmitted, received, parsed, signature-verified, and then *a potentially different portion* is extracted for business logic. Every link in this chain — construction, canonicalization, parsing, verification, extraction — may be performed by different code, different libraries, or different configurations. The mutation space exists in every gap between these processing stages.

---

## S1. XML Signature Wrapping (XSW)

XML Signature Wrapping exploits the structural separation between the signed reference (identified by URI) and the element the SP actually processes for authentication decisions. By relocating, duplicating, or nesting XML elements, an attacker can make the signature verify against a legitimate element while the SP processes a forged one.

### S1-1. Response-Level Wrapping

The attacker duplicates or relocates the entire `<samlp:Response>` element, positioning the forged copy where the SP's XPath query will find it first.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Post-Signature Clone (XSW1)** | A cloned unsigned `<Response>` is inserted *after* the existing `<Signature>` element. The SP processes the first `<Response>` it encounters (the forged one) while signature verification targets the original via URI reference. | SP uses non-specific XPath (e.g., `//Response`) rather than URI-anchored lookup |
| **Pre-Signature Clone (XSW2)** | A cloned unsigned `<Response>` is inserted *before* the `<Signature>` element. Parser ordering determines which element the SP consumes. | SP selects elements by document order rather than by `ID` attribute matching |
| **Envelope Inversion** | The original signed Response is wrapped inside the forged Response as a child element (e.g., within `<samlp:Extensions>`). The SP processes the outer Response; signature verification follows the URI into the nested original. | SP does not enforce maximum document depth or structural schema |

### S1-2. Assertion-Level Wrapping

The attacker targets the `<saml:Assertion>` element specifically, injecting forged assertions while preserving the signed original.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Pre-Assertion Injection (XSW3)** | An unsigned forged `<Assertion>` is placed before the legitimate signed Assertion within the Response. The SP extracts the first Assertion by document order. | SP does not verify that every Assertion carries a valid signature |
| **Intra-Assertion Injection (XSW4)** | A forged unsigned Assertion is nested *inside* the signed Assertion as a child element. The SP's XPath query traverses into the nested forged copy. | SP uses descendant axis XPath (`//Assertion`) that matches nested elements |
| **Assertion Swap (XSW5)** | The values within the signed Assertion are modified (e.g., `NameID` changed to admin). The original unmodified Assertion is appended to the document with its Signature stripped, serving as a decoy. | Signature verification checks the modified copy by position rather than by `ID` reference |
| **Post-Signature Assertion (XSW6)** | Similar to XSW5, but the original unsigned Assertion copy is placed immediately after the `<Signature>` element rather than at the document end. | Position-dependent signature verification logic |

### S1-3. Extension/Object Block Embedding

Schema-permitted extension points in SAML provide containers where complete signed structures can be hidden or relocated.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Extensions Block Embedding (XSW7)** | A cloned unsigned Assertion is embedded within the `<samlp:Extensions>` element of the Response. The SP processes this forged Assertion while the signature validates against the original Assertion in its expected position. | SP does not restrict Assertion extraction to the immediate Response children |
| **Object Block Embedding (XSW8)** | The original signed Assertion is relocated into a `<ds:Object>` element within the `<ds:Signature>` block. A forged Assertion replaces it at the top level. The signature's URI reference can still resolve to the original inside `<ds:Object>`. | SP processes assertions by position; signature verification follows URI references into `<ds:Object>` |
| **Encrypted Assertion Wrapping** | In systems supporting encrypted assertions, a valid signed Response is embedded inside a `<ds:Object>` element. Signatures found only after decryption are not re-validated, allowing the outer forged assertion to pass. (CVE-2024-9487) | Encrypted assertions enabled; post-decryption signature extraction not validated |

### S1-4. Namespace-Assisted Wrapping

Namespace manipulation enhances signature wrapping by making elements invisible to one processing stage while visible to another.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Namespace Redeclaration Hiding** | A forged `<Signature>` element is placed at the Assertion level with a redeclared namespace (e.g., `xml:xmlns='http://www.w3.org/2000/09/xmldsig#'`). One parser treats this as a valid Signature; another treats it as an unknown element and skips it. Combined with XSW to place a legitimate signature elsewhere. | Parser-specific handling of `xml:` prefix namespace redeclaration |
| **Namespace-Scoped Element Hiding** | Elements are placed in a namespace that the signature verification module recognizes but the SP's business logic ignores (or vice versa), effectively creating invisible containers. | Namespace-aware vs. namespace-agnostic XPath queries in different stages |

---

## S2. XML Parser Differential Attacks

Parser differentials exploit the fact that SAML implementations frequently use multiple XML parsers — or the same parser in different configurations — for signature verification vs. business logic extraction. When two parsers construct different document trees from the same input, the attacker can make the signed content and the processed content diverge.

### S2-1. Dual-Parser Divergence

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Nokogiri vs. REXML Differential** | Ruby-SAML uses Nokogiri (libxml2-backed) for signature verification and REXML (pure Ruby) for Assertion extraction. Identical XPath queries return different nodes due to structural divergences in tree construction. An attacker crafts XML that both parsers accept but interpret differently. (CVE-2025-25291, CVE-2025-25292) | Ruby-SAML < 1.18.0 using dual-parser architecture |
| **libxml2 vs. Custom Parser** | PHP SAML implementations using libxml2 for one stage and a custom or different parser for another exhibit similar divergence in namespace handling, attribute ordering, and DOCTYPE processing. | Any implementation using heterogeneous parser stack |
| **DOM vs. SAX Divergence** | DOM parsers build complete in-memory trees while SAX parsers process events sequentially. Inconsistencies in entity resolution, namespace scoping, and error handling between the two models create divergent interpretations. | Implementations mixing DOM and SAX processing stages |

### S2-2. Attribute Resolution Conflicts

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Duplicate Attribute Pollution** | When an element contains both `ID="1"` and `samlp:ID="2"`, namespace-agnostic attribute lookups (e.g., `node.attribute('ID')`) return unpredictable results depending on parser implementation. The signature module and the business logic module may resolve different `ID` values, breaking the signature-to-assertion binding. | Parser does not guarantee attribute resolution order for namespace-colliding attributes |
| **Default Namespace Attribute Shadowing** | XML attributes do not inherit default namespaces, but some parsers incorrectly apply default namespace to attributes. This creates phantom namespace qualifications that cause attribute lookups to fail or return wrong values in one parser but not another. | Divergent default namespace application to attributes |

### S2-3. DOCTYPE and DTD Processing Differentials

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DOCTYPE ATTLIST Injection** | `<!ATTLIST>` declarations in an internal DTD define default attribute values. REXML applies these defaults (e.g., setting a conflicting namespace declaration), while Nokogiri/libxml2 may ignore them. This allows an attacker to make REXML see a completely different namespace structure than the signature verifier. (CVE-2025-25291) | REXML processing with DTD enabled; Ruby < 3.4.2 |
| **Entity Definition Differential** | Custom entity declarations in internal DTDs are expanded by some parsers but rejected by others. An attacker defines entities that, when expanded, alter the semantic content of the Assertion visible to only one parser. | Mixed DTD processing policies across parser stages |

### S2-4. Round-Trip Mutation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Parse-Serialize-Reparse Mutation** | When a SAML document is parsed, serialized, and re-parsed (common in middleware chains), structural mutations can occur: attribute ordering changes, namespace declarations move, whitespace is normalized differently. Signatures verified on the first parse may not match the re-parsed structure. | Multi-stage processing pipelines with serialization between stages |
| **Comment-Induced Round-Trip** | XML comments injected between text nodes (e.g., `admin<!---->@evil.com`) are stripped during canonicalization but may cause text node splitting during parsing. After round-trip, the split text nodes may recombine differently, altering the extracted value. | Text node extraction uses first-child-only semantics |

---

## S3. Canonicalization Exploitation

XML Canonicalization (C14N) is the process of transforming XML into a canonical byte-stream form before digest computation. Attacks on canonicalization exploit edge cases where the C14N output diverges from what either the signer or verifier expects.

### S3-1. Void Canonicalization

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Relative URI Canonicalization Failure** | Introducing a relative namespace declaration (e.g., `xmlns:ns="1"`) causes the C14N algorithm to encounter an unresolvable relative URI. Per spec, this should produce an error, but many implementations silently return an empty string. The digest of an empty string (`SHA-256: 47DEQpj8...`) is predictable, allowing the attacker to forge a matching `<DigestValue>`. (CVE-2025-66568, CVE-2025-66567) | Implementation returns empty string on C14N error rather than failing hard |
| **Namespace Error Swallowing** | Similar to relative URI failure but triggered by malformed namespace URIs, circular namespace references, or namespace declarations that exceed implementation limits. The C14N output degrades to empty, enabling predictable digest forgery. | Permissive error handling in C14N implementation |
| **Forced Empty Canonicalization** | The attacker constructs XML where the signed element, after C14N processing, produces an empty or near-empty canonical form (e.g., by using only namespace nodes that are excluded by exclusive C14N). The attacker then sets the DigestValue to the hash of the expected empty output. | Exclusive C14N with carefully crafted namespace exclusion |

### S3-2. Comment and Whitespace Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Comment Injection Identity Spoofing** | XML comments within `<NameID>` (e.g., `admin@legit.com<!-->.evil.com`) are stripped during C14N, so the signature verifies against `admin@legit.com.evil.com`. But the SP's text extraction may stop at the comment boundary, extracting only `admin@legit.com`. (CVE-2017-11427, CVE-2017-11428) | SP extracts text using first text node rather than full concatenated text content |
| **CDATA Section Differential** | CDATA sections (`<![CDATA[...]]>`) are resolved to text during C14N but may be preserved or split by certain parsers during text extraction, altering the effective value the SP processes. | Parser-specific CDATA handling in text extraction |
| **Insignificant Whitespace Injection** | Whitespace between XML elements is insignificant per schema but may be preserved differently by various C14N modes (C14N 1.0 vs. C14N 1.1 vs. exclusive C14N). This can alter digest values or create processing divergence. | Mixed C14N algorithm versions across signer and verifier |

### S3-3. Comment-Digest Divergence (SAMLStorm)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DigestValue Comment Injection** | An XML comment containing the forged digest is injected into the `<DigestValue>` element: `<DigestValue><!--forged_digest-->legitimate_digest</DigestValue>`. The digest verification code reads the *first child node* (the comment containing the forged digest) while C14N strips the comment, making signature verification pass against the legitimate digest. (CVE-2025-29775) | xml-crypto <= 6.0.0; digest extraction uses firstChild rather than textContent |
| **SignatureValue Comment Injection** | Similar technique applied to `<SignatureValue>`: inject a comment to make the verification code read a different signature value than what C14N produces, enabling signature bypass in conjunction with digest manipulation. (CVE-2025-29774) | Same firstChild extraction pattern in SignatureValue processing |

---

## S4. Signature Validation Bypass

Rather than manipulating XML structure, these attacks exploit implementations that perform incomplete, incorrect, or absent signature validation.

### S4-1. Signature Absence Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Signature Stripping** | The `<ds:Signature>` element is completely removed from the SAML Response. Implementations that treat missing signatures as "not required" rather than "validation failure" accept the unsigned assertion as valid. | SP configured with optional signature verification or default-accept policy |
| **Assertion Signature Removal** | In a Response containing both Response-level and Assertion-level signatures, only the Response-level signature is removed (or vice versa). The implementation validates whichever signature remains but processes content from the unsigned portion. | SP validates only one signature level but processes elements from both |
| **Selective Signature Stripping** | In responses containing multiple Assertions, signatures are removed from specific Assertions while leaving others signed. The SP validates one signed Assertion and then processes all Assertions including the unsigned ones. | SP applies signature validation to the first Assertion only |

### S4-2. Certificate and Key Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Self-Signed Certificate Substitution** | The attacker generates a self-signed certificate, signs the forged SAML Response with it, and includes the certificate in the `<ds:KeyInfo>` element. SPs that extract the verification key from the message itself (rather than a pre-configured trust store) will validate the forged signature. | SP trusts embedded KeyInfo certificates without checking against IdP trust store |
| **Certificate Cloning** | The legitimate IdP certificate is cloned (subject, issuer, validity copied) with a new keypair. The SP's certificate validation checks metadata fields but not the actual public key fingerprint. | Certificate validation based on DN/issuer matching rather than key pinning |
| **KeyInfo Injection** | A `<ds:KeyInfo>` element containing an attacker-controlled public key is injected into the Signature block. Implementations that prioritize embedded key material over pre-configured IdP keys will use the attacker's key for verification. | Implementation preference for inline key material over configured trust anchors |

### S4-3. Algorithm Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Algorithm Downgrade** | The `<ds:SignatureMethod>` or `<ds:DigestMethod>` algorithm URI is changed to a weaker algorithm (e.g., SHA-1, MD5) or a non-standard algorithm that the implementation handles insecurely. | SP does not enforce an algorithm allowlist |
| **"None" Algorithm Injection** | The algorithm identifier is set to a value indicating "none" or is left empty. Implementations that fail to validate the algorithm may skip verification entirely. | No algorithm validation before verification execution |
| **HMAC Confusion** | The algorithm is changed from an asymmetric algorithm (RSA-SHA256) to an HMAC algorithm. If the implementation uses the IdP's public key (or certificate) as the HMAC secret, the attacker can sign with the publicly available key material. | Implementation does not enforce algorithm family consistency |

### S4-4. Reference and Transform Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Empty Reference URI** | The `<ds:Reference URI="">` targets the entire document. The attacker modifies elements outside the expected signed scope while the digest still covers (or appears to cover) the document root. | Ambiguous scope definition when URI is empty |
| **Reference URI Mismatch** | The Reference URI is changed to point to a different element than the Assertion the SP processes. The signature verifies against the referenced element; the SP consumes a different one. | SP does not verify that the signed Reference URI matches the processed Assertion's ID |
| **Transform Chain Injection** | Additional `<ds:Transform>` elements are injected into the signature's transform chain, altering what data the digest is computed over (e.g., an XPath transform that excludes the attacker-modified elements). | SP does not restrict permitted Transform algorithms |

---

## S5. XML Injection and Entity Attacks

SAML's XML foundation inherits the full spectrum of XML parsing vulnerabilities. These attacks target the XML layer rather than the SAML protocol layer.

### S5-1. XML External Entity (XXE) Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Classic XXE via DOCTYPE** | A `<!DOCTYPE>` declaration with an external entity reference (e.g., `<!ENTITY xxe SYSTEM "file:///etc/passwd">`) is injected into the SAML Response. When the XML parser resolves the entity, it reads local files or makes outbound HTTP requests. | XML parser has external entity resolution enabled (default in many parsers) |
| **Out-of-Band XXE (OOB-XXE)** | The external entity triggers an HTTP request to an attacker-controlled server, exfiltrating file contents via URL parameters. This works even when the entity value is not reflected in the SAML processing output. | External entity resolution + outbound HTTP allowed |
| **Parameter Entity XXE** | Parameter entities (`%entity;`) in the DTD subset are used instead of general entities, bypassing filters that block `&entity;` syntax in the document body. | Parser processes parameter entities in internal DTD subset |
| **XXE via SAML Metadata** | The XML parser processes SAML metadata documents (IdP or SP metadata) that contain malicious entity declarations. Metadata is often fetched automatically from configured URLs. | Automatic metadata refresh with vulnerable XML parsing |

### S5-2. XML Entity Expansion (DoS)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Billion Laughs (Exponential Expansion)** | Nested entity definitions create exponential expansion: each entity references the previous one multiple times. A <1KB payload expands to gigabytes in memory. `<!ENTITY lol9 "&lol8;&lol8;&lol8;...">` | No entity expansion depth or size limits |
| **Quadratic Blowup** | A single large entity is repeated many times in the document body. Avoids depth-based detection but still causes quadratic memory consumption. | Entity expansion limits based on depth but not total size |
| **Recursive Entity Loop** | Circular entity references (`<!ENTITY a "&b;"><!ENTITY b "&a;">`) cause infinite processing loops, exhausting CPU. | No circular reference detection in entity resolution |

### S5-3. XSLT Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Transform-Based XSLT Execution** | A malicious `<xsl:stylesheet>` is embedded within a `<ds:Transform>` element in the Signature block. XSLT processing occurs *before* signature verification, so the signature can be self-signed or invalid. The XSLT can read local files (`unparsed-text('/etc/passwd')`) and exfiltrate them via HTTP. | XML processor supports XSLT transforms; no Transform algorithm allowlist |
| **XSLT-Based SSRF** | The XSLT payload uses `document()` or `unparsed-text()` functions to make outbound HTTP requests to internal services, enabling SSRF from the SAML processing endpoint. | XSLT processor permits network access functions |

### S5-4. SAML XML Injection (IdP-Side)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **InResponseTo Attribute Injection** | The SAML Request ID (reflected in the `InResponseTo` attribute of the Response) is crafted to break out of the XML attribute context and inject new XML elements or attributes. Since the injection occurs *before* the IdP signs the response, the forged content is included in the valid signature. | IdP builds XML via string concatenation without proper encoding |
| **User Attribute Injection** | User-controlled attributes (name, email, phone) are included in the SAML Assertion without XML encoding. An attacker sets their display name to a value like `"/>admin<saml:Attribute Name="role"><saml:AttributeValue>admin`, injecting additional attributes or role assignments into the signed Assertion. | IdP uses template-based XML construction without escaping |
| **Issuer/Audience Injection** | The SP's EntityID or other SP-controlled values reflected in the Assertion are crafted to inject XML, altering the Assertion's audience restrictions or other conditions. | IdP reflects SP-provided values without sanitization |

---

## S6. Assertion Content and Protocol-Level Attacks

These attacks target the semantic content of SAML Assertions and the protocol flow rather than the XML or signature layers.

### S6-1. Replay Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Simple Assertion Replay** | A valid SAML Response is captured (via browser inspection, proxy interception, or XSS) and resubmitted to the SP's Assertion Consumer Service (ACS) endpoint. | SP does not track consumed Assertion IDs; no `InResponseTo` validation |
| **Cross-Session Replay** | A captured Assertion is replayed from a different browser, session, or IP address. The SP does not bind the Assertion to the original authentication context. | No session binding, IP validation, or channel binding on Assertion consumption |
| **Window Extension Replay** | An Assertion with a generous `NotOnOrAfter` window (or no time constraint) remains valid for an extended period, giving the attacker a large replay window. | SP accepts assertions with validity windows exceeding minutes; no strict clock enforcement |

### S6-2. Identity Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **NameID Spoofing** | In unsigned or weakly-verified assertions, the `<saml:NameID>` value is directly modified to impersonate a target user (e.g., changing `attacker@corp.com` to `admin@corp.com`). | Relies on upstream signature bypass (S1-S4) or missing signature validation |
| **Attribute Value Manipulation** | Role attributes, group memberships, or entitlement values within `<saml:AttributeStatement>` are modified to escalate privileges (e.g., changing `role=user` to `role=admin`). | Combined with any signature bypass; SP trusts attribute values without secondary authorization check |
| **NameID Format Confusion** | The NameID format is changed (e.g., from `emailAddress` to `unspecified`), causing the SP to interpret the NameID differently or match it against a different user store. | SP does not enforce expected NameID format |

### S6-3. Recipient and Audience Validation Failures

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Token Recipient Confusion** | An Assertion legitimately issued by a shared IdP for SP-A is submitted to SP-B. If SP-B does not verify the `Recipient` attribute matches its own ACS URL, it accepts the assertion and authenticates the attacker. | SP does not validate `<SubjectConfirmationData Recipient="...">` |
| **Audience Restriction Bypass** | The `<AudienceRestriction>` element specifies which SP(s) should accept the Assertion. SPs that skip this check accept assertions intended for other relying parties. | SP does not validate `<Audience>` against its own EntityID |
| **Destination Mismatch** | The `Destination` attribute on the `<samlp:Response>` must match the SP's ACS URL. When unchecked, an assertion intended for a staging environment can be replayed against production. | SP does not validate `Destination` attribute |
| **InResponseTo Bypass** | The `InResponseTo` attribute linking the Response to the original AuthnRequest is not validated. This enables unsolicited Response attacks where the attacker submits a forged assertion without a corresponding authentication request. | SP accepts IdP-initiated SSO or does not maintain request ID cache |

### S6-4. RelayState Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Open Redirect via RelayState** | The `RelayState` parameter (used to redirect users after SSO) is not validated. The attacker sets RelayState to a malicious URL, and the SP redirects the authenticated user to an attacker-controlled site for credential phishing or session theft. | SP does not whitelist RelayState redirect targets |
| **RelayState Injection** | The RelayState value is reflected in the SP's response without sanitization, enabling XSS or header injection. | RelayState reflected in HTML or HTTP headers without encoding |

### S6-5. Logout and Session Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Logout Request Forgery** | A forged `<samlp:LogoutRequest>` is sent to the SP, terminating another user's session. If the LogoutRequest signature is not verified, any user can log out any other user. | LogoutRequest signature validation not enforced |
| **Session Fixation via SAML** | The attacker initiates a SAML flow, captures the pre-authentication session, and tricks the victim into completing authentication in that session. The attacker then uses the now-authenticated session. | SP does not regenerate session ID after SAML assertion consumption |

---

## S7. Cryptographic and Infrastructure Attacks

These attacks target the trust infrastructure underlying SAML rather than individual messages.

### S7-1. Key Compromise and Forgery

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Golden SAML** | The attacker compromises the IdP's SAML signing private key (e.g., by extracting it from AD FS servers or token-signing certificate stores). With the private key, the attacker can forge any SAML assertion for any user to any SP, achieving persistent, undetectable access. Associated with the SolarWinds supply chain attack. | IdP signing key compromise (typically via AD FS DKM master key or similar) |
| **Silver SAML** | Instead of compromising the IdP's key, the attacker obtains the private key of an externally generated certificate that was imported into a cloud IdP (e.g., Microsoft Entra ID). Since cloud IdPs allow importing external signing certificates, compromise of the external key — which may be stored less securely — enables the same assertion forgery capabilities. | Cloud IdP configured with externally generated signing certificate; external key compromise |
| **Metadata Key Injection** | The attacker modifies the IdP's published metadata to include their own signing certificate. If the SP automatically refreshes metadata without integrity verification (e.g., no signed metadata, no pinned certificate), subsequent assertions signed with the attacker's key will be accepted. | Automatic metadata refresh over insecure channel or without metadata signature validation |

### S7-2. Certificate Lifecycle Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Expired Certificate Acceptance** | SPs that do not enforce certificate validity periods accept assertions signed with expired IdP certificates. An attacker who obtains an old, expired private key can forge assertions. | SP does not check certificate NotBefore/NotAfter |
| **Certificate Rollover Race** | During IdP certificate rotation, there is a window where both old and new certificates are valid. If the old key is compromised during or after rollover, the SP may still accept it. | SP maintains both old and new certificates without revoking the old one promptly |
| **CRL/OCSP Bypass** | The SP does not check Certificate Revocation Lists or OCSP status, accepting assertions signed with revoked certificates. | No revocation checking configured |

---

## S8. Implementation-Specific Parsing Flaws

Beyond parser differentials, individual library implementations contain unique parsing bugs that create exploitable conditions.

### S8-1. libxml2 Quirks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **libxml2 Internal Caching Abuse** | libxml2's internal node caching can be manipulated to cause canonicalization functions to process stale or incorrect node data, producing unexpected digest values. This was exploited to bypass SAML authentication on GitHub Enterprise. (CVE-2025-23369) | libxml2-backed XML processing in signature verification path |
| **libxml2 Namespace Inheritance** | libxml2 handles namespace inheritance differently in certain edge cases (e.g., default namespace undeclaration `xmlns=""`), leading to canonicalization output that differs from what other processors expect. | Mixed libxml2 and non-libxml2 processing in the same pipeline |

### S8-2. Language-Specific Library Flaws

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **xml-crypto firstChild Bug** | The Node.js xml-crypto library extracts DigestValue and SignatureValue using `firstChild` rather than `textContent`. XML comments are child nodes, so `<!--forged-->real` returns the comment node (forged value) rather than the concatenated text. (CVE-2025-29775, CVE-2025-29774 — SAMLStorm) | xml-crypto <= 6.0.0 |
| **samlify XPath Scope Failure** | The samlify Node.js library's signature verification does not properly scope which element the signature covers. An attacker can embed a valid signature (from metadata or error responses) and place a forged Assertion outside the signature's scope. (CVE-2025-47949) | samlify < 2.10.0 |
| **ruby-saml REXML Quirks** | REXML treats reserved `xml:` and `xmlns` prefixes as regular attributes and applies DOCTYPE-defined ATTLIST defaults, both of which libxml2/Nokogiri do not. This creates divergent document trees enabling namespace confusion and attribute pollution attacks. (CVE-2025-25291, CVE-2025-25292) | ruby-saml < 1.18.0 with REXML |
| **xmlseclibs C14N Failure** | The PHP xmlseclibs library's canonicalization implementation silently returns empty output on certain malformed namespace constructions, enabling void canonicalization attacks. (Fixed in 3.1.4) | xmlseclibs < 3.1.4 |
| **node-saml Signature Bypass** | The node-saml library fails to properly validate that the signature covers the specific assertion being processed, enabling wrapping attacks where a valid signature from any signed document is repurposed. (CVE-2025-54369) | Specific node-saml versions with incomplete reference validation |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|---------------------------|
| **Authentication Bypass / User Impersonation** | Any SP accepting SAML SSO | S1 + S2 + S3 + S4 (any signature bypass combined with NameID manipulation) |
| **Privilege Escalation** | SP with role-based access from SAML attributes | S5-4 (attribute injection at IdP) or S6-2 (attribute manipulation with signature bypass) |
| **Cross-SP Lateral Movement** | Multiple SPs sharing a single IdP | S6-3 (token recipient confusion) + S7-1 (Golden/Silver SAML) |
| **Persistent Backdoor Access** | Enterprise environments with AD FS / Entra ID | S7-1 (Golden SAML / Silver SAML — survives password resets and MFA) |
| **Data Exfiltration via XML** | SP with vulnerable XML parser | S5-1 (XXE) + S5-3 (XSLT injection) — reads local files and exfiltrates via OOB channels |
| **Denial of Service** | Any SAML endpoint processing XML | S5-2 (XML bomb / Billion Laughs) targeting ACS or SLO endpoints |
| **Session Hijacking** | SP with weak session management | S6-1 (replay) + S6-5 (session fixation) |
| **Phishing / Credential Theft** | SP with unvalidated RelayState | S6-4 (open redirect) — redirects authenticated users to attacker-controlled sites |

---

## CVE / Bounty Mapping (2024-2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| S3-1 + S1-4 (Void Canonicalization + Namespace-Assisted Wrapping) | CVE-2025-66568, CVE-2025-66567 (ruby-saml, php-saml, xmlseclibs) | Full auth bypass across Ruby/PHP SAML ecosystem. Affects all ruby-saml < 1.18.0, xmlseclibs < 3.1.4 |
| S2-1 + S2-3 (Parser Differential + DOCTYPE ATTLIST) | CVE-2025-25291, CVE-2025-25292 (ruby-saml) | CVSS 8.8. Account takeover via Nokogiri/REXML divergence. Fixed in ruby-saml 1.12.4, 1.18.0. Impacted GitLab (patched 17.9.2, 17.8.5, 17.7.7) |
| S3-3 (DigestValue/SignatureValue Comment Injection — SAMLStorm) | CVE-2025-29775, CVE-2025-29774 (xml-crypto) | Critical auth bypass in Node.js SAML ecosystem. xml-crypto <= 6.0.0, affecting 500k+ weekly downloads (node-saml, samlify, saml2-js) |
| S8-1 (libxml2 Caching Abuse) | CVE-2025-23369 (GitHub Enterprise) | SAML auth bypass on GitHub Enterprise via libxml2 canonicalization quirk |
| S1-3 (Encrypted Assertion Wrapping) | CVE-2024-9487, CVE-2024-4985 (GitHub Enterprise Server) | Unauthenticated site administrator access. Only when encrypted assertions enabled |
| S1-2 + S8-2 (Assertion Wrapping + XPath Scope Failure) | CVE-2025-47949 (samlify) | Critical auth bypass + admin impersonation. samlify < 2.10.0 |
| S4-1 + S6-2 (Missing Signature + Identity Manipulation) | CVE-2024-45409 (ruby-saml / GitLab) | Auth bypass via improper verification of SAML Response signature. Exploited in the wild against GitLab |
| S4-3 (Signature Validation Logic) | CVE-2024-8698 (Keycloak) | SAML signature verification bypass enabling auth bypass and privilege escalation |
| S8-2 (node-saml Signature Bypass) | CVE-2025-54369 (node-saml) | Auth bypass via signature scope validation failure |
| S7-1 (Golden SAML) | SolarWinds/SUNBURST (2020, ongoing relevance) | Nation-state persistent access. Used by UNC2452/Nobelium for lateral movement across Microsoft 365 tenants |
| S7-1 (Silver SAML) | Semperis Research (2024) | Entra ID assertion forgery via externally generated certificate compromise. Evades Golden SAML mitigations |
| S5-1 (XXE via SAML) | Oracle Commerce Cloud (2023) | SSRF via XXE in SAML login flow. File read and internal service access |
| S4-1 (Signature Stripping) | Rocket.Chat HackerOne Report #812064 | Admin authentication bypass — SAML responses not checked for signature presence |
| S6-2 + S6-3 (Identity + Recipient Confusion) | CVE-2020-2021 (PAN-OS) | CVSS 10.0. SAML auth bypass when SAML is enabled and "Validate Identity Provider Certificate" is disabled |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **SAML Raider** (Burp Extension) | XSW1-8, certificate cloning, signature manipulation | Interactive SAML message editing with signature spoofing, certificate import/export, automatic XSW attack generation |
| **SAMLReQuest** (Burp Extension) | SAML message inspection | Automatic decoding of compressed/encoded SAML messages in Proxy, Repeater, and Intercept |
| **XSW Burp Extension** (d0ge/XSW) | XML Signature Wrapping variants | Automated XSW attack payload generation for all 8 classic variants |
| **SAMLExtractor** | SP endpoint discovery | Extracts SAML consumer URLs from target applications for further testing |
| **samltool.io** (Online) | SAML message debugging | Decode, inspect, and verify SAML assertions, signatures, and certificates |
| **Invicti / Acunetix** (DAST) | XXE, signature validation, XSW | Automated SAML security scanning including XXE and signature bypass detection |
| **jwt_tool** (adapted) | SAML token inspection | While primarily for JWT, some modes support SAML assertion analysis |
| **ADFSDump / ADFSRelay** | Golden SAML key extraction | Extract SAML signing certificates and keys from AD FS servers for Golden SAML detection/testing |
| **AADInternals** (PowerShell) | Entra ID/Azure AD SAML | Export SAML signing certificates, test Silver SAML scenarios, federation configuration manipulation |
| **PayloadsAllTheThings** (Repository) | Reference payloads | Curated SAML injection payloads: XSW1-8, XXE, XSLT, comment injection, signature stripping templates |

---

## Summary: Core Principles

SAML's mutation surface is fundamentally a consequence of using XML — a format designed for maximum structural flexibility — as the carrier for security-critical authentication assertions. The entire security model depends on a single assumption: that the element verified by the digital signature is *exactly* the element the SP processes for authentication decisions. Every category in this taxonomy represents a different way to violate that assumption — by moving elements (S1), by making parsers disagree about structure (S2), by breaking canonicalization (S3), by skipping verification steps (S4), by attacking the XML layer itself (S5), by exploiting protocol-level gaps (S6), by compromising the trust infrastructure (S7), or by exploiting library-specific bugs (S8).

Incremental patches consistently fail to eliminate SAML threats because each library implements its own XML parsing, canonicalization, XPath evaluation, and signature verification stack. A fix in one library (e.g., ruby-saml) does not protect another (e.g., xml-crypto or samlify), and the same *class* of vulnerability (parser differentials, void canonicalization, comment injection) recurs independently across languages and ecosystems. The 2025 research wave — demonstrating void canonicalization, SAMLStorm comment injection, and parser differential attacks — affected Ruby, PHP, Node.js, and Go ecosystems simultaneously, despite decades of prior research on SAML signature wrapping.

A structural solution would require either (a) abandoning XML in favor of a simpler, unambiguous token format (as OIDC/JWT partially achieves), (b) mandating a single canonical XML parser implementation across all processing stages, or (c) redesigning the signature-to-content binding to be structurally inseparable rather than reference-based. Until then, SAML remains a protocol where every XML parser quirk, every library implementation choice, and every canonicalization edge case is a potential authentication bypass.

---

## References

- PortSwigger Research, "The Fragile Lock: Novel Bypasses For SAML Authentication" (2025) — https://portswigger.net/research/the-fragile-lock
- PortSwigger Research, "SAML Roulette: The Hacker Always Wins" (2025) — https://portswigger.net/research/saml-roulette-the-hacker-always-wins
- WorkOS, "SAMLStorm: Critical Authentication Bypass in xml-crypto and Node.js Libraries" (2025) — https://workos.com/blog/samlstorm
- GitHub Security Lab, "GHSL-2024-329/GHSL-2024-330: Authentication Bypasses in ruby-saml" — https://securitylab.github.com/advisories/GHSL-2024-329_GHSL-2024-330_ruby-saml/
- ProjectDiscovery, "GitHub Enterprise SAML Authentication Bypass (CVE-2024-4985 / CVE-2024-9487)" — https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass
- Semperis, "Meet Silver SAML: Golden SAML in the Cloud" (2024) — https://www.semperis.com/blog/meet-silver-saml/
- NCC Group, "SAML XML Injection" — https://www.nccgroup.com/research-blog/saml-xml-injection/
- WorkOS, "Fun with SAML SSO Vulnerabilities and Footguns" — https://workos.com/blog/fun-with-saml-sso-vulnerabilities-and-footguns
- WorkOS, "Common SAML Security Vulnerabilities" — https://workos.com/guide/common-saml-security-vulnerabilities
- NetSPI, "Attacking SSO: Common SAML Vulnerabilities and Ways to Find Them" — https://www.netspi.com/blog/technical-blog/web-application-penetration-testing/attacking-sso-common-saml-vulnerabilities-ways-find/
- Endor Labs, "CVE-2025-47949: Samlify Signature Wrapping" — https://www.endorlabs.com/learn/cve-2025-47949-reveals-flaw-in-samlify-that-opens-door-to-saml-single-sign-on-bypass
- Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012) — https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky
- OWASP, "SAML Security Cheat Sheet" — https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- SwissKyRepo, "PayloadsAllTheThings — SAML Injection" — https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SAML%20Injection
- CSO Online, "SAML Authentication Broken Almost Beyond Repair" (2025) — https://www.csoonline.com/article/4105030/saml-authentication-broken-almost-beyond-repair.html

---

*This document was created for defensive security research and vulnerability understanding purposes.*
