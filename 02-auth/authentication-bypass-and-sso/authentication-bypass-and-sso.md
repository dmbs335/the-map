# Authentication Bypass & SSO Vulnerability Mutation Taxonomy

**Scope**: Authentication bypass and Single Sign-On (SSO) vulnerabilities
**Exclusions**: OAuth, JWT, SAML (covered in separate taxonomies)
**Coverage**: Kerberos, NTLM, RADIUS, LDAP, CAS, FIDO2/WebAuthn, MFA, session management, middleware/framework auth, password recovery, credential acquisition
**Period**: Focused on 2024–2025 discoveries, with foundational techniques included

---

## Classification Structure

This taxonomy organizes authentication bypass and SSO vulnerabilities along three orthogonal axes:

**Axis 1 — Authentication Layer Targeted (Primary Axis):** The structural component of the authentication system being attacked. This axis structures the main body of the document (§1–§9). Each top-level category represents a distinct layer of the authentication stack — from low-level credential validation logic through protocol-level mechanisms, multi-factor enforcement, session lifecycle, SSO trust architecture, modern passwordless systems, framework middleware, account recovery flows, and finally large-scale credential acquisition techniques.

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
| **Full Domain Compromise** | Active Directory / Windows domain | §2 + §9 (Kerberos + credential acquisition) |
| **Cloud/SaaS Account Takeover** | Azure/Entra ID, Okta, Google Workspace | §3 + §4 (MFA bypass + session theft) |
| **Network Appliance Takeover** | Firewalls, VPN gateways, management interfaces | §7 (framework/middleware bypass) |
| **Web Application Access** | Custom web applications | §1 + §7 + §8 (logic flaws + middleware + recovery) |
| **Lateral Movement** | Post-initial-compromise expansion | §2 + §5 (protocol relay + SSO trust) |
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

The Okta bcrypt incident (October 2024) exemplifies this category: usernames exceeding 52 characters caused the password component of the bcrypt-hashed cache key to be truncated entirely, allowing authentication with cached results regardless of the actual password supplied. The fix replaced bcrypt with PBKDF2 for cache key generation.

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
| **Type Juggling / Loose Comparison** | Weakly-typed languages (PHP, JavaScript) evaluate `"0" == 0 == false == null` as equal, bypassing password checks when magic hashes or null values are supplied | Loose equality (`==`) instead of strict equality (`===`) in credential comparison |
| **Encoding Normalization Mismatch** | Different Unicode normalization forms for the same visual string produce different hash values, allowing pre-computed hashes to match unexpected inputs | Unicode normalization not applied consistently between registration and authentication |

---

## §2. Protocol-Level Authentication Attacks

Attacks exploiting design or implementation flaws in network authentication protocols. These target the protocol mechanisms themselves rather than application-level logic.

### §2-1. Kerberos Ticket Forging

Creating or manipulating Kerberos tickets without legitimate authority, enabling authentication as arbitrary principals.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Golden Ticket** | Forging Ticket-Granting Tickets (TGTs) using the compromised `krbtgt` account hash. Forged tickets are accepted unconditionally because the KDC's own key signed them, granting authentication as any user including Domain Admins | Attacker has obtained the `krbtgt` NTLM hash (typically via domain controller compromise) |
| **Silver Ticket** | Forging Ticket-Granting Service (TGS) tickets using a compromised service account hash. Unlike Golden Tickets, these target specific services but do not require communication with the KDC, making detection significantly harder | Attacker has obtained a service account NTLM hash (via Kerberoasting §9-3 or other means) |
| **Diamond Ticket** | Modifying legitimate TGTs obtained from the KDC rather than forging from scratch, blending into normal ticket lifecycle and evading detections that look for tickets with anomalous creation metadata | `krbtgt` hash compromised; attacker wants to evade Golden Ticket detection mechanisms |
| **Golden dMSA** | Exploiting a design flaw in Windows Server 2025's delegated Managed Service Accounts (dMSA) where the `ManagedPasswordId` structure contains only 1,024 possible time-based combinations, reducing password derivation to a trivial brute-force operation | Windows Server 2025 with dMSA deployed; attacker has KDS root key (Domain Admin, Enterprise Admin, or SYSTEM access) |

The Golden dMSA vulnerability, discovered in May 2025, is particularly notable because it attacks a feature explicitly designed to *improve* service account security. Microsoft acknowledged the finding but characterized it as by-design behavior for scenarios where domain controller secrets are already compromised.

### §2-2. Kerberos Relay and Reflection

Forwarding or reflecting Kerberos authentication messages to gain unauthorized access to services the victim machine is authorized for.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Reflective Kerberos Relay** | Coercing a Windows host to authenticate via SMB, then relaying the computer account's Kerberos ticket back to the same host, achieving SYSTEM privileges and RCE | Target does not enforce SMB signing; attacker can coerce SMB authentication (CVE-2025-33073) |
| **DNS CNAME Relay** | Abusing DNS CNAME records to manipulate Kerberos SPN resolution. When Windows resolves a CNAME alias, it may construct a Kerberos service ticket request for the aliased target, allowing relay to unintended services | DNS CNAME records resolvable in the domain; target service accepts relayed tickets |
| **Ghost SPN Exploitation** | Registering or manipulating Service Principal Names to redirect Kerberos authentication to attacker-controlled services | Attacker has write access to SPN attributes; vulnerable service accepts any ticket encrypted with its key (CVE-2025-58726) |

### §2-3. NTLM Relay and Coercion

Forcing Windows machines to authenticate and relaying or abusing the resulting NTLM authentication material.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Classic NTLM Relay** | Intercepting NTLM authentication between a client and server, then forwarding the authentication messages to a different target service, impersonating the client | Target service does not require SMB signing or channel binding; attacker is in network path |
| **Coercion via MS-EFSRPC (PetitPotam)** | Abusing the Encrypting File System Remote Protocol to force a domain controller to authenticate to an attacker-controlled server | MS-EFSRPC accessible; domain controller not patched; relay target available |
| **Coercion via MS-DFSNM (DFSCoerce)** | Abusing the Distributed File System Namespace Management protocol to trigger domain controller authentication to arbitrary servers | MS-DFSNM accessible; domain controller not patched |
| **Coercion via MS-EVEN (EventLog)** | Exploiting the remote event logging interface to force machines to authenticate outbound. Detected in the wild in March 2025 targeting healthcare organizations | MS-EVEN RPC interface accessible; no coercion-agnostic detection in place |
| **NTLM LDAP Auth Bypass** | Combining coercion with NTLM relay manipulation to achieve domain controller compromise, bypassing traditional channel binding and LDAP signing requirements | Domain controller running LDAP/LDAPS; standard hardening measures in place (CVE-2025-54918, CVSS Critical) |
| **NTLM Hash Disclosure** | Vulnerabilities that leak NTLMv2 password hashes with minimal or no user interaction, enabling offline cracking or pass-the-hash attacks | Victim interaction as minimal as viewing a file in Explorer (CVE-2024-43451) |

The coercion attack landscape continues to expand because it targets rarely-used RPC protocols. Detection strategies that are coercion-agnostic (monitoring for outbound authentication anomalies rather than specific protocol abuse) are more resilient than signature-based approaches.

### §2-4. RADIUS Protocol Attacks

Exploiting weaknesses in the RADIUS authentication protocol specification and its cryptographic foundations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **BlastRADIUS Response Forgery** | Exploiting MD5 chosen-prefix collision vulnerability in RADIUS Response Authenticator (RFC 2865) to forge valid Access-Accept responses from Access-Reject, enabling authentication bypass without knowing passwords or shared secrets | Man-in-the-middle position between RADIUS client and server; MD5 collision computation capability (CVE-2024-3596, CVSS 7.5) |
| **Shared Secret Brute-Force** | Offline cracking of the RADIUS shared secret from captured authentication exchanges, then forging arbitrary authentication responses | Captured RADIUS traffic; weak or short shared secret |
| **RADIUS Relay** | Forwarding RADIUS authentication requests to a rogue server that always returns Access-Accept, bypassing the legitimate authentication backend | Attacker controls network path between NAS and RADIUS server |

The BlastRADIUS vulnerability (July 2024) is significant because it attacks a *protocol-level* design flaw — MD5's use for authentication integrity — rather than an implementation bug. Mitigation requires mandating Message-Authenticator attributes or migrating to RADIUS over TLS (RADSEC).

### §2-5. LDAP Authentication Attacks

Targeting the LDAP protocol as an authentication backend, beyond the injection attacks covered in §1-2.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Anonymous Bind Exploitation** | LDAP servers configured to accept anonymous binds (empty DN + empty password) as valid authentication, where the application interprets any successful bind as authenticated | LDAP anonymous bind enabled; application doesn't distinguish anonymous from authenticated bind |
| **LDAP Referral Abuse** | Manipulating LDAP referrals to redirect authentication queries to attacker-controlled LDAP servers that return forged positive results | LDAP client follows referrals; no referral validation |
| **Pass-Back Attack** | Reconfiguring a device to point its LDAP authentication to an attacker-controlled server, capturing credentials in cleartext as users authenticate | Administrative access to device LDAP configuration; credentials sent in cleartext |
| **ACL Hierarchy Exploitation** | Leveraging LDAP group hierarchy resolution and ACL misconfigurations to escalate from limited access to SYSTEM level | Misconfigured Active Directory ACLs; LDAP query access to group objects (CVE-2025-29810, CVSS 7.5) |

---

## §3. Multi-Factor Authentication Bypass

Techniques that defeat second-factor or additional authentication requirements. These attacks acknowledge that the first factor (typically password) may be compromised and target the additional verification layer.

### §3-1. TOTP / OTP Brute-Force

Exhausting the code space of time-based or event-based one-time passwords through rapid enumeration.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Session-Parallel Enumeration (AuthQuake)** | Rapidly creating new authentication sessions and enumerating TOTP codes across all sessions simultaneously. A 6-digit TOTP code has 1,000,000 possible values; with no cross-session rate limiting, exhaustion takes approximately 70 minutes | No rate limiting across sessions (only per-session); no alerting on failed MFA attempts (Microsoft Azure MFA, patched October 2024) |
| **TOTP Window Exploitation** | Exploiting overly generous time windows where TOTP codes remain valid for extended periods beyond the standard 30-second window | Server accepts codes from multiple time steps (past and future); no single-use enforcement |
| **OTP Predictability** | Sequential, time-derived, or insufficiently random OTP generation allowing prediction of future codes | OTP derived from timestamp via weak algorithm (e.g., MD5 of epoch); no cryptographic HMAC |
| **SMS OTP Interception** | SS7 network exploitation, SIM swapping, or malware-based SMS interception to obtain OTP codes in transit | SMS used as OTP delivery channel; attacker has telco-level access or social engineering capability |

### §3-2. MFA Fatigue and Social Engineering

Exploiting the human element in MFA by bombarding users with approval requests or manipulating them into authorizing attacker sessions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Push Notification Bombing** | Repeatedly triggering MFA push notifications until the user approves one out of fatigue, confusion, or desire to stop the alerts | Push-based MFA without number matching; no rate limiting on push requests |
| **Number Matching Social Engineering** | Calling the victim and convincing them to provide the number displayed on their MFA prompt, ostensibly for "IT verification" | Number-matching MFA deployed; attacker has victim's phone number and credentials |
| **MFA Enrollment Hijacking** | Registering an attacker-controlled MFA device during the initial enrollment window before the legitimate user completes setup | No pre-registration verification; enrollment link sent to compromised email; open enrollment window |

### §3-3. Authentication Downgrade Attacks

Forcing the authentication system to fall back from phishing-resistant methods (FIDO2/passkeys) to interceptable alternatives.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **User-Agent Spoofing Downgrade** | AitM proxy spoofs a browser user agent incompatible with FIDO2 (e.g., Safari on Windows), triggering a WebAuthn error that prompts the user to select a weaker alternative (OTP, push notification) | IdP offers fallback authentication methods; AitM proxy can modify User-Agent header |
| **CSS Injection Method Hiding** | Injecting CSS `<style>` blocks through AitM proxy or XSS that hide the FIDO2/security key authentication option from the user's view, leaving only phishable methods visible | AitM proxy can inject HTML/CSS; IdP authentication page renders method choices client-side |
| **Protocol Version Downgrade** | Delivering a spoofed browser or environment that reports no WebAuthn support, forcing fallback to TOTP/SMS even when the user has registered a hardware key | IdP does not enforce FIDO2-only policy; graceful degradation to weaker methods enabled |

This attack category, first formally presented at OutOfTheBox 2025 in Bangkok, is particularly concerning because it targets authentication methods explicitly marketed as "phishing-resistant." The core issue is that most deployments maintain phishable fallback methods for compatibility.

### §3-4. Adversary-in-the-Middle (AitM) Session Interception

Positioning a real-time proxy between the user and the legitimate service to capture post-MFA session tokens, rendering all authentication factors ineffective.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Reverse Proxy Phishing (Evilginx-style)** | Deploying a phishing site backed by a reverse proxy that passes all traffic to the legitimate service in real-time, capturing credentials, MFA responses, and the resulting session cookies simultaneously | Victim directed to phishing domain; no device-bound session credential enforcement |
| **Phishing-as-a-Service Kits** | Commercial-grade AitM platforms (Tycoon 2FA, Sneaky 2FA, NakedPages, EvilProxy, Saiga 2FA) that provide turnkey AitM infrastructure with anti-detection, lure templating, and cookie exfiltration | PhaaS subscription; target organization uses cloud SSO without device-bound tokens |
| **Browser Extension AitM** | Malicious browser extensions that intercept authentication flows and exfiltrate session cookies directly from the browser's cookie store after successful authentication | Victim installs malicious extension (e.g., Cookie-Bite technique) |

AitM attacks experienced a 46% year-over-year surge in 2025. The most recent evolution involves transitioning lure delivery from QR codes to HTML attachments and SVG files. The fundamental defense gap is that these attacks steal *post-authentication* artifacts, so stronger authentication methods alone are insufficient.

### §3-5. MFA Implementation Logic Flaws

Architectural errors in how MFA is integrated into the authentication flow, allowing the second factor to be skipped entirely.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Step-Skip Bypass** | The MFA verification step is implemented as a separate page/endpoint. After first-factor success, directly navigating to the post-MFA URL bypasses the check because the server doesn't verify that the second factor was actually completed | Server-side MFA state not tracked; URL for post-MFA destination is predictable |
| **Session Binding Mismatch** | MFA verification is not bound to the same session as the first factor, allowing an attacker to complete first-factor auth in one session and satisfy MFA in a different session they control | Session ID not validated across authentication steps; MFA code accepted for any pending session |
| **User Agent Classification Bypass** | MFA enforcement policies exempt certain user agents classified as "unknown" (uncommon browsers, Python scripts, CLI tools) from MFA requirements | SSO policy does not enforce MFA for unrecognized user agents (Okta vulnerability, 2024) |
| **TOCTOU in MFA Verification** | Race condition between MFA check and access grant allows requests that slip through during the verification window | MFA check and authorization are not atomic; concurrent request processing (CVE-2025-62004) |

---

## §4. Session & Token Lifecycle Attacks

Targeting authentication state *after* credential verification succeeds. These attacks bypass the need to authenticate entirely by stealing, manipulating, or predicting the artifacts that represent an established authenticated session.

### §4-1. Session Fixation

Forcing a victim to use an attacker-predetermined session identifier, which the attacker can then use to access the session after the victim authenticates.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **URL-Based Fixation** | Session ID embedded in URL parameters; attacker sends victim a URL containing a pre-set session ID | Application accepts session IDs from URL parameters; session not regenerated on login |
| **Cookie-Based Fixation** | Attacker sets a session cookie in the victim's browser (via XSS, subdomain control, or HTTP header injection) before authentication | Cookies settable across subdomains; session not regenerated on login |
| **Cross-Subdomain Fixation** | Exploiting cookie scope to set session cookies from a subdomain the attacker controls for the parent domain's authentication | Attacker controls any subdomain; cookie domain set too broadly |

### §4-2. Session Hijacking and Token Theft

Capturing or extracting valid session tokens from authenticated users.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Infostealer Cookie Extraction** | Malware families (RedLine, Raccoon, Vidar, Lumma) extract session cookies, authentication tokens, and browser credentials from victim machines at industrial scale — 17+ billion cookies stolen in 2024 alone | Victim machine infected with infostealer; stolen logs sold on darknet marketplaces |
| **XSS Session Theft** | Cross-site scripting vulnerabilities used to exfiltrate session cookies via JavaScript | XSS vulnerability in authenticated application; cookies not marked HttpOnly |
| **Network-Level Sniffing** | Capturing session tokens from unencrypted network traffic or TLS-terminated inspection points | Unencrypted HTTP in use; or compromised TLS inspection endpoint |
| **Browser Extension Cookie Theft** | Malicious or compromised browser extensions with cookie access permissions exfiltrating authentication tokens | Extension with `cookies` permission installed; extensions can read any site's cookies |
| **App-Bound Encryption Bypass** | Infostealers circumventing Chrome's App-Bound Encryption (released July 2024) within 45 days of deployment, continuing to extract cookies despite browser-level protections | Chrome App-Bound Encryption deployed; infostealer has bypass capability (observed September 2024) |

The infostealer ecosystem's scale is staggering: 1.8 billion credentials stolen across 5.8 million devices in 2025, with over 54% of ransomware victims having domain credentials appear on infostealer marketplaces *before* the attack. The median time from stolen log to ransomware incident is under 48 hours.

### §4-3. Token Replay and Session Persistence

Using stolen or captured authentication tokens to establish access without re-authenticating.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cookie Replay** | Importing stolen session cookies into an attacker's browser to assume the victim's authenticated session | Valid session cookie obtained (via §4-2 methods); no device binding on session |
| **Pass-the-Cookie** | Enterprise-specific variant of cookie replay targeting cloud SSO sessions (Azure, Google Workspace, Okta) where a single session cookie grants access to multiple applications | SSO session cookie stolen; cookie not bound to specific device/IP |
| **Token Lifetime Exploitation** | Abusing excessively long token lifetimes — sessions remaining valid for days or weeks without re-authentication requirements | Long-lived session tokens; no continuous authentication or token rotation |
| **Insufficient Logout/Revocation** | Session tokens remaining valid after user logout or password change because the server doesn't properly invalidate server-side session state | Stateless tokens without server-side revocation list; or revocation check not implemented |

### §4-4. SSO Response Manipulation

Tampering with SSO authentication responses at the HTTP level to convert rejections into approvals.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Status Code Tampering** | Intercepting HTTP 302 redirect-to-SSO responses and modifying them to 200 OK while removing the Location header, bypassing the SSO redirect entirely and accessing the internal response body | Application returns the protected content alongside the 302 redirect; client-side interception possible |
| **SSO Header Injection** | Injecting or modifying SSO-related headers (e.g., `X-Forwarded-User`, `Remote-User`) that the application trusts for authenticated identity without independent verification | Application trusts proxy-set identity headers; attacker can inject headers directly |

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
| **WebAuthN Integration Flaws** | Vulnerabilities in how CAS integrates with WebAuthN/FIDO2, allowing authentication bypass through flow manipulation | Apereo CAS with WebAuthN enabled (patched April 2025) |

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

Forcing fallback from phishing-resistant to phishable authentication. (Detailed mechanisms in §3-3; this section covers the broader architectural implications.)

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

Exploiting account recovery mechanisms, which by design provide an authentication-equivalent path that bypasses the primary credential.

### §8-1. Password Reset Token Attacks

Targeting the token-based password reset flow.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Predictable Token Generation** | Reset tokens derived from guessable values (timestamp, user ID, sequential counter) using weak algorithms (MD5 of epoch, Base64 of user email) | Token generation algorithm lacks cryptographic randomness; tokens derivable from observable values |
| **Token Reuse / Non-Expiration** | Reset tokens that remain valid after use, have excessively long expiration windows, or are never invalidated after successful reset | No single-use enforcement; no expiration; or expiration measured in days rather than minutes |
| **Token Leakage via Referrer** | Reset tokens in URL parameters leaked to third-party sites through the HTTP Referrer header when the reset page contains external resources | Token in URL query string; reset page loads external JavaScript, CSS, or images |
| **Password Reset Poisoning** | Manipulating the `Host` header in password reset requests to cause the application to generate reset links pointing to an attacker-controlled domain, stealing the token when the victim clicks | Application uses Host header to construct reset URLs without validation; email sent to legitimate user with attacker's domain |

### §8-2. Account Recovery Flow Bypass

Exploiting weaknesses in the overall account recovery process beyond token attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **IDOR in Recovery Endpoints** | Manipulating user identifiers in recovery API calls to reset other users' passwords (e.g., changing `user_id=123` to `user_id=456` in the reset confirmation request) | User identifier in recovery request not bound to the authenticated recovery session |
| **Email/Phone Verification Bypass** | Skipping or manipulating the verification step that confirms ownership of the recovery email or phone number | Verification status stored client-side; or verification endpoint accepts any code; or verification step can be skipped by direct URL navigation |
| **Recovery Flow State Machine Bypass** | Completing recovery steps out of order, or replaying an earlier step's success token to skip later verification steps | Recovery flow state not tracked server-side; state transitions not validated |
| **Security Question Exploitation** | Answering security questions using publicly available information (social media, data breaches) or exploiting questions with limited answer spaces | Weak security questions (e.g., "favorite color"); answers available through OSINT |
| **MFA Reset via Recovery** | Using the account recovery flow to remove or reset MFA enrollment, then authenticating with only the first factor | Recovery flow allows MFA reconfiguration without current MFA verification |

---

## §9. Credential Acquisition at Scale

Systematic techniques for obtaining valid credentials that enable authentication bypass through legitimate-appearing login. These are not "bypass" in the traditional sense but represent the primary pipeline feeding all other attack categories.

### §9-1. Password Spraying

Testing a small number of commonly used passwords against a large number of accounts simultaneously, staying below per-account lockout thresholds.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Classic Spray** | Attempting top passwords (e.g., `Season+Year`, `Company+123`) across all enumerated accounts with delays between attempts | Account lockout based on per-account attempt count; no global anomaly detection |
| **Smart Spray** | Using OSINT-derived password patterns specific to the target organization (founded year, office location, sports teams) combined with common password structures | Publicly available organizational information; password policy known or guessable |
| **Slow Spray** | Distributing attempts across days or weeks with randomized intervals to evade time-based detection | Detection tuned for burst attempts; no long-term baseline comparison |

### §9-2. Credential Stuffing

Testing credential pairs (username + password) leaked from breaches against target services, exploiting password reuse.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct Stuffing** | Automated submission of breach-sourced credential pairs to login endpoints | Users reuse passwords across services; no credential screening against breach databases |
| **Variant Stuffing** | Applying common password mutation rules (incrementing numbers, changing seasons, adding special characters) to known passwords from breaches | Users make predictable modifications to compromised passwords |
| **Proxy-Rotated Stuffing** | Distributing stuffing attempts across residential proxy networks to evade IP-based rate limiting | Rate limiting based on source IP; no behavioral/fingerprinting detection |

Current scale: approximately 26 billion stuffing attempts per month (2024), with a 50% growth rate over 18 months.

### §9-3. Kerberos Credential Extraction

Offline password cracking of Kerberos authentication material.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Kerberoasting** | Requesting TGS tickets for service accounts with SPNs, then cracking the ticket's encrypted portion offline to recover the service account password | Any authenticated domain user; service accounts with weak passwords; SPNs registered |
| **AS-REP Roasting** | Requesting AS-REP messages for accounts with Kerberos pre-authentication disabled, cracking the encrypted portion offline | Target accounts have "Do not require Kerberos pre-authentication" flag set; weak passwords |
| **Targeted Kerberoasting** | Setting SPNs on specific high-value accounts (if the attacker has SPN write access), then performing Kerberoasting against those accounts | Attacker has write access to servicePrincipalName attribute on target accounts |

### §9-4. Infostealer Ecosystem

Industrial-scale credential theft through malware families that extract stored credentials, session tokens, and authentication material from compromised endpoints.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Browser Credential Store Extraction** | Extracting saved usernames and passwords from browser credential stores (Chrome, Firefox, Edge) | Victim machine infected; browser stores credentials; no additional encryption beyond OS-level |
| **Session Cookie Harvesting** | Extracting active session cookies from browser storage, enabling authenticated access without credentials or MFA (detailed in §4-2) | Browser cookies not bound to device; cookies accessible to malware with user-level privileges |
| **Certificate and Key Theft** | Extracting client certificates, private keys, and Kerberos tickets/hashes from the operating system credential store | Access to LSASS memory (Mimikatz-style); or certificate store accessible with user privileges |
| **Credential Log Marketplace** | Stolen credentials aggregated and sold on darknet marketplaces (Russian Market, Genesis) with filtering by domain, service, and freshness | Mature criminal marketplace infrastructure; logs priced at $1–$50 per machine |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Chain |
|----------|-------------|---------------------------|---------------|
| **Full AD Domain Compromise** | On-premises Active Directory | §2 + §9 | Credential stuffing (§9-2) → Kerberoasting (§9-3) → Golden Ticket (§2-1) |
| **Cloud/SaaS Account Takeover** | Azure/Entra, Okta, Google Workspace | §3 + §4 + §9 | Infostealer (§9-4) → Cookie replay (§4-3) → Lateral access via SSO |
| **Network Appliance Takeover** | Firewalls, VPN, management interfaces | §7 + §1 | WebSocket bypass (§7-2) or middleware injection (§7-1) → Admin access |
| **Web Application Access** | Custom applications | §1 + §7 + §8 | LDAP injection (§1-2) → Session fixation (§4-1) → Account takeover |
| **MFA-Protected Account Bypass** | Enterprise with MFA deployed | §3 + §6 | Downgrade attack (§3-3) → AitM interception (§3-4) → Session theft (§4-2) |
| **Persistent Domain Backdoor** | Windows Server 2025 | §2-1 + §5-3 | Golden dMSA (§2-1) → Cross-domain movement (§5-3) → Indefinite access |
| **AD Sync to Cloud Pivot** | Hybrid on-prem + cloud | §5-2 + §2 | AD sync credential compromise (§5-2) → Cloud IdP control → Full tenant |
| **Recovery Flow Exploitation** | Any web application | §8 + §4 | Reset poisoning (§8-1) → Password reset → MFA reset (§8-2) → Full access |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Product | Impact / CVSS |
|---------------------|-----------|---------|---------------|
| §1-1 (Hash Truncation) | Okta Advisory (Oct 2024) | Okta AD/LDAP DelAuth | Auth bypass via bcrypt 52-char truncation; no CVE assigned |
| §1-2 (LDAP Injection) | CVE-2024-37782 | Gladinet CentreStack v13.12 | Unauthorized access + RCE via username field injection |
| §1-2 (LDAP ACL Exploit) | CVE-2025-29810 | Windows AD Domain Services | Privilege escalation to SYSTEM; CVSS 7.5 |
| §2-1 (Kerberos Reflection) | CVE-2025-33073 | Windows SMB | Reflective Kerberos relay → SYSTEM RCE; patched June 2025 |
| §2-1 (Golden dMSA) | Semperis Disclosure (May 2025) | Windows Server 2025 dMSA | Auth bypass for all managed service accounts; Microsoft: "by design" |
| §2-2 (Ghost SPN) | CVE-2025-58726 | Windows SMB Server | Elevation of privilege; patched October 2025 |
| §2-3 (NTLM LDAP Bypass) | CVE-2025-54918 | Windows Domain Controllers | Coercion + relay → DC compromise; bypasses channel binding |
| §2-3 (Hash Disclosure) | CVE-2024-43451 | Microsoft Windows | NTLMv2 hash leakage with minimal interaction |
| §2-4 (RADIUS Forgery) | CVE-2024-3596 | RADIUS Protocol (RFC 2865) | MD5 collision → response forgery; CVSS 7.5 |
| §3-1 (TOTP Brute Force) | Oasis Security (Dec 2024) | Microsoft Azure MFA | AuthQuake: session-parallel TOTP brute-force; no CVE assigned |
| §3-5 (User Agent Bypass) | Okta Advisory (2024) | Okta SSO Policies | MFA bypass via unknown user agent classification |
| §5-1 (CAS WebAuthN) | Apereo Advisory (Apr 2025) | Apereo CAS 7.x | Authentication bypass in WebAuthN integration; CVSS ~7.5 |
| §5-1 (CAS Flow Mgmt) | Apereo Advisory (Sep 2025) | Apereo CAS 7.x | OAuth/OIDC flow manipulation → auth bypass; CVSS ~7.5 |
| §6-1 (FIDO Credential Confusion) | CVE-2025-26788 | StrongKey FIDO Server 4.10–4.15 | Account takeover via discoverable/non-discoverable credential confusion |
| §6-3 (BLE Proximity Hijack) | CVE-2024-9956 | Google Chrome Android | WebAuthn BLE proximity attack → credential capture |
| §7-1 (Middleware Header) | CVE-2025-29927 | Next.js (all versions) | Complete auth middleware bypass; CVSS 9.1 |
| §7-2 (WebSocket Bypass) | CVE-2024-55591 | FortiOS 7.0.x / FortiProxy | Super-admin via WebSocket; CVSS 9.8; zero-day exploited since Nov 2024 |
| §7-2 (Mgmt Interface) | CVE-2024-0012 | Palo Alto PAN-OS | Unauthenticated admin access to management web interface |
| §7-2 (Mgmt Interface) | CVE-2025-0108 | Palo Alto PAN-OS | Auth bypass in management web interface |
| §2-1 (Kerberos Cert Auth) | CVE-2025-26647 | Windows Kerberos | Certificate-based auth bypass when cert issuer not in NTAuth store |
| §2-1 (Kerberos Storage) | CVE-2025-29809 | Windows Kerberos | Security feature bypass via insecure storage of Kerberos keys; CVSS 7.1 |
| §6-1 (WSO2 mTLS) | CVE-2025-9312 | WSO2 Products | mTLS auth bypass → admin privileges on REST/SOAP APIs |
| §3-5 (MFA TOCTOU) | CVE-2025-62004 | BullWall Server | Race condition bypassing MFA after initial admin auth; CVSS 7.5 |

---

## Detection Tools

### Offensive / Testing Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Impacket** | Kerberos, NTLM, LDAP, SMB | Python library for network protocol interaction; includes GetTGT, GetST, ntlmrelayx, secretsdump |
| **Rubeus** | Kerberos (Windows) | C# Kerberos abuse toolkit: Kerberoasting, AS-REP roasting, ticket forging, overpass-the-hash |
| **Mimikatz** | Windows credential store | LSASS memory extraction, pass-the-hash, pass-the-ticket, Golden/Silver ticket creation |
| **Evilginx** | AitM phishing / MFA bypass | Open-source reverse proxy phishing framework for real-time session cookie interception |
| **Coercer** | NTLM coercion | Automated coercion testing across all known MS-RPC coercion methods (EFSRPC, DFSNM, EVEN, etc.) |
| **CrackMapExec / NetExec** | AD reconnaissance + credential testing | Network-wide credential spraying, pass-the-hash, Kerberos attacks |
| **Hashcat / John the Ripper** | Offline credential cracking | GPU-accelerated hash cracking for Kerberos tickets, NTLM hashes, TOTP seeds |
| **Burp Suite** | Web authentication testing | HTTP interception, authentication flow analysis, session management testing |
| **Nuclei** | CVE scanning | Template-based vulnerability scanner with auth bypass detection templates |
| **NextSploit** | CVE-2025-29927 | Dedicated scanner/exploiter for Next.js middleware auth bypass |
| **PetitPotam / DFSCoerce** | NTLM coercion | Targeted coercion tools for specific MS-RPC interfaces |

### Defensive / Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **CrowdStrike Identity Protection** | NTLM relay, Kerberos abuse | Real-time identity threat detection; coercion-agnostic relay detection |
| **Microsoft Defender for Identity** | AD authentication attacks | Kerberoasting, pass-the-hash, Golden Ticket detection via DC sensor |
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

2. **Protocol ossification**: Protocols like RADIUS (MD5-based since 1997), NTLM (maintained for backward compatibility despite known weaknesses), and Kerberos (designed before modern threat models) cannot be fundamentally redesigned without breaking compatibility with millions of deployed systems.

3. **The fallback problem**: Every authentication system maintains weaker alternatives for disaster recovery, accessibility, or compatibility. The authentication downgrade attacks of 2025 prove that the *effective* security of any system is equal to its weakest maintained fallback method.

4. **Trust boundary proliferation**: The explosion of SSO, federation, cloud synchronization, and hybrid architectures means that authentication trust boundaries are multiplying faster than they can be secured. Each trust relationship (AD ↔ Azure, IdP ↔ SP, RADIUS client ↔ server) is an independent attack surface.

### Structural Solutions

The only comprehensive mitigations are those that address the trust materialization gap directly:

- **Device-bound session credentials (DBSC)**: Cryptographically binding session tokens to specific devices prevents replay even if cookies are stolen, addressing §4 entirely.
- **Continuous authentication**: Re-verifying identity throughout a session rather than trusting a single point-in-time authentication event, addressing §4 and reducing the value of §3 bypasses.
- **Zero-fallback MFA policies**: Eliminating all phishable fallback methods, accepting the usability/accessibility trade-off, which is the only defense against §3-3 downgrade attacks.
- **Protocol modernization**: Migrating from MD5-based RADIUS to RADSEC, from NTLM to Kerberos with modern protections, and enforcing AES encryption for all Kerberos operations.
- **Credential-less architectures**: Moving toward systems where there is no extractable secret at rest (hardware-bound passkeys without synchronization, certificate-based auth with non-exportable keys), which structurally eliminates §9 credential acquisition attacks.

The trajectory is clear: authentication security must evolve from "verify once, trust forever" to "verify continuously, trust nothing." Until that transition is complete, the techniques documented in this taxonomy will continue to evolve faster than point defenses can contain them.

---

## References

- CrowdStrike, "Analyzing NTLM LDAP Auth Bypass Vulnerability (CVE-2025-54918)," 2025
- RedTeam Pentesting, "A Look in the Mirror - The Reflective Kerberos Relay Attack," June 2025
- Semperis, "Golden dMSA: What Is dMSA Authentication Bypass?," July 2025
- Oasis Security, "Microsoft Azure MFA Bypass," December 2024
- IOActive, "Authentication Downgrade Attacks: Deep Dive into MFA Bypass," 2025
- Proofpoint, "Don't Phish-let Me Down: FIDO Authentication Downgrade," 2025
- JFrog, "CVE-2025-29927 - Authorization Bypass in Next.js," March 2025
- Watchtowr Labs, "FortiOS Authentication Bypass CVE-2024-55591," January 2025
- Sekoia, "Global Analysis of Adversary-in-the-Middle Phishing Threats," 2025
- Palo Alto Unit 42, "Authentication Coercion Keeps Evolving," 2025
- BlastRADIUS Research Team, "RADIUS Protocol Forgery Vulnerability," July 2024
- Securing.pl, "CVE-2025-26788: Passkey Authentication Bypass in StrongKey FIDO Server," February 2025
- PortSwigger Research, "The Fragile Lock: Novel Bypasses for SAML Authentication," 2025
- Apereo Foundation, "CAS OAuth/OpenID Connect & WebAuthN Vulnerability Disclosure," April/September 2025
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
