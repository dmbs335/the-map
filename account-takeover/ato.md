# Registration & Account Takeover — Mutation/Variation Taxonomy

---

## Classification Structure

Registration & Account Takeover (Reg/ATO) is a vulnerability class spanning the entire account lifecycle — from account creation, authentication, and session maintenance to recovery. It is not a single vulnerability but a complex attack surface arising at various transition points of the **authentication state machine**.

This taxonomy is structured along three axes:

- **Axis 1 — Mutation Target**: Which component of the account lifecycle is being manipulated. This forms the primary structure of the document.
- **Axis 2 — Discrepancy Type**: What kind of verification failure or state inconsistency enables the attack. This is the cross-cutting axis that applies across all categories.
- **Axis 3 — Attack Scenario**: How the mutation is weaponized in real-world exploitation.

### Axis 2 — Discrepancy Types (Cross-Cutting Classification)

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D1** | Identity Verification Gap | Absence or bypass of email/phone ownership verification |
| **D2** | State Management Flaw | Abnormal persistence or non-invalidation of sessions, tokens, or state transitions |
| **D3** | Token/Secret Weakness | Token predictability, low entropy, or existence of leakage paths |
| **D4** | Logic Flow Bypass | Skipping steps or manipulating the order of authentication/verification flows |
| **D5** | Race Condition / TOCTOU | Exploiting the time gap between validation and use |
| **D6** | Trust Boundary Violation | Server unconditionally trusts client-side data |
| **D7** | Channel Compromise | Compromise of the authentication channel itself (SMS, email, deep links) |

---

## §1. Registration / Account Creation Attacks

The account creation phase is the **pre-authentication battleground** of ATO. Attackers either pre-create accounts on services where the victim has not yet registered, or exploit flaws in the registration process itself.

### §1-1. Pre-Account Takeover

An attack class where the attacker creates an account **before the victim registers**, maintaining access to that account when the victim later signs up. Five variants were systematically classified by Microsoft Research in 2022.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Classic-Federated Merge** | Attacker creates a classic (password-based) account with the victim's email → victim signs up via OAuth/SSO with the same email → service auto-merges both accounts, granting the attacker access | Service auto-merges classic/federated accounts based on email | D1, D4 |
| **Unexpired Session Identifier** | Attacker creates an account with the victim's email and maintains a login session → victim recovers the account via password reset → attacker's existing session is not invalidated | Password reset does not invalidate existing sessions | D2 |
| **Trojan Identifier** | Attacker creates an account with the victim's email and adds secondary authentication factors (phone number, backup email) → victim recovers the account but attacker's secondary factors persist | Account recovery does not remove pre-existing secondary authentication methods | D2, D4 |
| **Unexpired Email Change** | Attacker creates an account with the victim's email → initiates an email change request (without completing confirmation) → victim recovers the account → attacker completes the pending email change confirmation link to change the email to their own | Password reset does not invalidate pending email change tokens | D2, D3 |
| **Non-Verifying IdP** | Attacker creates an account via an IdP that does not verify email ownership → victim signs up via the classic route with the same email → service trusts the IdP email as verified and merges accounts | IdP does not verify email ownership and service blindly trusts it | D1, D6 |

### §1-2. Email Verification Bypass

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Response Manipulation** | Tamper with server response status codes or JSON fields to activate an account without email verification (e.g., `{"verified": false}` → `{"verified": true}`) | Server relies on client response for verification state | D6 |
| **Forced Browsing** | Directly access post-verification pages/APIs without completing email verification | Server does not check verification state on every request | D4 |
| **Activation Endpoint Direct Call** | Directly invoke the activation API endpoint without an email token to activate the account | Token verification not implemented on activation endpoint | D4 |
| **Email Normalization Differential** | Exploit normalization differences in email addresses — case sensitivity, dots (.), plus (+) tags — to bypass verification (e.g., `victim@gmail.com` vs `Victim@Gmail.com`) | Inconsistent email normalization logic between registration and verification | D1 |
| **Verification Link Reuse** | Reuse a previously used verification link for a new email change | Verification token not bound to a specific email address | D3 |
| **Auto-Login on Registration** | Auto-login on registration completion without email verification; attacker registers with the victim's email and immediately obtains a session | Email verification decoupled from the registration flow | D1, D4 |

### §1-3. Mass Assignment / Parameter Injection

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Role Escalation** | Add privilege fields such as `role=admin` or `isAdmin=true` to the registration request to create an administrator account | Server binds all request body fields to the object | D6 |
| **Organization/Tenant Injection** | Manipulate `org_id` or `tenant_id` parameters during registration to join another organization as an admin | Insufficient tenant isolation in multi-tenant architecture | D6 |
| **Account State Manipulation** | Inject state fields such as `verified=true`, `active=true`, or `email_confirmed=true` into the registration request | Account state fields not protected by an allowlist | D6, D4 |
| **Hidden Field Injection** | Add API parameters not exposed in the frontend (e.g., `credit_balance`, `subscription_tier`) to the registration request | API schema accepts more fields than the client form | D6 |

### §1-4. Registration Race Condition

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Duplicate Account Creation** | Send simultaneous registration requests with the same email/username to bypass uniqueness constraints and create duplicate accounts | Uniqueness check performed at application level rather than DB transaction level | D5 |
| **Invitation Code Reuse** | Send simultaneous multiple registration requests with a single-use invitation code to reuse the code | Invitation code consumption is not an atomic operation | D5 |
| **Promo/Coupon Double-Spend** | Apply a promotional code multiple times during registration via race condition | Non-atomic processing of coupon consumption logic | D5 |
| **Registration Flooding** | Automatically create a large number of fake accounts to exhaust service resources or perform user enumeration | No rate limiting / CAPTCHA on the registration endpoint | D4 |

---

## §2. Password Reset / Recovery Attacks

Password reset is the **most frequent entry point** for ATO. Vulnerabilities arise at every stage of the reset flow — token generation, delivery, validation, and application.

### §2-1. Token Generation Weakness

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Predictable Token (Timestamp-based)** | Reset token generated as an MD5/SHA1 hash of a timestamp, making it predictable | No CSPRNG used; timestamp-based token generation | D3 |
| **Sequential Token** | Tokens generated as sequential integers or following a sequential pattern | No randomness in token generation | D3 |
| **Short Token / Low Entropy** | Token length is short (e.g., 4-6 digit numbers), making brute-force feasible | Insufficient token entropy + inadequate rate limiting | D3 |
| **Token Reuse Across Users** | Reset tokens generated in the same time window are identical across different users | No per-user unique seed in token generation | D3 |
| **UUID v1 Token** | UUID v1 (timestamp + MAC address based) used as reset token, making it predictable | UUID v1 used instead of CSPRNG-based UUID v4 | D3 |

### §2-2. Token Delivery / Leakage

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Host Header Poisoning** | Attacker tampers with the `Host` header in the reset request to their domain → server generates a reset link pointing to that domain → victim clicks and token is sent to the attacker's server | Server uses the `Host` header to construct the reset URL | D3, D6 |
| **Referer Header Leakage** | Token in the URL leaks via the `Referer` header when the reset page loads external resources (images, scripts, links) | Reset token included in URL parameters + external resource loading | D3 |
| **Response Body Exposure** | Reset token included in the API response body, exposed to the client | Token returned in the HTTP response, not only via email | D3 |
| **X-Forwarded-Host Poisoning** | Manipulate proxy headers such as `X-Forwarded-Host` or `X-Original-URL` to alter the reset URL's host | Host determination behind a reverse proxy trusts proxy headers | D3, D6 |
| **Password Reset via API Response** | Reset token or temporary password directly included in the API response | Debug information exposure for development convenience | D3 |

### §2-3. Token Validation Bypass

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **User ID Manipulation** | Change the `user_id` parameter in the reset URL to another user's ID to reset their password | Token not bound to a specific user | D4, D6 |
| **Token-User Decoupling** | Reset token and user identifier passed as separate parameters, enabling a valid own token + another user's ID combination | User binding not verified during token validation | D4 |
| **Empty/Null Token** | Pass empty string, `null`, or `undefined` as the token value to bypass validation | Inadequate exception handling for empty tokens (e.g., `if (token == storedToken)` where storedToken is null) | D4 |
| **Token Expiration Bypass** | Expired tokens are still processed as valid | Token expiration validation not implemented or server time mismatch | D2, D3 |
| **Brute-Force Token** | Brute-force a short token (4-6 digits) to find a valid one (success cases with ~60,000 requests documented) | No rate limiting on the token validation endpoint | D3 |
| **Token Not Invalidated After Use** | Used reset tokens are not invalidated and can be reused | Token deletion/invalidation not implemented after use | D2 |

### §2-4. Password Reset Flow Logic Flaw

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **MFA Step Skip** | Skip the MFA verification step in the reset flow and directly access the password change step | Each step in the reset flow does not verify completion of the previous step | D4 |
| **Email Parameter Override** | Tamper with the `email` parameter in the reset request to the attacker's email to receive the reset token at the attacker's inbox | Server uses the request parameter email instead of session/token-bound email | D6 |
| **Password Reset via OAuth Chain** | Cross-exploit the OAuth "forgot password" flow and the standard reset flow to bypass authentication | No state isolation between OAuth callback and password reset flows | D4 |
| **Account Recovery Question Bypass** | Security question answers are empty, case-insensitive, or guessable from public information | Inherent weakness of security question-based recovery | D1 |

---

## §3. Session Management Attacks

Sessions are the **runtime representation** of authentication state. ATO can occur at every stage of session token lifecycle — generation, delivery, maintenance, and invalidation.

### §3-1. Session Fixation

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **URL-based Fixation** | Attacker sends the victim a URL containing a known session ID → victim logs in via that URL → attacker accesses the authenticated session using the same session ID | Session ID not regenerated on login | D2 |
| **Cookie-based Fixation** | Set a session cookie known to the attacker in the victim's browser via XSS or a related domain vulnerability | Subdomain XSS + session ID not regenerated | D2 |
| **Cross-Subdomain Fixation** | Set a parent domain cookie from a related subdomain to fix the target application's session | Wildcard cookie domain configuration | D2 |

### §3-2. Session Hijacking

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **XSS-based Token Theft** | Exfiltrate session tokens from `document.cookie` or `localStorage` via Stored/Reflected XSS | XSS vulnerability + HttpOnly flag not set | D7 |
| **Cookie Theft via Malware** | Infostealer malware extracts session cookies from the browser and sends them to the attacker | Inadequate endpoint security | D7 |
| **Network-level Interception** | Capture session tokens via network sniffing on unencrypted communications (HTTP) | HTTPS not enforced or Secure flag not set | D7 |
| **Token Replay / Pass-the-Cookie** | Reuse stolen session tokens in the attacker's browser to bypass authentication (also bypasses MFA) — 147,000 token replay attacks detected by Microsoft in 2024 | Session token not bound to device/IP | D2 |
| **Citrix-style Session Theft** | Directly query/steal other users' session cookies via a server-side vulnerability (2024 MITRE breach case) | Server-side vulnerability enabling access to the session store | D7 |

### §3-3. Session State Exploitation

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Session Non-Invalidation on Password Change** | Existing sessions not invalidated after password change/reset, allowing the attacker to maintain access | Full session invalidation not implemented on password change | D2 |
| **Concurrent Session Abuse** | No limit on concurrent sessions per account, allowing attacker and victim to be active simultaneously | No concurrent session control implemented | D2 |
| **Session Persistence After Account Deactivation** | Existing sessions remain valid even after account deactivation/deletion | Session invalidation not linked to account state changes | D2 |
| **JWT None Algorithm** | Set the JWT algorithm to `none` to create a valid token without a signature | JWT library allows the `none` algorithm | D3, D4 |
| **JWT Key Confusion (RS256→HS256)** | Use the RS256 public key as the HS256 secret key to forge tokens | JWT implementation allows algorithm confusion | D3 |

---

## §4. Multi-Factor Authentication Bypass

MFA is the **last line of defense** against ATO, yet implementation flaws enable numerous bypasses.

### §4-1. OTP/Code Bypass

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **OTP Brute-Force** | Systematically brute-force 4-6 digit OTPs (up to 999,999 attempts) | No rate limiting / account lockout on the OTP verification endpoint | D3 |
| **Rate Limit Reset via Resend** | Requesting OTP resend resets the attempt counter, enabling unlimited brute-force | Resend resets the existing OTP attempt count | D4 |
| **OTP in Response Body** | OTP included in the API response body, visible in network traffic | OTP included in the response for development/debug purposes | D3 |
| **OTP Non-Expiration** | OTP remains valid indefinitely without a time limit, enabling slow brute-force | OTP expiration time not configured | D3 |
| **Universal/Default OTP** | A specific value (e.g., `000000`, `123456`) is always valid as a backdoor OTP | Test default OTP persists in production | D3, D4 |
| **OTP Reuse** | Already-used OTP is not invalidated and can be reused | OTP invalidation after use not implemented | D2 |

### §4-2. MFA Flow Logic Bypass

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Direct Dashboard Access** | After step 1 (password) authentication, directly access post-authentication pages without completing step 2 (MFA) | MFA completion not verified server-side on every request | D4 |
| **MFA Step Parameter Manipulation** | Manipulate request parameters such as `mfa_required=false` or `step=3` to skip the MFA step | MFA state depends on client-side parameters | D6 |
| **Response Manipulation** | Tamper with the MFA verification response status code from `403` → `200` | Client-side flow control based on response codes | D6 |
| **Backup Code Brute-Force** | Brute-force MFA backup codes (typically 8-character alphanumeric) | No rate limiting on backup code verification | D3 |
| **MFA Downgrade (2FA → No FA)** | 2FA deactivation request requires no re-authentication, allowing an attacker to remove MFA after session hijack | 2FA deactivation does not require current 2FA code verification | D4 |
| **MFA Setup Hijack** | TOTP seed exposed in API response during 2FA setup, or accessible from another session before setup completion | TOTP seed exposure + insufficient session isolation in setup flow | D3, D2 |

### §4-3. MFA Channel Compromise

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **SIM Swap** | Deceive the carrier into transferring the victim's number to the attacker's SIM → receive SMS OTP — 1,055% increase in UK in 2024 | SMS-based MFA + inadequate carrier identity verification | D7 |
| **SS7 Interception** | Exploit SS7 protocol vulnerabilities to intercept SMS OTP at the network level | SS7's lack of authentication/encryption (legacy design) | D7 |
| **MFA Prompt Bombing / Fatigue** | Repeatedly send MFA approval push notifications to the victim, inducing accidental or fatigue-driven approval | Push-based MFA + no notification rate limit | D7 |
| **OAuth Device Code Phishing** | Abuse the OAuth 2.0 Device Authorization Grant flow to trick the victim into entering the attacker's device code on a legitimate Microsoft authentication page — actively used by state-sponsored actors since January 2025 | OAuth Device Code Flow + social engineering | D7 |
| **AiTM (Adversary-in-the-Middle) Phishing** | Real-time reverse proxy (Evilginx, Modlishka, etc.) relays the legitimate site while simultaneously capturing MFA tokens and session cookies | Real-time phishing proxy + session token not bound to device | D7 |

---

## §5. OAuth / SSO / Federated Authentication Attacks

OAuth and SSO form the **delegation layer** of authentication. Unique attack surfaces exist in state management, token exchange, and account linking during the delegation process.

### §5-1. OAuth Flow Exploitation

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **CSRF on OAuth Callback** | OAuth `state` parameter not validated → attacker sends their own OAuth callback URL to the victim → victim's account is linked to the attacker's social account | `state` parameter not used or not validated | D4, D6 |
| **Open Redirect in OAuth** | Lax validation of the OAuth `redirect_uri` leaks authorization code/token to the attacker's domain | Wildcard or sub-path only validation of redirect_uri | D3 |
| **Authorization Code Replay** | Used authorization code is not invalidated and can be reused | One-time use of authorization code not enforced | D2 |
| **Token Substitution** | OAuth token issued for a different application used to authenticate on the target application | Token's `aud` (audience) claim not validated | D4 |
| **Implicit Flow Token Interception** | Access token in the fragment (#) of an Implicit Grant is leaked via an open redirect | Implicit Flow usage + inadequate redirect_uri validation | D3 |

### §5-2. Account Linking Exploitation

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Email-based Auto-Linking** | During OAuth login, the email returned by the IdP is auto-linked to an existing account with the same email → attacker uses an IdP that returns the victim's email to access the existing account | Email-based auto account linking + IdP email verification not checked | D1, D6 |
| **IdP Email Unverified Trust** | Service ignores `email_verified=false` returned by the IdP and trusts the email regardless | IdP response's `email_verified` field not checked | D1 |
| **Dangling OAuth Connection** | OAuth connection of a deleted social account persists on the service; a new account with the same social ID accesses the existing service account | OAuth connection not refreshed on social account deletion/recreation | D2 |
| **Google Domain Ownership Change** | When company domain ownership changes, the new owner authenticates via Google OAuth with the same domain email → accesses former employees' SaaS accounts | Google OAuth allows domain email-based authentication + domain ownership change not reflected | D1 |

---

## §6. Credential-Based Attacks

Direct credential attacks represent the **highest-volume** ATO attack vector. As of 2024, over 7 billion credentials are circulating on the dark web.

### §6-1. Credential Replay

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Credential Stuffing** | Automatically attempt leaked email/password combinations at scale against target services — 2025 Synthient data: 2 billion unique emails, 1.3 billion unique passwords | Password reuse + inadequate rate limiting | D3 |
| **Password Spraying** | Attempt a small set of common passwords (`Password1!`, `Summer2025!`, etc.) against many accounts | Account lockout policies fail to detect distributed attempts | D3 |
| **AI-Optimized Credential Selection** | AI agents optimize attacks by analyzing previous success patterns, targeting high-value domains, and predicting password reuse probability | Next-generation credential attacks leveraging ML models | D3 |
| **Stealer Log Exploitation** | Access accounts using session cookies + credential logs collected by infostealer malware | Endpoint infection + stored login credentials | D7 |

### §6-2. Brute-Force Variants

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Classic Brute-Force** | Attempt all possible password combinations against a single account | No account lockout or rate limiting | D3 |
| **Distributed Brute-Force** | Perform brute-force from multiple IPs to bypass rate limiting | Only IP-based rate limiting applied (no account-based limiting) | D3 |
| **Username Enumeration → Targeted Attack** | Extract a list of valid usernames using differential responses from registration/login/reset flows, then launch targeted attacks | Differential responses such as "User does not exist" vs. "Incorrect password" | D1 |

---

## §7. Client-Side Vulnerability Chains

Not ATO on their own, but XSS and CSRF serve as **core building blocks of ATO chains**.

### §7-1. XSS → ATO Chains

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Stored XSS → Cookie Exfiltration** | Exfiltrate session cookies to an external server via Stored XSS | XSS + HttpOnly flag not set | D7 |
| **Stored XSS → Email/Password Change** | XSS payload calls email or password change APIs within an authenticated context | XSS + no re-authentication required for sensitive operations | D7, D4 |
| **Self-XSS + Login CSRF** | Login CSRF forces the victim to log into the attacker's account, then Self-XSS on the settings page executes in the victim's browser → steals the victim's real session/data | Self-XSS + no CSRF protection on login endpoint | D7 |
| **XSS → OAuth Token Theft** | Steal OAuth access tokens or refresh tokens from localStorage/sessionStorage via XSS | OAuth tokens stored in JavaScript-accessible storage | D7 |
| **Zero-Click XSS ATO** | XSS in an external script or embedded component auto-executes without user interaction to achieve ATO — in the Meta CAPI Gateway case, combined with CORS whitelist to enable Facebook ATO | XSS in auto-loaded scripts + CORS misconfiguration | D7 |

### §7-2. CSRF → ATO Chains

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **CSRF Email Change** | When the victim visits the attacker's page, an email change request is automatically sent, changing the account email to the attacker's email | No CSRF token on email change + no re-authentication required | D4 |
| **CSRF Password Change** | Password change request has no CSRF protection and does not require the current password | No current password + no CSRF token required for password change | D4 |
| **CORS Misconfiguration → Token Theft** | Overly permissive CORS policy (`Access-Control-Allow-Origin: *` with credentials) allows authenticated API calls and token theft from the attacker's site — Langflow CVE-2025-34291 case | CORS misconfiguration + `SameSite=None` cookies | D4, D7 |

---

## §8. Authorization & Parameter Control Attacks

Even after authentication, flaws in **authorization boundaries** allow access to other accounts.

### §8-1. IDOR-based ATO

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Profile IDOR** | Change the user ID in an API request to view another user's profile (email, password hash, etc.) | No object-level access control implemented | D6 |
| **Password Change IDOR** | Change the user ID in the password change API to reset another user's password ($500 bounty case) | Session user and target user match not verified during password change | D6 |
| **API Key/Token IDOR** | Retrieve another user's API key or authentication token via IDOR to access their account | Inadequate access control on API key management endpoints | D6 |
| **Account Settings IDOR** | Modify another user's account settings (email, MFA, linked social accounts, etc.) via IDOR | No object-level authorization verification on settings change APIs | D6 |

### §8-2. Privilege Escalation via Registration Context

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Invitation System Abuse** | Tamper with the role/permission parameters in an invitation link to register with higher privileges | Role information included in invitation token without signing | D6 |
| **Tenant Switching** | Tamper with the tenant identifier during registration/login to authenticate as a user of another organization | Insufficient multi-tenant isolation | D6 |
| **Admin Registration Endpoint Exposure** | Admin-only registration endpoints (`/admin/register`, `/api/admin/signup`) accessible without authentication — Shopify bounty case | No access control implemented on admin endpoints | D4 |

---

## §9. Passwordless / Magic Link Attacks

Passwordless authentication creates a new attack surface.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Magic Link Token Interception** | Intercept the magic link token in the email via MITM, email account compromise, or Referer leakage | Magic link includes token in URL parameters + inadequate email channel security | D3, D7 |
| **Deep Link Hijacking (Mobile)** | A malicious app intercepts the mobile app's deep link handler to steal the magic link token — $500 bounty case on Android | Inadequate deep link verification + malicious app installed | D7 |
| **Magic Link URL Parameter Manipulation** | Tamper with the callback URL parameter in the magic link to redirect to the attacker's site after authentication + token leakage | No callback URL allowlist applied | D3 |
| **Magic Link Non-Expiration** | Magic link does not expire or remains valid for an extended period (days), enabling reuse from email archives | Token expiration not set or excessively long validity period | D3 |
| **Passwordless → Password Recovery Paradox** | Account recovery mechanism in a passwordless system is vulnerable, causing ATO during the recovery process | Recovery flow negates the security benefits of passwordless | D4 |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Condition | Primary Mutation Categories |
|----------|-------------------------|---------------------------|
| **Pre-Account Takeover** | Victim has not registered on the service + attacker knows the victim's email | §1-1, §5-2 |
| **Full Account Takeover** | Complete control of the account obtained post-authentication | §2, §3-2, §4, §6, §7 |
| **Privilege Escalation** | Elevation from a normal user to admin/high-privilege role | §1-3, §8-2 |
| **Credential Replay at Scale** | Automated attacks leveraging large-scale leaked data | §6-1, §6-2 |
| **MFA Bypass → ATO** | Account access after circumventing MFA protection | §4-1, §4-2, §4-3 |
| **Session Persistence ATO** | Maintaining access even after the legitimate owner changes the password | §1-1 (Unexpired Session), §3-3 |
| **Chain Attack (Multi-Bug)** | Composite attack combining two or more vulnerabilities | §7-1, §7-2 + §2 or §5 |
| **Supply Chain / Domain ATO** | Account access via domain ownership changes or service acquisitions | §5-2 (Domain Ownership Change) |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §5-1 + §7-2 (CORS + CSRF + OAuth) | CVE-2025-34291 (Langflow) | Critical — ATO + RCE. Cross-origin requests enable token refresh |
| §7-1 (Zero-Click XSS → ATO) | Meta CAPI Gateway XSS (2026) | Full Facebook ATO. CORS whitelist + Stored XSS chain |
| §3-2 + §4-3 (Session Theft + MFA Bypass) | MITRE Corporation Breach (2024) | Citrix vulnerability → session cookie theft → MFA bypass |
| §5-2 (Domain Ownership Change) | Google OAuth Domain Takeover | Mass SaaS ATO. Domain ownership change enables access to former employees' accounts |
| §4-3 (Device Code Phishing) | UNK_SneakyStrike Campaign (2025-01) | 80,000+ accounts targeted, ~100 cloud tenants attacked |
| §6-1 (Credential Stuffing) | Snowflake Customer Breach (2024) | Massive data breach. Leaked credentials + MFA not enforced |
| §2-1 + §2-3 (Predictable Token + Brute-Force) | RubyGems Password Reset (2024) | Package manager ATO possible. MD5(timestamp)-based token |
| §4-3 (SIM Swap) | T-Mobile Arbitration Ruling (2024) | $33M award. Single SIM swap leading to cryptocurrency theft |
| §8-1 (IDOR → Password Change) | HackerOne Bounty Report | $500. IDOR enabling password change for other users |
| §7-1 (Stored XSS + IDOR) | Label Studio GHSA-2mq9 | Full ATO. Stored XSS + IDOR chain via custom_hotkeys field |
| §1-3 (Mass Assignment) | Shopify Privilege Escalation | Unrestricted admin account creation. Role parameter manipulation in registration |
| §1-2 (Invalid Email Registration) | HackerOne Signup Process | $3,750. Account creation with invalid emails containing special characters (%) |
| §2-2 (Host Header Poisoning) | CVE-2024-5910 (Palo Alto Expedition) | Critical. Missing authentication leading to admin ATO |
| §3-3 (JWT None Algorithm) | CVE-2025-6023 (Grafana) | High. Incomplete fix → path traversal + open redirect → Full ATO |
| §3-3 + §4-2 (Session + MFA) | CVE-2025-1723 (ADSelfService Plus) | Session mismanagement enabling unauthorized access to user enrollment data when MFA not enabled |
| §7-1 (Self-XSS → ATO) | Facebook Self-XSS Payments | $62,500. Self-XSS in payment flow chained to Full ATO |
| §7-1 (FXAuth Token Abuse) | Facebook Two-Click ATO | $30,000. FXAuth token abuse for two-click ATO |

---

## Detection Tools

### Offensive Tools (Attack / Testing)

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Burp Suite** (Proxy) | Full authentication flow | Request interception, parameter tampering, automated scanning |
| **Evilginx** (Reverse Proxy) | AiTM phishing | Real-time session token/MFA capture reverse proxy |
| **Modlishka** (Reverse Proxy) | AiTM phishing | Automatic certificate generation + real-time session capture |
| **SquarephishV2** (Phishing) | OAuth Device Code | Device code phishing campaign automation |
| **Nuclei** (Scanner) | Known ATO patterns | Template-based large-scale vulnerability scanning |
| **ffuf / Turbo Intruder** (Fuzzer) | Rate Limiting / OTP | High-speed brute-force and race condition testing |
| **jwt_tool** (JWT) | JWT tokens | None algorithm, key confusion, claim tampering |
| **Autorize** (Burp Extension) | IDOR / Access Control | Automated authorization verification testing |
| **Hydra / Medusa** (Brute-Force) | Login endpoints | Distributed password brute-force |

### Defensive Tools (Defense / Detection)

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Cloudflare Bot Management** | Credential Stuffing | AI-driven bot detection + behavioral analysis + threat intelligence |
| **Netacea** | All ATO attempts | Intent Analytics engine — session intent prediction |
| **Imperva ATO Protection** | Login protection | Zero-latency login protection module |
| **Proofpoint ATO Protection** | Email + Account | Threat intelligence + ML-based anomaly detection |
| **Datadog ATO Protection** | Full application | Runtime behavior monitoring + automatic blocking |
| **Have I Been Pwned (HIBP)** | Leaked credentials | Leaked password/email database lookup |
| **Passkeys / FIDO2 WebAuthn** | Full authentication | Phishing-resistant hardware-based authentication |

---

## Summary: Core Principles

### Root Cause: Incompleteness of the Authentication State Machine

The root cause of Registration & Account Takeover vulnerabilities is that the **authentication state machine is inherently incomplete**. A web application's account undergoes dozens of state transitions — creation, verification, authentication, session maintenance, recovery, linking, and deactivation — and at each transition point, the following invariant must hold: *"Is the entity performing this action the legitimate owner of this account?"* If this invariant breaks at even a single transition, ATO occurs.

### Why Incremental Patches Fail

The ATO attack surface is **combinatorial**. Individual features (registration, login, reset, OAuth, MFA) may each be implemented correctly, yet new vulnerabilities emerge from their **interactions** (Classic-Federated Merge, OAuth + Reset chains, XSS + CSRF + Email Change). Furthermore, MFA — the supposed silver bullet — is bypassed via SIM Swap, AiTM proxies, OTP brute-force, and Device Code phishing. Attackers can choose the weakest channel, while defenders must protect all channels.

### Structural Solution

A true structural solution is grounded in three principles:

1. **Phishing-Resistant Authentication**: Passkeys/FIDO2 WebAuthn ensures authentication secrets never leave the device and are bound to the domain, structurally blocking AiTM and phishing.
2. **Session-Device Binding**: Cryptographically bind session tokens to the issuing device's hardware characteristics, preventing token reuse after theft (Token Binding, DPoP).
3. **Atomic State Transition Verification**: Re-verify the authentication context at the point of every state change (password reset, email change, OAuth linking, MFA deactivation), and atomically invalidate all related prior tokens/sessions.

Until these three principles are fully applied, Registration & Account Takeover will continue to remain the most frequent and impactful vulnerability class.

---

## References

- Microsoft Security Response Center, "Pre-hijacking Attacks on Web User Accounts" (2022)
- Sudhodanan & Paverd, "Pre-hijacked Accounts: An Empirical Study of Security Failures in User Account Creation on the Web" (USENIX Security 2022)
- PortSwigger Web Security Academy — Password Reset Poisoning, Race Conditions, OAuth
- OWASP Testing Guide — Authentication Testing, Session Management Testing
- OWASP Cheat Sheet Series — Forgot Password, Session Management, Credential Stuffing Prevention
- HackTricks — Reset/Forgotten Password Bypass, 2FA/MFA/OTP Bypass
- Proofpoint Threat Insight — "Access Granted: Phishing with Device Code Authorization" (2025)
- Positive Security — "Ransacking Your Password Reset Tokens"
- Sentry Security Blog — "Cracking Password Reset Mechanisms"
- Obsidian Security — CVE-2025-34291 Langflow Disclosure
- OPSWAT Unit 515 — Grafana CVE-2025-6023
- Microsoft MSRC — "Weaponizing Cross-Site Scripting" (2025)
- Youssef Sammouda — "Multiple XSS in Meta Conversion API Gateway" (2026)
- Bugcrowd — "Breaking the Chain: Exploiting OAuth and Forgot Password for Account Takeover"
- Keepnet Labs — "SIM Swap Fraud 2025: Stats, Legal Risks & 360° Defenses"
- Vectra AI — "The Hidden Risks of SMS-Based Multi-Factor Authentication"
- AppOmni — "How to Handle Increased Account Takeover Risks from Recent Credential Dumps" (2025)
- HackerOne Reports — Various bug bounty disclosures referenced in CVE/Bounty table

---

*This document was created for defensive security research and vulnerability understanding purposes.*
