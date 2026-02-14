# OAuth 2.0 / OpenID Connect Mutation & Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire OAuth/OIDC attack surface along three orthogonal axes derived from systematic analysis of CVEs, academic research (USENIX, IEEE, BlackHat/DEF CON), practitioner writeups, and bug bounty disclosures through 2025.

**Axis 1 — Mutation Target (Primary):** The structural component of the OAuth protocol being mutated or exploited. This axis structures the main body of the document across 10 top-level categories covering redirect flow, authorization codes/tokens, client identity, user identity, consent/scope, session/state, token lifecycle, protocol flow selection, server-side infrastructure, and cross-protocol/integration architecture.

**Axis 2 — Discrepancy Type (Cross-cutting):** The nature of the mismatch or bypass that each mutation creates. Every technique exploits one or more of the following discrepancy types:

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D1** | Validation Bypass | redirect_uri, scope, or client validation is absent or insufficient |
| **D2** | Identity Confusion | User, client, or IdP identity is misattributed or spoofed |
| **D3** | Token/Code Leakage | Authorization material escapes to an unintended party |
| **D4** | State Manipulation | Session, CSRF state, or nonce integrity is broken |
| **D5** | Privilege Escalation | Granted permissions exceed what was authorized |
| **D6** | Protocol Confusion | Flow downgrade, mix-up, or cross-protocol mismatch |
| **D7** | Temporal Exploitation | Race conditions, replay, or token lifetime abuse |

**Axis 3 — Attack Scenario (Mapping):** The real-world outcome: account takeover, token theft, persistent access, SSRF, phishing, supply-chain compromise, or lateral movement. Mapped in §11.

---

## §1. Redirect URI Manipulation

The `redirect_uri` parameter is the primary target for OAuth attacks because it controls where authorization material (codes, tokens) is delivered. Any weakness in redirect URI validation creates a direct path to credential theft.

### §1-1. Validation Bypass Techniques

The authorization server must verify that the `redirect_uri` in the authorization request exactly matches a pre-registered URI. Failures in this validation create the broadest class of OAuth vulnerabilities.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **No validation** | Server accepts any `redirect_uri` value without checking against registered URIs | AS has no allowlist enforcement | D1 |
| **Domain-only matching** | Server validates only the domain/origin, ignoring path, query, and fragment components. Attacker uses `https://legitimate.com/attacker-controlled-path` | AS checks origin but not full path | D1 |
| **Subdomain matching** | Server validates `*.example.com`, allowing `attacker.example.com` or exploiting subdomain takeover | Wildcard or suffix-based validation | D1 |
| **Path traversal** | Attacker appends `/../` or `/..\` sequences to escape validated path prefixes, e.g., `https://client.com/callback/../attacker` | Server normalizes path after validation | D1 |
| **Parameter pollution** | Injecting duplicate `redirect_uri` parameters; server uses the first for validation but the last for redirection (or vice versa) | Inconsistent parameter parsing | D1, D6 |
| **Regex bypass** | Exploiting flawed regex patterns — missing anchors (`^`, `$`), unescaped dots, or greedy quantifiers. E.g., `redirect_uri=https://legitimateXcom.attacker.com` | Custom regex validation instead of exact match | D1 |
| **Scheme manipulation** | Changing `https://` to `http://`, custom schemes (`myapp://`), or `javascript:` URIs | AS doesn't enforce scheme restrictions | D1 |
| **Fragment injection** | Appending `#fragment` to redirect URI; some servers ignore fragments during validation but browsers preserve them during redirect | Inconsistent fragment handling | D1, D3 |
| **Unicode/encoding bypass** | Using URL-encoded, double-encoded, or Unicode characters (e.g., `%2F` for `/`, full-width characters) to bypass string comparison | Validation occurs before URL normalization | D1 |
| **Port manipulation** | Specifying non-standard ports in `redirect_uri` when validation ignores port numbers, e.g., `https://legitimate.com:8443/callback` | Port not included in validation | D1 |

### §1-2. Open Redirect Chaining

When the authorization server enforces strict `redirect_uri` matching but the client application contains an open redirect vulnerability, the attacker chains the two to leak authorization material.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Classic open redirect chain** | `redirect_uri=https://client.com/redirect?url=https://attacker.com` — code/token lands on client, then immediately redirected to attacker | Client has an open redirect endpoint under the registered domain | D1, D3 |
| **Referer-based leakage** | After redirect to client, the client page loads external resources; the `Referer` header leaks the authorization code from the URL query string to third parties | Client pages include external images, scripts, or tracking pixels | D3 |
| **Fragment persistence in redirect** | In implicit flow, access token is in the URL fragment (`#access_token=...`). During client-side redirects, fragments are preserved by the browser and can leak to attacker-controlled destinations | Implicit flow + open redirect on client | D3 |
| **Proxy page leakage** | Client page with `postMessage` or `window.name` that can be read cross-origin acts as a proxy for token exfiltration | Client uses `postMessage` without origin validation | D3 |
| **Path confusion via directory listing** | Redirect to a directory on the client that serves an index page with external links, leaking code via Referer | Client serves user-controllable content under registered path | D3 |

### §1-3. Mobile Redirect Scheme Hijacking

Mobile OAuth implementations use custom URI schemes (e.g., `myapp://callback`) which are not globally unique, creating interception opportunities.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Custom scheme collision** | Multiple apps register the same custom URI scheme; OS delivers the redirect to the wrong (malicious) app | Android/iOS allow duplicate scheme registration | D2, D3 |
| **Intent filter hijacking (Android)** | Malicious app registers a more specific Intent Filter for the OAuth callback URI, gaining priority over the legitimate app | Attacker's app matches the URI with higher specificity | D3 |
| **Claimed URL bypass** | Bypassing Android App Links or iOS Universal Links verification to intercept HTTPS-based redirects | Improperly configured `.well-known/assetlinks.json` or `apple-app-site-association` | D3 |

---

## §2. Authorization Code & Token Handling

The authorization code is the bearer credential exchanged for tokens. Attacks in this category target the code grant flow, token exchange, and the mechanisms that bind codes to their intended recipients.

### §2-1. Authorization Code Interception & Injection

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Code interception via redirect** | Attacker obtains the authorization code through redirect URI manipulation (§1) and exchanges it at the token endpoint before the legitimate client | No PKCE; code is a bearer credential | D3 |
| **Code injection (login CSRF)** | Attacker initiates an OAuth flow, obtains a code bound to their own identity, then injects it into the victim's callback URL. Victim's session is now linked to attacker's account | Missing or weak `state` parameter validation | D4 |
| **Code replay** | Reusing a previously valid authorization code if the AS doesn't invalidate it after first use or has a wide time window | AS allows code reuse or has long code lifetime | D7 |
| **PKCE downgrade** | Attacker strips the `code_challenge` parameter from the authorization request or forces fallback to `plain` method. If AS doesn't mandate PKCE, the code becomes interceptable | AS doesn't require PKCE for all clients | D6 |
| **PKCE bypass via open redirect** | Even with PKCE, if the code leaks to the attacker through an open redirect on the client domain (§1-2), the attacker can steal the code. However, they still need the `code_verifier` — unless the client's own endpoint processes the code automatically | Client auto-exchanges code without PKCE verification | D1, D3 |

### §2-2. Token Leakage Vectors

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Implicit flow token exposure** | Access token delivered in URL fragment is accessible to JavaScript on the page, including injected scripts (XSS) | Use of deprecated implicit flow | D3, D6 |
| **Token in browser history** | Authorization code or token appears in URL, persisting in browser history, proxy logs, and server access logs | Code/token delivered via query parameter | D3 |
| **Token via postMessage** | Client page uses `window.postMessage()` to communicate tokens cross-origin without proper `targetOrigin` restriction | Missing origin validation in postMessage handler | D3 |
| **Token in error responses** | Authorization server or client includes token/code in error redirect parameters, exposing them in logs or to third parties | Verbose error handling that echoes sensitive parameters | D3 |
| **Token via WebSocket** | Client transmits token over unencrypted WebSocket or to an attacker-observable WebSocket endpoint | Insecure WebSocket implementation for token transport | D3 |

### §2-3. Token Exchange Attacks

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Token endpoint CSRF** | Attacker submits a forged token request with a stolen code to the authorization server's token endpoint | Token endpoint doesn't validate client secret or uses public client | D4 |
| **Scope upgrade at token exchange** | Attacker modifies the `scope` parameter in the token request to include higher privileges than originally authorized | AS accepts scope parameter at token endpoint without comparing to original authorization | D5 |
| **Client secret brute-force** | Attacking the token endpoint to guess client_secret values for confidential clients | No rate limiting on token endpoint; weak client secrets | D1 |

---

## §3. Client Identity & Registration

The OAuth client's identity determines what access it receives. Attacks here target client authentication, registration, and impersonation.

### §3-1. Dynamic Client Registration Abuse

OAuth/OIDC dynamic client registration (RFC 7591) allows programmatic client creation, introducing server-side attack surface.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **SSRF via `logo_uri`** | Registering a client with `logo_uri` pointing to an internal resource; AS fetches and returns the content when rendering the consent page | AS resolves `logo_uri` server-side without SSRF protections | D1 |
| **SSRF via `jwks_uri`** | Setting `jwks_uri` to an internal endpoint; AS fetches it when validating client JWT assertions | AS resolves `jwks_uri` without network restrictions | D1 |
| **SSRF via `sector_identifier_uri`** | This OIDC-specific URL points to a JSON array of redirect URIs; AS fetches it during validation | AS resolves the URI without SSRF controls | D1 |
| **SSRF via `request_uris`** | Registering `request_uris` pointing to internal resources; AS fetches them when processing pushed authorization requests | AS supports PAR and resolves request URIs | D1 |
| **XSS via `logo_uri` / `client_name`** | Injecting script payloads into client metadata that renders on the consent screen | AS renders client metadata without sanitization | D1 |
| **Arbitrary redirect registration** | Registering a new client with attacker-controlled redirect URIs, then using session poisoning (§6-2) to redirect tokens to the new client | Open registration endpoint without admin approval | D1, D4 |

### §3-2. Client Impersonation

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Public client spoofing** | Since public clients (SPAs, mobile apps) have no client_secret, any party knowing the `client_id` can impersonate the client | Public client with no PKCE enforcement | D2 |
| **Client secret leakage** | Client secret exposed in client-side code, version control, or error messages, enabling attacker to act as the legitimate client | Secret stored in public artifact (JS bundle, mobile APK, Git repo) | D2, D3 |
| **Client ID metadata document spoofing** | In MCP and newer specs using URL-based client IDs, attacker claims a legitimate client's metadata URL as their own `client_id`, binding to localhost redirect | Metadata document URL used as client_id without ownership verification | D2 |
| **First-party app abuse** | Exploiting pre-consented first-party applications (e.g., Azure CLI, Azure PowerShell) that have high-privilege permissions across all enterprise tenants | Pre-consented apps with `Directory.ReadWrite.All` or similar scopes | D2, D5 |

---

## §4. User Identity & Claims

OAuth delegates authentication; OIDC extends it with identity claims. Attacks here target how user identity is established, verified, and consumed.

### §4-1. Identity Binding Attacks

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Mutable claim confusion** | Application identifies users by mutable fields (email, username) rather than the immutable `sub` claim. Attacker changes their email at the IdP to match the victim's email at the client | Client uses `email` or `preferred_username` as primary identifier | D2 |
| **Pre-account takeover** | Attacker creates an account at the client using the victim's email (without verification), then waits for the victim to "Sign in with OAuth" — the OAuth identity merges with the pre-created account under attacker's control | Client allows account creation without email verification | D2 |
| **Account linking hijack** | When a client supports multiple OAuth providers, attacker forces linking of their IdP account to the victim's existing account by manipulating the linking flow | No CSRF protection on account linking endpoints | D2, D4 |
| **Email verification bypass** | IdP provides `email_verified: false` in the ID token, but the client ignores this flag and trusts the email as verified | Client doesn't check `email_verified` claim | D2 |
| **Sub claim collision across IdPs** | Different IdPs may use the same `sub` value (e.g., numeric IDs). Client using `sub` without scoping to the issuer creates cross-IdP identity collision | Client stores `sub` without `iss` binding | D2 |

### §4-2. Identity Injection

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **ID token forgery** | Attacker forges an ID token with arbitrary claims if the client doesn't validate the JWT signature, or the signing key is compromised/weak | Client skips signature verification or uses `alg: none` | D2 |
| **Claim injection via userinfo** | Attacker modifies claims returned by the userinfo endpoint if the client fetches user data over an insecure channel or doesn't validate against ID token claims | Unprotected userinfo endpoint or lack of cross-validation | D2 |
| **Audience injection** | A novel attack class (2025) exploiting audience handling in signature-based client authentication. Attacker AS claims an honest AS's issuer URI as its token endpoint; client sends credentials to the attacker's endpoint believing it's the honest AS | Client interacts with multiple AS instances and doesn't bind audience to issuer | D2, D6 |

---

## §5. Consent & Scope

OAuth's authorization model relies on user consent and scope boundaries. Attacks here bypass consent or escalate granted permissions.

### §5-1. Consent Bypass

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Consent phishing** | Attacker creates a legitimate-looking OAuth application with deceptive names ("Security Compliance Tool", "Data Loader") and requests dangerous scopes via social engineering | Users approve broad scopes without understanding implications | D5 |
| **Hidden consent grant** | Using `Directory.ReadWrite.All` delegated permission to call `oauth2PermissionGrant` API, programmatically granting additional delegated permissions (e.g., `RoleManagement.ReadWrite.Directory`) to malicious apps without user interaction | Attacker already holds directory write permissions | D5 |
| **Pre-consented app exploitation (AuthCodeFix/ConsentFix)** | Exploiting first-party applications (Azure CLI, Azure PowerShell) with broad pre-consented permissions across all enterprise tenants. Attacker steals auth codes for these apps and exchanges them for high-privilege tokens | Pre-consented apps exist with overly broad scopes | D5, D2 |
| **Incremental scope accumulation** | Requesting minimal scopes initially, then gradually requesting additional scopes in subsequent authorization flows. Users become habituated and approve increasingly dangerous permissions | Application supports incremental consent | D5 |
| **Admin consent phishing** | Targeting administrators to grant `admin_consent` for an application, bypassing per-user consent and granting organization-wide access | Target organization allows admin consent; admin is socially engineered | D5 |

### §5-2. Scope Manipulation

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Scope parameter injection** | Modifying the `scope` parameter in the authorization request to include additional permissions beyond what the application normally requests | AS doesn't restrict requestable scopes per client | D5 |
| **Scope upgrade at token exchange** | Including elevated scopes in the token request that weren't present in the original authorization request (see §2-3) | AS accepts and honors scope parameter at token endpoint | D5 |
| **Offline access persistence** | Including `offline_access` scope to obtain refresh tokens that provide long-lived access beyond the user's session | AS grants offline_access without explicit user understanding | D5, D7 |
| **Dangerous scope combinations** | Individually benign scopes that create dangerous capabilities when combined (e.g., `Application.ReadWrite.All` + `AppRoleAssignment.ReadWrite.All` = full privilege escalation) | No policy engine evaluates combined scope risk | D5 |

---

## §6. Session & State Management

OAuth relies on browser sessions, state parameters, and nonces to maintain flow integrity. Attacks here break these bindings.

### §6-1. CSRF & State Attacks

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Missing state parameter** | No `state` parameter in authorization request; attacker forges the callback URL with their own authorization code, linking victim's session to attacker's identity | Client omits `state` or doesn't validate it | D4 |
| **Predictable state** | State parameter is guessable (sequential, timestamp-based, or derived from known values); attacker pre-computes valid state values | Weak PRNG or deterministic state generation | D4 |
| **State fixation** | Attacker initiates an OAuth flow, captures the `state` value, then tricks the victim into completing the flow with the attacker's state, causing the client to associate the resulting tokens with the attacker's session | State not cryptographically bound to user session | D4 |
| **Cross-tab state confusion** | User has multiple tabs open; authorization response from one flow is consumed by a different tab's OAuth session due to shared cookie state | Client uses cookies (not per-tab storage) for state tracking | D4 |

### §6-2. Session Poisoning

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Authorization session overwrite** | AS stores authorization parameters (`client_id`, `redirect_uri`) in server-side session. Concurrent requests overwrite stored values, causing the response to be sent to attacker's redirect URI | AS uses session-based (not request-ID-based) parameter storage | D4, D3 |
| **Mass assignment on consent endpoint** | Framework's mass assignment (e.g., Spring `@ModelAttribute`) allows attacker to inject parameters like `redirectUri` directly into the consent confirmation request, bypassing initial validation | Framework automatically binds request parameters to session objects (CVE-2021-27582) | D4, D1 |
| **Cookie clobbering** | Attacker sets or overwrites cookies from a related domain that the OAuth client uses for session tracking, disrupting state validation | Related-domain cookie scope or cookie tossing vulnerability | D4 |

### §6-3. Nonce & Replay

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Missing nonce validation** | Client doesn't include or validate the `nonce` in the ID token, allowing replay of intercepted ID tokens from previous sessions | Client omits nonce or skips verification | D7 |
| **ID token replay** | Attacker captures a valid ID token (via network interception or XSS) and replays it to the client to establish an authenticated session | No nonce; long `exp` window; client doesn't track token usage | D7 |
| **Authorization response replay** | Replaying an entire authorization response (code + state) if the code hasn't been invalidated and the state is still valid | AS doesn't enforce single-use codes; client doesn't expire state | D7 |

---

## §7. Token Lifecycle & Persistence

Once tokens are issued, their lifecycle creates an extended attack surface. This category covers post-issuance token abuse.

### §7-1. Token Theft

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **XSS-based token extraction** | JavaScript injection extracts access tokens from localStorage, sessionStorage, or in-memory variables | Token stored in browser-accessible location; XSS vulnerability present | D3 |
| **Token from browser storage** | Access/refresh tokens stored in localStorage are accessible to any script running in the same origin, including injected third-party scripts | Token stored in localStorage instead of httpOnly cookies | D3 |
| **Token from credential stores** | Extracting OAuth tokens from OS credential managers, configuration files, or environment variables on compromised hosts | Token persisted in plaintext on disk | D3 |
| **Token from repository leaks** | OAuth tokens (especially long-lived refresh tokens or client secrets) committed to version control systems | Secrets in source code or configuration files | D3 |
| **Token from proxy/log exposure** | Tokens appearing in server logs, CDN logs, or proxy logs when transmitted as URL parameters rather than headers | Token sent as query parameter instead of Authorization header | D3 |
| **Pass-the-Token** | Using stolen OAuth access tokens directly against resource servers, bypassing the need for credentials or MFA | Bearer token accepted without sender constraint | D3 |

### §7-2. Token Persistence & Abuse

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Refresh token persistence** | Refresh tokens remain valid for 90+ days. Attacker with a stolen refresh token continuously mints new access tokens, maintaining access indefinitely | No refresh token rotation; long token lifetime | D7 |
| **Device code persistence** | Device authorization codes obtain refresh tokens that persist across sessions; attacker maintains access without re-authentication | Device flow tokens not scoped or time-limited | D7 |
| **Token not revoked on password change** | User changes password but existing OAuth tokens remain valid, allowing an attacker who previously stole tokens to maintain access | AS doesn't invalidate tokens on credential change | D7 |
| **Zombie tokens in supply chain** | Third-party integration tokens (e.g., Salesforce connectors) remain active long after the integration relationship ends. Single compromised integration token provides access to hundreds of customer environments (UNC6395/Drift incident, 2025) | No integration token lifecycle management | D7, D3 |
| **Lateral movement via Graph API** | Using stolen OAuth tokens to enumerate tenants, users, and connected applications via Microsoft Graph API, then pivoting to additional services | Token has Graph API scopes; interconnected SaaS environment | D5, D7 |

---

## §8. Protocol Flow Selection & Confusion

OAuth defines multiple grant types. Attacks here exploit the selection, downgrade, or confusion between flows.

### §8-1. Flow Downgrade & Deprecation Exploitation

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Implicit flow exploitation** | Forcing or exploiting use of the implicit flow (deprecated in OAuth 2.1) where tokens are exposed in URL fragments, accessible to JavaScript and leaked via Referer | Application still supports implicit flow | D6, D3 |
| **ROPC (Resource Owner Password Credentials) abuse** | Exploiting applications that accept username/password directly, bypassing the authorization server's authentication UI and any MFA | Application supports ROPC grant | D6 |
| **PKCE downgrade** | Stripping PKCE parameters from authorization requests when the AS doesn't mandate PKCE, reverting to less secure authorization code flow | AS supports both PKCE and non-PKCE flows | D6 |
| **Response type manipulation** | Changing `response_type` from `code` to `token` or `id_token token` to force implicit-like behavior and receive tokens directly | AS supports multiple response types for the same client | D6, D3 |

### §8-2. IdP Mix-Up Attack

When a client interacts with multiple authorization servers, an attacker can confuse the client about which AS issued a particular response.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Classic mix-up** | Attacker operates a malicious AS (AIdP). Client initiates flow with AIdP, but attacker redirects the user to the honest AS (HIdP). User authenticates at HIdP; client sends the resulting code to AIdP's token endpoint, giving the attacker the victim's code | Client interacts with multiple AS; no `iss` parameter in authorization response | D6, D2 |
| **Token endpoint mix-up** | Attacker's AS declares the honest AS's authorization endpoint as its own, but provides its own token endpoint. Client sends credentials (code + client_secret) to attacker's token endpoint | AS metadata not cryptographically verified | D6, D3 |
| **Issuer confusion** | Attacker's AS returns the honest AS's `iss` value in its metadata, tricking the client into treating tokens from different issuers as equivalent | Client doesn't verify `iss` against the AS it originally contacted | D6, D2 |

### §8-3. Device Authorization Grant Attacks

The device code flow (RFC 8628) has emerged as a major attack vector in 2024-2025, particularly in enterprise environments.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Device code phishing** | Attacker initiates device authorization flow, obtains the user code, then socially engineers the victim (email, Teams message, QR code) to enter the code at the legitimate authorization URL. Victim authenticates and grants access to the attacker's session | Device flow enabled; social engineering target susceptible | D4 |
| **MFA bypass via device flow** | Because the user authenticates directly at the AS's login page (which handles MFA), the attacker's device receives tokens with full MFA-authenticated privileges without ever possessing the second factor | Device flow by design separates authentication from the requesting device | D6 |
| **Automated device code campaigns** | Large-scale automated phishing using tools like SquarePhish2 that generate QR codes → redirect to AS → email device codes. Success rates exceeding 50% reported in 2024-2025 campaigns | Bulk phishing infrastructure; enterprise targets | D4 |
| **Mimicry apps** | Attacker registers OAuth applications with names mimicking legitimate tools ("Data Loader", "Security Compliance Tool", "My Ticket Portal") to appear trustworthy in consent prompts | Open app registration; no naming policy enforcement | D2, D5 |

---

## §9. Server-Side Endpoints & Infrastructure

OAuth servers expose multiple endpoints (authorization, token, registration, discovery, userinfo, WebFinger) that present their own attack surface beyond the protocol flow itself.

### §9-1. Discovery & Metadata Attacks

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Metadata endpoint spoofing** | Attacker serves fake `/.well-known/openid-configuration` response (via DNS hijack, MITM, or cache poisoning), redirecting clients to malicious authorization/token endpoints | Client fetches metadata over insecure channel or doesn't pin metadata | D2, D6 |
| **Metadata manipulation** | Modifying specific fields in the discovery document (e.g., `token_endpoint`, `jwks_uri`) to redirect credential flows to attacker infrastructure | Compromised or misconfigured metadata endpoint | D2 |

### §9-2. Registration Endpoint SSRF

(See §3-1 for detailed dynamic client registration SSRF vectors via `logo_uri`, `jwks_uri`, `sector_identifier_uri`, `request_uris`)

### §9-3. WebFinger Injection

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **User enumeration** | `/.well-known/webfinger` endpoint returns HTTP 200 for existing users and 404 for non-existent ones, enabling username enumeration | Unauthenticated WebFinger endpoint with differential responses | D1 |
| **LDAP injection via WebFinger** | The `resource` parameter in WebFinger requests is embedded unescaped into LDAP queries. Attacker uses LDAP wildcards (`*`) and filter injection to extract password hashes character by character | WebFinger backed by LDAP directory without input sanitization (CVE in ForgeRock OpenAM) | D1 |

### §9-4. Token Endpoint Attacks

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Token endpoint SSRF** | If the AS resolves client-provided URLs during token exchange (e.g., fetching JWKS for client authentication), SSRF to internal networks is possible | AS resolves URLs from client assertions without network restrictions | D1 |
| **Consent screen injection** | Injecting malicious content (XSS) via client metadata fields (name, logo, description) that render on the AS consent page | AS renders client metadata without sanitization (CVE-2021-26715) | D1, D3 |

---

## §10. Cross-Protocol & Integration Architecture

Modern OAuth deployments involve integration platforms, multi-hop authorization chains, and protocol bridging that introduce architectural attack surface.

### §10-1. Integration Platform Attacks

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Cross-app OAuth Account Takeover (COAT)** | In integration platforms (Zapier, IFTTT, Microsoft Power Automate), attacker's malicious app exploits the platform's shared OAuth architecture to steal authorization codes intended for other apps. A single click on an attacker link compromises the victim's connected services | Platform's OAuth architecture doesn't isolate per-app authorization flows (CVE-2023-36019, CVSS 9.6) | D2, D3 |
| **Cross-app OAuth Request Forgery (CORF)** | Attacker app on integration platform initiates unauthorized actions using the victim's tokens through the platform's shared token store | Platform doesn't enforce app-level token isolation | D4, D5 |
| **Supply chain token compromise** | Third-party SaaS integration stores OAuth tokens that are later compromised. Single token provides access to hundreds of customer environments (UNC6395/Drift → Salesforce incident, 2025) | Centralized token storage in integration middleware | D3, D7 |

### §10-2. MCP (Model Context Protocol) Authorization Attacks

The MCP protocol's adoption of OAuth (2025) introduces new attack surface in AI agent authorization.

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **Authorization endpoint injection (CVE-2025-6514)** | Malicious MCP server returns crafted `authorization_endpoint` containing embedded shell commands. MCP proxy (`mcp-remote`) executes these via system shell when opening the browser for authorization | MCP proxy doesn't sanitize server-provided OAuth metadata URLs | D1, D6 |
| **Multi-hop confused deputy** | In MCP's multi-hop flow (user → AI host → MCP client → MCP server), identity and permission context is lost or confused at each boundary, enabling privilege escalation | Complex delegation chain without end-to-end authorization binding | D5, D6 |
| **SSRF via Client ID Metadata Documents** | MCP servers fetch client metadata from client-provided URLs. Malicious clients provide URLs pointing to internal resources | Server resolves client_id URLs without SSRF protections | D1 |

### §10-3. Cross-Protocol Confusion

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **OAuth/SAML confusion** | Systems supporting both OAuth and SAML for SSO may have inconsistent identity binding, allowing attackers to exploit differences in how identity is established | Dual-protocol SSO with different identity resolution paths | D2, D6 |
| **Token type confusion** | Using an access token where an ID token is expected (or vice versa), exploiting applications that don't properly validate token type and audience | Application doesn't check token `typ` or `aud` claims | D2 |
| **JWT bearer assertion abuse** | Using legitimate JWT tokens from one context as client assertions in another, exploiting shared signing keys or insufficient audience validation | Shared key infrastructure across services | D2, D6 |

---

## §11. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Account Takeover** | Any OAuth-protected application | §1 + §2-1 + §4-1 + §6-1 |
| **Token Theft / Credential Harvesting** | Applications with token leakage vectors | §1-2 + §2-2 + §7-1 + §8-3 |
| **Persistent Unauthorized Access** | Enterprise cloud environments | §5-2 + §7-2 + §8-3 |
| **Privilege Escalation** | Multi-scope enterprise OAuth (Azure AD, Google Workspace) | §2-3 + §5-1 + §5-2 |
| **SSRF / Server-Side Exploitation** | OAuth servers with dynamic registration | §3-1 + §9-2 + §9-3 |
| **Phishing / Social Engineering** | Enterprise OAuth, device flow | §5-1 + §8-3 |
| **Supply Chain Compromise** | Integration platforms, third-party SaaS | §7-2 + §10-1 |
| **Lateral Movement (Cloud)** | Microsoft 365, Azure AD, Google Workspace | §7-2 + §10-1 + §10-2 |

---

## §12. CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §3-1 (SSRF via `logo_uri`) + §9-4 | CVE-2021-26715 (MITREid Connect) | SSRF + XSS via client registration endpoint. Server fetches and returns `logo_uri` content without validation |
| §6-2 (Mass assignment session poisoning) | CVE-2021-27582 (MITREid Connect) | Spring `@ModelAttribute` mass assignment allows `redirectUri` override at consent endpoint |
| §10-1 (COAT cross-app takeover) | CVE-2023-36019 (Microsoft) | CVSS 9.6. Single click compromises Microsoft 365 suite via integration platform |
| §3-2 (First-party app abuse) | ConsentFix/AuthCodeFix (2025) | Azure CLI and Azure PowerShell pre-consented apps exploitable for tenant-wide privilege escalation |
| §4-1 (Mutable claim confusion) | Google OAuth domain reuse (2024) | Failed startup domains expose millions of accounts. $1,337 Google VRP bounty |
| §10-2 (MCP authorization endpoint injection) | CVE-2025-6514 (mcp-remote) | RCE via malicious MCP server. 558,846 affected downloads |
| §9-3 (LDAP injection via WebFinger) | CVE in ForgeRock OpenAM | Password hash extraction via character-by-character LDAP wildcard injection |
| §8-3 (Device code phishing) | Storm-2372 / ShinyHunters campaigns (2024-2025) | Enterprise-wide compromise of Google, Qantas, and dozens of major organizations. MFA bypass |
| §7-2 (Supply chain token compromise) | UNC6395/Drift-Salesforce (2025) | Single stolen OAuth token provided access to 700+ customer Salesforce instances |
| §2-1 (PKCE downgrade) | OAuth 2.1 / RFC 9700 (2025) | PKCE now mandatory for all clients; non-PKCE flows formally deprecated |
| §4-2 (Audience injection) | Disclosed to IETF OAuth WG (Jan 2025) | New attack class affecting OAuth 2.0, OIDC, FAPI, CIBA, and multiple extensions. Coordinated multi-standard fix effort |
| §10-1 (Cross-app attacks) | USENIX Security '25 | 11 of 18 major integration platforms vulnerable to COAT; 5 to CORF. Microsoft, Google, Amazon affected |
| §1-1 (Redirect URI validation bypass) | Multiple HackerOne reports | Numerous $X,XXX+ bounties for redirect_uri bypasses across major platforms |
| §9-1 (Proxy auth bypass) | CVE-2025-54576 (OAuth2-Proxy) | Authentication bypass in OAuth2-Proxy; fixed in v7.11.0 |
| §8-3 (SAML/OAuth bypass) | CVE-2024-4985 (GitHub Enterprise Server) | Authentication bypass via SAML/OAuth in GitHub Enterprise Server |

---

## §13. Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Burp Suite** (PortSwigger) | Full OAuth/OIDC flow testing | HTTP proxy with OAuth-specific scanning rules; manual flow manipulation |
| **ActiveScan++** (Burp Extension) | OpenID/OAuth discovery | Detects `.well-known/openid-configuration` and registration endpoints automatically |
| **COVScan** (USENIX '25) | Cross-app OAuth vulnerabilities in integration platforms | Semi-automated network traffic analysis for COAT/CORF detection |
| **SquarePhish2** (Offensive) | Device code phishing simulation | Automated device code flow phishing with QR code generation |
| **OWASP ZAP** | General OAuth flow testing | Active/passive scanning of OAuth endpoints |
| **oauth-scanner** (GitHub) | OAuth misconfiguration detection | Checks for common redirect_uri bypasses, missing state, scope issues |
| **Nuclei** (ProjectDiscovery) | OAuth template-based scanning | Community templates for OAuth/OIDC misconfiguration detection |
| **Obsidian Security** (Commercial) | SaaS OAuth token monitoring | Detects suspicious OAuth grants, token abuse, and scope anomalies in cloud environments |
| **Push Security** (Commercial) | OAuth scope risk analysis | Identifies dangerous third-party OAuth integrations and risky scope combinations |
| **Microsoft Entra ID Protection** (Defensive) | Azure AD OAuth monitoring | Detects anomalous OAuth app consent, risky sign-ins, and device code phishing patterns |

---

## §14. Summary: Core Principles

### The Fundamental Property

OAuth's entire mutation space emerges from a single architectural reality: **OAuth is a delegation protocol that separates the party that authenticates (the user) from the party that consumes the authorization (the client), mediated by bearer credentials that traverse the browser**. This three-party architecture — with the browser as an untrusted transport layer — creates inherent trust boundaries that every attack in this taxonomy exploits in some form.

The authorization code, access token, and refresh token are all bearer credentials: whoever possesses them can use them. Unlike passwords (which prove knowledge) or certificates (which prove possession of a private key), OAuth tokens carry no intrinsic binding to their intended holder. PKCE, DPoP, and sender-constrained tokens are mitigations for this fundamental design property, not solutions to it.

### Why Incremental Fixes Fail

Each generation of OAuth security improvements addresses specific attack vectors while the underlying attack surface shifts. PKCE prevented code interception but didn't stop code injection via open redirects. Deprecating implicit flow addressed token exposure in fragments but didn't eliminate token leakage via XSS or postMessage. Strict redirect URI validation prevented trivial redirects but opened the door to increasingly creative chaining attacks through open redirectors, Referer leakage, and proxy pages.

The 2024-2025 wave of device code phishing attacks illustrates this perfectly: the attack exploits no software vulnerability — it leverages the protocol's designed behavior where user authentication is intentionally separated from the requesting device. Similarly, the 2025 audience injection attacks demonstrate that even signature-based client authentication (the strongest client authentication method) carries fundamental ambiguity when clients interact with multiple authorization servers.

### The Structural Solution

A truly structural solution would require three properties that current OAuth deployments largely lack: **(1) sender-constrained tokens** (DPoP, mTLS-bound tokens) that cryptographically bind tokens to their intended holder, **(2) universal PKCE + issuer verification** (now mandated in OAuth 2.1 / RFC 9700) that prevents code interception and mix-up attacks, and **(3) continuous authorization evaluation** that moves beyond one-time consent to real-time policy enforcement over token usage, scope consumption, and behavioral anomalies. Until all three are ubiquitous, the taxonomy above will continue to grow.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- Doyensec, "Common OAuth Vulnerabilities," January 2025 — https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html
- PortSwigger, "Hidden OAuth Attack Vectors" — https://portswigger.net/research/hidden-oauth-attack-vectors
- PortSwigger, "OAuth 2.0 Authentication Vulnerabilities" — https://portswigger.net/web-security/oauth
- Luo et al., "Universal Cross-app Attacks: Exploiting and Securing OAuth 2.0 in Integration Platforms," USENIX Security '25 — https://www.usenix.org/conference/usenixsecurity25/presentation/luo-kaixuan
- Küsters & Würtele, "Audience Injection Attacks: A New Class of Attacks on Web-Based Authorization and Authentication Standards," 2025 — https://eprint.iacr.org/2025/629
- IETF, "Updates to OAuth 2.0 Security Best Current Practice" — https://datatracker.ietf.org/doc/draft-wuertele-oauth-security-topics-update/
- IETF, "OAuth 2.0 Security Best Current Practice" — https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-22.html
- Obsidian Security, "The New Attack Surface: OAuth Token Abuse" — https://www.obsidiansecurity.com/blog/the-new-attack-surface-oauth-token-abuse
- Obsidian Security, "From Well-Known to Well-Pwned: Common Vulnerabilities in AI Agents" — https://www.obsidiansecurity.com/blog/from-well-known-to-well-pwned-common-vulnerabilities-in-ai-agents
- Semperis, "A New App Consent Attack: Hidden Consent Grant" — https://www.semperis.com/blog/app-consent-attack-hidden-consent-grant/
- Amla Labs, "When OAuth Becomes a Weapon: Lessons from CVE-2025-6514" — https://amlalabs.com/blog/oauth-cve-2025-6514/
- Proofpoint, "Access Granted: Phishing with Device Code Authorization" — https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover
- Unit42, "Trusted Connections, Hidden Risks: Token Management in the Third-Party Supply Chain" — https://unit42.paloaltonetworks.com/third-party-supply-chain-token-management/
- Push Security, "Dangerous OAuth Scopes in Third-Party Integrations" — https://pushsecurity.com/blog/the-risky-terrain-of-oauth-scopes-in-third-party
- Praetorian, "Attacking and Defending OAuth 2.0" — https://www.praetorian.com/blog/attacking-and-defending-oauth-2/
- WorkOS, "Defending OAuth: Common Attacks and How to Prevent Them" — https://workos.com/blog/oauth-common-attacks-and-how-to-prevent-them
- HackTricks, "OAuth to Account Takeover" — https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover
- OWASP, "OAuth 2.0 Protocol Cheatsheet" — https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
