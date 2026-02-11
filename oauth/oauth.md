# OAuth 2.0 / OpenID Connect Vulnerability Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire OAuth 2.0 and OpenID Connect (OIDC) attack surface under three orthogonal axes. **Axis 1 (Mutation Target)** is the primary structural axis — it defines *what component of the OAuth/OIDC mechanism is being mutated*. **Axis 2 (Discrepancy Type)** is the cross-cutting axis — it explains *what kind of mismatch or bypass the mutation creates*. **Axis 3 (Attack Scenario)** is the mapping axis — it connects mutations to *real-world impact*.

OAuth 2.0 (RFC 6749) is a delegation protocol — it enables a **Resource Owner** to grant a **Client** limited access to resources hosted by a **Resource Server**, mediated by an **Authorization Server (AS)**. OpenID Connect (OIDC) extends OAuth with an identity layer, adding ID tokens (JWTs), UserInfo endpoints, and discovery mechanisms. The security model relies on redirect-based flows where authorization codes or tokens traverse the user agent (browser). Every mutation in this taxonomy exploits a failure in how these flows validate redirects, bind state, verify tokens, manage consent, or establish trust between parties.

For JWT-specific vulnerabilities (algorithm confusion, key injection, claim manipulation, brute force), see the dedicated [JWT Vulnerability Taxonomy](../jwt/jwt.md).

### Axis 2: Discrepancy Types (Cross-Cutting)

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D1** | Redirect/URL Validation Failure | Redirect URI or URL-based parameter is not properly validated against the registered value |
| **D2** | State/Binding Mismatch | CSRF state, nonce, PKCE verifier, or session binding is absent or not properly enforced |
| **D3** | Validation Omission | A required verification step (token validation, scope check, audience check) is missing or incomplete |
| **D4** | Trust Boundary Confusion | Client, AS, or RP trusts an unverified or attacker-controlled entity |
| **D5** | Token/Credential Leakage | Token or secret is exposed through front-channel, logs, referer, or insecure storage |
| **D6** | Scope/Permission Escalation | Granted permissions exceed what was authorized by the resource owner |
| **D7** | Flow Abuse | Legitimate protocol flow is weaponized via social engineering or redirection |
| **D8** | Protocol-Level Gap | Structural omission or ambiguity in the specification itself enables attack |

---

## §1. Redirect URI Manipulation

The `redirect_uri` parameter is the critical trust anchor of OAuth's authorization code and implicit flows. The AS redirects the user agent back to this URI carrying authorization codes or tokens. If an attacker can substitute or manipulate this URI, they intercept the authorization response.

### §1-1. Redirect URI Validation Bypass

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Missing validation** | AS does not validate `redirect_uri` at all, accepting any attacker-controlled URL. The authorization code or token is delivered to the attacker's server | D1 | No redirect_uri validation implemented; or validation only at registration, not at authorization |
| **Subdomain matching** | Validation checks only the parent domain (e.g., `*.example.com`), allowing redirect to an attacker-controlled subdomain (`evil.example.com`) or a subdomain with XSS | D1 | Wildcard or suffix-based domain validation |
| **Path manipulation** | Validation checks domain + base path but allows path traversal (e.g., `https://legit.com/callback/../../../attacker/steal`) or appended path segments (e.g., `https://legit.com/callback/../../attacker`) | D1 | Path normalization not applied before comparison; or prefix-only matching |
| **URL parser differential** | Exploit differences between how the AS and the client parse URLs. Techniques include userinfo confusion (`https://legit.com@evil.com`), backslash confusion (`https://evil.com\.legit.com`), percent-encoding tricks (`%40`, `%2F`), and Unicode normalization differences | D1, D4 | Different URL parsing libraries between AS and client; inconsistent handling of special characters |
| **Fragment injection** | Append `#` to redirect_uri, causing the authorization code to be appended after a fragment delimiter. The code is not sent to the server in the HTTP request but is accessible via JavaScript on the page | D1, D5 | Client-side code on the callback page processes URL fragments; or AS does not strip fragments from redirect_uri |
| **Open redirect chaining** | Use a legitimate open redirect endpoint on the whitelisted callback domain to bounce the authorization response to an attacker-controlled destination | D1, D7 | Open redirect exists on a domain within the allowed redirect_uri set |
| **Scheme downgrade** | Change `redirect_uri` from `https://` to `http://` to enable token interception via network-level MitM | D1, D5 | AS does not enforce HTTPS for redirect_uri |
| **Port manipulation** | Register `https://legit.com/callback` but request authorization with `https://legit.com:8443/callback` where the attacker controls port 8443 | D1 | AS applies lax port matching or ignores port in comparison |
| **Regex bypass** | When the AS validates redirect_uri using regular expressions, exploit unescaped special characters (`.` matching any character, missing `$` anchor, unescaped `?`) to match unintended URIs | D1 | AS uses regex matching without proper escaping or anchoring (CVE-2024-52289, Authentik) |
| **Response_mode manipulation** | Change `response_mode` from `query` to `fragment` or `form_post`. Some AS implementations apply different redirect_uri validation logic depending on the response mode, or the change alters where/how the token is exposed | D1, D5 | AS validation behavior varies by response_mode |

### §1-2. Mobile & Native App Redirect Interception

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Custom scheme hijacking** | Multiple apps register the same custom URI scheme (e.g., `myapp://callback`). A malicious app intercepts the authorization code intended for the legitimate app | D4, D5 | Mobile app uses custom URI scheme without platform-verified app links (Universal Links / App Links) |
| **Localhost port sniffing** | Native desktop app uses `http://localhost:{port}/callback`. Attacker runs a listener on the same port before the legitimate app starts, intercepting the authorization code | D5 | Loopback redirect without PKCE; OS allows binding to the same port |
| **WebView token theft** | Malicious app opens the OAuth flow in an embedded WebView rather than the system browser, gaining JavaScript access to the callback URL and intercepting tokens or codes | D5 | User is directed to authenticate in an embedded WebView controlled by the attacker app |
| **Loopback IPv4/IPv6 confusion** | Authorization server validates `redirect_uri` against `http://localhost`, but attacker binds to `http://127.0.0.1` or `http://[::1]` which bypass the validation while resolving to the same machine | D1 | AS treats `localhost`, `127.0.0.1`, and `[::1]` as distinct values |

### §1-3. Front-Channel Token Interception via Browser Mechanisms

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **postMessage token theft** | OAuth popup flow uses `window.postMessage()` to send the authorization response to the parent window. If the `targetOrigin` is set to `"*"` or validated with weak regex, any parent window (including attacker-controlled pages) receives the token | D5, D1 | postMessage target origin not strictly validated; or `response_type=web_message` used without origin whitelist (Frans Rosen, "Dirty Dancing in Sign-In OAuth Flows") |
| **Service Worker interception** | A malicious Service Worker registered on the redirect URI's origin (via XSS or supply chain compromise) intercepts all `fetch` events within its scope, capturing authorization codes and tokens. SWs persist across page loads and browser restarts, providing durable persistence even after the initial XSS is patched | D5 | XSS or supply chain compromise on the callback domain enables SW registration |
| **Third-party JS on callback page** | The legitimate redirect_uri page includes third-party JavaScript (analytics, tag managers, ads). These scripts can read `location.hash` (fragment) or `location.search` (query string), exfiltrating the authorization code or token to external servers | D5 | Third-party scripts loaded on the OAuth callback page; no strict CSP |

---

## §2. Authorization Code & PKCE Exploitation

The authorization code flow is the recommended OAuth flow. PKCE (Proof Key for Code Exchange, RFC 7636) was designed to protect the code exchange from interception. Failures in PKCE enforcement or code handling create interception vectors.

### §2-1. Code Interception Without PKCE

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Classic code interception** | Intercept the authorization code from the redirect URI (via network MitM, open redirect, or malicious app) and exchange it for tokens at the token endpoint. Without PKCE, any party possessing the code and client credentials can complete the exchange | D2, D5 | Client does not use PKCE; code transmitted via front channel without binding |
| **Code leakage via Referer header** | The authorization code in the callback URL is leaked through the HTTP Referer header when the callback page loads external resources (images, scripts, tracking pixels) | D5 | Callback page loads third-party resources; code is in query string (not fragment) |
| **Code leakage via browser history** | Authorization code persists in browser history and can be extracted by shared computer users or browser extensions | D5 | Code in URL query string; no immediate code exchange and redirect |

### §2-2. PKCE Downgrade & Bypass

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **PKCE not enforced** | AS supports PKCE but does not require it. Attacker sends the authorization request without `code_challenge`, then intercepts and exchanges the code without `code_verifier` | D2, D3 | PKCE optional; AS accepts requests without code_challenge (CVE-2024-23647, Authentik) |
| **PKCE method downgrade** | Downgrade from `S256` (SHA-256 hashed) to `plain` code challenge method. If the AS accepts `plain`, the attacker who intercepts the authorization request can read the `code_challenge` directly and use it as the `code_verifier` | D2 | AS accepts `plain` method; does not enforce S256 |
| **PKCE state mismatch** | AS does not bind the `code_challenge` to the specific authorization session. Attacker initiates their own authorization request (obtaining a code_challenge-free session) and then substitutes the victim's authorization code into this session | D2 | code_challenge not cryptographically bound to the authorization session |
| **PKCE skip via MCP proxy** | In MCP (Model Context Protocol) OAuth implementations, the PKCE check can be bypassed by manipulating the proxy's state handling, allowing code exchange without the verifier | D2, D3 | MCP OAuth proxy does not enforce PKCE on code exchange (Cloudflare workers-oauth-provider GHSA-qgp8-v765-qxx9) |

### §2-3. Code Replay & Exchange Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Code replay** | Use the same authorization code multiple times. If the AS does not invalidate the code after first use, tokens can be obtained repeatedly | D3 | AS does not enforce single-use authorization codes |
| **Code substitution** | Attacker obtains an authorization code (e.g., via social engineering or rogue client) and substitutes it into the victim's callback flow | D2, D4 | Missing state parameter validation; code not bound to the specific client session |
| **Client authentication bypass** | Exchange authorization code at the token endpoint without proper client authentication (missing or forged `client_secret`, or no client authentication required for confidential clients) | D3, D4 | Token endpoint does not enforce client authentication |

### §2-4. Pushed Authorization Requests (PAR) Bypass

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **PAR not enforced (fallback to inline)** | AS supports PAR but does not require it (`require_pushed_authorization_requests` not enabled). Attacker bypasses PAR protections entirely by sending a traditional authorization request with manipulated inline parameters directly to the authorization endpoint | D3, D8 | PAR optional; AS accepts both PAR `request_uri` and inline parameters |
| **request_uri replay** | The `request_uri` returned by the PAR endpoint is intercepted and reused in a different browser session. If the AS does not enforce single-use semantics or has an excessively long TTL, the attacker completes the flow using the stolen reference | D2 | PAR `request_uri` not single-use; excessive validity window (>60 seconds) |
| **request_uri prediction** | PAR `request_uri` reference values are generated with insufficient entropy (sequential, timestamp-based, or short). Attacker guesses valid references and uses them before the legitimate client | D2, D5 | Weak randomness in `request_uri` generation |
| **Client auth downgrade at PAR endpoint** | PAR endpoint accepts multiple client authentication methods. Attacker compromises the weaker credential (e.g., `client_secret_post`) and pushes authorization requests on behalf of the legitimate client that normally uses `private_key_jwt` | D3, D4 | AS does not enforce single authentication method per client at PAR endpoint |
| **PAR + unsigned request tampering** | PAR requests are not signed (relying on client authentication + TLS). An attacker in a MitM position between client and AS (e.g., compromised corporate proxy) modifies PAR request parameters in transit | D4 | PAR used without JAR (RFC 9101) for request signing; TLS termination at an intermediary |

---

## §3. Token Lifecycle & Binding Attacks

OAuth tokens (access tokens, refresh tokens, ID tokens) are bearer credentials by default — anyone possessing the token can use it. Attacks on token lifecycle exploit this bearer property, weak binding, and lifecycle management failures.

### §3-1. Token Leakage Vectors

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Implicit flow token exposure** | In the Implicit Grant, the access token is returned in the URL fragment, exposable via Referer header leaks, browser history, XSS on the callback page, or browser extensions | D5, D7 | Application uses Implicit Grant (deprecated in OAuth 2.1) |
| **Token in URL query string** | Access token passed as URL query parameter (e.g., `?access_token=...`) instead of Authorization header. Logged in server access logs, proxy logs, and browser history | D5 | Client or API accepts tokens in query parameters |
| **Token leakage via error pages** | Authorization errors redirect back to the client with the token still in the URL. Error pages may log or display the token | D5 | Error handling exposes token-bearing URLs |
| **Token leakage via XSS** | Cross-site scripting on the callback domain or application pages allows JavaScript extraction of tokens from URL fragments, localStorage, sessionStorage, or cookies | D5 | XSS vulnerability on a domain that handles or stores tokens |
| **Response_mode fragment exposure** | When `response_mode=fragment`, the token is delivered in the URL fragment. While fragments are not sent to servers in HTTP requests, they are accessible to any JavaScript on the page and persist in browser history | D5 | Application relies on fragment-based token delivery without strict CSP |

### §3-2. Token Replay & Revocation Failure

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Refresh token persistence after revocation** | OAuth consumer authorization is revoked, but existing refresh tokens remain valid and can continue generating new access tokens | D3 | Revocation of authorization does not cascade to refresh tokens (CVE-2025-32068, MediaWiki OAuth Extension) |
| **Refresh token theft** | Steal a long-lived refresh token (from device storage, database, or network interception) and use it to continuously generate new access tokens, maintaining persistent access even after password changes | D5 | Refresh tokens not bound to client/device; not revoked on password/credential change |
| **Refresh token rotation race condition** | Send multiple concurrent requests to the token endpoint using the same refresh token. Non-atomic read-check-rotate operations allow multiple requests to succeed, each returning a different new refresh token — creating multiple valid token "branches" that defeat rotation | D3 | Refresh token rotation not serialized; no atomic compare-and-swap |
| **Refresh token rotation grace period abuse** | Many implementations allow a "grace period" (30–120s) during which the old refresh token remains valid after rotation. Attacker who steals a token during this window uses the old token to obtain an independent new token pair, even after the legitimate client has rotated | D3, D5 | Grace/reuse interval implemented for reliability; attacker obtains token within window |
| **Token replay across services** | Bearer access token issued for Resource Server A is replayed against Resource Server B that shares the same AS. Without audience restriction, the token is accepted | D3, D4 | No audience (`aud`) restriction on access tokens; shared AS across services |
| **Missing token revocation endpoint** | Application has no mechanism to revoke tokens (RFC 7009). After user logout or password change, existing tokens remain valid until natural expiration | D3 | Token revocation endpoint not implemented; stateless token validation only |

### §3-3. Sender-Constrained Token Bypass

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **DPoP proof replay** | Capture a DPoP (Demonstrating Proof of Possession, RFC 9449) proof JWT and replay it within its validity window. If the AS or RS does not enforce nonce binding or strict timestamp validation, the proof is accepted | D2 | DPoP nonce not enforced; excessive validity window |
| **mTLS certificate substitution** | In certificate-bound access tokens (RFC 8705), substitute the client certificate during token presentation. If the RS does not validate that the presented certificate matches the one bound at issuance, the binding is ineffective | D3, D4 | RS does not validate certificate thumbprint against token binding |
| **Downgrade to bearer** | Remove DPoP or mTLS binding headers from the request. If the RS accepts both sender-constrained and bearer tokens, the attacker can use the stolen token as a plain bearer token | D3 | RS does not enforce sender-constraining; accepts fallback to bearer |

---

## §4. State, Nonce & CSRF Exploitation

OAuth and OIDC rely on ephemeral state parameters to prevent cross-site request forgery and token replay. Weaknesses in these binding mechanisms enable session fixation and login CSRF attacks.

### §4-1. State Parameter Attacks

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Missing state parameter** | No CSRF protection on the OAuth callback. Attacker initiates an OAuth flow with their own identity, forces the victim's browser to complete it, linking the attacker's identity to the victim's session | D2 | `state` parameter not implemented or not validated on callback |
| **State fixation** | Attacker obtains a valid state value and forces the victim to use it (e.g., by pre-loading the authorization URL). The attacker can then complete the flow on behalf of the victim | D2 | State is predictable, reusable, or not cryptographically bound to the user session |
| **Predictable state** | State parameter is generated using weak randomness (sequential counter, timestamp, MD5 of session ID). Attacker predicts the value and crafts a forged callback URL | D2 | Insufficient entropy in state generation |
| **State leakage** | State parameter leaked via Referer header, server logs, or browser history, enabling an attacker to use it for CSRF or session correlation | D2, D5 | State transmitted in URL without protections against leakage |

### §4-2. Nonce & ID Token Replay (OIDC)

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Missing nonce validation** | ID token `nonce` claim is not validated against the value sent in the authorization request. Attacker replays a captured ID token to authenticate as the victim | D2 | Client does not verify `nonce` claim matches the authorization request value (CVE-2024-10318, NGINX OIDC) |
| **Nonce reuse** | Client reuses the same nonce across multiple authorization requests, defeating replay detection | D2 | Nonce not generated fresh per authorization request |
| **ID token injection** | Attacker obtains an ID token (e.g., from their own flow) and injects it into the victim's callback response. Without `nonce` validation and `c_hash`/`at_hash` verification, the injected token is accepted | D2, D4 | Client does not validate `c_hash` (code hash) or `at_hash` (access token hash) claims in the ID token |

### §4-3. Login CSRF & Session Fixation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Login CSRF (forced login)** | Attacker forces victim to log into the attacker's account via OAuth, then captures the victim's subsequent actions (credentials entered, sensitive data uploaded) in what the victim believes is their own account | D2, D7 | Application allows OAuth-initiated login without CSRF protection |
| **Post-authentication session fixation** | After successful OAuth authentication, the application does not regenerate the session ID. An attacker who set the session ID before authentication can now use the authenticated session | D2 | Session ID not regenerated after OAuth callback completes |

---

## §5. Scope, Consent & Permission Exploitation

OAuth scopes define the permissions a client is requesting. The consent screen is the user's opportunity to approve or deny these permissions. Manipulating scope handling or bypassing consent enables privilege escalation.

### §5-1. Scope Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Scope upgrade in token request** | Send an elevated `scope` parameter in the token exchange request (not specified in the original authorization). If the AS trusts the scope in the token request without cross-referencing the authorization grant, elevated permissions are issued | D6 | AS does not verify scope in token request matches the authorized scope |
| **Scope manipulation via token reuse** | Steal an access token from Implicit Flow and replay it with manually appended scope parameters against the resource server | D6 | Resource server reads scope from the request rather than from the token introspection |
| **Unrestricted client scopes** | AS allows any client to request any scope. Attacker registers a new client and requests highly privileged scopes (e.g., `admin:*`, `user.read.all`) | D6, D3 | No per-client scope restriction; AS grants any requested scope if user consents |
| **Scope parameter injection** | Inject additional scope values via parameter pollution or delimiter manipulation (e.g., `scope=openid+admin:write` where `+` is interpreted as a space/delimiter differently by AS and client) | D6 | Inconsistent scope string parsing between components |

### §5-2. Consent Bypass

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Consent bypass via `prompt=none`** | Submit authorization request with `prompt=none`. If the user has previously consented to any scope for this client, the AS may grant access without re-prompting, even if the current request includes additional scopes | D6, D7 | AS grants previously-consented scopes without re-prompting when additional scopes are requested |
| **Pre-approved scope exploitation** | Some first-party or "trusted" clients are pre-approved and skip consent entirely. If the client_id of a pre-approved client is obtained, any authorization request using that client_id bypasses consent | D6, D4 | Pre-approved clients exist; client_id is predictable or leaked |
| **Consent phishing (illicit consent grant)** | Attacker registers a malicious OAuth application with a legitimate-sounding name and requests broad permissions. Social engineering tricks the user into granting consent. The attacker then has persistent, MFA-bypassing access via OAuth tokens | D7 | No admin approval required for app registration; users can consent to broad scopes |
| **Incremental consent abuse** | Request minimal scopes initially to gain user trust and approval, then silently escalate via incremental authorization without a new consent screen | D6, D7 | AS applies incremental consent without user re-approval for new scopes |

### §5-3. Token Exchange & Delegation Abuse

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Impersonation via token exchange** | Use RFC 8693 Token Exchange to request a token acting as a different user. If the AS does not validate the `may_act` claim or restrict which clients can perform impersonation, arbitrary user impersonation is possible | D6, D4 | AS allows token exchange without validating delegation/impersonation constraints |
| **Excessive delegation scope** | Token exchange produces a delegated token with broader scope than the original token, violating the principle that delegation should not escalate privileges | D6 | AS does not restrict delegated token scope to be a subset of the original |
| **Chained token exchange** | Perform multiple successive token exchanges, each incrementally expanding scope or changing the subject, resulting in a token with permissions far beyond the original grant | D6 | No chain depth limit or cumulative scope restriction on token exchange |

---

## §6. Client Identity & Registration Exploitation

OAuth clients are registered entities with credentials (client_id, client_secret). Weaknesses in client identity management, credential protection, and dynamic registration create impersonation and SSRF vectors.

### §6-1. Client Credential Exploitation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Client secret exposure** | `client_secret` leaked via source code repository, mobile app reverse engineering, client-side JavaScript, configuration files, or debug endpoints. Attacker impersonates the legitimate client | D5 | Secret embedded in public client (mobile app, SPA) or committed to version control |
| **Client secret in URL** | `client_secret` passed as URL query parameter in token requests, logged in server access logs and proxy logs | D5 | Client sends secret via GET parameters instead of POST body or Authorization header |
| **Missing client authentication** | Token endpoint does not require client authentication for confidential clients. Any party possessing an authorization code can exchange it for tokens | D3 | Token endpoint accepts unauthenticated token requests |
| **Weak client secret** | Client secret is short, predictable, or shared across environments. Can be brute-forced or guessed | D5 | Insufficient entropy in client secret generation |
| **OIDC client_secret leak (CVE-2025-59363)** | OIDC provider API exposes plaintext `client_secret` for all applications in the tenant, enabling mass client impersonation | D5 | Provider API does not redact secrets in admin responses |

### §6-2. Dynamic Client Registration Abuse

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Unauthenticated registration** | OAuth/OIDC dynamic client registration endpoint (RFC 7591) accepts registration requests without authentication. Attacker registers a malicious client with attacker-controlled redirect_uri | D4 | Dynamic registration enabled without authentication or admin approval |
| **SSRF via client metadata URIs** | Set `logo_uri`, `policy_uri`, `tos_uri`, `sector_identifier_uri`, or `jwks_uri` to internal network addresses during client registration. When the AS fetches these URLs for display or validation, it performs server-side requests to internal services | D4 | AS fetches client metadata URIs without SSRF protection |
| **Client impersonation via registration** | Register a client with a name, logo, and description closely resembling a trusted application. Users grant consent believing they are authorizing a legitimate service | D7 | No verification of client identity or branding during registration |
| **Redirect URI injection via registration** | Register a client with multiple redirect_uris, including an attacker-controlled URL alongside legitimate ones. If the AS allows any registered redirect_uri to be used in authorization requests, the attacker can specify their URI | D1, D4 | AS does not restrict which registered redirect_uri can be used per-request |

---

## §7. OIDC Discovery & Federation Exploitation

OpenID Connect adds a discovery layer (`.well-known/openid-configuration`) and federation trust chains on top of OAuth 2.0. These additional components introduce their own attack surface.

### §7-1. Discovery Endpoint Manipulation

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Discovery endpoint injection** | Manipulate the OIDC discovery document (`.well-known/openid-configuration`) via path traversal or host header injection. The attacker's modified document specifies attacker-controlled `authorization_endpoint`, `token_endpoint`, or `jwks_uri`, redirecting the entire OAuth flow | D4 | Discovery endpoint is vulnerable to path manipulation or host header injection |
| **MCP OAuth metadata injection** | In MCP (Model Context Protocol) environments, the server returns a crafted `authorization_endpoint` in its OAuth metadata. The MCP client opens this URL without sanitization, enabling command injection or redirection to attacker-controlled authentication pages | D4 | MCP client trusts server-provided OAuth metadata without validation (CVE-2025-6514, mcp-remote) |
| **JWKS endpoint substitution** | Replace the `jwks_uri` in the discovery document with an attacker-controlled URL hosting crafted signing keys. The RP fetches the attacker's keys and accepts tokens signed with them | D4 | RP fetches JWKS from the discovery document URL without pinning or verification |
| **Metadata inconsistency exploitation** | Different AS nodes behind a load balancer serve different versions of the discovery document (e.g., inconsistent `code_challenge_methods_supported`). Clients parsing different metadata versions behave differently, creating exploitable divergence | D4, D8 | AS cluster serves inconsistent discovery metadata |

### §7-2. IdP Trust & Multi-Tenant Confusion

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **IdP mix-up attack** | Attacker tricks the client into sending the authorization request to one IdP but processing the response as if it came from another. The client accepts a token from an attacker-controlled IdP because it doesn't verify the `iss` claim against the intended provider | D4 | Client does not verify issuer matches the IdP it sent the authorization request to; multiple IdPs share the same redirect_uri |
| **Multi-tenant common endpoint abuse** | In multi-tenant IdP deployments (e.g., Azure AD/Entra ID), attacker creates a tenant and configures it as a trusted IdP for target RPs that accept tokens from the common endpoint (`/common/` or `/organizations/`) | D4 | RP trusts the IdP's common endpoint rather than a tenant-specific endpoint |
| **Mutable claim identity binding** | RP identifies users by mutable fields (email, UPN) from OIDC claims instead of immutable `sub` claim. Attacker changes their email at the IdP to match the victim's identifier at the RP | D4, D6 | RP uses email or other mutable claim as primary user identifier (GHSA-gxh2-6vvc-rrgp, Grafana Azure AD) |

### §7-3. OIDC Federation in CI/CD Environments

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Overly permissive OIDC trust policy** | Cloud IAM roles trust OIDC tokens from a CI/CD provider with wildcarded conditions (e.g., `repo:*`, `branch:*`), allowing any repository or branch to assume the role | D4, D6 | Trust policy does not restrict to specific repos/branches/environments |
| **Forked repo token abuse** | CI/CD platform issues OIDC tokens to workflow executions from forked repositories. Attacker forks a public repo, modifies the workflow to exfiltrate the OIDC token, and uses it to access cloud resources | D4 | CI/CD platform issues tokens to forked repo workflows without restriction |
| **Subject claim wildcard bypass** | OIDC trust policy uses regex-based matching on the `sub` claim. Attacker creates new organizations, repos, or branches whose names match the regex pattern | D4 | Regex-based `sub` claim matching without strict anchoring (Unit 42 "OH-MY-DC" research, DEF CON 32) |
| **Poisoned pipeline execution + OIDC** | Attacker modifies a CI/CD pipeline definition (via PR, compromised dependency, or branch manipulation) to execute code that requests OIDC tokens, then uses those tokens to access cloud resources | D4, D7 | Pipeline allows execution of untrusted code with access to OIDC token generation |

---

## §8. Grant Flow Abuse

Each OAuth/OIDC grant type defines a specific authorization flow for different client types and deployment scenarios. Abusing the intended semantics of these flows — especially through social engineering — represents a growing attack vector.

### §8-1. Device Authorization Grant (Device Code Flow) Exploitation

The Device Authorization Grant (RFC 8628) is designed for input-constrained devices. It has become the most actively exploited OAuth flow in 2024–2025, weaponized at scale for enterprise phishing.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Device code phishing** | Attacker initiates a device authorization request, obtains a user code, and socially engineers the victim into entering it at the legitimate IdP's device login page (e.g., `microsoft.com/devicelogin`). Victim authenticates with full MFA, granting the attacker's polling client an access and refresh token | D7 | Device flow is enabled; no mechanism to verify that the person entering the code is the device operator |
| **Automated device code harvesting** | Scale device code phishing through automated campaigns (tools like SquarePhish, Graphish), generating unique device codes per target and polling for completion. Reported success rates exceed 50% in targeted campaigns | D7 | No rate limiting on device code generation; long polling intervals (default 5-minute expiry allows extended attack windows) |
| **Device code + MFA bypass** | Since the victim authenticates directly at the IdP (including completing MFA), the attacker's token inherits full MFA-authenticated privileges. This makes device code phishing uniquely effective against MFA-protected accounts | D7 | Token does not distinguish between direct and device-code-mediated authentication |
| **Persistent access via device code** | Attacker obtains refresh tokens through device code phishing, enabling long-term access that survives password changes (unless refresh tokens are explicitly revoked) | D7, D5 | Refresh tokens issued during device code flow are not specially restricted or monitored |
| **Branded app social engineering** | Register OAuth applications with legitimate-sounding names ("Data Loader", "Security Compliance Tool", "My Ticket Portal") to increase credibility of the device code phishing pretext | D7 | No verification of app name/branding during registration |

### §8-2. Client Credentials Grant Abuse

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Stolen service credentials** | Obtain `client_id` and `client_secret` for a service account (from source code, config files, CI/CD variables). Use client_credentials grant to obtain tokens with the service's permissions, bypassing user authentication entirely | D5 | Service credentials exposed; no additional controls on client_credentials grant |
| **Over-permissioned service identity** | Service account is granted broad scopes (`*`, `admin:*`) for operational convenience. Compromise of the service credentials provides total access | D6 | Principle of least privilege not applied to service accounts |

### §8-3. Resource Owner Password Credentials (ROPC) Grant Abuse

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Credential harvesting via rogue client** | A malicious or compromised client collects username/password directly (the ROPC grant requires the client to handle raw credentials). The client forwards credentials to the AS but also exfiltrates them | D5, D7 | Application uses ROPC grant; user enters credentials directly into the client (deprecated in OAuth 2.1) |
| **Brute force via ROPC endpoint** | Use the token endpoint with ROPC grant as a credential-testing oracle, attempting username/password combinations. Rate limiting may be weaker on the token endpoint than on the login page | D7 | ROPC grant enabled; token endpoint lacks rate limiting |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **Account Takeover** | Web apps with OAuth login | §1 + §4-1 + §2-1 | Full account compromise via redirected auth code |
| **Token Theft & Lateral Movement** | Multi-service OAuth ecosystems | §3-1 + §3-2 + §5-1 | Cross-service access from single token compromise |
| **Enterprise Phishing (MFA Bypass)** | Microsoft 365, Google Workspace | §8-1 (device code) + §5-2 (consent) | MFA-bypassing account takeover at scale |
| **Privilege Escalation** | APIs with scope-based access | §5-1 + §5-3 | Admin access via scope manipulation |
| **CI/CD Pipeline Compromise** | Cloud-native OIDC federation | §7-3 + §3-2 | Cloud resource access via pipeline tokens |
| **SSRF / Internal Network Access** | AS with dynamic client registration | §6-2 (SSRF) | Internal service scanning, metadata theft |
| **Persistent Backdoor** | OAuth with refresh tokens | §3-2 + §8-1 | Long-term access surviving password changes |
| **Client Impersonation** | Multi-tenant OAuth providers | §6-1 + §6-2 | Act as trusted application, harvest user consent |
| **AI Agent Compromise** | MCP/Agent OAuth flows | §7-1 (metadata injection) | RCE on AI client via crafted OAuth metadata |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Product | Impact |
|---------------------|-----------|---------|--------|
| §1-1 (regex bypass) | CVE-2024-52289 | Authentik | Account takeover via redirect_uri regex bypass |
| §2-2 (PKCE downgrade) | CVE-2024-23647 | Authentik | PKCE bypass by removing code_challenge; code interception |
| §2-2 (PKCE skip via MCP) | GHSA-qgp8-v765-qxx9 | Cloudflare workers-oauth-provider | PKCE check skipped in MCP OAuth proxy |
| §4-2 (nonce replay) | CVE-2024-10318 | NGINX OIDC Reference Impl. | Session fixation via missing nonce validation |
| §1-1 (skip_auth_routes regex) | CVE-2025-54576 | OAuth2-Proxy | CVSS 9.1. Auth bypass via regex match against full URI including query params |
| §3-2 (refresh token revocation) | CVE-2025-32068 | MediaWiki OAuth Extension | Revoked authorization leaves refresh tokens valid |
| §7-1 (MCP metadata injection) | CVE-2025-6514 | mcp-remote | CVSS 9.6. RCE via crafted OAuth authorization_endpoint in MCP metadata |
| §6-1 (client_secret exposure) | CVE-2025-59363 | OneLogin API | Plaintext client_secret exposed for all OIDC apps in tenant |
| §7-2 (mutable claim binding) | GHSA-gxh2-6vvc-rrgp | Grafana (Azure AD OAuth) | Account takeover via email claim manipulation in multi-tenant Azure AD |
| §7-3 (CI/CD OIDC) | — (Unit 42 "OH-MY-DC") | GitHub Actions, CircleCI | Cloud resource access via OIDC trust policy misconfiguration |
| §8-1 (device code phishing) | — (ShinyHunters/UNC6040) | Microsoft 365, Google, Salesforce | Mass enterprise compromise, MFA bypass, data exfiltration (2024–2025) |
| §8-1 (device code phishing) | — (Storm-2372/UNK_AcademicFlare) | Microsoft 365 | State-aligned espionage via device code phishing (Proofpoint, 2025) |
| §5-2 (consent phishing) | — (Multiple campaigns) | Microsoft 365 | Illicit consent grants; persistent OAuth access to email, files, Teams |

---

## Detection Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **OAUTHScan** | Burp Extension | OAuth 2.0 / OIDC | Automated passive and active scanning for OAuth/OIDC misconfigurations; integrated with Burp Scanner |
| **EsPReSSO** | Burp Extension | Multi-protocol SSO | Detect and test SAML, OAuth, OIDC, BrowserId, Facebook Connect flows |
| **Authz0** | CLI Tool | OAuth scope testing | Automated scope enumeration and permission boundary testing |
| **oauth-device-code-phishing** | Red Team Tool | Device code flow | Automated device code phishing simulation for security assessments |
| **SquarePhish** | Phishing Kit | OAuth device code | Device code phishing automation (v1: email-based, v2: QR code-based) |
| **Graphish** | Phishing Kit | Microsoft Graph OAuth | Device code phishing with Microsoft Graph API integration |
| **Nuclei OAuth templates** | Scanner Templates | OAuth misconfigurations | Pre-built templates for common OAuth endpoint misconfigurations |
| **oauth2-proxy** | Reverse Proxy | OAuth authentication | OAuth2 authentication proxy for protecting upstream services (itself subject to CVE-2025-54576) |
| **Keycloak** | Identity Platform | OAuth/OIDC provider | Open-source OAuth/OIDC provider for testing; also used as reference implementation |

---

## Summary: Core Principles

**The fundamental property that makes the OAuth/OIDC mutation space so expansive is the reliance on redirect-based flows through an untrusted user agent.** Every OAuth authorization flow requires the AS to redirect the user's browser back to the client carrying security-sensitive material (authorization codes, tokens, state). This means that URL parsing, redirect validation, and front-channel security are not peripheral concerns — they are load-bearing pillars of the entire security model. Every URL parsing discrepancy, every open redirect, every fragment-handling quirk becomes a potential token theft vector.

**The 2024–2025 attack wave demonstrates that social engineering of legitimate flows is now the dominant OAuth threat.** Device code phishing (ShinyHunters, Storm-2372) achieves what credential phishing cannot: full MFA bypass, persistent refresh token access, and invisible compromise. The victim authenticates at the legitimate IdP with their real credentials and real MFA — there is no fake login page to detect, no credential to rotate. OAuth 2.1's omission of the Implicit Grant and mandatory PKCE address the *technical* flow-level mutations, but they do nothing against the *social engineering* vector that weaponizes device code flow. Similarly, illicit consent grants exploit the legitimate consent mechanism to extract persistent API access.

**Structural solutions require reducing flow complexity, constraining client capabilities, and binding tokens to senders.** OAuth 2.1 addresses the most common technical mutations: mandatory PKCE closes code interception, exact redirect_uri matching closes URL manipulation, and deprecating Implicit Flow closes front-channel token leakage. Pushed Authorization Requests (PAR, RFC 9126) move authorization parameters from the front channel to a back-channel request, preventing parameter tampering. Sender-constrained tokens (DPoP, RFC 9449; mTLS, RFC 8705) bind tokens to cryptographic keys, making stolen tokens unusable. For the social engineering vector, the structural solution is restricting device code flow issuance to managed devices (Conditional Access), enforcing admin consent policies (Microsoft's July 2025 default), and implementing anomaly detection on OAuth grant patterns. The emergence of MCP as a new OAuth consumer surface (CVE-2025-6514) signals that the OAuth attack surface will continue expanding as AI agents become first-class OAuth clients.

---

## References

- RFC 6749: The OAuth 2.0 Authorization Framework
- RFC 6750: The OAuth 2.0 Authorization Framework: Bearer Token Usage
- RFC 7009: OAuth 2.0 Token Revocation
- RFC 7519: JSON Web Token (JWT) — see [JWT Taxonomy](../jwt/jwt.md)
- RFC 7591: OAuth 2.0 Dynamic Client Registration Protocol
- RFC 7636: Proof Key for Code Exchange (PKCE)
- RFC 8628: OAuth 2.0 Device Authorization Grant
- RFC 8693: OAuth 2.0 Token Exchange
- RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
- RFC 9126: OAuth 2.0 Pushed Authorization Requests (PAR)
- RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- RFC 9700: Best Current Practice for OAuth 2.0 Security
- OAuth 2.1 Draft Specification (draft-ietf-oauth-v2-1)
- OpenID Connect Core 1.0
- OpenID Connect Discovery 1.0
- Doyensec, "Common OAuth Vulnerabilities" (2025): https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html
- Proofpoint, "Access Granted: Phishing with Device Code Authorization" (2025): https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover
- Unit 42, "OH-MY-DC: OIDC Misconfigurations in CI/CD" (DEF CON 32, 2024): https://unit42.paloaltonetworks.com/oidc-misconfigurations-in-ci-cd/
- PortSwigger Web Security Academy, "OAuth 2.0 Authentication Vulnerabilities": https://portswigger.net/web-security/oauth
- ZeroPath, "CVE-2025-54576: OAuth2-Proxy Authentication Bypass" (2025): https://zeropath.com/blog/cve-2025-54576-oauth2-proxy-auth-bypass
- Amla Labs, "When OAuth Becomes a Weapon: CVE-2025-6514" (2025): https://amlalabs.com/blog/oauth-cve-2025-6514/
- Omegapoint, "Account Takeover in Authentik: CVE-2024-52289" (2024): https://securityblog.omegapoint.se/en/writeup-authentik-cve-2024-52289/
- Praetorian, "Attacking and Defending OAuth 2.0" (2024): https://www.praetorian.com/blog/attacking-and-defending-oauth-2/

---

*This document was created for defensive security research and vulnerability understanding purposes.*
