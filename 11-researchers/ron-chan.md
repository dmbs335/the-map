# Ron Chan (ngalog) Bug Bounty Research Techniques & Methodologies Taxonomy

---
## Classification Structure

This taxonomy organizes Ron Chan's documented vulnerability discovery techniques across three analytical dimensions:

**Axis 1: Attack Surface Component** — The structural target of exploitation. This primary axis divides techniques by what system component is being analyzed or manipulated (OAuth/SSO flows, server-side endpoints, client-side mechanisms, business logic, etc.).

**Axis 2: Exploitation Mechanism** — The type of bypass or chain created. These cross-cutting patterns explain *why* each technique succeeds:

| Mechanism Type | Definition | Common Indicators |
|----------------|------------|-------------------|
| **Token Interception** | Authentication tokens stolen via redirect, fragment, or header manipulation | OAuth codes, access tokens, session cookies in URL/Referer |
| **Chain Escalation** | Multiple low-severity bugs combined into critical-impact attack | Login CSRF + Open Redirect, SSRF + Token Leak |
| **Validation Bypass** | Input validation or path restrictions circumvented through encoding or parser confusion | Double encoding, fragment injection, host header manipulation |
| **Trust Boundary Violation** | External input treated as trusted or improperly isolated | SSRF, XSSI, postMessage without origin check |
| **State Confusion** | Authentication or session state exploited across boundaries | Login CSRF, SSO merge flow, cross-account session binding |

**Axis 3: Attack Scenario** — The deployment context and ultimate impact (covered in §6).

### Core Research Philosophy

Ron Chan's methodology emphasizes:
1. **Simplicity over automation** — "test whatever is presented to me"; minimal tooling, thorough manual testing with Burp Suite
2. **Impact amplification** — "increase the impact even if it is a trivial bug"; chain low-severity findings (open redirect → account takeover)
3. **OAuth flow mastery** — Deep expertise in redirect_uri, Login CSRF, state parameter, and fragment behavior across SSO implementations
4. **Target dedication** — Sustained focus on specific programs (Uber, Yahoo/Flickr, Shopify) to build deep domain knowledge
5. **Learning from writeups** — "Keep reading write-ups and replicate it in your local environment"

### Background

- Hong Kong-based security researcher, started bug bounty in April 2016 after OSCP
- First vulnerability: Yahoo Pay price manipulation
- Significant public HackerOne earnings
- Created the influential `bug-bounty-reference` GitHub repository
- Security Consultant by profession; major focus on bug bounty research
- Breakthrough moment: zseano's tutorial on leveraging open redirects to Facebook account takeover

---

## §1. OAuth & SSO Exploitation

OAuth and SSO flows are Ron Chan's primary specialization. These techniques exploit the complex multi-party redirect flows in OAuth 2.0 and SSO implementations to intercept authentication tokens.

### §1-1. Redirect URI Manipulation

Bypassing redirect_uri validation to redirect OAuth tokens to attacker-controlled destinations.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Double URL Encoding Traversal** | `redirect_uri` path restriction bypassed via double-encoded slashes (`%252f`) that normalize to `../` sequences after server-side decoding | Uber: `redirect_uri=https://login.uber.com/login%252f..%252f..%252flogout` bypassed Facebook OAuth whitelist, reinstating open redirect for token theft |
| **Open Redirect as Proxy** | Valid `redirect_uri` endpoint contains an open redirect parameter, forwarding tokens to attacker domain | Uber: `next_url` parameter on `auth.uber.com/login` accepted arbitrary URLs, enabling post-login redirect to attacker domain |
| **Fragment Persistence** | Browser preserves URL fragments during 302 redirects; access tokens in implicit flow fragments leak to the final redirect destination | Uber: Facebook access token appended as `#access_token=...` persisted through redirect chain to attacker-controlled endpoint |

### §1-2. Login CSRF + Chain Attacks

Forcing victim to authenticate as attacker's account, then exploiting the session mismatch to steal victim tokens.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Login CSRF → Open Redirect → Token Theft** | Force victim login to attacker account via CSRF, then trigger open redirect carrying victim's real token to attacker | Uber: Login CSRF on `central.uber.com` forced auth with attacker's OAuth code; state parameter misused as redirect destination (`//attacker.com`) leaked victim's `access_token` in fragment |
| **Login CSRF → SSO Session Mismatch → ATO** | Force victim to login with attacker's service account while victim's identity provider session remains active, exposing real credentials | Flickr: Login CSRF forced victim into attacker's Flickr session while Yahoo SSO session persisted; `.data` auth token exposed in URL and stolen via open redirect |
| **Login CSRF → Referer Leakage** | Victim authenticated to attacker account; subsequent navigation to attacker-controlled resource leaks tokens via HTTP Referer header | Applied when `.data` or similar auth tokens appear in URL paths during SSO flows |

### §1-3. State Parameter Exploitation

Abusing the OAuth `state` parameter when it serves dual purposes beyond CSRF protection.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **State as Redirect Destination** | `state` parameter used for post-auth redirect instead of CSRF validation; attacker injects redirect URL | Uber: `state=/somewhere` was used as redirect target after OAuth callback; changing to `state=//attacker.com` redirected victim with access token |
| **Missing State Validation** | OAuth flow accepts requests without state parameter or with arbitrary state values | Precondition for Login CSRF attacks; enables attacker to craft OAuth authorize URLs that skip CSRF checks |

### §1-4. SSO Trust Boundary Attacks

Exploiting the trust relationship between identity provider and service provider in SSO flows.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **SSO Re-login Session Confusion** | Initiating re-authentication on a service with existing SSO session triggers credential exposure | Flickr: Re-login to different account while Yahoo SSO session active exposed `.data` credential in URL — "Try to re-login the different session when you encounter any SSO" |
| **Host Header Manipulation in OAuth** | Changing the `Host` header during OAuth flow redirects authorization to attacker domain | Periscope TV: Changing host from `www.periscope.tv` to `attacker.com/www.periscope.tv` altered OAuth redirect destination, enabling ATO when victim had linked Twitter account |
| **SSO Merge Flow Exploitation** | Exploiting account merge/link operations in SSO systems to gain unauthorized access | Shopify: Multiple critical vulnerabilities in Shopify ID merge flow; email confirmation bypass allowed accessing accounts without ownership verification |
| **Email Confirmation Bypass** | Bypassing email verification in SSO/identity systems to claim unowned accounts | Shopify: Bypass of email verification for subset of accounts → full privilege escalation to shop owner |

### §1-5. Fix Bypass Techniques

Re-exploiting vulnerabilities after incomplete patches.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Fragment Identifier Injection (%23)** | Appending URL-encoded hash (`%23`) to redirect parameter causes auth token to appear after `#`, preventing server-side logging but enabling client-side extraction | Flickr: Yahoo restricted `redirect_uri` to `/signin/yahoo` directory; appending `%23` (decoded to `#`) caused `.data` token to be appended after hash, bypassing directory restriction |
| **Encoding Layer Mismatch** | Original fix validates one encoding layer; attacker applies additional encoding to bypass | Uber: First patch for `redirect_uri` bypass defeated by double URL encoding (`%252f` → `%2f` → `/`) |

---

## §2. Server-Side Request Forgery (SSRF)

Exploiting server-side HTTP request mechanisms to access internal resources or steal credentials.

### §2-1. OAuth Integration SSRF

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Source Import URL Injection** | Application fetches external resources (Git repos, APIs) via user-controlled URL parameter without validation | Google VRP (GCP StackDriver): Debugger source import feature accepted attacker-controlled URL in `resourcelist?url=` parameter; server-side request included victim's OAuth `Authorization` header, enabling token theft to GitHub/GitLab/Bitbucket accounts |
| **GET Request SSRF (No CSRF Protection)** | SSRF triggered via GET request without CSRF token, enabling one-click exploitation via crafted link | GCP StackDriver: GET request to `resourcelist` endpoint required no CSRF token; victim clicking link triggered server-side request with their credentials |

---

## §3. Path Traversal & URL Manipulation

Exploiting insufficient path validation in microservice architectures to access unauthorized endpoints.

### §3-1. Internal API Path Traversal

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Encoded Dot-Dot-Slash Traversal** | User-controlled input appended to internal API URL path; encoded `../` sequences (`%2f..%2f`) escape intended directory to access different API endpoints | Uber (partners.uber.com): Statement UUID parameter passed to internal `127.0.0.1:123/v1/statements/[UUID]` endpoint; injecting `%2f..%2f..%2f..%2fv1%2fpartners%2f[VICTIM_UUID]` traversed to token-leaking endpoint |
| **Hash Truncation (Query String Suppression)** | Appending `%23` (`#`) to injected path suppresses original query parameters, ensuring clean internal request | Uber: `%23` at end of traversal payload prevented original `?earnings_structure_type=&locale=en` from being sent to the traversed endpoint |

---

## §4. Client-Side Attacks

Cross-origin data theft and code execution through browser-side vulnerabilities.

### §4-1. Cross-Site Script Inclusion (XSSI)

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **JSONP Callback Hijacking for Token Theft** | API endpoint returns JSONP-wrapped response without authentication; attacker page includes `<script>` tag pointing to victim's JSONP endpoint, executing callback with victim's data | Flickr: `flickr.site.getCsrf` endpoint returned CSRF token via JSONP callback without requiring authentication; attacker page loaded script to steal CSRF token, enabling full API access on behalf of victim |
| **API Key + CSRF Token Chain** | Obtaining API key and CSRF token through separate XSSI calls to chain into authenticated API access | Flickr: `api_key` was universal; CSRF token obtainable via `getCsrf` endpoint without prior CSRF token ("user does not need any csrf token to get a csrf token"), granting full API access |

### §4-2. postMessage Exploitation

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Missing Origin Validation** | `window.addEventListener("message", ...)` handler processes messages without checking `event.origin`, allowing any origin to inject data or extract tokens | Educational writeup: Demonstrated how missing `event.origin` check enables XSS and token theft from cross-origin frames |
| **Insufficient Origin Check** | Origin validation uses weak pattern matching (substring, regex) that can be bypassed with attacker-controlled subdomains | Demonstrated partial origin checks bypassed by registering similar-looking domains |

---

## §5. Business Logic & Access Control

Exploiting flawed business logic, IDOR, and access control mechanisms in large-scale applications.

### §5-1. Shopify Platform Vulnerabilities

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Identity Merge Flow Abuse** | Exploiting account merge/link operations to gain unauthorized cross-account access | Shopify ID: Multiple critical vulnerabilities in merge flow disclosed April 2021; community built on findings to discover further issues |
| **Email Verification Bypass → Privilege Escalation** | Bypassing email confirmation requirement to claim and escalate on unverified accounts | Shopify: Bypass for subset of accounts → full privilege escalation to shop owner via `myshop.myshopify.com` |
| **H1-2102 Live Hacking Event Findings** | Many valid submissions during live hacking event | Shopify (Jan-Feb 2021): 1st place, Best Bug (Exterminator), Most Valuable Hacker; findings across Shopify ID, GraphQL, and merchant platform |

### §5-2. Authentication Logic Flaws

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Price Manipulation** | Modifying price parameters in purchase flow requests | Yahoo Pay: First bug bounty finding — purchasing items at any price by manipulating request parameters |
| **LINE Authentication Bypass** | Exploiting authentication logic flaws in messaging platform | LINE: Two authentication problems identified during 30-day challenge |

---

## §6. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Account Takeover via OAuth** | OAuth 2.0 with third-party IdP | §1-1 + §1-2 + §1-3 |
| **Account Takeover via SSO** | SSO with session sharing | §1-4 + §1-5 |
| **Internal API Access** | Microservice with reverse proxy | §3-1 |
| **Credential Theft via SSRF** | Cloud platform with OAuth integration | §2-1 |
| **Cross-Origin Data Theft** | JSONP/postMessage API | §4-1 + §4-2 |
| **Privilege Escalation** | Multi-tenant SaaS platform | §5-1 |

---

## §7. CVE / Bounty Mapping (2016–2021)

| Mutation Combination | Case | Impact / Bounty |
|---------------------|------|----------------|
| §1-2 + §1-3 | Uber Login CSRF + Open Redirect ATO | Full account takeover via state parameter abuse |
| §1-1 + §1-5 | Uber redirect_uri Double Encoding Bypass | Undisclosed. Facebook OAuth token theft via encoding bypass |
| §1-2 + §1-4 | Flickr SSO Login CSRF + Open Redirect ATO | Undisclosed. One-click account takeover via .data token theft |
| §1-5 | Flickr ATO Fix Bypass (Fragment Injection) | Bypassed Yahoo's directory restriction via %23 |
| §4-1 | Flickr XSSI JSONP Token Theft | Full API access via CSRF token exfiltration |
| §2-1 | Google VRP SSRF in GCP StackDriver | Undisclosed. OAuth token theft for GitHub/GitLab/Bitbucket |
| §3-1 | Uber Microservice Path Traversal | Undisclosed. Internal API access via dot-dot-slash traversal |
| §1-4 | Periscope TV OAuth Host Header ATO | Undisclosed. Account takeover via Host header manipulation |
| §1-4 + §5-1 | Shopify ID Merge Flow + Email Bypass | Undisclosed. Multiple critical Shopify ID vulnerabilities |
| §5-2 | LINE Authentication Bypass (x2) | Two authentication logic flaws |
| §5-1 | Shopify H1-2102 Event | 1st place, MVP |
| §5-2 | Yahoo Pay Price Manipulation | Undisclosed. First bug bounty finding |

**30-Day Challenge (Oct 2017):** multi-program bug bounty challenge across HackerOne, LINE, and Bugcrowd

---

## §8. Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Burp Suite** | Primary testing tool | Proxy interception, request modification, parameter tampering |
| **VPS** | Brute forcing | Remote compute for credential testing and enumeration |
| **JSON Beautifier (Burp Extension)** | API response analysis | Formatting JSON responses for readability |
| **Vim** | Payload crafting | Text editing for exploit development |
| **bug-bounty-reference** (GitHub) | Community resource | Curated write-up reference categorized by vulnerability type |
| **Burp Collaborator** | SSRF confirmation | Out-of-band interaction detection for SSRF validation |
