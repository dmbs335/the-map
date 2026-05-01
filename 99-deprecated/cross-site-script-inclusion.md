> **DEPRECATED** — Moved to `99-deprecated/`.
> - Most XSSI vectors are neutralized by modern browser defenses: SameSite cookies (Lax default), CORB/ORB
> - The document itself states "modern browser defenses have narrowed the attack surface significantly"
> - Residual attack surface (JSONP abuse, etc.) can be briefly referenced in `csrf.md` or `xss.md`

# Cross-Site Script Inclusion (XSSI) Mutation/Variation Taxonomy

---

## Classification Structure

Cross-Site Script Inclusion (XSSI) is a client-side vulnerability class in which an attacker's page includes a cross-origin resource via the `<script>` tag and extracts sensitive data from the response. The fundamental enabler is the Same-Origin Policy's deliberate exemption for script inclusion: while `XMLHttpRequest` and `fetch` enforce origin checks on responses, `<script src="...">` does not — the browser fetches the resource, attaches ambient-authority credentials (cookies), and executes the response in the including page's context. Any data embedded in that response becomes accessible to the attacker.

XSSI is distinct from both XSS and CSRF. XSS injects code into the victim application's output; CSRF triggers state-changing actions. XSSI does neither — it **reads** cross-origin data by exploiting the fact that script inclusion is an SOP exemption. The vulnerability was first publicly exploited in 2006 (Gmail address book theft via Array constructor override) and remains relevant today, though modern browser defenses (SameSite cookies, CORB/ORB) have narrowed the attack surface significantly.

This taxonomy organizes the XSSI attack surface along three orthogonal axes:

- **Axis 1 — Response Data Format (WHAT is included):** The structural format of the cross-origin response that enables data extraction. This is the primary organizational axis.
- **Axis 2 — Extraction Mechanism (HOW data is captured):** The JavaScript-level technique used to intercept, read, or infer the data from the included response.
- **Axis 3 — Exploitation Objective (WHAT is stolen):** The nature of the sensitive data leaked and its downstream impact.

### Axis 2: Extraction Mechanism Summary

| Extraction Type | Mechanism | Applicability |
|---|---|---|
| **Global variable read** | Directly access variables declared in the included script | §1, §2 |
| **Callback hijacking** | Override the callback function to receive data as argument | §3 |
| **Prototype/constructor override** | Tamper with Array/Object prototypes to intercept data during construction | §3, §4 |
| **Proxy-based interception** | Use ES6 `Proxy` with `has` trap to capture variable name lookups | §4, §5 |
| **Charset manipulation** | Force re-encoding (UTF-16BE, UTF-7) to make non-JS data parseable as JS identifiers | §5 |
| **Error event inference** | Distinguish `onload` vs `onerror` events to infer HTTP status / resource existence | §6 |
| **JavaScript parse error analysis** | Capture error messages from `window.onerror` when non-JS data fails to parse | §5, §6 |
| **CSS attribute selector probing** | Exfiltrate data character-by-character via CSS selectors (adjacent technique) | §6 |

### Fundamental Mechanism

All XSSI variants exploit a single architectural property: **the `<script>` tag is an unrestricted cross-origin data channel that carries ambient-authority credentials**. When a browser encounters `<script src="https://target.com/api/data">`, it issues a GET request to `target.com` with the user's cookies, receives the response, and attempts to execute it as JavaScript — all without any origin check on the response. If the response contains data in any format that produces observable side effects when parsed as JavaScript (global variables, function calls, parse errors, or even just successful/failed loading), that data can be captured by the including page.

---

## §1. Static JavaScript Inclusion

The simplest XSSI variant: a publicly available or access-controlled JavaScript file contains sensitive data embedded in global scope. The attacker includes this file via `<script>` and reads the data directly.

### §1-1. Globally Scoped Sensitive Data

When server-side code generates JavaScript files that embed secrets, API keys, tokens, or personal data in global variables, any cross-origin page can read them by including the script.

| Subtype | Mechanism | Example |
|---|---|---|
| **Global variable with secret** | Script declares `var apiKey = "sk-..."` in global scope; attacker reads `window.apiKey` | `<script src="//victim.com/config.js"></script><script>alert(apiKey)</script>` |
| **Global object with PII** | Script populates a global object with user data: `var userData = {email: "...", ssn: "..."}` | Attacker reads `userData.email` after inclusion |
| **Global array with records** | Script initializes array of records: `var contacts = [{name:"...",phone:"..."},...]` | Attacker iterates `contacts` array after inclusion |
| **Inline configuration block** | Server embeds config in `<script>` tag within HTML page; if served without proper Content-Type, can be included | `window.__CONFIG__ = {csrfToken: "...", userId: ...}` |

### §1-2. Authentication-Gated Static JavaScript

The same vulnerability, but the JavaScript file requires cookies (session authentication) to serve the sensitive version. Without cookies, the server returns a generic or empty script.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Session-dependent config file** | `/app/config.js` returns user-specific API keys only when valid session cookie is present | Victim is logged in; cookie `SameSite=None` or absent |
| **Role-based script variation** | Admin users receive script with additional sensitive endpoints; regular users receive stripped version | Admin is tricked into visiting attacker page |
| **Language/locale-specific scripts** | Script contains localized content including user-specific data (name, preferences) | Dynamic content mixed with static delivery |

Detection approach: issue the same request with and without cookies and compare responses. If they differ, the response is authentication-dependent and potentially exploitable.

---

## §2. Dynamic JavaScript Inclusion

The server dynamically generates JavaScript responses that embed user-specific data. Unlike static files, these responses are created per-request and may include tokens, session identifiers, personal information, or application state.

### §2-1. Inline Data Embedding

Server-side code generates JavaScript that contains user data within variable assignments or function calls.

| Subtype | Mechanism | Example |
|---|---|---|
| **Variable assignment with user data** | Server template produces `var user = {name: "Alice", email: "alice@..."}` | Attacker includes script, reads `window.user` |
| **Function call with embedded data** | Server produces `initApp({token: "...", uid: 123})` | Attacker defines `initApp` before inclusion to capture argument |
| **State serialization** | Frameworks serialize application state into `<script>` blocks: `window.__INITIAL_STATE__ = {...}` | SSR frameworks (Next.js, Nuxt.js) expose state in script tags |
| **Ad/tracking pixel with user identifiers** | Analytics scripts embed user IDs, demographics, or behavioral data | Third-party inclusion inherits first-party cookies |

### §2-2. Timestamp/Nonce-Bearing Dynamic Scripts

Some dynamic scripts embed time-sensitive data (CSRF tokens, one-time nonces) that change per request but are still extractable via XSSI.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CSRF token in JavaScript** | Server generates `var csrfToken = "abc123"` per session; token changes per request but remains valid for session | Attacker reads token, chains with CSRF attack |
| **Session-bound nonce** | One-time use token embedded in script for subsequent API calls | Token valid for limited window after extraction |
| **OAuth/API access token** | Access token embedded in dynamically generated script for SPA initialization | Token grants API access until expiration |

---

## §3. JSONP Callback Hijacking

JSON with Padding (JSONP) was designed to enable cross-origin data exchange before CORS existed. The server wraps JSON data in a callback function call, which the client specifies. This makes JSONP **inherently vulnerable to XSSI** — any cross-origin page can specify its own callback and receive the data.

### §3-1. Classic Callback Override

The attacker controls the callback function name via a URL parameter. The server wraps the response in this function call, and the attacker's page defines the function to capture the data.

| Subtype | Mechanism | Example |
|---|---|---|
| **User-controlled callback parameter** | `?callback=attacker_func` → server returns `attacker_func({...data...})` | `<script>function steal(d){exfil(d)}</script><script src="//victim.com/api?callback=steal"></script>` |
| **Fixed callback with known name** | Server uses hardcoded callback name (e.g., `jQuery_callback_1`); attacker pre-defines it | Attacker defines `jQuery_callback_1 = function(d){...}` before inclusion |
| **Framework-specific callback convention** | AngularJS uses `angular.callbacks._N`; attacker overrides the specific callback slot | Override `angular.callbacks._7 = function(leaked){alert(JSON.stringify(leaked))}` |
| **Nested object path callback** | Callback specified as dotted path: `?callback=a.b.c` → `a.b.c({...})` | Attacker constructs matching object hierarchy |

### §3-2. Callback Injection for CSP Bypass

JSONP endpoints on CSP-whitelisted domains can be weaponized to bypass Content Security Policy — a cross-cutting use beyond pure data theft.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CSP whitelist + JSONP endpoint** | CSP allows `script-src cdn.example.com`; CDN has JSONP endpoint | `<script src="//cdn.example.com/jsonp?callback=alert(1)//">` |
| **Callback parameter reflection as XSS** | Server reflects callback value without sanitization; inject arbitrary JS | `?callback=alert(document.domain)//` |
| **Open redirect + JSONP chain** | Redirect from whitelisted domain to JSONP endpoint on another whitelisted domain | CSP trusts both domains; redirect carries context |

### §3-3. JSONP Without Explicit Callback Parameter

Some applications generate JSONP-like responses without a user-controllable callback parameter, but the response format is still executable JavaScript.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Implicit callback function** | Server always wraps in `processData({...})` regardless of parameters | Attacker defines `processData` globally |
| **JavaScript assignment response** | Server returns `var data = {...}` instead of callback-wrapped JSON | Attacker reads `window.data` after inclusion |
| **Executable array/object literal** | Response is bare `[{...},{...}]` — valid JS expression | Attacker overrides Array constructor (§4-1) |

---

## §4. Prototype and Constructor Tampering

When the cross-origin response returns data structures (arrays, objects) that are parsed by the JavaScript engine, attackers can intercept the data by overriding built-in constructors and prototype methods that are invoked during parsing.

### §4-1. Constructor Override

Override the `Array` or `Object` constructor so that when the included script's data is parsed, the overridden constructor captures the data.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Setter-based interception** | `Object.defineProperty(Object.prototype, 'key', {set: function(v){exfil(v)}})` | Target response uses known property name |

The original `Array` constructor override against JSON arrays (Jeremiah Grossman, 2006) was patched in Firefox in 2007, and equivalent Object/Array overrides have not been viable in mainstream browsers since the early ECMAScript 5 era; setter-based interception via `Object.defineProperty(Object.prototype, ...)` remains viable when the target response uses known property names.

### §4-2. Prototype Chain Poisoning

Override methods on `Array.prototype` or `Object.prototype` to intercept operations performed on data during script execution.

| Subtype | Mechanism | Example |
|---|---|---|
| **`Array.prototype.slice` override** | Intercept `.slice()` calls on data arrays | `Array.prototype.slice = function(){exfil(this)}` |
| **`Array.prototype.forEach` override** | Capture array iteration | Attacker's `forEach` receives `this` as target array |
| **`Object.prototype.toString` override** | Intercept string coercion | Capture object data when implicitly converted |
| **`Object.prototype.__defineGetter__`** | Define getters on prototype for known property names | Trigger on property access within included script |
| **`valueOf`/`toString` coercion** | Override implicit type conversion methods | Data captured during comparison or concatenation |

### §4-3. ES6 Proxy-Based Interception

ES6 Proxy objects provide a meta-programming mechanism to intercept arbitrary property access. When combined with `__proto__` manipulation, they capture variable name lookups from included scripts.

| Subtype | Mechanism | Example |
|---|---|---|
| **`has` trap on prototype** | `Object.setPrototypeOf(__proto__, new Proxy(__proto__, {has: (t,n) => exfil(n)}))` | Captures every identifier lookup in the global scope |
| **`get` trap for property access** | Proxy intercepts property reads on polluted objects | Access to object properties within included script |
| **`caller` context leak (Chrome)** | Proxy `has` trap's `caller` property exposes calling function source | Read the calling function's `toString()` to extract inline data |

---

## §5. Non-Script Data Inclusion (Non-Script XSSI)

When the cross-origin response is **not** JavaScript (CSV, JSON, XML, plaintext), the `<script>` tag still fetches it. While non-JS data typically causes a parse error, several techniques can extract data from parsing side effects or through charset manipulation.

### §5-1. CSV / Tabular Data Theft

CSV data included via `<script>` produces parse errors, but the error messages and execution behavior can leak data.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CSV as variable/function names** | CSV cell values parsed as JavaScript identifiers: `Name,Email` becomes attempted variable lookups for `Name` and `Email` | Error handler or Proxy captures the identifier names |
| **Quoted CSV injection** | Strategic quote placement in CSV (`"`) causes JavaScript parser to treat portions as string literals | Attacker controls partial CSV content (injection point) |
| **UTF-16 forced interpretation** | `<script charset="UTF-16BE" src="...">` forces two-byte character interpretation of ASCII CSV | Browser re-encodes response bytes into UTF-16 character pairs |

### §5-2. Charset Manipulation Attacks

By forcing a different character encoding on the included resource, attackers transform non-JavaScript content into valid JavaScript identifiers or expressions.

| Subtype | Mechanism | Example |
|---|---|---|
| **UTF-16BE conversion** | ASCII bytes reinterpreted as UTF-16BE form valid Unicode identifiers; `{"email":"..."}` becomes variable names | `<script charset="UTF-16BE" src="//victim.com/api/user.json"></script>` |
| **UCS-2 / UTF-16LE** | Similar to UTF-16BE but with different byte-order; usable for XML data import | More brittle than UTF-16BE; limited browser support |
| **Data-free charset exploitation** | Even without controlling response content, charset-shifted bytes form valid JS variable names | Attacker enumerates window properties to find the constructed variable |

The UTF-16BE technique is significant because it works **without the attacker controlling any part of the response** — the charset conversion alone creates valid JavaScript identifiers from arbitrary data, and the attacker can detect which variables were created by enumerating `window` properties.

### §5-3. JSON Array Direct Execution

Bare JSON arrays (`[{...},{...}]`) are syntactically valid JavaScript expressions. In older browsers, including them as scripts would trigger Array/Object constructors that could be overridden.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unprotected JSON array endpoint** | API returns `[{"name":"Alice"},{"name":"Bob"}]` without wrapper | No JSON prefix protection; pre-2018 browser |
| **JSON object assignment** | API returns `name = {"email":"..."}` which is valid JS assignment | Attacker reads the assigned global variable |
| **Angular/framework JSON prefix stripping** | Frameworks add `)]}',\n` prefix; if absent, response is executable | Application forgot to add anti-XSSI prefix |

---

## §6. Side-Channel and Inference-Based XSSI

Even when the response data cannot be directly read or parsed, the browser's behavior when loading a cross-origin script reveals information through side channels.

### §6-1. HTTP Status Code Oracle

The `<script>` tag's `onload` and `onerror` events reveal whether the cross-origin request received a 2XX or non-2XX response — regardless of content type.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Binary status detection** | `onload` fires for HTTP 200; `onerror` fires for 4XX/5XX | Endpoint returns different status based on authenticated state or data existence |
| **Search enumeration oracle** | Query `?search=a*` → 200 means match exists; 404 means no match | Recursive binary search reveals full dataset |
| **Authentication state detection** | Protected endpoint returns 200 for logged-in users, 401 for others | Login oracle: determine if victim is authenticated to target service |
| **Authorization probe** | Role-specific endpoint returns 200 for admins, 403 for regular users | Infer victim's privilege level |
| **Redirect chain following** | `<script>` follows 3XX redirects; final status determines event: redirect to 200 → `onload`, redirect to 404 → `onerror` | Redirect destination reveals information |

### §6-2. Parse Error Information Leakage

When non-JavaScript data is included as a script, the parse error messages can reveal data content through `window.onerror`.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Line number leakage** | Error line number reveals which line of the response caused the first syntax error | Response structure inference |
| **Error type differentiation** | `SyntaxError` vs `ReferenceError` vs successful parse reveals data format | Different data shapes produce different error types |

Modern browsers have mitigated most verbose error messages for cross-origin scripts (reporting generic "Script error." instead), but **residual information leakage remains possible** through error event timing and type differentiation.

### §6-3. Timing-Based Data Inference

The time taken to parse, execute, or fail on an included script reveals information about the response.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Response size inference** | Larger responses take longer to download and parse; timing reveals data volume | Detectable difference between "empty result" and "large result set" |
| **Parse complexity timing** | Complex JSON structures parse slower than simple ones | Significant size/complexity difference between result states |
| **Cache timing** | Previously loaded (cached) resource loads faster; reveals prior visit | Victim has/hasn't visited specific resource URL |

### §6-4. XS-Leaks Integration

XSSI overlaps with the broader XS-Leaks (Cross-Site Leaks) vulnerability class. Script tag inclusion is one of many **inclusion methods** cataloged in the XS-Leaks framework.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Frame count oracle** | Including a script that redirects changes `window.frames.length` | Navigation-based side channel |
| **Performance API timing** | `PerformanceObserver` measures cross-origin resource load time and size | `Timing-Allow-Origin` header present or same-site context |
| **Content-Type error differentiation** | Different MIME types produce different error behaviors when forced through `<script>` | Absence of `X-Content-Type-Options: nosniff` |
| **CORB/ORB blocking detection** | CORB-blocked responses produce distinguishable behavior from allowed ones | Attacker infers content type from blocking behavior |

---

## §7. Browser Defense Bypass and Evasion

Modern browsers have implemented multiple layers of protection against XSSI. This category catalogs techniques that circumvent or degrade these protections.

### §7-1. SameSite Cookie Bypass

The most impactful browser-side defense against XSSI is the `SameSite` cookie attribute. Chrome shipped Lax-by-default in Chrome 80 (released February 4, 2020; staged rollout to 100% from February 17, 2020 onward), preventing cookies from being sent with cross-site `<script>` requests. Other Chromium-based browsers followed.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Explicit `SameSite=None`** | Application explicitly sets `SameSite=None; Secure` on session cookie | JSONP or cross-origin script endpoints require cross-site cookie delivery |
| **Legacy application without SameSite** | Application predates SameSite; browsers without Lax-by-default (Safari, older mobile) still send cookies | Victim uses non-Chromium browser or older version |
| **Top-level navigation escalation** | `SameSite=Lax` allows cookies on top-level GET navigations; attacker navigates to target in new window then reads script | Requires additional gadget (open redirect, popup) |
| **Same-site context (subdomain)** | Attacker controls a subdomain of the target (e.g., `evil.sub.target.com`); same-site context bypasses SameSite | Subdomain takeover or shared hosting |
| **Cookie refresh within 2-minute window** | Chrome allows Lax cookies for POST within 2 minutes of being set; window.open + XSSI chain | Tight timing requirement; limited applicability |

### §7-2. CORB / ORB Evasion

Cross-Origin Read Blocking (CORB) and its successor Opaque Response Blocking (ORB) prevent certain MIME types (HTML, JSON, XML) from being delivered to cross-origin `<script>` tags. Evasion requires the response to not trigger CORB's content-type heuristics.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JavaScript Content-Type** | Response served as `application/javascript` or `text/javascript` bypasses CORB entirely | JSONP endpoints typically use JS content-type |
| **Missing Content-Type** | No Content-Type header; CORB falls back to content sniffing heuristics | Server misconfiguration |
| **CORB content sniffing ambiguity** | Response content doesn't match CORB's detection heuristics for protected types | Response is not clearly HTML/JSON/XML to the sniffer |
| **`X-Content-Type-Options` absent** | Without `nosniff`, browsers may sniff content and execute as script | Server doesn't send `nosniff` header |
| **Double `X-Content-Type-Options`** | Sending two `X-Content-Type-Options` headers with conflicting values causes some browsers to ignore both | Server or proxy adds duplicate headers |

### §7-3. Content-Type Enforcement Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Polyglot response** | Response is valid as both JSON/CSV and JavaScript (e.g., starts with `var x =`) | Server can be tricked into generating dual-valid response |
| **MIME type confusion via extension** | URL ending in `.js` regardless of actual content-type may be treated as script | Some CDNs/proxies set content-type based on extension |
| **Charset override** | `<script charset="UTF-16BE">` overrides content interpretation without changing server behavior | Browser accepts charset attribute on script tags |

---

## §8. Application-Level Anti-XSSI Defenses and Their Bypasses

Applications deploy specific countermeasures against XSSI. Each defense has known bypass conditions.

### §8-1. JSON Response Prefix (Unparseable Cruft)

Applications prepend a non-executable prefix to JSON responses to prevent direct script execution. Angular uses `)]}',\n`; Google uses `)]}'`; Facebook uses `for(;;);`.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Missing prefix on specific endpoint** | Some API endpoints forget to add the prefix | Inconsistent application of defense |
| **Prefix stripping via charset** | UTF-16BE encoding transforms prefix bytes into different characters, potentially making the remainder executable | Charset manipulation bypasses prefix defense |
| **Prefix only on JSON, not JSONP** | Application prefixes JSON responses but JSONP endpoints remain unprotected | JSONP inherently wraps in callback; prefix not applied |
| **Prefix in response body but not all content types** | XML or CSV endpoints lack prefix protection | Content-type specific gaps |

### §8-2. CSRF Token Validation on Data Endpoints

Requiring a CSRF token for data-returning endpoints prevents `<script>` inclusion because the token cannot be attached to a script tag's GET request.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Token not required on GET endpoints** | CSRF protection only applied to POST/PUT/DELETE; GET endpoints serve data without token | `<script>` tag issues GET requests |
| **Token in cookie (double-submit)** | CSRF token sent as cookie; `<script>` automatically includes cookies | Double-submit pattern doesn't protect against XSSI |
| **Token leakable via separate XSSI** | One endpoint leaks CSRF token; attacker chains with second endpoint requiring token | Multi-step XSSI chain |

### §8-3. Referrer/Origin Validation

Server checks `Referer` or `Origin` header to reject cross-origin requests.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Missing Referer in privacy modes** | Some browsers strip Referer for cross-origin requests; server accepts empty Referer | Server allows missing Referer |
| **Referer spoofing via redirect** | Open redirect on target domain causes Referer to appear same-origin | Target domain has open redirect |
| **`Referrer-Policy: no-referrer`** | Attacker page sets referrer policy to suppress Referer; server accepts absent header | Server doesn't enforce Referer presence |
| **Data URI / `about:blank` origin** | Requests from data URIs have null/empty origin | Server accepts null origin |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Precondition | Primary Mutation Categories |
|---|---|---|
| **Access token theft** | JSONP endpoint returns access token; `SameSite=None` cookie | §3-1 + §7-1 |
| **PII exfiltration** | Dynamic JS embeds user profile data; missing CORB headers | §2-1 + §7-2 |
| **CSRF token leakage → CSRF chain** | CSRF token in dynamic JS; chained with state-changing action | §2-2 + §8-2 |
| **Contact list / address book theft** | API returns JSON array of contacts; no anti-XSSI prefix | §5-3 + §4-1 |
| **Authentication state detection** | Protected endpoint returns 200/401 based on login status | §6-1 |
| **Internal data enumeration** | Search endpoint returns different statuses for matching/non-matching queries | §6-1 |
| **Account takeover** | JSONP leaks session token or password reset token; attacker replays | §3-1 + §3-3 |
| **CSP bypass via JSONP gadget** | JSONP endpoint on CSP-whitelisted domain; callback parameter reflects XSS payload | §3-2 |
| **Non-JS data theft (CSV/JSON)** | CSV export endpoint included via charset manipulation; data extracted as identifiers | §5-1 + §5-2 |
| **Admin-level data theft** | Admin-only dynamic JS exposes internal configuration; admin visits attacker page | §1-2 + §2-1 |
| **OAuth token interception** | OAuth flow returns token in JSONP; attacker site includes response | §3-1 + §2-2 |

---

## CVE / Bounty Mapping (2015–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §3-1 (JSONP callback hijacking) | PayPal XSSI (HackerOne) | Email + plaintext password leaked via dynamic JS inclusion |
| §4-1 (Array constructor override) | Gmail Contact List Theft (2006) | Landmark. First public XSSI — full address book exfiltration via JSON array |
| §3-1 + §7-1 (JSONP + SameSite=None) | XSSI on private program (HackerOne) | JSONP endpoint leaked user data cross-origin |
| §3-1 (JSONP access token theft) | Staging XSSI → Account Takeover (2023 writeup) | Access token + UID leaked via JSONP callback; full message read/write/delete |
| §6-1 (HTTP status oracle) | Coinbase XSSI (HackerOne #118631) | Disclosed. Authentication state detection via script inclusion |
| §5-2 (UTF-16BE charset manipulation) | JSON Hijacking for the Modern Web (2016) | Research. UTF-16BE charset forces JSON to parse as JS variable names; CSP bypass demonstrated |
| §3-2 (JSONP CSP bypass) | Liberapay JSONP Callback Exploitation (HackerOne #361951) | Disclosed. JSONP callback parameter used for CSP bypass |
| §5-1 + §5-2 (CSV data theft) | MBSD Identifier-Based XSSI (2015) | Research. CSV data exfiltrated via script tag with charset manipulation |
| §7-2 + §7-3 (CORB bypass) | Chrome CORB implementation gaps (ongoing) | Browser-level. Ongoing tightening of content-type sniffing heuristics |
| §3-1 (JSONP hijacking) | Flickr API Contact List Leak | Disclosed. Authenticated user contact list accessible via JSONP endpoint |
| §3-2 (JSONP callback injection) | ossrs/srs JSONP XSS (GHSA-gv9r-qcjc-5hj7) | Disclosed. DOM XSS via JSONP callback reflection |
| §7-1 (SameSite=None exploitation) | CVE-2025-55462 (Eramba CORS misconfiguration) | 2025. CORS + SameSite=None → session hijack and data exfiltration |

---

## Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **DetectDynamicJS** (Burp Extension) | Dynamic JavaScript files | Passive scanner comparing authenticated vs. unauthenticated script responses; flags content differences |
| **Burp Suite Scanner** | JSONP endpoints, dynamic JS | Active/passive detection of JSONP callback injection and dynamic JS inclusion |
| **JSParser** | JavaScript endpoint discovery | Extract URLs and API endpoints from JavaScript files for XSSI surface mapping |
| **Retire.js** | Vulnerable JS libraries | Detect outdated libraries with known XSSI-related vulnerabilities |
| **LinkFinder** | Endpoint enumeration | Discover hidden API endpoints returning data in exploitable formats |
| **XSinator** | Browser-level XS-Leak testing | Automated testing framework for XS-Leaks including script inclusion vectors |
| **Custom PoC scripts** | Specific XSSI validation | Manual exploitation scripts for callback hijacking, prototype tampering, charset manipulation |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Browser SameSite enforcement** | Cookie-based XSSI | Browsers with Lax-by-default behavior, especially Chromium-family browsers, strip cookies from cross-site script requests; Firefox/Safari behavior should be assessed via ETP/ITP and compatibility tables |
| **CORB / ORB** (Chromium) | Non-script response blocking | Blocks HTML/JSON/XML responses from being delivered to cross-origin `<script>` tags |
| **`X-Content-Type-Options: nosniff`** | MIME sniffing prevention | Prevents browsers from sniffing content type; script rejected if Content-Type is not JS |
| **JSON response prefix** (`)]}',\n`) | JSON execution prevention | Makes JSON responses syntactically invalid as JavaScript |
| **CSP `script-src`** | Script source restriction | Limits which origins can serve scripts |
| **Subresource Integrity (SRI)** | Script tampering detection | Hash-based verification of script content; prevents JSONP response manipulation |

### Research Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **XS-Leaks Wiki / xsleaks.dev** | XS-Leak catalog | Comprehensive reference of cross-site information leakage techniques including script inclusion |
| **XSinator.com** | Browser defense evaluation | Automated browser test suite for XS-Leak inclusion methods and defenses |

---

## Summary: Core Principles

### Why XSSI Exists

The fundamental property enabling XSSI is the **SOP exemption for script inclusion**. The web's architecture requires scripts to be includable from arbitrary origins (for CDNs, analytics, ads, and third-party libraries). This creates an unrestricted cross-origin GET channel that: (1) carries ambient-authority cookies, (2) receives the full response body, and (3) processes the response in the including page's execution context. Any data embedded in a script-includable response is implicitly shared with every page on the internet that includes it. XSSI is the exploitation of this implicit sharing.

### Why Incremental Patches Fail

Each defense addresses one dimension while leaving others exposed:

- **`SameSite=Lax`** is the single most effective defense, but fails when: applications explicitly set `SameSite=None` (required for legitimate cross-site JSONP); victims use browsers without Lax-by-default (Safari for years lagged behind); or attackers achieve same-site context via subdomain takeover.
- **CORB/ORB** blocks non-script MIME types, but JSONP endpoints use `application/javascript` content-type, which CORB explicitly allows through — because JSONP is *designed* to be cross-origin-includable. This is the fundamental paradox: JSONP's intended behavior is indistinguishable from its exploited behavior.
- **JSON prefixes** (`)]}',\n`) prevent bare JSON execution, but do nothing for JSONP responses, dynamic JS with embedded data, or side-channel inference attacks (§6).
- **CSRF tokens** protect state-changing endpoints but are rarely applied to data-reading GET endpoints — precisely the ones XSSI targets.
- **Referrer validation** is easily bypassed by privacy-mode browsers, referrer-stripping policies, and redirect chains.

### Structural Solution Direction

The structural solution is threefold: (1) **Eliminate JSONP entirely** in favor of CORS-based APIs — CORS provides origin-checked, credential-controlled cross-origin data access without the inherent XSSI exposure of callback-wrapped responses; (2) **Enforce `SameSite=Lax` or `Strict` universally** — no session cookie should ever be sent on a cross-site subresource request; and (3) **Apply `X-Content-Type-Options: nosniff` and explicit `Content-Type` headers on all responses** — this ensures CORB/ORB can reliably block non-script responses from being executed as scripts. Together, these three measures close the XSSI attack surface at its root. The remaining risk lies in legacy applications that cannot migrate away from JSONP and `SameSite=None`, and in side-channel inference attacks (§6) that require no cookies at all — for these, only proper access control (authentication via request headers rather than cookies) provides complete protection.

---

## References

- [OWASP Web Security Testing Guide: Testing for Cross Site Script Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/13-Testing_for_Cross_Site_Script_Inclusion)
- [HackTricks: XSSI (Cross-Site Script Inclusion)](https://book.hacktricks.wiki/pentesting-web/xssi-cross-site-script-inclusion.html)
- [Scip AG: Cross-Site Script Inclusion — A Fameless but Widespread Web Vulnerability Class](https://www.scip.ch/en/?labs.20160414)
- [MBSD (Takeshi Terada): Identifier Based XSSI Attacks](https://www.mbsd.jp/Whitepaper/xssi.pdf)
- [PortSwigger Research: JSON Hijacking for the Modern Web](https://portswigger.net/research/json-hijacking-for-the-modern-web)
- [SideChannel/Tempest: XSSI — An Overview of the Vulnerability in 2024](https://www.sidechannel.blog/en/xssi-an-overview-of-the-vulnerability-in-2024/)
- [Hurricane Labs: How Red and Blue Teamers Can Leverage the XSSI Vector](https://hurricanelabs.com/blog/how-red-and-blue-teamers-can-leverage-the-xssi-vector/)
- [Cobalt: Cross-Site Script Inclusion (XSSI) Vulnerability Wiki](https://www.cobalt.io/vulnerability-wiki/v5-validation-sanitization/cross-site-script-inclusion-xssi)
- [PentesterLab: Cross-Site Script Inclusion (XSSI) Glossary](https://pentesterlab.com/glossary/cross-site-script-inclusion)
- [CQR Company: Cross-Site Script Inclusion](https://cqr.company/web-vulnerabilities/cross-site-script-inclusion/)
- [HackerOne: XSSI to Steal AccessToken and More (Writeup)](https://github.com/AnkitCuriosity/Write-Ups/blob/main/XSSI%20(Cross%20Site%20Script%20Inclusion)%20to%20Steal%20AccessToken%20and%20More.md)
- [HackerOne: Coinbase XSSI Disclosure (#118631)](https://hackerone.com/reports/118631)
- [HackerOne: Liberapay JSONP Callback Exploitation (#361951)](https://hackerone.com/reports/361951)
- [Angular: XSSI Prefix Relevance Discussion (#52027)](https://github.com/angular/angular/issues/52027)
- [Chromium: Cross-Origin Read Blocking for Developers](https://www.chromium.org/Home/chromium-security/corb-for-developers/)
- [XS-Leaks Wiki: Cross-Origin Read Blocking](https://xsleaks.dev/docs/defenses/secure-defaults/corb/)
- [XS-Leaks Wiki: Error Events](https://xsleaks.dev/docs/attacks/error-events/)
- [XSinator: XS-Leak Browser Test Suite](https://xsinator.com/)
- [PortSwigger: Bypassing SameSite Cookie Restrictions](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions)
- [Reconless Blog: SameSite by Default and What It Means for Bug Bounty Hunters](https://blog.reconless.com/samesite-by-default/)
- [OffensiveWeb: Cross-Origin Read Blocking (CORB)](https://www.offensiveweb.com/docs/http/cross-origin-read-blocking-corb/)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
