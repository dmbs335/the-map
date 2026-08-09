# DOMPurify Bypass / Sanitizer Evasion Mutation Taxonomy

---
## Classification Structure

DOMPurify is the most widely-deployed DOM-only HTML sanitizer. Its architecture—parse untrusted HTML into a DOM tree, walk the tree removing dangerous nodes/attributes, then serialize back—creates a fundamental attack surface: **any discrepancy between how DOMPurify interprets HTML during sanitization and how the browser interprets the serialized output during rendering** can yield Cross-Site Scripting.


- **Axis 1 — Mutation Target (WHAT is mutated):** The structural component of the HTML/DOM being exploited—namespace, nesting depth, node type, attribute, configuration option, encoding, or post-sanitization context.
- **Axis 2 — Discrepancy Type (WHY it works):** The nature of the parsing/interpretation mismatch—serialize-parse roundtrip mutation, namespace confusion, property clobbering, regex deficiency, configuration logic error, or context differential.
- **Axis 3 — Attack Scenario (WHERE it's weaponized):** Default-config mXSS bypass, non-default-config bypass, misconfiguration exploitation, post-sanitization gadget chain, or server-side rendering bypass.

mXSS bypasses rely on non-idempotent parsing: `P(serialize(P(input))) ≠ P(input)`. Assigning sanitized string output to `innerHTML` can produce a different DOM tree after the serialize-parse round trip.

### Discrepancy Type Summary (Axis 2)

| Discrepancy Type | Mechanism | Primary Categories |
|---|---|---|
| **Serialize-Parse Roundtrip Mutation** | DOM tree changes when serialized to HTML and re-parsed | §1, §2, §3 |
| **Namespace Confusion** | Element parsed in one namespace during sanitization, different namespace during rendering | §1, §2 |
| **Property/DOM Clobbering** | DOM properties overridden via named elements to defeat internal checks | §3 |
| **Regex/Pattern Deficiency** | Sanitization regex fails to match dangerous patterns | §4, §5 |
| **Configuration Logic Error** | Non-default options create exploitable code paths | §5 |
| **Context Differential** | Sanitization context differs from rendering context | §6 |
| **Post-Sanitization Interference** | Third-party code modifies sanitized output before rendering | §7 |

---

## §1. Namespace Switching Mutations

Namespace switching is the dominant and most prolific DOMPurify bypass category. It exploits the fundamental difference in parsing rules between HTML, SVG, and MathML namespaces—particularly how `<style>` tag content is treated as raw text in HTML but as child elements in foreign (SVG/MathML) namespaces.

### §1-1. MathML Integration Point Confusion

MathML text integration points (`<mi>`, `<mo>`, `<mn>`, `<ms>`, `<mtext>`) allow HTML content as children. Two special elements—`mglyph` and `malignmark`—have unique namespace behavior: they reside in the MathML namespace when direct children of text integration points, but in the HTML namespace otherwise.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **mglyph/malignmark namespace flip** | Element is initially parsed in HTML namespace but switches to MathML on re-parse after form removal restructures the tree | Nested `<form>` elements with MathML text integration points |
| **annotation-xml encoding switch** | `<annotation-xml>` with `encoding="text/html"` or `encoding="application/xhtml+xml"` creates an HTML integration point inside MathML, allowing HTML children | Custom element handling permits `<annotation-xml>` through sanitization |
| **MathML style content parsing** | `<style>` inside MathML namespace treats children as elements rather than raw text, enabling embedded `<img onerror>` payloads | Style tag must end up in MathML namespace after mutation |

**Example (DOMPurify < 2.0.17):**
```html
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```
On first parse, `<mglyph>` is in HTML namespace (safe). After serialization and re-parse, form restructuring places `<mglyph>` as direct child of `<mtext>`, switching it to MathML namespace. The `<style>` tag's children are now parsed as elements, not text.

### §1-2. SVG Namespace Style Exploitation

In SVG namespace, `<style>` children are parsed as elements rather than raw text. By tricking the sanitizer into keeping a `<style>` tag in SVG context while the browser renders its content as HTML, attackers inject executable markup inside what appears to be CSS text.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SVG style breakout** | Content inside `<svg><style>` treated as text during sanitization but parsed as elements on namespace switch | SVG namespace reached via integration point confusion |
| **SVG desc/title integration** | `<desc>` and `<title>` inside SVG are HTML integration points; combined with `<style>`, content escapes SVG namespace | Browser flattening or table insertion mode manipulation |
| **Image-to-img conversion** | `<image>` tag in SVG converts to `<img>` when entering HTML namespace; used to trigger namespace switch without HTML integration points | "Elevator mutation" via button/dd/dt/li/table stack popping |

**Example (SVG style breakout pattern):**
```html
<svg><style><a id="</style><img src=x onerror=alert(1)>"></a></style></svg>
```
If the `<style>` tag can be placed in SVG namespace during sanitization but the `</style>` closing tag is consumed or removed, the browser re-parses the content after `<a id="` as live HTML.

### §1-3. Comment-Based Namespace Smuggling

HTML comments inside attribute values can smuggle namespace-breaking patterns through sanitization. Recent DOMPurify bypasses have relied heavily on attributes containing `<!--` or `-->` patterns that, after template processing or roundtrip mutation, alter how the browser parses namespace boundaries.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Comment in attribute** | Attribute value containing `<!--` is serialized into HTML; browser treats it as opening a comment, breaking out of the attribute context | DOMPurify versions before comment-pattern regex filter |
| **Incorrectly opened comment** | WHATWG spec recognizes `<!...>` as a valid comment form; this variant evades standard `<!--` pattern checks | SAFE_FOR_TEMPLATES enabled; regex only checks for `<!--` pattern |
| **Comment-after-style** | `<!--</style>` pattern forces browser to interpret style closing tag differently across namespaces | Combined with namespace switching and template processing |

**Example (incorrectly opened comment, DOMPurify ≤ 3.2.3):**
```html
<math><foo-test><mi><li><table><foo-test><li></li></foo-test>
<a><style><! ${ </style> } <foo-b id="><img src onerror='alert(1)'>">
</a></table></li></mi></foo-test></math>
```
With `SAFE_FOR_TEMPLATES: true`, the `${ }` template expression is replaced with spaces, removing `</style>`. The `<!` creates an incorrectly opened comment, and the style context extends past its intended boundary.

---

## §2. Nesting Depth Exploitation

Modern browsers impose implicit depth limits on DOM trees (typically 512 elements). When this limit is exceeded, browsers "flatten" the tree by relocating deeply nested elements upward. This restructuring can move elements across namespace boundaries, creating mutations invisible to the sanitizer.

### §2-1. Node Flattening via Browser Depth Limits

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Direct depth overflow** | 500+ nested `<div>` elements trigger browser flattening; elements inside SVG/MathML subtrees get relocated to HTML namespace | DOMPurify ≤ 3.1.0 (no custom depth counter) |
| **Caption insertion mode fallback** | Closing a `<caption>` tag pops the stack of open elements regardless of validity or namespace, resetting the "in table" insertion mode to "in body" | Flattened tree must contain `<table><caption>` structure |
| **Double flattening via clobbering** | DOM clobbering resets the depth counter (`__depth`) by injecting `<input name="parentNode">`, enabling two rounds of 255-depth nesting for a total of 510 | DOMPurify 3.1.1 with `parentNode` property access |

**Example (depth flattening, DOMPurify ≤ 3.1.0):**
```html
<div>×506 <table><caption><svg><title>
<table><caption></caption></table>
</title><style><a id="</style><img src=x onerror=alert()>"></a></style>
</svg></caption></table>
```
The 506 nested divs exceed the browser's 512-depth limit. During DOMPurify's sanitization, the `<style>` resides inside SVG namespace where children are parsed as elements—so `<a id="</style>...">` is treated as a safe child element with an attribute. After `innerHTML` assignment triggers browser flattening, the SVG subtree is restructured and the `<style>` shifts to HTML namespace. In HTML, `<style>` content is RAWTEXT: the browser now encounters `</style>` as an actual closing tag (not an attribute value), terminating the style element and exposing `<img src=x onerror=alert()>` as executable HTML.

### §2-2. Elevator Mutation

Certain HTML elements (`<button>`, `<dd>`, `<dt>`, `<li>`, `<table>`) pop the stack of open elements to specific depths when their closing tags are encountered, effectively "elevating" subsequent elements upward across namespace boundaries.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Button/list element stack popping** | Closing `</button>`, `</li>`, `</dd>`, or `</dt>` pops the stack to the nearest matching open element, moving subsequent siblings to a higher level | Deep nesting combined with mismatched closing tags |
| **Image-to-img namespace escape** | `<image>` converts to `<img>` in HTML namespace but not in SVG; combined with elevator mutation, this forces an SVG→HTML namespace transition | No need for HTML integration points |

**Example (elevator mutation, DOMPurify 3.1.2):**
```html
<form id="x "><r>×504 <a><svg><image><a><desc>
<svg><image></image></svg></desc></a></image>
<style><a id="</style><img src=x onerror=alert(1)>"></a></style>
</svg></a></form><input form="x" name="__depth">
```

### §2-3. Triple-Parse Form Reordering

When `<table>`, `<marquee>`, `<applet>`, or `<object>` elements appear between nested `<form>` tags, the browser's foster parenting algorithm moves elements at the same level as the first form into the form's subtree. Repeating this pattern creates mutations detectable only after a third HTML parse.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Form reordering cascade** | First parse: normal structure; second parse: form reordering shifts elements; third parse: payload activates | Application performs double sanitization (e.g., Mermaid.js) |
| **Table foster parenting** | Elements misplaced inside `<table>` are "foster parented" above the table, changing their namespace context | `<form></form><table><form></form></table>` nesting pattern |

**Example (triple-parse, defeats double sanitization):**
```javascript
var payload = `${'<form><h1></form><table><form></form></table></form></table></h1></form>'.repeat(510)}
<math><mi><style><!--</style>
<style id="--></style></mi></math><img src='x' onerror='alert(1)'>"></style></mi></math>`;
document.body.innerHTML = DOMPurify.sanitize(payload);
document.body.innerHTML = document.body.innerHTML; // Second parse triggers payload
```

---

## §3. DOM Clobbering and Property Pollution

DOMPurify's internal logic relies on DOM property access (e.g., `parentNode`, `nodeName`, `remove()`). Named HTML elements (`<input name="...">`, `<form id="...">`) can override these properties, disabling sanitization checks.

### §3-1. Property Clobbering

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **parentNode clobbering** | `<input name="parentNode">` overrides the `parentNode` property of form elements, causing DOMPurify's depth counter to read from the clobbered value | DOMPurify 3.1.1 using direct property access |
| **remove() clobbering** | `<input name="remove">` overrides the `.remove()` method, preventing DOMPurify from removing detected dangerous nodes | DOMPurify 3.1.3–3.1.4 with nested node restriction |
| **__depth clobbering** | `<input form="x" name="__depth">` overrides the internal depth tracking attribute, bypassing depth limits via second-order clobbering | Combined with attribute trimming in `_sanitizeAttributes` |

### §3-2. Prototype Pollution

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Depth counter weakening** | Polluting `Object.prototype` with properties like `__depth` or depth-related values weakens or disables the nesting depth check | CVE-2024-45801; DOMPurify < 2.5.4 / < 3.1.3 |
| **Config option injection** | Prototype pollution injects unexpected configuration values (e.g., `ALLOWED_TAGS`, `SAFE_FOR_XML`) into DOMPurify's sanitization logic | Prototype pollution primitive in application code |
| **Destructuring exploitation** | DOMPurify retrieves `currentNode` attributes using JavaScript destructuring; polluted prototypes inject extra attributes into the iteration | Similar to DOM clobbering but via prototype chain |

---

## §4. Regex and Pattern Matching Deficiencies

DOMPurify relies on regular expressions for critical security checks—template literal detection, comment pattern filtering, data attribute validation, and namespace attribute matching. Flaws in these patterns create bypasses.

### §4-1. Template Literal Regex

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Missing closing brace** | TMPLIT_EXPR regex `/${[\w\W]}/gm` required closing `}` brace; payloads omitting `}` bypassed detection, allowing `${ ... ` without `}` | CVE-2025-26791; SAFE_FOR_TEMPLATES enabled; DOMPurify < 3.2.4 |
| **Template expression removal side-effect** | SAFE_FOR_TEMPLATES replaces `${ }`, `<%= %>`, `{{ }}` with spaces; this can remove closing tags like `</style>`, extending the style context | Combined with namespace switching |

### §4-2. Attribute Value Regex

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Data attribute anchor missing** | Regex `/^data-[\-\w.\u00B7-\uFFFF]/` lacked end anchor `$`, allowing `data-x<` or `data-x:` to pass validation | SVG namespace; xmlns prefix injection |
| **Comment pattern incomplete** | DOMPurify filters `<!--` and `-->` in attributes but misses WHATWG's "incorrectly opened comment" form `<!...>` | Combined with template processing |
| **SAFE_FOR_XML regex bypass** | Setting `SAFE_FOR_XML=false` disables the regex protection DOMPurify depends on for mXSS prevention, rendering sanitization ineffective | Explicit misconfiguration |

### §4-3. SVG Namespace Attribute Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **xmlns prefix injection** | Missing end anchor in data-attribute regex allows `xmlns:data-x` namespace declarations; attacker creates custom namespace mapping to `xlink`, then uses `data-x:href="javascript:..."` | SVG parsing context; DOMParser recognizes namespace prefixes |
| **xlink:href smuggling** | Custom namespace alias maps to `http://www.w3.org/1999/xlink`, enabling `javascript:` protocol in href attributes | User interaction (click) required for execution |

**Example (dirty namespace bypass):**
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:data-slonser="http://www.w3.org/1999/xlink">
  <a data-slonser:href="javascript:alert(1)">click</a>
</svg>
```

---

## §5. Configuration-Dependent Bypasses

DOMPurify offers extensive configuration options. Several non-default configurations create exploitable code paths—not bugs in DOMPurify per se, but dangerous interactions between features.

### §5-1. Custom Element Handling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Permissive tagNameCheck** | Overly broad regex (e.g., `/-/` or `/^[a-z]+-/`) can accidentally match `<annotation-xml>` (a MathML element containing a hyphen, not a custom element), creating namespace integration points that enable mXSS | CUSTOM_ELEMENT_HANDLING with regex that inadvertently matches MathML/SVG elements |
| **FORBID_CONTENTS interaction** | Combining CUSTOM_ELEMENT_HANDLING with FORBID_CONTENTS creates code paths where namespace confusion bypasses the sanitizer | Both options enabled simultaneously |
| **Custom element + template mode** | Custom elements combined with SAFE_FOR_TEMPLATES enable comment-based namespace attacks that standard mode would block | SAFE_FOR_TEMPLATES + CUSTOM_ELEMENT_HANDLING |

### §5-2. Attribute Allow-listing

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`is` attribute in ALLOWED_ATTR** | A 2021 code change made `forceRemove` obsolete when `is` is in ALLOWED_ATTR, allowing arbitrary content in the `is` attribute | ADD_ATTR: ['is'] or is in ALLOWED_ATTR |
| **Event handler allow-listing** | Developers adding `onerror`, `onclick`, etc. to ALLOWED_ATTR directly enables XSS | Explicit misconfiguration |
| **URI attribute extension** | `ADD_URI_SAFE_ATTR` applied to attributes that accept URIs without validation enables `javascript:` protocol injection | Combined with permissive URI regexp |

### §5-3. Hook Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **forceKeepAttr bypass** | Setting `hookEvent.forceKeepAttr = true` in `uponSanitizeAttribute` skips all sanitization including regex verification | Versions 3.1.3–3.1.5 where regex was placed after forceKeepAttr check |
| **setAttribute in hooks** | Attributes added via `.setAttribute()` inside `uponSanitizeAttribute` are not sanitized because the attribute list was already retrieved | Any version; developer misuse |
| **afterSanitizeAttribute normalization** | String operations like `.toUpperCase()` in post-hooks can recreate dangerous patterns via Unicode normalization (e.g., `ı` → `I` recreating `</STYLE>`) | Turkish locale or explicit case transformation |
| **beforeSanitizeElements clobbering** | This event fires before DOM clobbering checks (`_isClobbered`), allowing API calls in the hook to be clobbered and crash sanitization | Developer uses hookEvent properties in this hook |
| **insertBefore evasion** | Using `.insertBefore()` in hooks moves nodes above the currently sanitized position, hiding them from DOMPurify's tree walker | Developer manipulates DOM in hooks |

### §5-4. Parser Media Type Confusion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Processing Instruction injection** | `PARSER_MEDIA_TYPE: "application/xhtml+xml"` enables XML parsing; Processing Instructions (`<?...?>`) are not filtered, and HTML parsers treat them as bogus comments exposing injected content | XHTML mode explicitly configured |
| **CDATA section injection** | XML CDATA sections `<![CDATA[...]]>` are parsed differently in HTML (bogus comment state ending at `>`), exposing content between `>` and `]]>` | XHTML mode; DOMPurify before CDATA filter |
| **nodeName confusion** | Processing Instructions return their target as `nodeName`; `<?img >` has nodeName "img" (allowed tag), but HTML parses it as a bogus comment exposing subsequent content | PI target matches an allowed tag name |

---

## §6. Context Differential Attacks

The rendering context can differ from the sanitization context, creating exploitable mismatches even when sanitization is technically correct.

### §6-1. Serialize-Parse Roundtrip

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **innerHTML assignment** | Standard `element.innerHTML = DOMPurify.sanitize(input)` serializes the cleaned DOM to a string then re-parses it, creating a mutation window | Default string-return mode; not using RETURN_DOM |
| **Fragment vs document parsing** | DOMPurify parses in document mode; `insertAdjacentHTML` or fragment insertion uses fragment parsing mode with different tree construction rules | Application uses non-innerHTML insertion methods |
| **Noscript/noembed differential** | `<noscript>` content is parsed differently based on JavaScript enablement; DOMParser (used by DOMPurify) treats scripting as disabled, but browsers parse with scripting enabled | `<noscript><style></noscript><img src=x onerror=alert(1)>` |

### §6-2. Encoding-Based Differentials

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ISO-2022-JP encoding** | Japanese encoding with escape sequences can cause character boundary misalignment between sanitizer and browser rendering | Missing charset declaration; server-side DOMPurify |
| **Missing Content-Type charset** | Absent charset declarations in server-side implementations enable encoding-based bypasses where sanitizer and browser interpret byte sequences differently | Server-side rendering without explicit charset |

### §6-3. Embedding Context Mismatch

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SVG document embedding** | Application sanitizes HTML but embeds output inside an SVG document, changing namespace context for all elements | `<svg>` wrapper around sanitized output |
| **XHTML document embedding** | Sanitized HTML placed in XHTML context follows XML parsing rules (case-sensitive, no void elements), creating structural mismatches | Content-Type: application/xhtml+xml |
| **Base href pollution** | `<base>` tag can create origin confusion between DOMPurify's parsing context and the receiving document. Note: DOMPurify's default configuration implicitly blocks `<base>` (it is not in the default ALLOWED_TAGS) — this vector requires explicit `ADD_TAGS: ['base']` or `WHOLE_DOCUMENT: true` configuration | Base tag explicitly allowed via configuration; redirects relative URLs to attacker domain |

---

## §7. Post-Sanitization Gadgets

Even when DOMPurify correctly sanitizes all XSS vectors, the remaining "safe" elements can be weaponized for secondary attacks or combined with application-specific code to achieve execution.

### §7-1. Script Gadgets

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **jQuery HTML normalization** | jQuery ≤ 3.4.1 normalizes self-closing tags (e.g., `<div/>`) into paired tags, changing DOM structure after sanitization | Application uses jQuery to manipulate sanitized HTML |
| **TinyMCE post-processing** | TinyMCE < 6.7.3 performs replacements on sanitized content that can recreate dangerous HTML structures | Sanitized output passed through TinyMCE |
| **Framework template injection** | Frameworks (Angular, Vue) that process `{{ }}` template expressions in sanitized output can achieve arbitrary code execution | Sanitized HTML placed in template context |
| **CSS-based gadgets** | DOMPurify allows `<style>` by default; CSS can exfiltrate sensitive data via `url()`, `background-image`, attribute selectors, and `@import` | Default configuration; sensitive content on same page |

### §7-2. Semantic Attacks via Allowed Elements

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Form-based CSRF** | `<form>` is allowed by default; attacker constructs forms pointing to sensitive endpoints with disguised `<button>` submit triggers (requires user click; true auto-submit is not possible without JavaScript, which DOMPurify strips) | Form action points to same-origin sensitive endpoint |
| **Link redirection** | `<a>` tags allowed by default can redirect users to phishing pages or trigger protocol handlers | No rel="noopener nofollow" enforcement |
| **Meta refresh injection** | If `<meta>` is allowed, `http-equiv="refresh"` redirects users to attacker-controlled pages | Meta tag in ALLOWED_TAGS |
| **DOM clobbering via sanitized output** | Sanitized elements with `id` or `name` attributes override global JavaScript properties, potentially breaking application logic | SANITIZE_NAMED_PROPS not enabled |

### §7-3. Server-Side Rendering Issues

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **jsdom/happy-dom inconsistencies** | Server-side DOM implementations don't perfectly replicate browser parsing. DOMPurify README explicitly warns that happy-dom is not safe and should not be used with DOMPurify. Specific version boundaries and RCE potential are not detailed in DOMPurify's official documentation | Server-side DOMPurify with non-browser DOM (happy-dom explicitly unsupported) |
| **Headless browser differences** | Different headless browser engines may parse HTML differently from the target client browser | Server-side pre-rendering with sanitization |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Default-config mXSS** | Standard `innerHTML = DOMPurify.sanitize(input)` | §1 + §2 (namespace switching + depth exploitation) |
| **Non-default-config bypass** | Custom DOMPurify options (templates, custom elements, XHTML) | §5 + §4 (config logic + regex deficiency) |
| **Misconfiguration exploitation** | Developer misuse of hooks, allow-lists, or options | §5-2 + §5-3 (attribute allow-listing + hook exploitation) |
| **Post-sanitization gadget** | Sanitized output processed by framework or library | §7 (script gadgets + semantic attacks) |
| **Server-side bypass** | DOMPurify running on Node.js with jsdom/happy-dom | §6-2 + §7-3 (encoding differential + SSR inconsistency) |
| **Double-sanitization bypass** | Application sanitizes twice (e.g., Mermaid.js) | §2-3 (triple-parse form reordering) |
| **SVG file sanitization** | DOMPurify used to clean uploaded SVG | §4-3 + §6-3 (namespace attribute + embedding context) |

---

## CVE / Bounty Mapping (2019–2025)

| Mutation Combination | CVE / Case | Impact / Detail |
|---|---|---|
| §1-1 (mglyph namespace flip) | DOMPurify < 2.0.17 | Full bypass via MathML namespace confusion with nested forms |
| §1-1 (MathML namespace) + §6-1 | DOMPurify 2.0.0 | Full bypass via MathML text integration point confusion with nested forms |
| §1-2 (SVG style) + §6-1 | DOMPurify < 2.0.1 | SVG-based mXSS in Chrome 77; separate vector from 2.0.0 MathML bypass |
| §2-1 (depth overflow) + §1-2 | CVE-2024-47875 / DOMPurify < 2.5.0 and >= 3.0.0 < 3.1.3 | Full bypass via 512-depth node flattening + caption insertion mode (both 2.x and 3.x branches affected per GitHub Advisory/NVD) |
| §3-1 (parentNode clobbering) + §2-1 | DOMPurify 3.1.1 | Full bypass via DOM clobbering of depth counter |
| §3-1 (__depth clobbering) + §2-2 | DOMPurify 3.1.2 | Full bypass via elevator mutation + second-order clobbering |
| §3-2 (prototype pollution) + §2 | CVE-2024-45801 / DOMPurify < 2.5.4, < 3.1.3 | Depth check weakening via prototype pollution; NVD CVSS v3.1 7.0; GitHub Advisory CVSS v4.0 8.3 |
| §3-2 (prototype pollution) | CVE-2024-48910 / DOMPurify < 2.4.2 | Prototype pollution tampering; related but separately assigned from CVE-2024-45801 |
| §4-1 (template regex) + §1-3 | CVE-2025-26791 / DOMPurify < 3.2.4 | mXSS via incorrect template literal regex; CVSS 4.5 |
| §4-3 (xmlns prefix) | DOMPurify (pre-fix) | `javascript:` via SVG namespace alias; requires user click |
| §5-2 (`is` attribute) + §1 | DOMPurify 3.2.1 (non-default) | `is` attribute for customized built-in elements can carry unexpected content when explicitly added to ALLOWED_ATTR — this is a configuration foot-gun rather than a confirmed vulnerability (no official advisory) |
| §5-1 + §5-4 (custom element + template) | DOMPurify 3.2.3 (non-default) | mXSS via incorrectly opened comment + template removal |
| §5-4 (Processing Instruction) | DOMPurify (XHTML mode) | XSS via `<?img >` PI injection in XML parsing mode |
| §5-4 (CDATA section) | DOMPurify (XHTML mode) | XSS via CDATA section in XML parsing mode |
| §5-3 (forceKeepAttr) | DOMPurify 3.1.3–3.1.5 | Research-identified potential regex bypass when forceKeepAttr set in hooks (no official advisory/GHSA/NVD entry — treat as research finding, not confirmed vulnerability) |
| §6-1 (noscript differential) | DOMPurify (historic) | `<noscript>` scripting-flag mismatch |
| §2-3 (triple-parse) | DOMPurify ≤ 3.1.2 | Defeats double sanitization; affects Firefox, Chrome, Safari |
| §7-1 (jQuery gadget) | jQuery ≤ 3.4.1 + DOMPurify | Post-sanitization tag normalization re-enables XSS |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Sanity** (Fuzzer) | DOMPurify bypass discovery | Python mutation engine + client-side iframe workers; diffs sanitized output with `innerHTML` to detect mutations |
| **mXSS Cheatsheet** (Reference) | Browser mXSS vectors | Curated mutation examples with explained mechanisms; covers namespace, form, style, and encoding mutations |
| **GMSGadget** (Gadget DB) | Post-sanitization XSS via CSP/sanitizer bypass | Collection of JavaScript gadgets for bypassing DOMPurify and CSP; maps gadgets to popular libraries |
| **DOMPurify Demo** (Testing) | Manual payload testing | Interactive sanitization tester with sample payloads and configuration options |
| **Browser DevTools** (Manual) | Mutation inspection | Compare `DOMPurify.sanitize()` output DOM with `innerHTML` re-parse DOM tree |
| **Sanitizer API** (Browser-native) | Reduced mXSS exposure | W3C/WICG proposal; `setHTML()` avoids the serialize-parse roundtrip, reducing mXSS exposure. However, if sanitized DOM is subsequently serialized back to string (e.g., via `.innerHTML`) and re-parsed, mutation issues can recur. Not absolutely "mXSS-free" in all usage patterns; still in incubation |

---

## References

- [PortSwigger Research — "Bypassing DOMPurify again with mutation XSS"](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss)
- [Securitum — "Write-up of DOMPurify 2.0.0 bypass using mutation XSS"](https://research.securitum.com/dompurify-bypass-using-mxss/)
- [Securitum — "Mutation XSS via namespace confusion – DOMPurify < 2.0.17 bypass"](https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/)
- [Mizu — "Exploring the DOMPurify library: Bypasses and Fixes (1/2)"](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes)
- [Mizu — "Exploring the DOMPurify library: Hunting for Misconfigurations (2/2)"](https://mizu.re/post/exploring-the-dompurify-library-hunting-for-misconfigurations)
- [Mizu — "Playing with DOMPurify's custom elements handling"](https://mizu.re/post/playing-with-dompurify-ce-handling)
- [Slonser — "DOM Purify – dirty namespace bypass"](https://blog.slonser.info/posts/dompurify-dirty-namespace-bypass/)
- [Slonser — "DOM Purify – untrusted Node bypass"](https://blog.slonser.info/posts/dompurify-node-type-confusion/)
- [Flatt Security — "Bypassing DOMPurify with good old XML"](https://flatt.tech/research/posts/bypassing-dompurify-with-good-old-xml/)
- [YNizry — "DOMPurify 3.2.1 Bypass (Non-Default Config)"](https://yaniv-git.github.io/2024/12/08/DOMPurify%203.2.1%20Bypass%20(Non-Default%20Config)/)
- [ensy — "DOMPurify 3.2.3 Bypass (Non-Default Config)"](https://ensy.zip/posts/dompurify-323-bypass/)
- [SonarSource — "mXSS: The Vulnerability Hiding in Your Code"](https://www.sonarsource.com/blog/mxss-the-vulnerability-hiding-in-your-code/)
- [SonarSource — "mXSS Cheatsheet"](https://sonarsource.github.io/mxss-cheatsheet/)
- [s1r1us — "MXSS Evolution and Timeline: A primer to MXSS"](https://s1r1us.ninja/posts/mxss-101/)
- [BeaconRed — "When Purification Fails: Exploiting DOMPurify's Leftovers"](https://shaheen.beaconred.net/research/2025/05/28/when-purification-fails.html)
- [GitHub Advisory — CVE-2024-45801: DOMPurify prototype pollution](https://github.com/advisories/GHSA-mmhx-hmjr-r674)
- [GitHub Advisory — CVE-2025-26791: DOMPurify template regex mXSS](https://github.com/advisories/GHSA-vhxf-7vqr-mrjg)
- [WICG — Sanitizer API Specification](https://wicg.github.io/sanitizer-api/)
- [cure53 — DOMPurify GitHub Repository](https://github.com/cure53/DOMPurify)
