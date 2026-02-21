# Universal XSS (UXSS) Mutation/Variation Taxonomy

---

## Classification Structure

Universal XSS (UXSS) is fundamentally distinct from application-level XSS. While traditional XSS exploits flaws in a specific web application's input handling, UXSS exploits flaws in the **browser itself** — its rendering engine, navigation logic, extension system, or embedded contexts — to execute attacker-controlled script in the context of **any** origin. The victim website need not have any vulnerability; the browser's failure to enforce the Same-Origin Policy (SOP) is the sole root cause.

This taxonomy organizes the UXSS attack surface along three axes:

- **Axis 1 (Primary): Vulnerability Location** — the structural component of the browser where the flaw resides. This forms the main body of the document (§1–§8).
- **Axis 2 (Cross-cutting): Root Cause Mechanism** — the specific way the Same-Origin Policy is violated. Each subtype references its applicable mechanism.
- **Axis 3 (Mapping): Attack Scenario** — the deployment context and ultimate impact when the mutation is weaponized.

### Axis 2: Root Cause Mechanism Summary

| Code | Mechanism | Description |
|------|-----------|-------------|
| **M1** | Missing Origin Check | No cross-origin validation exists where one is required |
| **M2** | Incorrect Origin Check | Validation exists but is flawed (incomplete, bypassable, wrong timing) |
| **M3** | Origin Confusion | The browser assigns the wrong origin to a document or execution context |
| **M4** | Origin Inheritance Error | Special URLs (about:blank, data:, blob:) inherit an incorrect origin |
| **M5** | Navigation Race Condition | Timing window during document swap allows script to execute in a transitional state |
| **M6** | Context Confusion | Script executes in a wrong or overly-privileged context |
| **M7** | Privilege Boundary Violation | Lower-privilege code accesses higher-privilege APIs or contexts |
| **M8** | Message Passing Flaw | Inter-component communication (extension IPC, postMessage) lacks origin validation |

### Fundamental Principle

The browser enforces SOP by associating every document, script, and resource with an **origin** (scheme + host + port). UXSS occurs whenever the browser **fails to correctly compute, assign, propagate, or check** this origin at any point in the document lifecycle — from initial navigation through final rendering and script execution.

---

## §1. Rendering Engine / DOM Processing Flaws

Vulnerabilities in the browser's HTML/DOM rendering engine (Blink, WebKit, Gecko) that allow script execution to bypass origin boundaries during document parsing, DOM manipulation, or event handling.

### §1-1. Event Dispatch Origin Confusion

When the browser dispatches DOM events across frame boundaries, incorrect origin association can allow a cross-origin frame to access the DOM of another frame through the event object.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-frame event leakage** | An event dispatched on a cross-origin iframe propagates with access to the target frame's DOM, allowing the attacker to read or modify cross-origin content via event properties. (M1, M3) | Victim page is embedded in an attacker-controlled iframe, and the browser does not restrict event object access across origins. |
| **Window event handler origin bypass** | A page embedded in an iframe has a handler for a window event (e.g., `message`, `hashchange`). If the handler returns a DOM node or accesses event properties, the embedding page can retrieve the cross-origin document element. (M1) | Target page has a handler for any window event that gets/sets a property of the event object or returns a DOM node. |

**Example (CVE-2014-1701):** `dispatchEvent` on an iframe allows the parent frame to trigger an event whose handler executes with access to the iframe's document, leaking cross-origin DOM content.

### §1-2. Parser-Initiated JavaScript URI Execution

The HTML parser may encounter elements (e.g., `<iframe src="javascript:...">`) that trigger JavaScript URI execution. If the parser does not correctly associate the resulting document's origin, the script can execute in the context of a cross-origin page.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Iframe javascript: URI origin mismatch** | When an iframe's `src` is set to a `javascript:` URI, the resulting document should inherit the creator's origin. Bugs in origin assignment cause it to inherit the navigated-to page's origin instead. (M3, M4) | Browser fails to correctly assign origin during parser-initiated javascript: URI processing. |
| **Synchronous page load with javascript: URI** | A synchronous page load combined with a `javascript:` URI execution creates a window where the script runs with the previous document's origin while the new document is being committed. (M5, M3) | Precise timing between navigation initiation and javascript: URI execution. |

**Example:** `<iframe src="javascript:parent.document.cookie">` executing in the context of the parent's origin rather than a null/opaque origin.

### §1-3. DOM Clobbering and Prototype Chain Attacks

While DOM clobbering is typically an application-level issue, browser-specific handling of named property access on `window` or `document` can create origin-boundary violations when combined with cross-frame access.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Named window access across frames** | Browsers expose cross-origin windows by name via `window.open()` return values or `window.frames[name]`. Bugs in the access-check logic for named properties can leak cross-origin data. (M2) | Browser's cross-origin access check for WindowProxy named properties is incomplete. |

---

## §2. Navigation & Document Lifecycle Exploitation

Vulnerabilities arising from the complex state machine of browser navigation — from URL request through response processing, document commit, and old-document teardown. The transitional states during navigation create windows where origin enforcement may be inconsistent.

### §2-1. Document Swap Race Conditions

During navigation, the browser replaces the current document with a new one. This involves multiple steps: initiating the load, receiving the response, committing the new document, and destroying the old one. Race conditions in this sequence can allow script to execute with the wrong origin.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unload handler exploitation** | During document replacement, `Document::prepareForDestruction` may trigger JavaScript execution via a nested frame's `unload` or `beforeunload` event handler. Script in this handler can reference the new document's context before origin checks are fully applied. (M5, M6) | A frame being navigated away from has an unload handler that accesses the new document during the transition. |
| **Initial empty document timing** | Setting the frame state to `DisplayingInitialEmptyDocumentPostCommit` then calling `document.open()` on the frame's document immediately after insertion stops the initial load and sets the document URL to a value that passes `isSecureTransitionTo` checks. (M5, M2) | Attacker can manipulate frame insertion and document.open timing before the initial navigation completes. |
| **Redirect-during-commit exploitation** | A 302 redirect issued during document commit can cause the browser to associate the redirected document's content with the original URL's origin, creating a cross-origin execution context. (M3, M5) | Server-side redirect occurs at a precise point during the document commit phase. |

**Example (Focus for iOS < 123):** A 302 redirect was used to conduct UXSS on a victim website, executing attacker script in the victim's origin.

### §2-2. History and Session State Manipulation

The browser maintains a history of navigated documents with their associated origins. Manipulation of this state can cause origin misattribution.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **History entry origin confusion** | Manipulating `history.pushState` or `history.replaceState` in combination with navigation can cause the browser to restore a document with an incorrect origin from the back-forward cache. (M3) | Browser does not re-validate origin when restoring from bfcache or history entries. |
| **Fragment navigation origin leak** | Fragment-only navigation (`#hash`) does not trigger a full document reload, but can trigger event handlers. In combination with cross-origin iframes, this can leak information about the target page's state. (M2) | Cross-origin iframe monitors fragment changes on the parent. |

### §2-3. HTTP Redirect Chain Origin Confusion

When a navigation passes through multiple HTTP redirects, the browser must track the final origin. Errors in redirect handling can cause the browser to use an intermediate or initial origin instead of the final one.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Redirect origin inheritance** | During a chain of redirects (A → B → C), the browser incorrectly retains origin A for the document loaded from origin C, allowing scripts at C to act with A's privileges. (M3) | Multiple redirects with at least one cross-origin hop, and the browser failing to update origin tracking at each redirect step. |
| **Meta-refresh and Location header conflict** | Conflicting navigation directives (HTTP `Location` header vs. `<meta http-equiv="refresh">`) during document loading create ambiguous origin states. (M3, M5) | Server responds with a redirect header while the partially-loaded document contains a meta-refresh to a different origin. |

---

## §3. Origin Inheritance & Propagation Errors

Certain URL schemes produce documents whose origin is not self-evident from the URL itself. The browser must **inherit** or **assign** an origin based on the creation context. Errors in this process constitute one of the most historically prevalent classes of UXSS.

### §3-1. about:blank Origin Inheritance

`about:blank` documents inherit the origin of the document that created them. This inheritance mechanism is a rich source of UXSS when the browser incorrectly tracks or assigns the creator's origin.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Domainless blank exploitation** | When an `about:blank` document is created without a clear creator context (e.g., via certain extension APIs or privileged pages), it may receive a null/universal origin. If a regular webpage can access this domainless blank, it can execute script with effectively universal access. (M4, M7) | A pathway exists to create an about:blank in a domainless state accessible from regular web content. |
| **Creator origin mismatch** | A bug in tracking the "creator" of an about:blank page causes it to inherit the wrong origin — typically the attacker's origin instead of the target's, or vice versa. (M4) | The browser's creator-tracking logic is confused by rapid frame manipulation, window.open chains, or intermediate navigations. |
| **Iframe about:blank with opener trick** | Creating an iframe, navigating it to about:blank, then using the opener relationship to bridge origins. If the browser doesn't properly isolate the about:blank frame's origin from its opener, cross-origin access is possible. (M4, M2) | The browser allows cross-origin access to about:blank frames through opener or parent references without proper origin checks. |

**Example (Edge — Domainless World):** Loading a `data:` URI instead of `about:blank` to create a domainless site accessible from a regular webpage, then using `document.write` to match the origin to its parent, achieving full SOP bypass.

### §3-2. data: URI Origin Confusion

`data:` URIs should be treated as opaque origins in modern browsers. Historically, many browsers treated them as inheriting the creator's origin, leading to widespread UXSS.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **data: URI origin inheritance** | In older browsers, a `data:` URI loaded in an iframe inherits the origin of the referring page. If the attacker controls the iframe source, they can craft a data: document that executes script in the parent's origin. (M4) | Browser treats data: URIs as same-origin with their creator/referrer. |
| **data: URI reload origin confusion** | Reloading an isolated `data:text/html` URL causes origin confusion — the browser reassigns the origin upon reload, potentially matching it to a cross-origin context. (M4, M3) | Specific reload sequences for data: URIs in isolated contexts. |
| **data: URI as navigation target** | Setting a data: URI as the location of an existing cross-origin frame can, in buggy browsers, cause the data: document to execute in the frame's previous origin rather than an opaque origin. (M3, M4) | The browser does not reset the frame's origin when navigating to a data: URI. |

**Example (CVE-2017-5466, Firefox):** Origin confusion when reloading an isolated `data:text/html` URL, allowing cross-origin script execution.

### §3-3. blob: URL Origin Confusion

`blob:` URLs inherit the origin of the context that created them. Bugs in blob URL lifecycle management — particularly revocation, cross-context access, and worker scoping — can create UXSS conditions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Blob URL cross-context access** | A blob URL created in one origin is accessible from another origin due to insufficient origin checking in the blob URL resolution logic. (M1, M4) | The browser's blob URL store does not properly scope blob URLs by their creator origin. |
| **Blob URL post-revocation access** | After a blob URL is revoked via `URL.revokeObjectURL()`, the underlying data may still be accessible through cached references, potentially with incorrect origin attribution. (M4, M5) | Race condition between blob URL revocation and navigation to the blob URL. |

---

## §4. Browser Extension & Plugin Exploitation

Browser extensions operate with elevated privileges compared to web content. UXSS through extensions occurs when extension APIs, content scripts, or plugin-browser interfaces allow web content to escalate to cross-origin capabilities.

### §4-1. Content Script Injection Attacks

Content scripts run in web page contexts but have access to extension messaging APIs. Flaws in when/where content scripts are injected can create UXSS.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Content script race condition** | During navigation, a content script meant for origin A is injected into a document that has already transitioned to origin B due to a race condition in the content script injection timing. (M5, M6) | Precise navigation timing causes content script to execute in wrong origin context. |
| **Extension origin bypass via content script** | A content script with access to `chrome.runtime.sendMessage` or similar APIs can be leveraged by a malicious web page (through DOM interaction) to perform cross-origin actions via the extension's background page. (M8, M7) | Extension content script does not properly validate web page interactions before forwarding messages. |

**Example (Mozilla Bug 1452045):** Race condition allows injecting content scripts into a wrong origin context during navigation.

### §4-2. Extension API Origin Leaks

Extension APIs may expose cross-origin data or execution capabilities that, when improperly guarded, allow UXSS.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SchemaRegistry interception** | Extension API schemas can be intercepted by malicious web pages, allowing attackers to invoke privileged extension APIs and perform UXSS in all frames and tabs. (M7, M1) | Browser does not properly isolate extension API schema definitions from web content. |
| **debugger API origin bypass** | Extensions using the `chrome.debugger` API can script any page regardless of origin. If a web page can trigger a debugger attachment (via extension vulnerability), it gains universal access. (M7) | A vulnerable extension exposes debugger API functionality to web content. |
| **webRequest/webNavigation API abuse** | Extensions with broad permissions (e.g., `<all_urls>`) that expose their APIs to web content (intentionally or via bugs) enable cross-origin request interception and script injection. (M8, M7) | Extension's message handler does not validate the sender's origin before performing privileged operations. |

**Example (CVE-2016-5168, Chromium):** Persistent UXSS via SchemaRegistry, where extension API schemas could be intercepted by malicious web pages.

### §4-3. Browser Extension UXSS

Extensions themselves can contain UXSS vulnerabilities that allow any webpage to execute script in the context of other tabs/origins.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Extension message handler UXSS** | An extension's background script or service worker processes messages from content scripts without validating the sender's origin or URL, allowing a malicious page to trigger privileged actions (cookie access, tab scripting, etc.). (M8) | Extension does not validate `sender.origin` or `sender.url` in its message handler. |
| **Extension popup/page DOM XSS** | XSS in an extension's popup or options page allows attacker-controlled content to execute with extension privileges, enabling cross-origin tab access via `chrome.tabs.executeScript`. (M7, M6) | Extension renders untrusted web content in its privileged UI pages. |

**Example (CVE-2024-49378, Smartup extension):** UXSS in Edge and Firefox via the Smartup extension, allowing another extension or page to execute arbitrary code in the context of the user's tab.

---

## §5. JavaScript Engine Bindings & API Flaws

The JavaScript engine's integration with the browser's DOM (via bindings layers like V8/Blink bindings, JSC/WebKit bindings) requires careful cross-origin checks. Flaws in these bindings allow script to bypass SOP at the engine level.

### §5-1. Cross-Origin Access Check Failures

The browser's bindings layer must enforce cross-origin checks when JavaScript accesses properties of cross-origin `WindowProxy` or `Location` objects. Missing or incorrect checks create direct UXSS.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Missing cross-origin check on WindowProxy property** | A property or method on the `WindowProxy` object (representing a cross-origin window) lacks the required origin check, allowing direct read/write access to cross-origin DOM. (M1) | The bindings layer fails to annotate a WindowProxy property with `[CrossOrigin]` checks. |
| **Incorrect cross-origin check logic** | The origin check exists but is implemented incorrectly — e.g., comparing only the host without the scheme, or allowing `null` origins to match any origin. (M2) | Flawed comparison logic in the security check implementation. |
| **contentWindow.eval cross-origin execution** | Accessing `iframe.contentWindow.eval()` across origin boundaries when the browser fails to enforce the same-origin check on the `eval` function. (M1) | Browser does not apply cross-origin restriction to eval access via contentWindow. |

### §5-2. Incorrect Execution Context

The JavaScript engine must track which security context (origin) code is executing in. Context confusion causes code to execute with the wrong origin's privileges.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **V8 context mismatch** | The V8 engine enters the wrong security context when executing a callback or promise resolution, causing the code to run with a different origin's privileges. (M6) | Asynchronous operations (promises, microtasks) that cross origin boundaries. |
| **Blink binding context confusion** | In the Blink/V8 bindings, the wrong context is used when invoking a DOM method or accessing a property, bypassing the cross-origin check for that operation. (M6) | Complex DOM operation chains that cause the bindings layer to lose track of the calling context. |

### §5-3. JavaScript Upcall Invariant Violations

V8 functions that implicitly "upcall" back into JavaScript (e.g., via proxies, getters, `Symbol.toPrimitive`) can violate security invariants if the bindings code assumes state is unchanged after the upcall.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Proxy-based invariant violation** | An attacker uses JavaScript `Proxy` objects to intercept and modify operations during V8 bindings processing. The bindings code assumes certain invariants hold (e.g., an object's type hasn't changed), but the proxy alters state during the upcall. (M2, M6) | Bindings code does not re-validate state after calling into JavaScript (which may trigger proxy traps). |
| **Getter/setter side-effect exploitation** | Custom getters or setters on objects passed to DOM APIs cause unexpected side effects (e.g., navigating a frame, modifying the DOM) during the API's execution, breaking origin assumptions. (M5, M6) | DOM API processes an object with attacker-controlled getters that cause navigation or DOM mutation. |

---

## §6. Privileged Browser UI & Internal Pages

Browsers have internal pages (e.g., `chrome://`, `about:config`, New Tab Page, DevTools) that run with elevated privileges. XSS in these contexts can escalate to UXSS because these pages can bypass SOP by design.

### §6-1. New Tab Page / Start Page Exploitation

The browser's New Tab or Start Page often has access to privileged APIs (e.g., Mojo IPC in Chrome) not available to regular web content. XSS here is effectively UXSS+.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Search history injection** | Attacker injects malicious JavaScript via search queries that are stored in browser history and rendered unsanitized on the New Tab Page, triggering execution in the NTP's privileged context. (M6, M7) | Browser renders search history on NTP using innerHTML or equivalent without sanitization. |
| **Mojo IPC abuse** | The New Tab Page exposes Mojo.JS bindings for inter-process communication. XSS on the NTP can abuse this IPC channel to trigger browser-process-level bugs or access privileged APIs. (M7) | NTP context has access to Mojo bindings; XSS achieves code execution in this context. |

### §6-2. DevTools Exploitation

DevTools operates with the highest privilege level when attached to a page — it can execute script in any origin, bypass CSP, and access internal APIs.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DevTools localStorage overwrite** | Overwriting DevTools settings via localStorage allows injection of arbitrary JavaScript through `watchExpression` that runs in the context of the inspected website when DevTools is launched. (M6, M7) | Attacker can write to DevTools' localStorage (via extension or prior XSS in DevTools context). |
| **Extension → DevTools privilege escalation** | A malicious or vulnerable extension scripts the DevTools instance while it is attached to a target page, gaining the ability to execute arbitrary code in any origin. (M7) | Extension has access to DevTools instance; DevTools is attached to a target page. |

**Key insight:** Code running within a DevTools instance attached to a page can script **any** page regardless of origin or privilege level. Unlike extensions using the debugger API (which detach when targeting privileged pages), DevTools maintains attachment.

### §6-3. Bookmark and Reading Mode Exploitation

Browsers process bookmark URLs and reading-mode content in contexts that may have elevated trust.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Bookmark javascript: URI execution** | A malicious bookmark containing a `javascript:` URI executes in the context of the currently active tab's origin when clicked. If the user can be tricked into bookmarking an attacker-crafted URL, any origin can be targeted. (M6) | User saves a bookmark with an attacker-controlled URL containing JavaScript. |
| **Reading mode origin bypass** | Browser reading mode (e.g., Edge's Reading View) re-renders page content in a separate context. If this context has elevated privileges or incorrect origin attribution, it creates UXSS. (M3, M7) | Reading mode does not properly isolate the re-rendered content's origin. |

**Example (CVE-2016-5191, Chromium):** UXSS via bookmarks containing user information, where a crafted bookmark URL executed JavaScript in the context of the active tab's domain.

---

## §7. Embedded Browser Contexts (WebView / In-App Browsers)

Mobile and desktop applications embed browser engines (WebView, WKWebView, Electron) to render web content. These embedded contexts often have different security boundaries than standalone browsers, creating unique UXSS vectors.

### §7-1. Android WebView UXSS

Android's WebView component has historically been a significant UXSS attack surface, particularly before the migration to Chromium-based WebView.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-origin iframe escalation** | A malicious iframe within a WebView can perform UXSS on the top-level document by exploiting WebView-specific origin-check failures. (M1, M3) | Android WebView version prior to 83.0.4103.106; attacker controls an iframe within the WebView. |
| **file:// scheme universal access** | When a WebView loads content via `file://` scheme and has `setAllowUniversalAccessFromFileURLs(true)`, any file:// content can access any origin's data. (M7, M1) | App configures WebView with insecure file access settings. |
| **JavaScript bridge exploitation** | Apps exposing Java objects to JavaScript via `addJavascriptInterface` create a bridge that, combined with UXSS, allows arbitrary native code execution. (M7) | App exposes native interface and WebView has a UXSS condition. |

**Example (CVE-2020-6506):** Universal XSS in Android WebView allowed cross-origin iframes to execute arbitrary JavaScript in the top-level document, affecting all apps using vulnerable WebView versions including Apache Cordova and React Native apps.

### §7-2. iOS In-App Browser / WKWebView UXSS

iOS restricts all browsers to use WebKit, but in-app browsers and WebView implementations introduce additional UXSS surfaces.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **In-app browser SOP bypass** | In-app browsers (e.g., LINE, Facebook) may implement custom navigation handling that fails to enforce SOP, allowing embedded iframes to execute JavaScript in the top frame of any website. (M1, M2) | Victim views a page containing a malicious iframe in the in-app browser. |
| **Address bar spoofing + UXSS** | In-app browsers and some third-party iOS browsers implement the address bar separately from WebKit. If the address bar can be spoofed while UXSS is executed, the attack becomes undetectable to the user. (M3) | In-app browser does not correctly synchronize displayed URL with actual loaded origin. |

**Example (CVE-2024-5739):** LINE in-app browser on iOS before version 14.9.0 was vulnerable to UXSS, allowing attackers to execute arbitrary JavaScript within the top frame from an embedded iframe on any website.

### §7-3. Electron Application UXSS → RCE

Electron applications combine Chromium with Node.js. UXSS in Electron contexts can escalate directly to Remote Code Execution (RCE) because the renderer process may have access to Node.js APIs.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **nodeIntegration-enabled UXSS** | If `nodeIntegration` is enabled in the renderer, any XSS (including UXSS from Chromium bugs) immediately grants `require('child_process').exec()` access — full RCE. (M7) | Electron app has `nodeIntegration: true` (or doesn't explicitly disable it in older versions). |
| **Context isolation bypass** | Even with `nodeIntegration` disabled, bypassing context isolation allows renderer-side code to reach into the isolated Electron context and access Node.js APIs. (M7, M6) | Electron version with known context isolation bypass; or app-specific preload script vulnerability. |
| **will-navigate bypass for top-frame navigation** | The `will-navigate` event that apps use to prevent navigations to unexpected destinations can be bypassed when a sub-frame performs a top-frame navigation across sites. (M2) | Attacker can trigger cross-site navigation from a sub-frame. |

---

## §8. Content Processing Pipeline Exploitation

Browsers process various content types (XSLT, SVG, MHTML, PDF) through specialized pipelines. Interactions between these pipelines and the browser's origin model can create UXSS conditions.

### §8-1. SVG and XML Namespace Confusion

SVG documents processed inline or via `<img>`/`<object>` tags execute in contexts where the interaction between XML namespaces and HTML parsing creates exploitable discrepancies.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SVG foreignObject origin bypass** | SVG's `<foreignObject>` element allows embedding HTML content within an SVG context. If the browser does not properly enforce origin restrictions on the embedded HTML, it creates a cross-origin execution path. (M1, M6) | SVG with foreignObject is processed in a context where the HTML content can access cross-origin resources. |
| **Namespace confusion parsing differential** | The `<style>` tag has different parsing behavior depending on its namespace (HTML vs SVG vs MathML). This differential can confuse sanitizers and, in certain browser implementations, lead to script execution in unexpected contexts. (M6) | Browser's parser handles namespace transitions incorrectly, allowing script execution during namespace switch. |

### §8-2. PDF Viewer Exploitation

Browser-integrated PDF viewers (Chrome's PDFium, Firefox's PDF.js) run in specialized contexts that may have different security properties.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **PDF.js CSP bypass** | Vulnerabilities in PDF.js (Firefox's JavaScript-based PDF viewer) can bypass Content Security Policy restrictions of the hosting page, allowing script execution. (M6, M7) | Vulnerable version of PDF.js; attacker can serve a malicious PDF. |
| **PDF embedded JavaScript execution** | PDFs can contain JavaScript that executes within the PDF viewer's context. If this context has access to the hosting page's DOM (e.g., via `top.document`), it creates a UXSS path. (M7) | PDF viewer context is not properly isolated from the hosting page. |

**Example (CVE-2024-4367):** Vulnerable PDF.js library allowed XSS through crafted PDFs, enabling `top.document.domain` access from the PDF context.

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Condition | Primary Mutation Categories |
|----------|------------------------|---------------------------|
| **Cross-origin DOM read/write** | Any browser with UXSS bug | §1 + §2 + §3 + §5 |
| **Universal credential theft** | Victim uses vulnerable browser; attacker lures to malicious page | §1 + §2 + §3 + §4 |
| **Session hijacking at scale** | UXSS affects all origins simultaneously | §3 + §5 + §6 |
| **Privileged API access** | Browser with privileged UI XSS (NTP, DevTools) | §6 |
| **XSS → RCE escalation** | Electron app with nodeIntegration or WebView with JS bridge | §7 |
| **Mobile account takeover** | In-app browser UXSS + address bar spoofing | §7-2 |
| **Extension-mediated UXSS** | Vulnerable extension with broad permissions | §4-2 + §4-4 |
| **Cache/CDN poisoning via UXSS** | UXSS combined with service worker registration | §2 + §4-1 |
| **Phishing amplification** | UXSS + address bar spoofing on mobile | §7-2 |
| **Sandbox escape** | UXSS as first stage for renderer compromise | §5 + §8 |

---

## CVE / Bounty Mapping (2014–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-2 (parser javascript: URI) | Multiple Chromium CVEs (2014–2018) | SOP bypass; mitigated by Site Isolation |
| §1-1 (event dispatch) | CVE-2014-1701 (Chromium) | UXSS via dispatchEvent on iframes |
| §2-1 (redirect-during-commit) | Focus for iOS < 123 | UXSS via 302 redirect |
| §2-1 (javascript URI + sync load) | Focus for iOS < 122 | UXSS via window.open() with javascript: URI |
| §3-1 (domainless blank) | Edge — multiple patches | Full SOP bypass; Microsoft patched with random GUIDs |
| §3-2 (data: URI reload) | CVE-2017-5466 (Firefox) | Origin confusion when reloading isolated data:text/html |
| §3-1 + §3-2 (origin inheritance) | IE — CVE-2015-0072 | Full SOP bypass via iframe redirect + origin confusion |
| §4-2 (SchemaRegistry) | CVE-2016-5168 (Chromium) | Persistent UXSS in all frames and tabs |
| §4-3 (Adobe plugin) | Acrobat Reader plugin (2007) | UXSS via PDF URL parameter injection; first documented UXSS |
| §4-4 (extension UXSS) | CVE-2024-49378 (Smartup) | UXSS in Edge/Firefox via extension |
| §5-1 (bindings check) | 94 Chromium UXSS bugs (2014–2018) | All mitigated by Site Isolation deployment |
| §6-1 (NTP XSS) | Chromium NTP bug (2021) | XSS on New Tab Page with Mojo IPC access |
| §6-3 (bookmark UXSS) | CVE-2016-5191 (Chromium) | UXSS via bookmark with user information |
| §7-1 (WebView UXSS) | CVE-2020-6506 (Android) | Universal XSS in Android WebView; all apps affected |
| §7-1 (WebView SOP bypass) | CVE-2014-6041 (Android < 4.4) | SOP bypass in Android default browser |
| §7-2 (in-app browser) | CVE-2024-5739 (LINE iOS) | UXSS in LINE in-app browser |
| §7-2 (iOS semi-UXSS) | CVE-2019-17004 (Firefox iOS) | Semi-UXSS affecting Firefox for iOS |
| §7-3 (Electron) | CVE-2020-16608 | RCE via XSS in Electron application |
| §8-1 (XSLT) | WebKit XSLT UXSS (EDB-47237) | UXSS via XSLT and nested document replacements |
| §8-2 (MHTML) | CVE-2014-1747 (Chromium) | UXSS from local MHTML file |
| §8-2 (PDF viewer) | CVE-2024-4367 (PDF.js) | XSS via crafted PDF, CSP bypass |
| §7-2 (Safari/WebKit) | CVE-2022-22587 (Safari) | $100,500 Apple bounty; full account takeover on every visited site |
| §8 + §4 (Payment manifest + SW registration) | CVE-2023-5480 (Chrome, Slonser 2024) | UXSS via manipulated payment manifest triggering JIT service worker registration in victim origin; Payment Handler API allows attacker to install malicious SW that executes JavaScript in any origin's context |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **FuzzOrigin** (Fuzzer) | Chrome, Firefox UXSS | Origin sanitizer with static origin tagging; prioritizes origin-update operations via chained-navigation generation. Found 4 new UXSS bugs. |
| **uxss-db** (Database) | Chrome, Edge, Safari, Firefox | Curated database of browser logic vulnerabilities with PoC exploits organized by CVE. |
| **Chromium Site Isolation** (Defense) | Chromium-based browsers | Process-level SOP enforcement; each site runs in a separate process. Mitigated all 94 reported UXSS bugs (2014–2018). |
| **CORP / COOP / COEP** (Defense headers) | All modern browsers | HTTP response headers that control cross-origin resource loading, opener relationships, and embedder policies at the server level. |
| **Firefox HTML Sanitizer** (Defense) | Firefox privileged pages | Built-in sanitizer for about: pages to prevent UXSS in privileged contexts; validates innerHTML usage. |
| **Trusted Types** (Defense) | Chromium-based browsers | DOM API restriction preventing string-based DOM XSS sinks; used to eliminate XSS from WebUI (chrome:// pages). |
| **Electron Security Checklist** (Defense) | Electron apps | Context isolation, nodeIntegration disabling, webSecurity enforcement, and sandbox mode configuration. |
| **Android WebView Security Audit** (Defense) | Android apps | Oversecured's checklist for WebView configuration: file access, JavaScript interface, SSL handling, and URL validation. |

---

## Summary: Core Principles

### The Root Cause

The entire UXSS mutation space exists because the Same-Origin Policy is a **software-enforced invariant**, not a hardware-enforced boundary. Every document in every frame at every point in the navigation lifecycle must have a correctly computed and correctly checked origin. The browser's origin model interacts with dozens of subsystems — the HTML parser, the navigation state machine, the JavaScript engine bindings, the extension API surface, content processing pipelines, and embedded browser contexts — each of which must independently and correctly implement origin checks. A single missing or incorrect check in any of these subsystems breaks the entire security model for every website the user visits.

### Why Incremental Patches Fail

UXSS bugs are not caused by a single flawed pattern that can be fixed once. They emerge from the **combinatorial complexity** of browser state: navigation can be triggered from unload handlers (§2-1), origins can be inherited through multiple indirection layers (§3), extension APIs can bridge privilege boundaries (§4), and content processing pipelines introduce new execution contexts (§8). Each browser feature that interacts with the origin model introduces new potential for UXSS. This is why the rate of UXSS discoveries remained relatively constant for over a decade despite continuous patching — each fix addressed one specific state combination while leaving the vast majority of the state space unchecked.

### The Structural Solution

The most effective structural mitigation deployed to date is **Site Isolation** (Chrome 67+, hardened in Chrome 77+), which enforces SOP at the **process level**. By placing cross-site documents in separate operating system processes, UXSS bugs in the renderer process are contained — even if script bypasses SOP within the renderer, it cannot access cross-site data because that data exists in a different process's address space. This architectural shift rendered all 94 UXSS bugs reported to Chrome between 2014–2018 ineffective. However, Site Isolation does not protect against: (a) UXSS bugs in the browser process itself (§6), (b) extension-mediated UXSS (§4), (c) embedded browser contexts that don't implement site isolation (§7), or (d) same-site UXSS (where attacker and victim share the same site but different origins). The ultimate direction is toward **per-origin process isolation** — but the memory and performance costs remain prohibitive for full deployment.

---

## References

- Google Research — *Analysis of UXSS Exploits and Mitigations in Chromium* (Moroz & Glazunov, 2019)
- USENIX Security 2022 — *FuzzOrigin: Detecting UXSS Vulnerabilities in Browsers through Origin Fuzzing* (Kim et al.)
- USENIX Security 2023 — *Extending a Hand to Attackers: Browser Privilege Escalation Attacks via Extensions* (Kim et al.)
- Chromium — *Site Isolation Design Document*
- Microsoft Edge VR — *Deep Dive into Site Isolation* (Parts 1 & 2)
- Microsoft Edge VR — *Eliminating XSS from WebUI with Trusted Types*
- Microsoft Edge VR — *Attacking the DevTools*
- Broken Browser (Manuel Caballero) — IE/Edge UXSS vulnerability series
- Huli — *Beyond XSS: The Most Powerful XSS: Universal XSS*
- AntoineRondelet — *uxss-vulnerabilities-research/uxssDB*
- Metnew — *uxss-db: Browser logic vulnerabilities database*
- SoK: *On the Analysis of Web Browser Security* (arXiv:2112.15561)
- OWASP — *Browser Extension Vulnerabilities Cheat Sheet*

---

## Cross-References

- **Mutation XSS (mXSS)**: See [`mutation-xss.md`](mutation-xss.md) for the comprehensive mXSS taxonomy covering namespace switching, parser differentials, and sanitizer bypass mutations — mXSS shares the namespace confusion mechanism (§1) with UXSS but operates at the application/sanitizer level rather than the browser level
- **Application-Level XSS**: See [`xss.md`](../01-injection/xss.md) for the full XSS taxonomy including §7 (Markup Parser Differential Context) where mXSS is classified within the broader XSS landscape

---

*This document was created for defensive security research and vulnerability understanding purposes.*
