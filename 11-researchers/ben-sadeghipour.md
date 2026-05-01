# Ben Sadeghipour (NahamSec) Bug Bounty Research Techniques & Methodologies Taxonomy

---

## Classification Structure

This taxonomy organizes Ben Sadeghipour's documented vulnerability discovery techniques across three analytical dimensions:

**Axis 1: Attack Surface Component** — The structural target of reconnaissance or exploitation. This primary axis divides techniques by what system component is being analyzed or manipulated (recon infrastructure, PDF/document processors, authentication, ad platforms, etc.).

**Axis 2: Exploitation Mechanism** — The type of discrepancy or bypass created. These cross-cutting patterns explain *why* each technique succeeds:

| Mechanism Type | Definition | Common Indicators |
|----------------|------------|-------------------|
| **Trust Boundary Violation** | External input treated as trusted or improperly isolated | SSRF, HTML injection into PDF generators, headless browser exploitation |
| **Validation Bypass** | Input or authentication checks circumvented through encoding or parser confusion | URL filter bypass, CSP-free backends, PDF link-tag exploitation |
| **Authorization Mismatch** | Privilege checks fail to restrict access to resources or functions | IDOR, missing access controls, admin panel exposure |
| **Patch Lag Exploitation** | Known vulnerabilities remain unpatched in internal/backend systems | Headless Chrome CVEs in ad infrastructure, Jenkins RCE |
| **Configuration Weakness** | Default or misconfigured settings expose administrative functionality | OAuth misconfig on Jenkins, exposed actuator endpoints |
| **Chain Amplification** | Multiple low-severity findings combined into critical-impact sequences | IDOR + 2FA bypass → admin takeover, recon → SSRF → RCE |

**Axis 3: Attack Scenario** — The deployment context and ultimate impact (covered in §8).

### Core Research Philosophy

Sadeghipour's methodology emphasizes:
1. **Breadth-first reconnaissance** — Systematically map the entire attack surface before deep-diving into individual targets
2. **Application-first understanding** — Use the target as a regular user before testing; understand business logic and data flows
3. **PDF generators as high-value targets** — "9 out of 10 PDF generators are vulnerable" if they render user-controlled HTML
4. **Vulnerability chaining over single bugs** — Combine reconnaissance findings, low-severity issues, and logic flaws into impactful chains
5. **Persistent, iterative testing** — Return to targets with fresh perspectives; major bugs often come from previously-tested features

---

## §1. Reconnaissance & Asset Discovery

Infrastructure reconnaissance establishes the attack surface before targeted exploitation. Sadeghipour's recon methodology emphasizes automation, breadth of coverage, and systematic cataloging.

### §1-1. Subdomain & Asset Enumeration

Comprehensive asset discovery through DNS, certificate transparency, and automated scanning.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Certificate Transparency Mining** | Query CT logs via Censys.io and crt.sh for Subject Alternative Names | Discovered Snapchat Jenkins instances via `*.sc-corp.net` SAN patterns |
| **Subdomain Bruteforcing** | Automated wordlist-based DNS resolution with tools like `HostileSubBruteforcer` | Enumerate `dev`, `stage`, `alpha`, `beta`, `test` environment subdomains |
| **CIDR Block Scanning** | Map entire IP ranges owned by target organizations via ASN lookup | Apple 17.0.0.0/8 scan revealed 25,000 web servers (collaborative project) |
| **Screenshot Automation** | Visual cataloging of discovered endpoints for manual pattern recognition | Identify admin panels, dashboards, and forgotten applications at scale |

**Key Insight**: Non-production environments (`dev`, `stage`, `beta`) consistently have weaker security controls than production, making environment enumeration a high-value recon step.

### §1-2. JavaScript & Client-Side Analysis

Extract backend information from client-side code and archived resources.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **JavaScript Endpoint Extraction** | Parse JS bundles for API routes, internal domains, and configuration data using `JSParser` | Find undocumented API endpoints and internal service URLs |
| **Archive.org Reconnaissance** | Retrieve deleted documentation and historical endpoints from Wayback Machine | Recover removed API documentation and legacy endpoints |
| **GitHub Dorking** | Search target organization's GitHub presence for leaked credentials, API keys, internal URLs | Common API calls and internal or dev/stage domains in public repos |

### §1-3. Recon Automation

Custom tooling for scaling reconnaissance workflows.

| Tool | Purpose | Key Feature |
|------|---------|-------------|
| **lazyrecon** | End-to-end recon automation | Combines subdomain enumeration, port scanning, and screenshot capture in organized output |
| **lazys3** | AWS S3 bucket enumeration | Discovers staging, sandboxed, dev, and production buckets via naming patterns |
| **HostileSubBruteforcer** | Subdomain bruteforcing and takeover detection | Identifies dangling CNAME records for subdomain takeover |
| **crtndstry** | Certificate transparency subdomain finder | Lightweight CT log querying for rapid subdomain discovery |
| **recon_profile** | Recon automation shell profiles | Pre-configured environment for reconnaissance workflows |
| **bbht** | Bug bounty hunting toolkit setup | Automated Ubuntu toolbox provisioning with preferred security tools |

---

## §2. SSRF & PDF Generator Exploitation

Server-Side Request Forgery through document generation pipelines is a core research focus, presented at DEF CON 27 as "Owning the Clout Through SSRF and PDF Generators."

### §2-1. HTML-to-PDF Injection

Most modern PDF generators perform HTML→PDF conversion using headless browsers or rendering libraries. User-controlled content injected into this pipeline executes in the server context.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **XSS-to-SSRF via PDF** | Inject HTML/JavaScript into fields rendered by PDF generators; scripts execute server-side | Lyft expense report: injected HTML into "Expense Notes" field → rendered in PDF email |
| **`<link>` Tag File Read** | WeasyPrint supports `<link rel=attachment href="file:///path">` to attach local files to PDF output | `<link rel=attachment href="file:///etc/passwd">` embedded server files in generated PDF |
| **`<iframe>` Internal Resource Loading** | Embed iframes pointing to internal services; PDF renders the response content | `<iframe src="http://169.254.169.254/latest/meta-data/">` captures AWS metadata |
| **DNS Rebinding via PDF** | Bypass URL allowlists by resolving to internal IPs after initial validation | Circumvent SSRF protections in PDF generators with strict URL filtering |

**Key Insight**: Identify the PDF generator library by analyzing the `User-Agent` string in outbound requests. WeasyPrint, wkhtmltopdf, Puppeteer, and Chrome headless each have distinct exploitation vectors.

### §2-2. PDF Generator Identification & Exploitation

| Generator | Identification | Primary Attack Vector |
|-----------|---------------|----------------------|
| **WeasyPrint** | User-Agent header contains "WeasyPrint" | `<link rel=attachment>` for file attachment; no JavaScript support |
| **wkhtmltopdf** | User-Agent or error messages reference wkhtmltopdf | Full JavaScript execution; `<iframe>` and `<script>` both work |
| **Puppeteer/Chrome Headless** | Chrome-based User-Agent string | Full browser capabilities; `file://` protocol, JavaScript, network access |
| **PrinceXML** | `-prince-` CSS properties accepted | CSS-based attacks; `@import url()` for SSRF |

### §2-3. SSRF Escalation via PDF

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **AWS Metadata Harvesting** | SSRF to `169.254.169.254` reads IAM role credentials | PDF generator → SSRF → EC2 access keys → full cloud access |
| **Internal Service Scanning** | Use PDF generator to probe internal network addresses and ports | Map internal infrastructure via response-based blind SSRF |
| **File Exfiltration** | `file://` protocol reads arbitrary server-side files via PDF content | Extract `/etc/passwd`, application configuration, source code |

---

## §3. Headless Browser & Ad Platform Exploitation

Backend systems using headless browsers for rendering, ad delivery, or content processing represent a high-value attack surface due to their extensive server-side capabilities.

### §3-1. Unpatched Headless Chrome in Backend Infrastructure

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Patch Lag RCE** | Backend headless Chrome instances remain unpatched for known CVEs | Meta ad platform server used vulnerable Chrome → RCE via known browser exploit; public high-impact bounty case |
| **Ad Payload Injection** | Malicious content delivered through ad creation workflows triggers headless Chrome vulnerabilities | Crafted ad payload exploits unpatched Chrome flaw in rendering pipeline |
| **Lateral Movement from Ad Server** | RCE on ad processing server provides access to internal infrastructure | Command-line control over Meta's ad workflow server → internal network access |

**Key Insight**: Ad platforms perform extensive server-side data processing — URL fetching, screenshot capture, content rendering — each operation potentially vulnerable to SSRF, RCE, or SSRF-to-RCE chains. Similar patterns exist across ad platforms industry-wide.

---

## §4. Authentication & Access Control

### §4-1. Exposed Administrative Interfaces

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Jenkins Console Exposure** | Non-production Jenkins instances accessible via misconfigured OAuth | Snapchat's Jenkins: Gmail OAuth granted Script Console access → arbitrary Groovy code execution; public bounty case |
| **Admin Panel Discovery via Recon** | Systematic subdomain enumeration reveals employee-facing admin portals | `REDACTED-jenkins-{env}.sc-corp.net` pattern discovered via Censys certificate enumeration |
| **Actuator/Debug Endpoint Exposure** | Spring Boot Actuator endpoints leak heap dumps containing valid session tokens | `/actuator/heapdump` exposed authentication cookies on Apple infrastructure |

### §4-2. Authentication Bypass Chains

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **2FA Bypass via Code Generation API** | API endpoint generates new 2FA codes for arbitrary user IDs without authorization | `POST /api/users/newAuthenticationCode/{id}` → generate valid 2FA for any user |
| **Registration Parameter Manipulation** | Admin registration requires hidden parameters; comparing API responses reveals them | Missing `securityQuestions` parameter in admin vs. user registration endpoints |
| **Error-Masked State Mutation** | Server returns error responses while successfully applying changes | `PUT /api/users` modifies credentials despite "Something went wrong" error response |
| **Role Escalation via Authority Parameter** | Unprotected endpoint accepts role assignment in request body | `PUT /api/account/updateAdmin` with `"authorities":["ROLE_ADMIN"]"` escalates to admin |

### §4-3. Credential Harvesting from Infrastructure

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Jenkins Build Artifact Extraction** | Build logs and artifacts contain API keys, secrets, source code | GitHub OAuth tokens extracted from Jenkins plugin configurations |
| **Groovy Script Console RCE** | Jenkins Script Console executes arbitrary Groovy code with system privileges | Read files, execute commands, harvest credentials via one-line Groovy scripts |
| **Error Message Token Leakage** | Application error responses contain authentication tokens | Spotify access tokens leaked in error messages |

---

## §5. Cross-Site Scripting (XSS)

### §5-1. Blind XSS Methodology

Sadeghipour advocates a systematic approach to blind XSS, targeting backend/admin interfaces where CSP is often absent.

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Backend Admin Panel Injection** | Stored XSS payloads trigger when admin views user-submitted data in internal tools | Support tickets, user profiles, form submissions rendered in admin dashboards |
| **Combined Payload Strategy** | Deploy standard `alert(1)` for immediate confirmation alongside blind XSS Hunter payloads | Dual-payload approach maximizes both reflected and blind XSS coverage |
| **Custom Infrastructure for Blind XSS** | Self-hosted XSS Hunter JS payload with PHP parser and .htaccess routing | Captures execution context, cookies, DOM, screenshots from blind triggers |
| **CSP-Free Backend Exploitation** | Internal applications lack CSP headers, enabling unrestricted script execution | Backend admin tools not designed with client-side attack threat model |

**Key Methodology**: Start with plain text input, use Ctrl+F to find where input is reflected, understand the rendering context, then escalate to XSS payloads. Inject blind XSS payloads into every available input field.

### §5-2. XSS Discovery Patterns

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Input Reflection Tracking** | Insert unique strings (`test123nahamsec`) and search all pages for reflection points | Browser DevTools Ctrl+F to locate output contexts across multi-page flows |
| **Cross-Domain Propagation** | User input on one application propagates to another within the same organization | Profile fields set on app A render on admin panel B without sanitization |
| **Filter Bypass via Simple Tags** | Start with basic HTML tags (`<u>`, `<b>`) before advancing to complex payloads | Identify which tags and attributes are permitted before crafting bypass |

---

## §6. Advanced Vulnerability Patterns

### §6-1. Web Cache Deception

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Extension-Based Cache Deception** | Append static file extensions to dynamic URLs to trick CDN caching | `/api/user/profile.css` cached by CDN, exposing user-specific data |
| **Cache Header Analysis** | Monitor `X-Cache`, `Age`, `Cache-Control` headers to identify caching behavior | Use CAIDO's HTTPQL to track cache interactions across requests |
| **Multi-Layer CDN Exploitation** | Exploit misconfigurations in stacked CDN/proxy layers | Each caching layer may apply different caching rules to the same request |

### §6-2. Supply Chain Attacks

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Dependency Confusion** | Publish malicious packages to public registries that shadow internal package names | Internal package names leaked via recon → publish malicious version publicly |
| **Build Pipeline Injection** | Compromise CI/CD systems to inject code into release artifacts | Jenkins access → modify build scripts → distribute backdoored releases |
| **Third-Party Script Compromise** | Exploit trust relationships with external JavaScript and CDN resources | Subdomain takeover on CDN-hosted scripts → persistent XSS across applications |

### §6-3. Race Conditions

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **Gift Card/Coupon Multi-Redemption** | Concurrent requests redeem single-use codes multiple times | Parallel requests during narrow validation window |
| **Rate Limit Bypass** | Concurrent requests exceed throttling mechanisms | Multi-connection simultaneous requests bypass per-endpoint rate limits |
| **Trial/Subscription Abuse** | Exploit timing windows in subscription state management | Repeated activation of trial periods via concurrent enrollment requests |

### §6-4. Path Traversal

| Subtype | Mechanism | Example/Condition |
|---------|-----------|-------------------|
| **URL Encoding Bypass** | Double-encoding and mixed encoding bypasses path traversal filters | `%252e%252e%252f` bypasses single-decode URL filters |
| **Server-Specific Path Handling** | Different servers normalize paths differently | API-specific path traversal within REST endpoint routing |
| **403 Bypass via Path Manipulation** | Path normalization differences between proxy and origin server | Encoding tricks to bypass 403 responses on restricted paths |

---

## §7. Collaborative Research: Apple Security Assessment

Three-month collaborative engagement (July–September 2020) with Sam Curry, Brett Buerhaus, Samuel Erb, and Tanner Barnes targeting Apple's entire attack surface. Sadeghipour led the reconnaissance effort.

### §7-1. Scope & Results

| Metric | Value |
|--------|-------|
| **Duration** | 3 months (July–September 2020) |
| **Vulnerabilities Found** | 55 total |
| **Critical** | 11 |
| **High** | 29 |
| **Medium** | 13 |
| **Low** | 2 |
| **Total Bounty** | Public high-value bounty history |

### §7-2. Vulnerability Categories Discovered

| Category | Technique | Impact |
|----------|-----------|--------|
| **Infrastructure Scanning** | 17.0.0.0/8 CIDR scan → 25,000 web servers | Complete attack surface mapping across apple.com, icloud.com subdomains |
| **Authentication Bypass** | Jive forum and DELMIA Apriso authentication flaws | Unauthorized access to employee-facing applications |
| **SSRF/XXE** | iCloud Pages SSRF, Java API XXE injection | Internal service access, data exfiltration |
| **SQL Injection** | Vertica database injection on GSF API | Database access on backend systems |
| **Command Injection** | ePublisher and Nova Admin command injection | Remote code execution on Apple servers |
| **Stored XSS** | iCloud Mail XSS via style/hyperlink confusion | Account compromise via worm-capable XSS |
| **IDOR** | App Store Connect, Find My Friends object references | Access to other users' data and resources |
| **Information Disclosure** | Heap dumps, AWS credentials, source code exposure | Credential harvesting and internal architecture mapping |

---

## §8. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Categories |
|----------|-------------|-------------------|
| **Internal Infrastructure RCE** | Backend headless browsers / processing servers with unpatched software | §3 + §2 |
| **Cloud Credential Theft** | PDF generators with SSRF to cloud metadata endpoints | §2-3 |
| **Admin Account Takeover** | Authentication bypass chains on employee-facing portals | §4-2 |
| **Data Exfiltration** | File read via PDF `<link>` tags or SSRF `file://` protocol | §2-1 + §2-3 |
| **CI/CD Compromise** | Exposed Jenkins with script console access | §4-1 + §4-3 |
| **Supply Chain Attack** | Build pipeline injection or dependency confusion | §6-2 |
| **Backend Blind XSS** | Stored payloads executing in admin contexts | §5-1 |

---

## §9. CVE / Bounty Mapping

| Vulnerability | Target | Impact / Bounty |
|---------------|--------|----------------|
| Headless Chrome RCE in ad platform (§3-1) | Meta / Facebook | Server-side RCE via unpatched Chrome in ad delivery infrastructure; high-impact bounty case |
| 55 vulnerabilities across Apple services (§7) | Apple | Broad multi-service research effort with multiple critical and high-severity findings |
| WeasyPrint SSRF via expense reports (§2-1) | Lyft | Maximum bounty on program. File read via `<link rel=attachment>` in PDF generator |
| Jenkins Script Console RCE (§4-1) | Snapchat | Unauthenticated Groovy code execution via exposed Jenkins |
| Multi-vuln chain to admin access (§4-2) | Private HackerOne Program | Undisclosed. IDOR + 2FA bypass + role escalation → full admin |

---

## §10. Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **lazyrecon** (recon automation) | Full reconnaissance pipeline | Subdomain enumeration, port scanning, screenshot capture in automated workflow |
| **lazys3** (S3 enumeration) | AWS S3 bucket discovery | Naming pattern permutation for staging/dev/prod bucket identification |
| **HostileSubBruteforcer** (subdomain) | Subdomain bruteforcing & takeover | DNS resolution with takeover detection for dangling CNAMEs |
| **JSParser** (JS analysis) | JavaScript endpoint extraction | Parse JS files for API routes, internal URLs, and configuration data |
| **crtndstry** (CT log) | Certificate transparency querying | Rapid subdomain discovery via CT log enumeration |
| **bbht** (toolkit setup) | Ubuntu environment provisioning | Automated installation of preferred bug bounty hunting tools |
| **interact.sh** (OOB testing) | Out-of-band interaction verification | Self-hosted alternative to Burp Collaborator for SSRF/blind XSS confirmation |
| **CAIDO** (proxy/cache analysis) | HTTP traffic analysis | HTTPQL for cache behavior tracking and web cache deception testing |
| **XSS Hunter** (blind XSS) | Blind XSS payload tracking | Custom JS payload with PHP parser for capturing blind execution contexts |
| **Censys.io** (certificate search) | Certificate transparency and host discovery | SAN enumeration for infrastructure mapping |

---

## Summary: Core Principles

Sadeghipour's research demonstrates that **breadth of reconnaissance directly correlates with depth of exploitation**. His most impactful findings — from Snapchat's Jenkins to Meta's ad platform — began with systematic asset discovery that revealed backend infrastructure invisible to surface-level testing.

The PDF generator attack surface represents a structural weakness in modern web architecture: any feature that converts user-controlled HTML to rendered output (expense reports, invoicing, reporting dashboards) introduces server-side execution capabilities that bypass client-side security models entirely. This pattern extends to ad platforms, where headless browsers process untrusted content with elevated infrastructure privileges.

The common thread across all research areas is **trust boundary identification** — finding the seam between user-controlled input and server-side processing, then leveraging that boundary for escalation. Whether through PDF generators, admin panel blind XSS, or CI/CD credential harvesting, the methodology consistently transforms reconnaissance breadth into exploitation depth through systematic chaining.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

### References

- DEF CON 27: "Owning the Clout Through SSRF and PDF Generators" (Ben Sadeghipour & Cody Brocious, 2019)
- "We Hacked Apple for 3 Months: Here's What We Found" (Sam Curry, Ben Sadeghipour, Brett Buerhaus, Samuel Erb, Tanner Barnes, 2020)
- "My Expense Report Resulted in a Server-Side Request Forgery (SSRF) on Lyft" (NahamSec Blog, 2020)
- "Secure Your Jenkins Instance or Hackers Will Force You To" (NahamSec Blog, 2017)
- "Chaining Multiple Vulnerabilities to Gain Admin Access" (NahamSec Blog, 2018)
- "Vulnerabilities to Master in 2025" (NahamSec Blog, 2025)
- Meta Bug Bounty Disclosure (TechCrunch, January 2025)
- [NahamSec Blog](https://www.nahamsec.com/posts)
- [GitHub](https://github.com/nahamsec)
