# Harsh Jaiswal & Rahul Maini: Server-Side Vulnerability Research Taxonomy

**Scope**: Comprehensive analysis of Harsh Jaiswal (@rootxharsh) and Rahul Maini (@iamnoooob)'s collaborative security research spanning 2019–2026, focusing on pre-authentication remote code execution, server-side exploitation chains, authentication bypass, and Electron application security.

**Coverage Period**: 2019–2026 (7+ years of collaborative research)

**Primary Affiliations**: ProjectDiscovery Research, Hacktron AI, Electrovolt

---

## Classification Structure

Jaiswal and Maini's research reveals a consistent exploitation philosophy: identifying **pre-authentication attack surfaces** in enterprise software and chaining multiple primitives — deserialization, template injection, authentication bypass, command injection — into full remote code execution. Their work emphasizes **source code review and patch diffing** as primary discovery methods, consistently targeting high-value enterprise products (Atlassian, Adobe, Apple, GitHub, VMware, Ivanti, BeyondTrust).

### Three-Axis Classification Framework

**Axis 1 (Primary)**: **Attack Surface Component** — The structural target being exploited (deserialization, template engine, authentication layer, file operations, command execution, Electron framework)

**Axis 2 (Cross-cutting)**: **Exploitation Mechanism** — The type of bypass or mismatch that enables exploitation

| Mechanism Type | Definition | Common Indicators |
|----------------|------------|-------------------|
| **Unsafe Reflection/Deserialization** | User-controlled input triggers class instantiation, method invocation, or object reconstruction | WDDX, Java serialization, JNDI, gadget chains |
| **Template/Expression Injection** | User input evaluated as template syntax or expression language | OGNL, CFML, EL, Velocity templates |
| **Authentication/Authorization Bypass** | Security checks circumvented through namespace confusion, signature manipulation, or missing annotations | SAML, namespace routing, WebSudo, annotation gaps |
| **Path/File Manipulation** | File system operations exploited via traversal, race conditions, or predictable naming | Upload traversal, log path injection, backup disclosure |
| **Command/OS Injection** | User input reaches system command execution without sanitization | `popen()`, `exec()`, shell metacharacters |
| **Validation Order Mismatch** | Security checks execute after dangerous operations have already occurred | Spring MVC validation-before-auth, TOCTOU |
| **Sandbox/Isolation Escape** | Breaking out of restricted execution contexts | Electron sandbox, Docker containers, CSP bypass |

**Axis 3 (Impact)**: **Attack Scenario** — The deployment context and ultimate impact (covered in §8).

### Core Research Philosophy

1. **Patch diffing as discovery method** — Comparing vulnerable and patched versions to identify root causes, then searching for bypasses or variants
2. **Source code review over black-box** — Deep analysis of application internals (Java decompilation, CFML source, binary analysis) rather than blind fuzzing
3. **Chain construction** — Combining low-severity primitives (file write + race condition, SQLi + password reset) into critical-impact sequences
4. **Variant analysis** — Once a bug class is identified, systematically searching for the same pattern across other codebases (AI-enabled in recent work)

---

## §1. Deserialization & Unsafe Reflection

Deserialization and reflection-based attacks represent the most technically deep category in Jaiswal and Maini's research, targeting Java, CFML, and Ruby applications where user-controlled input triggers class instantiation or method invocation.

### §1-1. WDDX Deserialization (Adobe ColdFusion)

ColdFusion's WDDX (Web Distributed Data eXchange) packet processing deserializes XML input into Java objects via unsafe reflection. The `WDDXDeserialize()` function instantiates arbitrary classes and invokes setter methods based on user-controlled type attributes and property names.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WDDX Struct Type Injection** | `argumentCollection` parameter accepts XML WDDX packets; struct `type` attribute controls class instantiation via `getClassBySignature()` | Pre-auth CFC endpoints like `/CFIDE/adminapi/accessmanager.cfc` |
| **Setter Method Chain** | Instantiated class setter methods (methods starting with "set") invoked with user-controlled arguments | Target class needs parameterless constructor + setter accepting single argument |
| **JNDI Lookup Gadget** | `com.sun.rowset.JdbcRowSetImpl` used as gadget: `setDataSourceName()` + `setAutoCommit(true)` triggers JNDI lookup to attacker LDAP | `commons-beanutils` on classpath for ysoserial payload |
| **Patch Bypass via Format Confusion** | Initial blacklist checked `L...;` format; bypass used `X...X` format that `getClassBySignature()` strips identically | TOCTOU between filter check and class resolution |

**CVEs**: CVE-2023-29300, CVE-2023-38203, CVE-2023-38204

**Attack Chain**: Craft WDDX XML → inject `JdbcRowSetImpl` type → trigger JNDI lookup → rogue LDAP serves deserialization payload → RCE on ColdFusion 2018/2021/2023

### §1-2. Java Deserialization in REST Mappings (Lucee)

Lucee's REST endpoint handling deserializes Java objects from request bodies when REST mappings accept serialized arguments.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **REST Argument Deserialization** | `JavaConverter.deserialize()` processes request body in REST endpoint handlers | REST mappings exposed; CVE-2023-38693 |
| **CFML Expression Interpreter via Cookie** | `StorageScopeCookie` evaluates cookie values through `CFMLExpressionInterpreter.interpret()` | Requires `rotateSessions` + Client Management enabled |
| **isDefined() Expression Evaluation** | Mura/Masa CMS passes user-controlled parameters to `isDefined('#params.method#')`, enabling CFML function execution | Pre-auth FEED API endpoint, universally exploitable |

**Attack Chain (Apple)**: Recon → identify Lucee + Mura CMS → exploit `isDefined()` with `imageRead()` / `createObject("java",...)` → arbitrary Java class instantiation → RCE

### §1-3. Ruby Deserialization Gadget Chains

Updated gadget chains for Ruby's `Marshal.load()` deserialization, enabling RCE through crafted serialized objects.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Ruby Marshal RCE Gadget** | Updated gadget chain for Ruby deserialization attacks using standard library classes | Application deserializes untrusted Marshal data |
| **ImageMagick Command Injection** | `ruby-mini-magick` library passes unsanitized input to ImageMagick CLI | CVE-2019-13574; user-controlled filenames/parameters |

---

## §2. Template & Expression Language Injection

Server-Side Template Injection (SSTI) and Expression Language (EL) injection attacks exploit template engines that evaluate user-controlled input as executable expressions.

### §2-1. OGNL Injection (Atlassian Confluence)

Confluence's Velocity templates and Struts2 framework process OGNL expressions that can be injected through unauthenticated endpoints.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Velocity Template Parameter Injection** | `.vm` files directly accessible without auth; `$stack.findValue("getText('$parameters.label')")` evaluates user input as OGNL | `text-inline.vm` reachable at `/template/aui/text-inline.vm` |
| **Unicode Escape Encoding** | `\u0027` (single quote) bypasses HTML entity encoding in Velocity context | Confluence's output encoding doesn't handle Unicode escapes |
| **OGNL Sandbox Bypass via Struts Context** | Access `.KEY_velocity.struts2.context` from `#request` map to reach `OgnlTool` outside sandbox | Struts2 internal context accessible from Velocity |
| **Expression Length Bypass** | `#parameters` map passes arguments indirectly, circumventing `struts.ognl.expressionMaxLength` (~200 chars) | Long payloads split across multiple parameters |

**CVE**: CVE-2023-22527 (CVSS 10.0)

**Attack Chain**: POST to `/template/aui/text-inline.vm` → Unicode-encoded OGNL in `label` parameter → Struts context access → `OgnlTool` evaluation → `freemarker.template.utility.Execute` → OS command execution

### §2-2. Hibernate Validator EL Injection (Ivanti EPMM)

Spring MVC applications using Hibernate Validator's `buildConstraintViolationWithTemplate()` with user-controlled input enable Expression Language injection — critically, validation executes **before** authorization checks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Validator Message Template Injection** | `ConstraintValidatorContext.buildConstraintViolationWithTemplate()` processes `${...}` EL expressions from user input | Custom validator uses unsanitized parameter values in error messages |
| **Pre-Authorization Execution** | Spring MVC resolves arguments and runs `@Valid` before `@PreAuthorize` interceptor executes | `@Valid` + `@PreAuthorize` on same controller method |
| **Java Reflection via EL** | `${''.getClass().forName('java.lang.Runtime')...}` chain achieves arbitrary command execution through EL evaluation | Standard Java EL engine with Spring context |

**CVEs**: CVE-2025-4427, CVE-2025-4428

**Attack Chain**: HTTP request with malicious `format` parameter → Spring MVC argument binding → `@Valid` triggers custom validator → EL expression evaluated in error message → RCE executes before `@PreAuthorize` check

---

## §3. Authentication & Authorization Bypass

Systematic identification of authentication bypass vectors in enterprise products, particularly SAML implementations and namespace routing confusion.

### §3-1. SAML Signature Bypass

Multiple SAML implementation vulnerabilities discovered through analysis of XML signature verification logic.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Encrypted Assertion Signature Skip (GitHub Enterprise)** | Signature extraction before decryption prevents post-decryption signature validation; inner assertion never verified | Encrypted SAML assertions enabled; `signatures = message_class.signatures(doc)` runs before decrypt |
| **DigestValue Smuggling via XPath (Ruby-SAML/GitLab)** | Overly permissive `//ds:DigestValue` XPath selects attacker-injected DigestValue from `samlp:Extensions` instead of SignedInfo block | Ruby-SAML library; attacker places DigestValue in Extensions element |
| **Response ID Substitution** | Modify outer Response ID while embedding original signed response inside `<ds:Object>` element | Original signature remains valid; inner assertion is tampered |
| **Digest Recalculation** | Attacker calculates correct digest for malicious assertion, bypassing `validate_assertion_digest_values` | Only digest validation applied; full signature verification skipped |

**CVEs**: CVE-2024-4985, CVE-2024-9487, CVE-2024-45409

### §3-2. Namespace Routing Bypass (Atlassian Confluence)

Atlassian's Struts2-based routing applies different security interceptors to different namespaces, creating bypass opportunities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Admin-to-JSON Namespace Swap** | `/admin/` routes accessible via `/json/` namespace with different interceptor stack; WebSudo check skipped for JSON | `WebSudoRequired` annotation absent on action class |
| **Unauthenticated Database Restore** | `POST /json/setup-restore.action` lacks authentication; `synchronous=true` parameter triggers immediate database restoration | Multi-part form upload with attacker-controlled backup ZIP |

**CVE**: CVE-2023-22518

### §3-3. URL Decoding Inconsistency (Versa Concerto)

Authentication filters and controllers apply URL decoding at different stages, creating TOCTOU bypass opportunities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Double-Decode Auth Bypass** | Auth filter decodes URL during checks but passes undecoded URL to controller | Path like `/portalapi/v1/users/username/admin;%2fv1%2fping` |
| **Traefik Header Drop** | `Connection: X-Real-Ip` causes Traefik to drop header; Spring Boot Actuator skips auth without `X-Real-Ip` | Vulnerable Traefik version as reverse proxy |

**CVEs**: CVE-2025-34025, CVE-2025-34026, CVE-2025-34027

---

## §4. SQL Injection to RCE Chains

Escalating SQL injection beyond data extraction into full remote code execution through post-exploitation primitives.

### §4-1. CFML SQL Injection (Apple/Masa CMS)

Masa/Mura CMS's `getObjects()` function lacks parameterized queries for `ContentHistID`, and Lucee's default single-quote escaping can be bypassed with backslash.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Backslash Quote Escape** | Lucee escapes `'` with `\'`; injecting `\'` causes the backslash to escape the quote, freeing the next character | CFML `cfquery` with `#arguments.contentHistID#` |
| **PreviewID Condition Trigger** | `dspObjects()` requires `isOnDisplay=true`; passing `previewID` parameter auto-sets this property via `standardSetIsOnDisplayHandler` | Required to reach vulnerable code path |
| **SQLi-to-RCE via Password Reset** | Extract admin password reset token via blind SQLi → reset admin password → install malicious plugin → upload CFM webshell | Admin plugin upload functionality available |

**CVE**: CVE-2024-32640

**Attack Chain**: JSON API endpoint → `processAsyncObject` with `contenthistid=x\'` → blind SQLi → extract reset token → admin access → plugin upload → RCE

### §4-2. Static Code Analysis for SQLi Discovery

Automated approach using CFM/CFC parser to identify `cfquery` tags containing unsanitized `arguments` variables, bypassing manual code review complexity.

---

## §5. File Operations & Path Traversal

Exploiting file system operations through path traversal, log manipulation, and race conditions.

### §5-1. Log Path Injection (CrushFTP)

CrushFTP's session handling populates user session objects from HTTP headers, and log file operations use controllable session keys to determine file locations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **AS2 Header Session Pollution** | `as2-to` header triggers session population from request headers; `drain_log()` uses controllable log paths | Anonymous session cookie auto-issued on any request |
| **Session Object File Copy** | `user_log_path` + `user_log_path_custom` headers control source/destination for file move operations | CrushFTP ≥10.5: direct file copy capability |
| **Log-Based File Write** | For CrushFTP ≤10.4: request details logged to attacker-specified path; partial content control | Requires crafting log content as payload |

**CVE**: CVE-2023-43177 (CVSS 9.8)

**Attack Chain**: GET `/WebInterface` for cookies → POST with `as2-to` + log path headers → copy `sessions.obj` to webroot → admin session hijack

### §5-2. Upload Path Traversal (DELMIA Apriso)

File upload endpoints with unsanitized filename parameters allow writing executable files to web-accessible directories.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unauthenticated User Creation** | SOAP endpoint `ProcessMessageASync_v2` creates accounts without authentication or message signing | Pre-auth SOAP endpoint at `/Apriso/MessageProcessor/` |
| **Upload Filename Traversal** | `UploadFile` endpoint accepts path traversal in filename (`\..\..\..\portal\uploads\webshell.asp`) | Authenticated via created account |

**CVEs**: CVE-2025-6204, CVE-2025-6205

### §5-3. Rails send_file Disclosure (Discourse)

Rack/Rails's `send_file` processes attacker-supplied `X-Accel-Mapping` header, performing regex substitution on filesystem paths to bypass Nginx `internal` directive.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **X-Accel-Mapping Path Rewrite** | Attacker supplies `X-Accel-Mapping` header; Rack regex-replaces internal path with external Nginx location | Rails `send_file` + Nginx `internal` directive |
| **Predictable Backup Naming** | Backup filenames follow `<site>-YYYY-MM-DD-HHMMSS-v<stamp>.tar.gz` pattern | Local file storage (`FileStore--LocalStore`) |

**CVE**: CVE-2024-53991

### §5-4. Race Condition File Write (Versa Concerto)

The package upload endpoint writes files before validating bearer tokens, creating a brief exploitation window.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Pre-Validation File Write** | `/portalapi/v1/package/spack/upload` writes file before token check; deleted on exception | Race condition window during health check interval |
| **LD_PRELOAD Hijack** | Write to `/etc/ld.so.preload` + `/tmp/hook.so`; health check `curl` (every 10s) loads malicious shared object | Linux `ld.so.preload` mechanism |

---

## §6. OS Command Injection

Direct command injection through unsanitized input reaching system command execution.

### §6-1. SMTP Command Injection (Zimbra)

Zimbra's `postjournal` binary passes recipient addresses from SMTP `RCPT TO:` commands to `popen()` without sanitization.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **popen() Injection via RCPT TO** | User-controlled email address in `RCPT TO:` field reaches `popen()` in `read_maps()` function | `postjournal_enabled=true` (disabled by default) |
| **Command Substitution in Quotes** | `$()` syntax executes commands even inside double-quoted strings; `${IFS}` substitutes spaces | Shell command string construction |

**CVE**: CVE-2024-45519

### §6-2. AI-Discovered Command Injection (BeyondTrust)

Pre-authentication OS command injection in BeyondTrust Remote Support, discovered through AI-enabled variant analysis searching for arithmetic evaluation bugs across codebases.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Pre-Auth OS Command Injection** | Unauthenticated endpoint allows OS command execution in site user context | CWE-78; CVSS 9.9 |

**CVE**: CVE-2026-1731 (CISA KEV; actively exploited in ransomware)

---

## §7. Electron Application Exploitation

Cross-application research targeting Electron-based desktop applications, identifying novel attack surfaces in the framework's security model.

### §7-1. Sandbox Escape via Window Events (Discord)

Discord's Electron configuration lacked explicit sandbox settings, allowing new renderer processes to spawn without sandbox isolation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **XSS via Embed Integration** | Cross-site scripting through Vimeo embed endpoint within Discord | Crafted Open Graph metadata pointing to XSS-vulnerable embed |
| **CSP Bypass via Chromium Bug** | Chromium bug (crbug.com/1115045) bypasses `frame-src` restrictions to load external iframes | Outdated Chromium version (83.0.4103.122) |
| **new-window Sandbox Escape** | Insufficient `new-window` event filtering allows opening windows without sandbox; redirect to different origin clears sandbox | `sandbox` not explicitly set in webPreferences |
| **V8 Exploit** | Outdated Chromium contains exploitable V8 bugs for code execution | Electron 9.x with Chromium 83 |

### §7-2. Path Traversal in Webview Protocol (VS Code)

VS Code's Restricted Mode bypassed through webview protocol path traversal leading to Node.js execution.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Extension ID Leak via Font CSS** | CSP `font-src` side-channel leaks extension ID through Origin header | Required for webview identification |
| **Meta Redirect CSP Bypass** | HTML `<meta>` refresh navigates to attacker domain despite strict CSP | Navigation not restricted by script-src |
| **vscode-webview XSS** | `parentOrigin` query parameter spoofing enables postMessage injection with `allowScripts:true` | Origin validation via query parameter |
| **vscode-file Path Traversal** | `..%2F` encoded traversal in `vscode-file://` URLs; this origin has `nodeIntegration` enabled | `require('child_process').exec()` available |

**CVE**: CVE-2021-43908

---

## §8. Infrastructure & Cloud Exploitation

Targeting infrastructure-level vulnerabilities including cloud metadata, static credentials, and container escapes.

### §8-1. Cloud Metadata via SSRF (Vimeo)

Server-side request forgery in API testing interfaces exposing cloud provider metadata.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **API Playground SSRF** | Server-side request from API testing interface reaches internal GCP metadata endpoint | Google Cloud infrastructure; `metadata.google.internal` accessible |
| **Service Account Token Extraction** | GCP metadata API returns service account tokens enabling lateral movement | SSRF reaches `169.254.169.254` |

### §8-2. Static Credential Reuse (VMware Aria)

VMware Aria Operations for Networks reused static SSH keys across versions, enabling authentication bypass.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Static SSH Key Across Versions** | SSH keys for `support` and `ubuntu` users not regenerated between versions 6.0–6.10 | SSH access to target; keys extractable from any version |

**CVE**: CVE-2023-34039 (CVSS 9.8)

### §8-3. Container Escape (Versa Concerto)

Docker volume misconfigurations enabling container-to-host privilege escalation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Host Binary Overwrite** | `/usr/bin/` and `/bin/` mapped to host filesystem; overwriting `test` binary exploits hourly cron job | `popularity-contest` cron job executes `test` |

**CVE**: CVE-2025-34025

---

## §9. Research Methodology & Tooling

### §9-1. Vulnerability Research Workflow

Rahul Maini's documented methodology for CVE analysis and n-day reverse engineering:

1. **Environment Setup** — Identify technology stack; obtain vulnerable software versions
2. **Patch Diffing** — Decompile both versions; create git repo; analyze diffs for validation changes, new checks, callsite modifications
3. **Code Analysis** — Focus on input validation changes where insecure functions are invoked
4. **PoC Development** — Version-pinned demonstrations using read-only signals
5. **Knowledge Organization** — Lab notes, requests, diffs, and Nuclei detection templates in structured folders

### §9-2. Workshop: "Demystifying the Server Side"

Presented at Ekoparty, Hackitivity, and NoNameCon 2020 with Rajanish Pathak. Covered:
- SSRF identification and exploitation techniques
- XXE (XML External Entity) injection
- Server-side misconfigurations (F5 Auth Bypass case study)
- Hands-on scenarios for manual identification of scanner-evading vulnerabilities

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| Pre-Auth RCE | Internet-facing enterprise apps | §1 + §2 + §6 |
| Authentication Bypass | SAML-based SSO, namespace routing | §3 |
| SQLi-to-RCE Chain | CMS with admin plugin upload | §4 + §5 |
| File-Based RCE | Upload traversal, log injection, race conditions | §5 |
| Desktop App RCE | Electron-based applications | §7 |
| Infrastructure Compromise | Cloud, SSH, containers | §8 |
| WAF/Filter Bypass | Encoding, format confusion, expression indirection | §1-4 (patch bypass), §2-1 (Unicode/sandbox bypass) |

---

## CVE / Bounty Mapping (2019–2026)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-1 (WDDX Deser) | CVE-2023-29300 / CVE-2023-38203 / CVE-2023-38204 (Adobe ColdFusion) | Pre-auth RCE; patch bypass chain |
| §1-2 (Lucee isDefined) | Apple Lucee/Mura RCE | $50,000 Apple Bug Bounty |
| §1-3 (Ruby deser) + §7-1 | Discord Desktop RCE | Bounty paid (undisclosed) |
| §2-1 (OGNL injection) | CVE-2023-22527 (Confluence) | CVSS 10.0; 40,000+ exploitation attempts in 3 days |
| §2-2 (EL injection) | CVE-2025-4427/4428 (Ivanti EPMM) | Pre-auth RCE; validation-before-auth pattern |
| §3-1 (SAML bypass) | CVE-2024-4985/9487 (GitHub Enterprise) | Authentication bypass on GHE with encrypted assertions |
| §3-1 (SAML XPath) | CVE-2024-45409 (Ruby-SAML/GitLab) | Critical auth bypass affecting GitLab |
| §3-2 (Namespace bypass) | CVE-2023-22518 (Confluence) | Unauthenticated database restore |
| §3-3 (URL decode) | CVE-2025-34025/34026/34027 (Versa Concerto) | Auth bypass → file write → RCE chain |
| §4-1 (CFML SQLi) | CVE-2024-32640 (Masa CMS / Apple) | SQLi-to-RCE; Apple fixed in 2 hours |
| §5-1 (Log path injection) | CVE-2023-43177 (CrushFTP) | CVSS 9.8; unauthenticated RCE |
| §5-2 (Upload traversal) | CVE-2025-6204/6205 (DELMIA Apriso) | Unauth user creation + upload RCE |
| §5-3 (send_file disclosure) | CVE-2024-53991 (Discourse) | Backup file disclosure; CVSS 7.5 |
| §6-1 (popen injection) | CVE-2024-45519 (Zimbra) | Unauthenticated command execution |
| §6-2 (OS command injection) | CVE-2026-1731 (BeyondTrust) | CVSS 9.9; CISA KEV; active ransomware exploitation |
| §7-2 (Electron path traversal) | CVE-2021-43908 (VS Code) | $3,000 MSRC bounty |
| §8-2 (Static SSH keys) | CVE-2023-34039 (VMware Aria) | CVSS 9.8; static keys across all versions |
| PayPal RCE | PayPal (undisclosed) | $30,000 bounty |
| SSRF (Vimeo) | Vimeo API Playground | GCP metadata access; bounty paid |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Nuclei** (ProjectDiscovery) | All vulnerability classes | YAML-based templates for automated detection; templates published for most CVEs above |
| **CFM/CFC Static Parser** | ColdFusion/Lucee applications | Automated identification of `cfquery` tags with unsanitized arguments |
| **IntelliJ IDEA Ultimate** | Java application debugging | Remote JVM debugging via `-agentlib:jdwp` for code path analysis |
| **CFR / FernFlower / Procyon** | Java decompilation | Patch diff analysis of JAR files |
| **ILSpy / dotPeek / dnSpyEx** | .NET decompilation | .NET assembly analysis for patch diffing |
| **GDB** | Binary analysis | Dynamic analysis of C binaries (e.g., Zimbra `postjournal`) |
| **Hacktron AI** | Cross-codebase variant analysis | AI-enabled pattern matching for bug class discovery |

---

## Summary: Core Principles

The fundamental pattern across Jaiswal and Maini's research is the exploitation of **enterprise software's complexity surface** — the gap between what developers intend security controls to cover and what actually reaches dangerous operations. In ColdFusion, XML parsing reaches Java reflection. In Confluence, Velocity templates reach OGNL evaluation. In Ivanti, bean validation reaches Expression Language evaluation before authorization checks execute. In every case, **user input travels through a longer path than developers anticipate**, crossing trust boundaries that were never explicitly defended.

Their patch bypass work (ColdFusion CVE-2023-38203/38204, Confluence CVE-2023-22518 variants) demonstrates that **incremental fixes consistently fail** when the root cause is architectural — blacklists are bypassed through format confusion, namespace restrictions are circumvented through alternative routing, and sandbox constraints are broken through context escalation. Structural solutions require eliminating the dangerous evaluation surface entirely (replacing `popen()` with `execvp()`, removing expression evaluation from error messages, enforcing signature verification order), not adding filters to the input path.

Their evolution from manual source code review (2019–2023) to AI-enabled variant analysis (2024–2026) represents a shift toward **systematic vulnerability discovery** — identifying bug classes once, then searching programmatically across the entire software ecosystem for the same pattern.

---

*This document was created for defensive security research and vulnerability understanding purposes.*
