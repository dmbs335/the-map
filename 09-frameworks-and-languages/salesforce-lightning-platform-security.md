# Salesforce / Lightning Platform Security — Mutation & Variation Taxonomy

---

## Classification Structure

The Salesforce Lightning Platform presents a unique attack surface shaped by its multi-tenant architecture, declarative security model, and layered execution contexts. Unlike traditional web applications where security enforcement is monolithic, Salesforce distributes security responsibility across platform-managed guardrails, administrator configuration, and developer-written code. This distribution creates a taxonomy of mutations organized along three orthogonal axes.

**Axis 1 — Mutation Target (Primary Axis)**: The structural component of the Salesforce platform being attacked. This axis structures the main body of this document across 12 top-level categories, ranging from the access control model to AI agent integrations.

**Axis 2 — Discrepancy Type (Cross-Cutting Axis)**: The nature of the security gap that makes each mutation exploitable. Every technique in this taxonomy succeeds because of one of these fundamental discrepancies:

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D-MODE** | Execution Mode Gap | System mode vs. user mode differential — Apex runs with elevated privileges by default |
| **D-ENFORCE** | Enforcement Location Gap | Client-side vs. server-side security enforcement differential |
| **D-DEFAULT** | Insecure Default Gap | Overly permissive default configurations shipped by the platform or packages |
| **D-TRUST** | Trust Boundary Gap | Misplaced trust in third-party packages, automation contexts, or namespace isolation |
| **D-AUTH** | Authentication Boundary Gap | Session/token/OAuth trust that bypasses or outlives authentication ceremonies |
| **D-VISIBILITY** | Monitoring Visibility Gap | Actions that evade detection through legitimate-appearing API calls or audit blind spots |

**Axis 3 — Attack Scenario (Mapping Axis)**: The deployment context in which mutations are weaponized — unauthenticated data harvesting, privilege escalation, large-scale exfiltration, account takeover, phishing/impersonation, or supply chain compromise. This axis is mapped in §13.

### Foundational Concept: The Salesforce Security Model Stack

Understanding the taxonomy requires understanding the four layers of Salesforce's security model, each of which can be independently misconfigured or bypassed:

```
Layer 4: Field-Level Security (FLS)     — Which fields a user can see/edit
Layer 3: Object-Level Security (CRUD)   — Which objects a user can read/create/update/delete
Layer 2: Record-Level Security (Sharing) — Which records a user can access (OWD, sharing rules, roles)
Layer 1: Authentication & Session       — Who the user is (login, OAuth, MFA, session tokens)
```

Apex code running in **system mode** bypasses Layers 2–4 entirely. This is the single most important architectural property driving the Salesforce attack surface.

---

## §1. Access Control Model Bypass (CRUD / FLS / Sharing)

The most prevalent vulnerability class on the Salesforce platform. Because Apex runs in system mode by default, every custom controller, trigger, and service class must explicitly enforce object-level (CRUD), field-level (FLS), and record-level (sharing) security. Failure to do so is the #1 reason applications fail AppExchange security review.

### §1-1. CRUD Enforcement Bypass

Apex DML operations (insert, update, delete, upsert) do not check whether the running user has Create, Read, Update, or Delete permissions on the target object unless explicitly coded.

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Missing CRUD check on DML** | Apex controller performs DML on an object without calling `Schema.sObjectType.X.isAccessible()` / `isCreateable()` / `isUpdateable()` / `isDeletable()` | D-MODE |
| **System-mode SOQL in controllers** | `@AuraEnabled` methods execute SOQL without `WITH USER_MODE` or `WITH SECURITY_ENFORCED`, returning all records regardless of the calling user's profile | D-MODE |
| **Trigger-based CRUD bypass** | After-insert/update triggers perform cross-object DML in system context, escalating a user's write on Object A to unauthorized writes on Object B | D-MODE |
| **Batch Apex privilege escalation** | Batch jobs running as a system user inherit full CRUD regardless of the initiating user's permissions | D-MODE |

### §1-2. Field-Level Security (FLS) Bypass

Even when CRUD is enforced, individual field access may not be checked, exposing sensitive fields (SSN, salary, health data) to users whose profiles restrict those fields.

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Missing FLS in SOQL SELECT** | Dynamic SOQL builds field lists without checking `Schema.SObjectType.X.fields.Y.getDescribe().isAccessible()` | D-MODE |
| **OmniStudio SOQL data source FLS bypass** | FlexCard SOQL data sources ignore FLS entirely, exposing all field values for queried records (CVE-2025-43698) | D-DEFAULT |
| **Classic Encryption plaintext leakage** | OmniStudio Data Mappers return plaintext values for Classic Encrypted fields without checking `View Encrypted Data` permission (CVE-2025-43697, CVE-2025-43700) | D-DEFAULT |
| **Describe-based field enumeration** | Attackers call `getObjectInfo` or GraphQL introspection to discover field names, then access them through FLS-blind controllers | D-MODE |

### §1-3. Sharing Rule Bypass

Record-level security (who can see which records) is governed by Organization-Wide Defaults (OWD), role hierarchy, sharing rules, and manual shares. Apex classes declared `without sharing` bypass all of these.

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **`without sharing` Apex class** | Controller declared `without sharing` (or inheriting it from a parent class) returns all records regardless of the user's sharing context | D-MODE |
| **Inherited sharing context confusion** | Class declared with no explicit sharing keyword inherits the sharing context of its caller — if called from `without sharing` code, it runs without sharing | D-MODE |
| **Flow system-context sharing bypass** | Flows configured to run in "System Context without Sharing" grant unrestricted record access to the triggering user (§9-1) | D-MODE |
| **OmniStudio Guest User Custom Settings access** | FlexCard SOQL data sources allow guest users to bypass platform protections and read Custom Settings containing sensitive configuration data (CVE-2025-43701) | D-DEFAULT |

---

## §2. Query Language Injection (SOQL / SOSL)

Salesforce Object Query Language (SOQL) and Salesforce Object Search Language (SOSL) are not SQL, but they are susceptible to injection when user input is concatenated into dynamic queries without parameterized binding.

### §2-1. Classic SOQL Injection

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Dynamic WHERE clause injection** | User input concatenated into `Database.query('SELECT ... WHERE Name = \'' + userInput + '\'')` allows injection of additional WHERE conditions, LIMIT manipulation, or ORDER BY exploitation | D-MODE |
| **Blind SOQL injection via response discrepancy** | When query results are not directly returned, attackers observe response differences (timing, error messages, record counts) to infer data character-by-character — analogous to blind SQL injection | D-MODE |
| **SOQL injection in standard Aura controllers** | Built-in platform controllers (e.g., `CsvDataImportResourceFamilyController/ACTION$getCsvAutoMap`) accept parameters unsafely embedded into dynamic SOQL, creating 0-day injection points present in all Salesforce deployments | D-DEFAULT |
| **Subquery-based data extraction** | Injected SOQL subqueries (`WHERE Id IN (SELECT ... FROM SensitiveObject)`) enable cross-object data harvesting through boolean inference | D-MODE |

### §2-2. SOSL Injection

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Dynamic SOSL FIND injection** | User input in `Search.query('FIND {' + userInput + '} ...')` allows modification of search scope, returning objects, or field restrictions | D-MODE |
| **Cross-object SOSL harvesting** | Injected RETURNING clauses expand the search to return fields from objects the UI would not normally expose | D-MODE |

### §2-3. Prevention Bypass

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **`String.escapeSingleQuotes()` insufficiency** | While escaping single quotes prevents basic injection, LIKE wildcards (`%`, `_`) and certain SOQL operators remain injectable | D-MODE |
| **Bind variable avoidance in dynamic SOQL** | Developers use string concatenation instead of bind variables (`:variableName`) for dynamic field names or object names, which cannot use bind variables by design | D-MODE |

---

## §3. Aura / Lightning Framework Exploitation

The Aura framework powers the Lightning Experience UI and exposes HTTP endpoints that can be called directly, bypassing the UI layer entirely. This creates an attack surface invisible to traditional web application testing.

### §3-1. Aura Endpoint Enumeration

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Guest user Aura API access** | The `/s/sfsites/aura` endpoint accepts requests from unauthenticated guest users with `token=undefined`, exposing all `@AuraEnabled` methods accessible to the Guest User profile | D-DEFAULT |
| **Controller discovery via `getConfigData`** | The `HostConfigController/ACTION$getConfigData` method returns the org's domain, security settings, and list of accessible objects without authentication | D-DEFAULT |
| **`@AuraEnabled` method enumeration** | Custom Apex classes with `@AuraEnabled` annotations are discoverable and callable through the Aura endpoint — attackers enumerate available methods by probing common controller naming patterns | D-DEFAULT |
| **Self-registration detection** | Probing the Aura endpoint reveals whether self-registration is enabled on an Experience Cloud site, providing an entry vector for creating authenticated sessions | D-DEFAULT |

### §3-2. GraphQL Controller Exploitation

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Unauthenticated GraphQL introspection** | The GraphQL Aura controller is available to guest users by default, enabling full schema introspection — discovery of all UIAPI-supported objects, their fields, and relationships | D-DEFAULT |
| **GraphQL pagination-based record harvesting** | Unlike basic Aura controllers (limited to ~2,000 records), GraphQL supports standardized pagination enabling retrieval of all records tied to an object | D-DEFAULT |
| **Object/field discovery via GraphQL** | Built-in introspection queries reveal field names without requiring `getObjectInfo` calls, facilitating targeted data extraction | D-DEFAULT |

### §3-3. Standard Controller Abuse

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **`getRecord` / `getRecordUi` data harvesting** | Standard Lightning Data Service controllers return record data including fields not displayed in the UI, if the user's profile grants field access | D-ENFORCE |
| **Record type enumeration** | Standard controllers expose available record types, revealing business logic and object structure to low-privilege users | D-DEFAULT |
| **Bulk record retrieval via `getListUi`** | List view controllers return full result sets that may include records not intended for the requesting user's view | D-ENFORCE |

---

## §4. Experience Cloud (Community) Misconfiguration

Experience Cloud sites (formerly Communities) are the most frequently exploited Salesforce attack surface. The combination of guest user access, configurable sharing, and Aura endpoint exposure creates a rich misconfiguration landscape.

### §4-1. Guest User Over-Permissioning

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Excessive object access on Guest User profile** | Administrators grant Read access on sensitive objects (Account, Contact, Case, User) to the Guest User profile for site functionality, inadvertently exposing all records with compatible sharing | D-DEFAULT |
| **Guest user record ownership** | Historically, guest users became owners of records they created, gaining full CRUD on those records and potentially triggering sharing cascades | D-DEFAULT |
| **Guest user API access** | The Guest User profile retains API access by default, enabling programmatic data harvesting via REST/SOAP/Aura endpoints (§8) | D-DEFAULT |
| **Guest user Custom Settings access** | FlexCard SOQL data sources allow guest users to read Custom Settings, which often contain API keys, configuration secrets, or business-critical parameters (CVE-2025-43701) | D-DEFAULT |

### §4-2. URL-Based Access Manipulation

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **`/s/` to `/003` URL switching** | Changing the Experience Cloud URL path from `/s/` to the classic Salesforce record ID prefix (e.g., `/003` for Contact) bypasses the community's custom UI and renders a standard Salesforce list view with broader data visibility | D-ENFORCE |
| **Direct object ID navigation** | Replacing a record ID in the URL with another ID of the same object type grants access if sharing rules are misconfigured — classic IDOR enabled by predictable Salesforce ID structure (§4-3) | D-ENFORCE |
| **Visualforce page direct access** | Navigating directly to `/apex/PageName` may bypass Lightning Experience access controls if the underlying Visualforce page lacks its own authorization checks | D-ENFORCE |

### §4-3. Salesforce ID Predictability

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Object prefix enumeration** | The first 3 characters of every Salesforce ID encode the object type (e.g., `001` = Account, `003` = Contact), enabling targeted object discovery | D-ENFORCE |
| **Instance identifier leakage** | Characters 4–6 encode the Salesforce instance, narrowing the search space for record enumeration | D-ENFORCE |
| **Sequential increment exploitation** | The remaining 8+ characters are a base-62 incrementor — not random — enabling ID iteration attacks to discover valid record IDs by incrementing from a known ID | D-ENFORCE |

---

## §5. OAuth & Authentication Abuse

Salesforce's OAuth implementation for Connected Apps is a primary attack vector in the 2025 breach wave. Long-lived OAuth tokens bypass MFA, and social engineering can trick users into authorizing malicious applications.

### §5-1. Connected App Token Abuse

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Compromised third-party integration tokens** | Attackers obtain OAuth refresh tokens from a compromised third-party integration (e.g., Salesloft/Drift), then use those tokens to access Salesforce environments of all customers using that integration — 700+ organizations affected in the 2025 UNC6395 campaign | D-AUTH |
| **Malicious Connected App authorization** | Attackers social-engineer users (often via vishing) into authorizing fraudulent Connected Apps that mimic legitimate tools (e.g., fake "Data Loader"), granting long-lived OAuth tokens | D-AUTH |
| **OAuth token MFA bypass** | Once an OAuth refresh token is obtained, it generates new access tokens without requiring MFA, enabling persistent access that survives password changes | D-AUTH |
| **Data Loader impersonation** | Attackers clone the Salesforce Data Loader OAuth client configuration, creating a connected app with identical scope that victims authorize through a spoofed device code flow | D-AUTH |

### §5-2. OAuth Device Flow Exploitation

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Vishing + device code flow** | Attackers call victims posing as IT support, directing them to enter an 8-digit device code that authorizes a malicious application — the victim sees a legitimate Salesforce authorization page | D-AUTH |
| **Long-lived refresh token persistence** | Device flow tokens persist until explicitly revoked, providing backdoor access that can survive incident response actions that only change passwords or rotate session tokens | D-AUTH |

### §5-3. Session & Authentication Bypass

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Session token theft** | Malware, browser extensions, or AiTM proxies capture Salesforce session cookies post-MFA, enabling "pass-the-cookie" access without re-authentication | D-AUTH |
| **SSO misconfiguration bypass** | Improperly configured SSO providers may issue tokens with excessive scope, or fail to properly validate audience restrictions, allowing cross-tenant access | D-AUTH |
| **IP range bypass via API access** | Login IP restrictions configured on profiles may not apply to API-only access paths, allowing token-based access from any IP | D-ENFORCE |

---

## §6. Client-Side Component Security

Lightning components (both Aura and LWC) run in the browser and are subject to client-side attack vectors. The platform provides Lightning Locker (legacy) and Lightning Web Security (LWS) for namespace isolation, but vulnerabilities persist at the component level.

### §6-1. Cross-Site Scripting (XSS)

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Visualforce unescaped output** | `<apex:outputText value="{!userInput}" escape="false"/>` renders user input directly into the page without encoding | D-ENFORCE |
| **`{!expression}` merge field injection** | Visualforce merge fields used outside of component attributes can inject script into the page if the underlying data contains HTML/JavaScript | D-ENFORCE |
| **LWC `innerHTML` / `lwc:dom="manual"` injection** | Lightning Web Components that use manual DOM manipulation to insert user-controlled content bypass LWS sanitization | D-ENFORCE |
| **Aura `$A.createComponent` with user input** | Dynamic component creation using unsanitized parameters can inject malicious component configurations | D-ENFORCE |
| **Third-party library XSS** | LWS allows broader use of community JavaScript libraries than Lightning Locker, increasing the attack surface from vulnerable dependencies | D-TRUST |

### §6-2. Cross-Site Request Forgery (CSRF)

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **State-changing GET requests** | Visualforce `<apex:page action="...">` handlers that perform DML during page load are vulnerable to CSRF — an attacker crafts a link that triggers the action when the victim visits | D-ENFORCE |
| **Lightning component `init`/`connectedCallback` DML** | Components that execute server-side DML operations on initialization (rather than on explicit user interaction) can be exploited via CSRF | D-ENFORCE |
| **Anti-CSRF token absence in custom API** | Custom REST endpoints built with `@RestResource` that perform state changes without validating the platform's anti-CSRF token | D-ENFORCE |

### §6-3. Namespace Isolation Bypass

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Lightning Locker secure wrapper escape** | Historical bypasses of Lightning Locker's `SecureWindow`/`SecureDocument` wrappers that allowed cross-namespace DOM access | D-TRUST |
| **LWS JavaScript sandbox distortion gaps** | LWS uses API distortions instead of wrappers — edge cases where distortions fail to cover certain browser APIs may allow cross-namespace access | D-TRUST |
| **CSP bypass via whitelisted domains** | Content Security Policy includes trusted domains — if any whitelisted domain is compromised or expired, attackers can load external scripts (as in the ForcedLeak CSP bypass via expired `my-salesforce-cms.com` domain, §10-1) | D-TRUST |

---

## §7. Server-Side Apex Code Exploitation

Apex is a strongly-typed, Java-like language that runs on Salesforce's servers. While the platform prevents many traditional server-side attacks (no filesystem access, no OS commands), Apex's HTTP callout capabilities and system-mode execution create distinctive vulnerability patterns.

### §7-1. Server-Side Request Forgery (SSRF)

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **User-controlled callout URL** | Apex `HttpRequest.setEndpoint(userInput)` without URL validation allows attackers to make the Salesforce server issue requests to arbitrary destinations | D-MODE |
| **Remote Site Settings misconfiguration** | Overly broad Remote Site Settings (e.g., wildcards, broad domain patterns) expand the reachable attack surface for SSRF | D-DEFAULT |
| **Named Credential scope abuse** | Named Credentials configured with `Named Principal` identity type allow any user executing the Apex code to make authenticated requests to the external system with a shared credential, potentially accessing data beyond their authorization level | D-TRUST |
| **Internal metadata endpoint targeting** | SSRF payloads targeting Salesforce's internal infrastructure endpoints (if accessible) or cloud metadata endpoints in integration scenarios | D-MODE |

### §7-2. System Mode Exploitation

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Apex action FLS/CRUD bypass in Flows** | Apex Invocable Actions called from Flows do not inherit the Flow's security context settings — they always run in Apex's default system mode (§9-2) | D-MODE |
| **Trigger chain escalation** | A user creates/updates a record they have access to → after-trigger executes Apex in system mode → performs DML on objects/records the user cannot access | D-MODE |
| **Schedulable/Batchable privilege escalation** | Scheduled Apex and Batch Apex run as the user who scheduled them but execute in system mode, combining the user's session with elevated CRUD/FLS access | D-MODE |
| **Test class data access** | Apex test classes running `@isTest` with `SeeAllData=true` can access all org data in system mode, creating potential data exposure vectors in development workflows | D-MODE |

### §7-3. Hardcoded Secrets & Credential Exposure

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Hardcoded API keys in Apex** | Developers embed API keys, passwords, or tokens directly in Apex code — managed packages hide source code from customers but the secrets are still executable | D-TRUST |
| **Debug log credential leakage** | `System.debug()` statements that log sensitive data (tokens, passwords, PII) are visible to any user with access to debug logs | D-VISIBILITY |
| **Custom Metadata/Custom Setting secrets** | API keys stored in Custom Metadata or Custom Settings accessible to users with the appropriate profile permissions | D-DEFAULT |
| **Integration Procedure credential exposure** | OmniStudio Integration Procedures with hardcoded credentials that leak when executed in debug mode or accessed by guest users through misconfigured community portals | D-TRUST |

---

## §8. API Surface & Data Exfiltration

Salesforce exposes multiple API surfaces (REST, SOAP, Bulk, Composite, GraphQL, Aura) that provide legitimate integration points but also serve as high-volume data exfiltration channels.

### §8-1. REST / SOAP API Exploitation

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Bulk query exfiltration** | Compromised OAuth tokens used to execute SOQL queries via `/services/data/vXX.0/query`, returning ~2.3 MB (~1,000 records) per request — IP rotation evades per-IP rate limits | D-VISIBILITY |
| **API-only access bypassing UI controls** | Security controls visible in the Lightning UI (warning dialogs, field visibility restrictions) do not apply to API access, enabling data access beyond what the UI would suggest | D-ENFORCE |
| **Bulk API 2.0 mass export** | Bulk API jobs process millions of records asynchronously — a compromised service account can initiate bulk exports that blend with legitimate ETL traffic | D-VISIBILITY |
| **Composite API chaining** | Composite requests chain up to 25 subrequests, enabling complex data harvesting operations in a single API call that may evade per-request monitoring | D-VISIBILITY |

### §8-2. Public Link & Content Document Manipulation

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Public link SOQL injection** | Public links create unauthenticated Aura endpoints — historical vulnerability allowed blind SOQL injection through these endpoints to extract PII character-by-character (patched February 2024) | D-DEFAULT |
| **ContentDocument access expansion** | Attackers with access to one ContentDocument can enumerate related ContentVersions and potentially access documents shared with other users through shared ContentDocumentLink records | D-ENFORCE |
| **Public link enumeration** | Systematically testing content delivery URLs to discover shared files that lack password protection or expiration dates | D-DEFAULT |

### §8-3. Detection Evasion Techniques

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Business-hours operation** | Sophisticated attackers time exfiltration to business hours and normal traffic patterns, making API calls indistinguishable from legitimate usage | D-VISIBILITY |
| **Volume throttling** | Staying within per-IP and per-user rate limits while slowly exfiltrating data over days/weeks | D-VISIBILITY |
| **Proxy IP rotation** | Cycling through exit nodes/proxies to avoid single-IP anomaly detection | D-VISIBILITY |
| **Legitimate tool impersonation** | Using Data Loader or other recognized Salesforce tools (or their OAuth client IDs) for exfiltration, creating API traffic indistinguishable from normal operations | D-VISIBILITY |

---

## §9. Automation & Low-Code Logic Abuse

Salesforce Flows, Process Builder (deprecated), and Apex triggers create automation chains that execute with configurable security contexts. Misuse of execution context can create privilege escalation paths invisible to traditional security review.

### §9-1. Flow Execution Context Exploitation

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **System Context without Sharing** | Flows configured to run in "System Context without Sharing" grant unrestricted access to all records and bypass FLS, CRUD, and sharing — effectively giving temporary admin access to the triggering user | D-MODE |
| **System Context with Sharing escalation** | Even with sharing enforced, system context bypasses FLS and CRUD checks, allowing Flows to read/write fields the user cannot access through the UI | D-MODE |
| **Scheduled Flow privilege persistence** | Scheduled Flows run in the context of the user who created them — if that user's permissions later change, the Flow retains the original elevated context | D-MODE |
| **Flow-to-Apex context mismatch** | Flows invoking Apex actions via `@InvocableMethod` always execute the Apex in system mode, regardless of the Flow's security context setting (§7-2) | D-MODE |

### §9-2. Hidden Automation Backdoors

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Background workflow data exfiltration** | Attackers with admin access create hidden workflows, scheduled jobs, or record-triggered Flows that continuously exfiltrate data through outbound messages or HTTP callouts | D-VISIBILITY |
| **Trigger-based lateral movement** | Malicious triggers that fire on common objects (e.g., FeedItem, Task) to execute arbitrary Apex whenever any user performs routine operations | D-VISIBILITY |
| **Process Builder email exfiltration** | Automated email alerts configured to send record field values to external email addresses on record creation/update | D-VISIBILITY |

---

## §10. AI Agent Exploitation (Agentforce / Einstein)

Salesforce's AI integration through Agentforce and Einstein introduces a new attack surface combining traditional web vulnerabilities with LLM-specific attacks.

### §10-1. Indirect Prompt Injection (ForcedLeak)

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Web-to-Lead payload injection** | Malicious text injected into Web-to-Lead form fields (particularly the 42,000-character `description` field) is later processed by Agentforce, executing injected instructions in the AI's context — CVSS 9.4 | D-TRUST |
| **CSP bypass via expired whitelisted domain** | Salesforce's Content Security Policy whitelisted an expired domain (`my-salesforce-cms.com`) that researchers purchased for $5, enabling data exfiltration through attacker-controlled URLs | D-TRUST |
| **CRM data exfiltration via AI** | Prompt injection causes Agentforce to query CRM objects and transmit results to attacker-controlled endpoints, bypassing traditional data access controls | D-TRUST |
| **Persistent access establishment** | Injected prompts can manipulate CRM records (updating contact information, creating tasks) to establish persistent attacker footholds that survive the AI interaction | D-TRUST |

### §10-2. AI Context Manipulation

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Cross-conversation context pollution** | Malicious data persisted in CRM records influences future AI interactions with other users, creating stored prompt injection analogous to stored XSS | D-TRUST |
| **Tool/action hijacking** | Prompt injection causes the AI agent to invoke specific Salesforce actions (email sending, record updates, approval processes) outside the intended workflow | D-TRUST |

---

## §11. Third-Party & Supply Chain

The Salesforce ecosystem includes ~7,000 AppExchange packages and countless custom integrations. Each extends the trust boundary of the platform.

### §11-1. Managed Package Risks

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Hidden Apex in managed packages** | Managed package Apex source code is hidden from customers — malicious or vulnerable code is unauditable yet executes with the same privileges as customer-written Apex | D-TRUST |
| **Named Credential cross-platform pivot** | Managed packages configure Named Credentials to external systems — if misconfigured with `Named Principal` identity type, any user executing the package's Apex can make authenticated requests to the external system | D-TRUST |
| **Package permission escalation** | Installing a managed package may grant its Permission Sets to existing profiles, inadvertently expanding user access beyond the administrator's intent | D-DEFAULT |
| **Dependency vulnerability inheritance** | Third-party JavaScript libraries bundled in Lightning components inherit vulnerabilities from their open-source dependencies | D-TRUST |

### §11-2. Integration Credential Abuse

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Compromised integration user** | Service accounts used for system integrations often have broad API access with no MFA — compromising one account grants API access to the entire org's data | D-AUTH |
| **Named Credential identity type misconfiguration** | `Named Principal` shares one credential across all users; `Per User` requires individual credential management — the easier option (`Named Principal`) creates a shared-credential risk | D-DEFAULT |
| **OAuth scope over-provisioning** | Connected Apps granted `full` scope when only specific object access is needed, enabling lateral movement if the app's credentials are compromised | D-DEFAULT |

---

## §12. Platform Email & Communication Abuse

Salesforce's email services, when misconfigured, provide high-trust phishing infrastructure that bypasses traditional email security controls.

### §12-1. Email Service Exploitation (PhishForce)

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Email-to-Case domain hijacking** | Attackers exploit Salesforce's Email-to-Case feature to generate email addresses on the `salesforce.com` domain, then repurpose those addresses to send phishing emails that inherit Salesforce's domain trust | D-TRUST |
| **SPF/DKIM/DMARC pass-through** | Phishing emails originating from legitimate Salesforce mail servers pass all email authentication checks (SPF, DKIM, DMARC), defeating signature-based anti-phishing filters | D-TRUST |
| **Brand impersonation via sender spoofing** | After gaining control of a Salesforce email address, attackers modify the display name, sender username, and email body to impersonate legitimate brands (e.g., Meta/Facebook) | D-TRUST |
| **Unicode homoglyph bypass** | Sender names use Unicode lookalike characters to bypass brand impersonation detection filters while appearing legitimate to recipients | D-TRUST |

### §12-2. Outbound Email Abuse

| Subtype | Mechanism | Discrepancy |
|---------|-----------|-------------|
| **Workflow email alert data leakage** | Email alerts configured on workflows/Flows include merge fields containing sensitive data — if the recipient list is manipulated or misconfigured, data is sent externally | D-VISIBILITY |
| **Mass email template exploitation** | Salesforce Marketing Cloud or org email templates used to send phishing at scale, leveraging Salesforce's sending reputation | D-TRUST |

---

## §13. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Precondition | Primary Mutation Categories |
|----------|---------------------------|---------------------------|
| **Unauthenticated Data Harvesting** | Public Experience Cloud site with Aura/GraphQL endpoints | §3 + §4 + §1 |
| **Authenticated Privilege Escalation** | Low-privilege user with access to custom controllers or Flows | §1 + §7 + §9 |
| **Large-Scale Data Exfiltration** | Compromised OAuth token or service account | §5 + §8 + §11 |
| **Account Takeover & Persistent Backdoor** | Social engineering + OAuth device flow | §5 + §9 |
| **Phishing & Brand Impersonation** | Access to Email-to-Case or Marketing Cloud | §12 |
| **Supply Chain Compromise** | Vulnerable managed package or compromised ISV | §11 + §1 + §7 |
| **AI-Driven Data Exfiltration** | Agentforce with Web-to-Lead enabled | §10 + §1 |
| **Insider Threat / Stealth Exfiltration** | Legitimate user with API access | §8 + §9 |
| **OmniStudio Industry Cloud Exploitation** | Salesforce Industry Cloud with OmniStudio components | §1-2 + §4-1 + §7-3 |

---

## §14. CVE / Incident Mapping (2023–2025)

| Mutation Combination | CVE / Incident | Impact |
|---------------------|---------------|--------|
| §1-2 (FLS bypass via SOQL data source) | CVE-2025-43698 | All FlexCard deployments exposed full field data regardless of FLS |
| §1-2 (Encrypted field plaintext leak) | CVE-2025-43697 | Data Mappers returned plaintext for Classic Encrypted fields |
| §1-3 + §6-3 (Client-side permission bypass) | CVE-2025-43699 | FlexCard "Required Permission" check performed only client-side |
| §1-2 (Encrypted field exposure) | CVE-2025-43700 | OmniStudio exposed encrypted data to unauthorized users |
| §4-1 (Guest user Custom Settings access) | CVE-2025-43701 | Guest users could read Custom Settings via FlexCard SOQL |
| §2-1 (Standard controller SOQL injection 0-day) | Disclosed 2025, no CVE | Built-in `CsvDataImportResourceFamilyController` allowed blind SOQL injection in all Salesforce orgs |
| §8-2 (Public link SOQL injection) | Patched Feb 2024, no CVE | Blind SOQL injection through public link Aura endpoints enabled PII extraction |
| §5-1 (Third-party token compromise) | UNC6395 / 2025 | 700+ organizations compromised via Salesloft/Drift OAuth token breach |
| §5-1 + §8-1 (OAuth abuse + bulk exfil) | UNC6040 / 2025 | Google Ads Salesforce instance: 2.55M records exfiltrated via stolen OAuth tokens |
| §10-1 (ForcedLeak prompt injection) | CVSS 9.4 / Patched Sept 2025 | Agentforce indirect prompt injection via Web-to-Lead with CSP bypass |
| §12-1 (PhishForce email exploitation) | Disclosed Aug 2023 | Salesforce Email-to-Case exploited for phishing campaign targeting Facebook users |
| §4-1 + §3-1 (Community guest user exposure) | Multiple 2023-2025 incidents | Government agencies, healthcare orgs exposed SSNs, health records via misconfigured communities |

---

## §15. Detection & Security Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **AuraInspector** (Mandiant) | Offensive / Audit | Aura endpoint misconfiguration | Automated discovery of accessible Aura endpoints, objects, GraphQL introspection, self-registration detection |
| **Salesforce CLI Scanner** | Defensive / SAST | Apex, Visualforce, LWC | Static analysis for SOQL injection, CRUD/FLS violations, hardcoded secrets |
| **Checkmarx Apex Scanner** | Defensive / SAST | Apex code | Deep scan for injection, authentication, data leak patterns |
| **DigitSec** | Defensive / DAST+SAST | Full Salesforce stack | Automated SAST, DAST, SCA for Salesforce environments |
| **CodeScan** (AutoRABIT) | Defensive / SAST | Apex, VF, LWC, metadata | Static analysis with Salesforce-specific rules for coding standards and security |
| **AppOmni** | Defensive / SSPM | SaaS configuration | Continuous SaaS posture monitoring, misconfiguration detection, threat detection |
| **SalesForce-Exploit** (xOryus) | Offensive / PoC | Aura endpoints | PoC tool for dumping object data via vulnerable Aura endpoints with guest access |
| **Salesforce Health Check** | Defensive / Config | Org security settings | Built-in analysis of security settings against Salesforce baseline |
| **Salesforce Shield** | Defensive / Monitoring | Event monitoring, encryption | Real-time event monitoring, threat detection, field audit trail, platform encryption |
| **Burp Suite + Aura extensions** | Offensive / DAST | Aura API surface | Manual and semi-automated testing of Aura endpoint access controls |
| **PaaS Cloud Goat** | Training / Lab | Salesforce attack simulation | Vulnerable Salesforce app for hands-on security training (DEF CON 32 workshop tool) |
| **Obsidian Security** | Defensive / SSPM | SaaS misconfiguration | Continuous monitoring for Salesforce misconfigurations and data exposure |
| **Varonis DatAdvantage** | Defensive / DLP | Salesforce data access | Data exposure detection, permission analysis, public link monitoring |

---

## §16. Summary: Core Principles

### The Root Cause: Inverted Security Enforcement

The fundamental architectural property that drives the entire Salesforce attack surface is **inverted security enforcement**: unlike traditional platforms where the security model restricts by default and developers explicitly grant access, Salesforce Apex operates in system mode by default, bypassing CRUD, FLS, and sharing. Security is an opt-in concern that developers must explicitly implement for every controller, trigger, and service class. This creates an asymmetry where insecure code is shorter and simpler than secure code, incentivizing the very patterns that create vulnerabilities.

This inversion manifests at every layer: Flows running in system context bypass sharing, `@AuraEnabled` methods default to system mode, Batch Apex inherits elevated privileges, and OmniStudio components were discovered to silently ignore FLS entirely (CVE-2025-43698). The platform's own low-code tooling repeatedly introduces bypasses that mirror the same structural flaw.

### Why Incremental Fixes Fail

Salesforce cannot simply change Apex to run in user mode by default — doing so would break millions of deployed applications. Instead, the platform has introduced incremental opt-in mechanisms: `WITH SECURITY_ENFORCED` for SOQL (2019), `WITH USER_MODE` for SOQL (2022), `Security.stripInaccessible()` for DML (2019), and `with sharing` class declarations. Each mechanism covers a different attack surface fragment, creating a patchwork where developers must independently discover, understand, and implement each one. The OmniStudio CVEs of 2025 demonstrate that even Salesforce's own product teams fail to consistently enforce these controls.

The OAuth/Connected App attack surface compounds this: every third-party integration extends the trust boundary, and a single compromised integration (Salesloft/Drift, 2025) can cascade to hundreds of customer orgs. The platform's trust model assumes integrations are benign until revoked, creating persistent access that survives password changes and MFA enforcement.

### The Structural Solution

Addressing the Salesforce attack surface requires three structural shifts:

1. **Default-secure execution**: Apex should run in user mode by default, with explicit `system mode` elevation requiring security review justification — similar to how `without sharing` should require justification rather than being the implicit default.

2. **Zero-trust integration model**: Connected Apps should enforce continuous authorization validation, automatic token rotation, anomaly-based scope restriction, and mandatory minimum privilege reviews — rather than granting persistent, MFA-exempt access.

3. **Configuration-as-code security testing**: Guest User profiles, Experience Cloud sharing settings, Flow execution contexts, and OmniStudio security flags should be testable through automated pipelines with security assertions, rather than relying on manual administrator review of hundreds of interdependent settings.

Until these structural shifts occur, the Salesforce ecosystem will continue to produce the same categories of vulnerabilities — each round affecting new components (OmniStudio in 2025, Agentforce in 2025) while the root cause remains unchanged.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

### CVE Databases & Advisories
- Salesforce Security Advisories — https://security.salesforce.com/security-advisories
- CVE Details: Salesforce — https://www.cvedetails.com/vendor/17066/Salesforce.html

### Research & Vulnerability Analysis
- AppOmni — Salesforce Industry Clouds: 0-days and Exploitable Misconfigs (2025) — https://appomni.com/ao-labs/salesforce-industry-clouds-security-report-omnistudio-cves/
- Mandiant / Google Cloud — AuraInspector: Auditing Salesforce Aura for Data Exposure — https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure
- Varonis — Abusing Misconfigured Salesforce Experiences for Recon and Data Theft — https://www.varonis.com/blog/abusing-salesforce-communities
- Varonis — Data Theft in Salesforce: Manipulating Public Links — https://www.varonis.com/blog/manipulating-salesforce-public-links
- mastersplinter.work — Finding an SOQL Injection 0-Day in Salesforce (2025) — https://mastersplinter.work/research/salesforce-sqli/
- Noma Security — ForcedLeak: AI Agent Risks Exposed in Salesforce AgentForce (2025) — https://noma.security/blog/forcedleak-agent-risks-exposed-in-salesforce-agentforce/
- Enumerated.ie — Salesforce Lightning Exploitation Vectors — https://www.enumerated.ie/index/salesforce
- Intigriti — Hacking Salesforce Lightning: A Guide for Bug Hunters — https://www.intigriti.com/researchers/blog/hacking-tools/hacking-salesforce-lightning-guide-for-bug-hunters
- 0xbro — Pentesting Salesforce Communities — https://0xbro.red/writeups/web-hacking/salesforce-hacking/
- Guard.io — PhishForce: Vulnerability Uncovered in Salesforce's Email Services — https://labs.guard.io/phishforce-vulnerability-uncovered-in-salesforces-email-services-exploited-for-phishing-32024ad4b5fa

### Threat Intelligence
- Google Cloud / Mandiant — Widespread Data Theft Targets Salesforce Instances via Salesloft Drift (UNC6395) — https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift
- Google Cloud — The Cost of a Call: From Voice Phishing to Data Extortion — https://cloud.google.com/blog/topics/threat-intelligence/voice-phishing-data-extortion
- Palo Alto Unit 42 — Threat Brief: Salesloft Drift Integration Compromise — https://unit42.paloaltonetworks.com/threat-brief-compromised-salesforce-instances/
- Mitiga — Salesforce Data Loader Exfiltration Attack Explained — https://www.mitiga.io/blog/how-threat-actors-used-salesforce-data-loader-for-covert-api-exfiltration

### Salesforce Official Security Documentation
- Salesforce Secure Coding Guide — https://developer.salesforce.com/docs/atlas.en-us.secure_coding_guide.meta/secure_coding_guide/
- Salesforce Lightning Security — https://developer.salesforce.com/docs/atlas.en-us.secure_coding_guide.meta/secure_coding_guide/secure_coding_lightning_security.htm
- Salesforce Top 20 AppExchange Vulnerabilities — https://developer.salesforce.com/blogs/2023/08/the-top-20-vulnerabilities-found-in-the-appexchange-security-review
- Salesforce Trailhead: Secure Server-Side Development — https://trailhead.salesforce.com/content/learn/modules/secure-serverside-development/
- Salesforce SOQL Injection Prevention — https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/pages_security_tips_soql_injection.htm
- Spinning Code — Salesforce ID Iteration Attacks — https://spinningcode.org/2025/04/salesforce-id-iteration-attacks/

### Industry Analysis
- Salesforce Ben — Why Salesforce Orgs Got Hacked So Much in 2025 — https://www.salesforceben.com/why-salesforce-orgs-got-hacked-so-much-in-2025-and-how-to-avoid-this-in-2026/
- AppOmni — How to Avoid Salesforce Security Vulnerabilities in Custom Lightning Components — https://appomni.com/resources/aolabs/how-to-avoid-introducing-salesforce-security-vulnerabilities-when-building-custom-lightning-components-in-apex/
- Blueinfy — Understanding CRUD/FLS and Sharing Violation Vulnerabilities — https://blog.blueinfy.com/2024/11/understanding-crudfls-and-sharing.html
- Obsidian Security — Salesforce Misconfigurations are Exposing Sensitive Data — https://www.obsidiansecurity.com/blog/salesforce-misconfigurations-expose-sensitive-data
