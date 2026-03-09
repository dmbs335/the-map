# Adobe Experience Manager (AEM) Vulnerability Mutation Taxonomy

---

## Classification Structure

Adobe Experience Manager is a Java-based enterprise CMS built on a layered architecture: **Apache Sling** (request routing) → **JCR** (Java Content Repository for storage) → **OSGi** (modular runtime) → **Dispatcher** (Apache-based caching/security proxy). Each layer introduces distinct attack surfaces, and the *differential interpretation* between layers — particularly between the Dispatcher proxy and the Sling resolution engine — is the root cause of the most impactful AEM-specific vulnerability class.

This taxonomy organizes AEM vulnerabilities by **what architectural component is targeted** (Axis 1), cross-referenced with **what type of security bypass or discrepancy is exploited** (Axis 2), and mapped to **real-world attack scenarios** (Axis 3).

### Axis 2: Bypass/Discrepancy Types (Cross-cutting)

| Type | Description |
|------|-------------|
| **URL Parsing Differential** | Dispatcher and Sling interpret the same URL differently, allowing filter bypass |
| **Extension/Selector Confusion** | Sling's flexible URL decomposition (path.selectors.extension/suffix) creates ambiguity |
| **Missing/Weak Authentication** | Endpoints accessible without credentials or with trivially bypassable auth |
| **Default Credentials** | Factory-shipped username/password pairs left unchanged |
| **Misconfiguration** | Secure-by-default features disabled or debug modes left enabled in production |
| **Input Validation Failure** | User-controlled data flows into security-sensitive operations unsanitized |
| **Allowlist/Denylist Bypass** | Filter rules circumvented through encoding, path manipulation, or semantic tricks |
| **Deserialization Weakness** | Untrusted serialized data processed by vulnerable object input streams |

### Fundamental Mechanism: The Dispatcher–Sling URL Resolution Gap

AEM's Dispatcher decomposes URLs into discrete filter particles: `path`, `extension`, `selectors`, `suffix`, `query`. Sling, upon receiving a request that passes the Dispatcher, performs its own decomposition — and the two systems do not always agree. Key differences:

1. **Suffix interpretation**: Dispatcher considers the suffix as the part after the first `/` following the first `.`. Sling treats it differently based on JCR node resolution.
2. **Extension fallback**: When Sling cannot find a content node matching the full URL, it discards trailing extensions and resolves to the longest matching node path.
3. **Selector transparency**: Selectors (`.infinity`, `.tidy`, `.childrenlist`) modify Sling's rendering behavior but may not be filtered by Dispatcher rules.
4. **Path parameter injection**: Semicolon-delimited path parameters (`;x=y`) are visible to Sling but may be ignored by Dispatcher filter patterns.

This structural gap enables the majority of AEM-specific bypass techniques documented below.

---

## §1. Dispatcher/Proxy Filter Bypass

The AEM Dispatcher is the primary perimeter defense, filtering inbound requests via allow/deny rules before they reach the AEM publish instance. Bypassing the Dispatcher grants direct access to AEM's internal servlets and JCR content. This is the most critical and AEM-specific vulnerability category.

### §1-1. Extension Append Bypass

When Dispatcher rules block specific paths (e.g., `/bin/querybuilder.json`), appending an "allowed" extension after the blocked path can cause the Dispatcher to evaluate the request against the appended extension while Sling resolves to the original resource.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Suffix extension injection** | Append an allowed extension as a suffix after the blocked path; Dispatcher sees `.css`, Sling resolves to the JSON servlet | `/bin/querybuilder.json/a.css` |
| **Dot-extension append** | Add a second extension that matches allowed patterns | `/bin/querybuilder.json.css` |
| **Path-as-suffix with extension** | Use a path segment after the blocked resource with an allowed extension | `/bin/querybuilder.json/a.html` |
| **Icon/image extension** | Exploit common Dispatcher allowlist for static assets | `/bin/querybuilder.json/a.ico`, `/bin/querybuilder.json/a.png` |

**Key Condition**: Sling's extension fallback behavior — when the appended path/extension does not correspond to an actual JCR node, Sling discards it and resolves to the longest matching path (e.g., `/bin/querybuilder`).

### §1-2. Path Obfuscation Bypass

Manipulating the URL path structure to evade Dispatcher's pattern-matching regex while preserving Sling's ability to resolve the target resource.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Triple-slash obfuscation** | Multiple leading slashes bypass simple path-prefix rules | `///bin///querybuilder.json` |
| **Semicolon path parameter** | Path parameters (matrix parameters) are parsed by Sling but may be invisible to Dispatcher filters | `/bin/querybuilder.json;x='x/graphql/execute/json/x'` |
| **URL-encoded characters** | Character encoding of path separators or special characters confuses pattern matching | `/bin/querybuilder.json;%0aa.css` |
| **Null byte injection (legacy)** | On older systems, null bytes truncate the path at different points in Dispatcher vs Sling | `/bin/querybuilder.json%00.css` |
| **ASCII encoding bypass** | Specific ASCII code substitution for characters in deny rules | Encoding `}` and other special characters in filter-matched paths |

### §1-3. Selector and Suffix Manipulation

Exploiting Sling's URL decomposition model where `path.selectors.extension/suffix` components modify rendering behavior.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Depth selector injection** | Selectors like `.infinity`, `.tidy`, or numeric depth selectors (`.1`, `.3`, `.400`) modify DefaultGetServlet output depth | `/content.infinity.json`, `/content.children.400.json` |
| **Servlet selector registration** | Using `.servlet` as a selector to match servlets registered by resource type | `/bin/querybuilder.feed.servlet` |
| **Suffix content-type override** | The suffix component can influence the response Content-Type, potentially enabling XSS | Adding `.html` suffix changes Content-Type to `text/html` |
| **Query parameter confusion** | Query strings may be interpreted differently by Dispatcher and Sling | `/bin/querybuilder.json?a.html` |

### §1-4. Decomposed Filter vs URL Pattern Filter

Dispatcher filter rules can match against decomposed URL particles (`/path`, `/extension`, `/selectors`, `/suffix`) or against the full `/url` pattern. Decomposed rules create wider bypass opportunities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Particle mismatch** | Decomposed filter matches path but ignores suffix that carries the actual exploit | Dispatcher uses `/extension` rules instead of `/url` patterns |
| **Wildcard over-allowance** | Overly permissive glob patterns in `/path` rules allow unintended paths through | Rules like `/url "*.css"` instead of `/extension 'css'` |
| **Order-dependent bypass** | Allow rules evaluated before deny rules create bypass windows | Misconfigured filter ordering |

**Mitigation**: Adobe recommends using `/url` patterns instead of decomposed particles wherever URL interpretation ambiguities cannot be prevented.

---

## §2. JCR Content Repository Exposure

The Java Content Repository (JCR) is AEM's underlying storage layer. When accessible, it exposes the entire content tree including user data, configuration, credentials, and internal structure.

### §2-1. DefaultGetServlet Abuse

AEM's DefaultGetServlet renders JCR nodes in multiple formats (JSON, XML) with configurable traversal depth. When exposed, it enables systematic repository enumeration.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Root node JSON dump** | Requesting the root path with JSON extension exposes the top-level JCR structure | `/.json`, `/.1.json`, `/.ext.json` |
| **Depth-controlled traversal** | Numeric selectors control how many levels deep the JSON output includes | `/content.3.json`, `/etc.-1.json` (unlimited depth) |
| **Children enumeration** | Special selectors enumerate child nodes at configurable depth | `/.childrenlist.json`, `/content.children.400.json` |
| **Tidy output** | The `.tidy` selector produces pretty-printed JSON, easing automated parsing | `/content.tidy.3.json` |
| **Infinity selector** | The `.infinity` selector returns the entire subtree — also a DoS vector | `/content.infinity.json` |
| **Resource binary retrieval** | The `.res` format returns the raw binary content of a JCR node's `jcr:data` property, enabling direct file download | `/content/dam/secret.pdf/jcr:content/renditions/original/jcr:content.res` |

**Sensitive JCR Paths**:
- `/etc` — may contain passwords, API keys, encryption keys
- `/apps/system/config` or `/apps/<name>/config` — service credentials
- `/home` — user profiles, password hashes, PII
- `/var` — workflow data, replication queues, private information
- `/content/dam` — uploaded assets, potentially sensitive documents

### §2-2. Username and Credential Harvesting

AEM stores system metadata as JCR node properties. Several property naming conventions reliably contain usernames.

| Subtype | Mechanism | Key Properties |
|---------|-----------|---------------|
| **"*By" property enumeration** | Properties ending with "By" contain usernames of content authors/modifiers | `jcr:createdBy`, `jcr:lastModifiedBy`, `cq:LastModifiedBy` |
| **Home path traversal** | The `/home/users` and `/home/groups` subtrees expose user profiles and group memberships | `/home/users.tidy.3.json` |
| **Password hash extraction** | User nodes may contain `rep:password` properties with hashed passwords | QueryBuilder search for `path=/home&p.hits=full` |
| **Plaintext credential discovery** | Configuration nodes sometimes store service account passwords in plaintext | `/apps/system/config.json`, `/etc/replication/agents.author.json` |

### §2-3. QueryBuilder Servlet Data Extraction

AEM's QueryBuilder provides a SQL-like interface to search JCR content. When exposed, it enables targeted extraction of any repository data.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **User enumeration via QueryBuilder** | Query the /home path for all user nodes | `path=/home&p.hits=full&p.limit=-1` |
| **File discovery** | Search for uploaded files across the repository | `type=nt:file&nodename=*.zip` |
| **Write permission check** | Determine which paths are writable by the current user; also accepts `jcr:addChildNodes` and `jcr:modifyProperties` for granular permission probing | `hasPermission=jcr:write&path=/content` |
| **PII harvesting** | Search for form submissions containing personal data | `path=/content/usergenerated&type=nt:unstructured` |
| **Feed servlet variant** | Alternative endpoint that returns results in Atom/RSS format | `/bin/querybuilder.feed.servlet` |

**QueryBuilder Bypass Paths**: `/bin/querybuilder.json/a.css`, `/bin/querybuilder.json;%0aa.css`, `/bin/querybuilder.feed.ico`

### §2-4. GQL Search Servlet

An alternative search interface using Graph Query Language syntax, often forgotten in Dispatcher deny rules.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Unrestricted GQL search** | GQL servlet accepts free-form queries against the entire JCR | `/bin/wcm/search/gql.servlet.json?query=type:base` |
| **DoS via unlimited results** | Removing result limits causes the server to attempt serializing the entire repository | `query=type:base%20limit:..-1` |

### §2-5. WebDAV Repository Access

AEM can expose the JCR over the WebDAV protocol, providing an alternative access path to repository content.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WebDAV traversal** | Standard WebDAV methods (PROPFIND, GET) enumerate and retrieve JCR nodes | WebDAV enabled and accessible through Dispatcher |
| **XXE via WebDAV** | WebDAV XML request parsing vulnerable to XXE injection (CVE-2015-1833) | Unpatched Apache Jackrabbit WebDAV implementation |
| **Stored XSS via WebDAV** | Upload HTML/SVG content to JCR nodes accessible via web | Write access to DAM or content nodes |

---

## §3. Exposed Built-in Servlets

AEM ships with dozens of built-in Sling servlets and CQ components. Many provide powerful functionality intended only for development or internal use. When accessible in production — either through misconfiguration or Dispatcher bypass — they become direct attack vectors.

### §3-1. Information Disclosure Servlets

| Subtype | Servlet / Endpoint | Information Exposed |
|---------|-------------------|-------------------|
| **Login status enumeration** | `LoginStatusServlet` (`/system/sling/loginstatus`) | Authentication state, current user identity |
| **Current user disclosure** | `CurrentUserServlet` | Authenticated user details |
| **User info servlet** | `UserInfoServlet` | User profile data |
| **Reporting services** | `ReportingServicesServlet` | Internal reporting data; also SSRF vector (§5-3) |
| **WCM suggestions** | `WCMSuggestionsServlet` | Reflected XSS vector (§7-1) |
| **Merge metadata** | `MergeMetadataServlet` | Reflected XSS; metadata about DAM assets |
| **Audit log exposure** | `AuditLogServlet` | Audit trail records containing user actions, timestamps, and internal operation details |

### §3-2. Content Manipulation Servlets

| Subtype | Servlet / Endpoint | Capability |
|---------|-------------------|-----------|
| **SlingPostServlet (POSTServlet)** | Default POST handler for all Sling resources | Create, modify, delete JCR nodes — enables stored XSS (§7-2) and content injection |
| **SlingPostServlet :applyTo enumeration** | Failed `:applyTo` operations expose filesystem paths (CVE-2016-0956) | Internal path structure disclosure via error messages |
| **GuideInternalSubmitServlet** | AEM Forms internal submission handler | XXE injection (CVE-2019-8086) |

### §3-3. Authentication Probing Servlets

These servlets enable credential brute-forcing when accessible.

| Subtype | Servlet | Attack Method |
|---------|---------|--------------|
| **LoginStatusServlet brute force** | `/system/sling/loginstatus` | POST with `j_username` and `j_password` parameters; response differentiates valid/invalid credentials |
| **GetLoggedInUser brute force** | Various auth-check endpoints | Response content varies based on authentication success |
| **CurrentUserServlet enumeration** | `/libs/granite/security/currentuser.json` | Leaks current session's user identity |

---

## §4. Administrative Console Exposure

AEM bundles several powerful administrative interfaces. Their exposure in production environments — directly or through Dispatcher bypass — frequently leads to complete system compromise.

### §4-1. OSGi Felix Console

The Apache Felix Web Management Console provides full control over AEM's OSGi runtime.

| Subtype | Mechanism | Impact |
|---------|-----------|--------|
| **Default credentials access** | OSGi console accessible at `/system/console` with default or weak credentials | Full OSGi runtime control |
| **Bundle upload RCE** | Upload a malicious OSGi bundle containing arbitrary code | Remote code execution via custom bundle activation |
| **Configuration manipulation** | Modify OSGi service configurations to disable security features | Privilege escalation, security bypass |
| **Component disable/enable** | Toggle security-critical components (auth handlers, filters) on/off | Authentication bypass |

**Default credentials**: `admin:admin` is the most common; also `author:author`, `replication-receiver:replication-receiver`

### §4-2. CRXDE Lite and CRX Package Manager

Content Repository Extreme Development Environment — a web-based IDE with full JCR access.

| Subtype | Mechanism | Impact |
|---------|-----------|--------|
| **CRXDE Lite exposure** | Web IDE accessible at `/crx/de/index.jsp` | Full read/write access to entire JCR repository |
| **CRX Package Manager** | Package management at `/crx/packmgr/index.jsp` | Install arbitrary CRX packages containing code/content |
| **Package Manager auth bypass** | Default security controls removed from `/etc/packages` path | Unauthenticated access to package operations |
| **Package download** | Download existing packages containing application source code | Source code disclosure, credential extraction |

### §4-3. Groovy Console

AEM's Groovy Console allows execution of arbitrary Groovy scripts with full system access.

| Subtype | Mechanism | Impact |
|---------|-----------|--------|
| **Direct script execution** | POST to `/bin/groovyconsole/post.servlet` with arbitrary Groovy code | Remote code execution |
| **JCR manipulation** | Groovy scripts can read/write any JCR node | Complete data access and modification |
| **OSGi service invocation** | Scripts can call any registered OSGi service | Unrestricted system-level operations |

**Example payload**: `def proc = "cat /etc/passwd".execute(); println proc.text`

### §4-4. ACS AEM Tools

Adobe Consulting Services (ACS) tools for AEM provide development utilities that enable code execution.

| Subtype | Mechanism | Impact |
|---------|-----------|--------|
| **Fiddle (JSP execution)** | Execute arbitrary JSP code via the ACS Fiddle interface | Remote code execution |
| **Query editor** | Execute JCR queries with full repository access | Unrestricted data extraction |

---

## §5. Server-Side Request Forgery (SSRF)

Multiple AEM servlets accept URL parameters and make server-side HTTP requests, enabling SSRF attacks. These are particularly valuable as Dispatcher bypass alternatives — instead of bypassing the Dispatcher externally, the attacker leverages an allowed endpoint to make requests internally.

### §5-1. OpenSocial / Shindig Proxy

AEM includes the Apache Shindig OpenSocial container, which provides a proxy endpoint for making HTTP requests.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Shindig proxy GET** | Proxy endpoint forwards GET requests to arbitrary URLs and returns responses | `/libs/opensocial/proxy?container=default&url=http://target` |
| **Shindig makeRequest** | Alternative endpoint with the same SSRF capability | `/libs/shindig/proxy?container=default&url=http://target` |
| **Secret exfiltration** | Use SSRF to read internal AEM endpoints that are blocked by Dispatcher | Proxy to `http://localhost:4502/etc.json` |
| **XSS via proxy response** | Proxy returns the target's response with controllable Content-Type | Proxy to attacker-controlled HTML page |

### §5-2. SitecatalystServlet and AutoprovisioningServlet

Internal servlets with SSRF capabilities that can be chained to achieve RCE.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **SitecatalystServlet SSRF** | Accepts a URL parameter and makes blind server-side POST requests; supports CRLF/LF injection in parameters, enabling arbitrary HTTP header control and HTTP request smuggling | Accessible through Dispatcher bypass; smuggling tested on Jetty |
| **AutoprovisioningServlet SSRF** | Similar blind POST SSRF capability through provisioning functionality; also supports CRLF/LF header injection for HTTP smuggling | AEM versions before AEM-6.2-SP1-CFP7 on Jetty |
| **SSRF-to-RCE chain** | SSRF with CRLF header injection used to smuggle a PUT request to `TopologyConnectorServlet` on localhost, joining a fake AEM topology and triggering reverse replication for code execution | Requires crafted external AEM server (via `aem_ssrf2rce.py`) |

### §5-3. Reporting and Analytics Servlets

| Subtype | Mechanism | CVE |
|---------|-----------|-----|
| **ReportingServicesServlet SSRF** | Content Insight proxy forwards requests to arbitrary URLs; domain validation bypassable via URL-encoded fragment (`%23`) — e.g., `url=http://169.254.169.254%23/api1.omniture.com/a` causes validation to see the whitelisted domain while the request targets the attacker-specified host | CVE-2018-12809 |
| **SalesforceSecretServlet SSRF** | Salesforce integration servlet makes POST requests to attacker-controlled URLs; same `%23` fragment bypass applies to domain validation | CVE-2018-5006 |

### §5-4. SSRF as Dispatcher Bypass

A meta-technique: rather than bypassing the Dispatcher directly, use any accessible SSRF endpoint to reach blocked internal endpoints.

| Subtype | Mechanism | Impact |
|---------|-----------|--------|
| **Internal endpoint access** | SSRF to `localhost:4502` reaches the AEM publish instance directly, bypassing all Dispatcher rules | Full access to any internal servlet |
| **Cloud metadata access** | SSRF to cloud metadata endpoints (e.g., `169.254.169.254`) on cloud-hosted AEM instances | Cloud credential theft |
| **Internal network scanning** | SSRF to internal IP ranges for service discovery | Network reconnaissance |

---

## §6. Authentication and Authorization Flaws

### §6-1. Default and Weak Credentials

AEM ships with well-known default credentials across multiple interfaces.

| Subtype | Interface | Default Credentials |
|---------|----------|-------------------|
| **AEM admin account** | Author/Publish instances at `/libs/granite/core/content/login.html` | `admin:admin` |
| **Author account** | Author instance | `author:author` |
| **OSGi console** | `/system/console` | `admin:admin` |
| **Replication receiver** | Replication agent endpoints | `replication-receiver:replication-receiver` |

### §6-2. Authentication Bypass Techniques

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **URL substring filter bypass** | Security filters that check for substrings (e.g., `"login."`) in the URL can be satisfied by inserting that substring into any URL path component | CVE-2025-54253: adding `login.` to URL bypasses auth filter |
| **Dispatcher anonymous access** | Dispatcher rules allow certain paths without authentication; combined with §1 bypasses, sensitive paths become accessible | Misconfigured `/filter` rules |
| **Package Manager path override** | Removing default CRX security controls from `/etc/packages` allows unauthenticated package operations | Manual security configuration removal |
| **Sling servlet resource type bypass** | Servlets registered by `sling.servlet.resourceTypes` can be accessed through unexpected paths, bypassing path-based auth checks | Servlet registered on a resource type accessible via multiple paths |

### §6-3. Credential Brute Force Vectors

| Subtype | Endpoint | Method |
|---------|---------|--------|
| **LoginStatusServlet** | `/system/sling/loginstatus` | POST with `j_username`/`j_password` |
| **GET-based auth check** | Various login-status endpoints | Response differentiation on valid vs invalid credentials |
| **Replication agent auth** | Replication receiver endpoints | Agent-level authentication brute force |

---

## §7. Cross-Site Scripting (XSS)

AEM has been affected by a massive volume of XSS vulnerabilities — 225 of 254 flaws patched in a single 2025 security bulletin were classified as XSS. The attack surface is amplified by Sling's content-driven rendering model and JCR's ability to store arbitrary content.

### §7-1. Reflected XSS

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **WCMSuggestionsServlet XSS** | User input reflected in servlet response without encoding | Inject script in query parameter |
| **MergeMetadataServlet XSS** | DAM metadata merge endpoint reflects input unsanitized | Script injection in metadata parameters |
| **WCMDebugFilter XSS** | Debug filter reflects URL components (CVE-2016-7882) | Script injection in URL path/parameters |
| **Selector/suffix reflection** | Sling URL components (selectors, suffix) reflected in rendered pages | Script in selector position of URL |
| **SWF-based XSS** | Flash files in AEM (SWF) act as XSS vectors when serving user-controlled parameters | Legacy SWF files under `/etc/clientlibs` |
| **SetPreferences page XSS** | User preferences page reflects input parameters without encoding | Script injection via preference values |

### §7-2. Stored XSS via Content Injection

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **POSTServlet node creation** | SlingPostServlet creates JCR nodes with attacker-controlled content; when rendered, the content executes as script | POST to `/content/usergenerated/...` with `jcr:data` containing script and `jcr:mimeType=text/html` |
| **DAM asset upload** | Upload SVG or HTML files to DAM that contain embedded scripts | Upload crafted SVG to `/content/dam/` |
| **WebDAV stored XSS** | Write HTML/SVG content to JCR via WebDAV protocol | PROPFIND + PUT on exposed WebDAV endpoints |
| **User-generated content** | Content written to `/content/usergenerated/` is rendered to other users | POST requests creating nodes under user-generated paths |

### §7-3. Cloud-Specific XSS (AEM Cloud Service)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **RUM proxy JavaScript injection** | AEM Cloud's Real User Monitoring loads JS from `/.rum/@adobe/helix-rum-js` via CDN proxy (JSDelivr/Unpkg). Bypassing the package name allowlist allows injecting arbitrary JavaScript | CVE-2025-47114, CVE-2025-47115 — affected ~45,000 AEM Cloud sites |
| **CDN allowlist bypass** | Validation mistakes in the reverse proxy layer allow substituting the legitimate NPM package with an attacker-controlled one | Three distinct bypasses found and patched in 2025 |

---

## §8. Remote Code Execution (RCE)

RCE is the highest-impact outcome in AEM exploitation. Multiple paths exist, often chained from lower-severity primitives.

### §8-1. OGNL Injection (Struts2 DevMode)

The most critical AEM RCE discovered to date, stemming from Apache Struts2 development mode left enabled in AEM Forms.

| Subtype | Mechanism | CVE |
|---------|-----------|-----|
| **Pre-auth OGNL RCE** | AEM Forms exposes `/adminui/debug` servlet that evaluates arbitrary OGNL expressions as Java code without authentication | CVE-2025-54253 (CVSS 10.0) |
| **Auth bypass + OGNL chain** | Weak security filter bypassed by inserting `login.` in URL, then OGNL injection for command execution | `/adminui/updateLicense1.do;login.?debug=command&expression=...` |
| **Struts2 devmode expression evaluation** | DevMode's debug interceptor evaluates user-supplied expressions | `/adminui/debug?debug=OGNL:` followed by expression |

**Impact**: Pre-authentication RCE. Actively exploited in the wild. (CISA KEV listing unverified as of 2026-03)

### §8-2. Groovy Console Script Execution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct Groovy RCE** | Execute system commands via Groovy's runtime exec | Groovy Console accessible (§4-3) |
| **Groovy JCR manipulation** | Modify JCR content to plant persistent backdoors | Script execution with JCR write access |

### §8-3. OSGi Bundle Upload

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Malicious bundle installation** | Upload and activate an OSGi bundle containing a webshell or reverse shell | Felix Console accessible (§4-1) |
| **Bundle activator exploit** | Code in `BundleActivator.start()` executes immediately upon installation | Bundle install permissions available |

### §8-4. JSP Webshell Upload

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JSP upload to /apps** | Upload a JSP file to the `/apps` JCR node via CRXDE, Package Manager, or SlingPostServlet | Write access to `/apps` node |
| **JSP execution** | Sling compiles and executes JSP files placed in the JCR | JSP file accessible via URL resolution |

### §8-5. Java Deserialization

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ExternalJobServlet deserialization** | The `file` parameter accepts a serialized Java object stream and passes it to `ObjectInputStream.readObject()` | Servlet at `/libs/dam/cloud/proxy` accessible; AEM 5.5/5.6 |
| **OSGi gadget chain complexity** | Exploitation is harder in OSGi environments due to classloader isolation, but not impossible | Specific gadget chains required for the AEM classloader hierarchy |
| **Untrusted data deserialization (Forms)** | AEM Forms deserialization vulnerability allowing arbitrary code execution | CVE-2025-49533 |

### §8-6. SSRF-to-RCE Chains

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Fake AEM topology join** | Use SSRF with CRLF injection (§5-2) to smuggle a PUT request to `TopologyConnectorServlet` on localhost (default: accessible only locally); the target AEM instance joins the attacker-controlled topology, automatically creating a reverse replication agent that replicates malicious nodes (e.g., JSP webshells) from the fake AEM server to the Publish instance | SSRF via SitecatalystServlet or AutoprovisioningServlet with CRLF header injection; AEM < 6.2-SP1-CFP7 on Jetty |
| **Internal service exploitation** | Use SSRF to reach internal management APIs (JMX, OSGi console) on localhost | Any SSRF vector + internal management ports accessible on localhost |

---

## §9. XML Processing Vulnerabilities

### §9-1. XML External Entity (XXE) Injection

| Subtype | Mechanism | CVE |
|---------|-----------|-----|
| **AEM Forms web services XXE** | XML External Entity reference in AEM Forms web service endpoints allows arbitrary file read | CVE-2025-54254 (CVSS 8.6) |
| **GuideInternalSubmitServlet XXE** | AEM Forms submission handler processes XML with external entity resolution enabled | CVE-2019-8086 |
| **WebDAV XXE** | Apache Jackrabbit WebDAV implementation processes XML requests with entity expansion | CVE-2015-1833 |
| **BlazeDS XXE** | BlazeDS AMF deserialization triggers XML parsing with external entity resolution | Legacy AEM Forms integrations |

### §9-2. DTD and Entity Expansion

| Subtype | Mechanism | Impact |
|---------|-----------|--------|
| **Billion laughs DoS** | Recursive entity expansion in XML parsers | Denial of service via memory exhaustion |
| **File exfiltration via OOB** | Out-of-band XXE using external DTD to exfiltrate file contents to attacker server | Arbitrary file read on the AEM server |

---

## §10. Denial of Service (DoS)

### §10-1. Repository Exhaustion

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Infinity JSON dump** | Request the entire JCR tree in JSON format | `/.ext.infinity.json?tidy=true` |
| **Unlimited QueryBuilder** | Remove result limits causing full repository serialization | `/bin/querybuilder.json?type=nt:base&p.limit=-1` |
| **Unlimited GQL search** | GQL query with no result limit | `/bin/wcm/search/gql.servlet.json?query=type:base%20limit:..-1` |
| **Asset search wildcard** | Asset search servlet with wildcard query triggers expensive repository scan | `/content.assetsearch.json?query=*&start=0&limit=10`, `/..assetsearch.json?query=*&start=0&limit=10` |

### §10-2. Background Service Abuse

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **BGServlets infinite loop** | Background servlet test endpoint with extreme iteration counts | `/system/bgservlets/test.json?cycles=999999&interval=0` |
| **Replication queue flooding** | Trigger mass replication operations consuming system resources | Bulk activation requests via replication agent |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Information Disclosure (PII, credentials)** | Any AEM instance with Dispatcher misconfiguration | §1 + §2 + §3-1 |
| **Pre-auth Remote Code Execution** | AEM Forms on JEE with default configuration | §6-2 + §8-1 |
| **Stored XSS → Account Takeover** | AEM author or publish with writable content paths | §3-2 + §7-2 |
| **Universal Cloud XSS** | AEM as a Cloud Service (AEMaaCS) | §7-3 |
| **SSRF → Internal Network Access** | Cloud-hosted AEM instances | §1 + §5 |
| **SSRF → RCE Chain** | AEM < 6.2-SP1-CFP7 on Jetty | §5-2 + §8-6 |
| **Full Repository Compromise** | AEM with exposed CRXDE/Package Manager | §4-2 |
| **Credential Harvesting + Brute Force** | AEM with exposed auth servlets | §2-2 + §3-3 + §6-3 |
| **Denial of Service** | Any exposed AEM instance | §2-1 + §10 |
| **XXE → Arbitrary File Read** | AEM Forms with XML processing endpoints | §9-1 |

---

## CVE / Bounty Mapping (2018–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §6-2 + §8-1 (Auth bypass + OGNL RCE) | CVE-2025-54253 (AEM Forms on JEE) | CVSS 10.0. Pre-auth RCE via Struts2 devmode. Actively exploited in the wild. (CISA KEV listing unverified as of 2026-03) |
| §9-1 (XXE in Forms web services) | CVE-2025-54254 (AEM Forms on JEE) | CVSS 8.6. Arbitrary file read via XXE. Zero-day disclosure. |
| §8-5 (Deserialization in Forms) | CVE-2025-49533 (AEM Forms on JEE) | Pre-auth RCE via untrusted data deserialization. |
| §7-3 (Cloud RUM proxy XSS) | CVE-2025-47114, CVE-2025-47115 (AEM Cloud) | Persistent XSS on ~45,000 AEM Cloud sites. Three distinct bypasses found. |
| §1 + §7-1 (Multiple Dispatcher bypass + XSS) | CVE-2025-54251, -54249, -54252, -54250, -54247, -54248, -54246 | Multiple critical/important dispatcher bypass and XSS flaws found by Searchlight Cyber. |
| §7-1 + §7-2 (225 XSS vulnerabilities) | APSB25-115 / AEM Cloud Release 2025.5 | 225 of 254 patched flaws were XSS. Affects AEM Cloud and all versions ≤ 6.5.22. |
| §5-3 (SSRF via ReportingServicesServlet) | CVE-2018-12809 | SSRF enabling secret exfiltration and XSS via reporting proxy. |
| §5-3 (SSRF via SalesforceSecretServlet) | CVE-2018-5006 | SSRF via Salesforce integration endpoint. |
| §3-2 (SlingPostServlet path disclosure) | CVE-2016-0956 | Internal filesystem path enumeration via `:applyTo` error messages. Affected nearly every public AEM instance. |
| §7-1 (WCMDebugFilter reflected XSS) | CVE-2016-7882 | Reflected XSS via debug filter. |
| §1 (Dispatcher bypass — original) | CVE-2016-0957 | Classic Dispatcher bypass still found in modern deployments. |
| §9-1 (WebDAV XXE) | CVE-2015-1833 (Apache Jackrabbit) | XXE via WebDAV XML processing. |
| §9-1 (GuideInternalSubmitServlet XXE) | CVE-2019-8086 | XXE in AEM Forms submission handler. |
| §2 + §3 (JCR exposure via Dispatcher bypass) | U.S. DoD HackerOne #1939272 | AEM misconfiguration exposing JCR content on U.S. Department of Defense infrastructure. |

---

## Detection Tools

### Offensive / Reconnaissance

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **aem-hacker** (0ang3el) | Comprehensive AEM security testing | Suite of Python scripts: `aem_hacker.py` (vuln detection), `aem_discoverer.py` (AEM fingerprinting), `aem_enum.py` (username/secret enumeration), `aem_ssrf2rce.py` (SSRF to RCE chain) |
| **hopgoblin** (Assetnote/Searchlight) | AEM instance scanning | Automated checks for common AEM misconfigurations and Dispatcher bypasses |
| **Burp AEM Scanner** (thomashartm) | Burp Suite extension for AEM | Fingerprinting and active scanning for AEM misconfigurations and vulnerabilities |
| **Nuclei AEM templates** | AEM vulnerability detection | YAML-based templates for automated scanning of known AEM CVEs and misconfigurations |

### AEM Instance Fingerprinting Patterns

Confirming that a target runs AEM before launching specific checks. These URLs produce distinctive responses (JSON node dumps, servlet status pages) that are unique to AEM's Sling/JCR stack. Each path should be tested with standard Dispatcher bypass suffixes (`/a.css`, `/a.html`, `/a.ico`, `/a.png`, `;%0aa.css`).

| Probe Category | Paths |
|---------------|-------|
| **JCR node dump** | `/.json`, `/.1.json`, `/.ext.json`, `/.childrenlist.json`, `/.4.2.1...json` |
| **Servlet status** | `/system/sling/loginstatus`, `/system/bgservlets/test.json` |
| **Content paths** | `/content.json`, `/content.1.json`, `/bin.json` |

### Defensive / Hardening

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **AEM Dispatcher Optimizer Tool** (Adobe) | Dispatcher configuration analysis | Rule analysis to identify overly permissive or misconfigured filter rules |
| **Adobe Security Checklist** | AEM deployment hardening | Comprehensive checklist covering credentials, OSGi, Dispatcher, CRX, and access control configuration |
| **Acunetix AEM checks** | Automated web scanner | Detects AEM misconfigurations including OSGi console exposure, information disclosure |
| **Tenable WAS AEM plugin** | AEM Dispatcher bypass detection | Automated testing for known Dispatcher bypass patterns |

---

## Summary: Core Principles

### Why AEM Is Uniquely Vulnerable

The fundamental property that makes AEM's attack surface so rich is its **multi-layer URL interpretation pipeline**. An HTTP request passes through at least three interpretation stages — the Dispatcher (Apache-based), the Sling servlet resolution engine, and the JCR content resolution — and each stage has its own URL parsing semantics. This creates a combinatorial explosion of potential mismatches: what the Dispatcher blocks, Sling may resolve; what Sling renders, the JCR may expose. Unlike simpler web frameworks where routing is defined by the application, AEM's content-driven architecture means *every JCR node is potentially URL-addressable*, and the Dispatcher must explicitly deny access to everything that should not be public.

### Why Incremental Patches Fail

AEM's patch-and-bypass cycle is well-documented: CVE-2016-0957 (the original Dispatcher bypass) uses techniques that conceptually recur in 2025 research. Each patch addresses a specific bypass vector, but the underlying architectural tension — between Sling's intentional URL flexibility and the Dispatcher's pattern-matching defense — ensures that new bypass combinations continue to emerge. The volume of XSS CVEs (225 in a single 2025 bulletin) reflects the content-driven rendering model where any JCR property can potentially influence HTML output.

### Structural Solutions

A defense-in-depth approach is required: (1) **Dispatcher hardening** using full `/url` patterns rather than decomposed particle filters, with explicit deny-all default and narrow allowlists; (2) **JCR access control** enforcing least-privilege on all repository paths, particularly `/home`, `/etc`, `/apps`, and `/var`; (3) **Administrative interface isolation** ensuring OSGi console, CRXDE, Groovy Console, and Package Manager are network-inaccessible from any public-facing interface; (4) **Servlet registration audit** disabling or restricting all non-essential Sling servlets in production; (5) **AEM Cloud migration** which eliminates several on-premise attack classes (direct JCR access, OSGi console) but introduces new ones (CDN proxy trust assumptions, shared infrastructure).

---

## References

- [Searchlight Cyber — Finding Critical Bugs in AEM](https://slcyber.io/research-center/finding-critical-bugs-in-adobe-experience-manager/)
- [Searchlight Cyber — Struts Devmode in 2025](https://slcyber.io/research-center/struts-devmode-in-2025-critical-pre-auth-vulnerabilities-in-adobe-experience-manager-forms/)
- [Searchlight Cyber — Persistent XSS on Every AEM Cloud Site Thrice](https://slcyber.io/assetnote-security-research-center/how-we-got-persistent-xss-on-every-aem-cloud-site-thrice/)
- [WithSecure Labs — Securing AEM With Dispatcher](https://labs.withsecure.com/publications/securing-aem-with-dispatcher)
- [0ang3el/aem-hacker — GitHub](https://github.com/0ang3el/aem-hacker)
- [Assetnote/hopgoblin — GitHub](https://github.com/assetnote/hopgoblin)
- [Bugcrowd LevelUp — AEM Hacker: Approaching AEM Webapps](https://www.bugcrowd.com/resources/levelup/aem-hacker-approaching-adobe-experience-manager-webapps/)
- [Mikhail Egorov — Securing AEM Webapps by Hacking Them (adapt.to 2019)](https://adapt.to/2019/presentations/adaptto2019-securing-aem-webapps-by-hacking-them-mikhail-egorov.pdf)
- [Mikhail Egorov — Hunting for Security Bugs in AEM Webapps (Hacktivity 2018)](https://www.slideshare.net/0ang3el/hunting-for-security-bugs-in-aem-webapps-129262212)
- [Pen Test Partners — Quick Wins with AEM](https://www.pentestpartners.com/security-blog/quick-wins-with-adobe-experience-manager/)
- [Perficient — AEM Security: Sling Resolution](https://blogs.perficient.com/2022/10/11/how-good-is-your-aem-security-sling-resolution/)
- [Perficient — AEM Security: XSS](https://blogs.perficient.com/2022/10/04/how-good-is-your-aem-security-xss/)
- [Adobe Security Bulletin APSB25-115](https://helpx.adobe.com/security/products/experience-manager/apsb25-115.html)
- [Adobe Security Bulletin APSB25-82](https://helpx.adobe.com/security/products/aem-forms/apsb25-82.html)
- [Adobe AEM Security Checklist](https://experienceleague.adobe.com/en/docs/experience-manager-65/content/security/security-checklist)
- [CVE-2025-54253 — CISA KEV catalog (listing unverified as of 2026-03)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (see also: [The Hacker News coverage](https://thehackernews.com/2025/10/cisa-flags-adobe-aem-flaw-with-perfect.html))
- [CVE Details — AEM Vulnerability List](https://www.cvedetails.com/vulnerability-list/vendor_id-53/product_id-33138/Adobe-Experience-Manager.html)
- [AEM Vulnerability Checklist (Az0x7)](https://github.com/Az0x7/vulnerability-Checklist/blob/main/Aem%20misconfiguration/aem.md)
- [Burp AEM Scanner Extension (thomashartm)](https://github.com/thomashartm/burp-aem-scanner)
- [AEM Dispatcher Optimizer Tool (Adobe)](https://github.com/adobe/aem-dispatcher-optimizer-tool)
- [Detectify Labs — AEM Package Manager Auth Bypass](https://labs.detectify.com/writeups/undocumented-authentication-bypass-issue-in-aem-package-manager-blog-updated/)
- [HackerOne — U.S. DoD AEM Misconfiguration Report #1939272](https://hackerone.com/reports/1939272)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
