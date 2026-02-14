# ASP.NET Attack Surface Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy catalogs the full attack surface of the ASP.NET ecosystem — spanning ASP.NET Framework (Web Forms, MVC), ASP.NET Core (MVC, Razor Pages, Blazor, SignalR), and the underlying infrastructure layer (IIS, Kestrel, HTTP.sys). Every technique is classified along three orthogonal axes.

**Axis 1 — Mutation Target (Primary Structure):** The structural component of the ASP.NET stack being manipulated. This axis organizes the main body of the document into twelve top-level categories (§1–§12), each targeting a distinct architectural surface.

**Axis 2 — Effect Type (Cross-Cutting Dimension):** The nature of the security consequence produced by the mutation. A single mutation target may produce multiple effect types depending on context. The effect types are summarized below and referenced throughout.

**Axis 3 — Attack Scenario (Deployment Mapping):** The real-world exploitation context in which the mutation becomes weaponizable, mapped in §12.

### Axis 2: Effect Type Summary

| Code | Effect Type | Description |
|------|------------|-------------|
| **E1** | Parser Differential | Front-end/back-end interpretation mismatch |
| **E2** | Authentication Bypass | Circumventing identity verification |
| **E3** | Authorization Bypass | Accessing resources without proper permissions |
| **E4** | Code Execution | Achieving arbitrary code/command execution |
| **E5** | Information Disclosure | Leaking sensitive data, config, or source code |
| **E6** | Injection | Inserting malicious code/queries into processing |
| **E7** | State Manipulation | Tampering with server/client-side state |
| **E8** | Cryptographic Weakness | Exploiting key management or crypto primitives |
| **DoS** | Denial of Service | Resource exhaustion or service disruption |

### Foundational Architecture

The ASP.NET ecosystem creates a uniquely rich attack surface due to its layered architecture:

```
[Client] → [Reverse Proxy (IIS/Nginx/Apache)] → [Kestrel / HTTP.sys] → [ASP.NET Middleware Pipeline] → [MVC/Razor/Blazor/SignalR]
                                                                                ↓
                                                                    [Entity Framework / ADO.NET]
                                                                                ↓
                                                                         [Data Store]
```

Each layer performs independent parsing, normalization, and validation — creating differential gaps that attackers exploit. The .NET Framework's extensive serialization surface (BinaryFormatter, ViewState, SOAP) and IIS's legacy URL handling behavior (8.3 filenames, cookieless sessions) add unique attack primitives not present in other web frameworks.

---

## §1. Serialization & State Management Attacks

ASP.NET's heavy reliance on object serialization — for ViewState, session management, caching, and inter-process communication — creates one of the most critical attack surfaces in the framework. The core issue is that .NET formatters deserialize type metadata from untrusted input, enabling arbitrary object instantiation and gadget chain execution.

### §1-1. ViewState Deserialization

ViewState is a mechanism in ASP.NET Web Forms that persists page state across HTTP postbacks by serializing UI control data into a Base64-encoded, optionally encrypted and MAC-signed blob embedded in `__VIEWSTATE` hidden form fields.

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Machine Key Theft → ViewState Forgery** | Attacker obtains the `machineKey` (validationKey + decryptionKey) from publicly disclosed sources (GitHub, Stack Overflow, Pastebin, MSDN docs). Crafts malicious serialized payload, signs it with stolen key, submits via POST. ASP.NET runtime trusts the signature and deserializes, achieving RCE. | E4, E8 | Machine key is known or leaked. Microsoft identified 3,000+ publicly exposed keys in Feb 2025. |
| **Disabled ViewState MAC** | When `enableViewStateMac="false"` is set in web.config (or via legacy CVEs that disable MAC at runtime), the ViewState blob is accepted without signature verification. Attacker crafts arbitrary serialized payload without needing any key material. | E4 | ViewState MAC validation disabled in configuration. |
| **ViewState via Path Traversal** | Attacker exploits a file-write vulnerability (§5-2) to place a malicious web.config that disables ViewState MAC or sets a known machine key, then exploits ViewState deserialization on the target page. | E4 | File write primitive available. |
| **Padding Oracle on ViewState** | When custom errors are improperly configured, the server returns distinguishable error responses for decryption failures vs. validation failures. Attacker performs byte-by-byte decryption of ViewState ciphertext, then crafts forged payloads. Exploits the `WebResource.axd` handler's differential error responses (valid padding → 200, invalid padding → 500, valid padding but invalid data → 404). | E4, E5, E8 | Custom errors not uniformly configured; pre-.NET 4.5 default behavior (CVE-2010-3332 / MS10-070). |

### §1-2. .NET Formatter Exploitation

The .NET ecosystem provides numerous serialization formatters, many of which perform unrestricted type resolution during deserialization.

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **BinaryFormatter RCE** | `BinaryFormatter.Deserialize()` resolves arbitrary types from the serialized stream, instantiating objects and invoking constructors/setters. Gadget chains (e.g., `WindowsIdentity`, `ClaimsIdentity`, `DataSet`, `TypeConfuseDelegate`) chain property setters to achieve `Process.Start()` or assembly loading. | E4 | Application deserializes untrusted BinaryFormatter data. BinaryFormatter is now officially deprecated as "never safe." |
| **LosFormatter RCE** | LosFormatter (used internally by ViewState) wraps BinaryFormatter with Base64 encoding. Same gadget chains apply when LosFormatter processes untrusted input outside the ViewState context. | E4 | Direct LosFormatter use on untrusted input. |
| **SoapFormatter RCE** | SoapFormatter embeds .NET type information in XML/SOAP structure. Accepts the same gadget chains as BinaryFormatter but via XML-encoded payloads, which can evade binary-focused WAF rules. | E4 | Application accepts SOAP-formatted serialized data. |
| **NetDataContractSerializer RCE** | Similar to DataContractSerializer but includes full .NET type information in the XML output, enabling arbitrary type instantiation. Gadget chains leverage `ISerializable` callbacks. | E4 | Application uses NetDataContractSerializer on untrusted input. |
| **JSON.NET TypeNameHandling Exploitation** | When `TypeNameHandling` is set to anything other than `None`, JSON.NET resolves `$type` metadata from the JSON payload, instantiating arbitrary types. Exploited via gadgets like `ObjectDataProvider`, `System.Windows.Data.ObjectDataProvider`, or `System.Configuration.Install.AssemblyInstaller`. | E4 | `TypeNameHandling` != `None` in Newtonsoft.Json configuration. |
| **DataContractSerializer with Known Types** | While safer than BinaryFormatter, DataContractSerializer can be exploited when the known types list includes dangerous types, or when a `DataContractResolver` resolves arbitrary types. | E4 | Overly permissive known types or custom resolver. |
| **ResourceSet / RESX Deserialization** | `.resx` resource files embed serialized .NET objects. When applications dynamically load attacker-controlled resource files, the embedded BinaryFormatter data is deserialized automatically. | E4 | Application loads untrusted .resx files. |

### §1-3. Gadget Chain Architecture

Gadget chains are sequences of existing .NET class operations that, when triggered during deserialization, achieve unintended side effects (typically RCE). The `ysoserial.net` tool catalogs known chains.

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Property-Oriented Programming (POP)** | Chains property getter/setter invocations across multiple objects to reach a dangerous sink (e.g., `Process.Start`, `Assembly.Load`). Each "gadget" performs one step in the chain. | E4 | Vulnerable formatter + gadget libraries on classpath. |
| **ISerializable Callback Chains** | Exploits `ISerializable` constructor and `OnDeserialized` callbacks to execute logic during deserialization without requiring property access. | E4 | Target type implements ISerializable. |
| **Type Confusion via Discriminators** | .NET formatters include arbitrary type discriminators that allow instantiation of any type in the loaded assemblies. Attacker specifies unexpected types that trigger dangerous constructors. | E4 | Formatter permits unrestricted type resolution. |
| **Bridge/Derived Gadgets** | Techniques that convert between formatter-specific gadget chains — e.g., wrapping a BinaryFormatter gadget inside a DataContractSerializer-compatible envelope. Extends exploitability across formatter boundaries. | E4 | Multiple formatters in use within same application. |

---

## §2. HTTP Request Parsing & Smuggling

The layered proxy architecture of ASP.NET deployments (reverse proxy → Kestrel/HTTP.sys → middleware) creates parsing differential surfaces exploitable for request smuggling.

### §2-1. Chunked Encoding Differentials

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Lone LF in Chunk Extensions (CVE-2025-55315)** | Kestrel's `ParseExtension` method in `Http1ChunkedEncodingMessageBody` searched only for `\r` when parsing chunk extensions. A lone `\n` character was treated as part of the extension, while most proxies interpret bare `\n` as a line terminator. This creates a framing mismatch: the proxy sees the end of a chunk where Kestrel does not, enabling injection of a second smuggled request. CVSS 9.9 — the highest ever for ASP.NET Core. | E1, E3, E4 | Kestrel behind a reverse proxy that normalizes bare LF as line terminator. Affected: ASP.NET Core 8.0.20, 9.0.9, 10.0-rc.1, and 2.x (Kestrel.Core ≤2.3.0). |
| **Transfer-Encoding Obfuscation** | Standard TE obfuscation techniques (e.g., `Transfer-Encoding: chunked`, `Transfer-Encoding : chunked`, `Transfer-Encoding\t: chunked`, multiple TE headers) can create discrepancies between IIS/Nginx front-ends and Kestrel's TE parsing. | E1 | Proxy and Kestrel disagree on TE header validity. |
| **CL.TE / TE.CL Desync** | Classic HTTP smuggling where Content-Length and Transfer-Encoding headers are both present and interpreted differently by the proxy and Kestrel. | E1 | Proxy prioritizes CL while Kestrel prioritizes TE (or vice versa). |

### §2-2. Header Parsing Differentials

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Host Header Injection** | ASP.NET applications that trust `Request.Host` or `Request.Headers["Host"]` without validation enable attackers to manipulate URL generation, password reset links, cache keys, and virtual host routing. | E6, E7 | Application uses Host header value in response generation. |
| **X-Forwarded-For/X-Forwarded-Host Spoofing** | When `ForwardedHeadersMiddleware` is configured to trust all proxies (`ForwardedHeaders.All` without `KnownProxies`/`KnownNetworks` restrictions), attackers can inject arbitrary IP/host values. | E2, E3 | Middleware trusts all forwarded headers. |
| **HTTP/2 → HTTP/1.1 Downgrade** | When Kestrel serves HTTP/2 and downgrades to HTTP/1.1 for backend communication, pseudo-headers (`:authority`, `:path`) may be mapped inconsistently, creating injection points. | E1, E6 | HTTP/2 front-end with HTTP/1.1 backend. |

### §2-3. Connection-Level Attacks

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **HTTP/3 Resource Exhaustion (CVE-2025-26682)** | Improper handling of HTTP/3 connections in ASP.NET Core leads to unbounded resource allocation, enabling denial of service. | DoS | HTTP/3 (QUIC) enabled on Kestrel. |
| **0.CL Desync** | The front-end treats a request as having no body while Kestrel reads Content-Length bytes, creating a deadlock broken via early response gadgets (static files, Windows reserved filenames, redirects, `Expect: 100-continue`). | E1 | Front-end and Kestrel disagree on body presence. |
| **Response Queue Poisoning** | After a successful smuggle, the attacker's injected request receives the response destined for a victim's subsequent request, enabling credential capture or session hijacking. | E2, E5 | Persistent connection reuse (HTTP/1.1 keep-alive). |

---

## §3. URL/Path Processing & Normalization

IIS and ASP.NET perform multi-stage URL normalization, creating a rich surface for path confusion attacks. The normalization pipeline includes: URL decoding → backslash normalization → dot-segment removal → 8.3 filename resolution → extension mapping → routing.

### §3-1. Cookieless Session URL Manipulation

ASP.NET Framework supports embedding session identifiers directly in URLs using the pattern `/(S(sessionid))/`. This feature creates a powerful path manipulation primitive.

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Double Cookieless Pattern Auth Bypass (CVE-2023-36899)** | Two cookieless patterns embedded in the URL (e.g., `/(S(X))/prot/(S(X))ected/target.aspx`) cause the first pattern to be stripped during early processing, leaving the second embedded within a directory name. Authentication rules evaluate the malformed path while ASP.NET processes the reconstructed `/protected/` path, bypassing directory-level authentication. | E2, E3 | Cookieless sessions not disabled; .NET Framework on IIS. |
| **App Pool Privilege Escalation (CVE-2023-36560)** | Placing double cookieless patterns before application subdirectories forces ASP.NET to execute pages under the parent application's App Pool identity instead of the child's. For example, `/(S(X))/(S(X))/child/page.aspx` executes under root's DefaultAppPool even if `/child/` is configured for a restricted pool. | E3 | Nested IIS applications with different App Pool assignments. |
| **PathInfo Variant** | Appending the cookieless pattern after the file extension (`/target.aspx/(S(X))/`) achieves identical bypasses through post-extension path manipulation. | E2, E3 | .NET Framework cookieless processing. |
| **Source Code Disclosure via /bin Access** | Cookieless URL patterns split the `/bin/` directory name across session markers (`/(S(X))/b/(S(X))in/target.dll`), bypassing IIS path restrictions on the `/bin/` directory and enabling DLL download for decompilation. | E5 | Cookieless sessions enabled; `runAllManagedModulesForAllRequests=true`. |
| **WAF Bypass via Cookieless Paths** | Cookieless session patterns inserted into malicious URLs evade WAF rules that pattern-match on clean paths (e.g., `/(S(X))/admin/(S(X))/` evades rules matching `/admin/`). | E3 | WAF operates on raw URL without cookieless normalization. |

### §3-2. IIS 8.3 Short Filename Enumeration

Windows NTFS creates legacy 8.3 short filenames (e.g., `LONGFI~1.TXT` for `LongFileName.txt`). IIS responds differently to requests referencing valid vs. invalid short names, enabling file/directory enumeration.

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Tilde Enumeration** | Requests containing `~` trigger IIS's short filename resolution. Differential response codes (404 for valid short names vs. 400 for invalid ones) allow character-by-character brute-forcing of file/directory names. Pattern: `GET /e*~1*/.aspx` → 404 means files starting with 'e' exist. | E5 | 8.3 name creation enabled on NTFS; IIS serves the directory. |
| **::$INDEX_ALLOCATION Directory Probing** | NTFS alternate data stream `::$INDEX_ALLOCATION` appended to directory names confirms directory existence without triggering normal access controls. Used to enumerate `/bin/` contents in conjunction with cookieless session attacks (§3-1). | E5 | NTFS filesystem; IIS does not filter ADS syntax. |
| **Short Name + Cookieless Combo** | Combining 8.3 enumeration results with cookieless session path manipulation enables downloading files from restricted directories by first discovering short filenames, then bypassing path restrictions. | E5 | Both 8.3 names and cookieless sessions available. |

### §3-3. Path Traversal & Encoding Bypasses

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Double URL Encoding** | Encoding `../` as `%252e%252e%252f` bypasses first-pass URL decoding by filters, with the second decode occurring at the application layer. IIS's request filtering operates on the first-decoded URL. | E3, E5 | Application performs additional URL decoding; IIS request filtering is the only defense layer. |
| **Backslash Normalization** | IIS normalizes `\` to `/` in URL paths, but upstream proxies may not. Submitting `..\..\..\` instead of `../../../` can bypass proxy-level path traversal filters while IIS resolves the traversal. | E3, E5 | Proxy does not normalize backslashes; IIS handles the request. |
| **Dot-Segment Removal Discrepancy** | Different handling of `/.//`, `/./`, `/../` sequences between reverse proxies and IIS/Kestrel. Proxies may strip dot segments before forwarding, changing which path the origin server processes. | E1, E3 | Proxy and origin disagree on dot-segment handling. |
| **Null Byte Truncation** | In legacy .NET Framework versions, `%00` in file paths truncated the path at the null byte, allowing extension bypass (e.g., `malicious.aspx%00.jpg`). Largely fixed in modern .NET but may persist in third-party libraries. | E3, E4 | Legacy .NET Framework; unpatched libraries. |
| **Unicode Normalization** | IIS performs Unicode normalization on URLs. Characters like fullwidth solidus (`／`, U+FF0F) or fullwidth period (`．`, U+FF0E) may be normalized to `/` and `.` respectively after security filters have processed the raw form. | E3 | IIS Unicode normalization enabled; filters operate pre-normalization. |

---

## §4. Model Binding & Data Input Attacks

ASP.NET's automatic model binding maps HTTP request data (form fields, query strings, route values, JSON body) to C# object properties, creating opportunities for injection and manipulation.

### §4-1. Mass Assignment / Over-Posting

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Direct Entity Binding** | When a controller action binds directly to a database entity (e.g., `public IActionResult Update(User user)`), the model binder populates all public properties from request data — including sensitive properties like `IsAdmin`, `Role`, `Balance`, or `PasswordHash` that are not exposed in the UI form. | E3, E7 | Controller binds to entity model without `[Bind]`, `[BindNever]`, or DTO pattern. |
| **JSON Body Over-Posting** | API endpoints that accept JSON body and deserialize to entity models are vulnerable to additional properties injected into the JSON payload. Unlike form-based attacks, JSON makes it trivial to add arbitrary key-value pairs. | E3, E7 | Web API endpoint binds JSON to entity model. |
| **Nested Object Injection** | Model binder traverses nested object graphs. If a bound model has navigation properties (e.g., `User.Role.Permissions`), attackers can set properties on related objects by submitting `Role.Name=Admin`. | E3, E7 | Navigation properties exposed on bound model. |
| **Query String / Route Value Binding** | Properties can be bound from query strings and route values even when the primary binding source is the request body, enabling over-posting through URL parameters that bypass body-focused validation. | E3, E7 | Multiple binding sources active; no explicit `[FromBody]` restriction. |

### §4-2. ORM & Database Injection

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **FromSqlRaw / FromSqlInterpolated Injection** | Entity Framework Core's `FromSqlRaw()` accepts raw SQL strings. If user input is concatenated (not parameterized), classic SQL injection applies despite using an ORM. `FromSqlInterpolated()` is safe when used correctly but can be misused with pre-built strings. | E6 | Developer concatenates user input into `FromSqlRaw()`. |
| **ExecuteSqlRaw Injection** | Direct SQL execution via `DbContext.Database.ExecuteSqlRaw()` with string concatenation bypasses all EF Core query parameterization. | E6 | Raw SQL execution with unsanitized input. |
| **Stored Procedure Parameter Injection** | EF Core stored procedure calls that construct parameter strings dynamically remain vulnerable to injection, especially with complex parameter types. | E6 | Dynamic parameter construction for stored procedures. |
| **LINQ Injection via Dynamic LINQ** | Libraries like `System.Linq.Dynamic.Core` accept string-based LINQ expressions. If user input flows into these expressions, attackers can manipulate query logic or invoke arbitrary methods. | E6 | Dynamic LINQ library with user-controlled expressions. |

### §4-3. LDAP Injection

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Filter Manipulation** | ASP.NET applications authenticating against Active Directory via `DirectorySearcher` construct LDAP filters by concatenation: `"(&(uid=" + username + "))"`. Injecting `admin)(|(memberOf=*))` breaks the filter structure, adding a tautology that bypasses password verification. | E2, E6 | LDAP filter constructed by string concatenation in `System.DirectoryServices`. |
| **DN Injection** | Distinguished Name components constructed from user input enable path traversal within the LDAP directory tree, potentially reaching administrative OUs. | E3, E6 | DN built from unsanitized input. |

---

## §5. Template Engine & View Resolution Attacks

ASP.NET's Razor engine compiles views to .NET assemblies, meaning any attacker-controlled content that enters the compilation pipeline achieves full code execution.

### §5-1. Server-Side Template Injection (SSTI)

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Razor.Parse() with User Input** | When applications dynamically compile Razor templates from user-controlled strings using `RazorEngine.Parse()` or `RazorTemplateEngine.CreateCodeDocument()`, any injected `@{ }` code block is compiled and executed as C#. Payloads can invoke `System.Diagnostics.Process.Start()` for RCE. | E4 | Application passes user input to template compilation. |
| **Encoded C# Payloads** | SSTI payloads use integer array encoding to bypass basic string filters: `@{string x=null;int[]l={119,104,111,97,109,105};foreach(int c in l){x+=((char)c).ToString();};}@x` generates "whoami" without containing the literal string. | E4 | Template injection present; keyword-based WAF. |
| **Blazor Render Fragment Injection** | In Blazor Server, if `RenderFragment` delegates are constructed from user input, the Razor compiler processes the content, potentially executing embedded C# directives. | E4 | User input flows into RenderFragment construction. |

### §5-2. View Engine Search Pattern Exploitation

The Razor View Engine resolves views through a deterministic search hierarchy. Combined with a file-write primitive, this creates a reliable RCE chain.

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **File Write → View Resolution RCE** | The View Engine searches `~/Views/{Controller}/{Action}.cshtml` → `~/Views/Shared/{Action}.cshtml`. Attacker exploits a path traversal file-write vulnerability to place a `.cshtml` file containing `@{ Process.Start("cmd.exe", "/c payload"); }` at a location in the search hierarchy, then triggers the route. The View Engine discovers, compiles, and executes the malicious view. | E4 | Arbitrary file-write primitive + routable controller action without explicit view path. |
| **IIS Extension Whitelist Bypass** | IIS Request Filtering may block direct `.cshtml` access, but the View Engine accesses files through internal `File.Exists()` operations that completely bypass IIS filtering. Requesting the extensionless controller route (e.g., `GET /Controller/Action`) triggers internal `.cshtml` resolution without IIS ever seeing a `.cshtml` URL. | E4, E3 | IIS extension whitelist in place; file-write primitive available. |
| **Area-Based View Resolution** | MVC Areas add additional search paths (`~/Areas/{Area}/Views/{Controller}/{Action}.cshtml`), expanding the set of writable locations that trigger compilation. | E4 | Application uses MVC Areas. |

---

## §6. Authentication & Session Management Attacks

### §6-1. Forms Authentication Bypass

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Cookie Replay After Logout** | ASP.NET Forms Authentication cookies remain valid server-side even after `FormsAuthentication.SignOut()` unless sessions are also invalidated. Captured cookies can be replayed indefinitely until expiration. | E2 | No server-side session invalidation on logout. |
| **RefreshSignInAsync Impersonation (CVE-2025-24070)** | Calling `RefreshSignInAsync` with an improperly authenticated user parameter allows an attacker to sign into another user's account, achieving elevation of privilege. | E2, E3 | Application uses `RefreshSignInAsync` with controllable user parameter. |
| **Sliding Expiration Abuse** | With sliding expiration enabled, authentication cookies are renewed on each request. Automated keep-alive requests can extend a captured session token indefinitely beyond its intended lifetime. | E2 | Sliding expiration enabled on auth cookie. |

### §6-2. JWT / Token Manipulation

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Algorithm Confusion (RS256→HS256)** | If the ASP.NET application's JWT validation does not enforce the expected signing algorithm, an attacker changes the JWT header from RS256 to HS256 and signs the token using the public RSA key as the HMAC secret. The server verifies using the public key as a symmetric key, validating the forged token. | E2 | `TokenValidationParameters.ValidAlgorithms` not set; public key accessible. |
| **kid Parameter Injection** | The `kid` (Key ID) JWT header parameter may be vulnerable to injection if used unsafely to locate key files. Directory traversal in `kid` (e.g., `kid: "../../dev/null"`) can point to an empty file, allowing signing with an empty secret. SQL injection in `kid` is also possible if keys are database-stored. | E2, E6 | Application resolves signing keys via `kid` without validation. |
| **None Algorithm Attack** | Setting the JWT algorithm to `"none"` and removing the signature. ASP.NET's `JwtSecurityTokenHandler` rejects this by default, but custom validation implementations or older libraries may not. | E2 | Custom JWT validation logic that doesn't enforce algorithm presence. |

### §6-3. CSRF / Anti-Forgery Token Attacks

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **XSS → CSRF Token Extraction** | A cross-site scripting vulnerability nullifies all CSRF protections. Injected JavaScript reads the `__RequestVerificationToken` from the hidden form field and includes it in forged requests, bypassing the double-submit cookie pattern. | E7 | XSS vulnerability exists in the application. |
| **Missing Validation on API Endpoints** | ASP.NET Web API controllers do not automatically validate anti-forgery tokens unless explicitly configured with `[ValidateAntiForgeryToken]`. AJAX-heavy SPAs may omit this protection. | E7 | API endpoint lacks anti-forgery validation. |
| **SameSite Cookie Bypass** | When `SameSite=Lax` (ASP.NET Core default), top-level GET navigations include cookies. If state-changing actions are accessible via GET (violating REST principles), CSRF remains possible through link clicks or redirects. | E7 | State-changing GET endpoints; SameSite=Lax. |

---

## §7. Authorization & Access Control Attacks

### §7-1. Insecure Direct Object Reference (IDOR)

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Sequential ID Enumeration** | API endpoints like `/api/orders/{orderId}` return data for any valid ID without verifying the requesting user's ownership. Attackers enumerate integer IDs to access all records. | E3 | No object-level authorization check; predictable IDs. |
| **GUID Leakage** | GUIDs used as "unguessable" identifiers are leaked through API responses, client-side code, or URL referrers, enabling IDOR even without sequential enumeration. | E3 | GUID exposed in response data accessible to other users. |
| **Batch/Bulk API IDOR** | Endpoints accepting arrays of IDs (e.g., `POST /api/orders/batch` with `[1,2,3,999]`) may validate ownership on the first item but skip validation on subsequent items. | E3 | Batch endpoint with inconsistent authorization. |

### §7-2. SignalR Hub Authorization Failures

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Unauthenticated Hub Method Access** | Without the `[Authorize]` attribute on hub classes or methods, all public methods are accessible to any connected client, including anonymous users. SignalR's connection token is not an authentication token — it only confirms connection identity, not user identity. | E3 | Hub methods lack `[Authorize]` attribute. |
| **Group Message Eavesdropping** | SignalR groups have no built-in authorization. Any client that knows or guesses a group name can join it via `Groups.AddToGroupAsync()` and receive all messages broadcast to that group. | E3, E5 | No server-side group membership validation. |
| **Hub Method Parameter Tampering** | Hub methods accepting object parameters are subject to the same mass assignment risks as MVC controllers (§4-1). Attackers can inject additional properties in the JSON payload sent to hub methods. | E3, E7 | Hub methods bind complex objects from client input. |

### §7-3. Middleware Pipeline Bypass

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Middleware Ordering Vulnerability** | ASP.NET Core middleware executes in registration order. If authorization middleware is registered after a middleware that short-circuits the pipeline (e.g., static file middleware serving from a writable directory), requests bypass authorization entirely. | E3 | `app.UseStaticFiles()` registered before `app.UseAuthorization()`. |
| **Endpoint Routing Mismatch** | `[Authorize]` attributes on controllers may not apply to endpoints registered via `MapGet`/`MapPost` minimal APIs if `RequireAuthorization()` is not chained. Developers may assume attribute-based authorization applies globally. | E3 | Mixed controller + minimal API routing without consistent authorization. |
| **Fallback Policy Gaps** | `FallbackPolicy` in `AuthorizationOptions` only applies to endpoints that don't have any authorization metadata. Endpoints with an empty `[AllowAnonymous]` attribute or custom policies may inadvertently bypass the fallback. | E3 | Fallback policy assumed to cover all endpoints. |

---

## §8. Cryptographic Material & Key Management

### §8-1. Machine Key Exploitation

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Publicly Disclosed Machine Keys** | Microsoft identified 3,000+ publicly available machine keys (from GitHub repos, Stack Overflow posts, MSDN sample code). Attackers use these keys to sign ViewState payloads, authentication tickets, and other crypto-dependent tokens. In Dec 2024, attackers deployed the Godzilla webshell via this technique. | E4, E8 | Application uses a publicly known machine key. |
| **IsolateApps Modifier Derivation** | When `IsolateApps` is specified in the machine key configuration, per-application keys are derived from the base key and the application path. Knowing the base key and application path allows deriving the actual signing key. | E8 | `IsolateApps` used with a known base key. |
| **Machine Key from web.config Disclosure** | Path traversal (§3-3), backup file access, or source code disclosure (§3-1) that reveals `web.config` exposes machine keys in plaintext, enabling all ViewState and cookie forgery attacks. | E5, E8 | web.config accessible via any disclosure vector. |

### §8-2. Data Protection API Misuse

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Shared Key Ring Without Isolation** | ASP.NET Core's Data Protection API stores keys in a key ring. If multiple applications share a key ring without `SetApplicationName()` isolation, one application can decrypt/forge tokens for another. | E8, E2 | Shared hosting; key ring not application-isolated. |
| **Key Ring File Exposure** | Data Protection key ring files stored in default locations (e.g., `%LOCALAPPDATA%\ASP.NET\DataProtection-Keys\`) may be accessible through directory traversal or backup exposure, enabling offline token forgery. | E5, E8 | Key ring files in accessible filesystem location. |

---

## §9. SOAP/WCF & Protocol-Level Attacks

### §9-1. SOAPwn: WSDL-Based RCE (CVE-2025-34392)

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **File Write via Protocol Handler Confusion** | `HttpWebClientProtocol.GetWebRequest()` calls `WebRequest.Create(uri)` without scheme validation. A missing cast to `HttpWebRequest` returns the original `WebRequest` object, which may be a `FileWebRequest` when the URI uses `file://`. SOAP invocations then write XML request bodies directly to disk instead of sending network requests. | E4 | Application uses `SoapHttpClientProtocol` with attacker-controlled URL. Microsoft refuses to patch. |
| **WSDL-Controlled Proxy Generation** | `ServiceDescriptionImporter` generates C# proxy classes from WSDL metadata. Malicious WSDL containing `<soap:address location="file:///inetpub/wwwroot/shell.aspx"/>` generates a proxy hardcoded with the file:// URI. When the proxy's methods are invoked, SOAP bodies are written as webshells. | E4 | Application dynamically imports WSDL from untrusted sources. |
| **Namespace Smuggling for Payload Control** | WSDL-defined XML namespaces always appear inside generated SOAP bodies regardless of method parameters. Attacker sets namespace URLs to contain executable content (e.g., ASP.NET Razor code or `<script runat="server">`), which is written to disk as part of the SOAP body file. | E4 | WSDL-based file write achieved; target interprets written file as executable. |
| **NTLM Relay via UNC Path** | Setting the SOAP endpoint to a UNC path (`\\attacker\share`) causes the .NET HTTP client to initiate NTLM authentication to the attacker's server, leaking NTLM hashes for offline cracking or relay attacks. | E5, E2 | Windows authentication enabled; outbound SMB not blocked. |

### §9-2. XML External Entity (XXE) Injection

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **XmlDocument with XmlUrlResolver** | `XmlDocument` configured with `XmlResolver = new XmlUrlResolver()` resolves external entities from DTD declarations. Payloads like `<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">` read local files, and SSRF variants using `http://` URLs probe internal networks. | E5, E6 | `XmlDocument.XmlResolver` set to `XmlUrlResolver`; .NET < 4.5.2 is vulnerable by default. |
| **XmlReader DTD Processing** | `XmlReaderSettings.DtdProcessing` set to `DtdProcessing.Parse` (default in .NET < 4.5.2) enables DTD processing, allowing entity expansion attacks (Billion Laughs) and external entity resolution. | E5, DoS | `DtdProcessing` not set to `Prohibit`; .NET < 4.5.2. |
| **SOAP Envelope XXE** | WCF services processing raw SOAP XML may be vulnerable if the XML reader configuration permits DTD processing, allowing XXE payloads embedded in SOAP envelopes. | E5, E6 | WCF service with permissive XML reader settings. |
| **SVG/DOCX/XLSX XXE** | Applications processing XML-based file formats (SVG images, Office Open XML documents) via .NET XML parsers inherit the same XXE vulnerabilities when entity resolution is enabled. | E5 | File upload + XML parsing with entity resolution. |

---

## §10. Configuration & Information Disclosure

### §10-1. web.config Exposure

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Direct web.config Access** | Misconfigured IIS or alternative web servers may serve `web.config` as a static file. The file typically contains connection strings, machine keys, authentication settings, and debug configuration. | E5 | IIS request filtering misconfigured; alternative server without .NET-aware file filtering. |
| **web.config via File Upload** | Uploading a crafted `web.config` to a writable directory can override IIS configuration for that directory — enabling script execution, disabling authentication, or setting custom handlers. This bypasses extension-based upload blacklists since `.config` may not be blocked. | E4, E3 | File upload to IIS-served directory; `.config` extension not blacklisted. |
| **Backup File Disclosure** | Files like `web.config.bak`, `web.config.old`, `web.config~`, or `web.config.swp` (from editor auto-save) are served as static files since IIS only protects the exact `web.config` filename. | E5 | Backup files left in web root; IIS serves unknown extensions. |

### §10-2. Debug & Error Information Leakage

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Debug Mode Enabled in Production** | `<compilation debug="true"/>` in web.config enables detailed error pages, disables request timeouts, and may expose source code snippets. The `WebResource.axd` and `ScriptResource.axd` handlers provide additional information surfaces. | E5 | `debug="true"` in production web.config. |
| **Developer Exception Page Exposure** | ASP.NET Core's `app.UseDeveloperExceptionPage()` renders full stack traces, source code context, query strings, headers, and cookies in error responses. If enabled in production (via missing environment check), all exceptions become information disclosure. | E5 | `UseDeveloperExceptionPage()` active in production. |
| **Custom Errors Mode Off** | `<customErrors mode="Off"/>` displays full .NET exception details to all users, including stack traces that reveal internal paths, library versions, and database schemas. | E5 | Custom errors disabled in production. |
| **ELMAH / Glimpse Exposure** | Diagnostic tools like ELMAH (`/elmah.axd`) and Glimpse (`/glimpse.axd`) provide detailed request logs, SQL queries, and configuration data. If deployed without authentication restrictions, they become information goldmines. | E5 | Diagnostic endpoints accessible without authentication. |

### §10-3. Server Header & Version Disclosure

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **X-Powered-By / X-AspNet-Version Headers** | IIS adds `X-Powered-By: ASP.NET` and `X-AspNet-Version: 4.0.xxxxx` headers by default, revealing the technology stack and exact framework version for targeted exploit selection. | E5 | Default IIS header configuration. |
| **Server: Kestrel Header** | Kestrel's default `Server: Kestrel` header confirms the server technology. | E5 | Kestrel `AddServerHeader` not disabled. |

---

## §11. File Upload & Resource Handling

### §11-1. Extension Validation Bypass

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Double Extension** | Filename `shell.aspx.jpg` may pass extension whitelist checks that only examine the final extension, while IIS processes the file based on the first recognized extension. | E4 | Extension check only validates last extension; IIS handler mapped to `.aspx`. |
| **Trailing Characters** | Appending a space (`shell.aspx `) or dot (`shell.aspx.`) to filenames bypasses blacklist checks on the exact string `.aspx`, while Windows filesystem strips these characters, leaving a valid `shell.aspx`. | E4 | Blacklist-based extension validation; Windows NTFS filesystem. |
| **Null Byte Truncation** | Legacy path handling truncates at `%00`: `shell.aspx%00.jpg` passes `.jpg` whitelist checks but is written as `shell.aspx`. | E4 | Legacy .NET Framework path handling. |
| **Case Sensitivity Mismatch** | Blacklisting `.aspx` but not `.ASPX`, `.Aspx`, or `.aSpX`. IIS handles extensions case-insensitively, but string comparison in validation may be case-sensitive. | E4 | Case-sensitive blacklist check; IIS case-insensitive handler mapping. |
| **Alternate Executable Extensions** | Beyond `.aspx`, IIS maps `.ashx` (generic handlers), `.asmx` (web services), `.soap`, `.rem` (.NET Remoting), and `.svc` (WCF) to .NET execution. Blacklists focusing only on `.aspx` miss these alternatives. | E4 | Incomplete extension blacklist. |

### §11-2. web.config Upload for RCE

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Handler Mapping Override** | Uploading a `web.config` that maps a benign extension (e.g., `.jpg`) to the ASP.NET handler enables execution of any uploaded file with that extension as server-side code. Example config: `<handlers><add name="x" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"/></handlers>`. | E4 | File upload allows `.config` extension to writable, IIS-served directory. |
| **Static File Handler Removal** | A crafted `web.config` can remove the `StaticFileHandler` and replace it with a .NET handler, causing IIS to process all files in the directory through the ASP.NET pipeline. | E4 | Same as above. |

### §11-3. Client-Side Framework (Blazor WebAssembly)

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **WASM Decompilation** | Blazor WASM ships .NET assemblies (`.dll`) to the client browser. Tools like ILSpy or dnSpy decompile these assemblies, revealing business logic, API endpoints, hardcoded secrets, and authentication flows. | E5 | Sensitive logic or secrets in client-side Blazor assemblies. |
| **Client-Side Authorization Bypass** | `[Authorize]` attributes and `AuthorizeView` components in Blazor WASM are enforced only client-side. Users can modify the WASM code or directly call API endpoints, bypassing all client-side authorization. | E3 | Authorization logic only on client; server APIs lack independent authorization checks. |
| **Assembly Tampering** | Intercepting and modifying `.dll` files served to the Blazor WASM client enables logic manipulation (e.g., bypassing license checks, modifying pricing logic). Without server-side validation, tampered assemblies execute freely. | E7, E3 | No server-side integrity validation of client behavior. |

---

## §12. Cross-Site Scripting (XSS) — ASP.NET-Specific Mutations

While XSS is a generic web vulnerability, ASP.NET has framework-specific patterns and bypass vectors.

### §12-1. Razor Encoding Bypass

| Subtype | Mechanism | Effect | Key Condition |
|---------|-----------|--------|---------------|
| **Html.Raw() Misuse** | `@Html.Raw(userInput)` explicitly bypasses Razor's automatic HTML encoding, rendering user input as raw HTML/JavaScript. | E6 | Developer uses `Html.Raw()` with unsanitized user input. |
| **MarkupString in Blazor** | `MarkupString` (or `(MarkupString)userInput`) in Blazor bypasses HTML encoding in the Render Tree, enabling DOM-based XSS. | E6 | `MarkupString` constructed from user input. |
| **JavaScript Context Injection** | Razor's `@` syntax HTML-encodes output, but this encoding is insufficient when the output is placed inside a JavaScript context (e.g., `<script>var x = '@userInput';</script>`). JavaScript-specific characters like backslash are not encoded. | E6 | User input rendered inside `<script>` blocks via Razor. |
| **Legacy ValidateRequest Bypass** | ASP.NET Web Forms' `ValidateRequest` filter, designed to block XSS payloads, can be bypassed using sequences like `</` or `<~/` that are not in the filter's pattern set but are interpreted by browsers as valid HTML. | E6 | Legacy Web Forms with ValidateRequest as sole XSS defense. |

---

## §13. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Remote Code Execution** | Any ASP.NET deployment | §1 (Deserialization) + §5 (SSTI/View Injection) + §9-1 (SOAPwn) + §11-2 (web.config upload) |
| **Data Exfiltration** | IIS + .NET Framework | §3-1 (Cookieless source disclosure) + §3-2 (8.3 enumeration) + §10 (config exposure) + §9-2 (XXE) |
| **Privilege Escalation** | Multi-app IIS deployment | §3-1 (App Pool privesc) + §4-1 (Mass assignment) + §6-1 (RefreshSignInAsync) + §2 (Request smuggling) |
| **Account Takeover** | ASP.NET Core behind proxy | §2 (Request smuggling → session hijacking) + §6-2 (JWT manipulation) + §6-1 (Cookie replay) |
| **Cache Poisoning** | CDN/Reverse Proxy + ASP.NET | §2-1 (Smuggling) + §3-3 (Path normalization discrepancy) + §2-2 (Host header injection) |
| **Denial of Service** | ASP.NET Core with HTTP/3 | §2-3 (HTTP/3 resource exhaustion) + §9-2 (Billion Laughs XXE) |
| **Lateral Movement / SSRF** | Enterprise intranet | §9-1 (SOAPwn NTLM relay) + §9-2 (XXE SSRF) + §2-2 (Host header → routing-based SSRF) |
| **WAF Bypass** | WAF + IIS + ASP.NET | §3-1 (Cookieless path manipulation) + §3-3 (Encoding bypasses) + §3-2 (8.3 filenames) |
| **Supply Chain / Shared Hosting** | Multi-tenant IIS | §8 (Shared key ring) + §3-1 (App Pool escalation) + §7-3 (Middleware ordering) |

---

## §14. CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §2-1 (Chunked LF differential) | CVE-2025-55315 (ASP.NET Core Kestrel) | CVSS 9.9. HTTP request smuggling via lone LF in chunk extension. $10,000 MSRC bounty. Highest-severity ASP.NET Core CVE ever. |
| §9-1 (SOAPwn WSDL file write) | CVE-2025-34392 (Barracuda RMM), CVE-2025-13659 (Ivanti EPM) | Pre-auth RCE via WSDL proxy generation. Webshell deployment to IIS wwwroot. Microsoft declined to patch framework flaw. |
| §1-1 (ViewState + machine keys) | CVE-2025-53690 (Sitecore), CVE-2025-30406 (Gladinet CentreStack) | Zero-day ViewState deserialization via exposed machine keys. Active exploitation in the wild. Godzilla webshell deployment. |
| §1-1 (ViewState + machine keys) | CVE-2025-53770 (SharePoint) | "ToolShell" attack chain. ViewState deserialization for persistent server access. |
| §3-1 (Double cookieless auth bypass) | CVE-2023-36899 (ASP.NET Framework) | Authentication bypass on protected directories. WAF bypass via path manipulation. |
| §3-1 (Cookieless App Pool escalation) | CVE-2023-36560 (ASP.NET Framework) | Privilege escalation — execute code under parent App Pool identity. |
| §6-1 (RefreshSignInAsync impersonation) | CVE-2025-24070 (ASP.NET Core) | Elevation of privilege — sign in as another user. |
| §2-3 (HTTP/3 resource exhaustion) | CVE-2025-26682 (ASP.NET Core) | Denial of service via unbounded resource allocation. |
| §8-1 (Publicly disclosed machine keys) | Microsoft Security Blog Feb 2025 | 3,000+ public machine keys discovered. Active Godzilla webshell campaign in Dec 2024. |
| §1-2 (Padding Oracle) | CVE-2010-3332 / MS10-070 | ViewState decryption via WebResource.axd differential errors. Foundation for modern ViewState attacks. |
| §3-1 (Cookieless source disclosure) | PT SWARM Research 2024 | /bin DLL download via cookieless path + 8.3 enumeration. Source code disclosure in production applications. |

---

## §15. Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **ysoserial.net** | .NET deserialization (§1) | Generates gadget chain payloads for BinaryFormatter, SoapFormatter, JSON.NET, LosFormatter, NetDataContractSerializer, and others. Supports 30+ gadget chains. |
| **IIS-ShortName-Scanner** | IIS 8.3 filenames (§3-2) | Brute-forces short filenames via tilde `~` requests with differential response analysis. Supports `::$INDEX_ALLOCATION` directory probing. |
| **Cookieless-Session-Bypasser-IIS** | Cookieless session attacks (§3-1) | Automates cookieless session URL manipulation for /bin directory access and DLL fuzzing/download. |
| **ViewState Exploit PoC (CVE-2025-30406)** | ViewState forgery (§1-1) | Generates malicious ViewState payloads given a known machine key. |
| **Burp Suite Extensions** | Multiple categories | ViewState decoder/editor, .NET deserialization scanner, ASP.NET parameter tampering. |

### Defensive / Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **SharpFuzz** | .NET application fuzzing | AFL-based fuzz testing for .NET libraries, identifies crashes via exception monitoring. |
| **OWASP ZAP** | General ASP.NET scanning | Automated scanning with ASP.NET-specific checks: ViewState analysis, debug mode detection, path traversal. |
| **Acunetix / Invicti** | ASP.NET vulnerability scanning | Deep-crawling with .NET-specific checks: cookieless session detection, IIS tilde enumeration, debug mode, ViewState MAC validation. |
| **Microsoft Defender for DevOps** | .NET code analysis | SAST scanning for insecure deserialization, SQL injection, XSS, and configuration issues in .NET codebases. |
| **Security Code Scan** | .NET SAST | Open-source static analyzer detecting insecure deserialization, SQL injection, LDAP injection, XXE, and other vulnerabilities in C#/VB.NET. |
| **awesome-dotnet-security** | Resource collection | Curated GitHub repository of .NET security tools, libraries, and references. |

---

## §16. Summary: Core Principles

### The Fundamental Property

ASP.NET's attack surface is uniquely expansive because of three intersecting design characteristics:

1. **Deep Object Serialization**: The .NET Framework was designed around rich object serialization — ViewState, BinaryFormatter, SOAP, .NET Remoting — where type metadata travels with the data. Every serialization surface is a potential code execution surface, because .NET formatters instantiate arbitrary types as part of deserialization. The `ysoserial.net` project demonstrates that dozens of standard library classes can be chained into RCE gadgets. This is not a bug in any single formatter — it is an architectural consequence of .NET's type-aware serialization design.

2. **Multi-Layer URL Processing**: The IIS → Kestrel → ASP.NET middleware → routing pipeline performs URL decoding, normalization, rewriting, and routing at multiple independent stages. Each stage makes assumptions about what the previous stage has already normalized. Legacy features like cookieless sessions, 8.3 short filenames, and backslash-to-slash normalization create a combinatorial space of path manipulation techniques that bypass security controls operating at the wrong stage.

3. **Framework Trust Boundaries**: ASP.NET's model binder, View Engine, Data Protection API, and middleware pipeline all operate with implicit trust assumptions. The model binder trusts that HTTP requests only contain expected properties. The View Engine trusts that files in search paths are benign. The middleware pipeline trusts that registration order correctly reflects security requirements. Each trust assumption is a potential bypass vector.

### Why Incremental Fixes Fail

Microsoft's response to vulnerabilities in this space follows a pattern: patch the specific parsing differential (CVE-2025-55315), deprecate the dangerous formatter (BinaryFormatter), or document the misconfiguration risk (machine key exposure). However, the underlying architecture persists. Cookieless sessions, while patchable, represent a URL processing paradigm that introduces path manipulation regardless of specific bugs. The SOAPwn vulnerability (CVE-2025-34392) exemplifies this — Microsoft declined to fix the framework behavior, classifying it as an application responsibility.

### Structural Solution

A truly structural solution would require:
- **Eliminating type-aware deserialization** from all untrusted input boundaries (substantially achieved with BinaryFormatter deprecation in .NET 8+, but ViewState remains in legacy deployments)
- **Single-pass URL normalization** where security decisions operate on the final, fully-normalized path — not intermediate representations
- **Deny-by-default authorization** where every endpoint, hub method, and resource requires explicit authorization rather than relying on middleware ordering or attribute presence
- **Separation of compilation and rendering** in template engines, ensuring user-controlled data never enters the compilation pipeline (Razor's default encoding achieves this, but `Html.Raw()`, `MarkupString`, and dynamic compilation break the boundary)

Until legacy ASP.NET Framework deployments are fully retired and applications consistently adopt ASP.NET Core's security defaults, the attack surface cataloged in this taxonomy will remain exploitable.

---

## References

- Microsoft Security Blog: "Code injection attacks using publicly disclosed ASP.NET machine keys" (Feb 2025)
- Praetorian: "How I Found the Worst ASP.NET Vulnerability — A $10K Bug (CVE-2025-55315)"
- watchTowr Labs: "SOAPwn: Pwning .NET Framework Applications Through HTTP Client Proxies And WSDL" (Dec 2025)
- Soroush Dalili: "Cookieless DuoDrop: IIS Auth Bypass & App Pool Privesc in ASP.NET Framework (CVE-2023-36899 & CVE-2023-36560)"
- PT SWARM: "Source Code Disclosure in ASP.NET apps" (2024)
- Critical Thinking Bug Bounty Podcast: "ASP.NET MVC View Engine Search Patterns"
- Google Cloud / Mandiant: "ViewState Deserialization Zero-Day Vulnerability in Sitecore Products (CVE-2025-53690)"
- pwntester/ysoserial.net: Deserialization payload generator for .NET formatters
- irsdl/IIS-ShortName-Scanner: IIS short filename (8.3) disclosure scanner
- Andrew Lock: "Understanding the worst .NET vulnerability ever: request smuggling and CVE-2025-55315"
- OWASP: DotNet Security Cheat Sheet
- guardrailsio/awesome-dotnet-security: Curated .NET security resource collection

---

*This document was created for defensive security research and vulnerability understanding purposes.*
