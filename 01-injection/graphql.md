# GraphQL Security Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire GraphQL security attack surface under three orthogonal axes derived from systematic analysis of CVEs, bug bounty reports, academic research, practitioner writeups, and offensive tooling.

**Axis 1 — Attack Surface Target (Primary Axis):** The structural component of the GraphQL ecosystem being targeted. This forms the main body of the document, organizing techniques by *what* is attacked — from schema discovery mechanisms to transport-layer protocols. Ten top-level categories cover the full mutation space.

**Axis 2 — Exploitation Mechanism (Cross-Cutting Axis):** The nature of the exploitation technique that makes each attack work. A single attack surface target may be exploitable through multiple mechanisms, and a single mechanism may apply across multiple targets.

| Code | Mechanism | Description |
|------|-----------|-------------|
| **M1** | Information Disclosure | Leaking internal structure, types, fields, or debug data |
| **M2** | Resource Exhaustion | Consuming disproportionate server resources (CPU, memory, DB) |
| **M3** | Injection / Code Execution | Injecting malicious payloads through resolver inputs |
| **M4** | Authorization Bypass | Accessing data or operations without proper permission |
| **M5** | Input Validation Bypass | Circumventing filters, allowlists, or sanitization logic |
| **M6** | Protocol / Transport Abuse | Exploiting HTTP, WebSocket, or content-type handling |
| **M7** | Cache Manipulation | Poisoning or abusing caching layers |

**Axis 3 — Impact Scenario (Mapping Axis):** The real-world consequence when a technique is successfully weaponized — reconnaissance, DoS, data exfiltration, privilege escalation, RCE, account takeover, or SSRF. Mapped in §11.

### Foundational Context: Why GraphQL Creates a Unique Attack Surface

GraphQL's core design philosophy — a single endpoint, client-controlled queries, a strongly-typed schema, and introspection by default — fundamentally reshapes the security model compared to REST APIs. In REST, the attack surface is distributed across many endpoints with endpoint-specific authorization. In GraphQL, a single `/graphql` endpoint handles unlimited query shapes, and the client dictates exactly which fields to retrieve, which mutations to invoke, and how deeply to nest relationships. This client-side control, combined with the self-documenting nature of the schema, creates a concentrated and uniquely exploitable attack surface.

---

## §1. Schema Discovery & Information Disclosure

Schema discovery attacks target GraphQL's self-documenting nature to reconstruct the API's internal structure, revealing types, fields, arguments, mutations, and relationships that inform subsequent exploitation.

### §1-1. Introspection Query Abuse

The GraphQL specification includes a built-in introspection system that allows clients to query the schema for complete metadata about all types, fields, arguments, directives, and relationships.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Full introspection dump** | Sending `__schema` or `__type` queries to retrieve the complete schema definition, including all queries, mutations, subscriptions, input types, and enum values | Introspection enabled in production (default in most implementations) |
| **Selective type probing** | Querying `__type(name: "...")` for specific types (e.g., `User`, `Admin`, `InternalConfig`) to avoid detection by monitors watching for full introspection | Introspection enabled; no per-type access control on meta-fields |
| **Introspection via GET parameters** | Encoding introspection queries as URL query parameters in GET requests, bypassing WAFs or middleware that only inspect POST bodies | Server accepts GET-based queries; WAF only monitors POST |
| **Introspection through alternative content types** | Submitting introspection queries with `application/x-www-form-urlencoded` or `multipart/form-data` content types instead of `application/json` | Server accepts multiple content types without restriction |

### §1-2. Field Suggestion Enumeration

When introspection is disabled, GraphQL servers often still expose schema information through error messages that suggest similar field names when a client queries a non-existent field.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Typo-based suggestion extraction** | Deliberately querying misspelled field names (e.g., `usern` instead of `username`) to trigger the server's "Did you mean...?" response, revealing valid field names | Field suggestion feature enabled (default in Apollo, graphql-js, and others) |
| **Dictionary-driven schema reconstruction** | Systematically probing with common field name dictionaries (e.g., `password`, `token`, `secret`, `admin`, `internal`) and analyzing suggestion responses to reconstruct the schema without introspection | Field suggestions enabled; no rate limiting on failed queries |
| **Recursive suggestion chaining** | Using discovered field names from initial suggestions as seeds for subsequent probes, progressively uncovering deeper parts of the schema | Large schema with many interconnected types |

Tools like Clairvoyance automate this process by systematically probing the API and reconstructing the hidden schema from error messages.

### §1-3. Error-Based Information Leakage

Verbose error responses from GraphQL servers can reveal internal implementation details, database structures, file paths, and technology stack information.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Stack trace exposure** | Sending malformed queries or triggering resolver exceptions to elicit detailed stack traces containing file paths, library versions, and internal function names | Debug mode enabled in production; unfiltered error formatting |
| **Database error propagation** | Crafting inputs that cause database errors (e.g., type mismatches, constraint violations) which propagate through resolvers into GraphQL error responses, revealing table names, column names, and query structures | Resolvers pass raw database errors to GraphQL error handler |
| **Resolver path disclosure** | Triggering errors in nested resolvers to reveal the full resolver chain path, exposing internal service architecture and relationship structures | No error masking middleware; detailed error paths enabled |
| **Type system error mining** | Submitting queries with incorrect argument types to extract type information from validation error messages (e.g., "Expected type Int!, found String") | Default GraphQL validation; no custom error formatter |

### §1-4. Server Engine Fingerprinting

Identifying the specific GraphQL server implementation (Apollo, Hasura, graphql-java, Yoga, etc.) enables targeted exploitation of known CVEs and implementation-specific behaviors.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Behavioral fingerprinting** | Sending a mix of benign and malformed queries and analyzing response patterns (error message format, status codes, header values) that differ between implementations | GraphQL endpoint accessible |
| **Error format differential** | Comparing error response structures (JSON field ordering, error code conventions, extension fields) against known implementation signatures | Default error handling configuration |
| **Subscription protocol detection** | Probing WebSocket endpoints for subscription support and analyzing handshake patterns to identify the underlying transport library | WebSocket endpoint exposed |

---

## §2. Query Structure Exploitation (Denial of Service)

GraphQL's flexible query language allows clients to construct arbitrarily complex queries. Without server-side controls, these capabilities become potent denial-of-service vectors.

### §2-1. Depth-Based Attacks

GraphQL schemas often contain circular relationships (e.g., `User → Posts → Author → Posts → Author...`), enabling the construction of deeply nested queries that exponentially amplify database calls.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Circular relationship exploitation** | Constructing queries that traverse circular type relationships to arbitrary depth (e.g., `{ user { posts { author { posts { author ... } } } } }`) | Circular type references in schema; no depth limit |
| **Deep nesting with list fields** | Nesting list-type fields that return arrays, where each level multiplies the response size exponentially (e.g., 10 users × 10 posts × 10 comments = 1,000 objects at depth 3) | List fields in circular relationships; no complexity analysis |
| **Selective depth amplification** | Targeting specific branches of the schema graph known to be computationally expensive (e.g., fields involving JOINs, full-text search, or external API calls) at maximum depth | Expensive resolvers without per-resolver cost limits |

### §2-2. Width-Based Attacks (Alias Abuse)

GraphQL aliases allow the same field to be requested multiple times under different names within a single query, enabling horizontal amplification.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Alias multiplication** | Requesting the same expensive field hundreds of times using aliases (`a1: expensiveField, a2: expensiveField, ... a1000: expensiveField`) in a single query | No alias count limit; no query complexity analysis |
| **Alias-based brute force** | Using aliases to execute multiple authentication attempts (e.g., login mutations) in a single HTTP request, bypassing per-request rate limits | Rate limiting applied per HTTP request, not per operation |
| **Cross-field alias amplification** | Combining aliases across multiple expensive fields to maximize server-side computation within a single query | Multiple expensive resolvers accessible; no aggregate cost limit |

### §2-3. Fragment-Based Attacks

GraphQL fragments allow query reuse and composition but can be weaponized for amplification and evasion.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Circular fragment reference** | Creating fragments that recursively reference each other (`fragment A on User { ...B }` / `fragment B on User { ...A }`), causing infinite recursion during query validation or execution | GraphQL server does not detect circular fragment references before execution |
| **Fragment spread amplification** | Spreading the same large fragment across many fields or aliases to multiply the effective query size after fragment expansion | No post-expansion complexity analysis |
| **Inline fragment type confusion** | Using inline fragments on union/interface types to request fields from multiple concrete types, amplifying the number of resolved fields beyond what's apparent in the query text | Union/interface types with many implementing types |

### §2-4. Directive Overloading

Directives modify query behavior, and when overloaded, they can exhaust server resources or bypass security controls.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Repeated directive application** | Applying the same directive (e.g., `@skip`, `@include`, or custom directives) hundreds of times on a single field, forcing the server to evaluate each directive invocation | No directive count limit per field (CVE-2022-37734 in graphql-java) |
| **Non-existent directive injection** | Including references to directives that don't exist on the server, forcing the validation layer to perform exhaustive lookups | Validation processes all directives before rejecting unknown ones |
| **Custom directive resource exhaustion** | Targeting custom directives that perform expensive operations (database lookups, external API calls, cryptographic operations) by applying them across many fields | Custom directives with side effects; no per-directive cost assignment |

### §2-5. Batch Query Amplification

GraphQL servers often support processing multiple operations in a single HTTP request, either via array batching or query batching.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Array batch flooding** | Sending an array of hundreds or thousands of queries in a single POST body (`[{query: "..."}, {query: "..."}, ...]`) to amplify server workload | Array batching enabled; no batch size limit |
| **Combined batch + depth** | Batching multiple deeply-nested queries together, combining horizontal and vertical amplification | Both batching and deep queries allowed without aggregate limits |
| **Batch-based OTP exhaustion** | Sending all possible OTP values (e.g., 000000–999999) as individual operations in batched requests to brute-force two-factor authentication | Batching enabled for authentication mutations; per-request rate limiting |

---

## §3. Injection Through Resolvers

GraphQL itself is a query language layer — the actual data fetching happens in resolvers. When resolvers construct backend queries using unsanitized client input, classic injection vulnerabilities emerge.

### §3-1. SQL Injection via GraphQL Arguments

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct argument injection** | Injecting SQL payloads through query/mutation arguments (e.g., `user(name: "' OR 1=1 --")`) that are directly concatenated into SQL queries by resolvers | Resolver uses string concatenation for SQL construction |
| **Filter/sort parameter injection** | Injecting SQL through dynamic filter or sorting parameters (e.g., `users(orderBy: "name; DROP TABLE users--")`) | Custom filter/sort resolvers without parameterized queries |
| **Nested input object injection** | Exploiting deeply nested input types where inner fields are less likely to be validated (e.g., `createUser(input: { address: { city: "'; DROP TABLE--" } })`) | Inconsistent input validation across nested input types |

### §3-2. NoSQL Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **MongoDB operator injection** | Injecting MongoDB query operators through GraphQL arguments (e.g., `user(filter: { password: { $gt: "" } })`) to manipulate query logic | Resolver directly passes arguments to MongoDB query builder |
| **JSON-based query manipulation** | Exploiting GraphQL's native JSON input handling to inject NoSQL operators that wouldn't be possible in URL-based REST parameters | GraphQL input types mapped directly to NoSQL query documents |

### §3-3. Server-Side Request Forgery (SSRF)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **URL argument SSRF** | Providing attacker-controlled URLs in mutation arguments (e.g., `importData(url: "http://169.254.169.254/latest/meta-data/")`) that the resolver fetches server-side | Resolver performs HTTP requests based on user-supplied URLs |
| **File upload mutation SSRF** | Exploiting file upload mutations that accept URLs instead of file data, causing the server to fetch from internal or cloud metadata endpoints | Upload mutation accepts URL parameter for remote file fetching |
| **Webhook/callback SSRF** | Injecting internal URLs into webhook or notification configuration mutations | Mutation allows setting callback URLs without domain validation |

### §3-4. OS Command Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Resolver shell execution** | Injecting shell commands through arguments that are passed to `exec()`, `system()`, or similar functions in resolvers (e.g., `convertFile(filename: "file.pdf; cat /etc/passwd")`) | Resolver uses user input in shell commands |
| **Template injection through resolvers** | Injecting template syntax (e.g., `{{7*7}}` for Jinja2) through arguments that pass through server-side template engines | Resolver outputs pass through a template engine without sanitization |

### §3-5. Cross-Site Scripting (XSS) via GraphQL

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Stored XSS via mutations** | Submitting XSS payloads through mutations (e.g., `updateProfile(bio: "<script>...</script>")`) that are stored and later rendered in other users' browsers | Mutation accepts HTML/script content; output not sanitized |
| **Reflected XSS through error messages** | Injecting script content that is reflected in GraphQL error responses rendered in a browser context (e.g., GraphiQL interface) | Error messages rendered without HTML encoding in client UI |
| **Subscription-delivered XSS** | Pushing XSS payloads through subscription channels to connected clients | Subscription data rendered in DOM without sanitization |

---

## §4. Authentication & Session Attacks

GraphQL's single-endpoint architecture centralizes authentication challenges. Unlike REST where different endpoints can have different auth requirements, a GraphQL server must handle authentication uniformly across all operations.

### §4-1. Authentication Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unauthenticated mutation access** | Accessing sensitive mutations (e.g., `resetPassword`, `changeEmail`, `createAdmin`) without any authentication token by directly calling the GraphQL endpoint | Missing authentication middleware on specific mutations |
| **Alternative operation type bypass** | Using queries to perform actions that are only protected when invoked as mutations, or accessing subscription endpoints that bypass query-level auth checks | Inconsistent auth enforcement across operation types |
| **Introspection-guided auth mapping** | Using schema introspection to discover all authentication-related mutations and systematically testing each for missing auth requirements | Full schema visible; auth checks not applied uniformly |

### §4-2. Cross-Site Request Forgery (CSRF)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Content-type downgrade** | Changing the request Content-Type from `application/json` to `application/x-www-form-urlencoded` or `multipart/form-data`, which browsers send as "simple" requests without CORS preflight | Server accepts multiple content types; no CSRF token validation |
| **GET-based mutation execution** | Executing mutations via GET requests with query parameters, bypassing CSRF protections that only apply to POST requests | Server accepts mutations via GET; no method restriction |
| **Multipart upload CSRF** | Exploiting the `multipart/form-data` content type used by file upload mutations, which is exempt from CORS preflight checks | File upload mutations enabled; no additional CSRF protection (CVE-2024-4994 in GitLab) |

### §4-3. Session & Token Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Token replay via batching** | Reusing expired or revoked tokens across batched requests where token validation occurs only once for the entire batch | Batch processing validates auth once at the batch level |
| **Subscription session persistence** | Maintaining WebSocket connections after token expiration, continuing to receive real-time data on a stale session | No periodic re-authentication on long-lived WebSocket connections |
| **JWT claim manipulation** | Modifying JWT claims (e.g., role, permissions) in tokens used for GraphQL authentication when signature verification is weak or absent | Weak JWT configuration; `none` algorithm accepted |

---

## §5. Authorization & Access Control Bypass

Authorization failures in GraphQL are among the most commonly reported vulnerability classes in bug bounty programs, as GraphQL's flexible query model makes it easy for developers to miss access control checks on individual fields or relationships.

### §5-1. Object-Level Authorization Bypass (IDOR)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct ID enumeration** | Querying objects using sequential or predictable IDs (e.g., `user(id: 1)`, `user(id: 2)`, ...) without ownership verification | Resolver does not verify requesting user's access to the specific object |
| **Relay/Global ID manipulation** | Decoding and modifying Base64-encoded Relay global IDs (e.g., `VXNlcjox` → `User:1` → modify to `User:2`) to access unauthorized objects | Relay-style IDs without server-side authorization on decoded references |
| **Relationship traversal** | Accessing unauthorized objects by traversing relationships from an authorized starting point (e.g., `myPost { comments { author { privateEmail } } }`) | Authorization enforced on root queries but not on nested resolvers |

### §5-2. Field-Level Authorization Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sensitive field appending** | Adding sensitive fields (e.g., `passwordHash`, `ssn`, `internalNotes`) to otherwise authorized queries, exploiting missing per-field access controls | Schema exposes sensitive fields; authorization only at the query level, not the field level |
| **Fragment-based field extraction** | Using inline fragments on interface/union types to access fields on concrete types that have weaker authorization than the abstract type | Authorization enforced on interface but not on implementing types |
| **Alias-based field duplication** | Requesting the same sensitive field under multiple aliases to test if authorization is applied consistently or only on the first occurrence | Inconsistent authorization across aliased field references |

### §5-3. Mutation Authorization Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Privilege escalation via mutation** | Calling administrative mutations (e.g., `setUserRole(role: ADMIN)`) that lack role-based access control | Mutation exposed in schema without proper role verification (CVE-2025-14592 in GitLab) |
| **Mass assignment via input types** | Including unauthorized fields in mutation input objects (e.g., adding `isAdmin: true` to a `updateProfile` mutation) that the resolver applies without filtering | Resolver auto-maps all input fields to database columns without allowlisting |
| **Horizontal privilege escalation** | Modifying another user's data through mutations that accept a user ID without verifying the caller's relationship to that user | Mutation accepts target user ID without ownership validation |

### §5-4. Subscription Authorization Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unauthorized event subscription** | Subscribing to events (e.g., `newOrder`, `adminNotification`) without proper authorization checks on the subscription resolver | Subscription resolvers lack authorization middleware |
| **Cross-tenant data leakage** | Receiving subscription events from other tenants in a multi-tenant architecture due to missing tenant isolation in the subscription filter | Subscription filter does not include tenant context |

---

## §6. Rate Limiting & Abuse Prevention Bypass

GraphQL's single-endpoint model and support for batching/aliasing create fundamental challenges for traditional rate limiting approaches designed for REST APIs.

### §6-1. Batching-Based Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Array batch brute force** | Packing hundreds of login/OTP/password-reset attempts into a single batched HTTP request, making them appear as one request to network-level rate limiters | Rate limiting at network/proxy level (Nginx, CDN); batching enabled |
| **Alias-based brute force** | Using aliases to execute multiple authentication queries within a single GraphQL operation (e.g., `a1: login(pass: "aaa"), a2: login(pass: "aab"), ...`) | Per-HTTP-request rate limiting; no per-operation or per-alias counting |
| **Sequential batch chaining** | Sending batched requests in rapid succession, each containing the maximum number of operations, to multiply throughput beyond any single-request limit | Batch size unlimited or very high; no per-second operation count |

### §6-2. Query Shape Evasion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Variable-based obfuscation** | Using GraphQL variables to change the effective operation without changing the query structure, evading WAF rules that match on static query text | WAF pattern matching on raw query text; variables processed separately |
| **Fragment-based structural obfuscation** | Restructuring queries using fragments and fragment spreads to alter the syntactic representation while maintaining semantic equivalence | WAF or security middleware uses syntactic pattern matching |
| **Persisted query hash manipulation** | Attempting to register malicious queries as persisted queries (APQ) by exploiting hash collision or registration race conditions | APQ enabled without allowlisting; automatic registration allowed |

---

## §7. Directive Abuse & Custom Extension Exploitation

GraphQL directives (`@skip`, `@include`, and custom directives) provide powerful query modification capabilities that can be weaponized for both DoS and logic bypass attacks.

### §7-1. Built-in Directive Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Conditional logic manipulation** | Using `@skip(if: ...)` and `@include(if: ...)` with dynamic variable values to probe which fields exist and which authorization paths are evaluated | Server evaluates authorization before directive filtering |
| **Duplicate directive stacking** | Applying the same built-in directive multiple times on a single field to test for processing anomalies or crashes | No directive deduplication in the execution engine |

### §7-2. Custom Directive Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Auth directive bypass via fragments** | Evading `@auth` or `@hasRole` directives by accessing the protected field through deeply nested fragments or alternative relationship paths where the directive is not inherited | Authorization directives not propagated to all field access paths |
| **Internal directive injection** | Invoking internal-only directives (e.g., `@internalDebug`, `@bypassCache`, `@trace`) from client queries when the server doesn't restrict client-side directive usage | Internal directives not restricted to server-side usage |
| **Directive argument injection** | Injecting malicious values into directive arguments (e.g., `@cache(key: "../../admin")`) that are processed without sanitization | Custom directive arguments not validated |
| **Fragment-based directive evasion** | Accessing a field protected by a directive through an inline fragment on a different type in a union/interface, where the directive is not applied on the alternate path | Directive applied per-field on one type but not on alternative interface paths |

---

## §8. Transport & Protocol Layer Attacks

GraphQL operates over HTTP and WebSocket protocols, and vulnerabilities at the transport layer can undermine application-level security controls.

### §8-1. HTTP Method & Content-Type Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **GET-based mutation smuggling** | Executing mutations via HTTP GET requests, bypassing security controls that only apply to POST requests | Server does not restrict mutations to POST method |
| **Content-type confusion** | Sending GraphQL queries with unexpected content types (e.g., `text/plain`, `application/x-www-form-urlencoded`) to bypass WAFs or CORS restrictions | Server accepts queries in non-JSON content types |
| **Multipart boundary manipulation** | Crafting multipart requests with unusual boundary strings or nested parts to confuse parsing middleware while delivering valid GraphQL payloads | Server uses lenient multipart parsing |

### §8-2. WebSocket / Subscription Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Site WebSocket Hijacking (CSWSH)** | Opening WebSocket connections from a malicious website, leveraging the browser's automatic cookie attachment for WebSocket handshakes (no Same-Origin Policy enforcement) | Cookie-based authentication for WebSocket; no Origin header validation |
| **Subscription flooding** | Opening many concurrent subscriptions to resource-intensive events, causing the server to maintain excessive state and push computation | No per-client subscription limit; no subscription cost analysis |
| **WebSocket message injection** | Injecting malicious GraphQL operations through the WebSocket message protocol after connection establishment, bypassing initial auth checks | Authentication only at connection init; no per-message validation |
| **Connection persistence after auth revocation** | Maintaining WebSocket connections after token expiration or session revocation to continue receiving subscription data | No heartbeat-based re-authentication on long-lived connections |
| **Protocol downgrade** | Forcing fallback from `wss://` to `ws://` to enable man-in-the-middle interception of subscription data | Server allows unencrypted WebSocket connections (CVE-2024-54147 in Altair GraphQL Client) |

### §8-3. Endpoint Discovery & Routing

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Common path brute force** | Scanning common GraphQL endpoint paths (`/graphql`, `/gql`, `/api/graphql`, `/v1/graphql`, `/query`, `/graphiql`, `/playground`, `/altair`, `/explorer`) | GraphQL endpoint at predictable path without authentication |
| **Subdomain enumeration** | Discovering GraphQL APIs on subdomains (e.g., `api.example.com`, `graph.example.com`, `internal-api.example.com`) | Internal or staging GraphQL endpoints exposed on subdomains |
| **IDE/playground exposure** | Accessing GraphQL IDE interfaces (GraphiQL, Apollo Sandbox, Playground) left enabled in production, providing interactive schema exploration and query execution | Development tools not disabled in production deployment |

---

## §9. Caching & Response Manipulation

GraphQL's dynamic query model creates unique challenges for caching, and misconfigurations in caching layers can be exploited for data leakage or poisoning.

### §9-1. Server-Side Cache Poisoning

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Batch response header manipulation** | In batched requests, manipulating cache-control headers through one operation to affect caching behavior of another operation in the same batch, causing sensitive responses to be cached publicly | Batch processing merges response headers across operations (Apollo Server cache poisoning vulnerability) |
| **Persisted query cache poisoning** | Registering a malicious query under a hash that collides with or replaces a legitimate persisted query, causing subsequent clients requesting that hash to execute the attacker's query | APQ with open registration; no hash verification |
| **CDN cache key confusion** | Exploiting differences between how a CDN generates cache keys and how the GraphQL server interprets requests, storing one user's response for another user's cache key | CDN caching enabled for GraphQL; cache key doesn't include auth context |

### §9-2. Client-Side Cache Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Alias-based cache poisoning** | Using aliased `__typename` or `id` fields to cause Apollo Client's normalized cache to store attacker-controlled data under legitimate object cache keys | Apollo Client normalized cache; attacker can execute queries with aliases |
| **Cache pollution via type confusion** | Injecting objects with manipulated type metadata into the client cache through queries on union/interface types, causing the cache to return incorrect data for subsequent queries | Client-side normalized caching with polymorphic types |

---

## §10. Architecture & Federation-Specific Attacks

GraphQL federation and gateway patterns introduce additional attack surfaces at the composition and routing layers.

### §10-1. Gateway / Router Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Subgraph direct access** | Bypassing the federation gateway by directly querying individual subgraph services that may have weaker authentication or authorization than the gateway | Subgraph services network-accessible; not restricted to gateway-only traffic |
| **Cross-subgraph authorization gap** | Exploiting authorization inconsistencies between subgraphs, where a field is protected in one subgraph but the same data is accessible through a different subgraph's relationships | Authorization enforced per-subgraph rather than at the federated schema level |
| **Schema composition manipulation** | Exploiting the schema composition process to inject or override types and fields from one subgraph that affect another subgraph's behavior | Malicious or compromised subgraph in the federation |

### §10-2. Schema Stitching Vulnerabilities

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Stitched resolver injection** | Injecting malicious queries through stitched schemas where one service's output is used as input to another service's resolver without proper sanitization | Schema stitching without input validation between services |
| **Type conflict exploitation** | Exploiting naming conflicts between stitched schemas that cause type merging anomalies, potentially exposing fields from internal services | Multiple schemas with overlapping type names without proper conflict resolution |

### §10-3. Persisted Operations Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **APQ registration abuse** | Registering arbitrary queries through the APQ registration mechanism, effectively bypassing the persisted query allowlist | APQ (Automatic Persisted Queries) used instead of strict persisted operations |
| **Hash collision exploitation** | Crafting queries with SHA-256 hashes that collide with registered persisted queries (theoretical, high difficulty) | Persisted query system uses short or truncated hashes |
| **Fallback to arbitrary queries** | Exploiting fallback mechanisms where the server accepts arbitrary queries when a persisted query hash is not found, instead of rejecting the request | Permissive fallback behavior; no strict enforcement mode |

---

## §11. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|---------------------------|
| **Reconnaissance & Schema Discovery** | Any GraphQL endpoint; default configuration | §1-1, §1-2, §1-3, §1-4 |
| **Denial of Service** | High-traffic production; circular schema relationships | §2-1, §2-2, §2-3, §2-4, §2-5, §8-2 |
| **Brute Force / Credential Stuffing** | Auth mutations exposed; batching enabled | §2-5, §6-1, §6-2 |
| **Data Exfiltration** | Sensitive fields in schema; weak field-level auth | §5-1, §5-2, §5-4, §3-1, §3-2 |
| **Privilege Escalation** | Admin mutations accessible; mass assignment possible | §5-3, §4-1, §5-1 |
| **Remote Code Execution** | Unsafe resolvers; command/template injection | §3-4, §3-1 |
| **Server-Side Request Forgery** | URL-based inputs; file upload mutations | §3-3 |
| **Account Takeover** | Auth bypass + mutation access | §4-1, §4-2, §5-3, §6-1 |
| **Cache Poisoning** | CDN/proxy caching; batched responses | §9-1, §9-2 |
| **Cross-Site Attacks** | Browser-based GraphQL clients; WebSocket subscriptions | §4-2, §8-2, §3-5 |
| **Supply Chain / Federation Compromise** | Federated architecture; schema stitching | §10-1, §10-2, §10-3 |

---

## §12. CVE / Bounty Mapping (2022–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §2-4 (directive overloading) | CVE-2022-37734 (graphql-java) | DoS via unbounded directive repetition; caused excessive CPU consumption |
| §2-1 + §2-5 (depth + batching) | CVE-2024-40094 (graphql-java) | DoS via ExecutableNormalizedFields; introspection queries caused resource exhaustion in IBM WebSphere Liberty and Maximo |
| §1-1 (introspection access control) | CVE-2024-50312 (OpenShift) | Information disclosure; unauthorized users retrieved full query/mutation list |
| §2-2 (alias abuse) | CVE-2024-50311 (OpenShift) | DoS via alias batching in the GraphQL endpoint |
| §4-2 (CSRF via GET) | CVE-2024-4994 (GitLab) | High-severity CSRF allowing arbitrary GraphQL mutation execution |
| §5-3 (mutation authz bypass) | CVE-2025-14592 (GitLab GLQL) | Critical unauthorized mutation execution across CE/EE versions |
| §8-2 (WebSocket MITM) | CVE-2024-54147 (Altair GraphQL Client) | Missing HTTPS certificate validation on WebSocket connections; MITM interception of all queries |
| §3-3 (SSRF via upload) | GHSA-x27p-wfqw-hfcc (Craft CMS) | SSRF via GraphQL asset upload mutation; cloud metadata access |
| §9-1 (batch cache poisoning) | SNYK-JS-APOLLOSERVERCORE-3098876 (Apollo Server) | Cache poisoning via batched POST request header merging |
| §9-2 (client cache poisoning) | Apollo Client #10784 | Client-side cache poisoning via aliased `__typename` and `id` fields |
| §5-2 + §1-1 (field exposure) | Multiple HackerOne reports | $1,000–$10,000+ bounties for sensitive field extraction via introspection-guided queries |
| §6-1 (batch brute force) | Multiple bug bounty programs | 2FA/OTP bypass via batched authentication mutations |

---

## §13. Detection & Security Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **InQL** (Burp Suite extension) | Schema analysis, vulnerability scanning | Introspection query, schema reconstruction via Clairvoyance patterns, point-and-click attack generation |
| **graphw00f** (fingerprinting) | Server engine identification | Behavioral differential analysis across 30+ GraphQL implementations |
| **Clairvoyance** (schema recovery) | Schema reconstruction without introspection | Dictionary-based field suggestion probing; reconstructs types, fields, and arguments from error messages |
| **CrackQL** (brute force) | Authentication/rate limit testing | GraphQL-aware batching attack automation; OTP and password brute forcing |
| **GraphQLer** (fuzzer) | Comprehensive API security testing | Context-aware GraphQL API fuzzing with dependency resolution |
| **Goctopus** (discovery) | Endpoint discovery and fingerprinting | Subdomain enumeration, route brute-force, introspection, auth detection |
| **BatchQL** (DoS testing) | Batch vulnerability assessment | Automated batch query construction for rate limit and DoS testing |
| **graphql-cop** (auditing) | Security misconfiguration detection | Automated checks for common misconfigurations (introspection, batching, field suggestions) |
| **DVGA** (training) | Vulnerable GraphQL application | Intentionally vulnerable GraphQL app for practicing exploitation techniques |
| **Escape.tech** (SaaS scanner) | Production API security monitoring | Continuous GraphQL security scanning with automated vulnerability detection |
| **StackHawk** (DAST) | Dynamic application security testing | GraphQL-aware DAST scanning including field suggestion detection |

---

## §14. Summary: Core Principles

### The Root Cause: Client-Controlled Query Semantics

The fundamental property that makes the entire GraphQL attack surface possible is **client-controlled query semantics over a self-documenting schema**. Unlike REST, where the server defines fixed response shapes and the attack surface is distributed across endpoints, GraphQL concentrates all functionality behind a single endpoint and grants clients extraordinary control over what data is requested, how deeply relationships are traversed, and how many operations execute per request. The schema, which is queryable by default, serves as a complete attack blueprint.

### Why Incremental Fixes Fail

Each vulnerability class in this taxonomy stems from a different facet of GraphQL's design, which means fixing one class does not address others. Disabling introspection leaves field suggestions active (§1-2). Adding depth limits doesn't prevent alias-based amplification (§2-2). Rate limiting per HTTP request is meaningless when batching multiplies operations (§6-1). Authorization at the query level fails when nested resolvers lack their own checks (§5-1). This orthogonality of attack vectors means a comprehensive defense requires addressing **each axis independently** — there is no single configuration toggle or middleware that secures a GraphQL API.

### Structural Solutions

A defense-in-depth approach must layer multiple controls:

1. **Schema minimization**: Expose only the fields, mutations, and types that clients genuinely need. Remove internal, debug, and administrative operations from the public schema.
2. **Persisted operations (strict allowlist)**: Replace arbitrary client queries with server-registered operation hashes, eliminating entire attack classes (§2, §6, §7) by removing client control over query structure.
3. **Per-resolver authorization**: Enforce access control at every resolver, not just at the query entry point, to prevent relationship traversal and field-level bypass (§5).
4. **Query cost analysis**: Assign computational costs to fields and reject queries exceeding a threshold, addressing depth, width, and directive-based DoS (§2, §7).
5. **Input validation at the resolver boundary**: Treat every GraphQL argument as untrusted user input and apply parameterized queries, URL allowlists, and input sanitization (§3).
6. **Transport hardening**: Restrict mutations to POST, enforce strict content-type validation, validate WebSocket Origin headers, and implement per-operation rate limiting (§4, §8).
7. **Federation-aware security**: Apply authentication and authorization at the gateway level AND the subgraph level, restricting direct subgraph access (§10).

---

## References

- [GraphQL API Vulnerabilities — PortSwigger Web Security Academy](https://portswigger.net/web-security/graphql)
- [GraphQL Cheat Sheet — OWASP](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL Security — Official GraphQL Documentation](https://graphql.org/learn/security/)
- [GraphQL Vulnerabilities and Common Attacks — Imperva](https://www.imperva.com/blog/graphql-vulnerabilities-common-attacks/)
- [GraphQL — HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)
- [PayloadsAllTheThings — GraphQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection)
- [Awesome GraphQL Security — Escape Technologies](https://github.com/Escape-Technologies/awesome-graphql-security)
- [GraphQL Vulnerabilities — Application Security Cheat Sheet](https://0xn3va.gitbook.io/cheat-sheets/web-application/graphql-vulnerabilities)
- [8 Common GraphQL Vulnerabilities — Escape.tech](https://escape.tech/blog/8-most-common-graphql-vulnerabilities/)
- [GraphQL Security — Tyk](https://tyk.io/blog/graphql-security-7-common-vulnerabilities-and-how-to-mitigate-the-risks/)
- [Directive Deception: Exploiting Custom GraphQL Directives — InstaTunnel](https://instatunnel.my/blog/directive-deception-exploiting-custom-graphql-directives-for-logic-bypass)
- [GraphQL Batching Attack — Wallarm](https://lab.wallarm.com/graphql-batching-attack/)
- [Securing Your GraphQL API from Malicious Queries — Apollo](https://www.apollographql.com/blog/securing-your-graphql-api-from-malicious-queries)
- [Cross-Site Request Forgery Prevention — Apollo](https://www.apollographql.com/docs/graphos/routing/security/csrf)
- [That Single GraphQL Issue That You Keep Missing — Doyensec](https://blog.doyensec.com/2021/05/20/graphql-csrf.html)
- [GraphQL Error Handling: A Security POV — Escape.tech](https://escape.tech/blog/graphql-error-handling-a-security-pov/)
- [GraphQL Security from a Pentester's Perspective — AFINE](https://afine.com/graphql-security-from-a-pentesters-perspective/)
- [Enhancing GraphQL Security by Detecting Malicious Queries Using LLMs — arXiv](https://arxiv.org/html/2508.11711v2)
- [GraphQLer: Enhancing GraphQL Security with Context-Aware API Testing — arXiv](https://arxiv.org/html/2504.13358v1)
- [OWASP Web Security Testing Guide v4.2 — API Testing: GraphQL](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
