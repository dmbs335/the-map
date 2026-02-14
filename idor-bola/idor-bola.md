# IDOR / BOLA (Insecure Direct Object Reference / Broken Object Level Authorization) Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire attack surface of IDOR/BOLA vulnerabilities across three orthogonal axes. **Axis 1 (Identifier Mutation Target)** is the primary structural axis — it classifies techniques by *what component of the object reference or authorization flow is being manipulated*. **Axis 2 (Authorization Gap Type)** is the cross-cutting axis — it explains *what kind of authorization deficiency* makes each mutation exploitable. **Axis 3 (Impact Scenario)** maps techniques to *real-world exploitation outcomes*.

IDOR/BOLA is fundamentally a **missing or flawed authorization check on user-supplied object identifiers**. Unlike injection or parsing-differential vulnerabilities, the root cause is not a technical parsing flaw but a *logical absence* — the application authenticates the user but never verifies whether the authenticated identity is authorized to access the referenced object. This makes IDOR/BOLA uniquely persistent: it cannot be eliminated by a single library, framework feature, or protocol change, but requires per-endpoint authorization enforcement.

### Axis 2 Summary: Authorization Gap Types

| Gap Type | Description |
|----------|-------------|
| **Absent Check** | No authorization logic exists for the endpoint; any authenticated (or unauthenticated) user can access any object |
| **Inconsistent Check** | Authorization enforced on some endpoints/methods but not others touching the same resource |
| **Bypassable Check** | Authorization logic exists but can be circumvented via encoding, format manipulation, or parameter tricks |
| **Logic Flaw** | Authorization check is present but uses incorrect ownership validation (e.g., checks org but not user within org) |
| **Temporal Gap** | Authorization passes at check time but state changes before use time (TOCTOU) |
| **Trust Boundary Violation** | Internal services or downstream components skip authorization, trusting upstream to have performed it |

---

## §1. Identifier Type and Predictability

The nature of the object identifier determines the attack surface for enumeration and guessing. While unpredictable identifiers raise the bar, they do not substitute for authorization checks — they merely shift the attack from blind enumeration to identifier leakage exploitation.

### §1-1. Sequential Numeric Identifiers

The most classic and widely exploited IDOR vector. Applications that use auto-incrementing database primary keys as external identifiers expose the entire enumeration space to trivial arithmetic.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Integer increment/decrement** | Changing `user_id=1001` to `user_id=1002` accesses adjacent records | Auto-increment PKs exposed without authorization check |
| **Range enumeration** | Iterating through `id=1` to `id=N` to dump all records | No rate limiting combined with absent authorization |
| **Negative / zero ID** | Supplying `id=0` or `id=-1` to access default, admin, or sentinel records | Application uses special IDs for system objects without restricting access |
| **Large integer overflow** | Supplying values exceeding expected range (e.g., `id=999999999`) to hit edge-case records | Integer handling differences between validation layer and database layer |
| **ID arithmetic on composite keys** | Manipulating one component of a composite identifier (e.g., `org_id=5&user_id=3` → `org_id=5&user_id=4`) | Authorization checks only one component of the composite key |

### §1-2. UUID / GUID Identifiers

UUIDs (v4) are 128-bit random values with ~2^122 bits of entropy, making blind enumeration infeasible. However, the *perception* of security they provide often leads developers to skip authorization checks entirely, creating a false sense of protection that collapses when identifiers leak.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **UUID leakage via other endpoints** | Harvesting UUIDs from user listings, search results, activity feeds, or shared links, then using them on unprotected endpoints | UUID treated as a secret rather than an identifier; no authz check on consuming endpoint |
| **UUID leakage via error messages** | Application returns UUIDs in error responses (e.g., "User `abc-def-123` not found") | Verbose error messages expose internal identifiers |
| **UUID leakage via client-side code** | JavaScript source, HTML comments, or API responses embed UUIDs of other users' objects | Frontend leaks identifiers that backend trusts as "unguessable" |
| **UUIDv1 timestamp prediction** | UUIDv1 encodes timestamp and MAC address; if generation time is known, the UUID space can be narrowed dramatically | Application uses UUIDv1 instead of UUIDv4; attacker knows approximate creation time |
| **Weak PRNG UUID generation** | UUID generated with weak random source (e.g., `Math.random()` in JavaScript) can be predicted | Custom UUID generation with insufficient entropy |
| **UUID format downgrade** | Swapping a UUID with a simple integer (e.g., `id=1` instead of `id=550e8400-...`) and the backend accepts both formats | Backend ORM/DB accepts multiple ID formats without distinguishing them |

### §1-3. Encoded and Hashed Identifiers

Applications sometimes encode or hash identifiers to obscure them, treating the obscurity as an authorization mechanism. These are security-through-obscurity measures that collapse under analysis.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Base64-encoded ID decoding** | Decoding `aWQ9MTIz` reveals `id=123`; attacker encodes a different ID and submits it | Base64 used as sole "protection"; no server-side authorization |
| **Reversible encryption** | Identifiers encrypted with a static or leaked key; attacker decrypts, modifies, and re-encrypts | Symmetric encryption with key exposed in client-side code or configuration leak |
| **Hash collision / rainbow table** | Short or low-entropy inputs hashed (e.g., MD5 of sequential integers); attacker pre-computes hash table | Hash of predictable input (e.g., `MD5(user_id)`) without salt or secret key |
| **HMAC without authorization** | Object references protected by HMAC but the application checks only HMAC validity, not ownership | Valid HMAC token for object X does not guarantee that user A should access object X |
| **JWT-embedded object ID** | Object identifier embedded in a JWT claim; modifying the claim (with weak/none algorithm or key confusion) changes the referenced object | JWT validation flaw combined with object ID in payload (see §4-4) |

### §1-4. String-Based and Semantic Identifiers

When identifiers are human-readable strings (usernames, email addresses, filenames, slugs), the attack surface shifts from enumeration to social engineering and public information gathering.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Username/email substitution** | Replacing `user=alice@corp.com` with `user=admin@corp.com` in API requests | Email/username used as object key without verifying caller identity matches |
| **Filename manipulation** | Changing `file=report_alice.pdf` to `file=report_bob.pdf` to access another user's document | Filename as direct reference to file system or storage object |
| **Slug/path guessing** | Accessing `/api/projects/secret-project-name` by guessing or discovering project slugs | Slug used as sole access control; no membership verification |
| **Wildcard and glob injection** | Submitting `id=*` or `username=*` to trigger pattern matching that returns all records | Backend interprets wildcard characters in identifier fields |

---

## §2. Parameter Location and Transport Vector

The same authorization flaw manifests differently depending on where the object identifier appears in the HTTP request. Attackers systematically test all parameter locations because authorization may be enforced for one transport vector but not another.

### §2-1. URL Path Parameters

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **REST path segment manipulation** | Changing `/api/users/123/orders` to `/api/users/456/orders` | RESTful routing extracts ID from path; no middleware-level authz |
| **Nested resource traversal** | Accessing `/api/orgs/1/users/2/documents/3` by substituting any segment | Authorization checks parent resource but not child, or vice versa |
| **Path version bypass** | Switching from `/api/v2/users/123` (protected) to `/api/v1/users/123` (unprotected legacy) | Older API versions lack authorization that newer versions enforce |

### §2-2. Query String Parameters

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Simple query parameter swap** | Changing `?account_id=100` to `?account_id=101` | Most common and simplest IDOR vector |
| **HTTP Parameter Pollution (HPP)** | Submitting duplicate parameters: `?user_id=attacker&user_id=victim`; backend uses last value while authorization checks first | Server-side parameter parsing precedence differs from authorization middleware |
| **Parameter addition** | Adding an unexpected parameter like `&admin=true` or `&user_id=victim` to a request that normally derives the ID from the session | Application prioritizes explicit parameters over session-derived values |

### §2-3. Request Body (JSON/XML/Form)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JSON body field substitution** | Changing `{"user_id": 123}` to `{"user_id": 456}` in POST/PUT/PATCH body | Body parameters used for object lookup without ownership verification |
| **Array wrapping** | Changing `{"id": 123}` to `{"id": [123, 456]}` to access multiple objects or bypass type-checking authorization | Backend accepts array where scalar expected; iterates without per-element authz |
| **Nested object injection** | Changing `{"id": 123}` to `{"user": {"id": 456}}` to bypass flat-parameter authorization checks | Authorization logic checks `body.id` but ORM binds from `body.user.id` |
| **XML entity / attribute injection** | In XML APIs, modifying `<userId>123</userId>` or injecting entity references to alter the resolved ID value | XML-based APIs with entity expansion enabled |
| **Mass assignment on object properties** | Sending additional fields like `{"user_id": 456, "role": "admin"}` that the API binds directly to the data model | API framework auto-binds all input fields to model (§5-2 BOPLA) |

### §2-4. HTTP Headers and Cookies

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Custom header injection** | Modifying `X-User-Id: 123` or `X-Account-Id: 456` headers that internal services trust | Headers set by reverse proxy or API gateway; attacker can inject/override them |
| **Cookie value manipulation** | Changing a cookie like `user_session=base64(user_id=123)` to reference a different user | Object reference embedded in cookie value rather than server-side session |
| **Referer/Origin-based access** | Application grants access based on `Referer` header containing the "correct" object URL | Referer used as implicit authorization signal |

### §2-5. WebSocket and Real-Time Channels

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WebSocket message ID swap** | After establishing a WebSocket connection, sending messages with another user's channel/room ID | WebSocket authorization performed only at connection time, not per-message |
| **Subscription channel hijacking** | Subscribing to a real-time channel (e.g., `channel=user_456_notifications`) that belongs to another user | Pub/sub channel names derived from predictable identifiers without subscription authorization |

---

## §3. Authorization Logic Bypass Techniques

When authorization checks exist, attackers use structural manipulation techniques to circumvent them. These bypasses target the *implementation* of the check rather than the *absence* of one.

### §3-1. HTTP Method Tampering

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Method switching (GET ↔ POST)** | Authorization enforced on `GET /api/users/123` but not on `POST /api/users/123` or vice versa | Per-method authorization configuration; some methods unprotected |
| **PUT/PATCH/DELETE bypass** | Read operations protected but write/delete operations on the same resource lack authorization | Developers secure read paths but overlook mutation paths |
| **HEAD/OPTIONS information leak** | `HEAD /api/users/123` returns status code or headers revealing object existence without triggering authorization | HEAD method handler skips authorization middleware |
| **Method override headers** | Using `X-HTTP-Method-Override: DELETE` with a GET request to bypass method-based authorization rules | Framework supports method override; authorization checked against original method |

### §3-2. Encoding and Format Evasion

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **URL encoding** | Encoding the identifier (`%31%32%33` for `123`) to bypass string-matching authorization rules | Authorization performs string comparison without URL-decoding |
| **Double encoding** | Double-encoding (`%2531%2532%2533`) bypasses a single decode step in the authorization layer | Authorization decodes once; application decodes again |
| **Unicode normalization** | Using Unicode variants of digits or characters (e.g., fullwidth `１２３`) that normalize to the same value | Backend normalizes Unicode after authorization check |
| **Case manipulation** | Changing case of string identifiers (e.g., `UserName` vs `username`) when authorization is case-sensitive but lookup is case-insensitive | Case sensitivity mismatch between authorization and data layer |
| **JSON type juggling** | Sending `{"id": "123"}` (string) instead of `{"id": 123}` (integer) or `{"id": 123.0}` (float) to bypass type-strict checks | Authorization performs strict type comparison; backend coerces types |
| **Null byte injection** | Appending `%00` to an identifier to truncate it in one layer while passing through another | C-based string handling in authorization vs. length-aware handling in application |

### §3-3. Request Structure Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Content-Type switching** | Changing `Content-Type` from `application/json` to `application/x-www-form-urlencoded` or `multipart/form-data` to bypass body parsing in authorization middleware | Authorization middleware parses only one content type |
| **Parameter migration** | Moving the identifier from query string to body or vice versa to evade location-specific checks | Authorization checks query params; application also reads body params |
| **Batch request injection** | Embedding an unauthorized object reference within a batch/bulk API call (e.g., `POST /api/batch` with mixed authorized and unauthorized operations) | Batch endpoint performs authorization on the batch as a whole, not per-operation |
| **GraphQL alias abuse** | Using GraphQL aliases to request the same field with different IDs in a single query, bypassing per-query rate limiting or authorization | GraphQL resolver checks authorization per query but not per alias (§4-2) |

### §3-4. Indirect Reference Resolution Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Reference map prediction** | When applications use indirect reference maps (random tokens mapped to real IDs), predicting or brute-forcing the mapping tokens | Indirect reference map uses insufficient entropy or predictable generation |
| **Map pollution** | Injecting entries into the reference map to create a mapping from an attacker-controlled token to a victim's object ID | Reference map writable by the user (e.g., stored in client-side session) |
| **Cache key manipulation** | Accessing a cached response for another user's object by manipulating cache keys (e.g., stripping `Vary` headers or cache-buster parameters) | Cache does not include authorization context in cache key |

---

## §4. API Paradigm-Specific Vectors

Different API architectures and query languages introduce paradigm-specific attack surfaces for IDOR/BOLA.

### §4-1. REST API Vectors

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sub-resource traversal** | Accessing `/users/{victim_id}/settings` when authorized only for `/users/{attacker_id}/settings` | Per-resource authorization not enforced on nested routes |
| **Collection endpoint data leak** | Accessing `/api/users` or `/api/orders` listing endpoint that returns all records without filtering by ownership | Collection endpoints lack per-object filtering |
| **HATEOAS link following** | API responses include hypermedia links to related resources; following links intended for other users bypasses navigation-based access control | Authorization relies on "users will only follow their own links" |
| **Bulk/batch endpoint abuse** | `POST /api/bulk` accepting arrays of IDs where individual ID authorization is skipped for performance | Batch operations optimize away per-element authorization |

### §4-2. GraphQL Vectors

GraphQL's flexible query structure introduces unique IDOR surfaces absent in REST APIs.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Node/Global ID query** | Querying `node(id: "Base64EncodedGlobalId")` to access any object in the schema by its global ID | Relay-style `node` interface lacks per-type authorization |
| **Introspection-guided attack** | Using introspection to discover object types, fields, and relationships, then crafting queries to access unauthorized objects | Introspection enabled in production; reveals full authorization surface |
| **Nested relationship traversal** | Querying `user(id: attacker) { organization { users { privateData } } }` to traverse relationships to other users' data | Authorization checked on root field but not on resolved relationships |
| **Alias-based enumeration** | Using `a1: user(id: 1) { email } a2: user(id: 2) { email } ...` to enumerate objects in a single request, bypassing rate limits | Per-request rate limiting; no per-field authorization; aliases bypass rate logic |
| **Mutation argument tampering** | Modifying `mutation { updateUser(id: victim_id, input: {...}) }` to update another user's record | Mutation resolvers do not verify ownership of the target object |
| **Fragment-based field extraction** | Using fragments to selectively request sensitive fields that may have different authorization levels | Field-level authorization inconsistent across fragment expansion |

### §4-3. gRPC and Protocol Buffer Vectors

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Protobuf field number manipulation** | Modifying field numbers in serialized protobuf messages to reference different objects | gRPC services expose object IDs in protobuf fields without authorization |
| **Service method access** | Calling an internal gRPC service method (e.g., `AdminService.GetUser`) that lacks authorization because it's "internal" | Service mesh trusts all internal callers; no per-method authorization |

### §4-4. Webhook and Callback Vectors

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Webhook URL manipulation** | Registering a webhook for another user's events by specifying their user/resource ID in the webhook subscription | Webhook registration does not verify ownership of the subscribed resource |
| **Callback parameter injection** | OAuth/payment callbacks include object IDs in return URLs; modifying them redirects the callback result to the attacker's object | Callback handler trusts the object ID in the callback URL without re-verifying ownership |

---

## §5. Object Scope and Relationship Exploitation

IDOR/BOLA becomes more nuanced when targeting objects connected through relational hierarchies, multi-tenant boundaries, or property-level access rules.

### §5-1. Horizontal vs. Vertical Object Access

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Horizontal IDOR** | Accessing another user's resources at the same privilege level (e.g., User A reads User B's orders) | Most common IDOR pattern; no ownership check |
| **Vertical IDOR (privilege escalation)** | Accessing admin-only resources by referencing admin object IDs (e.g., accessing `/admin/config/1` as a regular user) | Role-based access control not enforced at object level |
| **Cross-role function access (BFLA crossover)** | User with role "viewer" accesses endpoints meant for "editor" role by referencing the same object IDs | Function-level and object-level authorization conflated; role check missing |

### §5-2. Object Property Level Manipulation (BOPLA)

BOPLA (Broken Object Property Level Authorization) is a refinement of BOLA where the attacker can access or modify specific *properties* of an object they may have partial access to.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sensitive field exposure** | API returns full object including fields the user shouldn't see (e.g., `password_hash`, `ssn`, `internal_notes`) | No field-level filtering based on requester's role/permissions |
| **Mass assignment / property injection** | Sending `{"role": "admin"}` or `{"balance": 99999}` alongside legitimate fields in an update request | Framework auto-binds request body to model; no whitelist of updatable fields |
| **Read-only field overwrite** | Modifying fields intended to be immutable (e.g., `created_by`, `owner_id`, `plan_tier`) via API request | API does not enforce field-level write permissions |
| **Partial update privilege bypass** | PATCH endpoint allows updating any field of an object the user can partially access | PATCH handler does not restrict which fields are modifiable per role |

### §5-3. Multi-Tenant and Cross-Organization Access

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-tenant ID reference** | User in Tenant A accesses resources belonging to Tenant B by using Tenant B's object IDs | Tenant isolation enforced at application level but not at data access layer |
| **Tenant ID manipulation** | Modifying `tenant_id`, `org_id`, or `workspace_id` in request parameters | Tenant scoping relies on client-supplied tenant identifier rather than session-derived |
| **Shared resource tenant leak** | Accessing shared/global resources that inadvertently expose tenant-specific data | Shared endpoints do not filter results by tenant context |
| **Sub-organization traversal** | Accessing sibling organizations' data within a hierarchical org structure by modifying org-level IDs | Authorization checks parent org membership but not specific sub-org |

### §5-4. Relational and Indirect Object Access

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Foreign key traversal** | Accessing related objects through foreign key relationships (e.g., `order.customer_id` → access customer record) | Authorization on primary object does not extend to related objects |
| **Inverse relationship exploitation** | Querying from the "other side" of a relationship (e.g., instead of `user/123/orders`, query `order/456` directly) | Authorization enforced on one traversal direction but not the reverse |
| **Aggregation endpoint data leak** | Endpoints like `/api/stats?group_by=user_id` or `/api/reports` aggregate data across users without ownership filtering | Aggregation queries bypass row-level security |

---

## §6. Observation Model: Blind and Second-Order IDOR

Not all IDOR exploitation produces immediately visible results. Understanding the feedback model is critical for both exploitation and detection.

### §6-1. Direct (Visible) IDOR

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Data in response body** | Unauthorized data returned directly in the HTTP response | Classic IDOR; immediate confirmation of exploitation |
| **Status code differential** | Different HTTP status codes for existing vs. non-existing objects reveal object existence | `200` for valid IDs vs `404` for invalid; enables enumeration even without data exposure |
| **Response timing differential** | Measurably different response times for valid vs. invalid object IDs | Database lookup time varies; enables blind enumeration via timing side-channel |

### §6-2. Blind IDOR

In blind IDOR, the attacker's action succeeds on the victim's object, but the attacker receives no direct confirmation in the response.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Write-only blind IDOR** | Modifying another user's data (e.g., changing their email, deleting their items) without receiving the data back | Write endpoint returns generic success response; victim observes the change |
| **Side-effect blind IDOR** | Triggering actions on another user's behalf (e.g., sending password reset, unsubscribing from service, triggering notification) | Action endpoint does not return target user's data but executes the side effect |
| **Blind enumeration via error differential** | Error messages differ subtly for authorized-but-missing vs. unauthorized objects (e.g., "Not found" vs. "Forbidden") | Error response leaks authorization state |

### §6-3. Second-Order IDOR

The exploitation effect manifests in a *different* functionality or at a *later time* than the initial injection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Audit log injection** | Manipulated object reference gets logged; viewing audit logs reveals other users' data that was resolved at log time | Authorization checked on the action but not on the data rendered in logs |
| **Report/export data leak** | Injected object reference included in a generated report, export, or notification sent later | Batch job processes stored references without re-checking authorization |
| **Notification channel hijack** | Modifying a notification target (e.g., webhook URL, email) on another user's object; subsequent events notify the attacker | Object modification succeeds (blind IDOR); data exfiltrated via notification pipeline |
| **Cached result poisoning** | Writing unauthorized data into a cache entry that is later served to legitimate users or the attacker | Cache key does not include authorization context; stale authz state |

---

## §7. Temporal and State-Based Manipulation

Authorization decisions can be invalidated by timing attacks, state transitions, and workflow manipulation.

### §7-1. Race Condition / TOCTOU IDOR

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Concurrent request authorization bypass** | Sending simultaneous requests to change object ownership and access the object; one request passes the check before the other changes state | Non-atomic check-then-act pattern in authorization |
| **Permission change race** | Accessing a resource in the window between permission revocation and enforcement | Asynchronous permission propagation; cached authorization decisions |
| **Token refresh race** | Using an old session/token to access objects during the window where a new token (with restricted permissions) is being issued | Token validation cached; revocation not instant |

### §7-2. Workflow and State Transition Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Multi-step process ID swap** | In a multi-step workflow (e.g., create → configure → submit), swapping the object ID between steps to attach the attacker's actions to the victim's object | Authorization checked at step 1 but not re-verified at subsequent steps |
| **Draft/pending state access** | Accessing objects in pre-publication states (e.g., draft posts, pending orders) via direct ID reference | State-based visibility not enforced at the object access layer |
| **Archived/deleted object resurrection** | Accessing soft-deleted or archived objects by directly referencing their IDs | Soft-delete sets a flag but object remains queryable via direct reference |
| **State rollback exploitation** | Triggering a state rollback (e.g., undo, revert) on another user's object to restore access to previously restricted data | Rollback functionality does not re-check authorization against current permissions |

---

## §8. Architectural and Deployment Context Exploitation

The deployment architecture of modern applications creates authorization gaps at system boundaries that individual services may not address.

### §8-1. Microservice Trust Boundary Violations

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Inter-service trust assumption** | Service A authenticates the user and passes user context to Service B; Service B trusts Service A's authorization without re-checking | "Trusted caller" pattern between microservices; no end-to-end authorization |
| **API gateway bypass** | Directly accessing a backend microservice endpoint that skips the API gateway's authorization layer | Backend service exposed on an internal network but reachable via SSRF or misconfigured networking |
| **Service mesh token reuse** | Using a service-to-service token obtained for one purpose to access objects in a different service | Coarse-grained service tokens without object-level scope |

### §8-2. Mobile and Client-Side Specific Vectors

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Mobile API parameter exposure** | Mobile app sends object IDs that are hidden in the UI but visible in intercepted traffic (e.g., via Burp Suite/mitmproxy) | Mobile backend trusts client-side UI restrictions as access control |
| **Offline cache exploitation** | Mobile app caches objects locally with their IDs; reverse-engineering the cache reveals IDs usable against the API | Local storage/cache contains IDs for objects beyond the user's authorization scope |
| **Deep link / URL scheme abuse** | Crafting a deep link like `myapp://user/456/profile` to trigger the app to fetch another user's profile without authorization | Deep link handler does not verify authorization before fetching referenced object |

### §8-3. Cloud and Infrastructure Layer Vectors

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cloud storage object ID guessing** | Accessing `https://bucket.s3.amazonaws.com/user_456_document.pdf` by modifying the filename pattern | Cloud storage objects named with predictable patterns; no per-object IAM policy |
| **Serverless function context leak** | Lambda/Cloud Function reuses execution context between invocations, leaking object references from previous requests | Serverless execution reuse without clearing request-scoped authorization state |
| **Shared database without row-level security** | Multiple microservices share a database; one service queries without tenant/user filtering that another service enforces | Shared datastore; authorization enforced in application layer, not database layer |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **Horizontal data access** | Any web/API application | §1 + §2 + §6-1 | PII exposure, privacy violation |
| **Vertical privilege escalation** | Role-based systems | §5-1 + §3-1 + §5-2 | Admin access, configuration control |
| **Cross-tenant breach** | Multi-tenant SaaS | §5-3 + §8-1 + §2-3 | Full tenant data compromise |
| **Mass data exfiltration** | APIs with enumerable IDs | §1-1 + §6-1 + §4-1 | Large-scale data breach |
| **Account takeover chain** | Applications with profile/settings APIs | §2-3 + §6-2 + §7-2 | Email/password change → full ATO |
| **Financial manipulation** | Payment/billing systems | §5-2 + §7-1 + §3-3 | Balance manipulation, unauthorized transactions |
| **Destructive blind IDOR** | Any write-enabled API | §6-2 + §3-1 + §2-2 | Data deletion, service disruption |
| **Supply chain compromise** | CI/CD and artifact systems | §8-1 + §4-3 + §5-3 | Unauthorized build/deploy modification |
| **IoT/device takeover** | IoT management platforms | §8-2 + §1-1 + §5-3 | Device control, firmware manipulation |

---

## CVE / Bug Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-1 + §4-1 (Sequential ID + REST sub-resource) | CVE-2024-1313 (Grafana) | Dashboard snapshot access by unauthenticated users in Grafana (20M+ users). Patch in v10.4.1 |
| §1-1 + §5-3 (Sequential ID + multi-tenant) | CVE-2024-46528 (KubeSphere v3.4.1/v4.1.1) | Low-privileged users access sensitive Kubernetes cluster resources across tenants |
| §4-1 + §5-1 (REST endpoint + horizontal access) | CVE-2023-3285 through CVE-2023-3290 (Easy!Appointments) | 6 BOLA vulnerabilities in this CVE range. Full patient/appointment data access |
| §4-1 + §8-1 (REST + microservice trust) | CVE-2024-22278 (Harbor) | BOLA in cloud-native container registry; unauthorized access to container images and repositories |
| §1-1 + §2-1 (Sequential ID + path param) | CVE-2024-56404 (One Identity Manager 9.x) | Identity management system IDOR; access to identity records across the enterprise |
| §2-3 + §5-2 (Body param + mass assignment) | CVE-2024-1626 (Lunary AI) | IDOR in AI platform allowing unauthorized data access |
| §1-1 + §5-1 (Numeric ID + horizontal) | CVE-2024-55471 (Oqtane Framework) | IDOR allowing cross-user data access in .NET CMS framework |
| §1-1 + §2-1 (Numeric param + path param) | CVE-2025-40658 (DM Corporative CMS < 2025.01) | CVSS 7.5. IDOR in admin panel via `option` parameter manipulation in `/administer/selectionnode/framesSelection.asp`. |
| §1-1 + §6-1 (Enumerable ID + direct feedback) | HackerOne #PayPal | $10,500. IDOR to add secondary users in PayPal business account management |
| §6-2 + §3-1 (Blind IDOR + method bypass) | HackerOne #various | $12,500. IDOR allowing deletion of licenses/certifications from other users' profiles |
| §5-3 + §8-3 (Cross-tenant + cloud) | Growatt Solar IoT (2025) | BOLA in solar inverter API allowed hackers to take control of IoT devices across organizations |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **BOLABuster** (Palo Alto Unit 42) | REST APIs with OpenAPI spec | LLM-driven analysis of API specifications; generates BOLA test cases automatically; sends <1% of requests vs. traditional fuzzers |
| **Autorize** (Burp Extension) | Any web application via proxy | Replays requests with low-privilege sessions; compares responses to detect authorization bypass |
| **AuthMatrix** (Burp Extension) | Web apps with role-based access | Matrix-based testing of users × endpoints × methods; highlights authorization gaps visually |
| **APIsec Scanner** | REST and GraphQL APIs | Automated BOLA detection with business logic understanding; CI/CD integration |
| **Cloudflare API Shield** | APIs behind Cloudflare | Runtime BOLA detection via traffic pattern analysis; labels endpoints with `cf-risk-bola-enumeration` and `cf-risk-bola-pollution` |
| **Akto** | REST and GraphQL APIs | BOLA testing via parameter pollution; automated test generation from API traffic |
| **Cequence UAP** | Enterprise API platforms | Network-based API discovery + behavioral analysis; detects enumeration patterns at runtime |
| **InQL** (Burp Extension) | GraphQL APIs | GraphQL introspection analysis; identifies queryable types and authorization test surfaces |
| **GraphQL Voyager** | GraphQL APIs | Schema visualization; maps relationship graph for identifying authorization-critical traversal paths |
| **Nuclei** (ProjectDiscovery) | General vulnerability scanning | Template-based scanning with IDOR-specific templates for common patterns |
| **OWASP ZAP Access Control Plugin** | Web applications | Access control testing through user-context comparison |

---

## Summary: Core Principles

**The fundamental property that makes IDOR/BOLA the most persistent web vulnerability class is the decoupling of authentication from authorization.** Modern web frameworks universally provide authentication middleware (session management, JWT validation, OAuth flows) that developers adopt by default. However, no framework can automatically determine *which* authenticated user should access *which* specific object — this is inherently a business logic decision. The result is a systematic gap: developers correctly verify *who* the user is, but neglect to verify *what* the user should access. Every endpoint that accepts a user-supplied object identifier is a potential IDOR surface, and with the proliferation of RESTful APIs, GraphQL, and microservices, the number of such endpoints per application has grown from dozens to thousands.

**Incremental fixes fail because IDOR is not a single bug but an architectural omission.** Patching one endpoint leaves hundreds of others unprotected. Replacing sequential IDs with UUIDs shifts the attack from enumeration to leakage exploitation without addressing the root cause. Adding API gateways moves the authorization problem rather than solving it. Even automated scanning tools struggle because BOLA is a *semantic* flaw — determining whether User A should access Object X requires understanding the application's business rules, not just its HTTP behavior. This is why BOLA has maintained its #1 position in the OWASP API Security Top 10 since 2019.

**The structural solution requires authorization-by-default architecture:** every data access operation must pass through an authorization layer that evaluates ownership/permission before returning data. This can be implemented as database-level row-level security (RLS) policies, ORM-level query scoping (e.g., always filtering by `tenant_id` and `user_id`), or middleware-level policy engines (e.g., OPA, Casbin, Cedar). The key architectural principle is that authorization must be **mandatory and inescapable** — no code path should be able to access an object without passing through the authorization gate. Combined with comprehensive integration testing that verifies cross-user access is denied for every endpoint (using tools like Autorize or BOLABuster), this transforms IDOR from an endpoint-by-endpoint patching problem into a systemic guarantee.

---

## References

- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP Insecure Direct Object Reference Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
- CWE-639: Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- Unit 42 — Harnessing LLMs for Automating BOLA Detection (BOLABuster): https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/
- Unit 42 — BOLA Vulnerabilities in Easy!Appointments: https://unit42.paloaltonetworks.com/bola-vulnerabilities-easyappointments/
- Unit 42 — BOLA Vulnerability in Harbor: https://unit42.paloaltonetworks.com/bola-vulnerability-impacts-container-registry-harbor/
- PortSwigger Web Security Academy — Insecure Direct Object References: https://portswigger.net/web-security/access-control/idor
- Cloudflare API Shield — BOLA Detection: https://developers.cloudflare.com/api-shield/security/bola-vulnerability-detection/
- HackerOne Top IDOR Reports: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPIDOR.md
- Intigriti — Complete Guide to Exploiting Advanced IDOR Vulnerabilities: https://www.intigriti.com/blog/news/idor-a-complete-guide-to-exploiting-advanced-idor-vulnerabilities
- Fortbridge — IDOR Exploitation via HPP Case Study: https://fortbridge.co.uk/research/idor-exploitation-via-hpp-api-hacking-case-study/
- Escape.tech — IDOR in GraphQL: https://escape.tech/blog/idor-in-graphql/

---

*This document was created for defensive security research and vulnerability understanding purposes.*
