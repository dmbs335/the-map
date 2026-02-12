# Mass Assignment / Autobinding Mutation & Variation Taxonomy

---

## Classification Structure

Mass assignment (also called autobinding, overposting, or object injection depending on the framework) is a vulnerability class that arises when web frameworks automatically bind user-supplied HTTP parameters to internal object properties without adequate filtering. The fundamental premise is simple: if a framework maps `request.parameter("X")` → `object.setX(value)` for *all* supplied parameters, any property accessible through the binding mechanism becomes attacker-controllable — including properties the developer never intended to expose.

This taxonomy organizes the attack surface along three axes:

**Axis 1 — Mutation Target (WHAT is injected)**: The structural category of the property or field being manipulated. This is the primary organizational axis, forming the main body of the document.

**Axis 2 — Binding Mechanism (HOW it binds)**: The cross-cutting dimension describing which framework binding pathway enables the injection. Each mutation target may be exploitable through one or more binding mechanisms.

| Binding Mechanism | Description | Primary Frameworks |
|---|---|---|
| **Form/Query Parameter Binding** | HTTP form fields or query params mapped to object setters | Spring MVC, ASP.NET MVC, Rails |
| **JSON/XML Body Binding** | Deserialized request body mapped to object properties | All REST API frameworks |
| **ORM Active Record Pattern** | Object-relational mapper auto-persists all set properties | Rails ActiveRecord, Laravel Eloquent, Sequelize |
| **GraphQL Mutation Binding** | Mutation input types bound to resolver objects | GraphQL servers (Apollo, Hasura, etc.) |
| **gRPC/Protobuf Field Binding** | Protobuf message fields bound to handler objects | gRPC service implementations |
| **Property Chain Traversal** | Dot-notation navigates nested object graph (e.g., `class.module.classLoader`) | Spring MVC, Java Beans |
| **Prototype/Constructor Pollution** | `__proto__` or `constructor.prototype` injection pollutes object hierarchy | Node.js (Express, Mongoose, Lodash merge) |

**Axis 3 — Impact Scenario (WHERE it's weaponized)**: The architectural context determining the severity of exploitation. See §8 for the full mapping.

---

## §1. Privilege & Role Escalation Properties

The most classic and impactful category of mass assignment — injecting values into authorization-controlling fields to elevate the attacker's access level.

### §1-1. Boolean Administrative Flags

The simplest and most frequently exploited pattern. The target object contains a boolean property controlling administrative status, and the attacker includes it in a creation or update request.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **isAdmin / is_admin injection** | Attacker adds `isAdmin=true` or `"is_admin": true` to registration/update request | Admin flag exists as a direct model property without binding restriction |
| **isSuperUser / superuser injection** | Same pattern targeting superuser-level flags | Framework uses superuser concept (Django, custom RBAC) |
| **isActivated / is_verified injection** | Bypasses email verification or account activation by setting `email_verified=true` | Verification status stored as model boolean |
| **isApproved injection** | Skips manual approval workflow by directly setting approval flag | Applications with admin-gated user approval |

**Example payload (JSON body):**
```json
POST /api/v1/users/register
{
  "username": "attacker",
  "password": "s3cret",
  "email": "attacker@evil.com",
  "isAdmin": true,
  "email_verified": true
}
```

### §1-2. Role/Permission String and Enum Fields

Rather than a boolean flag, the application uses a string or enum `role` field. The attacker overwrites it with a higher-privilege value.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Role string overwrite** | `"role": "admin"` or `"role": "superadmin"` injected into user creation/update | Role stored as plain string on user model |
| **Permission array injection** | `"permissions": ["read","write","admin"]` appended to request | Permissions stored as array/list on user model |
| **Group/team assignment** | `"group_id": 1` (admin group) injected | Group membership determined by foreign key on user model |
| **Multi-tenancy tenant escalation** | `"tenant_id": "target_org"` forces user into another organization | Tenant isolation relies on model-level tenant_id |

### §1-3. Account State Manipulation

Fields controlling account lifecycle that grant indirect privilege through state transitions.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Account status override** | `"status": "active"` on a suspended/banned account update | Status field writable via binding |
| **Trial/subscription tier escalation** | `"plan": "enterprise"` or `"subscription_tier": 3` | Billing tier stored on user or org model |
| **Rate limit / quota bypass** | `"api_calls_remaining": 999999` or `"quota_limit": -1` | Quota tracked as model property |
| **Feature flag manipulation** | `"features": {"beta_access": true, "premium": true}` | Feature toggles stored as user-level properties |

---

## §2. Object Identity & Ownership Manipulation

Attacks targeting the identity of the object itself — changing WHO owns it, WHICH record is affected, or HOW objects relate to each other.

### §2-1. Primary Key / ID Injection

Injecting or overwriting the object's primary key to target another record.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ID overwrite on creation** | `"id": 1` injected into POST to overwrite existing record (e.g., admin user) | ORM accepts client-supplied ID without auto-generation enforcement |
| **ID substitution on update** | Changing `"id"` in PUT/PATCH body to modify a different user's record | Server trusts body ID over URL path ID |
| **UUID collision** | Supplying a known UUID to claim another user's record | UUID not validated against authenticated user |
| **Numeric overflow ID** | Submitting `"id": 1e99999` or `"id": 2147483647` to cause integer overflow | Backend language converts to float/overflow, disrupting DB operations |

### §2-2. Foreign Key & Relationship Manipulation

Modifying foreign keys to reassign object ownership or association.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **user_id / owner_id reassignment** | `"user_id": 3` changes which user owns the resource | Foreign key included in model binding scope |
| **org_id / team_id hijack** | `"organization_id": "target_org"` moves resource across org boundary | Multi-tenant association via FK |
| **Parent object reassignment** | `"parent_id": 42` or `"category_id": 1` alters object hierarchy | Hierarchical models with bindable FK |
| **Polymorphic association abuse** | `"commentable_type": "Admin", "commentable_id": 1` changes associated type | Rails-style polymorphic associations with exposed type field |

### §2-3. Token & Credential Overwrite

Directly modifying authentication-related fields to hijack accounts.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Password hash overwrite** | `"password_digest": "attacker_hash"` directly sets stored credential | Password hash field exposed to binding |
| **Reset token overwrite** | Injecting `"reset_token": "attacker_controlled_value"` during profile update | Reset token stored as model attribute without binding protection |
| **API key overwrite** | `"api_key": "known_value"` replaces victim's API key | API key field writable via mass assignment |
| **OAuth token injection** | `"access_token"` or `"refresh_token"` fields set via binding | Token fields stored directly on user model |

---

## §3. Financial & Business Logic Properties

Properties controlling monetary values, transactions, and business-critical calculations.

### §3-1. Price & Amount Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Price override** | `"price": 0.01` on order creation sets item price to near-zero | Price stored on order line item model |
| **Discount injection** | `"discount": 100` or `"discount_percentage": 99.9` | Discount field exists on order/cart model |
| **Balance/credit injection** | `"balance": 999999` or `"credits": 10000` directly sets account funds | Balance tracked as user model property |
| **Currency manipulation** | `"currency": "KRW"` combined with amount in USD-scale numbers | Currency code on transaction model |

### §3-2. Transaction State Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Order status forgery** | `"status": "returned"` on a delivered order to fraudulently claim refund | Order status writable via binding |
| **Payment status bypass** | `"payment_status": "paid"` or `"is_paid": true` without actual payment | Payment flag on order model |
| **Shipping address swap post-payment** | Modifying delivery address after payment to redirect goods | Address field remains writable after order confirmation |
| **Quantity manipulation** | `"quantity": -1` to trigger negative pricing or refund | Quantity field without server-side validation |

---

## §4. Temporal & Lifecycle Properties

Fields controlling timestamps, deadlines, and object lifecycle that can be abused through mass assignment.

### §4-1. Timestamp Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **created_at / updated_at forgery** | Backdating or future-dating records for audit manipulation | ORM timestamps not protected from binding |
| **Expiration extension** | `"expires_at": "2099-12-31"` extends trial, license, or session lifetime | Expiry tracked as model field |
| **Cooldown/lockout bypass** | `"locked_until": "2000-01-01"` clears account lockout | Lockout timestamp stored on user model |
| **Scheduling manipulation** | `"publish_at"` or `"scheduled_for"` altered to bypass review periods | Content scheduling via model timestamp |

### §4-2. Counter & Sequence Manipulation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Login attempt counter reset** | `"failed_attempts": 0` clears brute-force protection | Counter stored on user model |
| **Version/revision override** | `"version": 999` or `"revision"` field manipulation | Optimistic locking field writable |
| **Sequence number injection** | Manipulating auto-increment or ordering fields | Sort order or sequence stored as model property |

---

## §5. Property Chain & Object Graph Traversal

The most dangerous category — exploiting the framework's ability to navigate nested properties via dot-notation or nested parameter syntax to reach objects far beyond the intended binding target.

### §5-1. Java Class Loader Access (Spring4Shell Pattern)

The landmark exploitation of property chaining in Spring MVC that culminated in CVE-2022-22965 (Spring4Shell, CVSS 9.8). When Java Beans binding processes a parameter like `class.module.classLoader.X`, it traverses: `getClass()` → `getModule()` → `getClassLoader()` → arbitrary classloader properties.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **ClassLoader property manipulation** | `class.module.classLoader.resources.context.parent.pipeline.first.*` modifies Tomcat AccessLogValve | Spring MVC + JDK 9+ + Tomcat WAR deployment |
| **Web shell via log manipulation** | Chaining classloader → Tomcat pipeline → AccessLogValve to write JSP web shell | Tomcat write access to webapps/ROOT |
| **Environment variable access** | Property chains reaching `System.getenv()` or environment configuration | Framework exposes environment through object graph |

**Exploit payload (HTTP parameters):**
```
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar
class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
```

### §5-2. Nested Object Property Injection

Exploiting frameworks that support nested parameter binding (e.g., `user.address.city`, `user[profile][bio]`).

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Deep nested property write** | `user.profile.internal_notes=malicious` writes to associated objects | Framework supports automatic nested binding |
| **Association creation via nesting** | `user[roles_attributes][0][name]=admin` creates associated role record | Rails accepts_nested_attributes_for without strict filtering |
| **Cross-entity traversal** | `order.customer.credit_limit=999999` navigates relationships | ORM eagerly resolves relationship chains during binding |

### §5-3. Prototype & Constructor Pollution (JavaScript)

In Node.js ecosystems, the mass assignment vector merges with prototype pollution when user-supplied JSON is unsafely merged into objects.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **__proto__ injection** | `{"__proto__": {"isAdmin": true}}` pollutes Object.prototype | Unsafe recursive merge (lodash.merge, deep-extend) |
| **constructor.prototype injection** | `{"constructor": {"prototype": {"role": "admin"}}}` | Object.assign or for...in loop triggers setter |
| **Mongoose schema pollution** | Prototype pollution through Schema.prototype.add() recursion | Mongoose ≤ vulnerable versions, CVE-2023-3696 |
| **Template engine RCE via pollution** | Polluted prototype triggers code execution in EJS/Pug/Handlebars rendering | Express + EJS with polluted `outputFunctionName` or `client` |

---

## §6. Data Type & Format Confusion

Exploiting mismatches between expected and supplied data types to bypass validation or trigger unexpected behavior.

### §6-1. Type Coercion Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Boolean-to-string confusion** | Sending `"isAdmin": "true"` (string) or `"isAdmin": 1` (integer) to bypass type-specific checks | Loose type comparison in validation (PHP `==`, JS truthy) |
| **Array where scalar expected** | `"email": ["victim@x.com", "attacker@y.com"]` associates multiple values | Framework/ORM accepts array without type enforcement |
| **Nested object where string expected** | `"name": {"toString": "admin"}` triggers object method invocation | Language-level type coercion |
| **Numeric string injection** | `"role": "0"` or `"role": "1"` in enum-mapped fields | Role stored as integer but accepted as string |

### §6-2. Encoding & Format Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Content-Type switching** | Sending form data as `application/json` or vice versa to reach different binding code paths | Framework uses different binders per content type |
| **Multipart boundary manipulation** | Injecting additional fields via multipart form boundaries | File upload endpoints with additional field binding |
| **XML entity injection via binding** | Using XML body binding to inject fields with XXE payload | Framework accepts `application/xml` for model binding |
| **Parameter name encoding** | URL-encoding or Unicode variants of field names (`is%41dmin`) | Binding mechanism decodes before matching |

---

## §7. Framework Protection Bypass Techniques

Techniques specifically designed to circumvent mass assignment protections that frameworks have implemented.

### §7-1. Allowlist/Blocklist Evasion

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Case sensitivity bypass** | `"IsAdmin"` vs `"isAdmin"` vs `"isadmin"` — different casing to evade string-match blocklists | Case-insensitive DB column but case-sensitive filter |
| **Alternative field naming** | `"admin"`, `"is_admin"`, `"isAdmin"`, `"user_type"` — trying synonyms | Blocklist misses alias or alternate column name |
| **Underscore/camelCase mismatch** | `"is_admin"` passes filter that blocks `"isAdmin"` | Framework normalizes naming convention after filtering |
| **attr_protected bypass (Rails < 3.2)** | Known bypass of the blocklist approach in older Rails versions | Using attr_protected instead of attr_accessible |

### §7-2. Binding Pathway Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **create_with / where bypass (Rails)** | `.where()` or `.create_with()` bypasses Strong Parameters entirely | Developer uses query builder methods instead of `.create()` |
| **:without_protection flag** | Explicitly disabling mass assignment protection in method call | Developer convenience shortcut left in production code |
| **TryUpdateModel whitelist gap (ASP.NET)** | [Bind] attribute sets excluded fields to null/default instead of leaving unchanged | Edit scenario where null-reset causes logic error |
| **JSON deserializer bypass** | `@RequestBody` uses Jackson/GSON which ignores Spring's `@InitBinder` restrictions | Different binding pipeline for JSON vs form parameters |
| **Unprotected endpoints** | Some endpoints bypass the protection middleware entirely | Developer inconsistency across controllers |

### §7-3. ORM-Level Bypasses

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Raw query fallback** | Using `Model.update_all()` or raw SQL that bypasses ORM mass-assignment guards | Developer uses bulk operations for performance |
| **$guarded override (Laravel)** | Setting `$guarded = []` (empty array) disables all protection | Developer misunderstanding: empty guarded ≠ fully guarded |
| **Fillable wildcard** | `$fillable = ['*']` or `Model::unguard()` globally disables protection | Seeder/migration code accidentally left in production |
| **Nested attributes bypass** | Modifying child records through parent's `accepts_nested_attributes_for` | Nested attributes not independently filtered |

---

## §8. Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|---|---|---|---|
| **Privilege Escalation** | Any app with role-based access | §1-1, §1-2 | Admin access, full system control |
| **Account Takeover** | User management APIs | §2-3, §1-3 | Credential/token overwrite, session hijack |
| **Horizontal Data Access** | Multi-tenant SaaS | §2-1, §2-2, §1-2 | Cross-tenant data breach |
| **Financial Fraud** | E-commerce, fintech APIs | §3-1, §3-2 | Price manipulation, fraudulent refunds |
| **Remote Code Execution** | Spring MVC on Tomcat (JDK 9+) | §5-1 | Web shell, full server compromise |
| **Prototype Pollution → RCE** | Node.js with template engines | §5-3 | Server-side template injection → RCE |
| **Verification Bypass** | Registration / onboarding flows | §1-1 (email_verified), §4-1 | Unverified account gains full access |
| **Audit Trail Manipulation** | Compliance-sensitive applications | §4-1, §4-2 | Tampered timestamps, false records |
| **Denial of Service** | Any application | §2-1 (numeric overflow), §4-2 | Application crash, data corruption |
| **Business Logic Bypass** | Workflow-driven applications | §1-3, §3-2, §4-1 | Skipped approval, bypassed cooldowns |

---

## §9. CVE / Real-World Incident Mapping

| Mutation Category | CVE / Incident | Product | Impact |
|---|---|---|---|
| §5-1 (ClassLoader chain) | **CVE-2022-22965** (Spring4Shell) | Spring Framework (JDK 9+, Tomcat WAR) | CVSS 9.8 — RCE via web shell. Mirai botnet weaponized. |
| §1-2 (Role escalation) | **GitHub 2012 Incident** | GitHub (Rails) | Egor Homakov uploaded SSH key to Rails org, committed to master. Catalyzed Rails' `strong_parameters`. |
| §1-1 (Admin flag) | **CVE-2024-40531** | Langflow < 1.0.13 | Privilege escalation to super admin via `/api/v1/users` mass assignment. |
| §1-1 + §7-2 | **CVE-2024-** (AnythingLLM) | mintplex-labs/anything-llm | Manager → Admin escalation via unfiltered system preferences endpoint. |
| §1-1 + §7-3 | **CVE-2025-2304** | Camaleon CMS < 2.9.1 | `permit!` (allow-all) in UsersController enabled full privilege escalation. |
| §5-3 (Prototype pollution) | **CVE-2023-3696** | Mongoose (Node.js) | Prototype pollution via `findByIdAndUpdate()` → RCE in Express+EJS apps. |
| §5-3 (Prototype pollution) | **SNYK-JS-MONGOOSE-1086688** | Mongoose Schema | Schema.prototype.add() recursive pollution. |
| §7-3 ($guarded bypass) | **GHSA-rj3w-99gc-8j58** | Laravel (historical) | Insufficient sanitization allowed bypass of guarded column protection. |
| §3-2 (Order status) | **crAPI Lab** | OWASP crAPI | Marking delivered items as "returned" for fraudulent refunds. |

---

## §10. Detection & Testing Tools

| Tool | Type | Target Scope | Core Technique |
|---|---|---|---|
| **Burp Suite Param Miner** | Offensive (Burp Extension) | REST/JSON APIs | Automatic guessing of up to 65,536 hidden JSON parameters per request. Custom wordlists tunable to discovered schemas. |
| **RestTestGen** | Research (Open Source) | RESTful APIs (OpenAPI spec) | Black-box mass assignment detection via OpenAPI spec clustering. Groups operations, identifies read-only fields, generates exploit sequences. (ICSE 2023) |
| **CATS** | Offensive/Fuzzer (Open Source) | REST APIs (OpenAPI/Swagger) | Automated negative testing including field injection and type confusion. Zero-code configuration. |
| **Brakeman** | Defensive (SAST) | Ruby on Rails | Static analysis detecting missing `attr_accessible`, unprotected models, and `permit!` usage. |
| **APIFuzzer** | Offensive (Open Source) | REST APIs (OpenAPI/Swagger) | Fuzz testing from API spec without coding. Mutates parameters and injects unexpected fields. |
| **RESTler** | Offensive (Microsoft, Open Source) | RESTful APIs | Stateful API fuzzing understanding inter-request dependencies. Finds complex bugs across API call sequences. |
| **Arjun / msarjun** | Offensive (Open Source) | HTTP endpoints | Mass-scale hidden parameter discovery via brute-force with optimized heuristics. |
| **Snyk / Dependabot** | Defensive (SCA) | Dependencies | Detects known vulnerable framework versions with mass assignment CVEs. |
| **OWASP ZAP** | Offensive (Open Source) | Web applications | Active scanning with parameter injection rules including mass assignment checks. |

---

## §11. Framework-Specific Protection Reference

| Framework | Vulnerability Name | Allowlist Approach | Blocklist Approach | Recommended Approach |
|---|---|---|---|---|
| **Spring MVC** | Autobinding | `@InitBinder` + `setAllowedFields()` | `setDisallowedFields()` | DTOs + `@InitBinder` allowlist |
| **ASP.NET MVC/Core** | Overposting | `[Bind(Include="...")]`, `TryUpdateModel` with property list | `[Bind(Exclude="...")]` | View Models / DTOs |
| **Ruby on Rails** | Mass Assignment | `strong_parameters` — `params.require(:user).permit(:name, :email)` | *(deprecated: `attr_protected`)* | Strong Parameters (default since Rails 4) |
| **Laravel (PHP)** | Mass Assignment | `$fillable` array on model | `$guarded` array on model | `$fillable` + `validated()` from Form Requests |
| **Django** | *(Less common)* | `ModelForm` with explicit `fields` | `ModelForm` with `exclude` | Explicit `fields` in serializers/forms |
| **Node.js / Express** | Mass Assignment | `_.pick(req.body, ['field1', 'field2'])` | Mongoose `protect: true` plugin | Schema validation (Joi, Zod) + explicit field picking |
| **GraphQL** | Mutation Injection | Strict input types, field-level resolvers | — | Separate Input types from internal models |
| **gRPC / Protobuf** | Field Injection | Explicit field validation in handlers | — | Input validation on every RPC handler |

---

## §12. Summary: Core Principles

**The Fundamental Property.** Mass assignment vulnerabilities exist because of a design tension at the heart of modern web frameworks: the same convenience feature that eliminates boilerplate (automatic binding of HTTP parameters to object properties) creates an implicit trust boundary violation. The framework treats all incoming parameters as equally trustworthy, while the application's security model requires differential trust — some properties are user-modifiable, others are system-controlled. Every framework that implements auto-binding must resolve this tension, and every resolution introduces its own bypass surface.

**Why Incremental Fixes Fail.** The history of mass assignment — from Rails' `attr_protected` (bypassed) to `attr_accessible` (opt-in but missed) to `strong_parameters` (controller-level, different code path bypasses via `.where`/`.create_with`) — demonstrates that each layer of defense addresses only the binding pathway it controls. The vulnerability resurfaces whenever data reaches the ORM through an unprotected channel: raw queries, bulk operations, nested attributes, alternative content types, or entirely separate binding pipelines (Jackson vs. Spring's `@InitBinder`). The OWASP API Security Top 10 2023 recognized this systemic nature by merging the former API6:2019 (Mass Assignment) with API3:2019 (Excessive Data Exposure) into the unified **API3:2023 — Broken Object Property Level Authorization (BOPLA)**, acknowledging that both reading and writing unintended properties share the same root cause.

**The Structural Solution.** The only robust defense is architectural separation: never bind user input directly to domain/persistence models. Instead, use explicitly defined Data Transfer Objects (DTOs), Input Types, or Form Objects as an intermediate layer where only intended fields exist. This eliminates the guessing game of allowlists and blocklists entirely — if the DTO doesn't have an `isAdmin` property, it cannot be bound regardless of what the attacker sends. Combined with schema validation at the API boundary (JSON Schema, OpenAPI spec, Joi/Zod validators, GraphQL strict input types), this approach makes mass assignment structurally impossible rather than relying on developers to remember protection annotations on every endpoint.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- OWASP Mass Assignment Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- OWASP API Security Top 10 2023 (API3:2023 BOPLA) — https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- Corradini, Pasqua, Ceccato — "Automated Black-box Testing of Mass Assignment Vulnerabilities in RESTful APIs" (ICSE 2023) — https://arxiv.org/abs/2301.01261
- CVE-2022-22965 (Spring4Shell) — https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- CVE-2025-2304 (Camaleon CMS) — https://vulert.com/vuln-db/CVE-2025-2304
- CVE-2024-40531 (Langflow) — https://nvd.nist.gov/vuln/detail/cve-2024-40531
- GitHub 2012 Mass Assignment Incident — https://www.infoq.com/news/2012/03/GitHub-Compromised/
- PortSwigger Web Security Academy: Mass Assignment Lab — https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability
- Spring Mass Assignment Cheat Sheet (0xn3va) — https://0xn3va.gitbook.io/cheat-sheets/framework/spring/mass-assignment
- DeepStrike: Mass Assignment Techniques — https://deepstrike.io/blog/mass-assignment-techniques
- Cobalt: API Security 101 Mass Assignment — https://www.cobalt.io/blog/mass-assignment-apis-exploitation-in-the-wild
- RestTestGen (Black-box MA Testing Framework) — https://github.com/SeUniVr/RestTestGen
- Brakeman Scanner (Rails SAST) — https://brakemanscanner.org/docs/warning_types/mass_assignment/
- Rails Strong Parameters — https://github.com/rails/strong_parameters
- Mongoose Prototype Pollution Disclosure — https://thecodebarbarian.com/mongoose-prototype-pollution-vulnerability-disclosure.html
