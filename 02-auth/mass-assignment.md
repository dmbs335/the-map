# Mass Assignment / Data Binding Mutation Taxonomy

---

## Classification Structure

Mass assignment is a class of vulnerabilities that arises when an application automatically binds user-controlled input to internal object properties without adequate restriction. The term originates from web frameworks that map HTTP parameters directly to model attributes — but the underlying problem is far more general. Wherever a system accepts structured input and uses it to populate an object graph, the risk of over-binding exists: the attacker supplies properties the developer never intended to be externally settable.

This taxonomy organizes the full mutation space along three axes. **Axis 1 (Binding Target)** classifies techniques by *what structural component* of the object graph the attacker reaches. This is the primary organizational axis. **Axis 2 (Bypass Mechanism)** describes *how* the attacker circumvents existing protections — denylist gaps, allowlist misconfigurations, property chain traversals, format differentials. **Axis 3 (Impact Scenario)** maps techniques to the *consequences* achieved: privilege escalation, remote code execution, data tampering, or authentication bypass.

The critical insight that connects "classical" mass assignment (overwriting `isAdmin`) to catastrophic outcomes like RCE is **nested property traversal**. When binding mechanisms follow object graphs recursively, a request parameter like `class.module.classLoader.resources.context.parent.pipeline.first.pattern` does not merely set a flat field — it navigates deep into the runtime's internal object structure. This realization, central to research on data binding insecurity in frameworks like Spring, Grails, and Struts, reframes mass assignment not as a simple input validation bug but as an **object graph navigation primitive** with a severity spectrum from attribute tampering to full system compromise.

### Axis 2 Summary: Bypass Mechanism Types

| Type | Description |
|------|-------------|
| **Denylist Gap** | Protection enumerates known-dangerous properties but misses new paths (e.g., JDK9 `module` property bypassing `class.classLoader` block) |
| **Allowlist Misconfiguration** | Allowlist exists but is overly permissive, incomplete, or defaults to open |
| **Property Chain Traversal** | Intermediate objects create alternative navigation paths to blocked targets |
| **Format/Encoding Differential** | Different content types (JSON nesting, dot notation, bracket syntax) are parsed differently by binding logic |
| **Schema/Introspection Exposure** | API schema or introspection reveals internal field names, enabling targeted over-binding |
| **Language Metaclass Access** | Language-level metaprogramming features (`__proto__`, `constructor`, `getClass()`) provide universal entry points |

### Fundamental Mechanism

Every data binding implementation shares a common pattern:

```
HTTP Request Parameters → Parser → Property Resolver → Object Graph Setter
```

The vulnerability surface exists at each transition: the parser may interpret format-specific constructs (JSON nesting, dot-notation expansion); the property resolver may follow object references recursively; and the setter may not validate whether the target property should be externally writable. When frameworks prioritize developer convenience over security defaults — making all properties bindable unless explicitly restricted — the entire object graph becomes the attack surface.

---

## §1. Direct Property Overwrite

The simplest and most common form of mass assignment: the attacker includes additional parameters in a request that map directly to model attributes not intended for external modification. No property chain traversal is needed — the binding mechanism sets flat fields on the target object.

### §1-1. Role and Privilege Field Injection

The attacker adds parameters corresponding to authorization-related fields that the application's forms do not expose but the model accepts.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Role field injection** | Adding `role=admin` or `is_admin=true` to a registration/update request | Model attribute for role is bindable; no allowlist restricts it |
| **Permission flag override** | Setting boolean permission flags (`can_delete=true`, `is_verified=true`) via extra parameters | Flag fields exist on the model and are not excluded from binding |
| **Account status manipulation** | Modifying `status=active`, `email_verified=true`, `banned=false` to bypass account lifecycle controls | Status fields are writable through the binding layer |
| **Tier/plan escalation** | Setting `subscription_tier=enterprise` or `quota=unlimited` on pricing-sensitive objects | Commercial attributes are part of the same model bound to user input |

This is the "textbook" mass assignment scenario and remains the most frequently reported variant in bug bounty programs. The GitHub mass assignment incident (2012) — where a researcher escalated privileges on any GitHub repository by injecting a `public_key` parameter — demonstrated its real-world severity. The OWASP API Security Top 10 (2023 edition) merged this category with Excessive Data Exposure under **API3:2023 Broken Object Property Level Authorization (BOPLA)**, recognizing that both stem from inadequate per-property access control.

### §1-2. Financial and Business Logic Field Tampering

Beyond privilege escalation, direct property overwrite targets fields with monetary or business logic significance.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Price/amount override** | Setting `price=0`, `discount=100`, `total=0.01` on order/transaction objects | Financial fields are on the same model as user-editable cart data |
| **Quantity manipulation** | Modifying `quantity`, `limit`, or `credits` fields beyond allowed bounds | Numeric constraints are enforced only at the UI layer |
| **Timestamp injection** | Setting `created_at`, `updated_at`, or `expires_at` to manipulate record ordering or extend validity | Timestamp fields are auto-generated but still bindable |
| **Foreign key reassignment** | Changing `user_id`, `owner_id`, or `organization_id` to associate objects with different entities | Relationship keys are part of the bound model and not restricted |

Foreign key reassignment is particularly impactful because it can turn a mass assignment into an IDOR — the attacker doesn't just modify their own record, they reassign ownership or access to objects belonging to other users.

### §1-3. Internal State and Metadata Injection

Targets attributes that control application-internal behavior rather than user-facing features.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Soft-delete flag reset** | Setting `deleted=false` or `deleted_at=null` to resurrect deleted records | Soft-delete implementation uses a bindable model attribute |
| **Workflow state override** | Forcing `state=approved`, `review_status=completed` to skip approval flows | State machine transitions are not enforced independently of the model |
| **Feature flag injection** | Setting `beta_features=true`, `experimental=enabled` on user preference objects | Feature flags are stored as user-level attributes and are bindable |
| **Audit field manipulation** | Overwriting `last_login`, `login_count`, `modified_by` to falsify audit trails | Audit fields are auto-populated but the binding layer doesn't exclude them |

---

## §2. Nested Property Traversal

This is where mass assignment transcends simple field overwriting and becomes an **object graph navigation attack**. When a data binding mechanism resolves property paths recursively — interpreting `a.b.c` as "get property `b` from object `a`, then set property `c` on that" — the attacker can traverse arbitrarily deep into the application's runtime object graph.

The severity escalation is dramatic. Direct property overwrite (§1) is constrained to fields on the immediately bound object. Nested property traversal reaches *any reachable object* in the graph, including framework internals, classloaders, and runtime configuration. Research on data binding insecurity across Java web frameworks (Spring, Grails, Struts) demonstrated that this mechanism is the structural root of binding-to-RCE escalation — the path from `user.name=Alice` to `class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{webshell}` is one of depth, not kind.

### §2-1. Java Bean Property Chain Navigation

Java's introspection model exposes `getClass()` on every object via `java.lang.Object`. From `getClass()`, the entire type hierarchy becomes navigable through property accessors. Data binding implementations that follow these chains without restriction expose the full runtime object graph.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct classLoader access** | `class.classLoader.*` — navigating from any object's `getClass()` to the ClassLoader | Pre-JDK9 environments without denylist, or denylist gaps |
| **Module-based classLoader bypass** | `class.module.classLoader.*` — using JDK9+ `java.lang.Module` as an intermediate hop to bypass `class.classLoader` denylists | JDK 9+ runtime; denylist blocks `class.classLoader` but not `class.module.classLoader` (CVE-2022-22965) |
| **ProtectionDomain traversal** | `class.protectionDomain.*` — accessing security policy and code source information | ProtectionDomain not included in the binding denylist |
| **Nested POJO graph navigation** | `address.city.region.country.*` — following relationships across associated domain objects | Framework resolves nested property paths recursively without depth limit |

The **module-based classLoader bypass** is the canonical example of why denylist approaches fail for nested property traversal. Spring Framework blocked `class.classLoader` after CVE-2010-1622, but when JDK 9 introduced `java.lang.Module` with its own `getClassLoader()` method, `class.module.classLoader` provided an alternative path to the same target. The denylist was structurally unable to anticipate this: it blocked a specific property path, not the *capability* of reaching the ClassLoader. The fix in Spring 5.3.18+ moved to an allowlist approach, restricting `Class` property descriptor access rather than enumerating forbidden paths.

### §2-2. ClassLoader Exploitation Primitives

Once an attacker reaches the ClassLoader through property chain navigation, multiple exploitation primitives become available depending on the application server and runtime configuration.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Tomcat AccessLogValve manipulation** | `classLoader.resources.context.parent.pipeline.first.*` — reconfiguring Tomcat's access log to write a JSP webshell: setting `pattern` to shell code, `suffix` to `.jsp`, `directory` to `webapps/ROOT` | Apache Tomcat; WAR deployment; writable webroot |
| **URLClassLoader resource injection** | Modifying classpath entries or resource URLs through ClassLoader properties to load remote classes | ClassLoader exposes mutable URL/path properties |
| **GroovyClassLoader code compilation** | Grails/Groovy environments expose `GroovyClassLoader` which can compile and execute arbitrary Groovy code from property values | Groovy-based framework; ClassLoader is GroovyClassLoader subtype (CVE-2022-35912) |
| **Thread context ClassLoader swap** | Replacing the thread's context ClassLoader to influence class resolution for subsequent operations | Thread-local ClassLoader is settable through the property chain |

The Tomcat AccessLogValve primitive works through four coordinated property assignments:

```
class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{shell_code}i
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell
```

This reconfigures Tomcat's access logging to write a JSP file containing attacker-controlled content to the web-accessible root directory. The attacker then requests the generated JSP to execute arbitrary commands. Notably, the Grails variant (CVE-2022-35912) achieved ClassLoader access even on Java 8, because Grails uses its own data binding implementation independent of Spring's denylist — demonstrating that the vulnerability class is **framework-structural**, not tied to any single runtime version.

### §2-3. Expression Language and Evaluation Chains

Some frameworks bind parameters through expression languages (OGNL, SpEL, MVEL) that provide even richer object graph navigation than simple property resolution.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **OGNL static method access** | Struts2 `ParametersInterceptor` evaluating `@java.lang.Runtime@getRuntime().exec(cmd)` through OGNL parameter expressions | Struts2 with insufficient OGNL sandbox; `allowStaticMethodAccess=true` |
| **OGNL classLoader navigation** | `class.classLoader` through OGNL property resolution in Struts2 parameter binding (S2-020, CVE-2014-0094) | `class` parameter not excluded from `ParametersInterceptor` |
| **SpEL injection via binding** | Spring Expression Language evaluation triggered during data binding when `@Value` or similar annotations process bound values | Binding values flow into SpEL evaluation contexts |
| **Double evaluation** | Parameter value is resolved once by the binder, then the result is re-evaluated as an expression (S2-045, S2-061, CVE-2020-17530) | Error messages or intermediate values containing user input are re-parsed |

In Struts2, the `ParametersInterceptor` was the critical boundary between HTTP parameters and OGNL evaluation. Vulnerabilities S2-003, S2-005, S2-009, S2-016, S2-020, and S2-021 represent a decade-long series of bypasses against successive restrictions on what parameter names and values could be evaluated. S2-020 specifically added `^class\\..*` to `excludeParams` — the Struts equivalent of Spring's denylist for `class.classLoader` — but like Spring's approach, this proved insufficient against creative property chain navigation.

---

## §3. Framework-Specific Binding Mechanism Exploitation

Each web framework implements data binding with distinct internal mechanisms, creating framework-specific attack surfaces. This section covers how the binding implementation itself — not the property graph it navigates — introduces vulnerabilities.

### §3-1. Spring Framework Binding Internals

Spring's `DataBinder` and `BeanWrapperImpl` use Java Bean introspection (`java.beans.Introspector`) to discover settable properties. The `CachedIntrospectionResults` class caches `PropertyDescriptor` objects, and any property with a public setter becomes bindable unless explicitly excluded.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Implicit @ModelAttribute binding** | Handler method parameters of non-simple types without explicit annotations are resolved as `@ModelAttribute`, triggering full data binding | Spring MVC controller with POJO parameter; developer unaware of implicit binding |
| **setDisallowedFields bypass** | `@InitBinder` with `setDisallowedFields("role")` blocks exact match but not nested paths like `role.name` or encoded variants | Denylist configured at the field name level, not the property path level |
| **WebDataBinder type coercion** | Spring's type conversion system (ConversionService) transforms string parameters into complex types, expanding the reachable type graph | Custom converters registered; enum/type parameters trigger object instantiation |
| **Multipart binding expansion** | File upload parameters (`MultipartFile`) bound alongside regular parameters; metadata fields (`originalFilename`, `contentType`) may overwrite model attributes | Multipart request handler binding all parameters to a single model |

The Spring fix for CVE-2022-22965 fundamentally changed `CachedIntrospectionResults` to use an allowlist approach: property descriptors on `Class` objects are now restricted to `name` and `customBooleanEditor` only, regardless of the actual accessor methods available. This architectural shift from "block known-bad" to "allow known-good" represents the framework's acknowledgment that the denylist strategy was structurally unsound. However, the fix is **framework-level** — custom `PropertyEditor` registrations or `ConversionService` configurations that create new property paths are not covered by the core fix.

### §3-2. Grails Data Binding

Grails implements its own data binding layer independent of Spring's `BeanWrapperImpl`, using Groovy's metaprogramming capabilities. This means Spring's denylists do not protect Grails applications.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **GroovyObject metaClass binding** | Groovy objects expose `metaClass` as a property, providing access to method dispatch and class mutation | Grails data binding without `metaClass` exclusion |
| **Command object auto-binding** | Grails command objects bind all request parameters by default; `bindable` constraints are opt-in | Developer uses command objects without explicit binding constraints |
| **Domain class constructor binding** | `new DomainClass(params)` binds all parameters to the domain instance | Constructor-based binding in Grails controllers; no `bindable` constraint |
| **bindData selective bypass** | `bindData(obj, params, [include: [...]])` allowlist can be misconfigured or bypassed through nested property syntax | Allowlist includes a parent property but the attacker navigates through it |

CVE-2022-35912 affected Grails versions from 3.3.10 onward and critically did not require JDK 9+ — unlike Spring4Shell. This proved that the vulnerability class is inherent to the data binding *pattern*, not to a specific JDK API. The fix restricted ClassLoader-related property access in Grails' own binding code, but the underlying architecture — where binding defaults to open — remains.

### §3-3. Struts2 Parameter Interception

Struts2 processes request parameters through an interceptor stack, with `ParametersInterceptor` converting HTTP parameters into OGNL expressions evaluated against the action's value stack.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **excludeParams regex bypass** | The `excludeParams` regex in `struts-default.xml` can be bypassed through Unicode encoding, parameter name manipulation, or regex edge cases | Regex pattern doesn't cover all encoding variants of the blocked pattern |
| **Prefixed parameter OGNL injection** | Parameters with framework-recognized prefixes (`action:`, `redirect:`, `redirectAction:`) are evaluated as OGNL expressions | Struts2 < 2.3.15; prefixed parameter processing enabled |
| **Value stack navigation** | OGNL can navigate the entire Struts2 value stack, accessing not just the action but also session, application, and servlet context objects | OGNL sandbox insufficient or bypassed |
| **Sandbox escape via OgnlContext** | Manipulating `_memberAccess` or `#context` to weaken OGNL sandbox restrictions before executing dangerous methods | Struts2 OGNL sandbox active but escape possible |

The history of Struts2 parameter binding vulnerabilities (S2-001 through S2-066) is essentially a chronicle of the OGNL sandbox being repeatedly bypassed. Each fix restricted specific evaluation paths, and each subsequent vulnerability found new ones. This mirrors the Spring/Grails pattern of denylist escalation, but in Struts2 the binding mechanism is *inherently* an expression evaluator, making the attack surface fundamentally larger.

### §3-4. Ruby on Rails Strong Parameters

Rails introduced `strong_parameters` (Rails 4+) as a response to the 2012 GitHub mass assignment incident. Before this, `attr_accessible` / `attr_protected` model-level declarations were the only protection, and they were off by default.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **permit! wildcard** | `params.permit!` allows all parameters, completely bypassing strong parameters | Developer uses `permit!` for convenience, often in admin controllers |
| **Nested attributes accept** | `accepts_nested_attributes_for` combined with `permit` on the parent object can expose nested model attributes | Nested attributes configured; permit list includes the association |
| **Hash parameter injection** | Permit list includes a hash parameter (`permit(:settings)`) without restricting its keys, allowing arbitrary key-value injection | Hash-type attributes with unconstrained permits |
| **Type coercion bypass** | Sending a parameter as a different type (array vs. string, hash vs. scalar) to bypass type-specific permit checks | Type checking in permit is lenient or absent |

### §3-5. Django and DRF Serializer Binding

Django's `ModelForm` and Django REST Framework's `ModelSerializer` control field exposure through `fields` / `exclude` declarations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **fields = '__all__' exposure** | Using `fields = '__all__'` on a ModelForm or ModelSerializer exposes every model field to binding | Developer uses `__all__` shortcut; model has sensitive fields |
| **exclude list gap** | `exclude = ['password']` blocks specific fields but any newly added model field is automatically exposed | Model evolves with new sensitive fields; exclude list is not updated |
| **Serializer inheritance override** | Child serializer inherits field declarations from parent but adds or overrides fields, inadvertently exposing parent's restricted fields | Complex serializer inheritance hierarchies |
| **Writable nested serializer** | `WritableNestedSerializer` with `create`/`update` methods that process nested data without validating which fields are writable | DRF nested serializer without explicit field-level `read_only` |

### §3-6. Laravel Eloquent Mass Assignment

Laravel uses `$fillable` (allowlist) and `$guarded` (denylist) model properties to control mass assignment.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Empty $guarded array** | Setting `$guarded = []` disables mass assignment protection entirely | Developer explicitly unguards the model |
| **JSON column nesting bypass** | JSON column expressions (`settings->theme`) bypass guarded checks in certain Laravel versions | Laravel < 6.18.35 / 7.x < 7.24.0; JSON column nesting in request |
| **forceFill / forceCreate abuse** | Methods that explicitly bypass fillable/guarded checks used with user-controlled data | Developer passes `$request->all()` to `forceFill()` |
| **$fillable over-inclusion** | Allowlist includes fields that should not be user-writable (e.g., `user_id`, `role_type`) | Manual `$fillable` declaration includes sensitive attributes |

---

## §4. Format and Encoding Differentials

The format in which binding data is submitted — URL-encoded form data, JSON, XML, multipart — affects how the binding mechanism parses and resolves property paths. Differentials between expected and actual formats create bypass opportunities.

### §4-1. JSON Structure Exploitation

JSON's native support for nesting, arrays, and type diversity (string, number, boolean, null, object, array) creates binding behaviors that differ from flat form parameters.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Deep nesting for property traversal** | `{"class": {"module": {"classLoader": {...}}}}` — JSON nesting directly maps to nested property paths without needing dot-notation parsing | Framework binds JSON body to object graph; nested keys become property chains |
| **Type confusion via JSON types** | Sending `{"admin": true}` (boolean) vs `admin=true` (string) — JSON preserves type information that may bypass string-based validation | Binding layer respects JSON types; validation checks string values only |
| **Array index injection** | `{"users[0].role": "admin"}` — injecting indexed property access to modify collection elements | Framework supports array index notation in JSON binding |
| **Null injection** | `{"field": null}` — setting fields to null to bypass "not empty" validation while still triggering the setter | Null values are processed by the binder; validation checks for presence, not null |

### §4-2. Content-Type Switching

Submitting data with an unexpected `Content-Type` may cause the framework to use a different parser, producing different binding behavior for the same logical parameters.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Form-to-JSON switch** | Sending `Content-Type: application/json` to an endpoint that normally receives form data; JSON parser may resolve nested properties differently | Framework falls back to or additionally processes JSON body |
| **XML entity expansion** | Submitting XML body with entity references that expand into property names or values not visible in the raw parameter inspection | XML body binding enabled; entity expansion not disabled |
| **Multipart field injection** | Adding non-file fields to a multipart request that are bound alongside file upload metadata | Multipart binding processes all parts, not just file parts |

### §4-3. Parameter Name Encoding

Encoding property names using URL encoding, Unicode, or framework-specific syntax to bypass pattern-based restrictions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **URL encoding of property separators** | `class%2Emodule%2EclassLoader` — URL-encoding the dot separator to bypass regex-based denylist patterns | Denylist regex matches literal dot but framework decodes before resolution |
| **Unicode normalization bypass** | Using Unicode equivalents of ASCII characters in property names | Framework normalizes Unicode after denylist check but before property resolution |
| **Bracket notation substitution** | `class[module][classLoader]` — using bracket syntax instead of dot notation | Framework supports both notations but denylist only covers one |

---

## §5. API Schema and Type System Exposure

Modern API architectures (GraphQL, OpenAPI/Swagger, gRPC) expose type information that enables targeted mass assignment attacks. Unlike traditional web forms where the attacker must guess hidden fields, schema-exposing APIs provide a complete map of the object graph.

### §5-1. GraphQL Introspection-Guided Mass Assignment

GraphQL's introspection system returns the complete type schema, including every field on every type — writable or not. This makes mass assignment discovery trivial.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Mutation field injection** | Introspection reveals fields on a mutation's input type (e.g., `role`, `isAdmin`) that are not exposed in the client application's UI | Introspection enabled in production; mutation input types include sensitive fields |
| **Schema-guided field enumeration** | Using `__schema` query to discover all types and fields, then systematically testing each writable field for over-binding | Introspection returns full schema without access control |
| **Nested input type traversal** | GraphQL input types with nested object fields allow deep property assignment in a single mutation | Input type definitions include nested objects with sensitive fields |
| **Subscription-based field leak** | Subscribing to events that return types with more fields than the corresponding query/mutation, revealing bindable field names | Subscription resolvers return full objects without field-level filtering |

### §5-2. OpenAPI / Swagger Schema Exposure

OpenAPI specifications explicitly document request body schemas, including properties, types, and constraints.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Schema definition enumeration** | Reading the OpenAPI spec to find all writable properties on request models, including those not used by the official client | OpenAPI spec is publicly accessible (e.g., `/swagger.json`) |
| **readOnly property binding** | Schema marks a property as `readOnly` (informational hint) but the server-side binding does not enforce it | OpenAPI `readOnly` is a documentation-level constraint, not enforced at the binding layer |
| **additionalProperties: true** | Schema allows arbitrary additional properties, meaning the server binding accepts any key-value pair | Default `additionalProperties: true` in OpenAPI; no server-side enforcement |

### §5-3. gRPC / Protocol Buffer Field Discovery

Protocol buffer definitions expose field numbers and types. While gRPC is binary, schema reflection or `.proto` file leakage enables field discovery.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Reflection-based field enumeration** | gRPC server reflection enabled; attacker enumerates all message fields including internal ones | Server reflection not disabled in production |
| **Unknown field passthrough** | Protobuf3's handling of unknown fields allows setting properties on newer message versions that the server's binding layer processes | Server processes proto3 messages with unknown fields forwarded to internal services |

---

## §6. Language-Level Metaclass Exploitation

Some mass assignment vectors exploit language-level metaprogramming features rather than framework-specific binding logic. These affect any framework built on the language, because the metaclass access is intrinsic to the language's object model.

### §6-1. JavaScript Prototype Pollution

JavaScript's prototype-based inheritance means every object delegates to a prototype chain. Properties set on `Object.prototype` propagate to *all* objects in the runtime. When binding mechanisms process property names like `__proto__`, `constructor.prototype`, or `constructor`, they can pollute the global prototype chain.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`__proto__` direct assignment** | `{"__proto__": {"isAdmin": true}}` — recursive merge functions follow `__proto__` as a regular key, setting properties on `Object.prototype` | Merge/assign utility does not skip `__proto__` key; e.g., `lodash.merge`, `hoek.merge` before fixes |
| **`constructor.prototype` traversal** | `{"constructor": {"prototype": {"isAdmin": true}}}` — traversing through `constructor` to reach the prototype | `__proto__` is blocked but `constructor.prototype` is not |
| **Object.assign with tainted source** | `Object.assign(target, userInput)` where `userInput` contains `__proto__` — native `Object.assign` does not copy `__proto__` but custom implementations may | Custom merge/deep-copy functions that iterate `Object.keys()` including inherited properties |
| **ORM query operator injection** | `{"where": {"role": {"$ne": "admin"}}}` — when binding feeds into NoSQL query operators (Mongoose, Sequelize), prototype pollution can inject query logic | Binding layer passes user object directly to ORM query builder |

Prototype pollution is JavaScript's structural equivalent of Java's `class.classLoader` traversal — both exploit language-level metaclass access to reach objects beyond the intended binding scope. The parallel is exact: `__proto__` navigates the prototype chain just as `class.module.classLoader` navigates the Java type hierarchy.

### §6-2. Python Attribute Access

Python's `__class__`, `__dict__`, `__init__`, and `__subclasses__()` provide reflection and metaclass access similar to Java's `getClass()`.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`__class__` traversal** | `obj.__class__.__init__.__globals__` — navigating from any object to its class's global namespace | Template engine or binding mechanism evaluates attribute paths without restriction |
| **`__dict__` direct manipulation** | Accessing `__dict__` to read or modify instance attributes including "private" (name-mangled) ones | Framework exposes `__dict__` through property resolution |
| **MRO exploitation** | Using `__mro__` (Method Resolution Order) to navigate the class hierarchy and find useful classes/methods | Python SSTI chains that traverse `__mro__` to reach `os.system` or `subprocess` |

### §6-3. Ruby Metaprogramming

Ruby's open class model and `method_missing` delegation create additional binding attack surfaces.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`send` method invocation** | If binding logic uses `obj.send(param_name, param_value)`, arbitrary methods can be called | Custom binding implementation uses `send` without restriction |
| **`instance_variable_set` access** | Direct instance variable manipulation bypassing attribute accessor controls | Binding mechanism or developer code uses `instance_variable_set` with user input |

---

## §7. ORM and Persistence Layer Interaction

Mass assignment does not always stop at the application object — when bound objects are persisted, the ORM layer may process additional properties that affect database-level behavior.

### §7-1. Relation and Association Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Foreign key reassignment** | Binding a different `user_id` or `account_id` to associate a record with another entity | FK field is bindable; no ownership validation at the persistence layer |
| **Polymorphic type override** | Changing `type` on a polymorphic association (e.g., `commentable_type=Admin`) to associate with a different model | STI or polymorphic association type field is mass-assignable |
| **Nested association creation** | `user[posts_attributes][0][published]=true` — creating or modifying associated records through nested binding | `accepts_nested_attributes_for` (Rails) or equivalent without `reject_if` guards |
| **Join table injection** | Adding entries to many-to-many join tables by binding association IDs (`role_ids=[1,2,3]`) | Association proxy allows ID-based assignment; no access control on the association |

### §7-2. Query and Scope Injection

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Default scope override** | Binding parameters that modify query scopes or default ordering, potentially revealing hidden records | ORM scope parameters are bindable or configurable through request input |
| **Soft-delete bypass** | Setting `deleted_at=null` to make soft-deleted records appear in queries, or vice versa | Soft-delete field is mass-assignable; default scope filters on this field |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|----------|-------------|---------------------------|
| **Privilege Escalation** | Any web application with role-based access | §1-1 + §5-1 (field discovery + role injection) |
| **Remote Code Execution** | Java frameworks (Spring, Grails, Struts) with ClassLoader-accessible binding | §2-1 + §2-2 + §2-3 (property chain → ClassLoader → exploitation primitive) |
| **Data Tampering** | E-commerce, SaaS, financial applications | §1-2 + §7-1 (financial field + relationship manipulation) |
| **Authentication Bypass** | APIs with schema exposure | §1-3 + §5 (internal state + schema-guided enumeration) |
| **Prototype Pollution → XSS/RCE** | Node.js applications with merge-based binding | §6-1 (prototype chain pollution → template override or child_process injection) |
| **Arbitrary File Write** | Java frameworks on Tomcat | §2-2 (AccessLogValve manipulation to write webshell) |
| **Denial of Service** | Any binding framework with deep nesting | §2-1 + §4-1 (recursive property resolution with deep nesting causing stack overflow or resource exhaustion) |
| **Audit Trail Falsification** | Applications with bindable audit metadata | §1-3 (timestamp/author field manipulation) |

---

## CVE / Bounty Mapping (2010–2025)

| Mutation Combination | CVE / Case | Impact |
|---------------------|-----------|--------|
| §2-1 (direct classLoader) | CVE-2010-1622 (Spring Framework) | RCE via `class.classLoader` property traversal; first data binding → RCE demonstration |
| §3-3 (OGNL class access) + §2-3 | CVE-2014-0094 / S2-020 (Struts2) | ClassLoader manipulation through `ParametersInterceptor` OGNL evaluation |
| §2-1 (module bypass) + §2-2 (AccessLogValve) | CVE-2022-22965 / Spring4Shell (Spring Framework) | Critical RCE; `class.module.classLoader` bypasses JDK9+ denylist; CVSS 9.8 |
| §3-2 (Grails binding) + §2-2 (classLoader) | CVE-2022-35912 (Grails Framework) | Critical RCE via Grails-specific data binding; affects Java 8+; CVSS 9.8 |
| §3-6 (JSON nesting bypass) | Laravel `$guarded` bypass (pre-6.18.35 / 7.x pre-7.24.0) | Mass assignment via JSON column nesting expressions bypassing `$guarded` (note: CVE-2020-10914/10915 are Veeam ONE Agent vulnerabilities, unrelated to Laravel) |
| §1-1 (role injection) | GitHub 2012 Incident | Public key injection on arbitrary repos; demonstrated mass assignment severity |
| §6-1 (`__proto__`) | CVE-2018-3721 (lodash) | Prototype pollution via `lodash.merge`; affects all downstream applications |
| §6-1 (`__proto__`) | CVE-2019-10744 (lodash) | Prototype pollution in `lodash.defaultsDeep`; CVSS 9.1 |
| §6-1 (constructor.prototype) | CVE-2024-21529 (dset) | Prototype pollution via improper sanitization in `dset` package |
| §2-3 (OGNL double eval) | CVE-2020-17530 / S2-061 (Struts2) | Double OGNL evaluation leading to RCE; OGNL sandbox bypass |
| §2-3 (OGNL injection) | CVE-2023-22527 (Confluence) | OGNL injection in Atlassian Confluence template injection leading to RCE |
| §2-1 + §2-2 (DIVER findings) | 81 vulnerabilities (Spring + Grails) | ISSTA 2024: automated discovery of 81 data binding vulnerabilities; 3 new CVEs assigned |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **DIVER** (Research) | Spring, Grails data binding | Nested Property Graph extraction + bind-site instrumentation + property-aware fuzzing; discovered 81 vulnerabilities |
| **Burp Suite Pro** (Commercial) | General web applications | Param Miner extension for hidden parameter discovery; active scan checks for mass assignment |
| **Arjun** (Open Source) | REST APIs | HTTP parameter brute-forcing using large wordlists to discover hidden bindable parameters |
| **Param Miner** (Burp Extension) | Web applications | Automated hidden parameter discovery through response differential analysis |
| **InQL** (Burp Extension) | GraphQL APIs | Introspection query automation; mutation field enumeration; batch testing |
| **graphql-voyager** (Open Source) | GraphQL APIs | Visual schema exploration for identifying mutation input types with sensitive fields |
| **Nuclei** (Open Source) | Multi-framework | Template-based scanning including Spring4Shell, Struts OGNL, and mass assignment checks |
| **mass-assignment-check** (npm) | Node.js/Express | Static analysis for detecting unprotected object spread/assign in route handlers |
| **Brakeman** (Open Source) | Ruby on Rails | Static analysis detecting `permit!`, missing strong parameters, and `attr_accessible` gaps |
| **Semgrep** (Open Source) | Multi-language | Rule-based static analysis with community rules for mass assignment patterns across frameworks |

---

## Summary: Core Principles

Mass assignment is not a single vulnerability — it is a **structural consequence** of automatic data binding, a design pattern adopted by virtually every modern web framework. The fundamental property that makes the entire mutation space possible is the **impedance mismatch between binding convenience and access control granularity**: frameworks default to binding all properties for developer productivity, while security requires per-property, per-context access decisions.

The escalation from simple field overwrite to remote code execution is a matter of object graph depth. Research across Java web frameworks (Spring, Grails, Struts) demonstrated a unified threat model: *any* data binding implementation that resolves nested property paths without restriction, combined with a language runtime that exposes metaclass information (Java's `getClass()`, JavaScript's `__proto__`, Python's `__class__`), creates a path from user-controlled HTTP parameters to runtime-internal objects. The CVE history — from CVE-2010-1622 through Spring4Shell (CVE-2022-22965) to CVE-2022-35912 — is a twelve-year case study in the failure of incremental denylist patching against a structurally open attack surface.

Incremental fixes fail because the attack surface is defined by the **reachable object graph**, which evolves with every runtime update (JDK 9's `Module`), every framework plugin, and every application model change. A denylist that blocks `class.classLoader` becomes obsolete when `class.module.classLoader` appears; a regex that blocks `^class\\..*` becomes obsolete when bracket notation or URL encoding is supported. The structural solution requires inverting the default: binding must be **closed by default** (explicit allowlisting of bindable properties per endpoint), combined with **depth-limited** property resolution that prevents traversal beyond the immediately bound object. Frameworks that have adopted this approach — Rails' strong parameters, Spring's post-5.3.18 `CachedIntrospectionResults` allowlist, Django's explicit `fields` declarations — represent the architectural direction, but the legacy of "bind everything" defaults means that mass assignment will remain a productive vulnerability class for years to come.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

## References

- CVE-2022-22965 (Spring4Shell) — NVD, Spring Security Advisory
- CVE-2022-35912 (Grails RCE) — GitHub Security Advisory GHSA-6rh6-x8ww-9h97
- CVE-2010-1622 (Spring ClassLoader) — NVD
- CVE-2014-0094 / S2-020 (Struts2 ClassLoader) — Apache Struts Security Bulletins
- CVE-2020-17530 / S2-061 (Struts2 OGNL) — Apache Struts Security Bulletins
- OWASP API Security Top 10 2023 — API3:2023 Broken Object Property Level Authorization
- OWASP Mass Assignment Cheat Sheet
- ISSTA 2024: "Automated Data Binding Vulnerability Detection for Java Web Frameworks via Nested Property Graph" — Yan et al.
- BlackHat EU 2022: "DataBinding2Shell: Novel Pathways to RCE via Web Frameworks" — Haowen Mu, Biao He (Ant Security FG Lab)
