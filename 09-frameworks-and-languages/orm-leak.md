# ORM Leak Mutation/Variation Taxonomy

---
## Classification Structure

ORM (Object-Relational Mapping) Leak vulnerabilities arise when the abstraction layer between application code and the database is improperly exposed to user-controlled input, enabling attackers to query, filter, or extract data that the application never intended to reveal. Unlike traditional SQL injection—which targets raw SQL string construction—ORM Leak exploits the **semantic features** of the ORM itself: its query-building DSL, relational traversal syntax, operator vocabulary, and automatic data binding mechanisms.

This taxonomy organizes ORM Leak mutations across three axes:

- **Axis 1 (Mutation Target)**: The structural component of the ORM interaction being abused — what part of the ORM's interface is manipulated by the attacker. This is the primary axis and structures the main body of the document (§1–§8).

- **Axis 2 (Extraction Oracle)**: The method by which the attacker observes the effect of their manipulation — how leaked data is extracted or confirmed. This is the cross-cutting axis, applicable across all §-categories.

- **Axis 3 (Attack Scenario)**: The real-world exploitation context — where the ORM Leak has security impact. This is the mapping axis connecting techniques to concrete impacts.

### Axis 2: Extraction Oracle Summary

| Oracle Type | Mechanism | Applicable To |
|------------|-----------|--------------|
| **Boolean** | Response content/length difference reveals match vs. no-match | §1, §2, §3, §4 |
| **Time-based** | Query execution time difference indicates match | §1, §2, §3 |
| **Error-based** | Database error (ReDoS timeout, type cast exception) reveals data | §1, §3, §4 |
| **Direct** | Sensitive field values returned verbatim in response body | §5, §6, §7 |
| **Search/Existence** | Confirmation of value existence through search hit/miss | §1, §5 |

### Fundamental Mechanism

All ORM Leak vulnerabilities share a common root condition: **user-controlled input reaches ORM query-building methods without validation against an allowlist of permitted fields and operators**. The four necessary conditions for exploitation are:

1. The attacker can control which **field/column** is filtered
2. The ORM supports **fragment-matching operators** (LIKE, regex, comparisons)
3. The attacker can control the **operator** applied to the filter
4. The queried model (or a relationally connected model) contains **sensitive fields** not intended for exposure

When all four conditions are met, the ORM's query DSL becomes an oracle for extracting arbitrary field values from the database.

---

## §1. Filter Parameter Injection

The most fundamental ORM Leak vector: user-supplied input is directly unpacked into the ORM's filter/query methods, allowing the attacker to select arbitrary fields and operators.

### §1-1. Direct Dictionary Unpacking

The canonical ORM Leak pattern — request parameters are expanded directly into a `filter()` call using the unpack operator (`**`), allowing the attacker to control both the target field and the matching operator.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Django `filter(**kwargs)`** | `User.objects.filter(**request.data)` directly maps user JSON/form data to QuerySet keyword arguments. Attacker sends `{"password__startswith": "pbkdf2"}` to test password hash prefixes. | Developer uses `**` expansion on unvalidated user dict |
| **Django `Q(**kwargs)`** | `Q` objects accept the same keyword syntax. When `Q(**user_input)` constructs query conditions, attackers inject arbitrary field lookups. | Q objects built from user-controlled dictionaries |
| **Prisma `where` injection** | `prisma.model.findMany({ where: req.query.filter })` passes user-controlled JSON directly to the query builder. Attacker sends `filter[password][startsWith]=p`. | User input reaches Prisma's `where` clause without validation |
| **Beego ORM `Filter()`** | `queryset.Filter(field, value)` accepts user-controlled field names. The `parseExprs` function resolves double-underscore notation to column references. | User controls field parameter in Beego's filter chain |
| **Ransack query params** | `q[field_predicate]=value` syntax in Ransack (< 4.0.0) allows filtering on any model attribute including sensitive ones like `reset_password_token`. | Ransack versions before 4.0.0 with default configuration |

**Example — Django direct unpacking:**
```python
# Vulnerable code
articles = Article.objects.filter(**request.data)

# Attack payload (JSON body)
{"created_by__user__password__startswith": "pbkdf2_sha256$"}
```

**Example — Prisma URL parameter injection:**
```
GET /articles?filter[createdBy][resetToken][startsWith]=06
```

### §1-2. URL Query Parameter Auto-Mapping

Some frameworks automatically map URL query parameters to ORM filter conditions without explicit developer opt-in, creating implicit filter injection surfaces.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Navidrome auto-parameter** | URL parameters are automatically added as SQL filter conditions. `?password=test` filters on the password column directly. (CVE-2024-47062) | Framework auto-maps URL params to query filters |
| **Harbor `q` parameter** | The `q` URL parameter accepts arbitrary field-operator-value triples like `password=~hashprefix`. The `orm.metadata.Filterable` function fails to restrict sensitive fields. (CVE-2025-30086) | Generic search endpoint without field allowlist |
| **OData `$filter`** | `$filter=Password gt 'A'` uses the standardized OData filter syntax to apply comparison operators on any property exposed in the Entity Data Model. | OData EDM exposes sensitive properties; `$filter` not restricted |

**Example — Harbor ORM Leak:**
```
GET /api/v2.0/users?q=password=~pbkdf2
```

### §1-3. Search Endpoint Abuse

Generic search functionalities that index all model fields — including sensitive ones — allow attackers to confirm existence of specific values through search hit/miss behavior.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Full-text search on sensitive fields** | Search endpoints index all string fields in a model, including `token`, `tfa_secret`, or `password`. Searching for a known hash confirms the value exists. (CVE-2025-64748, Directus) | Search function indexes concealed/sensitive fields |
| **Aggregation endpoint leaking** | Aggregation queries (count, sum, per_month) accept filter parameters that can target sensitive fields, revealing data through count changes. | Aggregation endpoints accept user-controlled filters |

**Example — Directus search on concealed fields:**
```
GET /items/directus_users?search=tfa_secret_value_prefix
```

---

## §2. Relational Traversal

ORM relationship navigation syntax allows attackers to "pivot" through foreign keys, one-to-one, and many-to-many relationships to reach sensitive fields on models that are not directly exposed by the vulnerable endpoint.

### §2-1. Foreign Key / One-to-One Traversal

The double-underscore (Django/Beego) or nested object (Prisma) syntax for following foreign key relationships extends the attacker's reach from the directly-queried model to any transitively related model.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Django FK chain** | `created_by__user__password__startswith` traverses Article → Author (FK) → User (OneToOne) → password field. Django automatically generates `INNER JOIN` statements. | ForeignKey or OneToOneField relationships exist between models |
| **Prisma nested relation filter** | `{ createdBy: { resetToken: { startsWith: "06" } } }` traverses through Prisma's relation definitions. | Prisma schema defines relational fields accessible to the attacker |
| **Beego relational field** | `email__password__startswith=a` — Beego's `parseExprs` incorrectly resolves the relational chain, allowing traversal to the password field. | Beego models define relational fields |

**Example — Django FK traversal:**
```python
# Article → Author (FK) → User (OneToOne) → password
Article.objects.filter(created_by__user__password__startswith="pbkdf2")
```

### §2-2. Many-to-Many Relational Pivoting

M2M relationships create exponential path expansion, allowing attackers to reach models that have no direct relationship to the entry-point model. The attacker can "loop back" through M2M junction tables to access the same model through a different access path.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **M2M loop-back** | `created_by__departments__employees__user__password__startswith` traverses Author → Department (M2M) → Employee (M2M) → User → password. Reaches arbitrary users not directly connected to the queried article. | M2M relationships form cycles or paths to sensitive models |
| **Django Groups/Permissions pivot** | `created_by__user__groups__user__password__startswith` leverages Django's built-in `PermissionsMixin` relationships. `related_query_name="user"` creates reverse-traversal paths. | Application uses Django's auth system with default related names |
| **Prisma `some` operator chaining** | `{ departments: { some: { employees: { some: { password: { startsWith: "x" } } } } } }` chains `some` operators across M2M relations. | Prisma schema exposes M2M relationships |

**Example — Django M2M loop with Groups pivot:**
```json
{
  "created_by__user__groups__user__password__startswith": "pbkdf2",
  "created_by__user__groups__user__id": 1
}
```

The `id` filter narrows the target to a specific user whose password is being extracted.

### §2-3. Reverse Relation Exploitation

ORM reverse relations (the "other side" of a ForeignKey) allow traversal in directions the developer may not have anticipated, reaching parent models from child endpoints.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Django reverse FK** | If `Order` has FK to `User`, then `User.objects.filter(order__total__gt=1000)` traverses the reverse relation. Attackers can inject `user__order__creditcard__number__startswith` from an endpoint filtering users. | Reverse relations not restricted in filter allowlist |
| **Implicit reverse query name** | Django auto-generates reverse relation names for query lookups using the lowercase model name (e.g., `order` not `order_set`). The `_set` suffix applies to the related manager API (e.g., `user.order_set.all()`), while filter expressions use the model name directly (e.g., `User.objects.filter(order__total__gt=1000)`). Developers may not realize these implicit lookup names exist. | Default `related_query_name` not overridden or blocked |

### §2-4. Access Control Bypass via Relational Filters

Relational filtering can circumvent application-level access restrictions by creating SQL JOIN chains that reach beyond the intended query scope.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Filter scope escape** | Code restricts `Article.objects.filter(is_secret=False, **request.data)`. Attacker sends `categories__articles__is_secret=True` to create a JOIN that returns secret articles through the category relationship. | Access control implemented at filter level, not model/row level |
| **Cross-tenant data access** | Multi-tenant applications filtering by `tenant_id` can be bypassed when relational filters JOIN to models in other tenants. | Tenant isolation relies on application-level filters rather than row-level security |

**Example — Bypassing is_secret filter:**
```json
{
  "categories__articles__is_secret": true,
  "categories__articles__title__startswith": "Confidential"
}
```

---

## §3. Operator Abuse

ORM filter operators (string matching, comparison, regex) provide the attacker with primitives for character-by-character data extraction, transforming a filter oracle into a systematic data exfiltration channel.

### §3-1. String Fragment Matching

String matching operators enable prefix/substring/suffix matching to progressively narrow down a target value.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`startswith` / `istartswith`** | Prefix matching enables character-by-character extraction starting from the beginning of the value. ~300 requests can extract a 64-character hash. | ORM supports `startswith` operator on the target field |
| **`contains` / `icontains`** | Substring matching via SQL `LIKE '%value%'`. Less precise than startswith but useful for confirming presence of specific patterns in the middle of values. | ORM supports `contains` operator |
| **`endswith` / `iendswith`** | Suffix matching complements startswith for bidirectional extraction. | ORM supports `endswith` operator |
| **Prisma `contains` for timing** | In Prisma, multiple `contains` conditions on random strings generate heavy LIKE queries that create measurable timing differences (~104ms with 100 rows and 1,000 conditions). | Prisma with PostgreSQL; attacker can inject OR conditions |

**Example — Django startswith extraction:**
```json
// Step 1: {"password__startswith": "p"} → match
// Step 2: {"password__startswith": "pb"} → match
// Step 3: {"password__startswith": "pbk"} → match
// ... continue until full hash extracted
```

### §3-2. Comparison Operators

Comparison operators (`gt`, `lt`, `gte`, `lte`) exploit database collation ordering to perform binary-search-style extraction without pattern matching functions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Greater-than / Less-than binary search** | `password__gt='a'` tests whether the password value is lexicographically greater than 'a'. Combined with `lt`, enables binary search on the character space. Collation rules vary by database (MSSQL, MySQL, PostgreSQL, SQLite). | ORM supports comparison operators; database collation is predictable |
| **OData logical operators** | `$filter=Password gt 'A'` in OData uses comparison operators, often overlooked by developers who only restrict function-based filters (contains, startswith). | OData endpoint allows `gt`/`lt` operators on sensitive fields |

**Example — Collation-based binary search:**
```
GET /api/users?password__gt=pbkdf2_sha256$260000$a → true
GET /api/users?password__gt=pbkdf2_sha256$260000$m → false
→ Next character is between 'a' and 'm'
```

### §3-3. Regular Expression Operators

Regex operators provide the most expressive matching capability but also enable error-based oracles through Regular Expression Denial of Service (ReDoS).

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Django `regex` / `iregex`** | `password__regex="^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"` crafts a ReDoS payload. On MySQL (32ms regex timeout), a matching prefix triggers a timeout error (HTTP 500), while non-matching returns normally (HTTP 200). | Django with MySQL backend; regex operator not restricted |
| **Authentik regex injection** | `{"action__regex": "^6.*"}` in the events endpoint uses regex matching to enumerate values character-by-character. Note: CVE-2024-42490 is officially classified as improper authorization on certificate/private key view endpoints per Authentik advisory, not as a regex injection issue. The regex technique here is a general Django ORM leak pattern. | Django filter accepts `__regex` operator from user input |

**Note**: ReDoS-based extraction works on MySQL (which has a default regex timeout) but **fails on PostgreSQL** (no timeout) and **MariaDB** (no regex limit).

**Example — ReDoS error oracle on MySQL:**
```json
{
  "password__regex": "^(?=^pbkdf2_sha256).*.*.*.*.*.*.*.*!!!!$"
}
// Matching prefix → MySQL timeout → HTTP 500 (match confirmed)
// Non-matching prefix → Normal response → HTTP 200 (no match)
```

### §3-4. Negation and Existence Operators

Negation operators invert the filter logic, providing alternative oracle construction when positive matching is restricted.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Prisma `not` operator injection** | `{ resetToken: { not: "E" } }` — when a Prisma filter expects a string value but receives an object with the `not` key, it applies negation logic. Non-null tokens that don't equal "E" return results, confirming token existence. | Prisma type coercion from string to filter object |
| **Cookie/Header type coercion** | `Cookie: resetToken=j:{"not": "E"}` — Express.js `cookie-parser` with `j:` prefix parses JSON from cookies, injecting objects where strings were expected. | Express.js cookie-parser with JSON parsing; value reaches Prisma filter |

---

## §4. Query Structure Manipulation

Beyond filter parameter injection, attackers can manipulate the structural grammar of the ORM-generated SQL query itself — controlling how clauses are joined, ordered, or grouped.

### §4-1. Query Connector Injection

Controlling the logical connector (`AND`/`OR`) between query conditions changes the semantics of the entire query.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Django `_connector` injection** | `Q(**user_input)` where user input includes `_connector: "OR"` modifies `WhereNode.as_sql()` to use `OR` instead of `AND` between conditions, bypassing intended filter logic. (CVE-2025-64459) | Django Q objects constructed from user-controlled dicts with `**` expansion |
| **Unsafe string formatting in WhereNode** | Django's `WhereNode.as_sql` used unsafe string formatting (`%s`) to inject the connector value into raw SQL, enabling SQL injection through the connector. | Django versions before 5.1.14, 4.2.26, or 5.2.8 |

**Example — Django _connector injection:**
```python
# Attacker sends: {"_connector": "OR", "is_admin": true, "username": "guest"}
Q(**user_input)
# Generates: WHERE is_admin = true OR username = 'guest'
# Instead of: WHERE is_admin = true AND username = 'guest'
```

### §4-2. Order-By Injection

When user input controls the `ORDER BY` clause, attackers can inject expressions that execute arbitrary SQL.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Django `order_by()` alias injection** | Column aliases containing period characters in combination with `FilteredRelation` allow SQL injection through `order_by()`. (CVE-2026-1312) | Django versions processing user-controlled order_by parameters |
| **Hibernate ORDER BY injection** | HQL `ORDER BY` clause accepts user-controlled column names or expressions. Unlike parameterized values, column references in ORDER BY cannot be parameterized. | Hibernate with user-controlled sort fields |

### §4-3. HQL/JPQL Query Injection

Hibernate Query Language and Java Persistence Query Language injections operate at a higher abstraction level than SQL injection but can achieve similar effects through ORM-specific constructs.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HQL context escape** | The sequence `\''` (backslash + two single quotes) creates a parsing differential between Hibernate and MySQL: Hibernate sees an escaped quote, MySQL sees a string terminator + new query segment. | Hibernate with MySQL; dynamic HQL construction |
| **HQL blind boolean** | `test' OR substring(login,1,1)='a'` — HQL supports `substring()` for character extraction, but lacks SQL metadata functions (`information_schema`, `UNION` to arbitrary tables). | HQL query with user-controlled WHERE clause values |
| **HQL error-based extraction** | `(select password from User where username='admin')=1` — type mismatch forces Hibernate to include the actual value in the exception message when exceptions are exposed. | Verbose error messages enabled; Hibernate exception contains queried values |
| **HQL time-based via native functions** | `pg_sleep(1)` or `SLEEP()` injected through HQL context escape reaches the underlying database engine for time-based extraction. | HQL context escape achieved; database supports sleep functions |

**Example — HQL error-based password extraction:**
```
from Book where title='' and (select password from User where username='admin')=1 or ''='
```
Hibernate returns: `java.lang.String cannot be cast to java.lang.Integer` with the password value in the exception.

---

## §5. Mass Assignment / Auto-Binding

Mass assignment (Ruby on Rails, Node.js) or auto-binding (Spring MVC, ASP.NET MVC) occurs when the framework automatically maps incoming request parameters to model/object properties, allowing attackers to set fields that were never intended to be user-modifiable.

### §5-1. Direct Model Attribute Overwrite

The attacker includes additional parameters in a request that directly map to model attributes the developer didn't intend to expose.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Rails `params.permit` bypass** | Before Rails 4.0 / without Strong Parameters, `User.new(params[:user])` maps all submitted parameters to model attributes including `is_admin`, `role`, `balance`. | Rails < 4.0 or missing `permit()` calls |
| **Spring MVC auto-binding** | `@ModelAttribute` automatically binds request params to Java object properties. `role=ADMIN` in POST body sets the role property if not excluded via `@InitBinder`. | Spring MVC without `setDisallowedFields()` or `@InitBinder` restrictions |
| **ASP.NET over-posting** | Model binding maps form fields to action parameters. `IsAdmin=true` in a profile update form sets the admin flag if the binding model includes that property. | ASP.NET MVC without `[Bind(Exclude=...)]` or view models |
| **Node.js/Express body binding** | `Object.assign(user, req.body)` or `user.update(req.body)` merges all request body properties into the model. | Direct object spreading from request body without filtering |

**Example — Rails mass assignment (pre-Strong Parameters):**
```
POST /users
user[name]=attacker&user[email]=a@b.com&user[is_admin]=true
```

### §5-2. Nested/Relational Attribute Injection

Mass assignment can target nested objects or related models when the framework supports nested attribute binding.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Rails `accepts_nested_attributes_for`** | Nested parameter structures (`user[profile_attributes][secret_field]=value`) modify related models through the parent model's update. | `accepts_nested_attributes_for` enabled without attribute restrictions |
| **Spring nested property binding** | `address.city=injected&role.name=ADMIN` binds to nested Java objects through property path resolution. | Complex object graphs without binding restrictions |

### §5-3. HTTP Method Confusion in Binding

Different HTTP methods may apply different validation or binding rules, allowing attackers to bypass restrictions by changing the request method.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **PUT vs POST binding scope** | PUT requests may bind to different (broader) sets of fields than POST requests. Note: CVE-2024-37905 (Authentik) is officially described as improper authorization allowing API token user reassignment, not specifically HTTP method confusion. The PUT vs POST framing here illustrates the general pattern but is not the official root cause classification. | Different binding/validation rules per HTTP method |

---

## §6. Serialization / Over-Exposure

Data leaks through improper serialization — the ORM fetches sensitive fields and the application returns them to the user without field-level filtering.

### §6-1. Include/Select Directive Injection

When the application exposes ORM include/select/expand directives to user input, attackers can request additional fields or related models not intended for the response.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Prisma `include` injection** | `{ include: { createdBy: true } }` includes all fields of the related user model in the response, including password and token fields. | User controls Prisma query options beyond `where` |
| **Prisma `select` injection** | `{ select: { createdBy: { select: { password: true } } } }` explicitly requests only the password field of a related model. | User controls Prisma `select` clause |
| **OData `$expand`** | `$expand=Credentials` includes related entities in the OData response, potentially exposing sensitive properties of related models. | OData EDM includes sensitive navigation properties |
| **GraphQL field selection** | GraphQL's per-query field selection allows requesting any field defined in the schema, including `passwordHash`, `apiToken`, `tfaSecret` if not individually authorized. Note: This is a schema exposure / field-level authorization issue distinct from ORM DSL leakage — included here as it often co-occurs with ORM-backed resolvers. | Schema exposes sensitive fields without per-field authorization |

**Example — Prisma include injection:**
```json
{
  "include": {
    "createdBy": {
      "select": {
        "id": true,
        "email": true,
        "password": true,
        "resetToken": true
      }
    }
  }
}
```

### §6-2. Lazy Loading / Eager Loading Misconfigurations

ORM loading strategies can unintentionally fetch and serialize sensitive related data.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Eager loading over-fetch** | Configured `eager_load` or `joinedload` fetches all columns of related models. When serialized to JSON without field filtering, sensitive data is included in the response. | Eager loading + automatic serialization (e.g., Django REST Framework `depth` parameter) |
| **Lazy loading trigger via serialization** | JSON serializers that access all object properties trigger lazy loading of related objects, fetching and returning data that was not explicitly requested. | Serializer accesses properties that trigger proxy objects |
| **N+1 query data spillover** | DataLoader or batch-loading mechanisms fetch related records in bulk. If authorization is checked at the resolver level but not at the batch level, unauthorized data may be included in batched queries. | Batch loading without per-record authorization checks |

### §6-3. Default Serializer Over-Exposure

Frameworks' default serialization includes all model fields unless explicitly excluded, creating a persistent risk of sensitive data exposure.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Django REST Framework `fields = '__all__'`** | `ModelSerializer` with `fields = '__all__'` includes every model field in the serializer. If the model contains sensitive fields (e.g., `password`, `secret_key`), they will be serialized unless explicitly excluded or overridden as write-only. In practice, well-written User serializers typically override `password` as write-only, but the risk applies to any model where sensitive fields exist and aren't individually excluded. | DRF serializer uses `__all__` without per-field write-only or exclusion overrides |
| **Rails `as_json` without `only/except`** | `user.as_json` returns all attributes. Without `only: [:id, :name]` or `except: [:password_digest]`, sensitive fields are exposed. | `.as_json` / `.to_json` called without field restrictions |
| **GraphQL introspection + full schema** | Schema introspection reveals all types, fields, and relationships. Even if fields are individually authorized, the schema structure itself leaks the data model. Note: This is a GraphQL schema exposure issue, not an ORM-layer vulnerability — included here as it amplifies ORM-backed data exposure. | GraphQL introspection enabled in production |

---

## §7. Error Message / Debug Information Disclosure

ORM and framework error messages inadvertently reveal database schema, query structure, internal paths, and sometimes actual data values.

### §7-1. Stack Trace Leakage

Unhandled ORM exceptions return full stack traces containing internal implementation details.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Django DEBUG=True** | Django's debug mode returns full stack traces with local variables, SQL queries, and template context when an ORM exception occurs. | `DEBUG=True` in production settings |
| **Hibernate exception with SQL** | Hibernate's default error handling includes the generated SQL query and parameter values in exception messages. Type mismatch errors can include actual column values. | Verbose error messages not suppressed in production |
| **ORM field validation errors** | Submitting invalid values to filter methods triggers errors that reveal field names, types, and valid operator lists: `"Cannot resolve keyword 'password' into field. Choices are: ..."` | Error responses include ORM-generated error messages |

### §7-2. Schema Reconnaissance via Invalid Queries

Deliberate submission of malformed queries to enumerate the database schema through error messages.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Field name enumeration** | Submitting `nonexistent_field__contains=x` triggers an error listing all valid field names: `"Choices are: id, username, email, password, ..."`. | ORM error messages include field choice lists |
| **Relationship discovery** | Submitting `valid_field__nonexistent_relation__contains=x` reveals available relationships: `"Invalid lookup: 'nonexistent_relation' is not a valid lookup"` plus valid relation names. | Error messages enumerate available lookups and relations |
| **Operator enumeration** | Submitting `field__invalid_op=x` triggers errors listing valid operators: `"Unsupported lookup 'invalid_op' for CharField. Available lookups: contains, exact, gt, ..."`. | Error messages list available operators per field type |
| **Type inference** | Different error messages for different value types (string vs. integer vs. date) reveal the column's data type. | Type validation errors vary by field type |

### §7-3. Database Configuration Exposure

ORM misconfiguration reveals database connection details and infrastructure information.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Connection string in errors** | Database connection failures expose host, port, database name, and sometimes credentials in the error message. | Connection errors not caught and sanitized |
| **SQL dialect fingerprinting** | Error message format and SQL syntax in ORM exceptions identify the underlying database engine (PostgreSQL, MySQL, SQLite, MSSQL). | ORM-generated SQL visible in error responses |

---

## §8. Expression Parser Bugs

Framework-specific parsing flaws in ORM query expression parsers that bypass field restriction protections.

### §8-1. Field Overwrite via Relational Parsing

Parsing ambiguity in how ORM expression parsers resolve field names versus relational paths allows bypassing of field deny-lists.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Beego `parseExprs` overwrite** | `email__password__startswith=a` — Beego's `parseExprs` processes `email` as a relational field, then `password` overwrites the field target. A deny-list blocking `password` as a direct field is bypassed because the parser resolves the full expression. Three successive Harbor patches were bypassed through variations of this technique before proper allowlisting was implemented. | Beego ORM with deny-list-based field protection |
| **Fuzzy-match format operator injection** | Harbor's `k=~v` (fuzzy match) format automatically applies LIKE operators. Combined with `parseExprs` overwrite, `email__password=~hash` leaks password hashes through fuzzy matching on the overwritten field. (CVE-2025-30086) | Framework-specific filter format supports implicit operators |

### §8-2. Type Coercion Bypasses

Frameworks that automatically coerce input types create unexpected ORM query structures.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Express.js query parameter parsing** | `filter[field][operator]=value` in URL query strings is parsed into nested objects by Express.js `qs` module, converting what should be a string into a filter operator object. | Express.js with default query parser; input reaches Prisma/Sequelize |
| **Cookie JSON injection** | Express.js `cookie-parser` interprets `j:{...}` prefix as JSON. `Cookie: token=j:{"not":"E"}` converts a string token to a Prisma filter object. | `cookie-parser` with JSON parsing; value reaches ORM filter |
| **Mongoose operator injection** | `{ username: { $gt: "" } }` — when request body is parsed as JSON, MongoDB query operators are injected into Mongoose queries. Operators like `$gt`, `$ne`, `$regex` enable data extraction; nested `$where` in `populate().match()` is covered by CVE-2025-23061 and can become code/search injection depending on the evaluation path | Mongoose with unvalidated JSON body reaching query methods |

### §8-3. ORM Operator Alias Exploitation

Legacy or misconfigured operator alias systems allow injecting query operators through string-based parameters.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sequelize string operator aliases** | Before Sequelize 5.0, string aliases like `$gt`, `$like`, `$ne` in query parameters were automatically resolved to Sequelize operators by default. `{ "password": { "$like": "p%" } }` performs a LIKE query on the password field. (CVE-2019-10748, CVE-2019-10749) | Sequelize < 5.0 with default `operatorAliases`, or explicitly enabled in 5.x+ |
| **Sequelize parameter escaping** | Query `replacements` parameters not properly escaped, allowing arbitrary SQL injection through the ORM's parameterization layer. (CVE-2023-25813 / Sequelize < 6.19.1) | Sequelize versions with improper replacement escaping |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|---------------------------|
| **Credential Extraction** | Any application storing password hashes in the database; filter endpoint accessible to authenticated or unauthenticated users | §1 + §2 + §3 (filter injection + relational traversal + operator abuse) |
| **Authentication Bypass** | Applications using token-based password reset or MFA; token values stored in filterable models | §1 + §3-1 (startswith extraction of reset/MFA tokens) |
| **Privilege Escalation** | Applications with role-based access; mass assignment or filter bypass allows role modification | §5-1 (mass assignment of `is_admin`/`role`) or §2-4 (filter scope escape) |
| **Schema Reconnaissance** | Applications with verbose errors; useful as first stage before targeted ORM leak | §7-1 + §7-2 (error messages revealing schema) |
| **Cross-Tenant Data Access** | Multi-tenant SaaS; tenant isolation via application-level filters | §2-4 (relational filter bypasses tenant scoping) |
| **API Token / Secret Theft** | Applications storing API keys, OAuth tokens, TFA secrets in the database | §1-3 (search on concealed fields) or §6-1 (include/select injection) |
| **PII Exfiltration** | GDPR/CCPA-regulated data; endpoints exposing user models | §6-2 + §6-3 (serialization over-exposure) |

---

## CVE / Bounty Mapping (2023–2026)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §1-2 + §8-1 (Beego parseExprs + field overwrite) | CVE-2025-30086 (Harbor) | Admin can infer user attributes (including password hashes/salts) via fuzzy-search ORM leak. Per GHSA/NVD, the scope is admin-level arbitrary attribute inference — "all users' complete hashes" overstates the practical extraction confirmed in the advisory. Three patches bypassed before proper fix. |
| §1-2 + §3-3 (URL auto-mapping + regex) | CVE-2024-47062 (Navidrome) | Multiple SQL injections + ORM Leak. Parameter names not escaped. |
| §1-1 + §3-3 + §7-2 (filter injection + regex + schema) | CVE-2024-42490 (Authentik) | Improper authorization on certificate/private key view endpoints (per official advisory). Not an ORM regex leak — classified here for context but the root cause is missing authorization checks, not ORM filter injection. |
| §5-3 (HTTP method confusion in binding) | CVE-2024-37905 (Authentik) | Improper authorization allowing API token user reassignment (per official advisory). Privilege escalation to superuser. Root cause is missing authorization on token user field, not specifically HTTP method confusion. |
| §4-1 (Q object _connector injection) | CVE-2025-64459 (Django) | SQL injection via ORM query structure manipulation. NVD has not yet assigned an independent CVSS score. |
| §4-2 (order_by alias injection) | CVE-2026-1312 (Django) | SQL injection through FilteredRelation + order_by with period characters. |
| §1-3 (search on concealed fields) | CVE-2025-64748 (Directus) | Concealed field existence inference — search on directus_users returns success/failure for masked values (tokens, TFA secrets), enabling boolean-based extraction of whether a concealed value exists. Not direct value leak. |
| §8-2 (Mongoose operator injection) | CVE-2025-23061 (Mongoose) | Nested `$where` operator in `populate().match()`; better classified under NoSQL/ODM operator injection than ORM leak. GitHub scores 9.1 and NVD analysis lists 9.8; impact depends on the application-side evaluation path |
| §8-3 (Sequelize operator aliases) | CVE-2019-10748/10749 (Sequelize) | SQL injection via unescaped JSON path keys on MySQL/MariaDB and operator alias injection. |
| §8-3 (Sequelize replacement escaping) | CVE-2023-25813 (Sequelize) | SQL injection through improper parameter escaping. |
| §1-1 + §2-1 (filter injection + FK traversal) | CVE-2023-47117 (Label Studio) | Authenticated user leaks password hashes via ORM filter chain. Combined with hardcoded SECRET_KEY, session token forgery becomes possible — but "full admin compromise" depends on the SECRET_KEY exposure being separately exploitable. |
| §1-1 + §3-1 (filter injection + startswith) | CVE-2023-31133 (Ghost CMS) | ORM Leak in content API. |
| §1-1 (filter parameter injection) | CVE-2023-30843 (Payload CMS) | ORM Leak vulnerability in CMS API. |
| §5-1 (direct model attribute overwrite) | GitHub SSH Key Injection (2012) | Mass assignment on Rails allowed injecting SSH public keys into GitHub user accounts. Landmark incident for mass assignment awareness. |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **plormber** (elttam) | Prisma ORM time-based & Django boolean | Pairwise comparison tournament with statistical hypothesis testing. Automates character-by-character extraction via time-based and boolean oracles. |
| **PayloadsAllTheThings ORM Leak** (swisskyrepo) | Django, Prisma, Ransack, Beego | Curated payload repository with framework-specific injection patterns, operator dictionaries, and relational traversal templates. |
| **Tenable WAS Plugin 115010** | Generic ORM Leak | Web application scanner plugin that detects ORM Leak patterns through automated parameter fuzzing. |
| **Nuclei Templates** (ProjectDiscovery) | Framework-specific CVEs | YAML-based templates for detecting known ORM Leak CVEs (Navidrome, Harbor, Directus, etc.) in automated scans. |
| **OWASP Testing Guide §07-05.7** | ORM Injection (general) | Testing methodology for identifying ORM injection points through systematic parameter manipulation. |
| **Brakeman** (Ruby) | Rails mass assignment | Static analysis scanner that detects mass assignment vulnerabilities in Ruby on Rails applications. |
| **Snyk / Semgrep** | Multi-framework | Static analysis rules for detecting unsafe `filter(**kwargs)`, missing `permit()`, and direct request-to-ORM parameter passing patterns. |
| **HQLmap** (0ang3el) | Hibernate HQL Injection | Automated exploitation tool for Hibernate HQL injection, supporting boolean-blind, time-blind, and error-based extraction. |

---

## References

- [elttam, "ORM Leaking More Than You Joined For" (2024)](https://www.elttam.com/blog/leaking-more-than-you-joined-for/)
- [elttam, "plORMbing your Django ORM" (2024)](https://www.elttam.com/blog/plormbing-your-django-orm/)
- [elttam, "plORMbing your Prisma ORM with Time-based Attacks" (2024)](https://www.elttam.com/blog/plorming-your-primsa-orm/)
- [CyberArk, "Let's Be Authentik: You Can't Always Leak ORMs" (2024)](https://www.cyberark.com/resources/threat-research-blog/lets-be-authentik-you-cant-always-leak-orms)
- [swisskyrepo, "PayloadsAllTheThings: ORM Leak"](https://swisskyrepo.github.io/PayloadsAllTheThings/ORM%20Leak/)
- [OWASP, "Testing for ORM Injection"](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
- [OWASP, "Mass Assignment Cheat Sheet"](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [PortSwigger, "Top 10 Web Hacking Techniques of 2024"](https://portswigger.net/research/top-10-web-hacking-techniques-of-2024)
- [PortSwigger, "Top 10 Web Hacking Techniques of 2025"](https://portswigger.net/research/top-10-web-hacking-techniques-of-2025)
- [Sonar, "Exploiting Hibernate Injections"](https://www.sonarsource.com/blog/exploiting-hibernate-injections/)
- [Trustwave, "HQL Injection Exploitation in MySQL"](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/hql-injection-exploitation-in-mysql/)
- [0ang3el, "Hibernate Injection Study"](https://github.com/0ang3el/Hibernate-Injection-Study)
- [Snyk, "Sequelize ORM npm library found vulnerable to SQL Injection attacks"](https://snyk.io/blog/sequelize-orm-npm-library-found-vulnerable-to-sql-injection-attacks/)
- [Wallarm, "Risks involved with operatorAliases in Sequelize"](https://lab.wallarm.com/risks-involved-with-operatoraliases-in-sequelize/)
- [Aikido, "Prisma and PostgreSQL vulnerable to NoSQL injection?"](https://www.aikido.dev/blog/prisma-and-postgresql-vulnerable-to-nosql-injection)
- [CVE-2024-47062 (Navidrome)](https://github.com/advisories/GHSA-58vj-cv5w-v4v6)
- [CVE-2025-30086 (Harbor)](https://github.com/advisories/GHSA-h27m-3qw8-3pw8)
- [CVE-2025-64459 (Django)](https://www.cycognito.com/blog/emerging-threat-django-sql-injection-vulnerability-cve-2025-64459/)
- [CVE-2025-64748 (Directus)](https://github.com/advisories/GHSA-8jpw-gpr4-8cmh)
- [CVE-2025-23061 (Mongoose)](https://github.com/advisories/GHSA-vg7j-7cwx-8wgw)
- [elttam, "plormber" tool](https://github.com/elttam/plormber)
