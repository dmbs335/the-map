# Arbitrary Object Instantiation — Mutation / Variation Taxonomy

---

## Classification Structure

Arbitrary Object Instantiation (AOI) is a vulnerability class in which an attacker controls — directly or indirectly — *which class is instantiated* and/or *what arguments are passed to its constructor*. The fundamental danger is not in any single "bad" class but in the meta-capability of selecting an arbitrary type at runtime, then leveraging the side-effects of its construction or subsequent method calls to achieve attacker-desired outcomes.

This taxonomy organizes the entire attack surface along three orthogonal axes:

| Axis | Question Answered | Role in Taxonomy |
|------|-------------------|------------------|
| **Axis 1 — Injection Vector** (§1–§7) | *How* does attacker-controlled data reach the instantiation point? | Primary structure: the seven top-level sections |
| **Axis 2 — Exploitation Primitive** | *What* capability does the instantiated object grant? | Cross-cutting: labels applied to every subtype (XXE, SSRF, File-R/W, RCE, Info-Leak, DoS) |
| **Axis 3 — Target Ecosystem** | *Where* (language / framework / runtime) does the instantiation occur? | Mapping axis: connects each technique to concrete environments |

### Axis 2 — Exploitation Primitive Reference

Every subtype in the taxonomy is annotated with one or more of these primitives:

| Primitive | Abbreviation | Description |
|-----------|-------------|-------------|
| Remote Code Execution | **RCE** | Attacker executes arbitrary system commands or code |
| Server-Side Request Forgery | **SSRF** | Object constructor initiates attacker-controlled network requests |
| XML External Entity | **XXE** | XML parsing in the constructor leads to file read / SSRF |
| Arbitrary File Read / Write | **File-R/W** | Constructor opens, reads, creates, or deletes files |
| Information Disclosure | **Info-Leak** | Constructor exposes sensitive data (config, env vars, internal paths) |
| Denial of Service | **DoS** | Constructor triggers resource exhaustion or process crash |
| Database Interaction | **DB** | Constructor connects to or queries a database |
| Privilege Escalation | **Priv-Esc** | Instantiated object bypasses authentication or authorization |

### Fundamental Mechanism

All AOI variants share a single root cause: **the decoupling of type selection from type safety**. In every language with dynamic class loading, reflection, or deserialization, there exists a gap between (a) the set of classes *available* for instantiation and (b) the set of classes *intended* by the developer. Exploitation occurs when this gap is wider than zero and the "unexpected" classes have exploitable side-effects in their constructors, destructors, or lifecycle methods.

---

## §1. Direct Reflection-Based Instantiation

When application code uses reflection APIs to create objects from a class name supplied — fully or partially — by user input, the attacker gains direct control over which type is instantiated.

### §1-1. Unvalidated Class Name from User Input

The most straightforward variant: user input is passed verbatim to a reflection-based instantiation API.

| Subtype | Language | API Pattern | Exploitation Primitive |
|---------|----------|-------------|----------------------|
| **Java Class.forName + newInstance** | Java | `Class.forName(userInput).newInstance()` | RCE, Info-Leak |
| **Java Constructor.newInstance with args** | Java | `Class.forName(name).getConstructor(String.class).newInstance(arg)` | RCE, SSRF, File-R/W |
| **C# Activator.CreateInstance** | .NET | `Activator.CreateInstance(Type.GetType(userInput))` | RCE, Info-Leak |
| **C# Assembly.Load + CreateInstance** | .NET | `Assembly.Load(name).CreateInstance(className)` | RCE, Priv-Esc |
| **PHP new $className($arg)** | PHP | `new $userInput($arg)` | XXE, SSRF, RCE, File-R/W |
| **Ruby String#constantize + new** | Ruby | `params[:type].constantize.new(params[:value])` | RCE, File-R/W |
| **Python getattr + call** | Python | `getattr(module, className)(*args)` | RCE |

The key condition is the absence of an allowlist. Even if the constructor is side-effect-free, subsequent method calls on the instantiated object may be dangerous if the caller assumes a specific interface.

**Java-specific nuance**: `Class.newInstance()` (deprecated since Java 9) only invokes the no-arg constructor, while `Constructor.newInstance(args)` permits parameterized construction, dramatically expanding the gadget surface.

**PHP-specific nuance**: PHP's `new $a($b)` pattern triggers `__construct()`, whereas deserialization triggers `__wakeup()`. The available gadget surface differs significantly — AOI via `new` targets constructors of both custom and built-in classes, while deserialization targets `__wakeup()` and `__destruct()` chains.

### §1-2. Partial Control — Class Name Prefix/Suffix Constrained

The application appends or prepends a fixed string to the user-supplied class name, narrowing but not eliminating the attack surface.

| Subtype | Pattern | Bypass Technique |
|---------|---------|-----------------|
| **Namespace-prefixed instantiation** | `new ("App\\Models\\" . $input)()` | Traverse namespace hierarchy via `..\\` or leverage autoloading of unexpected classes within the namespace |
| **Suffix-constrained instantiation** | `Class.forName(input + "Factory")` | Find classes ending in `Factory` with dangerous constructors (e.g., `ClassPathXmlApplicationContextFactory`) |
| **Interface-checked instantiation** | Instantiate then cast to expected interface | Constructor side-effects execute *before* the cast check fails with ClassCastException — damage already done |

The interface-check bypass is particularly critical in Java: even when the code wraps instantiation in `try { ... } catch (ClassCastException e)`, the constructor of the attacker's chosen class has already run.

### §1-3. Configuration-Driven Class Loading

The class name originates not from direct HTTP parameters but from configuration endpoints, API fields, or stored data.

| Subtype | Entry Point | Example |
|---------|-------------|---------|
| **REST API configuration endpoint** | PUT/POST to config API | Graylog's `/api/system/cluster_config/{className}` accepting arbitrary fully-qualified class names (CVE-2024-24824) |
| **JDBC connection string properties** | DSN/URL parameters | PostgreSQL JDBC `socketFactory` / `sslFactory` properties instantiating arbitrary classes (CVE-2022-21724) |
| **Plugin/extension class specification** | Plugin descriptor files | Application loading class name from plugin manifest without validation |
| **DI container configuration injection** | Spring XML / YAML beans | Attacker-controlled bean definitions specifying arbitrary class names |

The JDBC vector is especially dangerous because connection strings are often composed from user-supplied hostnames or parameters, and the driver internally instantiates helper classes specified in the URL — the developer may not realize that a "database URL" can trigger arbitrary class loading.

---

## §2. Deserialization-Triggered Instantiation

Deserialization is the most prolific source of arbitrary object instantiation. The serialized data stream itself encodes which classes to instantiate, and the deserialization engine faithfully obeys.

### §2-1. Native Serialization Formats

| Subtype | Language | Mechanism | Exploitation Primitive |
|---------|----------|-----------|----------------------|
| **Java ObjectInputStream** | Java | `readObject()` reconstructs arbitrary object graphs; gadget chains invoke `InvokerTransformer`, `InstantiateTransformer` | RCE, SSRF, File-R/W |
| **PHP unserialize()** | PHP | Reconstructs objects; triggers `__wakeup()`, `__destruct()` magic methods | RCE, File-R/W, SSRF |
| **Python pickle.loads()** | Python | `__reduce__()` method returns `(callable, args)` tuples — directly executes arbitrary callables | RCE |
| **.NET BinaryFormatter** | .NET | Reconstructs arbitrary type graphs; gadget chains via `ObjectDataProvider`, `TypeConfuseDelegate` | RCE |
| **Ruby Marshal.load()** | Ruby | Reconstructs objects with attacker-controlled types and properties | RCE |

**Java gadget chain anatomy**: The canonical exploitation flow is:
1. Deserialization entry point (e.g., `ObjectInputStream.readObject()`)
2. Trigger method (e.g., `PriorityQueue.readObject()` calling `compare()`)
3. Chain of transformers (e.g., `ChainedTransformer` → `InvokerTransformer`)
4. Sink: `Runtime.exec()`, `ProcessBuilder.start()`, or `Method.invoke()`

The `InstantiateTransformer` in Apache Commons Collections is a textbook AOI gadget — it explicitly calls `Constructor.newInstance()` on an attacker-specified class with attacker-specified arguments.

### §2-2. Data-Interchange Format Deserialization

Formats not traditionally considered "serialization" but which support type annotations or polymorphic handling.

| Subtype | Format / Library | Mechanism | Exploitation Primitive |
|---------|-----------------|-----------|----------------------|
| **Jackson DefaultTyping** | JSON (Java) | `@type` field in JSON specifies class to instantiate; `enableDefaultTyping()` allows arbitrary types | RCE, SSRF |
| **Fastjson AutoType** | JSON (Java) | `@type` key triggers class instantiation; blocklist-based defense repeatedly bypassed | RCE |
| **SnakeYAML / PyYAML unsafe load** | YAML (Java/Python) | YAML tags (`!!python/object`, `!!javax.script.ScriptEngineManager`) specify types | RCE |
| **.NET Json.NET TypeNameHandling** | JSON (.NET) | `$type` property specifies .NET type for deserialization | RCE |
| **XML-based deserializers** | XML (Java/.NET) | XStream, XMLDecoder, XAML allow type specification in element tags | RCE |

**Fastjson AutoType bypass history**: Fastjson's defense model relied on a blocklist of dangerous class names. Researchers repeatedly discovered bypass techniques — hash-based blocklist collisions, encoding variations, and new gadget classes not yet on the list — demonstrating why blocklist approaches fundamentally fail for AOI defense. The `safeMode` introduced in 1.2.68, which completely disables AutoType, was the first structurally sound mitigation.

### §2-3. Custom Serialization with Type Metadata

Application-level serialization schemes that embed type information in the serialized representation.

| Subtype | Pattern | Example |
|---------|---------|---------|
| **AI/ML framework serialization** | Framework-specific `dumps()`/`loads()` with type markers | LangChain `lc` key injection — user-controlled dictionaries containing the reserved `lc` serialization marker are treated as legitimate LangChain objects during `load()` (CVE-2025-68664, CVSS 9.3) |
| **Custom JSON with class hints** | Application embeds `className` or `_type` fields in JSON payloads | Any REST API that stores/transmits class names in JSON and reconstructs objects on receipt |
| **Message queue payloads** | Serialized objects passed through Redis/RabbitMQ/Kafka | Laravel Reverb passing Redis Pub/Sub data directly to `unserialize()` without `allowed_classes` restriction (CVE-2026-23524) |

The LangChain case is notable as an emerging pattern: AI agent frameworks that serialize/deserialize complex object graphs (chains, tools, prompts) across system boundaries create new AOI surfaces, especially when LLM outputs can influence the serialized representation.

---

## §3. Built-in Class Exploitation (No Custom Gadgets Required)

A critical dimension of AOI: exploitation is possible even when the application has no custom classes with dangerous magic methods. Built-in language classes and standard library classes provide sufficient gadgets.

### §3-1. PHP Built-in Class Gadgets

The exploitation capability depends on the number of constructor parameters the attacker controls:

#### Single-Parameter Instantiation (`new $class($arg)`)

| Built-in Class | Attack | Mechanism |
|---------------|--------|-----------|
| **SplFileObject** | SSRF, Local File Read | Constructor accepts any URL/path; connects to arbitrary local or remote resources. In PHP < 8.0, `phar://` scheme converts SSRF to deserialization |
| **PDO** | DB Connection, File Creation | Constructor accepts DSN strings; SQLite DSN creates empty files at arbitrary paths; remote DB connections leak credentials |
| **Imagick** | RCE (single request) | Supports 100+ URI schemes delegated to external programs. `vid:msl:/tmp/php*` technique chains multipart temp file upload with MSL script execution for single-request RCE |
| **GlobIterator** | Path Disclosure | Constructor globs the filesystem; response differences reveal file existence |
| **SplFileInfo** | Path Disclosure | Instantiation with controlled path leaks path resolution information |

**Imagick deep-dive**: The `vid:` pseudo-protocol in ImageMagick reads MSL (Magick Scripting Language) scripts. By uploading a PHP webshell as a multipart form-data temp file (`/tmp/phpXXXXXX`), then instantiating `new Imagick("vid:msl:/tmp/php*")`, the MSL script processes the wildcard to find and execute the uploaded content — achieving RCE without any out-of-band connection.

#### Multi-Parameter Instantiation (`new $class($a, $b, ...)`)

| Built-in Class | Parameters | Attack |
|---------------|-----------|--------|
| **SimpleXMLElement** | 2–5 (data, options, isDataURL, ns, is_prefix) | XXE — constructor parses XML with external entity support; enables blind file exfiltration |
| **SoapClient** | 2 (wsdl, options) | SSRF + XXE — fetches remote WSDL; in PHP ≤ 5.4.12, WSDL parsing was vulnerable to XXE |
| **ReflectionFunction** | 1 + subsequent `invoke()` | If the instantiated object's methods are later called, `ReflectionFunction` wrapping a closure can execute arbitrary code |

### §3-2. Java Standard Library Gadgets

| Class | Constructor Behavior | Exploitation Primitive |
|-------|---------------------|----------------------|
| **java.io.File** | Wraps a path; toString() returns path content in certain frameworks | Info-Leak (Graylog returned file content in REST response) |
| **java.net.URL** | Resolves hostname on construction via DNS | SSRF, DNS exfiltration |
| **javax.script.ScriptEngineManager** | SPI discovery instantiates all registered ScriptEngine providers | RCE (via malicious JAR on classpath or remote URL in older JVMs) |
| **org.springframework.context.support.ClassPathXmlApplicationContext** | Loads and processes Spring XML bean definition from URL | RCE (arbitrary bean instantiation from attacker-controlled XML) |
| **java.lang.ProcessBuilder** | When combined with reflection to call `start()` | RCE |

### §3-3. .NET Framework Gadgets

| Class / Gadget | Mechanism | Exploitation Primitive |
|---------------|-----------|----------------------|
| **ObjectDataProvider** | Wraps arbitrary object, invokes arbitrary method with arbitrary parameters during property setting | RCE |
| **TypeConfuseDelegate** | Exploits `SortedSet<T>.Comparer` to invoke `Process.Start` | RCE |
| **XamlReader** | Loads and instantiates objects from XAML markup | RCE |
| **ActivitySurrogateSelector** | Subverts serialization surrogates to execute arbitrary code | RCE |

---

## §4. Indirect Instantiation via Framework Mechanisms

The attacker does not directly call a reflection API; instead, they abuse a framework's own type-resolution, binding, or plugin-loading logic to trigger instantiation.

### §4-1. JNDI Injection (Java)

The Java Naming and Directory Interface resolves names to objects. A single string lookup (`InitialContext.lookup(userInput)`) can trigger remote class loading or local gadget-based instantiation.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **LDAP + Remote Codebase** | JNDI lookup contacts attacker LDAP server; response includes `javaCodeBase` URL; JVM downloads and instantiates remote class | Java < 8u191 (remote classloading enabled by default) |
| **LDAP + Local Gadget (BeanFactory)** | LDAP response returns `Reference` with `javaFactory` set to `org.apache.naming.factory.BeanFactory`; BeanFactory calls `forceString` to invoke arbitrary setter | Requires Tomcat on classpath |
| **LDAP + MemoryUserDatabaseFactory** | Newer factory class in Tomcat catalina library serving as JNDI gadget | Tomcat catalina on classpath (discovered 2024) |
| **RMI + Remote Object** | JNDI lookup via RMI returns serialized object; triggers deserialization chain | Depends on classpath gadgets |
| **DNS (info leak only)** | JNDI DNS lookup exfiltrates data through controlled DNS server | No additional requirements |

**Post-Log4Shell landscape**: After CVE-2021-44228 (Log4Shell) demonstrated JNDI injection at massive scale, Java 8u191+ restricted remote classloading. Modern exploitation pivots to local factory classes (BeanFactory, MemoryUserDatabaseFactory) that are already on the classpath — transforming a remote-loading vulnerability into a local-gadget instantiation problem.

### §4-2. Spring Framework Data Binding and Class Loader Access

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ClassLoader property traversal (Spring4Shell)** | Spring MVC data binding allows property navigation: `class.module.classLoader...` reaches Tomcat's classloader properties; attacker writes JSP webshell by manipulating logging configuration | Java 9+ (module system exposes `class.module`); Tomcat WAR deployment (CVE-2022-22965, CVSS 9.8) |
| **SpEL injection** | Spring Expression Language evaluation of user-controlled strings can instantiate arbitrary classes via `T(java.lang.Runtime)` | User input reaches SpEL evaluation context |
| **Bean definition injection** | Attacker-controlled XML/YAML/properties injected into Spring application context | External configuration source compromise |

**Spring4Shell mechanism**: The Java 9 module system introduced `Class.getModule()`, which became reachable through Spring's property binding: `class.module.classLoader.resources.context.parent.pipeline.first...`. This chain navigated from the bound POJO to Tomcat's `AccessLogValve`, allowing the attacker to set the log directory, filename pattern, and content prefix to write an arbitrary JSP file — achieving RCE without any deserialization.

### §4-3. Template Engine Class Access

Server-Side Template Injection (SSTI) provides indirect paths to arbitrary class instantiation by traversing the object graph available within the template sandbox.

| Subtype | Engine | Technique |
|---------|--------|-----------|
| **MRO traversal (Jinja2/Python)** | Jinja2 | `''.__class__.__mro__[2].__subclasses__()` enumerates all loaded Python classes; attacker selects a class with dangerous `__init__` or methods (e.g., `subprocess.Popen`) |
| **Twig sandbox bypass** | Twig/PHP | Access to registered global objects or filters; `_self.env` leads to template cache manipulation |
| **Freemarker built-in** | FreeMarker/Java | `<#assign ex="freemarker.template.utility.Execute"?new()>` instantiates and invokes arbitrary classes |
| **Velocity reflection** | Velocity/Java | `$class.forName("java.lang.Runtime")` accesses Class objects directly |

### §4-4. Dynamic Module / Package Loading

| Subtype | Language | Mechanism |
|---------|----------|-----------|
| **Node.js dynamic require()** | JavaScript | `require(userInput)` loads and executes arbitrary module; `Module._load()` can bypass policy restrictions |
| **Python dynamic import** | Python | `__import__(userInput)` or `importlib.import_module(userInput)` loads arbitrary modules; module-level code executes on import |
| **Ruby constantize** | Ruby | `String#constantize` converts strings to constants (classes); `params[:type].constantize.new(params[:value])` is a direct AOI sink |

---

## §5. Constructor / Lifecycle Side-Effect Exploitation

The impact of AOI depends entirely on *what happens* when the chosen class is instantiated. This section catalogs the side-effect categories that bridge instantiation to exploitation.

### §5-1. Network-Connecting Constructors

Objects whose constructors initiate outbound network connections.

| Side-Effect | Examples | Resulting Primitive |
|------------|----------|-------------------|
| **HTTP/HTTPS request** | `Imagick("https://attacker.com")`, `SplFileObject("http://...")`, `java.net.URL(...)`, `ClassPathXmlApplicationContext("http://...")` | SSRF |
| **Database connection** | `PDO("mysql:host=attacker.com")`, JDBC `socketFactory` classes | DB, Credential Theft |
| **DNS resolution** | `java.net.InetAddress.getByName()` in constructors, JNDI DNS lookup | Data Exfiltration |
| **LDAP/RMI connection** | JNDI providers, `DirContext` implementations | SSRF, RCE Chain |

### §5-2. File-System Interacting Constructors

Objects whose constructors read, write, create, or delete files.

| Side-Effect | Examples | Resulting Primitive |
|------------|----------|-------------------|
| **File read** | `SplFileObject("/etc/passwd")`, `java.util.Scanner(new File(...))` | File-R/W |
| **File creation** | `PDO("sqlite:/tmp/evil.db")` creates empty SQLite file; Imagick MSL writes files | File-R/W |
| **File deletion** | Imagick `ephemeral:` scheme deletes after read | DoS, File-R/W |
| **Log file manipulation** | Spring4Shell `AccessLogValve` property chain writes JSP webshell | RCE |

### §5-3. Code-Executing Constructors

Objects whose constructors directly execute code or commands.

| Side-Effect | Examples | Resulting Primitive |
|------------|----------|-------------------|
| **System command execution** | Python pickle `__reduce__` → `os.system(cmd)` | RCE |
| **Script engine evaluation** | `ScriptEngineManager` SPI loading malicious engine | RCE |
| **XML/XSLT processing** | `SimpleXMLElement` with external entities; `TransformerFactory` with malicious XSLT | XXE, RCE |
| **Bean/context loading** | `ClassPathXmlApplicationContext(url)` loads and processes Spring XML with arbitrary bean definitions | RCE |
| **Reflection chain completion** | `InvokerTransformer.transform()` calls `Method.invoke()` on attacker-specified method | RCE |

### §5-4. State-Corrupting Constructors

Objects whose instantiation alters application-level state rather than performing direct I/O.

| Side-Effect | Examples | Resulting Primitive |
|------------|----------|-------------------|
| **Classloader modification** | Spring4Shell traversal to classloader properties | RCE |
| **Singleton/registry poisoning** | Instantiating a class that registers itself in a global registry | Priv-Esc |
| **Thread pool exhaustion** | Constructor spawns threads or allocates large resources | DoS |
| **Prototype pollution (JS)** | Constructor modifying `Object.prototype` via prototype chain | Priv-Esc, RCE |

---

## §6. Defense Bypass Techniques

Defenses against AOI typically involve restricting which classes can be instantiated. This section catalogs techniques for evading those restrictions.

### §6-1. Blocklist Evasion

| Subtype | Technique | Example |
|---------|-----------|---------|
| **New gadget class discovery** | Find classes not on the blocklist with equivalent capability | Fastjson repeatedly bypassed via undiscovered gadget classes; new Tomcat `MemoryUserDatabaseFactory` for JNDI (2024) |
| **Class name obfuscation** | Encoding, casing, or Unicode variations in class names | `L` prefix / `;` suffix in Fastjson class name parsing |
| **Subclass substitution** | Use a subclass of the blocked class that inherits the dangerous behavior | Block `Runtime` but allow `ProcessBuilder`; block `URLClassLoader` but allow framework-specific classloaders |
| **Wrapper/proxy classes** | Instantiate a non-blocked wrapper that internally instantiates the blocked class | `MethodUtil.invoke()` wrapping blocked reflection calls |

### §6-2. Allowlist Escape

| Subtype | Technique | Example |
|---------|-----------|---------|
| **Namespace confusion** | Attacker's class resides within an allowed namespace | LangChain CVE-2025-68664: classes within `langchain_core`, `langchain`, `langchain_community` namespaces were all trusted |
| **Interface satisfaction** | Craft or find a class that implements the expected interface but has dangerous side-effects | JDBC driver plugins: any class implementing `SocketFactory` can be instantiated via `socketFactory=` parameter |
| **Autoloader abuse** | PHP autoloading loads any class matching a namespace/directory convention; inject a file to create a class within the allowed namespace | Composer autoload + file upload = custom class in trusted namespace |

### §6-3. Deserialization Filter Bypass

| Subtype | Technique | Example |
|---------|-----------|---------|
| **Filter-before-construction gap** | Exploit objects that trigger side-effects during `readResolve()` or field assignment, before the filter can reject them | Deep nesting attacks where filter depth limits are exceeded |
| **Allowed class as gadget entry** | An allowed class's `readObject()` internally triggers instantiation of disallowed classes | `HashMap` → `hashCode()` → gadget chain starting from an allowed class |
| **Serialization format switching** | Bypass `ObjectInputFilter` by using a different serialization format (JSON, XML, YAML) that doesn't have filters | Application accepts both binary and JSON input; filter only applies to binary |
| **Missing allowed_classes** | PHP `unserialize()` called without the `allowed_classes` option | Laravel Reverb CVE-2026-23524: `unserialize()` without `allowed_classes` restriction |

---

## §7. Emerging Attack Surfaces

### §7-1. AI/ML Framework Serialization

AI frameworks serialize complex object graphs (model pipelines, agent chains, tool configurations) using custom formats that embed type information.

| Surface | Framework | Mechanism |
|---------|-----------|-----------|
| **LLM chain serialization** | LangChain | `dumps()`/`loads()` with `lc` type markers; prompt injection → serialization injection → arbitrary class instantiation within trusted namespaces |
| **Model pickling** | PyTorch, scikit-learn | Models serialized via Python pickle; loading untrusted `.pkl` files executes arbitrary code via `__reduce__` |
| **Configuration deserialization** | MLflow, Kubeflow | Pipeline configurations containing class names for custom transformers/estimators |

### §7-2. Infrastructure-as-Code and Configuration

| Surface | Entry Point | Mechanism |
|---------|-------------|-----------|
| **Helm/Kubernetes manifests** | Container image specifications | Injecting arbitrary container images via templated values |
| **Terraform providers** | Provider plugin loading | Custom provider loading arbitrary Go packages |
| **CI/CD pipeline actions** | GitHub Actions `uses:` field | Specifying arbitrary action repositories |

### §7-3. WebAssembly and Edge Computing

| Surface | Mechanism | Status |
|---------|-----------|--------|
| **WASI module loading** | Dynamic module instantiation from user-specified paths | Emerging; limited current exploitation |
| **Edge function deployment** | User-supplied code bundles instantiated on edge infrastructure | Platform-dependent; isolation boundaries vary |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Impact |
|----------|-------------|---------------------------|----------------|
| **Web Application (PHP)** | LAMP stack, WordPress/Laravel ecosystem | §1-1, §2-1, §3-1 | XXE → File Read → RCE via Imagick/Phar chain |
| **Enterprise Java** | Spring Boot, Tomcat, microservices | §1-1, §1-3, §2-1, §2-2, §4-1, §4-2 | JNDI injection, gadget chain RCE, Spring4Shell |
| **REST API (JSON)** | Jackson/Fastjson-backed APIs | §2-2 | Polymorphic deserialization → RCE |
| **.NET Enterprise** | ASP.NET, WCF services | §1-1, §2-1, §2-2 | BinaryFormatter/ViewState gadget chains |
| **Python ML/Data Pipeline** | Flask + pickle/YAML | §2-1, §7-1 | Pickle RCE, unsafe YAML load, LangChain injection |
| **Node.js Microservice** | Express, dynamic require | §4-3, §4-4 | SSTI sandbox escape, dynamic module loading |
| **Database Client Libraries** | JDBC/ODBC drivers | §1-3 | Connection string class injection (PgJDBC) |
| **ITSM/Enterprise Tools** | GLPI, Graylog, iTop | §1-1, §1-3 | Arbitrary instantiation → SSRF → internal network access |

---

## CVE / Bounty Mapping (2022–2026)

| Mutation Combination | CVE / Case | Product | Impact / CVSS |
|---------------------|-----------|---------|---------------|
| §1-3 (config endpoint) + §3-2 | CVE-2024-24824 | Graylog | Arbitrary class instantiation via REST API; `java.io.File` → info leak. CVSS 8.8 |
| §1-3 (JDBC properties) + §5-1 | CVE-2022-21724 | PostgreSQL JDBC (PgJDBC) | `socketFactory`/`sslFactory` parameters instantiate arbitrary classes. CVSS 8.5 |
| §1-1 (PHP new) + §3-1 (Imagick) | CVE-2022-31084 | LDAP Account Manager | Unauthenticated RCE via Imagick `vid:msl:` technique. CVSS 9.1 |
| §1-1 (PHP new) + §3-1 (SimpleXMLElement) | CVE-2017-18357 | Shopware | Object instantiation → SimpleXMLElement → Blind XXE → file disclosure. Metasploit module available |
| §1-1 (PHP new) + §5-1 | CVE-2024-27098 | GLPI | Authenticated SSRF via arbitrary object instantiation. CVSS 6.4 |
| §1-1 (PHP new) + §3-1 | CVE-2024-13645 | tagDiv Composer (WordPress) | Unauthenticated PHP object instantiation. CVSS 9.8 |
| §1-1 (PHP new) + §5-1 | GHSA-w9g8-mxm5-ph62 | Combodo iTop | Arbitrary class instantiation → GuzzleHttp SSRF from low-privilege user |
| §4-2 (Spring binding) + §5-4 | CVE-2022-22965 | Spring Framework (Spring4Shell) | ClassLoader property traversal → JSP webshell write → RCE. CVSS 9.8 |
| §4-1 (JNDI) + §5-3 | CVE-2021-44228 | Apache Log4j (Log4Shell) | JNDI lookup from log message → remote class loading → RCE. CVSS 10.0 |
| §2-2 (Fastjson AutoType) + §6-1 | CVE-2022-25845 | Alibaba Fastjson | AutoType blocklist bypass → arbitrary class instantiation → RCE. CVSS 8.1 |
| §2-3 (custom serialization) + §6-2 | CVE-2025-68664 | LangChain Core | `lc` key injection → class instantiation within trusted namespaces → secret exfiltration / RCE. CVSS 9.3 |
| §2-3 (message queue) + §6-3 | CVE-2026-23524 | Laravel Reverb | `unserialize()` without `allowed_classes` on Redis Pub/Sub data → RCE |
| §2-1 (PHP unserialize) + §5-3 | CVE-2025-7384 | Contact Form Entries (WordPress) | PHP Object Injection via stored form submissions → RCE. CVSS 9.8 |
| §2-1 (PHP unserialize) + §5-3 | CVE-2024-10957 | UpdraftPlus (WordPress) | Deserialization in `recursive_unserialized_replace` → RCE |
| §2-1 (YAML) + §5-3 | CVE-2026-24009 | Docling | Unsafe PyYAML loader → arbitrary Python object instantiation → RCE |
| §2-2 (Jackson DefaultTyping) | Multiple CVEs (2017–2023) | Jackson Databind | Polymorphic type handling with `enableDefaultTyping()` → gadget chain RCE |

---

## Detection Tools

| Tool | Type | Target Scope | Core Technique |
|------|------|-------------|---------------|
| **ysoserial** | Offensive | Java deserialization gadget chains | Generates serialized payloads for known gadget chains (Commons Collections, Spring, Groovy, etc.) |
| **ysoserial.net** | Offensive | .NET deserialization gadget chains | Generates payloads for BinaryFormatter, Json.NET, DataContractSerializer, XAML, etc. |
| **PHPGGC** | Offensive | PHP deserialization gadget chains | Property-Oriented Programming (POP) chains for popular PHP frameworks (Laravel, Symfony, WordPress) |
| **FUGIO** | Research | PHP Object Injection | Automatic exploit generation via coarse-grained static/dynamic analysis + fuzzing; discovered 2 new CVEs (USENIX Security 2022) |
| **Marshalsec** | Offensive | Java unmarshalling libraries | Generates payloads for Jackson, Fastjson, SnakeYAML, XStream, etc. |
| **JNDI-Exploit-Kit** | Offensive | JNDI injection chains | Starts HTTP/RMI/LDAP servers for JNDI exploitation with multiple factory class gadgets |
| **rogue-jndi** | Offensive | JNDI injection | Malicious LDAP/RMI server with payload generation for BeanFactory, Tomcat, Groovy gadgets |
| **Semgrep** | Defensive (SAST) | Multi-language | Pattern-based detection of `Class.forName()`, `new $var()`, `unserialize()`, `pickle.loads()` sinks |
| **CodeQL** | Defensive (SAST) | Multi-language | Taint-tracking queries from user input to reflection/deserialization sinks; deeper dataflow analysis |
| **ObjectInputFilter** | Defensive (Runtime) | Java deserialization | JVM-level filter for classes during `ObjectInputStream` deserialization; supports allowlist/blocklist patterns |
| **NotSoSerial** | Defensive (Runtime) | Java deserialization | Java agent that hooks `ObjectInputStream` to block dangerous classes |
| **contrast-rO0** | Defensive (Runtime) | Java deserialization | RASP-based detection of deserialization attacks at runtime |
| **Fickling** | Research | Python pickle | Static analysis and decompilation of pickle files to detect malicious `__reduce__` calls |

---

## Summary: Core Principles

### The Root Cause: Unbounded Type Universes

Arbitrary Object Instantiation exists because most mainstream languages provide mechanisms to instantiate classes by name at runtime — reflection, deserialization, autoloading, JNDI, template engines — and the set of classes reachable through these mechanisms is vastly larger than the set intended by the developer. The vulnerability is not in any individual class having a dangerous constructor; it is in the *combinatorial explosion* of reachable types multiplied by the side-effects their lifecycle methods produce. A PHP application with Imagick installed, a Java application with Spring on its classpath, or a Python service accepting pickled data each expose an attack surface defined not by what they coded, but by what they linked.

### Why Incremental Fixes Fail

Blocklist-based defenses are structurally doomed against AOI. Every new library added to the classpath/autoloader potentially introduces new gadget classes. The Fastjson saga — where over a dozen blocklist bypasses were discovered across multiple years — is the canonical illustration. Similarly, patching individual CVEs (closing one JNDI factory class, blocking one PHP built-in) addresses symptoms while leaving the root cause intact. The next gadget is always waiting in the next dependency update.

### Structural Solutions

The only architecturally sound defense is **inversion of the default**: instead of blocking known-dangerous classes (blocklist), allow only known-safe classes (allowlist). This principle manifests differently across ecosystems:

- **Java**: `ObjectInputFilter` with explicit allowlist; `activateDefaultTyping()` with `PolymorphicTypeValidator` instead of `enableDefaultTyping()`; JNDI `com.sun.jndi.ldap.object.trustURLCodebase=false` (default since Java 8u191)
- **PHP**: `unserialize()` with `['allowed_classes' => [...]]`; avoid `new $variable()` patterns entirely; validate class names against an explicit allowlist before instantiation
- **.NET**: Migrate from `BinaryFormatter` to `System.Text.Json` or `DataContractSerializer` with known-type declarations
- **Python**: Never `pickle.loads()` untrusted data; use `json` for data interchange; `yaml.safe_load()` instead of `yaml.load()`
- **Frameworks**: Spring `PropertyAccessor` restrictions; LangChain `allowed_objects` parameter; Laravel `allowed_classes` in `unserialize()`

The meta-lesson is that **type selection is a security-critical operation**. Any code path where user-controlled data influences which class is instantiated must be treated with the same rigor as command injection — because in practice, it often leads to the same outcome.

---

## References

- CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') — https://cwe.mitre.org/data/definitions/470.html
- CWE-502: Deserialization of Untrusted Data — https://cwe.mitre.org/data/definitions/502.html
- OWASP Deserialization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- OWASP PHP Object Injection — https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection
- PT SWARM, "Exploiting Arbitrary Object Instantiations in PHP without Custom Classes" — https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/
- USENIX Security 2022, "FUGIO: Automatic Exploit Generation for PHP Object Injection Vulnerabilities" — https://www.usenix.org/conference/usenixsecurity22/presentation/park-sunnyeo
- ysoserial (Java) — https://github.com/frohoff/ysoserial
- ysoserial.net (.NET) — https://github.com/pwntester/ysoserial.net
- Jackson Polymorphic Deserialization CVE Criteria — https://github.com/FasterXML/jackson/wiki/Jackson-Polymorphic-Deserialization-CVE-Criteria
- Praetorian, "Ruby Unsafe Reflection Vulnerabilities" — https://www.praetorian.com/blog/ruby-unsafe-reflection-vulnerabilities/
- Sprocket Security, "A Primer on Insecure Reflection Practices in Java and C# Applications" — https://www.sprocketsecurity.com/blog/a-primer-on-insecure-reflection-practices-in-java-and-c-applications
- Patchstack, "PHP Object Injection via Insecure Instantiation" — https://patchstack.com/articles/php-object-injection-via-insecure-instantiation/

---

*This document was created for defensive security research and vulnerability understanding purposes.*
