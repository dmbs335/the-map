> **DEPRECATED** — Moved to `99-deprecated/`.
> - Core pattern is "exposed management interface + deserialization", already covered in `insecure-management-interface.md` and `deserialization.md`
> - JMX is a highly specialized Java infrastructure protocol rarely encountered outside Java ops teams
> - MBean registration/invocation RCE is a deserialization variant

# JMX (Java Management Extensions) Attack Mutation/Variation Taxonomy

---

## Classification Structure

Java Management Extensions (JMX) is a Java technology for managing and monitoring applications, system objects, devices, and service-oriented networks at runtime. JMX exposes **MBeans** (Managed Beans) — Java objects representing manageable resources — through **connectors** that allow remote clients to perform monitoring, configuration, and method invocation. The fundamental security problem is that JMX was designed as a *management* protocol with implicit trust assumptions: any client that can connect is expected to be a legitimate administrator. This trust model, combined with Java's native serialization as the default wire format, creates a vast and layered attack surface.

The taxonomy is organized along three axes:

**Axis 1 — Mutation Target (Primary):** The structural component of the JMX architecture being exploited. This axis forms the main body of the document and encompasses seven categories: transport protocol manipulation, authentication/authorization subversion, MBean registration and loading abuse, deserialization surface exploitation, default/application MBean weaponization, HTTP bridge (Jolokia) attacks, and network-level/discovery attacks.

**Axis 2 — Impact Type (Cross-cutting):** The class of effect achieved by each mutation. These apply across all categories:

| Impact Type | Description |
|---|---|
| **Remote Code Execution (RCE)** | Arbitrary command or class execution on the JMX server |
| **Arbitrary File Read/Write** | Reading or writing files on the server filesystem |
| **Information Disclosure** | Extraction of credentials, session tokens, configuration, or environment data |
| **Privilege Escalation** | Elevation from read-only to admin, or from application user to OS root |
| **Server-Side Request Forgery** | Forcing the server to make outbound requests to attacker-controlled or internal targets |
| **Denial of Service** | Crashing or degrading the JMX server or monitored application |

**Axis 3 — Attack Scenario (Mapping):** The architectural deployment context — covered in the Attack Scenario Mapping section at the end.

### JMX Architecture Foundation

Understanding the attack surface requires understanding the JMX connector architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                     JMX Client                              │
│  (JConsole, VisualVM, custom client, attacker tool)         │
└────────────┬──────────────┬──────────────┬──────────────────┘
             │              │              │
     ┌───────▼──────┐ ┌────▼─────┐ ┌──────▼──────────┐
     │  RMI/JRMP    │ │  JMXMP   │ │  HTTP (Jolokia) │
     │  (default)   │ │  (legacy)│ │  (bridge/agent) │
     └───────┬──────┘ └────┬─────┘ └──────┬──────────┘
             │              │              │
     ┌───────▼──────────────▼──────────────▼──────────┐
     │              MBean Server                       │
     │  ┌──────────┐ ┌──────────┐ ┌──────────────┐    │
     │  │ Standard │ │ Dynamic  │ │ Model MBeans │    │
     │  │ MBeans   │ │ MBeans   │ │ (Required    │    │
     │  │          │ │          │ │  ModelMBean) │    │
     │  └──────────┘ └──────────┘ └──────────────┘    │
     │  ┌──────────┐ ┌──────────┐ ┌──────────────┐    │
     │  │ MLet     │ │ App-     │ │ Platform     │    │
     │  │ (loader) │ │ specific │ │ MXBeans      │    │
     │  └──────────┘ └──────────┘ └──────────────┘    │
     └────────────────────────────────────────────────┘
```

The four transport-level entry points (RMI, JMXMP, HTTP/Jolokia, Invoker Servlet) each have distinct deserialization behaviors, authentication mechanisms, and filter configurations — creating independent attack surfaces that must be assessed separately.

---

## §1. Transport Protocol Exploitation

The JMX connector transport layer determines how client-server communication is serialized, authenticated, and filtered. Each protocol has distinct vulnerability characteristics.

### §1-1. RMI/JRMP Transport Attacks

The default JMX connector uses Java Remote Method Invocation (RMI) over the Java Remote Method Protocol (JRMP). RMI transmits data using native Java serialization in **plaintext by default**, making it both a deserialization target and vulnerable to network interception.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **RMI Registry Deserialization** | Send malicious serialized objects to the RMI registry's `bind()` method, triggering deserialization of attacker-controlled payloads | Pre-JEP-290 (Java < 8u121) or bypassed filter; valid gadget chain in classpath |
| **DGC (Distributed Garbage Collection) Attack** | Target the DGC service (present on every RMI listener) with ysoserial's `JRMPClient` gadget to trigger deserialization | Pre-JEP-290 or filter bypass; gadget chain available |
| **JRMP Listener Redirect** | Bypass deserialization filters by inducing the target to make an outbound JRMP connection to an attacker-controlled listener, which then delivers unrestricted deserialization payloads | Target can make outbound connections; JRMPClient or An Trinh bypass gadget |
| **RMI Protocol Plaintext Interception** | Intercept RMI traffic (credentials, MBean data, serialized objects) on the wire — RMI is a plaintext binary protocol despite appearing "encrypted" | Network MITM position; TLS not configured (`com.sun.management.jmxremote.ssl=false`) |
| **RMI Registry Stub Manipulation** | Replace legitimate remote object stubs in the RMI registry with malicious stubs that redirect clients to attacker-controlled endpoints | Write access to RMI registry; client does not validate stub integrity |

The RMI registry plays a dual role: it is both the lookup service for JMX connector stubs and an independent deserialization endpoint. The registry itself runs on a separate port from the JMX data connection, expanding the network attack surface.

### §1-2. JMXMP (JMX Message Protocol) Attacks

JMXMP is an optional connector defined in JSR 160 that uses a raw TCP socket with full Java serialization for all data transfer. Despite being deprecated, it remains common in enterprise environments.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Pre-Authentication Deserialization** | JMXMP deserializes all incoming data before any authentication check. Raw ysoserial payloads sent directly to the JMXMP port trigger code execution without credentials | JMXMP connector active; gadget chain in classpath |
| **SASL Authentication Bypass** | JMXMP supports SASL-based authentication (e.g., DIGEST-MD5), but the handshake itself involves deserialization, enabling attacks before SASL negotiation completes | JMXMP with SASL configured; exploitable gadget chain |
| **Unpatched Protocol Surface** | Oracle's JMX/RMI security patches (JEP-290 filters, type restrictions) do **not** apply to JMXMP — it remains permanently unfiltered | JMXMP in use on any Java version |

JMXMP is the most dangerous JMX transport because it has zero deserialization protection. An attacker who can reach a JMXMP port has pre-authentication RCE if any deserialization gadget is on the classpath.

### §1-3. HTTP-Based Transports

Several mechanisms expose JMX over HTTP, each with distinct attack characteristics.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JBoss JMXInvokerServlet** | Accepts HTTP POST requests containing `MarshalledInvocation` serialized objects, deserializes them, and forwards to target MBeans. Exposed at `/invoker/JMXInvokerServlet` by default | JBoss AS 4.x/5.x with default configuration (no auth on invoker) |
| **JBoss EJBInvokerServlet** | Similar to JMXInvokerServlet but targets EJB invocations; same deserialization surface | JBoss AS 4.x/5.x; unauthenticated access |
| **Custom HTTP-JMX Bridges** | Application-specific HTTP endpoints that proxy JMX operations, often without independent input validation | Application-specific; common in monitoring dashboards |

The HTTP invoker servlets transform a network-layer JMX attack into a web application attack, bypassing firewalls that block RMI but allow HTTP traffic.

---

## §2. Authentication and Authorization Subversion

JMX authentication is layered and each layer has independent weaknesses. Per Oracle's JMX agent documentation, when remote monitoring is enabled via `com.sun.management.jmxremote.port`, password authentication and SSL/TLS are **enabled by default**. Disabling authentication requires explicitly setting `authenticate=false`. However, many deployment guides and tutorials instruct users to disable authentication for convenience, leading to widespread insecure configurations in practice.

### §2-1. Unauthenticated Access

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Explicit No-Auth Configuration** | JMX remote access defaults to authentication **enabled**, but many deployments explicitly set `com.sun.management.jmxremote.authenticate=false` following insecure deployment guides. This is a deliberate misconfiguration, not a default | JMX remote enabled with `authenticate=false` explicitly set |
| **Localhost Binding Escape** | JMX bound to `localhost` is accessible to any local user on the system, including low-privilege service accounts in shared hosting or container environments | Multi-tenant host; JMX bound to `127.0.0.1` without OS-level access controls (CVE-2024-32656) |
| **Container Network Exposure** | In Kubernetes/Docker, JMX bound to `0.0.0.0` inside a container is reachable from any pod in the same network namespace due to default flat networking | Containerized Java app; default K8s NetworkPolicy |

### §2-2. Credential Attacks

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Brute Force (No Lockout)** | JMX authentication has no account lockout mechanism. Unlimited login attempts are possible at full network speed | Authentication enabled; weak or default passwords |
| **Default Credential Exploitation** | Many application servers ship with well-known JMX credentials (e.g., ActiveMQ `admin:admin`). Note: `monitorRole`/`controlRole` are example role names from Oracle's JMX password file documentation, not Tomcat-specific default credentials — but they are frequently copied verbatim into production configurations | Default or example credentials not changed post-deployment |
| **Credential File Permission Weakness** | JMX password files (`jmxremote.password`) may have excessive filesystem permissions, readable by non-admin users | Multi-user system; improper file ACLs |

### §2-3. Authorization Bypass

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Read-Only to RCE Escalation** | Users with `readonly` JMX role can trigger deserialization attacks because object deserialization occurs *before* permission checks. Invoking any MBean method (even read) with a malicious serialized argument achieves RCE | Read-only JMX credentials; gadget chain in classpath |
| **CVE-2016-3427: Credential Map Deserialization** | `JMXConnectorFactory.connect()` accepts a `Map<String, Object>` for credentials instead of just string username/password. A malicious object embedded in the credentials map is deserialized server-side before authentication | Pre-Java 8u91; gadget chain available; works against password-protected JMX |
| **Role Model Bypass via MBean Method Invocation** | Even with role-based access, certain MBean methods (e.g., `getLoggerLevel()`) accept `Object` parameters that trigger deserialization regardless of the caller's role | Gadget chain in classpath; any valid credential (including read-only) |

The CVE-2016-3427 pattern is particularly dangerous because it defeats the primary defense (enabling authentication) — the deserialization occurs *during* the authentication handshake, making password protection irrelevant.

---

## §3. MBean Registration and Dynamic Loading

JMX allows runtime registration of new MBeans, including loading arbitrary classes from remote sources. This capability is the foundation of several RCE techniques.

### §3-1. MLet (Management Applet) Remote Loading

The `javax.management.loading.MLet` MBean is a built-in classloader that can download and instantiate MBeans from remote HTTP URLs.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Classic MLet RCE** | (1) Create an MLet MBean instance on the target. (2) Host an MLet HTML file and malicious JAR on attacker HTTP server. (3) Invoke `getMBeansFromURL()` pointing to the attacker URL. (4) Target downloads JAR, loads malicious class, executes attacker code | Unauthenticated JMX access; target has outbound HTTP connectivity; no SecurityManager |
| **MLet with Custom ObjectName** | Use non-standard ObjectName to avoid collision with existing MLet instances or evade simplistic detection rules | Same as classic MLet; useful for repeated exploitation |
| **MLet via Jolokia** | Invoke MLet operations through the Jolokia HTTP bridge, turning a web-accessible Jolokia endpoint into an RCE vector without direct JMX connectivity | Jolokia exposed; no MBean operation restrictions |

MLet is the "original" JMX RCE technique and remains effective against systems with outbound connectivity. The requirement for outbound HTTP is its primary limitation.

### §3-2. RequiredModelMBean Arbitrary Method Invocation

The `javax.management.modelmbean.RequiredModelMBean` is a built-in JMX class that allows wrapping arbitrary serializable objects and exposing their methods as MBean operations. This enables calling **any public method** on **any serializable class** without requiring custom classloading.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Instance Method Invocation** | Create a `RequiredModelMBean` with `ModelMBeanOperationInfo` entries pointing to public instance methods of any serializable object, then invoke those methods remotely | Authenticated JMX access (any role); target class must be serializable |
| **Static Method Invocation** | Use the `class` field in the `Descriptor` to specify an arbitrary class and invoke its static methods. The managed resource can be any serializable object (even a String) — it is ignored for static calls | Same as instance method; extends to non-instantiable utility classes |
| **TemplatesImpl RCE via RequiredModelMBean** | Wrap a `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` object with embedded malicious bytecode as the RequiredModelMBean resource, expose `getOutputProperties()` or `newTransformer()`, then invoke to trigger class loading and arbitrary code execution | JMX access; no outbound connection required; works with default JDK classes only |

The RequiredModelMBean technique is the most powerful modern JMX exploitation primitive because it requires **no outbound connections**, **no application-specific MBeans**, and **no deserialization gadget chains** — it works using only classes present in every JDK installation.

### §3-3. StandardMBean Wrapping

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **StandardMBean with TemplatesImpl** | Register a `StandardMBean` wrapping a `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` instance, exposing the `Templates` interface. Reading the `OutputProperties` attribute triggers bytecode execution | JMX access; TemplatesImpl class available (standard JDK) |
| **StandardMBean with Custom Interface** | Create a StandardMBean exposing any interface implemented by a serializable class, enabling remote invocation of any method defined in that interface | JMX access; target class implements desired interface |

---

## §4. Deserialization Surface Exploitation

Java deserialization is the most pervasive attack vector in JMX. Deserialization occurs at multiple points in the JMX communication lifecycle, each with different filter configurations.

### §4-1. Transport-Level Deserialization

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **RMI Registry `bind()` Deserialization** | Sending a malicious serialized object as a parameter to `Registry.bind()` triggers deserialization on the registry endpoint | Pre-JEP-290 or filter bypass (JRMPClient gadget, An Trinh bypass) |
| **RMI DGC Deserialization** | The Distributed Garbage Collector deserializes incoming lease/clean requests without application-level filtering | Pre-JEP-290; gadget chain available |
| **JMXMP Raw Deserialization** | JMXMP uses Java serialization for **all** protocol messages. Any data sent to the JMXMP port is deserialized — including the initial handshake, before authentication | JMXMP connector; any gadget chain (§1-2) |
| **JMXInvokerServlet HTTP Deserialization** | HTTP POST body containing serialized `MarshalledInvocation` objects is deserialized by the invoker servlet | JBoss with exposed invoker; no auth on servlet path (§1-3) |

### §4-2. JMX Session-Level Deserialization

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **`RMIServer.newClient()` Deserialization** | The `newClient(Object credentials)` method on the RMI server stub deserializes the credentials parameter. Pre-CVE-2016-3427, this accepted arbitrary objects | Pre-Java 8u91; post-patch restricted to String/String[] |
| **`RMIConnection` Method Arguments** | After establishing a JMX connection, all `RMIConnection` method calls (getAttribute, invoke, createMBean, etc.) pass serialized arguments that are deserialized server-side **without JEP-290 filters** | Valid JMX connection (even read-only); gadget chain in classpath |
| **MBean `invoke()` Parameter Deserialization** | Calling `MBeanServerConnection.invoke()` with serialized Object parameters triggers deserialization before the invoked MBean method ever executes | Any JMX connection; parameters are deserialized regardless of method implementation |

The critical insight is that **JEP-290 filters protect only the RMI registry and DGC layers** — the actual JMX/RMIConnection communication channel remains **unfiltered**. This means any authenticated connection (including read-only) can deliver deserialization payloads through normal MBean operations.

### §4-3. Deserialization Filter Bypasses

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JRMPClient Gadget** | ysoserial's JRMPClient gadget creates an outbound JRMP connection from the target to an attacker-controlled listener, bypassing the registry's deserialization filter. The attacker's listener then delivers unrestricted payloads | Target can make outbound connections; registry-level filter active |
| **An Trinh Registry Bypass** | Exploits specific class relationships to bypass the JEP-290 whitelist for the RMI registry, enabling arbitrary deserialization within the registry context | Specific Java versions (patched in later updates) |
| **Application-Level Gadget via RMIConnection** | Since the RMIConnection channel has no deserialization filter, standard ysoserial gadgets (CommonsCollections, CommonsBeanutils, etc.) work directly without any bypass | Post-JEP-290 Java; valid JMX connection; gadget in classpath |

### §4-4. SSRF-Chained Deserialization

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **SSRF to RMI Registry** | Exploit an SSRF vulnerability to send raw bytes to an internal RMI registry, delivering deserialization payloads through the SSRF channel. The RMI Single Operation Protocol allows one-shot exploitation without waiting for responses | SSRF vulnerability that supports arbitrary binary data (including null bytes); internal JMX reachable |
| **SSRF to JMXMP** | Send ysoserial payloads directly through SSRF to a JMXMP port — since JMXMP deserializes all incoming data, no protocol handshake is needed | Binary SSRF; JMXMP port reachable internally |
| **SSRF via Jolokia Proxy Mode** | Jolokia's proxy mode connects to arbitrary JMX endpoints on behalf of the HTTP client, enabling SSRF-style attacks against internal JMX services through the Jolokia web endpoint | Jolokia in proxy mode; no target URL validation |

---

## §5. Default and Application-Specific MBean Weaponization

Many MBeans registered by default in the JVM or by application frameworks expose operations that can be chained into powerful attack primitives — even without deserialization vulnerabilities.

### §5-1. JVM Platform MXBeans

These MBeans are present in every HotSpot JVM. However, accessibility depends on JMX authorization configuration — individual operations may require `ManagementPermission("monitor")` or `ManagementPermission("control")`, and role-based access files can restrict which operations each role may invoke.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **DiagnosticCommandMBean — CompilerDirective File Read** | The `compilerDirectivesAdd` operation accepts a file path and attempts to parse it as compiler directives. On parse failure, the error message includes the file contents, enabling arbitrary text file read | JMX access; DiagnosticCommandMBean registered (default in HotSpot) |
| **DiagnosticCommandMBean — Library Enumeration / Agent Loading** | `vmDynlibs` (VM.dynlibs) **lists** currently loaded dynamic libraries — it does not load new ones. Native code loading is achievable via `JVMTI.agent_load` (jcmd equivalent), which loads a JVMTI agent from a filesystem path | JMX access; for agent loading: attacker has written a malicious agent library to the filesystem (chain with §5-2); `JVMTI.agent_load` operation available |
| **FlightRecorderMXBean — Arbitrary File Write** | Java Flight Recorder (JFR) can dump recording data to a file with a user-specified path and extension. Since the path/extension is not restricted, this provides an arbitrary file write primitive. However, the written content is JFR binary recording data, not attacker-controlled content — so writing a functional `.jsp` webshell is not directly achievable. The primitive is useful for DoS (overwriting files) or information disclosure (writing heap/thread data to accessible paths) | JMX access; JFR available (Java 11+ commercial, OpenJDK 11+); writable target directory |
| **HotSpotDiagnosticMXBean — Heap Dump** | The `dumpHeap` operation writes a heap dump to any path. Heap dumps contain sensitive data (credentials, session tokens, encryption keys) and can be written to attacker-accessible locations | JMX access; sufficient disk space |
| **RuntimeMXBean — Environment Disclosure** | The `SystemProperties` and `InputArguments` attributes expose environment variables, JVM flags, classpath, and startup arguments — frequently containing database passwords, API keys, and secret paths | JMX read access (even read-only role) |

### §5-2. Application Server MBeans

Application servers register powerful MBeans that extend the attack surface significantly.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Tomcat UserDatabase MBean — Credential Extraction** | The `Users` MBean tree exposes all configured Tomcat users and passwords in plaintext, including the `manager` account credentials | JMX access to Tomcat; UserDatabase configured (default) |
| **Tomcat AccessLogValve — Log Rotation File Write** | The `rotate(String newFileName)` operation on `AccessLogValve` writes the current access log to an arbitrary file path. By injecting JSP code into HTTP request headers (which are logged), the attacker creates a webshell at the rotated path | JMX access to Tomcat; ability to send HTTP requests that appear in access logs |
| **Tomcat Manager — Session Hijacking** | The `listSessionIds()` operation under each deployed application returns active JSESSIONID values, enabling session hijacking of authenticated users | JMX access to Tomcat; active user sessions |
| **Tomcat Catalina — Virtual Host Deployment** | The `createStandardHost` operation in Catalina MBeans can create a new virtual host mapped to the filesystem root (`/`), granting read access to any file through the web server | JMX or Jolokia access to Tomcat |
| **JBoss BSHDeployer — WAR Deployment** | The `createScriptDeployment` operation on JBoss's BSHDeployer MBean creates a local BeanShell script file, which is then deployed via MainDeployer to achieve arbitrary code execution | JBoss AS with JMXInvokerServlet; unauthenticated (§1-3) |

### §5-3. Log4J MBeans via Jolokia (CVE-2022-41678 Pattern)

When Log4J 2.x management MBeans are exposed through Jolokia, they enable a complete exploitation chain without deserialization.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Log4J Appender Reconfiguration — File Write** | Dynamically reconfigure Log4J appenders via MBean operations to write log output to arbitrary file paths with controlled content. By injecting payload into log messages, arbitrary files (including webshells) are created | Jolokia or JMX access; Log4J 2.x MBeans registered |
| **Log4J Configuration Reload — XXE** | The `reloadByURL` operation (provided by Logback) fetches logging configuration from an attacker-controlled URL, enabling XML External Entity injection | Jolokia access; Logback as logging framework |
| **Log4J Appender Reconfiguration — SSRF** | Reconfigure appenders to use network-based outputs (SocketAppender, SMTPAppender), forcing the server to connect to attacker-controlled or internal targets | Jolokia or JMX access; Log4J 2.x MBeans |
| **Log4J Appender Reconfiguration — File Read** | Certain appender configurations can be tricked into reading local files and forwarding their contents to attacker-controlled endpoints | Jolokia access; network egress available |

This pattern is distinct from Log4Shell — it does not involve JNDI lookups and is **unaffected** by Log4Shell mitigations.

---

## §6. Jolokia HTTP Bridge Attacks

Jolokia is an HTTP-to-JMX bridge that exposes MBean operations via a REST API, typically at `/jolokia/` or `/actuator/jolokia`. It transforms JMX's binary protocol into HTTP JSON, vastly expanding the attack surface to web-based vectors.

### §6-1. Direct Jolokia Exploitation

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **MBean Enumeration via `/jolokia/list`** | The `list` endpoint returns all registered MBeans, their attributes, and operations — providing a complete map of available attack primitives | Jolokia endpoint accessible; no access restrictions |
| **JNDI Injection via Proxy Mode** | Jolokia's proxy mode initiates JMX connections to arbitrary targets. By supplying an LDAP/RMI URL as the target, the server performs JNDI lookup, enabling remote class loading and RCE | Jolokia in proxy mode (pre-1.5.0 default); JNDI not restricted |
| **CSRF to RCE** | Jolokia versions 1.2 to 1.6.0 are vulnerable to system-wide CSRF — a user visiting a malicious webpage can trigger MBean operations including RCE on the Jolokia-protected server | Jolokia 1.2–1.6.0; victim browses attacker page while authenticated |
| **XSS via Error Responses** | Jolokia 1.3.7 reflects unsanitized input in error responses, enabling stored/reflected XSS in management interfaces | Jolokia 1.3.7; management UI renders Jolokia responses |

### §6-2. Jolokia-Chained MBean Exploitation

Jolokia translates MBean operations into HTTP GET/POST requests, making all techniques from §5 exploitable through web-based vectors — critically, **all via GET requests**, enabling exploitation through SSRF vulnerabilities that only support GET.

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **JFR File Write via Jolokia GET** | Chain FlightRecorderMXBean operations through Jolokia GET requests to write webshells — exploitable via any SSRF that can reach the Jolokia endpoint | Jolokia accessible (directly or via SSRF); JFR available |
| **VHost Creation via Jolokia** | Create Tomcat virtual hosts through Jolokia MBean invocation, mapping filesystem directories to web-accessible paths | Jolokia on Tomcat; Catalina MBeans accessible |
| **DiagnosticCommand via Jolokia** | File read and library loading through DiagnosticCommandMBean operations exposed over HTTP | Jolokia accessible; HotSpot JVM |
| **Tomcat Credential Extraction via Jolokia** | Read UserDatabase MBean attributes through Jolokia to extract plaintext credentials | Jolokia on Tomcat; UserDatabase MBean accessible |

### §6-3. Jolokia as SSRF Amplifier

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **Proxy Mode Internal SSRF** | Jolokia proxy mode connects to internal JMX services on behalf of the HTTP client, effectively converting web access into internal network JMX access | Jolokia proxy mode enabled; internal JMX services |
| **SMB Hash Capture (Windows)** | On Windows, using `rotate()` on Tomcat's AccessLogValve via Jolokia with a UNC path (`\\attacker\share`) forces the server to authenticate via SMB, leaking NTLM hashes | Jolokia on Windows Tomcat; network egress on port 445 |

---

## §7. Network Discovery and Enumeration

Identifying JMX services is the first step in any attack. JMX uses dynamic port allocation by default, making discovery non-trivial.

### §7-1. Service Discovery

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **RMI Registry Port Scanning** | JMX RMI uses a registry port (often 1099, but configurable) plus a dynamically allocated data port. Scanning for RMI handshake signatures identifies JMX endpoints | Network access to target; RMI port not firewalled |
| **Nmap RMI Enumeration** | Nmap's `rmi-dumpregistry` and `rmi-vuln-classloader` NSE scripts identify RMI services and dump registry contents | Nmap access; RMI registry port reachable |
| **JMXMP Port Detection** | JMXMP uses a distinct handshake pattern detectable by protocol-aware scanners | Network access; JMXMP port not firewalled |
| **Jolokia Path Discovery** | Web scanning for `/jolokia/`, `/actuator/jolokia`, `/api/jolokia` and similar paths identifies HTTP-exposed JMX | HTTP(S) access to web application |
| **JMX Process Argument Inspection** | On compromised hosts, inspecting process arguments (`/proc/PID/cmdline`) for `-Dcom.sun.management.jmxremote.port=` flags reveals JMX configuration including ports and authentication settings | Local access to target host |

### §7-2. Endpoint Profiling

| Subtype | Mechanism | Key Condition |
|---|---|---|
| **MBean Inventory** | Enumerate all registered MBeans to identify exploitation primitives: MLet, DiagnosticCommand, FlightRecorder, application-specific MBeans | JMX or Jolokia access |
| **Classpath Analysis** | Use RuntimeMXBean to extract the full classpath, identifying available deserialization gadget libraries (Commons Collections, Spring, etc.) | JMX read access |
| **JVM Version Fingerprinting** | Determine exact JVM version to identify which exploits are applicable (pre/post JEP-290, pre/post CVE-2016-3427 patch) | JMX or RMI handshake analysis |
| **SASL Authentication Enumeration** | For JMXMP endpoints, probe supported SASL mechanisms to identify authentication requirements and potential bypasses | JMXMP port reachable |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architecture | Primary Mutation Categories | Typical Chain |
|---|---|---|---|
| **Directly Exposed JMX** | JMX port accessible from internet/untrusted network | §1-1, §2-1, §3-1, §4-1 | Discovery (§7) → Unauthenticated access (§2-1) → MLet RCE (§3-1) or deserialization (§4) |
| **Internal Network / Red Team** | JMX accessible within corporate LAN after initial foothold | §2-2, §3-2, §5-1, §5-2 | Network scanning (§7-1) → Brute force or default creds (§2-2) → MBean abuse (§5) → Lateral movement |
| **Kubernetes / Container** | Java app in container with JMX on 0.0.0.0 | §2-1, §5-1 | Pod-to-pod scanning → Unauthenticated JMX (§2-1) → Environment variable extraction (§5-1) → Cloud credential theft |
| **Application Server (Tomcat)** | Tomcat with JMX enabled for monitoring | §5-2, §6-2 | JMX/Jolokia access → Credential extraction → Log rotation webshell (§5-2) → OS command execution |
| **Application Server (JBoss)** | Legacy JBoss with invoker servlets | §1-3, §4-1 | HTTP scan for `/invoker/JMXInvokerServlet` → Deserialization RCE (§4-1) |
| **Application Server (ActiveMQ)** | ActiveMQ with Jolokia and Log4J | §5-3, §6-1 | Jolokia access with default credentials → Log4J MBean reconfiguration (§5-3) → File write webshell → RCE |
| **SSRF to Internal JMX** | Web application with SSRF vulnerability; JMX on internal network | §4-4, §6-3 | SSRF discovery → Binary SSRF to RMI/JMXMP (§4-4) or GET SSRF to Jolokia (§6-2) → RCE |
| **Authenticated Low-Privilege** | JMX access with read-only credentials | §2-3, §4-2 | Read-only connection → RMIConnection deserialization (§4-2) → Full RCE despite read-only role |
| **Password-Protected JMX** | JMX with authentication enabled, unknown credentials | §2-3 (CVE-2016-3427) | Craft malicious credential Map → Deserialization during authentication → RCE without valid credentials |

---

## CVE / Bounty Mapping (2016–2025)

| Mutation Combination | CVE / Case | Impact |
|---|---|---|
| §2-3 (Credential Map Deser) | CVE-2016-3427 (Oracle JDK) | Pre-auth RCE against password-protected JMX. CVSS 9.0. Patched in Java 8u91 |
| §1-3 + §4-1 (JMX Invoker Deser) | CVE-2016-8735 (Apache Tomcat) | RCE via JmxRemoteLifecycleListener deserialization. Mirror of CVE-2016-3427 for Tomcat |
| §1-3 + §5-2 (JBoss Invoker) | CVE-2013-4810 (JBoss AS) | Unauthenticated RCE via JMXInvokerServlet → BSHDeployer → WAR deployment → webshell. Actively exploited in the wild |
| §5-3 + §6-1 (Log4J MBeans via Jolokia) | CVE-2022-41678 (Apache ActiveMQ) | Authenticated RCE via Jolokia → Log4J MBean reconfiguration → file write. No deserialization required |
| §4-4 + §2-1 (SSRF to JMX) | CVE-2024-28211, CVE-2024-28213 (nGrinder) | Unauthenticated RCE: SSRF forces nGrinder to connect to attacker-controlled RMI endpoint → deserialization |
| §6-1 + §4-2 (Jolokia Proxy Deser) | CVE-2024-32030 (Kafka UI) | RCE via JMX/RMI deserialization through Kafka UI's JMX monitoring feature. CVSS 8.1 |
| §2-1 + §5-1 (Localhost JMX escalation) | CVE-2024-32656 (Ant Media Server) | Local privilege escalation from unprivileged user to root via unauthenticated localhost JMX |
| §6-1 + §4-2 (Jolokia Deser) | CVE-2025-49127 (Kafbat UI) | Critical RCE (CVSS 8.9): unauthenticated → attacker-controlled JMX endpoint → deserialization. No login required |
| §6-1 (Jolokia JNDI) | CVE-2018-1000130 (Jolokia) | JNDI injection in Jolokia proxy mode pre-1.5.0 → arbitrary class loading → RCE |
| §6-1 (Jolokia CSRF) | CVE-2018-1000129 (Jolokia) | System-wide CSRF → RCE via MBean invocation from victim's browser |

---

## Detection Tools

### Offensive Tools (Enumeration & Exploitation)

| Tool | Target Scope | Core Technique |
|---|---|---|
| **beanshooter** | JMX (RMI, JMXMP, Jolokia) | Comprehensive JMX attack tool: enum, brute force, MBean deployment, RequiredModelMBean exploitation, Tonka shell, deserialization attacks, SASL enumeration |
| **mjet / sjet** | JMX over RMI | MLet-based MBean deployment and ysoserial payload delivery for deserialization RCE |
| **remote-method-guesser (rmg)** | RMI services | RMI service enumeration, method guessing, deserialization testing, JEP-290 bypass detection |
| **jmx-exploiter** | JMX over RMI | Automated MBean deployment and exploitation of unprotected JMX endpoints |
| **jmxbf** | JMX authentication | JMX credential brute force (NCC Group) |
| **jolokia-exploitation-toolkit (JET)** | Jolokia HTTP endpoints | VHost creation, JFR file write, file read via DiagnosticCommand, automated RCE chain — all via GET requests |
| **jexboss** | JBoss/JMX | JBoss vulnerability verification and exploitation including JMXInvokerServlet deserialization |
| **ysoserial** | Java deserialization | Gadget chain payload generation for JMX deserialization attacks (CommonsCollections, JRMPClient, etc.) |
| **Metasploit** (`exploit/multi/misc/java_jmx_server`) | JMX over RMI | Automated JMX MLet exploitation with Meterpreter payload delivery |

### Defensive Tools (Detection & Hardening)

| Tool | Target Scope | Core Technique |
|---|---|---|
| **Nmap NSE** (`rmi-dumpregistry`, `rmi-vuln-classloader`) | RMI/JMX discovery | Network-level identification of exposed RMI registries and vulnerable classloader configurations |
| **jmxsecurity** | JMX auditing | Jython-based pentesting and audit tool for JMX configuration assessment |
| **Red Hat Declawed** (JMX/RMI RCE Detector) | JMX/RMI detection | Scans for JMX/RMI services vulnerable to remote code execution |
| **JEP-290 Serialization Filters** | JVM deserialization | Built-in JVM mechanism to whitelist/blacklist classes during deserialization (registry and DGC layers) |
| **JEP-415 Context-Specific Deser Filters** | JVM deserialization | Java 17+ fine-grained deserialization filtering with per-stream filter configuration |

---

## Summary: Core Principles

### The Root Cause

JMX's entire attack surface stems from a single architectural assumption: **management interfaces are trusted**. The protocol was designed in an era when management traffic traversed dedicated management networks, and any client that could connect was presumed to be a legitimate administrator. This trust model manifests in three fundamental design decisions:

1. **Native Java serialization as the wire format.** Every JMX transport (RMI, JMXMP, Invoker Servlets) uses Java's native serialization, which is inherently unsafe for untrusted input. The protocol cannot be secured without replacing its serialization layer entirely.

2. **Implicit full-access semantics.** JMX's "read-only" role is a logical abstraction that does not prevent protocol-level operations like deserialization. The permission model was bolted on after the protocol design, leaving a semantic gap between "what the role allows" and "what the protocol executes."

3. **Dynamic code loading as a feature.** MLet, RequiredModelMBean, and dynamic MBean registration are *intended* functionality — they exist because JMX was designed to manage applications by loading and configuring components at runtime. Restricting these features breaks legitimate use cases.

### Why Incremental Fixes Fail

Every major JMX security patch has addressed a specific deserialization entry point while leaving others open:

- **JEP-290** (2017) filtered RMI registry and DGC deserialization — but left the `RMIConnection` channel unfiltered
- **CVE-2016-3427 patch** restricted credential types to `String/String[]` — but MBean invocation parameters remain unrestricted
- **Jolokia patches** addressed JNDI injection in proxy mode — but MBean operations accessible via Jolokia remain as powerful as direct JMX access
- **JMXMP** was never included in any Oracle security patch scope, remaining permanently vulnerable

Each patch creates a new "narrowest remaining gap" that attackers migrate to, because the fundamental architecture requires serialization at every layer.

### The Structural Solution

A truly secure JMX architecture would require:

1. **Transport-layer replacement**: Replacing Java serialization with a safe wire format (JSON, Protocol Buffers) for all JMX communication — which Jolokia partially achieves but then re-exposes through unrestricted MBean operations
2. **Operation-level authorization**: Every MBean operation (not just connection establishment) must be individually authorized against an explicit allow-list, with deserialization occurring only *after* authorization succeeds
3. **Capability restriction**: Default JVM installations should not register MBeans capable of code loading, file I/O, or process execution. These should require explicit opt-in with security policy configuration
4. **Network isolation enforcement**: Remote JMX already requires explicit opt-in (setting `com.sun.management.jmxremote.port`), but once enabled it binds to all interfaces. Binding to localhost-only by default when remote is enabled, with non-localhost access requiring explicit TLS+mutual-auth configuration, would treat remote JMX as equivalent to SSH access

Until these structural changes are adopted, JMX remains a high-value target where a single exposed port can yield complete system compromise through multiple independent attack paths.

---

*This document was created for defensive security research and vulnerability understanding purposes.*

## References

- MOGWAI LABS, "Attacking RMI based JMX services" (2019)
- Code White, "JMX Exploitation Revisited" (2023)
- Tobias Neitzel, beanshooter JMX enumeration and attacking tool
- NCC Group, "Compromising Apache Tomcat via JMX Access"
- GitHub Security Lab, GHSL-2023-238 through GHSL-2023-244 (nGrinder advisories)
- Badanoiu, "CVE-2022-41678: Dangerous MBeans Accessible via Jolokia API in Apache ActiveMQ"
- LaLuka, "Jolokia Exploitation Toolkit (JET)"
- Neitzel, "Attacking Java RMI via SSRF"
- Oracle, JEP 290: Filter Incoming Serialization Data
- PayloadsAllTheThings, Java RMI Section
- HackTricks, "1098/1099/1050 - Pentesting Java RMI"
